from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, ValidationError, field_validator

from zeroadr.core.events import SecurityContext, new_event
from zeroadr.llm.adjudication import LLMAdjudicator
from zeroadr.llm.calibration import GateCalibrationError, write_gate_label_records
from zeroadr.policy.engine import PolicyEngine
from zeroadr.runtime.service import RuntimeDecisionService


class GateDogfoodCase(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["0.1"] = "0.1"
    case_id: str
    expected_verdict: Literal["likely_true_positive", "likely_false_positive"]
    path: str
    scenario_summary: str
    user_consent: Literal["explicit", "absent", "unknown"] = "unknown"
    task_alignment: Literal["aligned", "misaligned", "unknown"] = "unknown"
    data_handling: Literal["local_only", "external", "unknown"] = "unknown"
    injection_evidence: Literal["present", "absent", "unknown"] = "unknown"

    @field_validator("case_id", "path", "scenario_summary")
    @classmethod
    def require_text(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("value must not be empty")
        return normalized

    @field_validator("path")
    @classmethod
    def require_env_path(cls, value: str) -> str:
        if not value.replace("\\", "/").endswith("/.env"):
            raise ValueError("dogfood path must end with /.env")
        return value


def load_dogfood_cases(path: Path) -> list[GateDogfoodCase]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise GateCalibrationError("cases_unreadable", f"Unable to read cases: {path}") from exc
    cases: list[GateDogfoodCase] = []
    seen: set[str] = set()
    for line_number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            case = GateDogfoodCase.model_validate_json(line)
        except (ValidationError, ValueError) as exc:
            raise GateCalibrationError(
                "invalid_dogfood_case",
                f"Invalid dogfood case at line {line_number}.",
            ) from exc
        if case.case_id in seen:
            raise GateCalibrationError(
                "duplicate_dogfood_case",
                f"Duplicate dogfood case at line {line_number}: {case.case_id}",
            )
        seen.add(case.case_id)
        cases.append(case)
    return cases


def run_gate_dogfood(
    *,
    cases_path: Path,
    db_path: Path,
    policy_path: Path,
    labels_output: Path,
    adjudicator: LLMAdjudicator,
    trace_path: Path | None = None,
    limit: int | None = None,
) -> dict[str, Any]:
    policy = PolicyEngine.from_file(policy_path)
    _require_shadow_policy(policy)
    cases = load_dogfood_cases(cases_path)
    if limit is not None:
        if limit <= 0:
            raise GateCalibrationError("invalid_limit", "Dogfood limit must be positive.")
        cases = cases[:limit]
    runtime = RuntimeDecisionService(
        source_type="hook",
        policy_engine=policy,
        trace_path=trace_path,
        db_path=db_path,
        adjudicator=adjudicator,
    )
    labels: list[dict[str, Any]] = []
    status_counts: Counter[str] = Counter()
    final_action_counts: Counter[str] = Counter()
    for index, case in enumerate(cases, start=1):
        event = new_event(
            event_type="tool.call.requested",
            source_type="hook",
            session_id=f"dogfood_{case.case_id}",
            request_id=index,
            server_name="dogfood",
            tool_name="read_file",
            capability="filesystem.read",
            security_context=SecurityContext(
                user_consent=case.user_consent,
                task_alignment=case.task_alignment,
                data_handling=case.data_handling,
                injection_evidence=case.injection_evidence,
            ),
            arguments={
                "path": case.path,
                "scenario_summary": case.scenario_summary,
            },
        )
        outcome = runtime.evaluate(event)
        if outcome.adjudication is None:
            status_counts["not_adjudicated"] += 1
            continue
        adjudication = outcome.adjudication
        status_counts[adjudication.status] += 1
        final_action_counts[adjudication.final_action] += 1
        labels.append(
            {
                "adjudication_id": adjudication.adjudication_id,
                "expected_verdict": case.expected_verdict,
                "case_id": case.case_id,
                "observed_verdict": adjudication.result.verdict if adjudication.result else None,
                "observed_confidence": (
                    adjudication.result.confidence if adjudication.result else None
                ),
                "status": adjudication.status,
                "error_code": adjudication.error_code,
            }
        )
    write_gate_label_records(labels_output, labels)
    return {
        "cases_path": str(cases_path),
        "cases_read": len(cases),
        "labels_output": str(labels_output),
        "adjudications_completed": status_counts.get("completed", 0),
        "adjudications_failed": status_counts.get("failed", 0),
        "not_adjudicated": status_counts.get("not_adjudicated", 0),
        "final_action_counts": dict(sorted(final_action_counts.items())),
    }


def _require_shadow_policy(policy: PolicyEngine) -> None:
    gate_configs: list[dict[str, Any]] = []
    for item in policy.policies:
        config = item.get("llm_adjudication")
        if isinstance(config, dict):
            gate_configs.append(config)
    if not gate_configs or any(config.get("mode", "shadow") != "shadow" for config in gate_configs):
        raise GateCalibrationError(
            "dogfood_requires_shadow",
            "Dogfood requires a policy containing only shadow LLM adjudication rules.",
        )
