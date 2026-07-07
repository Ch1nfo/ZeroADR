from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field

from zeroadr.core.events import RuntimeEvent
from zeroadr.core.findings import Finding
from zeroadr.core.policies import PolicyAction, PolicyDecision, new_policy_decision


class LLMAdjudicationPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")

    mode: Literal["shadow", "enforce"] = "shadow"
    min_confidence: float = Field(default=0.85, ge=0.0, le=1.0)
    true_positive_action: PolicyAction = "block"
    false_positive_action: PolicyAction = "alert"


class ToolResultGatePolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")

    mode: Literal["shadow", "enforce"] = "shadow"
    review: Literal["rules", "hybrid"] = "rules"
    min_confidence: float = Field(default=0.85, ge=0.0, le=1.0)
    true_positive_action: PolicyAction = "block"
    false_positive_action: PolicyAction = "allow"
    max_pending_responses: int = Field(default=256, gt=0)
    max_buffer_bytes: int = Field(default=32 * 1024 * 1024, gt=0)


class SemanticGatePolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")

    mode: Literal["shadow", "enforce"] = "shadow"
    review: Literal["rules", "hybrid"] = "rules"
    min_confidence: float = Field(default=0.85, ge=0.0, le=1.0)
    true_positive_action: PolicyAction = "block"
    false_positive_action: PolicyAction = "allow"


class SessionGuardPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")

    mode: Literal["shadow", "enforce"] = "shadow"
    compromised_action: PolicyAction = "require_approval"


class PolicyEngine:
    def __init__(
        self,
        *,
        mode: str = "audit",
        policies: list[dict[str, Any]] | None = None,
        tool_result_gate: ToolResultGatePolicy | None = None,
        agent_input_gate: SemanticGatePolicy | None = None,
        tool_request_gate: SemanticGatePolicy | None = None,
        session_guard: SessionGuardPolicy | None = None,
    ) -> None:
        self.mode = mode
        self.policies = policies or []
        self.tool_result_gate = tool_result_gate
        self.agent_input_gate = agent_input_gate
        self.tool_request_gate = tool_request_gate
        self.session_guard = session_guard

    @classmethod
    def from_dict(cls, config: dict[str, Any]) -> "PolicyEngine":
        if "tool_metadata_gate" in config:
            raise ValueError("tool_metadata_gate is no longer supported")
        gate_config = config.get("tool_result_gate")
        gate = (
            ToolResultGatePolicy.model_validate(gate_config)
            if gate_config is not None
            else None
        )
        def semantic(name: str) -> SemanticGatePolicy | None:
            value = config.get(name)
            return SemanticGatePolicy.model_validate(value) if value is not None else None

        guard_config = config.get("session_guard")
        return cls(
            mode=str(config.get("mode", "audit")),
            policies=list(config.get("policies", [])),
            tool_result_gate=gate,
            agent_input_gate=semantic("agent_input_gate"),
            tool_request_gate=semantic("tool_request_gate"),
            session_guard=(
                SessionGuardPolicy.model_validate(guard_config)
                if guard_config is not None
                else None
            ),
        )

    @classmethod
    def from_file(cls, path: Path) -> "PolicyEngine":
        if not path.exists():
            return cls()
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        if not isinstance(data, dict):
            raise ValueError(f"Policy file must contain a mapping: {path}")
        return cls.from_dict(data)

    def evaluate(self, event: RuntimeEvent, findings: list[Finding]) -> PolicyDecision:
        for policy in self.policies:
            if _event_policy_matches(policy.get("match", {}), event, findings):
                action = _policy_action(policy)
                return new_policy_decision(
                    policy_id=str(policy.get("id", "unnamed-policy")),
                    action=action,
                    reason=_policy_reason(policy, findings),
                    session_id=event.session_id,
                    event_id=event.event_id,
                    finding_ids=[finding.finding_id for finding in findings],
                )
        if findings:
            return new_policy_decision(
                policy_id=None,
                action="alert",
                reason="Finding produced in audit mode.",
                session_id=event.session_id,
                event_id=event.event_id,
                finding_ids=[finding.finding_id for finding in findings],
            )
        return new_policy_decision(
            policy_id=None,
            action="allow",
            reason="No findings matched.",
            session_id=event.session_id,
            event_id=event.event_id,
            finding_ids=[],
        )

    def llm_adjudication_for(
        self,
        event: RuntimeEvent,
        findings: list[Finding],
    ) -> LLMAdjudicationPolicy | None:
        for policy in self.policies:
            if not _event_policy_matches(policy.get("match", {}), event, findings):
                continue
            config = policy.get("llm_adjudication")
            if config is None:
                return None
            return LLMAdjudicationPolicy.model_validate(config)
        return None

    def has_llm_adjudication(self) -> bool:
        return any(policy.get("llm_adjudication") is not None for policy in self.policies)

    def has_stage_review(self) -> bool:
        return any(
            gate is not None and gate.review == "hybrid"
            for gate in (
                self.agent_input_gate,
                self.tool_request_gate,
            )
        )

    def evaluate_finding(self, finding: Finding) -> PolicyDecision:
        for policy in self.policies:
            if _finding_policy_matches(policy.get("match", {}), finding):
                return new_policy_decision(
                    policy_id=str(policy.get("id", "unnamed-policy")),
                    action=_policy_action(policy),
                    reason=finding.explanation,
                    session_id=finding.session_id,
                    event_id=_decision_event_id_for_finding(finding),
                    finding_ids=[finding.finding_id],
                )
        return new_policy_decision(
            policy_id=None,
            action="alert",
            reason="Finding produced in audit mode.",
            session_id=finding.session_id,
            event_id=_decision_event_id_for_finding(finding),
            finding_ids=[finding.finding_id],
        )

    def render_jsonrpc_error(self, request_id: str | int | None, decision: PolicyDecision) -> dict[str, Any]:
        return self._render_jsonrpc_error(
            request_id,
            message="Blocked by ZeroADR policy",
            reason=decision.reason,
            policy_id=decision.policy_id,
        )

    def render_approval_jsonrpc_error(
        self,
        request_id: str | int | None,
        *,
        message: str,
        reason: str,
        code: int = -32002,
    ) -> dict[str, Any]:
        return self._render_jsonrpc_error(
            request_id,
            message=message,
            reason=reason,
            policy_id=None,
            code=code,
        )

    def _render_jsonrpc_error(
        self,
        request_id: str | int | None,
        *,
        message: str,
        reason: str,
        policy_id: str | None,
        code: int = -32001,
    ) -> dict[str, Any]:
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {
                "code": code,
                "message": message,
                "data": {
                    "policy_id": policy_id,
                    "reason": reason,
                },
            },
        }


def _event_policy_matches(match: dict[str, Any], event: RuntimeEvent, findings: list[Finding]) -> bool:
    if not _matches_value(match.get("capability"), event.capability) and match.get("capability") is not None:
        return False
    if not _matches_value(match.get("event_type"), event.event_type) and match.get("event_type") is not None:
        return False
    if not _matches_value(match.get("tool_name"), event.tool_name) and match.get("tool_name") is not None:
        return False
    if not _matches_value(match.get("server_name"), event.server_name) and match.get("server_name") is not None:
        return False
    severity = match.get("severity")
    if severity is not None and not any(finding.severity == severity for finding in findings):
        return False
    rule_id = match.get("rule_id")
    if rule_id is not None and not any(_matches_value(rule_id, finding.rule_id) for finding in findings):
        return False
    target = match.get("target")
    if target is not None and not any(_matches_value(target, finding.target) for finding in findings):
        return False
    target_contains = match.get("target_contains")
    if target_contains is not None and not any(_contains_value(target_contains, finding.target) for finding in findings):
        return False
    return True


def _finding_policy_matches(match: dict[str, Any], finding: Finding) -> bool:
    if not _matches_value(match.get("capability"), finding.capability) and match.get("capability") is not None:
        return False
    if not _matches_value(match.get("severity"), finding.severity) and match.get("severity") is not None:
        return False
    if not _matches_value(match.get("rule_id"), finding.rule_id) and match.get("rule_id") is not None:
        return False
    if not _matches_value(match.get("target"), finding.target) and match.get("target") is not None:
        return False
    if not _contains_value(match.get("target_contains"), finding.target) and match.get("target_contains") is not None:
        return False
    return True


def _matches_value(expected: Any, actual: str | None) -> bool:
    if expected is None:
        return True
    if isinstance(expected, list):
        return actual in {str(item) for item in expected}
    return actual == str(expected)


def _contains_value(expected: Any, actual: str) -> bool:
    if expected is None:
        return True
    if isinstance(expected, list):
        return any(_contains_pattern(str(item), actual) for item in expected)
    return _contains_pattern(str(expected), actual)


def _contains_pattern(expected: str, actual: str) -> bool:
    if expected in actual:
        return True
    if expected.startswith("~/"):
        return actual.endswith(expected[1:])
    return False


def _policy_action(policy: dict[str, Any]) -> PolicyAction:
    action = str(policy.get("action", "alert"))
    if action not in {"allow", "alert", "block", "require_approval"}:
        return "alert"
    return action  # type: ignore[return-value]


def _decision_event_id_for_finding(finding: Finding) -> str:
    if finding.event_ids:
        return finding.event_ids[0]
    return finding.finding_id


def _policy_reason(policy: dict[str, Any], findings: list[Finding]) -> str:
    if findings:
        return findings[0].explanation
    reason = policy.get("reason")
    return str(reason) if reason else "Matched ZeroADR policy."
