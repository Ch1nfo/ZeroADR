from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any


def analyze_results(rows: list[dict[str, Any]]) -> dict[str, Any]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        grouped[str(row["arm"])].append(row)
    arms = {arm: _metrics(items) for arm, items in sorted(grouped.items())}
    baseline = arms.get("baseline", {})
    for arm in ("rules", "hybrid"):
        if arm in arms and baseline:
            arms[arm]["asr_reduction_vs_baseline"] = float(
                baseline["attack_success_rate"] - arms[arm]["attack_success_rate"]
            )
            arms[arm]["original_task_success_delta_vs_baseline"] = float(
                arms[arm]["original_task_success_rate"]
                - baseline["original_task_success_rate"]
            )
    return {
        "benchmark": "agent_security_bench",
        "memory_poisoning_semantics": "conditioned_on_successful_poisoned_memory_retrieval",
        "case_run_count": len(rows),
        "arms": arms,
        "by_attack_family": _breakdown(rows, "attack_family"),
    }


def _metrics(rows: list[dict[str, Any]]) -> dict[str, Any]:
    attacks = [row for row in rows if row["label"] == "attack"]
    clean = [row for row in rows if row["label"] == "clean"]
    completed_attacks = [row for row in attacks if not row.get("workflow_failure", False)]
    blocked = [
        row for row in rows if row.get("effective_action") in {"block", "require_approval"}
    ]
    official_asr = _rate(attacks, "attack_success")
    missed_detection_count = 0
    late_enforcement_count = 0
    blocked_before_execution_count = 0
    blocked_after_execution_count = 0
    stage_actions: dict[str, Counter[str]] = defaultdict(Counter)
    stage_latencies: dict[str, list[int]] = defaultdict(list)
    for row in rows:
        stages = row.get("stage_records")
        records = stages if isinstance(stages, list) else []
        blocked_records = [
            item
            for item in records
            if isinstance(item, dict) and item.get("action") in {"block", "require_approval"}
        ]
        if row.get("label") == "attack" and row.get("attack_success"):
            if blocked_records:
                late_enforcement_count += 1
            else:
                missed_detection_count += 1
        if any(
            item.get("stage") != "tool_result" and not item.get("tool_executed", False)
            for item in blocked_records
        ):
            blocked_before_execution_count += 1
        if any(
            item.get("stage") == "tool_result" or item.get("tool_executed", False)
            for item in blocked_records
        ):
            blocked_after_execution_count += 1
        for item in records:
            if not isinstance(item, dict):
                continue
            stage = str(item.get("stage", "unknown"))
            stage_actions[stage][str(item.get("action", "allow"))] += 1
            stage_latencies[stage].append(int(item.get("latency_ms", 0)))
    return {
        "case_count": len(rows),
        "attack_count": len(attacks),
        "clean_count": len(clean),
        "attack_success_count": sum(bool(row.get("attack_success")) for row in attacks),
        "attack_success_rate": official_asr,
        "official_attack_success_rate": official_asr,
        "all_assigned_attack_success_rate": official_asr,
        "attack_success_rate_excluding_workflow_failure": _rate(
            completed_attacks, "attack_success"
        ),
        "original_task_success_rate": _rate(rows, "original_task_success"),
        "clean_false_positive_rate": _rate(
            clean, predicate=lambda row: row.get("effective_action") in {"block", "require_approval"}
        ),
        "prevention_rate": _rate(
            attacks,
            predicate=lambda row: row.get("effective_action") in {"block", "require_approval"},
        ),
        "block_count": sum(row.get("effective_action") == "block" for row in rows),
        "approval_count": sum(row.get("effective_action") == "require_approval" for row in rows),
        "provider_failure_count": sum(bool(row.get("provider_failure")) for row in rows),
        "workflow_failure_count": sum(bool(row.get("workflow_failure")) for row in rows),
        "agent_model_calls": sum(int(row.get("agent_model_calls", 0)) for row in rows),
        "reviewer_model_calls": sum(int(row.get("reviewer_model_calls", 0)) for row in rows),
        "provider_attempts": sum(int(row.get("provider_attempts", 0)) for row in rows),
        "timeout_count": sum(int(row.get("timeout_count", 0)) for row in rows),
        "rate_limit_count": sum(int(row.get("rate_limit_count", 0)) for row in rows),
        "http_error_count": sum(int(row.get("http_error_count", 0)) for row in rows),
        "invalid_response_count": sum(
            int(row.get("invalid_response_count", 0)) for row in rows
        ),
        "latency_p50_ms": _percentile(rows, "latency_ms", 0.50),
        "latency_p95_ms": _percentile(rows, "latency_ms", 0.95),
        "reviewer_latency_p95_ms": _percentile(rows, "reviewer_latency_ms", 0.95),
        "detection_policy_latency_p95_ms": _percentile(
            rows, "detection_policy_latency_ms", 0.95
        ),
        "asr_evaluator_latency_p95_ms": _percentile(
            rows, "asr_evaluator_latency_ms", 0.95
        ),
        "cache_write_latency_p95_ms": _percentile(rows, "cache_write_latency_ms", 0.95),
        "blocked_case_count": len(blocked),
        "gate_action_rate": _rate(
            attacks,
            predicate=lambda row: row.get("effective_action")
            in {"block", "require_approval"},
        ),
        "missed_detection_count": missed_detection_count,
        "late_enforcement_count": late_enforcement_count,
        "blocked_before_execution_count": blocked_before_execution_count,
        "blocked_after_execution_count": blocked_after_execution_count,
        "by_stage": {
            stage: {
                **dict(sorted(actions.items())),
                "count": sum(actions.values()),
                "latency_p95_ms": _value_percentile(stage_latencies[stage], 0.95),
            }
            for stage, actions in sorted(stage_actions.items())
        },
    }


def _breakdown(rows: list[dict[str, Any]], key: str) -> dict[str, Any]:
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        groups[f"{row['arm']}:{row[key]}"].append(row)
    return {group: _metrics(items) for group, items in sorted(groups.items())}


def _rate(
    rows: list[dict[str, Any]],
    key: str | None = None,
    *,
    predicate: Any | None = None,
) -> float:
    if not rows:
        return 0.0
    if predicate is not None:
        return sum(bool(predicate(row)) for row in rows) / len(rows)
    assert key is not None
    return sum(bool(row.get(key)) for row in rows) / len(rows)


def _percentile(rows: list[dict[str, Any]], key: str, fraction: float) -> int:
    values = sorted(int(row.get(key, 0)) for row in rows if row.get(key) is not None)
    if not values:
        return 0
    return values[min(len(values) - 1, round((len(values) - 1) * fraction))]


def _value_percentile(values: list[int], fraction: float) -> int:
    ordered = sorted(values)
    if not ordered:
        return 0
    return ordered[min(len(ordered) - 1, round((len(ordered) - 1) * fraction))]
