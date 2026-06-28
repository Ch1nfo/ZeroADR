from __future__ import annotations

from pathlib import Path
from typing import Any

from zeroadr.reconstruction.session import reconstruct_from_sqlite, reconstruct_from_trace
from zeroadr.reconstruction.summary import summary_from_context

AgentBom = dict[str, Any]


def bom_from_trace(path: Path) -> AgentBom:
    return bom_from_context(reconstruct_from_trace(path), generated_from="trace")


def bom_from_sqlite(session_id: str, db_path: Path) -> AgentBom:
    return bom_from_context(
        reconstruct_from_sqlite(session_id, db_path),
        generated_from="sqlite",
    )


def bom_from_context(context: dict[str, Any], *, generated_from: str) -> AgentBom:
    summary = summary_from_context(context)
    return {
        "bom_version": "0.1",
        "session_id": context.get("session_id"),
        "generated_from": generated_from,
        "inventory": {
            "source_types": summary["source_types"],
            "servers": summary["servers"],
            "tools": summary["tools"],
            "capabilities": summary["capabilities"],
            "targets": summary["targets"],
            "sensitive_targets": summary["sensitive_targets"],
            "external_targets": summary["external_targets"],
            "endpoint_event_count": summary["endpoint_event_count"],
            "process_count": summary["process_count"],
        },
        "endpoint": {
            "process_tree": context.get("process_tree", {"nodes": [], "edges": []}),
            "correlations": context.get("endpoint_correlations", []),
        },
        "context": context.get("context_metadata", {}),
        "tool_calls": [_tool_call(item) for item in _dict_list(context.get("timeline"))],
        "risk": {
            "summary": summary["risk_summary"],
            "finding_rules": summary["finding_rules"],
            "findings": [_finding(finding) for finding in _dict_list(context.get("findings"))],
            "decisions": [_decision(decision) for decision in _dict_list(context.get("policy_decisions"))],
        },
    }


def _tool_call(item: dict[str, Any]) -> dict[str, Any]:
    requested_value = item.get("requested")
    completed_value = item.get("completed")
    requested: dict[str, Any] = requested_value if isinstance(requested_value, dict) else {}
    completed = completed_value if isinstance(completed_value, dict) else None
    return {
        "request_id": item.get("request_id"),
        "tool_name": item.get("tool_name"),
        "capability": item.get("capability"),
        "target": requested.get("target"),
        "requested_event_id": requested.get("event_id"),
        "completed_event_id": completed.get("event_id") if isinstance(completed, dict) else None,
        "decision": _timeline_decision(item.get("decision")),
        "findings": [_finding_ref(finding) for finding in _dict_list(item.get("findings"))],
    }


def _finding(finding: dict[str, Any]) -> dict[str, Any]:
    return {
        "finding_id": finding.get("finding_id"),
        "rule_id": finding.get("rule_id"),
        "severity": finding.get("severity"),
        "confidence": finding.get("confidence"),
        "event_ids": finding.get("event_ids", []),
        "capability": finding.get("capability"),
        "target": finding.get("target"),
        "title": finding.get("title"),
        "explanation": finding.get("explanation"),
    }


def _finding_ref(finding: dict[str, Any]) -> dict[str, Any]:
    return {
        "finding_id": finding.get("finding_id"),
        "rule_id": finding.get("rule_id"),
        "severity": finding.get("severity"),
        "target": finding.get("target"),
    }


def _decision(decision: dict[str, Any]) -> dict[str, Any]:
    return {
        "decision_id": decision.get("decision_id"),
        "policy_id": decision.get("policy_id"),
        "action": decision.get("action"),
        "reason": decision.get("reason"),
        "event_id": decision.get("event_id"),
        "finding_ids": decision.get("finding_ids", []),
    }


def _timeline_decision(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    return {
        "decision_id": value.get("decision_id"),
        "policy_id": value.get("policy_id"),
        "action": value.get("action"),
        "reason": value.get("reason"),
        "finding_ids": value.get("finding_ids", []),
    }


def _dict_list(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]
