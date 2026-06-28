from __future__ import annotations

from pathlib import Path
from typing import Any

from zeroadr.reconstruction.session import Context, reconstruct_from_trace


def evidence_from_trace(
    path: Path,
    *,
    finding_id: str | None = None,
    rule_id: str | None = None,
) -> dict[str, Any]:
    return evidence_from_context(
        reconstruct_from_trace(path),
        finding_id=finding_id,
        rule_id=rule_id,
    )


def evidence_from_context(
    context: Context,
    *,
    finding_id: str | None = None,
    rule_id: str | None = None,
) -> dict[str, Any]:
    finding = _select_finding(context["findings"], finding_id=finding_id, rule_id=rule_id)
    if finding is None:
        return {
            "session_id": context["session_id"],
            "finding": None,
            "events": [],
            "timeline": [],
            "related_decisions": [],
            "risk_summary": context["risk_summary"],
        }
    event_ids = set(finding["event_ids"])
    finding_ids = {finding["finding_id"]}
    return {
        "session_id": context["session_id"],
        "finding": finding,
        "events": [event for event in context["events"] if event["event_id"] in event_ids],
        "timeline": [
            item
            for item in context["timeline"]
            if _timeline_intersects(item, event_ids, finding_ids)
        ],
        "related_decisions": [
            decision
            for decision in context["policy_decisions"]
            if decision["event_id"] in event_ids
            or bool(set(decision["finding_ids"]) & finding_ids)
        ],
        "risk_summary": context["risk_summary"],
    }


def _select_finding(
    findings: list[dict[str, Any]],
    *,
    finding_id: str | None,
    rule_id: str | None,
) -> dict[str, Any] | None:
    candidates = findings
    if finding_id is not None:
        candidates = [finding for finding in candidates if finding["finding_id"] == finding_id]
    if rule_id is not None:
        candidates = [finding for finding in candidates if finding["rule_id"] == rule_id]
    if not candidates:
        return None
    return sorted(candidates, key=_finding_sort_key)[0]


def _finding_sort_key(finding: dict[str, Any]) -> tuple[int, str]:
    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    return severity_rank.get(str(finding["severity"]), 99), str(finding["finding_id"])


def _timeline_intersects(
    item: dict[str, Any],
    event_ids: set[str],
    finding_ids: set[str],
) -> bool:
    requested = item.get("requested")
    completed = item.get("completed")
    policy_event = item.get("policy_event")
    for event in (requested, completed, policy_event):
        if isinstance(event, dict) and event.get("event_id") in event_ids:
            return True
    return any(finding.get("finding_id") in finding_ids for finding in item.get("findings", []))
