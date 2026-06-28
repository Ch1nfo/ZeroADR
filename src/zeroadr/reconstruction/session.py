from __future__ import annotations

from pathlib import Path
from typing import Any

from zeroadr.core.events import RuntimeEvent
from zeroadr.core.findings import Finding
from zeroadr.core.policies import PolicyAction, PolicyDecision
from zeroadr.core.trace import SessionTrace
from zeroadr.reconstruction.correlation import correlate_endpoint_events
from zeroadr.reconstruction.process_tree import build_process_tree
from zeroadr.replay.runner import replay_trace
from zeroadr.security.redaction import REDACTED, redact_event
from zeroadr.storage.database import SQLiteStore

Context = dict[str, Any]


def reconstruct_from_trace(path: Path) -> Context:
    return reconstruct_session_trace(replay_trace(path))


def reconstruct_from_sqlite(session_id: str, db_path: Path) -> Context:
    store = SQLiteStore(db_path)
    trace = SessionTrace(
        session_id=session_id,
        events=store.events_for_session(session_id),
        findings=store.findings_for_session(session_id),
        policy_decisions=store.policy_decisions_for_session(session_id),
    )
    context = reconstruct_session_trace(trace)
    adjudications = store.llm_adjudications_for_session(session_id)
    context["llm_adjudications"] = [
        adjudication.model_dump(mode="json") for adjudication in adjudications
    ]
    adjudication_by_event = {item.event_id: item for item in adjudications}
    for timeline_item in context["timeline"]:
        requested = timeline_item.get("requested") or {}
        requested_event_id = requested.get("event_id")
        if not isinstance(requested_event_id, str):
            continue
        adjudication = adjudication_by_event.get(requested_event_id)
        if adjudication is None:
            continue
        timeline_item["adjudication"] = {
            "adjudication_id": adjudication.adjudication_id,
            "mode": adjudication.mode,
            "status": adjudication.status,
            "verdict": adjudication.result.verdict if adjudication.result else None,
            "confidence": adjudication.result.confidence if adjudication.result else None,
            "proposed_action": adjudication.proposed_action,
            "final_action": adjudication.final_action,
        }
    context["risk_summary"]["pending_approval_count"] = store.pending_approval_count(session_id=session_id)
    return context


def reconstruct_session_trace(trace: SessionTrace) -> Context:
    events = sorted(trace.events, key=lambda event: (event.event_time, event.ingest_time, event.event_id))
    findings = sorted(trace.findings, key=lambda finding: finding.finding_id)
    decisions = sorted(
        trace.policy_decisions,
        key=lambda decision: (decision.created_at, decision.decision_id),
    )
    return {
        "session_id": trace.session_id,
        "events": [_event_dict(event) for event in events],
        "findings": [_finding_dict(finding) for finding in findings],
        "policy_decisions": [_decision_dict(decision) for decision in decisions],
        "llm_adjudications": [],
        "timeline": _build_timeline(events, findings, decisions),
        "risk_summary": _risk_summary(findings, decisions),
        "context_metadata": _context_metadata(events),
        "process_tree": build_process_tree(events),
        "endpoint_correlations": correlate_endpoint_events(events),
    }


def _build_timeline(
    events: list[RuntimeEvent],
    findings: list[Finding],
    decisions: list[PolicyDecision],
) -> list[dict[str, Any]]:
    requested_events = [event for event in events if event.event_type == "tool.call.requested"]
    terminal_by_request: dict[str, RuntimeEvent] = {}
    policy_event_by_request: dict[str, RuntimeEvent] = {}
    for event in events:
        request_key = _request_key(event.request_id)
        if request_key is None:
            continue
        if event.event_type in {"tool.call.completed", "tool.call.failed"}:
            terminal_by_request[request_key] = event
        if event.event_type == "policy.evaluated":
            policy_event_by_request[request_key] = event

    findings_by_event: dict[str, list[Finding]] = {}
    for finding in findings:
        for event_id in finding.event_ids:
            findings_by_event.setdefault(event_id, []).append(finding)

    decision_by_event_id = _event_level_decisions(decisions)
    timeline: list[dict[str, Any]] = []
    for event in requested_events:
        request_key = _request_key(event.request_id)
        terminal = terminal_by_request.get(request_key or "")
        policy_event = policy_event_by_request.get(request_key or "")
        event_findings = findings_by_event.get(event.event_id, [])
        timeline.append(
            {
                "request_id": event.request_id,
                "tool_name": event.tool_name,
                "capability": event.capability,
                "requested": _timeline_event(event),
                "completed": _timeline_event(terminal) if terminal else None,
                "policy_event": _timeline_event(policy_event) if policy_event else None,
                "decision": _timeline_decision(decision_by_event_id.get(event.event_id)),
                "findings": [_finding_ref(finding) for finding in event_findings],
                "adjudication": None,
            }
        )
    return timeline


def _event_level_decisions(decisions: list[PolicyDecision]) -> dict[str, PolicyDecision]:
    decisions_by_event: dict[str, list[PolicyDecision]] = {}
    for decision in decisions:
        decisions_by_event.setdefault(decision.event_id, []).append(decision)
    selected: dict[str, PolicyDecision] = {}
    for event_id, event_decisions in decisions_by_event.items():
        preferred_id = f"decision_{event_id}"
        selected[event_id] = next(
            (
                decision
                for decision in event_decisions
                if decision.decision_id == preferred_id
            ),
            event_decisions[0],
        )
    return selected


def _risk_summary(findings: list[Finding], decisions: list[PolicyDecision]) -> dict[str, Any]:
    severity_counts = {"low": 0, "medium": 0, "high": 0, "critical": 0}
    for finding in findings:
        severity_counts[finding.severity] += 1
    decision_counts: dict[PolicyAction, int] = {
        "allow": 0,
        "alert": 0,
        "block": 0,
        "require_approval": 0,
    }
    for decision in decisions:
        decision_counts[decision.action] += 1
    return {
        "total_findings": len(findings),
        **severity_counts,
        "decisions": decision_counts,
    }


def _event_dict(event: RuntimeEvent) -> dict[str, Any]:
    redacted = redact_event(event).model_dump(mode="json")
    raw = redacted.get("raw")
    if isinstance(raw, dict):
        _redact_prompt_text(raw)
    return redacted


def _finding_dict(finding: Finding) -> dict[str, Any]:
    return finding.model_dump(mode="json")


def _decision_dict(decision: PolicyDecision) -> dict[str, Any]:
    return decision.model_dump(mode="json")


def _timeline_event(event: RuntimeEvent) -> dict[str, Any]:
    return {
        "event_id": event.event_id,
        "event_type": event.event_type,
        "event_time": event.event_time.isoformat(),
        "tool_name": event.tool_name,
        "capability": event.capability,
        "target": _event_target(event),
    }


def _timeline_decision(decision: PolicyDecision | None) -> dict[str, Any] | None:
    if decision is None:
        return None
    return {
        "decision_id": decision.decision_id,
        "policy_id": decision.policy_id,
        "action": decision.action,
        "reason": decision.reason,
        "finding_ids": decision.finding_ids,
    }


def _finding_ref(finding: Finding) -> dict[str, str]:
    return {
        "finding_id": finding.finding_id,
        "rule_id": finding.rule_id,
        "severity": finding.severity,
        "target": finding.target,
    }


def _request_key(request_id: str | int | None) -> str | None:
    return str(request_id) if request_id is not None else None


def _event_target(event: RuntimeEvent) -> str:
    arguments = event.arguments if isinstance(event.arguments, dict) else {}
    for key in ("path", "file", "filename", "command", "cmd", "url", "uri", "endpoint"):
        value = arguments.get(key)
        if isinstance(value, str):
            return value
    return event.tool_name or "unknown"


def _context_metadata(events: list[RuntimeEvent]) -> dict[str, Any]:
    clients: list[dict[str, str]] = []
    workspaces: list[dict[str, str]] = []
    prompts: list[dict[str, Any]] = []
    for event in events:
        raw = event.raw
        if not isinstance(raw, dict):
            continue
        client = _client_metadata(raw)
        workspace = _workspace_metadata(raw)
        prompt = _prompt_metadata(raw)
        if client:
            clients.append(client)
        if workspace:
            workspaces.append(workspace)
        if prompt:
            prompts.append(prompt)
    return {
        "clients": _unique_dicts(clients),
        "workspaces": _unique_dicts(workspaces),
        "prompts": _unique_dicts(prompts),
    }


def _client_metadata(raw: dict[str, Any]) -> dict[str, str]:
    client = raw.get("client")
    values = client if isinstance(client, dict) else raw
    return _compact_str_dict(
        {
            "name": values.get("name") or values.get("client_name"),
            "version": values.get("version") or values.get("client_version"),
            "session_id": values.get("session_id") or values.get("client_session_id"),
        }
    )


def _workspace_metadata(raw: dict[str, Any]) -> dict[str, str]:
    workspace = raw.get("workspace")
    values = workspace if isinstance(workspace, dict) else raw
    return _compact_str_dict(
        {
            "root": values.get("root") or values.get("workspace_root"),
            "name": values.get("name") or values.get("workspace_name"),
        }
    )


def _prompt_metadata(raw: dict[str, Any]) -> dict[str, Any]:
    prompt = raw.get("prompt")
    if isinstance(prompt, dict):
        metadata: dict[str, Any] = {"present": True}
        for key in ("source", "sha256"):
            value = prompt.get(key)
            if isinstance(value, str) and value:
                metadata[key] = value
        return metadata
    if isinstance(prompt, str) and prompt:
        return {"present": True}
    if raw.get("prompt_present") is True:
        return {"present": True}
    return {}


def _redact_prompt_text(raw: dict[str, Any]) -> None:
    prompt = raw.get("prompt")
    if isinstance(prompt, dict) and isinstance(prompt.get("text"), str):
        prompt["text"] = REDACTED


def _compact_str_dict(values: dict[str, Any]) -> dict[str, str]:
    return {key: value for key, value in values.items() if isinstance(value, str) and value}


def _unique_dicts(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    unique: dict[str, dict[str, Any]] = {}
    for item in items:
        key = repr(sorted(item.items()))
        unique[key] = item
    return [unique[key] for key in sorted(unique)]
