from __future__ import annotations

from pathlib import Path
from typing import Any

from zeroadr.reconstruction.session import reconstruct_from_sqlite, reconstruct_from_trace

Summary = dict[str, Any]

_EXTERNAL_CAPABILITIES = {
    "network.connect",
    "network.http_post",
    "message.send",
    "email.send",
}


def summary_from_trace(path: Path) -> Summary:
    return summary_from_context(reconstruct_from_trace(path))


def summary_from_sqlite(session_id: str, db_path: Path) -> Summary:
    return summary_from_context(reconstruct_from_sqlite(session_id, db_path))


def summary_from_context(context: dict[str, Any]) -> Summary:
    events = _dict_list(context.get("events"))
    findings = _dict_list(context.get("findings"))
    timeline = _dict_list(context.get("timeline"))
    context_metadata = context.get("context_metadata")
    metadata = context_metadata if isinstance(context_metadata, dict) else {}
    process_tree_value = context.get("process_tree")
    process_tree = process_tree_value if isinstance(process_tree_value, dict) else {}
    process_nodes = _dict_list(process_tree.get("nodes"))

    source_types = _sorted_unique(event.get("source_type") for event in events)
    servers = _sorted_unique(event.get("server_name") for event in events)
    tools = _sorted_unique(event.get("tool_name") for event in events)
    capabilities = _sorted_unique(event.get("capability") for event in events)
    finding_rules = _sorted_unique(finding.get("rule_id") for finding in findings)

    targets = _collect_targets(events, findings, timeline)
    sensitive_targets = _sorted_unique(
        finding.get("target")
        for finding in findings
        if finding.get("rule_id") == "sensitive-file-access"
    )
    external_targets = _collect_external_targets(events, findings)

    return {
        "session_id": context.get("session_id"),
        "source_types": source_types,
        "servers": servers,
        "tools": tools,
        "capabilities": capabilities,
        "targets": targets,
        "sensitive_targets": sensitive_targets,
        "external_targets": external_targets,
        "finding_rules": finding_rules,
        "risk_summary": context.get("risk_summary", {}),
        "clients": _metadata_names(metadata.get("clients")),
        "workspaces": _metadata_workspaces(metadata.get("workspaces")),
        "prompts_present": bool(metadata.get("prompts")),
        "endpoint_event_count": sum(1 for event in events if event.get("source_type") == "endpoint_sensor"),
        "process_count": len(process_nodes),
    }


def _collect_targets(
    events: list[dict[str, Any]],
    findings: list[dict[str, Any]],
    timeline: list[dict[str, Any]],
) -> list[str]:
    values: list[Any] = []
    for event in events:
        values.append(_event_target(event))
    for finding in findings:
        values.append(finding.get("target"))
    for item in timeline:
        requested = item.get("requested")
        completed = item.get("completed")
        if isinstance(requested, dict):
            values.append(requested.get("target"))
        if isinstance(completed, dict):
            values.append(completed.get("target"))
    return _sorted_unique(values)


def _collect_external_targets(
    events: list[dict[str, Any]],
    findings: list[dict[str, Any]],
) -> list[str]:
    values: list[Any] = []
    for event in events:
        if event.get("capability") in _EXTERNAL_CAPABILITIES:
            values.append(_event_target(event))
    for finding in findings:
        if finding.get("rule_id") == "external-data-exfiltration":
            values.append(finding.get("target"))
    return _sorted_unique(values)


def _event_target(event: dict[str, Any]) -> str | None:
    arguments = event.get("arguments")
    if not isinstance(arguments, dict):
        return None
    for key in (
        "path",
        "file",
        "filename",
        "command",
        "cmd",
        "url",
        "uri",
        "endpoint",
        "domain",
        "host",
        "webhook",
        "recipient",
        "to",
    ):
        value = arguments.get(key)
        if isinstance(value, str) and value:
            return value
    return None


def _dict_list(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _sorted_unique(values: Any) -> list[str]:
    return sorted({value for value in values if isinstance(value, str) and value})


def _metadata_names(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return _sorted_unique(item.get("name") for item in value if isinstance(item, dict))


def _metadata_workspaces(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return _sorted_unique(
        item.get("root") or item.get("name")
        for item in value
        if isinstance(item, dict)
    )
