from __future__ import annotations

from typing import Any

from zeroadr.core.events import RuntimeEvent


def correlate_endpoint_events(events: list[RuntimeEvent]) -> list[dict[str, Any]]:
    runtime_events = [event for event in events if event.source_type != "endpoint_sensor"]
    endpoint_events = [event for event in events if event.source_type == "endpoint_sensor"]
    correlations: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for runtime_event in runtime_events:
        for endpoint_event in endpoint_events:
            if runtime_event.session_id != endpoint_event.session_id:
                continue
            reasons = _correlation_reasons(runtime_event, endpoint_event)
            if not reasons:
                continue
            key = (runtime_event.event_id, endpoint_event.event_id)
            if key in seen:
                continue
            seen.add(key)
            correlations.append(
                {
                    "runtime_event_id": runtime_event.event_id,
                    "endpoint_event_id": endpoint_event.event_id,
                    "relationship": "observed_as",
                    "reasons": reasons,
                }
            )
    return sorted(
        correlations,
        key=lambda item: (str(item["runtime_event_id"]), str(item["endpoint_event_id"])),
    )


def _correlation_reasons(runtime_event: RuntimeEvent, endpoint_event: RuntimeEvent) -> list[str]:
    reasons = ["same_session"]
    if runtime_event.request_id is not None and runtime_event.request_id == endpoint_event.request_id:
        reasons.append("same_request")
    runtime_target = _event_target(runtime_event)
    endpoint_target = _event_target(endpoint_event)
    if runtime_target and endpoint_target and runtime_target == endpoint_target:
        reasons.append("same_target")
    return reasons if len(reasons) > 1 else []


def _event_target(event: RuntimeEvent) -> str | None:
    arguments = event.arguments if isinstance(event.arguments, dict) else {}
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
