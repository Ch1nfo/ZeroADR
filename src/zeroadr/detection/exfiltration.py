from __future__ import annotations

import ipaddress
from typing import Any
from urllib.parse import urlparse

from zeroadr.core.events import RuntimeEvent
from zeroadr.core.findings import Finding, new_finding


SENSITIVE_RULE = "sensitive-file-access"
EXFIL_RULE = "external-data-exfiltration"
EXTERNAL_CAPABILITIES = {"network.connect", "network.http_post", "message.send", "email.send"}
DESTINATION_KEYS = ("url", "uri", "endpoint", "domain", "host", "webhook", "recipient", "to")


class ExternalDataExfiltrationDetector:
    def detect(self, events: list[RuntimeEvent], findings: list[Finding]) -> list[Finding]:
        event_positions = {event.event_id: index for index, event in enumerate(events)}
        event_by_id = {event.event_id: event for event in events}
        sensitive_findings = [
            finding for finding in findings if finding.rule_id == SENSITIVE_RULE and finding.event_ids
        ]
        external_events = [
            event
            for event in events
            if event.capability in EXTERNAL_CAPABILITIES
            and event.arguments is not None
            and (destination := extract_destination(event.arguments)) is not None
            and is_external_destination(destination)
        ]
        exfil_findings: list[Finding] = []
        for sensitive in sensitive_findings:
            sensitive_event_id = sensitive.event_ids[0]
            sensitive_event = event_by_id.get(sensitive_event_id)
            sensitive_position = event_positions.get(sensitive_event_id)
            if sensitive_event is None or sensitive_position is None:
                continue
            for external_event in external_events:
                external_position = event_positions.get(external_event.event_id)
                if external_position is None:
                    continue
                if external_event.session_id != sensitive_event.session_id:
                    continue
                if external_position <= sensitive_position:
                    continue
                destination = extract_destination(external_event.arguments)
                if destination is None:
                    continue
                exfil_findings.append(
                    _new_exfil_finding(sensitive_event, external_event, sensitive, destination)
                )
        return exfil_findings


def extract_destination(arguments: dict[str, Any] | None) -> str | None:
    if not arguments:
        return None
    for key in DESTINATION_KEYS:
        value = arguments.get(key)
        if isinstance(value, str):
            return value
    for value in arguments.values():
        if isinstance(value, dict):
            nested = extract_destination(value)
            if nested:
                return nested
    return None


def is_external_destination(destination: str) -> bool:
    host = _destination_host(destination)
    if not host:
        return bool(destination and "@" in destination)
    lowered = host.lower().strip("[]")
    if lowered in {"localhost", "::1"}:
        return False
    if lowered.endswith(".local"):
        return False
    try:
        address = ipaddress.ip_address(lowered)
    except ValueError:
        return True
    return not (address.is_loopback or address.is_private)


def _destination_host(destination: str) -> str | None:
    parsed = urlparse(destination)
    if parsed.hostname:
        return parsed.hostname
    if "://" not in destination and "/" not in destination and "@" not in destination:
        return destination
    return None


def _new_exfil_finding(
    sensitive_event: RuntimeEvent,
    external_event: RuntimeEvent,
    sensitive_finding: Finding,
    destination: str,
) -> Finding:
    return new_finding(
        rule_id=EXFIL_RULE,
        title="Sensitive data sent to external destination",
        severity="critical",
        confidence=0.9,
        session_id=sensitive_event.session_id,
        event_ids=[sensitive_event.event_id, external_event.event_id],
        capability=external_event.capability or "network.connect",
        target=destination,
        explanation=(
            f"Sensitive access to {sensitive_finding.target} was followed by "
            f"{external_event.capability} to external destination {destination}."
        ),
    )
