from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any

from zeroadr.reconstruction.summary import summary_from_context
from zeroadr.security.redaction import redact_value

MAX_FINDINGS = 20
MAX_EVENTS = 40
MAX_DECISIONS = 40
MAX_COLLECTION_ITEMS = 40
MAX_TEXT_CHARS = 2048
MAX_PAYLOAD_BYTES = 64 * 1024

_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}


@dataclass(frozen=True)
class PreparedTriagePayload:
    payload: dict[str, Any]
    finding_ids: list[str]
    event_ids: list[str]
    input_sha256: str


def build_triage_payload(context: dict[str, Any]) -> PreparedTriagePayload:
    findings = sorted(
        _dict_list(context.get("findings")),
        key=lambda item: (
            _SEVERITY_RANK.get(str(item.get("severity")), 99),
            str(item.get("finding_id", "")),
        ),
    )[:MAX_FINDINGS]
    related_event_ids = {
        event_id
        for finding in findings
        for event_id in finding.get("event_ids", [])
        if isinstance(event_id, str)
    }
    finding_ids = {
        finding_id
        for finding in findings
        if isinstance((finding_id := finding.get("finding_id")), str)
    }
    events = [
        event
        for event in _dict_list(context.get("events"))
        if event.get("event_id") in related_event_ids
    ][:MAX_EVENTS]
    decisions = [
        decision
        for decision in _dict_list(context.get("policy_decisions"))
        if decision.get("event_id") in related_event_ids
        or bool(finding_ids & _string_set(decision.get("finding_ids")))
    ][:MAX_DECISIONS]
    base_payload: dict[str, Any] = {
        "session_id": context.get("session_id"),
        "summary": summary_from_context(context),
        "risk_summary": context.get("risk_summary", {}),
        "findings": findings,
        "events": events,
        "policy_decisions": decisions,
    }
    payload = _fit_payload(redact_value(_drop_raw(base_payload)))
    canonical = _canonical_json(payload)
    return PreparedTriagePayload(
        payload=payload,
        finding_ids=[
            str(item["finding_id"])
            for item in _dict_list(payload.get("findings"))
            if isinstance(item.get("finding_id"), str)
        ],
        event_ids=[
            str(item["event_id"])
            for item in _dict_list(payload.get("events"))
            if isinstance(item.get("event_id"), str)
        ],
        input_sha256=hashlib.sha256(canonical).hexdigest(),
    )


def _fit_payload(value: Any) -> dict[str, Any]:
    for text_limit in (MAX_TEXT_CHARS, 1024, 512, 256, 128):
        candidate = _bound_value(value, text_limit=text_limit)
        if isinstance(candidate, dict) and len(_canonical_json(candidate)) <= MAX_PAYLOAD_BYTES:
            return candidate
    candidate = _bound_value(value, text_limit=128)
    if not isinstance(candidate, dict):
        raise ValueError("triage payload must be an object")
    for collection_name in ("policy_decisions", "events", "findings"):
        collection = candidate.get(collection_name)
        if not isinstance(collection, list):
            continue
        while collection and len(_canonical_json(candidate)) > MAX_PAYLOAD_BYTES:
            collection.pop()
    if len(_canonical_json(candidate)) > MAX_PAYLOAD_BYTES:
        raise ValueError("triage payload exceeds 64 KiB after deterministic truncation")
    return candidate


def _drop_raw(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            str(key): _drop_raw(item)
            for key, item in value.items()
            if str(key).lower() != "raw"
        }
    if isinstance(value, list):
        return [_drop_raw(item) for item in value]
    if isinstance(value, tuple):
        return [_drop_raw(item) for item in value]
    return value


def _bound_value(value: Any, *, text_limit: int) -> Any:
    if isinstance(value, dict):
        return {
            _truncate_text(str(key), text_limit): _bound_value(item, text_limit=text_limit)
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [
            _bound_value(item, text_limit=text_limit)
            for item in value[:MAX_COLLECTION_ITEMS]
        ]
    if isinstance(value, str):
        return _truncate_text(value, text_limit)
    return value


def _truncate_text(value: str, limit: int) -> str:
    if len(value) <= limit:
        return value
    marker = "...[TRUNCATED]"
    return value[: limit - len(marker)] + marker


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _dict_list(value: object) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _string_set(value: object) -> set[str]:
    if not isinstance(value, list):
        return set()
    return {item for item in value if isinstance(item, str)}
