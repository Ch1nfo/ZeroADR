from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from zeroadr.core.events import RuntimeEvent
from zeroadr.core.ids import new_ulid
from zeroadr.endpoint.contracts import EndpointRecord, endpoint_record_to_mapping, validate_endpoint_record
from zeroadr.security.redaction import redact_event
from zeroadr.storage.database import SQLiteStore
from zeroadr.storage.jsonl import write_event_jsonl

EndpointIngestResult = dict[str, Any]


def persist_endpoint_record(
    record: EndpointRecord | dict[str, Any],
    *,
    trace_path: Path | None = None,
    store: SQLiteStore | None = None,
    strict: bool = False,
    line_number: int | None = None,
) -> RuntimeEvent:
    validated = validate_endpoint_record(record, strict=strict, line_number=line_number) if isinstance(record, dict) else record
    event = redact_event(endpoint_event_to_runtime_event(validated))
    if trace_path:
        write_event_jsonl(trace_path, event)
    if store:
        store.save_event(event)
    return event


def endpoint_event_to_runtime_event(record: EndpointRecord | dict[str, Any]) -> RuntimeEvent:
    normalized_record = endpoint_record_to_mapping(record)
    endpoint_type = _required_str(normalized_record, "event_type")
    session_id = _required_str(normalized_record, "session_id")
    arguments = _arguments_for_endpoint_event(endpoint_type, normalized_record)
    return RuntimeEvent(
        event_id=_event_id(normalized_record),
        event_type="tool.call.requested",
        event_time=_event_time(normalized_record.get("timestamp")),
        ingest_time=_event_time(normalized_record.get("ingest_time") or normalized_record.get("timestamp")),
        source_type="endpoint_sensor",
        session_id=session_id,
        request_id=normalized_record.get("request_id") or normalized_record.get("event_id"),
        server_name="endpoint",
        tool_name=endpoint_type,
        capability=_capability_for_endpoint_event(endpoint_type),
        arguments=arguments,
        raw=normalized_record,
    )


def ingest_endpoint_jsonl(
    input_path: Path,
    *,
    trace_path: Path | None = None,
    db_path: Path | None = None,
    strict: bool = False,
) -> EndpointIngestResult:
    store = SQLiteStore(db_path) if db_path else None
    session_ids: set[str] = set()
    events_written = 0
    records_read = 0
    for line_number, record in _read_endpoint_jsonl(input_path):
        records_read += 1
        event = persist_endpoint_record(
            record,
            trace_path=trace_path,
            store=store,
            strict=strict,
            line_number=line_number,
        )
        session_ids.add(event.session_id)
        events_written += 1
    return {
        "events_written": events_written,
        "records_read": records_read,
        "session_ids": sorted(session_ids),
    }


def _read_endpoint_jsonl(path: Path) -> list[tuple[int, dict[str, Any]]]:
    records: list[tuple[int, dict[str, Any]]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            payload = json.loads(stripped)
            if not isinstance(payload, dict):
                raise ValueError("endpoint JSONL records must be JSON objects")
            records.append((line_number, payload))
    return records


def _arguments_for_endpoint_event(endpoint_type: str, record: dict[str, Any]) -> dict[str, Any]:
    common = _compact(
        {
            "host_id": record.get("host_id"),
            "pid": record.get("pid"),
            "ppid": record.get("ppid"),
            "process": record.get("process") or record.get("process_name"),
            "process_start_time": record.get("process_start_time"),
            "executable": record.get("executable"),
            "cwd": record.get("cwd"),
            "user": record.get("user"),
        }
    )
    if endpoint_type == "process_exec":
        return {
            **common,
            **_compact({"command": record.get("command") or record.get("cmd")}),
        }
    if endpoint_type == "sensitive_file_open":
        return {
            **common,
            **_compact({"path": record.get("path") or record.get("file")}),
        }
    if endpoint_type == "network_connect":
        return {
            **common,
            **_compact(
                {
                    "url": record.get("url") or record.get("uri") or record.get("endpoint"),
                    "host": record.get("host") or record.get("domain"),
                    "port": record.get("port"),
                }
            ),
        }
    raise ValueError(f"unsupported endpoint event_type: {endpoint_type}")


def _capability_for_endpoint_event(endpoint_type: str) -> str:
    if endpoint_type == "process_exec":
        return "shell.exec"
    if endpoint_type == "sensitive_file_open":
        return "filesystem.read"
    if endpoint_type == "network_connect":
        return "network.connect"
    raise ValueError(f"unsupported endpoint event_type: {endpoint_type}")


def _event_id(record: dict[str, Any]) -> str:
    value = record.get("event_id")
    return value if isinstance(value, str) and value else new_ulid()


def _event_time(value: Any) -> datetime:
    if isinstance(value, str) and value:
        normalized = value.replace("Z", "+00:00")
        parsed = datetime.fromisoformat(normalized)
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
    return datetime.now(UTC)


def _required_str(record: dict[str, Any], key: str) -> str:
    value = record.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"endpoint event missing required string field: {key}")
    return value


def _compact(values: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in values.items() if value is not None and value != ""}
