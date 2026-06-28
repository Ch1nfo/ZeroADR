from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, ValidationError

EndpointEventType = Literal["process_exec", "sensitive_file_open", "network_connect"]


class EndpointRecordBase(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["0.1"] = "0.1"
    event_type: EndpointEventType
    event_id: str
    timestamp: str
    session_id: str
    host_id: str | None = None
    pid: int | None = None
    ppid: int | None = None
    process: str | None = None
    process_start_time: str | None = None
    executable: str | None = None
    cwd: str | None = None
    user: str | None = None


class ProcessExecRecord(EndpointRecordBase):
    event_type: Literal["process_exec"] = "process_exec"
    command: str


class SensitiveFileOpenRecord(EndpointRecordBase):
    event_type: Literal["sensitive_file_open"] = "sensitive_file_open"
    path: str


class NetworkConnectRecord(EndpointRecordBase):
    event_type: Literal["network_connect"] = "network_connect"
    url: str | None = None
    host: str | None = None
    domain: str | None = None
    port: int | None = None


EndpointRecord = ProcessExecRecord | SensitiveFileOpenRecord | NetworkConnectRecord


class EndpointValidationError(ValueError):
    pass


def validate_endpoint_record(
    record: dict[str, Any],
    *,
    strict: bool = False,
    line_number: int | None = None,
) -> EndpointRecord | dict[str, Any]:
    if not strict:
        return endpoint_record_from_mapping(record) if "schema_version" in record else dict(record)
    _require_explicit_schema_version(record, line_number=line_number)
    _require_network_destination(record, line_number=line_number)
    try:
        return endpoint_record_from_mapping(record)
    except (ValidationError, ValueError) as exc:
        raise EndpointValidationError(_message(str(exc), line_number=line_number)) from exc


def endpoint_record_from_mapping(record: dict[str, Any]) -> EndpointRecord:
    event_type = record.get("event_type")
    if event_type == "process_exec":
        return ProcessExecRecord.model_validate(record)
    if event_type == "sensitive_file_open":
        return SensitiveFileOpenRecord.model_validate(record)
    if event_type == "network_connect":
        return NetworkConnectRecord.model_validate(record)
    raise ValueError(f"unsupported endpoint event_type: {event_type}")


def endpoint_record_to_mapping(record: EndpointRecord | dict[str, Any]) -> dict[str, Any]:
    if isinstance(record, BaseModel):
        return record.model_dump(mode="json", exclude_none=True)
    return dict(record)


def _require_explicit_schema_version(record: dict[str, Any], *, line_number: int | None) -> None:
    if record.get("schema_version") != "0.1":
        raise EndpointValidationError(
            _message("endpoint record requires schema_version: 0.1", line_number=line_number)
        )


def _require_network_destination(record: dict[str, Any], *, line_number: int | None) -> None:
    if record.get("event_type") != "network_connect":
        return
    if not any(isinstance(record.get(key), str) and record.get(key) for key in ("url", "host", "domain")):
        raise EndpointValidationError(
            _message(
                "network_connect requires at least one of url, host, or domain",
                line_number=line_number,
            )
        )


def _message(message: str, *, line_number: int | None) -> str:
    if line_number is None:
        return message
    return f"line {line_number}: {message}"
