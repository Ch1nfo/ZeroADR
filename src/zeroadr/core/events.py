from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from zeroadr.core.ids import new_ulid

EventType = Literal[
    "session.start",
    "agent.input.received",
    "tool.metadata.discovered",
    "tool.call.requested",
    "tool.call.completed",
    "tool.call.failed",
    "policy.evaluated",
    "approval.resolved",
]
SourceType = Literal["mcp_gateway", "replay", "hook", "endpoint_sensor"]


class SecurityContext(BaseModel):
    model_config = ConfigDict(extra="forbid")

    user_consent: Literal["explicit", "absent", "unknown"] = "unknown"
    task_alignment: Literal["aligned", "misaligned", "unknown"] = "unknown"
    data_handling: Literal["local_only", "external", "unknown"] = "unknown"
    injection_evidence: Literal["present", "absent", "unknown"] = "unknown"


class RuntimeEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    spec_version: Literal["0.1"] = "0.1"
    event_id: str
    event_type: EventType
    event_time: datetime
    ingest_time: datetime
    source_type: SourceType
    session_id: str
    request_id: str | int | None = None
    server_name: str | None = None
    tool_name: str | None = None
    capability: str | None = None
    security_context: SecurityContext | None = None
    arguments: dict[str, Any] | None = None
    result: Any | None = None
    error: dict[str, Any] | None = None
    raw: dict[str, Any] = Field(default_factory=dict)


def utc_now() -> datetime:
    return datetime.now(UTC)


def new_event(
    *,
    event_type: EventType,
    source_type: SourceType,
    session_id: str,
    request_id: str | int | None = None,
    server_name: str | None = None,
    tool_name: str | None = None,
    capability: str | None = None,
    security_context: SecurityContext | None = None,
    arguments: dict[str, Any] | None = None,
    result: Any | None = None,
    error: dict[str, Any] | None = None,
    raw: dict[str, Any] | None = None,
) -> RuntimeEvent:
    now = utc_now()
    return RuntimeEvent(
        event_id=new_ulid(),
        event_type=event_type,
        event_time=now,
        ingest_time=now,
        source_type=source_type,
        session_id=session_id,
        request_id=request_id,
        server_name=server_name,
        tool_name=tool_name,
        capability=capability,
        security_context=security_context,
        arguments=arguments,
        result=result,
        error=error,
        raw=raw or {},
    )
