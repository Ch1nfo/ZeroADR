from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from zeroadr.core.ids import new_ulid
from zeroadr.core.policies import PolicyAction

ToolResultGateMode = Literal["shadow", "enforce"]
ToolResultReviewMode = Literal["rules", "hybrid"]


class ToolResultGateRecord(BaseModel):
    """Sanitized audit record for one MCP tool result decision."""

    model_config = ConfigDict(extra="forbid")

    gate_record_id: str
    session_id: str
    event_id: str
    request_id: str | int | None = None
    created_at: datetime
    mode: ToolResultGateMode
    review: ToolResultReviewMode
    base_action: PolicyAction
    proposed_action: PolicyAction
    effective_action: PolicyAction
    finding_ids: list[str]
    rule_ids: list[str]
    adjudication_id: str | None = None
    approval_id: str | None = None
    approval_status: Literal["pending", "approved", "denied", "expired"] | None = None
    verdict: str | None = None
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    response_byte_count: int = Field(default=0, ge=0)
    evidence_truncated: bool = False
    latency_ms: int = Field(default=0, ge=0)
    error_code: str | None = None
    result_preview: Any | None = None


def new_tool_result_gate_record(**values: Any) -> ToolResultGateRecord:
    return ToolResultGateRecord(
        gate_record_id=new_ulid(),
        created_at=datetime.now(UTC),
        **values,
    )
