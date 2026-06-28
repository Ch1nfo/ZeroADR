from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict

from zeroadr.core.ids import new_ulid

ApprovalStatus = Literal["pending", "approved", "denied", "expired"]
ResolvedApprovalStatus = Literal["approved", "denied"]


class ApprovalRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    approval_id: str
    decision_id: str
    session_id: str
    event_id: str
    request_id: str | int | None = None
    policy_id: str | None = None
    reason: str
    finding_ids: list[str]
    tool_name: str | None = None
    capability: str | None = None
    arguments: dict[str, Any] | None = None
    status: ApprovalStatus
    created_at: datetime
    resolved_at: datetime | None = None
    resolved_by: str | None = None
    resolution_comment: str | None = None


def new_approval_request(
    *,
    decision_id: str,
    session_id: str,
    event_id: str,
    request_id: str | int | None,
    policy_id: str | None,
    reason: str,
    finding_ids: list[str],
    tool_name: str | None,
    capability: str | None,
    arguments: dict[str, Any] | None,
) -> ApprovalRequest:
    return ApprovalRequest(
        approval_id=new_ulid(),
        decision_id=decision_id,
        session_id=session_id,
        event_id=event_id,
        request_id=request_id,
        policy_id=policy_id,
        reason=reason,
        finding_ids=finding_ids,
        tool_name=tool_name,
        capability=capability,
        arguments=arguments,
        status="pending",
        created_at=datetime.now(UTC),
    )
