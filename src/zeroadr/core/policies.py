from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict

from zeroadr.core.ids import new_ulid

PolicyAction = Literal["allow", "alert", "block", "require_approval"]


class PolicyDecision(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decision_id: str
    policy_id: str | None
    action: PolicyAction
    reason: str
    session_id: str
    event_id: str
    finding_ids: list[str]
    created_at: datetime


def new_policy_decision(
    *,
    policy_id: str | None,
    action: PolicyAction,
    reason: str,
    session_id: str,
    event_id: str,
    finding_ids: list[str],
) -> PolicyDecision:
    return PolicyDecision(
        decision_id=new_ulid(),
        policy_id=policy_id,
        action=action,
        reason=reason,
        session_id=session_id,
        event_id=event_id,
        finding_ids=finding_ids,
        created_at=datetime.now(UTC),
    )
