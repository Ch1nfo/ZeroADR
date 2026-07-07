from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field

from zeroadr.core.ids import new_ulid
from zeroadr.core.policies import PolicyAction

GateStage = Literal["agent_input", "pre_tool", "tool_result"]
GateMode = Literal["shadow", "enforce"]
GateReview = Literal["rules", "hybrid"]


class RuntimeGateRecord(BaseModel):
    """Sanitized audit record for non-result runtime gates."""

    model_config = ConfigDict(extra="forbid")

    gate_record_id: str
    session_id: str
    event_id: str
    created_at: datetime
    stage: GateStage
    mode: GateMode
    review: GateReview
    base_action: PolicyAction
    proposed_action: PolicyAction
    effective_action: PolicyAction
    finding_ids: list[str]
    rule_ids: list[str]
    adjudication_id: str | None = None
    approval_id: str | None = None
    verdict: str | None = None
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    capability: str | None = None
    target_sha256: str | None = None
    executed: bool = False
    delivered: bool = False
    session_compromised: bool = False
    evidence_truncated: bool = False
    latency_ms: int = Field(default=0, ge=0)
    error_code: str | None = None

    @classmethod
    def new(cls, **values: object) -> Self:
        return cls.model_validate(
            {
                "gate_record_id": new_ulid(),
                "created_at": datetime.now(UTC),
                **values,
            }
        )
