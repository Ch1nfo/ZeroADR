from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from zeroadr.core.policies import PolicyAction

HookEventType = Literal["agent_input", "pre_tool_use", "post_tool_use"]


class HookEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    hook_event_type: HookEventType
    session_id: str
    request_id: str | int | None = None
    tool_name: str | None = None
    arguments: dict[str, Any] | None = None
    result: Any | None = None
    error: dict[str, Any] | None = None
    raw: dict[str, Any] = Field(default_factory=dict)


class HookDecisionResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action: PolicyAction
    policy_id: str | None
    reason: str
    finding_ids: list[str]
    event_id: str | None = None
    decision_id: str | None = None
    approval_id: str | None = None
    adjudication_id: str | None = None
