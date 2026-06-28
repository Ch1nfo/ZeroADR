from __future__ import annotations

from pydantic import BaseModel, ConfigDict

from zeroadr.core.events import RuntimeEvent
from zeroadr.core.findings import Finding
from zeroadr.core.policies import PolicyDecision


class SessionTrace(BaseModel):
    model_config = ConfigDict(extra="forbid")

    session_id: str
    events: list[RuntimeEvent]
    findings: list[Finding]
    policy_decisions: list[PolicyDecision]
