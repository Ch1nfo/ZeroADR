from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict

from zeroadr.core.ids import new_ulid

Severity = Literal["low", "medium", "high", "critical"]


class Finding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    finding_id: str
    rule_id: str
    title: str
    severity: Severity
    confidence: float
    session_id: str
    event_ids: list[str]
    capability: str
    target: str
    explanation: str


def new_finding(
    *,
    rule_id: str,
    title: str,
    severity: Severity,
    confidence: float,
    session_id: str,
    event_ids: list[str],
    capability: str,
    target: str,
    explanation: str,
) -> Finding:
    return Finding(
        finding_id=new_ulid(),
        rule_id=rule_id,
        title=title,
        severity=severity,
        confidence=confidence,
        session_id=session_id,
        event_ids=event_ids,
        capability=capability,
        target=target,
        explanation=explanation,
    )
