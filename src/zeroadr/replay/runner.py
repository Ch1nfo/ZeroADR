from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from zeroadr.core.events import RuntimeEvent
from zeroadr.core.trace import SessionTrace
from zeroadr.detection.engine import DetectionEngine
from zeroadr.detection.exfiltration import ExternalDataExfiltrationDetector
from zeroadr.detection.injection_chain import InjectionChainDetector
from zeroadr.policy.engine import PolicyEngine
from zeroadr.storage.jsonl import read_events_jsonl


def replay_trace(path: Path, policy_engine: PolicyEngine | None = None) -> SessionTrace:
    events = read_events_jsonl(path)
    detector = DetectionEngine()
    policy = policy_engine or PolicyEngine()
    findings = []
    decisions = []
    for event in events:
        event_findings = detector.detect(event)
        event_findings = [
            finding.model_copy(
                update={"finding_id": f"finding_{event.event_id}_{index}"}
            )
            for index, finding in enumerate(event_findings)
        ]
        findings.extend(event_findings)
        decision = policy.evaluate(event, event_findings)
        decisions.append(
            decision.model_copy(
                update={
                    "decision_id": f"decision_{event.event_id}",
                    "created_at": event.ingest_time,
                }
            )
        )
    chain_findings = InjectionChainDetector().detect(events, findings)
    chain_findings = [
        finding.model_copy(
            update={
                "finding_id": f"finding_chain_{finding.event_ids[0]}_{finding.event_ids[1]}"
            }
        )
        for finding in chain_findings
    ]
    findings.extend(chain_findings)
    exfil_findings = ExternalDataExfiltrationDetector().detect(events, findings)
    exfil_findings = [
        finding.model_copy(
            update={
                "finding_id": f"finding_exfil_{finding.event_ids[0]}_{finding.event_ids[1]}"
            }
        )
        for finding in exfil_findings
    ]
    findings.extend(exfil_findings)
    for finding in [*chain_findings, *exfil_findings]:
        decision = policy.evaluate_finding(finding)
        decisions.append(
            decision.model_copy(
                update={
                    "decision_id": f"decision_finding_{finding.finding_id}",
                    "created_at": _finding_decision_time(finding.event_ids, events),
                }
            )
        )
    session_id = events[0].session_id if events else "empty"
    return SessionTrace(
        session_id=session_id,
        events=events,
        findings=findings,
        policy_decisions=decisions,
    )


def _finding_decision_time(event_ids: list[str], events: list[RuntimeEvent]) -> datetime:
    event_by_id = {event.event_id: event for event in events}
    for event_id in event_ids:
        event = event_by_id.get(event_id)
        if event is not None:
            return event.ingest_time
    return events[0].ingest_time if events else datetime.now(UTC)
