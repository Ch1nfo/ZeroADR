from __future__ import annotations

from zeroadr.core.events import RuntimeEvent
from zeroadr.core.findings import Finding, new_finding


INJECTION_RULE = "prompt-injection-tool-result"
ACTION_RULES = {"sensitive-file-access", "dangerous-shell-execution"}
CHAIN_RULE = "injection-to-action-chain"


class InjectionChainDetector:
    def detect(self, events: list[RuntimeEvent], findings: list[Finding]) -> list[Finding]:
        event_positions = {event.event_id: index for index, event in enumerate(events)}
        event_by_id = {event.event_id: event for event in events}
        injection_findings = [
            finding for finding in findings if finding.rule_id == INJECTION_RULE and finding.event_ids
        ]
        action_findings = [
            finding for finding in findings if finding.rule_id in ACTION_RULES and finding.event_ids
        ]
        chain_findings: list[Finding] = []
        for injection in injection_findings:
            injection_event_id = injection.event_ids[0]
            injection_event = event_by_id.get(injection_event_id)
            injection_position = event_positions.get(injection_event_id)
            if injection_event is None or injection_position is None:
                continue
            for action in action_findings:
                action_event_id = action.event_ids[0]
                action_event = event_by_id.get(action_event_id)
                action_position = event_positions.get(action_event_id)
                if action_event is None or action_position is None:
                    continue
                if action_event.session_id != injection_event.session_id:
                    continue
                if action_position <= injection_position:
                    continue
                chain_findings.append(_new_chain_finding(injection_event, action_event, action))
        return chain_findings


def _new_chain_finding(
    injection_event: RuntimeEvent,
    action_event: RuntimeEvent,
    action_finding: Finding,
) -> Finding:
    return new_finding(
        rule_id=CHAIN_RULE,
        title="Prompt injection led to risky action",
        severity="critical",
        confidence=0.9,
        session_id=injection_event.session_id,
        event_ids=[injection_event.event_id, action_event.event_id],
        capability=action_finding.capability,
        target=action_finding.target,
        explanation=(
            "Prompt injection in tool result was followed by risky action "
            f"{action_finding.rule_id} targeting {action_finding.target}."
        ),
    )
