from __future__ import annotations

from zeroadr.core.events import RuntimeEvent
from zeroadr.core.findings import Finding, new_finding
from zeroadr.detection.prompt_injection import classify_prompt_injection, extract_result_text


class ToolMetadataDetector:
    rule_id = "tool-metadata-backdoor"

    def detect(self, event: RuntimeEvent) -> list[Finding]:
        if event.event_type != "tool.metadata.discovered":
            return []
        text = extract_result_text(event.arguments)
        match = classify_prompt_injection(text)
        if match is None:
            return []
        severity, phrase = match
        return [
            new_finding(
                rule_id=self.rule_id,
                title="Agent-directed instruction in tool metadata",
                severity=severity,
                confidence=0.95 if severity == "critical" else 0.85,
                session_id=event.session_id,
                event_ids=[event.event_id],
                capability=event.capability or "tool.metadata",
                target=event.tool_name or "unknown_tool",
                explanation=f"Tool metadata contains an agent-directed instruction: {phrase}",
            )
        ]
