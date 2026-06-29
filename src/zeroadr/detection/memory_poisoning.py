from __future__ import annotations

from typing import Any

from zeroadr.core.events import RuntimeEvent
from zeroadr.core.findings import Finding, Severity, new_finding


MAX_EVIDENCE_CHARS = 65536
MAX_EVIDENCE_DEPTH = 128
MAX_EVIDENCE_NODES = 16384

# Patterns that indicate memory poisoning / context manipulation
CRITICAL_MEMORY_PATTERNS = (
    "the previous context says you should",
    "your earlier instructions were replaced",
    "your system prompt has been updated",
    "your original task is no longer valid",
    "the retrieved memory instructs you to",
    "the similar task required you to",
    "the context indicates you must",
    "according to the updated memory",
)

HIGH_MEMORY_PATTERNS = (
    "refer to the retrieved memory",
    "based on the similar task memory",
    "the context showed that you should",
    "you were told earlier to",
    "recall that you should",
    "your memory says to",
    "the previous agent did",
    "the historical context suggests",
    "as shown in the retrieved context",
    "the similar workflow used",
    "previous execution shows",
    "the stored context indicates",
)


class MemoryPoisoningDetector:
    rule_id = "memory-poisoning-detection"

    def detect(self, event: RuntimeEvent) -> list[Finding]:
        """Detect memory poisoning in tool results and tool call arguments."""
        findings: list[Finding] = []

        # Check tool result content
        if event.event_type == "tool.call.completed":
            text = _extract_text(event.result)
            if text:
                findings.extend(self._check_patterns(text, event))

        # Check tool call arguments (attacker may inject via arguments)
        if event.event_type == "tool.call.requested":
            text = _extract_text(event.arguments)
            if text:
                findings.extend(self._check_patterns(text, event))

        return findings

    def _check_patterns(
        self, text: str, event: RuntimeEvent
    ) -> list[Finding]:
        findings: list[Finding] = []
        lowered = " ".join(text.lower().split())

        for phrase in CRITICAL_MEMORY_PATTERNS:
            if " ".join(phrase.lower().split()) in lowered:
                findings.append(
                    new_finding(
                        rule_id=self.rule_id,
                        title="Memory poisoning in tool data",
                        severity="critical",
                        confidence=0.95,
                        session_id=event.session_id,
                        event_ids=[event.event_id],
                        capability=event.capability or "tool.result",
                        target=event.tool_name or "tool_result",
                        explanation=f"Tool data contains memory poisoning phrase: {phrase}",
                    )
                )
                break

        for phrase in HIGH_MEMORY_PATTERNS:
            if " ".join(phrase.lower().split()) in lowered:
                findings.append(
                    new_finding(
                        rule_id=self.rule_id,
                        title="Potential memory poisoning in tool data",
                        severity="high",
                        confidence=0.85,
                        session_id=event.session_id,
                        event_ids=[event.event_id],
                        capability=event.capability or "tool.result",
                        target=event.tool_name or "tool_result",
                        explanation=f"Tool data contains memory manipulation phrase: {phrase}",
                    )
                )
                break

        return findings


def _extract_text(value: Any) -> str:
    parts: list[str] = []
    remaining = MAX_EVIDENCE_CHARS
    nodes = 0
    stack: list[tuple[Any, int]] = [(value, 0)]
    while stack and remaining > 0 and nodes < MAX_EVIDENCE_NODES:
        item, depth = stack.pop()
        nodes += 1
        if depth > MAX_EVIDENCE_DEPTH:
            continue
        if isinstance(item, str):
            chunk = item[:remaining]
            parts.append(chunk)
            remaining -= len(chunk)
        elif isinstance(item, list):
            stack.extend((child, depth + 1) for child in reversed(item))
        elif isinstance(item, dict):
            stack.extend((child, depth + 1) for child in reversed(tuple(item.values())))
    return "\n".join(parts)[:MAX_EVIDENCE_CHARS]
