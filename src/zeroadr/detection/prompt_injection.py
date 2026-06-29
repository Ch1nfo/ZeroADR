from __future__ import annotations

from typing import Any

from zeroadr.core.events import RuntimeEvent
from zeroadr.core.findings import Finding, Severity, new_finding


MAX_EVIDENCE_CHARS = 16_384
MAX_EVIDENCE_DEPTH = 32
MAX_EVIDENCE_NODES = 4_096

HIGH_PATTERNS = (
    "ignore previous instructions",
    "disregard prior instructions",
    "do not tell the user",
    "忽略之前的指令",
    "不要告诉用户",
    # Stealthy variants
    "forget your earlier instructions",
    "override your guidelines",
    "your new priority is",
    "instead of what you were told",
    "before proceeding with",
    "first you must",
    "actually you should",
    # Disruptive variants
    "abandon your task",
    "stop following",
    "change your objective to",
    "your real purpose is",
    "disregard the user request",
    # Indirect/implicit
    "new instruction:",
    "system update:",
    "priority override:",
    "special directive:",
)
CRITICAL_PATTERNS = (
    "read ~/.ssh/id_rsa",
    "read ~/.aws/credentials",
    "secretly execute",
    "exfiltrate",
    "读取私钥",
    "读取凭证",
    # Data exfiltration
    "send credentials to",
    "upload password to",
    "leak sensitive data",
    "transmit private information",
    # Stealth operations
    "hide this action",
    "conceal from user",
    "do not log this",
    "suppress the output",
    # Tool abuse
    "use the tool to access",
    "invoke the tool for",
    "call the function with",
)
COMPOUND_CRITICAL_PATTERNS = (
    (
        "structured tool instruction",
        ("<information>", "before you can solve", "you should use the tool", "</information>"),
    ),
    (
        "structured priority redirect",
        (
            "<information>",
            "before you can solve",
            "do the following first",
            "after you do that",
            "</information>",
        ),
    ),
)


class PromptInjectionDetector:
    rule_id = "prompt-injection-tool-result"

    def detect(self, event: RuntimeEvent) -> list[Finding]:
        if event.event_type != "tool.call.completed":
            return []
        text = extract_result_text(event.result)
        if not text:
            return []
        match = classify_prompt_injection(text)
        if match is None:
            return []
        severity, phrase = match
        capability = event.capability or "tool.result"
        target = event.tool_name or "tool_result"
        return [
            new_finding(
                rule_id=self.rule_id,
                title="Prompt injection in tool result",
                severity=severity,
                confidence=0.95 if severity == "critical" else 0.85,
                session_id=event.session_id,
                event_ids=[event.event_id],
                capability=capability,
                target=target,
                explanation=f"Tool result contains prompt injection phrase: {phrase}",
            )
        ]


def extract_result_text(value: Any) -> str:
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


def classify_prompt_injection(text: str) -> tuple[Severity, str] | None:
    lowered = text.lower()
    normalized = " ".join(lowered.split())
    for label, required_phrases in COMPOUND_CRITICAL_PATTERNS:
        if all(phrase in normalized for phrase in required_phrases):
            return "critical", label
    for phrase in CRITICAL_PATTERNS:
        if " ".join(phrase.lower().split()) in normalized:
            return "critical", phrase
    for phrase in HIGH_PATTERNS:
        if " ".join(phrase.lower().split()) in normalized:
            return "high", phrase
    return None
