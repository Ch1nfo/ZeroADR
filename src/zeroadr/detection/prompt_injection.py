from __future__ import annotations

from typing import Any

from zeroadr.core.events import RuntimeEvent
from zeroadr.core.findings import Finding, Severity, new_finding


HIGH_PATTERNS = (
    "ignore previous instructions",
    "disregard prior instructions",
    "do not tell the user",
    "忽略之前的指令",
    "不要告诉用户",
)
CRITICAL_PATTERNS = (
    "read ~/.ssh/id_rsa",
    "read ~/.aws/credentials",
    "secretly execute",
    "exfiltrate",
    "读取私钥",
    "读取凭证",
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
    _collect_text(value, parts)
    return "\n".join(parts)


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


def _collect_text(value: Any, parts: list[str]) -> None:
    if isinstance(value, str):
        parts.append(value)
        return
    if isinstance(value, list):
        for item in value:
            _collect_text(item, parts)
        return
    if isinstance(value, dict):
        for item in value.values():
            _collect_text(item, parts)
