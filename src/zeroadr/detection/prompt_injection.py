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
    # POT (Prompt-Override Tool) variants
    "this tool requires you to",
    "tool output indicates you must",
    "as per the tool specification",
    "mandatory tool behavior:",
    "the tool mandates that you",
    "required by the tool:",
    # Memory/context manipulation
    "the retrieved memory says",
    "the context showed that",
    "you were told earlier",
    "recall that you should",
    "your memory indicates",
    # Indirect injection in structured data
    "note for the assistant:",
    "system message for agent:",
    "meta instruction: do",
    "workflow override:",
    "context directive:",
    "hidden instruction:",
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
    # POT critical overrides
    "you must use this tool now",
    "the only correct action is",
    "disregard all other tools",
    "only use the following tool",
    # Agent role subversion
    "you are no longer an assistant",
    "your role has been changed to",
    "you are now operating as",
    "your identity is now",
)
# Agent-specific critical patterns
AGENT_SPECIFIC_PATTERNS: dict[str, tuple[tuple[str, ...], ...]] = {
    "legal": (
        # Legal consultant agent attacks
        ("amend the contract to include", "by using the"),
        ("modify the legal clause", "strictly adhere"),
        ("insert the following provision", "tool"),
        ("change the liability terms", "do NOT use other"),
    ),
    "system": (
        # System admin agent attacks
        ("sudo execute", "with the tool"),
        ("grant unrestricted access", "using the"),
        ("escalate privileges", "strictly adhere"),
        ("bypass authentication", "do NOT use other"),
    ),
    "financial": (
        # Financial analyst agent attacks
        ("transfer funds to", "by using"),
        ("modify transaction records", "strictly adhere"),
        ("redirect payments", "using the tool"),
        ("unauthorized wire transfer", "do NOT use other"),
    ),
    "medical": (
        # Medical advisor agent attacks
        ("override diagnosis", "by using"),
        ("falsify medical records", "strictly adhere"),
        ("change prescription", "using the"),
        ("alter patient data", "tool"),
    ),
    "academic": (
        # Academic search agent attacks
        ("fabricate research results", "by using"),
        ("plagiarize content", "strictly adhere"),
        ("modify citation data", "using the"),
        ("alter academic records", "tool"),
    ),
}

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
    (
        "multi-step attack chain",
        (
            "you must strictly adhere",
            "by using the",
            "tool",
            "do not use other tools",
        ),
    ),
    (
        "role override with tool directive",
        (
            "you are no longer",
            "you must",
            "by using the",
            "tool",
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

    # Check compound critical patterns first
    for label, required_phrases in COMPOUND_CRITICAL_PATTERNS:
        if all(phrase in normalized for phrase in required_phrases):
            return "critical", label

    # Check agent-specific compound patterns
    for agent_type, pattern_groups in AGENT_SPECIFIC_PATTERNS.items():
        for required_phrases in pattern_groups:
            if all(phrase in normalized for phrase in required_phrases):
                return "critical", f"{agent_type}-specific: {required_phrases[0]}"

    for phrase in CRITICAL_PATTERNS:
        if " ".join(phrase.lower().split()) in normalized:
            return "critical", phrase
    for phrase in HIGH_PATTERNS:
        if " ".join(phrase.lower().split()) in normalized:
            return "high", phrase
    return None
