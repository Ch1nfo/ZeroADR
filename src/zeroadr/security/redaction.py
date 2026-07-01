from __future__ import annotations

import re
from typing import Any

from zeroadr.core.events import RuntimeEvent

REDACTED = "[REDACTED]"

SENSITIVE_KEY_PARTS = (
    "token",
    "api_key",
    "apikey",
    "password",
    "secret",
    "authorization",
    "credential",
    "private_key",
    "privatekey",
)

PRIVATE_KEY_PATTERN = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
    re.DOTALL,
)
INLINE_SECRET_PATTERNS = (
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{12,}"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{16,}"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
)


def redact_event(event: RuntimeEvent) -> RuntimeEvent:
    return event.model_copy(
        update={
            "arguments": redact_value(event.arguments),
            "result": redact_value(event.result),
            "error": redact_value(event.error),
            "raw": redact_value(event.raw),
        }
    )


def redact_value(value: Any) -> Any:
    if isinstance(value, dict):
        redacted: dict[str, Any] = {}
        for key, item in value.items():
            key_text = str(key)
            if _is_sensitive_key(key_text):
                redacted[key_text] = REDACTED
            else:
                redacted[key_text] = redact_value(item)
        return redacted
    if isinstance(value, list):
        return [redact_value(item) for item in value]
    if isinstance(value, tuple):
        return tuple(redact_value(item) for item in value)
    if isinstance(value, str):
        return _redact_string(value)
    return value


def _is_sensitive_key(key: str) -> bool:
    normalized = key.lower().replace("-", "_")
    return any(part in normalized for part in SENSITIVE_KEY_PARTS)


def _redact_string(value: str) -> str:
    if PRIVATE_KEY_PATTERN.search(value):
        return REDACTED
    for pattern in INLINE_SECRET_PATTERNS:
        value = pattern.sub(REDACTED, value)
    lines = value.splitlines()
    if not lines:
        return value
    redacted_lines = [_redact_env_line(line) for line in lines]
    separator = "\n" if "\n" in value else ""
    return separator.join(redacted_lines)


def _redact_env_line(line: str) -> str:
    key, separator, raw_value = line.partition("=")
    if not separator:
        return line
    if _is_sensitive_key(key.strip()):
        return f"{key}{separator}{REDACTED}"
    return f"{key}{separator}{raw_value}"
