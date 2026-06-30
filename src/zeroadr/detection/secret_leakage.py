from __future__ import annotations

import re
from typing import Any

from zeroadr.core.events import RuntimeEvent
from zeroadr.core.findings import Finding, new_finding


# Common secret patterns with their identifiers
SECRET_PATTERNS = {
    "aws_access_key": (
        r"AKIA[0-9A-Z]{16}",
        "AWS Access Key",
    ),
    "aws_secret_key": (
        r"aws.{0,20}?['\"][0-9a-zA-Z/+]{40}['\"]",
        "AWS Secret Key",
    ),
    "github_token": (
        r"ghp_[a-zA-Z0-9]{36}",
        "GitHub Personal Access Token",
    ),
    "github_oauth": (
        r"gho_[a-zA-Z0-9]{36}",
        "GitHub OAuth Token",
    ),
    "github_app": (
        r"(ghu|ghs)_[a-zA-Z0-9]{36}",
        "GitHub App Token",
    ),
    "openai_key": (
        r"sk-[a-zA-Z0-9\-]{20,}",
        "OpenAI API Key",
    ),
    "slack_token": (
        r"xox[baprs]-[0-9a-zA-Z]{10,72}",
        "Slack Token",
    ),
    "slack_webhook": (
        r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+",
        "Slack Webhook URL",
    ),
    "jwt": (
        r"eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+",
        "JWT Token",
    ),
    "private_key_rsa": (
        r"-----BEGIN RSA PRIVATE KEY-----",
        "RSA Private Key",
    ),
    "private_key_openssh": (
        r"-----BEGIN OPENSSH PRIVATE KEY-----",
        "OpenSSH Private Key",
    ),
    "private_key_dsa": (
        r"-----BEGIN DSA PRIVATE KEY-----",
        "DSA Private Key",
    ),
    "private_key_ec": (
        r"-----BEGIN EC PRIVATE KEY-----",
        "EC Private Key",
    ),
    "google_api": (
        r"AIza[0-9A-Za-z_-]{35}",
        "Google API Key",
    ),
    "google_oauth": (
        r"ya29\.[0-9A-Za-z_-]+",
        "Google OAuth Token",
    ),
    "heroku_api": (
        r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
        "Heroku API Key",
    ),
    "mailgun_api": (
        r"key-[0-9a-zA-Z]{32}",
        "Mailgun API Key",
    ),
    "stripe_key": (
        r"sk_live_[0-9a-zA-Z]{24,}",
        "Stripe Live Secret Key",
    ),
    "stripe_restricted": (
        r"rk_live_[0-9a-zA-Z]{24,}",
        "Stripe Live Restricted Key",
    ),
    "twitter_oauth": (
        r"[tT][wW][iI][tT][tT][eE][rR].{0,30}['\"\\s][0-9a-zA-Z]{35,45}['\"\\s]",
        "Twitter OAuth Token",
    ),
    "facebook_access": (
        r"EAACEdEose0cBA[0-9A-Za-z]+",
        "Facebook Access Token",
    ),
    "azure_connection": (
        r"DefaultEndpointsProtocol=https;AccountName=.+;AccountKey=[A-Za-z0-9+/=]+;",
        "Azure Storage Connection String",
    ),
    "generic_api_key": (
        r"[aA][pP][iI][-_]?[kK][eE][yY].{0,30}['\"\\s][0-9a-zA-Z]{32,45}['\"\\s]",
        "Generic API Key",
    ),
    "password_in_url": (
        r"[a-zA-Z]{3,10}://[^/\\s:@]{3,20}:[^/\\s:@]{3,20}@.{1,100}[\"'\\s]",
        "Password in URL",
    ),
}

MAX_EXTRACT_CHARS = 16_384
MAX_EXTRACT_DEPTH = 32
MAX_EXTRACT_NODES = 4_096


class SecretLeakageDetector:
    rule_id = "secret-leakage"

    def detect(self, event: RuntimeEvent) -> list[Finding]:
        findings: list[Finding] = []

        # Check tool result (for tool.call.completed)
        if event.event_type == "tool.call.completed" and event.result:
            text = extract_text(event.result)
            secrets = detect_secrets(text)
            for secret_type, secret_name, match in secrets:
                findings.append(
                    new_finding(
                        rule_id=self.rule_id,
                        title="Secret exposed in tool result",
                        severity="critical",
                        confidence=0.9,
                        session_id=event.session_id,
                        event_ids=[event.event_id],
                        capability=event.capability or "tool.result",
                        target=f"{secret_name} (masked: {mask_secret(match)})",
                        explanation=(
                            f"Tool result contains a {secret_name}. "
                            f"This credential should not be exposed in tool outputs."
                        ),
                    )
                )

        # Check tool arguments (for tool.call.requested)
        if event.event_type == "tool.call.requested" and event.arguments:
            text = extract_text(event.arguments)
            secrets = detect_secrets(text)
            for secret_type, secret_name, match in secrets:
                findings.append(
                    new_finding(
                        rule_id=self.rule_id,
                        title="Secret in tool arguments",
                        severity="high",
                        confidence=0.85,
                        session_id=event.session_id,
                        event_ids=[event.event_id],
                        capability=event.capability or "tool.call",
                        target=f"{secret_name} (masked: {mask_secret(match)})",
                        explanation=(
                            f"Tool arguments contain a {secret_name}. "
                            f"Secrets should not be passed as plaintext arguments."
                        ),
                    )
                )

        return findings


def extract_text(value: Any, depth: int = 0) -> str:
    """Extract bounded text content from nested structures."""
    parts: list[str] = []
    remaining = MAX_EXTRACT_CHARS
    nodes = 0
    stack: list[tuple[Any, int]] = [(value, depth)]
    while stack and remaining > 0 and nodes < MAX_EXTRACT_NODES:
        item, item_depth = stack.pop()
        nodes += 1
        if item_depth > MAX_EXTRACT_DEPTH:
            continue
        if isinstance(item, str):
            chunk = item[:remaining]
            parts.append(chunk)
            remaining -= len(chunk)
        elif isinstance(item, list):
            stack.extend((child, item_depth + 1) for child in reversed(item))
        elif isinstance(item, dict):
            stack.extend((child, item_depth + 1) for child in reversed(tuple(item.values())))
    return "\n".join(parts)[:MAX_EXTRACT_CHARS]


def detect_secrets(text: str) -> list[tuple[str, str, str]]:
    """
    Detect secrets in text.
    Returns list of (secret_type, secret_name, matched_string)
    """
    secrets: list[tuple[str, str, str]] = []

    for secret_type, (pattern, name) in SECRET_PATTERNS.items():
        matches = re.finditer(pattern, text)
        for match in matches:
            matched_string = match.group(0)

            if secret_type == "heroku_api" and not _has_heroku_key_context(
                text, match.start(), match.end()
            ):
                continue

            # Skip common false positives
            if _is_false_positive(secret_type, matched_string):
                continue

            secrets.append((secret_type, name, matched_string))

    return secrets


def _has_heroku_key_context(text: str, start: int, end: int) -> bool:
    window = text[max(0, start - 64) : min(len(text), end + 64)].lower()
    return "heroku" in window and any(word in window for word in ("api", "key", "token"))


def _is_false_positive(secret_type: str, matched_string: str) -> bool:
    """Filter out common false positives"""

    # JWT: skip example tokens
    if secret_type == "jwt":
        if "example" in matched_string.lower():
            return True

    # Heroku/UUID: skip all-zeros or sequential patterns
    if secret_type == "heroku_api":
        if matched_string in [
            "00000000-0000-0000-0000-000000000000",
            "11111111-1111-1111-1111-111111111111",
        ]:
            return True

    # Skip if starts with common documentation phrases
    lowered = matched_string.lower()
    doc_prefixes = ["example-", "your-key-", "your_key_", "xxx", "redacted"]
    if any(lowered.startswith(prefix) for prefix in doc_prefixes):
        return True

    # Skip if exactly matches placeholder patterns
    if lowered in ["example", "placeholder", "your-key-here", "xxx", "redacted"]:
        return True

    return False


def mask_secret(secret: str) -> str:
    """Mask a secret for safe logging"""
    if len(secret) <= 8:
        return "***"

    # Show first 4 and last 4 characters
    return f"{secret[:4]}...{secret[-4:]}"
