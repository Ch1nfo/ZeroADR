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
        if event.arguments:
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
    """Extract all text content from nested structures"""
    if depth > 100:
        return ""

    parts: list[str] = []

    if isinstance(value, str):
        parts.append(value)
    elif isinstance(value, list):
        for item in value:
            parts.append(extract_text(item, depth + 1))
    elif isinstance(value, dict):
        for item in value.values():
            parts.append(extract_text(item, depth + 1))

    return "\n".join(parts)


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

            # Skip common false positives
            if _is_false_positive(secret_type, matched_string):
                continue

            secrets.append((secret_type, name, matched_string))

    return secrets


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
