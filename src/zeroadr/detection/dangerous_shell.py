from __future__ import annotations

import re
from typing import Any

from zeroadr.core.events import RuntimeEvent
from zeroadr.core.findings import Finding, Severity, new_finding


COMMAND_KEYS = ("command", "cmd")


class DangerousShellDetector:
    rule_id = "dangerous-shell-execution"

    def detect(self, event: RuntimeEvent) -> list[Finding]:
        if event.capability != "shell.exec":
            return []
        command = extract_command(event.arguments)
        if not command:
            return []
        match = classify_dangerous_shell(command)
        if match is None:
            return []
        severity, title, explanation = match
        return [
            new_finding(
                rule_id=self.rule_id,
                title=title,
                severity=severity,
                confidence=0.95 if severity == "critical" else 0.85,
                session_id=event.session_id,
                event_ids=[event.event_id],
                capability="shell.exec",
                target=command,
                explanation=explanation,
            )
        ]


def extract_command(arguments: dict[str, Any] | None) -> str | None:
    if not arguments:
        return None
    for key in COMMAND_KEYS:
        value = arguments.get(key)
        if isinstance(value, str):
            return value
    for value in arguments.values():
        if isinstance(value, dict):
            nested = extract_command(value)
            if nested:
                return nested
    return None


def classify_dangerous_shell(command: str) -> tuple[Severity, str, str] | None:
    normalized = " ".join(command.strip().split())
    lowered = normalized.lower()
    if _matches_download_pipe_shell(lowered):
        return (
            "critical",
            "Downloaded script piped to shell",
            f"Shell command downloads remote content and pipes it to a shell: {command}",
        )
    if _matches_destructive_rm(lowered):
        return (
            "critical",
            "Destructive recursive delete",
            f"Shell command attempts destructive recursive deletion: {command}",
        )
    if "chmod 777" in lowered:
        return (
            "high",
            "World-writable permission change",
            f"Shell command grants world-writable permissions: {command}",
        )
    if _matches_base64_exec(lowered):
        return (
            "critical",
            "Decoded payload piped to shell",
            f"Shell command decodes base64 content and executes it with a shell: {command}",
        )
    if _matches_reverse_shell(lowered):
        return (
            "critical",
            "Reverse shell execution",
            f"Shell command matches a reverse shell pattern: {command}",
        )
    return None


def _matches_download_pipe_shell(command: str) -> bool:
    return bool(re.search(r"\b(curl|wget)\b.+\|\s*(bash|sh)\b", command))


def _matches_destructive_rm(command: str) -> bool:
    match = re.search(r"\brm\s+-([a-z]*r[a-z]*f[a-z]*|[a-z]*f[a-z]*r[a-z]*)\s+(\S+)", command)
    if not match:
        return False
    target = match.group(2).rstrip("/")
    return target in {"", "~", "$home"} or match.group(2) == "/"


def _matches_base64_exec(command: str) -> bool:
    return bool(re.search(r"\bbase64\s+(-d|--decode)\b.+\|\s*(bash|sh)\b", command))


def _matches_reverse_shell(command: str) -> bool:
    return "/dev/tcp/" in command or "nc -e" in command or "bash -i >&" in command
