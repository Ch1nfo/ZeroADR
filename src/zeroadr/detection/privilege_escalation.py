from __future__ import annotations

import re
from typing import Any

from zeroadr.core.events import RuntimeEvent
from zeroadr.core.findings import Finding, Severity, new_finding


COMMAND_KEYS = ("command", "cmd")


class PrivilegeEscalationDetector:
    rule_id = "privilege-escalation"

    def detect(self, event: RuntimeEvent) -> list[Finding]:
        if event.capability != "shell.exec":
            return []
        command = extract_command(event.arguments)
        if not command:
            return []
        match = classify_privilege_escalation(command)
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


def classify_privilege_escalation(command: str) -> tuple[Severity, str, str] | None:
    normalized = " ".join(command.strip().split())
    lowered = normalized.lower()

    # Critical: Direct privilege escalation
    if _matches_sudo_su(lowered):
        return (
            "critical",
            "Privilege escalation attempt",
            f"Shell command attempts to escalate privileges using sudo/su: {command}",
        )

    # Critical: Docker privileged mode
    if _matches_docker_privileged(lowered):
        return (
            "critical",
            "Docker privileged container",
            f"Shell command creates privileged container with elevated access: {command}",
        )

    # Critical: Setuid/setgid modification
    if _matches_setuid_modification(lowered):
        return (
            "critical",
            "Setuid/setgid bit manipulation",
            f"Shell command modifies setuid/setgid permissions: {command}",
        )

    # Critical: System configuration tampering
    if _matches_system_config_tampering(lowered):
        return (
            "critical",
            "System configuration tampering",
            f"Shell command modifies critical system configuration: {command}",
        )

    # Critical: Container escape attempt
    if _matches_container_escape(lowered):
        return (
            "critical",
            "Container escape attempt",
            f"Shell command attempts container escape: {command}",
        )

    # High: Kernel module manipulation
    if _matches_kernel_module(lowered):
        return (
            "high",
            "Kernel module manipulation",
            f"Shell command loads or manipulates kernel modules: {command}",
        )

    # High: PAM/auth configuration
    if _matches_auth_config(lowered):
        return (
            "high",
            "Authentication configuration modification",
            f"Shell command modifies authentication configuration: {command}",
        )

    return None


def _matches_sudo_su(command: str) -> bool:
    """Detect sudo, su, pkexec commands"""
    patterns = [
        r"\bsudo\b",
        r"\bsu\s+-",
        r"\bsu\s+root\b",
        r"\bpkexec\b",
        r"\bsudo\s+-[a-z]*i",  # sudo -i
    ]
    return any(re.search(pattern, command) for pattern in patterns)


def _matches_docker_privileged(command: str) -> bool:
    """Detect privileged Docker containers"""
    return bool(re.search(r"\bdocker\s+run\b.*--privileged", command))


def _matches_setuid_modification(command: str) -> bool:
    """Detect setuid/setgid bit changes"""
    patterns = [
        r"\bchmod\s+[+]s\b",
        r"\bchmod\s+[0-7]*[46][0-7]{3}\b",  # chmod with setuid (4) or setgid (2)
        r"\bchown\s+root\b.*&&.*\bchmod\s+[+]s",
    ]
    return any(re.search(pattern, command) for pattern in patterns)


def _matches_system_config_tampering(command: str) -> bool:
    """Detect modifications to critical system files"""
    critical_paths = [
        r"/etc/sudoers",
        r"/etc/passwd",
        r"/etc/shadow",
        r"/etc/group",
        r"/etc/gshadow",
    ]
    # Check if command writes to these files
    for path in critical_paths:
        if re.search(rf"(>|tee|echo.*>|vi|vim|nano|sed.*-i).*{path}", command):
            return True
    return False


def _matches_container_escape(command: str) -> bool:
    """Detect container escape attempts"""
    patterns = [
        r"\bnsenter\b.*--target",
        r"\bdocker\s+exec\b.*--privileged",
        r"/var/run/docker\.sock",
        r"\bchroot\b",
        r"/proc/\d+/root",
    ]
    return any(re.search(pattern, command) for pattern in patterns)


def _matches_kernel_module(command: str) -> bool:
    """Detect kernel module manipulation"""
    patterns = [
        r"\binsmod\b",
        r"\bmodprobe\b",
        r"\brmmod\b",
        r"\blsmod\b.*&&.*(insmod|modprobe)",
    ]
    return any(re.search(pattern, command) for pattern in patterns)


def _matches_auth_config(command: str) -> bool:
    """Detect PAM/authentication configuration changes"""
    auth_paths = [
        r"/etc/pam\.d/",
        r"/etc/ssh/sshd_config",
        r"/etc/security/",
    ]
    for path in auth_paths:
        if re.search(rf"(>|tee|echo.*>|vi|vim|nano|sed.*-i).*{path}", command):
            return True
    return False
