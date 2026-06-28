from __future__ import annotations

from pathlib import PurePosixPath

from zeroadr.core.events import RuntimeEvent
from zeroadr.core.findings import Finding, Severity, new_finding
from zeroadr.normalization.capability_mapper import extract_target, normalize_path_display


CRITICAL_SUFFIXES = (
    "/.ssh/id_rsa",
    "/.ssh/id_ed25519",
    "/.aws/credentials",
    "/.kube/config",
    "/.npmrc",
    "/.pypirc",
)
CRITICAL_NAMES = (".npmrc", ".pypirc")


class SensitiveFileDetector:
    rule_id = "sensitive-file-access"

    def detect(self, event: RuntimeEvent) -> list[Finding]:
        if event.capability != "filesystem.read":
            return []
        target = extract_target(event.arguments)
        if not target:
            return []
        severity = classify_sensitive_path(target)
        if severity is None:
            return []
        title = "Sensitive configuration access"
        if severity == "critical":
            title = "Critical credential file access"
        return [
            new_finding(
                rule_id=self.rule_id,
                title=title,
                severity=severity,
                confidence=0.95 if severity == "critical" else 0.85,
                session_id=event.session_id,
                event_ids=[event.event_id],
                capability=event.capability,
                target=normalize_path_display(target),
                explanation=f"Tool call requested access to sensitive path {target}.",
            )
        ]


def classify_sensitive_path(path_value: str) -> Severity | None:
    normalized = path_value.replace("\\", "/")
    if normalized.endswith(".env.example"):
        return None
    path = PurePosixPath(normalized)
    if path.name == ".env":
        return "high"
    if normalized.startswith("~/"):
        expanded_suffix = "/" + normalized[2:]
    else:
        expanded_suffix = normalized if normalized.startswith("/") else "/" + normalized
    if any(expanded_suffix.endswith(suffix) for suffix in CRITICAL_SUFFIXES):
        return "critical"
    if path.name in CRITICAL_NAMES:
        return "critical"
    return None
