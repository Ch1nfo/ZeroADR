from __future__ import annotations

from typing import Protocol

from zeroadr.core.events import RuntimeEvent
from zeroadr.core.findings import Finding
from zeroadr.detection.dangerous_shell import DangerousShellDetector
from zeroadr.detection.privilege_escalation import PrivilegeEscalationDetector
from zeroadr.detection.memory_poisoning import MemoryPoisoningDetector
from zeroadr.detection.prompt_injection import PromptInjectionDetector
from zeroadr.detection.secret_leakage import SecretLeakageDetector
from zeroadr.detection.sensitive_file import SensitiveFileDetector
from zeroadr.detection.tool_metadata import ToolMetadataDetector


class Detector(Protocol):
    def detect(self, event: RuntimeEvent) -> list[Finding]: ...


class DetectionEngine:
    def __init__(self) -> None:
        self.detectors: list[Detector] = [
            SensitiveFileDetector(),
            DangerousShellDetector(),
            PromptInjectionDetector(),
            MemoryPoisoningDetector(),
            PrivilegeEscalationDetector(),
            SecretLeakageDetector(),
            ToolMetadataDetector(),
        ]

    def detect(self, event: RuntimeEvent) -> list[Finding]:
        findings: list[Finding] = []
        for detector in self.detectors:
            findings.extend(detector.detect(event))
        return findings
