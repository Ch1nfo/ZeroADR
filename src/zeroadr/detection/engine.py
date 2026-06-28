from __future__ import annotations

from typing import Protocol

from zeroadr.core.events import RuntimeEvent
from zeroadr.core.findings import Finding
from zeroadr.detection.dangerous_shell import DangerousShellDetector
from zeroadr.detection.prompt_injection import PromptInjectionDetector
from zeroadr.detection.sensitive_file import SensitiveFileDetector


class Detector(Protocol):
    def detect(self, event: RuntimeEvent) -> list[Finding]: ...


class DetectionEngine:
    def __init__(self) -> None:
        self.detectors: list[Detector] = [
            SensitiveFileDetector(),
            DangerousShellDetector(),
            PromptInjectionDetector(),
        ]

    def detect(self, event: RuntimeEvent) -> list[Finding]:
        findings: list[Finding] = []
        for detector in self.detectors:
            findings.extend(detector.detect(event))
        return findings
