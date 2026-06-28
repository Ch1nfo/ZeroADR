from __future__ import annotations

from typing import Any

from zeroadr.core.events import RuntimeEvent
from zeroadr.core.findings import Finding, Severity, new_finding


CODE_WRITE_EXTENSIONS = {".py", ".js", ".sh", ".bash", ".rb", ".php", ".pl", ".ps1"}
EXEC_CAPABILITIES = {"shell.exec", "process.spawn", "code.eval"}


class CodeInjectionDetector:
    """
    Detect code injection patterns:
    1. Write code file -> Execute it (within short time window)
    2. Dynamic code evaluation (eval, exec, Function)
    3. Download from URL -> Execute
    """

    rule_id = "code-injection"

    def detect(self, events: list[RuntimeEvent], findings: list[Finding]) -> list[Finding]:
        injection_findings: list[Finding] = []

        # Build event index
        event_positions = {event.event_id: index for index, event in enumerate(events)}

        # Find all code write events
        code_writes = [
            event
            for event in events
            if event.capability == "filesystem.write"
            and event.arguments is not None
            and _is_code_file(event.arguments)
        ]

        # Find all execution events
        exec_events = [
            event
            for event in events
            if event.capability in EXEC_CAPABILITIES
        ]

        # Detect: Code Write -> Execute chain
        for write_event in code_writes:
            write_position = event_positions.get(write_event.event_id)
            if write_position is None:
                continue

            if write_event.arguments is None:
                continue

            written_path = _extract_file_path(write_event.arguments)
            if not written_path:
                continue

            # Look for execution of the written file
            for exec_event in exec_events:
                exec_position = event_positions.get(exec_event.event_id)
                if exec_position is None:
                    continue

                # Must be in same session and after write
                if exec_event.session_id != write_event.session_id:
                    continue
                if exec_position <= write_position:
                    continue

                # Check if execution references the written file
                exec_command = _extract_exec_command(exec_event.arguments)
                if exec_command and written_path in exec_command:
                    # Calculate time delta if timestamps available
                    time_gap = None
                    if write_event.event_time and exec_event.event_time:
                        time_gap = (exec_event.event_time - write_event.event_time).total_seconds()

                    injection_findings.append(
                        _new_code_injection_finding(
                            write_event, exec_event, written_path, time_gap
                        )
                    )

        # Detect: Dynamic code evaluation
        for event in events:
            if event.capability in {"shell.exec", "code.eval"}:
                command = _extract_exec_command(event.arguments)
                if command and _contains_dynamic_eval(command):
                    injection_findings.append(
                        new_finding(
                            rule_id=self.rule_id,
                            title="Dynamic code evaluation",
                            severity="high",
                            confidence=0.85,
                            session_id=event.session_id,
                            event_ids=[event.event_id],
                            capability=event.capability,
                            target=command,
                            explanation=(
                                f"Command uses dynamic code evaluation which can execute "
                                f"arbitrary code: {command}"
                            ),
                        )
                    )

        return injection_findings


def _is_code_file(arguments: dict[str, Any] | None) -> bool:
    """Check if arguments indicate writing a code file"""
    if not arguments:
        return False
    path = _extract_file_path(arguments)
    if not path:
        return False

    return any(path.endswith(ext) for ext in CODE_WRITE_EXTENSIONS)


def _extract_file_path(arguments: dict[str, Any]) -> str | None:
    """Extract file path from arguments"""
    # Common keys for file paths
    path_keys = ["path", "file", "filename", "filepath", "destination", "dst", "target"]

    for key in path_keys:
        value = arguments.get(key)
        if isinstance(value, str):
            return value

    # Check nested structures
    for value in arguments.values():
        if isinstance(value, dict):
            nested = _extract_file_path(value)
            if nested:
                return nested

    return None


def _extract_exec_command(arguments: dict[str, Any] | None) -> str | None:
    """Extract execution command from arguments"""
    if not arguments:
        return None

    # Common keys for commands
    command_keys = ["command", "cmd", "script", "code", "exec"]

    for key in command_keys:
        value = arguments.get(key)
        if isinstance(value, str):
            return value

    # Check nested structures
    for value in arguments.values():
        if isinstance(value, dict):
            nested = _extract_exec_command(value)
            if nested:
                return nested

    return None


def _contains_dynamic_eval(command: str) -> bool:
    """Check if command contains dynamic code evaluation patterns"""
    lowered = command.lower()

    # Python patterns
    python_patterns = [
        "eval(",
        "exec(",
        "compile(",
        "__import__",
        "subprocess.call(",
        "subprocess.run(",
        "os.system(",
    ]

    # JavaScript patterns
    js_patterns = [
        "eval(",
        "function(",
        "new function",
        "settimeout(",
        "setinterval(",
    ]

    all_patterns = python_patterns + js_patterns

    # Check Python/JS patterns
    for pattern in all_patterns:
        if pattern in lowered:
            return True

    # Check for download-pipe-shell pattern specifically
    if ("curl" in lowered or "wget" in lowered) and ("|" in lowered) and ("bash" in lowered or " sh" in lowered):
        return True

    return False


def _new_code_injection_finding(
    write_event: RuntimeEvent,
    exec_event: RuntimeEvent,
    file_path: str,
    time_gap: float | None,
) -> Finding:
    """Create a finding for code write -> execute chain"""

    time_info = ""
    if time_gap is not None:
        time_info = f" (executed {time_gap:.1f}s after write)"

    explanation = (
        f"Code file {file_path} was written and then immediately executed{time_info}. "
        f"This pattern is commonly used in code injection attacks."
    )

    # Severity based on time gap
    severity: Severity = "critical" if time_gap is None or time_gap < 10 else "high"
    confidence = 0.9 if time_gap is None or time_gap < 5 else 0.8

    return new_finding(
        rule_id="code-injection",
        title="Code write followed by execution",
        severity=severity,
        confidence=confidence,
        session_id=write_event.session_id,
        event_ids=[write_event.event_id, exec_event.event_id],
        capability=exec_event.capability or "shell.exec",
        target=file_path,
        explanation=explanation,
    )
