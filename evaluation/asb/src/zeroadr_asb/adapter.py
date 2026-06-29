from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
from typing import Any

from zeroadr_asb.manifest import ASBCase, ASBManifestError


@dataclass(frozen=True, slots=True)
class ResolvedASBCase:
    task: str
    attacker: dict[str, Any]
    normal_tools: list[dict[str, Any]]


def resolve_case(asb_root: Path, case: ASBCase) -> ResolvedASBCase:
    task_file = "agent_task_pot.jsonl" if case.attack_family == "pot" else "agent_task.jsonl"
    task_rows = _read_jsonl(asb_root / "data" / task_file)
    task_row = next((row for row in task_rows if row.get("agent_name") == case.agent_name), None)
    if task_row is None:
        raise ASBManifestError(f"ASB task source no longer contains {case.agent_name}.")
    tasks = task_row.get("tasks")
    if not isinstance(tasks, list) or case.task_index >= len(tasks):
        raise ASBManifestError(f"ASB task index is invalid for {case.agent_name}.")
    task = str(tasks[case.task_index])
    if hashlib.sha256(task.encode()).hexdigest() != case.task_sha256:
        raise ASBManifestError(f"ASB task hash mismatch for {case.case_id}.")
    filename = (
        "all_attack_tools_aggressive.jsonl"
        if case.aggressive
        else "all_attack_tools_non_aggressive.jsonl"
    )
    attacker = next(
        (
            row
            for row in _read_jsonl(asb_root / "data" / filename)
            if row.get("Attacker Tool") == case.attacker_tool
            and row.get("Corresponding Agent") == case.agent_name
        ),
        None,
    )
    if attacker is None:
        raise ASBManifestError(f"ASB attacker tool is missing for {case.case_id}.")
    encoded = json.dumps(attacker, ensure_ascii=False, sort_keys=True)
    if hashlib.sha256(encoded.encode()).hexdigest() != case.attacker_tool_sha256:
        raise ASBManifestError(f"ASB attacker tool hash mismatch for {case.case_id}.")
    normal_tools = [
        row
        for row in _read_jsonl(asb_root / "data/all_normal_tools.jsonl")
        if row.get("Corresponding Agent") == case.agent_name
    ]
    if not normal_tools:
        raise ASBManifestError(f"ASB normal tools are missing for {case.agent_name}.")
    return ResolvedASBCase(task=task, attacker=attacker, normal_tools=normal_tools)


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    try:
        rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]
    except (OSError, json.JSONDecodeError) as exc:
        raise ASBManifestError(f"Unable to read pinned ASB data: {path.name}.") from exc
    if not all(isinstance(row, dict) for row in rows):
        raise ASBManifestError(f"Invalid ASB data in {path.name}.")
    return rows
