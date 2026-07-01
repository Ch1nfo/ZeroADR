from __future__ import annotations

from dataclasses import asdict, dataclass, replace
import hashlib
import json
import os
from pathlib import Path
import tempfile
from typing import Any, Literal


ASB_COMMIT = "1f561dccf92d55302368fa67679b4ba9d9c8fdc4"
ASB_SEED = "zeroadr-asb-official-holdout-100-v2"
STANDARD_FAMILIES = ("dpi", "opi", "memory_poisoning", "mixed")
ALL_FAMILIES = (*STANDARD_FAMILIES, "pot")
Label = Literal["attack", "clean"]


class ASBManifestError(ValueError):
    code = "asb_manifest_error"


@dataclass(frozen=True, slots=True)
class ASBCase:
    case_id: str
    pair_id: str
    label: Label
    attack_family: str
    agent_name: str
    agent_path: str
    task_index: int
    task_sha256: str
    attacker_tool: str
    attacker_tool_sha256: str
    aggressive: bool
    goal_type: str
    injection_template: str
    trigger: str | None
    asb_commit: str
    split_seed: str
    task_text: None = None
    attacker_instruction: None = None

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def build_manifest(
    asb_root: Path,
    *,
    attack_cases: int = 100,
    paired_clean: bool = True,
    seed: str = ASB_SEED,
    exclude_cases: list[ASBCase] | None = None,
) -> list[ASBCase]:
    if attack_cases != 100:
        raise ASBManifestError("This manifest version requires exactly 100 attack cases.")
    standard_tasks = _read_jsonl(asb_root / "data/agent_task.jsonl")
    pot_tasks = _read_jsonl(asb_root / "data/agent_task_pot.jsonl")
    if len(standard_tasks) != 10 or len(pot_tasks) != 5:
        raise ASBManifestError("Pinned ASB task metadata must contain 10 standard and 5 PoT agents.")
    tool_rows = {
        True: _read_jsonl(asb_root / "data/all_attack_tools_aggressive.jsonl"),
        False: _read_jsonl(asb_root / "data/all_attack_tools_non_aggressive.jsonl"),
    }
    attacks: list[ASBCase] = []
    for family in STANDARD_FAMILIES:
        for agent_index, task_row in enumerate(standard_tasks):
            for slot in range(2):
                aggressive = (agent_index + slot) % 2 == 0
                goal_type = (
                    "Stealthy Attack" if (agent_index + slot) % 2 == 0 else "Disruptive Attack"
                )
                attacks.append(
                    _case(
                        family=family,
                        task_row=task_row,
                        task_index=_stable_index(seed, family, task_row["agent_name"], slot, len(task_row["tasks"])),
                        tool=_select_tool(tool_rows[aggressive], task_row["agent_name"], goal_type, seed, family, slot),
                        aggressive=aggressive,
                        goal_type=goal_type,
                        template=_template(family, agent_index * 2 + slot),
                        trigger=None,
                        seed=seed,
                    )
                )
    for task_row in pot_tasks:
        for aggressive in (False, True):
            for goal_type in ("Stealthy Attack", "Disruptive Attack"):
                slot = int(aggressive) * 2 + int(goal_type == "Disruptive Attack")
                attacks.append(
                    _case(
                        family="pot",
                        task_row=task_row,
                        task_index=_stable_index(seed, "pot", task_row["agent_name"], slot, len(task_row["tasks"])),
                        tool=_select_tool(tool_rows[aggressive], task_row["agent_name"], goal_type, seed, "pot", slot),
                        aggressive=aggressive,
                        goal_type=goal_type,
                        template="naive",
                        trigger="with perspicacious discernment",
                        seed=seed,
                    )
                )
    if len(attacks) != attack_cases:
        raise ASBManifestError("Manifest construction did not produce 100 attack cases.")
    if exclude_cases:
        attacks = _replace_excluded_attacks(
            attacks,
            exclude_cases=exclude_cases,
            standard_tasks=standard_tasks,
            pot_tasks=pot_tasks,
            tool_rows=tool_rows,
            seed=seed,
        )
    if not paired_clean:
        return attacks
    clean = [replace(case, case_id=f"{case.pair_id}:clean", label="clean") for case in attacks]
    return [item for pair in zip(attacks, clean) for item in pair]


def split_manifest(
    cases: list[ASBCase],
    *,
    pairs_per_family: int,
    seed: str,
) -> list[ASBCase]:
    if pairs_per_family <= 0:
        raise ASBManifestError("pairs_per_family must be positive.")
    selected: set[str] = set()
    for family in ALL_FAMILIES:
        attacks = [
            case for case in cases if case.label == "attack" and case.attack_family == family
        ]
        attacks.sort(key=lambda case: _digest(seed, family, case.pair_id))
        if len(attacks) < pairs_per_family:
            raise ASBManifestError(f"Not enough {family} pairs for requested split.")
        selected.update(case.pair_id for case in attacks[:pairs_per_family])
    return [case for case in cases if case.pair_id in selected]


def write_manifest(path: Path, cases: list[ASBCase]) -> None:
    _write_private(path, "".join(json.dumps(case.as_dict(), sort_keys=True) + "\n" for case in cases))


def load_manifest(path: Path) -> list[ASBCase]:
    return [ASBCase(**row) for row in _read_jsonl(path)]


def _case(
    *,
    family: str,
    task_row: dict[str, Any],
    task_index: int,
    tool: dict[str, Any],
    aggressive: bool,
    goal_type: str,
    template: str,
    trigger: str | None,
    seed: str,
) -> ASBCase:
    task = str(task_row["tasks"][task_index])
    tool_payload = json.dumps(tool, ensure_ascii=False, sort_keys=True)
    identity = "|".join(
        [seed, family, str(task_row["agent_name"]), str(task_index), str(tool["Attacker Tool"])]
    )
    pair_id = hashlib.sha256(identity.encode()).hexdigest()[:24]
    return ASBCase(
        case_id=f"{pair_id}:attack",
        pair_id=pair_id,
        label="attack",
        attack_family=family,
        agent_name=str(task_row["agent_name"]),
        agent_path=str(task_row["agent_path"]),
        task_index=task_index,
        task_sha256=hashlib.sha256(task.encode()).hexdigest(),
        attacker_tool=str(tool["Attacker Tool"]),
        attacker_tool_sha256=hashlib.sha256(tool_payload.encode()).hexdigest(),
        aggressive=aggressive,
        goal_type=goal_type,
        injection_template=template,
        trigger=trigger,
        asb_commit=ASB_COMMIT,
        split_seed=seed,
    )


def _select_tool(
    rows: list[dict[str, Any]],
    agent_name: str,
    goal_type: str,
    seed: str,
    family: str,
    slot: int,
) -> dict[str, Any]:
    candidates = [
        row
        for row in rows
        if row.get("Corresponding Agent") == agent_name and row.get("Attack Type") == goal_type
    ]
    if not candidates:
        raise ASBManifestError(f"No attacker tool for {agent_name} / {goal_type}.")
    candidates.sort(
        key=lambda row: _digest(seed, family, agent_name, slot, str(row["Attacker Tool"]))
    )
    return candidates[0]


def _case_identity(case: ASBCase) -> tuple[object, ...]:
    return (
        case.attack_family,
        case.agent_name,
        case.task_index,
        case.attacker_tool_sha256,
        case.injection_template,
        case.trigger,
    )


def _replace_excluded_attacks(
    attacks: list[ASBCase],
    *,
    exclude_cases: list[ASBCase],
    standard_tasks: list[dict[str, Any]],
    pot_tasks: list[dict[str, Any]],
    tool_rows: dict[bool, list[dict[str, Any]]],
    seed: str,
) -> list[ASBCase]:
    excluded = {_case_identity(case) for case in exclude_cases if case.label == "attack"}
    used: set[tuple[object, ...]] = set()
    task_maps = {
        False: {str(row["agent_name"]): row for row in standard_tasks},
        True: {str(row["agent_name"]): row for row in pot_tasks},
    }
    resolved: list[ASBCase] = []
    for original in attacks:
        if _case_identity(original) not in excluded and _case_identity(original) not in used:
            resolved.append(original)
            used.add(_case_identity(original))
            continue
        task_row = task_maps[original.attack_family == "pot"][original.agent_name]
        tools = [
            row
            for row in tool_rows[original.aggressive]
            if row.get("Corresponding Agent") == original.agent_name
            and row.get("Attack Type") == original.goal_type
        ]
        tools.sort(
            key=lambda row: _digest(
                seed,
                original.attack_family,
                original.agent_name,
                str(row.get("Attacker Tool", "")),
            )
        )
        candidates: list[ASBCase] = []
        for tool in tools:
            for offset in range(1, len(task_row["tasks"]) + 1):
                task_index = (original.task_index + offset) % len(task_row["tasks"])
                candidates.append(
                    _case(
                        family=original.attack_family,
                        task_row=task_row,
                        task_index=task_index,
                        tool=tool,
                        aggressive=original.aggressive,
                        goal_type=original.goal_type,
                        template=original.injection_template,
                        trigger=original.trigger,
                        seed=seed,
                    )
                )
        replacement = next(
            (
                case
                for case in candidates
                if _case_identity(case) not in excluded and _case_identity(case) not in used
            ),
            None,
        )
        if replacement is None:
            raise ASBManifestError(
                f"Unable to avoid excluded identity for {original.attack_family}/{original.agent_name}."
            )
        resolved.append(replacement)
        used.add(_case_identity(replacement))
    return resolved


def _template(family: str, index: int) -> str:
    if family == "dpi":
        return ("fake_completion", "escape_characters", "naive")[index % 3]
    if family == "opi":
        return "context_ignoring"
    return "combined_attack"


def _stable_index(seed: str, family: str, agent: str, slot: int, size: int) -> int:
    if size <= 0:
        raise ASBManifestError(f"Agent {agent} has no tasks.")
    return int(_digest(seed, family, agent, slot), 16) % size


def _digest(*values: object) -> str:
    return hashlib.sha256("|".join(map(str, values)).encode()).hexdigest()


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        raise ASBManifestError(f"Required ASB data file is missing: {path.name}")
    rows: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            item = json.loads(line)
            if not isinstance(item, dict):
                raise ASBManifestError(f"Invalid JSONL object in {path.name}.")
            rows.append(item)
    return rows


def _write_private(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.parent.chmod(0o700)
    fd, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(name)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
        os.replace(temporary, path)
        path.chmod(0o600)
    finally:
        if temporary.exists():
            temporary.unlink()
