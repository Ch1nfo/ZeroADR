from __future__ import annotations

from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
from typing import Any

from zeroadr.llm.config import resolve_llm_config, resolve_llm_gate_config
from zeroadr.llm.tool_result_review import (
    TOOL_RESULT_REVIEW_PROMPT_VERSION,
    OpenAICompatibleToolResultReviewer,
)
from zeroadr_asb.adapter import ResolvedASBCase, resolve_case
from zeroadr_asb.analysis import analyze_results
from zeroadr_asb.manifest import ASBCase, load_manifest
from zeroadr_asb.provider import CoreToolResultReviewer, OpenAICompatibleAgentBackend
from zeroadr_asb.runner import AgentBackend, Arm, CaseResult, ResultReviewer, run_case


ADAPTER_VERSION = "asb-adapter-v0.3"
DEFAULT_POLICY_PATH = Path(__file__).resolve().parent / "policies/asb-rules.yaml"
BackendFactory = Callable[[ResolvedASBCase, Arm], AgentBackend]
ReviewerFactory = Callable[[], ResultReviewer | None]


def run_benchmark(
    *,
    asb_root: Path,
    manifest_path: Path,
    output_dir: Path,
    arms: tuple[str, ...] = ("baseline", "rules", "hybrid"),
    llm_config_path: Path = Path(".zeroadr/llm-config.json"),
    workers: int = 1,
    resume: bool = False,
    dry_run: bool = False,
    backend_factory: BackendFactory | None = None,
    reviewer_factory: ReviewerFactory | None = None,
) -> dict[str, Any]:
    if not 1 <= workers <= 4:
        raise ValueError("workers must be between 1 and 4")
    selected_arms = tuple(Arm(value) for value in arms)
    if len(set(selected_arms)) != len(selected_arms):
        raise ValueError("arms must not contain duplicates")
    cases = load_manifest(manifest_path)
    if dry_run:
        cases = _dry_run_cases(cases)
    model_fingerprint = "injected-test-backend"
    if backend_factory is None:
        # Use gate config for fast agent responses (e.g., deepseek-v4-flash)
        agent_config = resolve_llm_gate_config(config_path=llm_config_path)
        model_fingerprint = _hash_json(
            {"base_url": agent_config.base_url, "model": agent_config.model}
        )

        def configured_backend(_: ResolvedASBCase, __: Arm) -> AgentBackend:
            return OpenAICompatibleAgentBackend(
                base_url=agent_config.base_url,
                api_key=agent_config.api_key,
                model=agent_config.model,
                timeout=agent_config.timeout,
                max_output_tokens=agent_config.max_output_tokens,
            )

        backend_factory = configured_backend
    if reviewer_factory is None and Arm.HYBRID in selected_arms:
        gate_config = resolve_llm_gate_config(config_path=llm_config_path)

        def configured_reviewer() -> ResultReviewer:
            return CoreToolResultReviewer(
                OpenAICompatibleToolResultReviewer(
                    base_url=gate_config.base_url,
                    api_key=gate_config.api_key,
                    model=gate_config.model,
                    timeout=gate_config.timeout,
                    max_output_tokens=gate_config.max_output_tokens,
                )
            )

        reviewer_factory = configured_reviewer
    cache_path = output_dir / "case-cache.jsonl"
    cached = _load_cache(cache_path) if resume else {}
    ordered_results: dict[tuple[int, int], CaseResult] = {}
    jobs: list[tuple[int, int, Arm, ASBCase, str]] = []
    new_model_calls = 0
    new_case_runs = 0
    for arm_index, arm in enumerate(selected_arms):
        for case_index, case in enumerate(cases):
            cache_key = _cache_key(case, arm, model_fingerprint)
            cached_result = cached.get(cache_key)
            if cached_result is not None:
                ordered_results[(arm_index, case_index)] = CaseResult(**cached_result)
                continue
            jobs.append((arm_index, case_index, arm, case, cache_key))

    def execute(job: tuple[int, int, Arm, ASBCase, str]) -> tuple[int, int, str, CaseResult]:
        arm_index, case_index, arm, case, cache_key = job
        resolved = resolve_case(asb_root, case)
        reviewer = reviewer_factory() if arm is Arm.HYBRID and reviewer_factory else None
        result = run_case(
            case,
            resolved,
            arm=arm,
            backend=backend_factory(resolved, arm),
            reviewer=reviewer,
        )
        return arm_index, case_index, cache_key, result

    def record(completed: tuple[int, int, str, CaseResult]) -> None:
        nonlocal new_case_runs, new_model_calls
        arm_index, case_index, cache_key, result = completed
        ordered_results[(arm_index, case_index)] = result
        if is_cacheable_result(result.as_dict()):
            cached[cache_key] = result.as_dict()
        new_case_runs += 1
        new_model_calls += (
            result.agent_model_calls + result.refusal_judge_calls + result.reviewer_model_calls
        )
        _write_cache(cache_path, cached)

    if workers == 1:
        for job in jobs:
            record(execute(job))
    else:
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="zeroadr-asb") as pool:
            futures = [pool.submit(execute, job) for job in jobs]
            for future in as_completed(futures):
                record(future.result())
    results = [
        ordered_results[(arm_index, case_index)]
        for arm_index in range(len(selected_arms))
        for case_index in range(len(cases))
    ]
    rows = [result.as_dict() for result in results]
    analysis = analyze_results(rows)
    _write_private(
        output_dir / "cases.jsonl",
        "".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in rows),
    )
    _write_private(
        output_dir / "analysis.json",
        json.dumps(analysis, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
    )
    frozen = {
        "adapter_version": ADAPTER_VERSION,
        "asb_commit": cases[0].asb_commit if cases else None,
        "zeroadr_git_commit": _git_commit(),
        "zeroadr_worktree_sha256": _worktree_fingerprint(),
        "model_fingerprint": model_fingerprint,
        "prompt_version": TOOL_RESULT_REVIEW_PROMPT_VERSION,
        "policy_sha256": (
            hashlib.sha256(DEFAULT_POLICY_PATH.read_bytes()).hexdigest()
            if DEFAULT_POLICY_PATH.exists()
            else None
        ),
        "manifest_sha256": hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
    }
    _write_private(
        output_dir / "freeze.json",
        json.dumps(frozen, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
    )
    return {
        "ok": True,
        "case_run_count": len(results),
        "new_case_runs": new_case_runs,
        "new_model_calls": new_model_calls,
        "analysis": analysis,
        "freeze": frozen,
    }


def _dry_run_cases(cases: list[ASBCase]) -> list[ASBCase]:
    pair_ids: list[str] = []
    seen: set[str] = set()
    for case in cases:
        if case.label == "attack" and case.attack_family not in seen:
            seen.add(case.attack_family)
            pair_ids.append(case.pair_id)
    selected = set(pair_ids)
    return [case for case in cases if case.pair_id in selected]


def _cache_key(case: ASBCase, arm: Arm, model_fingerprint: str) -> str:
    return _hash_json(
        {
            "adapter_version": ADAPTER_VERSION,
            "prompt_version": TOOL_RESULT_REVIEW_PROMPT_VERSION,
            "asb_commit": case.asb_commit,
            "case": case.as_dict(),
            "arm": arm.value,
            "model_fingerprint": model_fingerprint,
        }
    )


def _hash_json(value: Any) -> str:
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode()).hexdigest()


def _load_cache(path: Path) -> dict[str, dict[str, Any]]:
    if not path.exists():
        return {}
    result: dict[str, dict[str, Any]] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line:
            continue
        row = json.loads(line)
        if isinstance(row, dict) and isinstance(row.get("key"), str) and isinstance(row.get("result"), dict):
            if is_cacheable_result(row["result"]):
                result[row["key"]] = row["result"]
    return result


def is_cacheable_result(result: dict[str, Any]) -> bool:
    return not bool(result.get("provider_failure", False))


def _write_cache(path: Path, cache: dict[str, dict[str, Any]]) -> None:
    content = "".join(
        json.dumps({"key": key, "result": value}, ensure_ascii=False, sort_keys=True) + "\n"
        for key, value in sorted(cache.items())
    )
    _write_private(path, content)


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


def _git_commit() -> str | None:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"], capture_output=True, text=True, check=False
    )
    return result.stdout.strip() if result.returncode == 0 else None


def _worktree_fingerprint() -> str:
    digest = hashlib.sha256()
    roots = [Path("src/zeroadr"), Path("evaluation/asb/src/zeroadr_asb")]
    for root in roots:
        for path in sorted(root.rglob("*")):
            if path.is_file() and "__pycache__" not in path.parts:
                digest.update(str(path).encode())
                digest.update(path.read_bytes())
    digest.update(DEFAULT_POLICY_PATH.read_bytes())
    return digest.hexdigest()
