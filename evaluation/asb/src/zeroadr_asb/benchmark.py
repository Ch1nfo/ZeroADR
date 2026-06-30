from __future__ import annotations

from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import time
from typing import Any

from zeroadr.llm.config import resolve_llm_gate_config
from zeroadr.llm.tool_result_review import (
    TOOL_RESULT_REVIEW_PROMPT_VERSION,
    OpenAICompatibleToolResultReviewer,
)
from zeroadr_asb.adapter import ResolvedASBCase, resolve_case
from zeroadr_asb.analysis import analyze_results
from zeroadr_asb.manifest import ASBCase, load_manifest
from zeroadr_asb.official import run_official_case
from zeroadr_asb.provider import CoreToolResultReviewer, OpenAICompatibleAgentBackend
from zeroadr_asb.runner import AgentBackend, Arm, CaseResult, ResultReviewer
from zeroadr.policy.engine import PolicyEngine


ADAPTER_VERSION = "asb-official-agent-v1.0"
FLASH_MODEL = "deepseek-v4-flash"
FLASH_MIN_OUTPUT_TOKENS = 1_024
BENCHMARK_MIN_TIMEOUT_SECONDS = 30.0
DEFAULT_POLICY_PATH = Path(__file__).resolve().parent / "policies/asb-rules.yaml"
BackendFactory = Callable[[ResolvedASBCase, Arm], AgentBackend]
ReviewerFactory = Callable[[], ResultReviewer | None]
CaseRunner = Callable[..., CaseResult]


class AppendOnlyCaseJournal:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = threading.Lock()

    def load(self) -> dict[str, dict[str, Any]]:
        return _load_cache(self.path)

    def append(self, key: str, result: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.path.parent.chmod(0o700)
        encoded = json.dumps(
            {"key": key, "result": result}, ensure_ascii=False, sort_keys=True
        ) + "\n"
        with self._lock:
            fd = os.open(self.path, os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o600)
            try:
                os.write(fd, encoded.encode())
                os.fsync(fd)
            finally:
                os.close(fd)
            self.path.chmod(0o600)

    def compact(self) -> None:
        _write_cache(self.path, self.load())


def run_concurrency_sweep(
    *,
    asb_root: Path,
    manifest_path: Path,
    output_dir: Path,
    arms: tuple[str, ...] = ("baseline", "rules", "hybrid"),
    llm_config_path: Path = Path(".zeroadr/llm-config.json"),
    resume: bool = False,
    dry_run: bool = True,
) -> dict[str, Any]:
    measurements: list[dict[str, Any]] = []
    baseline_p95 = 0
    baseline_throughput = 0.0
    for workers in (1, 2, 4):
        started = time.monotonic()
        result = run_benchmark(
            asb_root=asb_root,
            manifest_path=manifest_path,
            output_dir=output_dir / f"sweep-workers-{workers}",
            arms=arms,
            llm_config_path=llm_config_path,
            workers=workers,
            resume=resume,
            dry_run=dry_run,
        )
        elapsed = time.monotonic() - started
        arm_metrics = list(result["analysis"]["arms"].values())
        p95 = max((int(item["latency_p95_ms"]) for item in arm_metrics), default=0)
        failures = sum(int(item["provider_failure_count"]) for item in arm_metrics)
        transport_errors = sum(
            int(item["timeout_count"])
            + int(item["rate_limit_count"])
            + int(item["http_error_count"])
            + int(item["invalid_response_count"])
            for item in arm_metrics
        )
        throughput = result["case_run_count"] / elapsed if elapsed else 0.0
        if workers == 1:
            baseline_p95 = p95
            baseline_throughput = throughput
        eligible = (
            failures == 0
            and transport_errors == 0
            and (baseline_p95 == 0 or p95 <= baseline_p95 * 1.5)
            and (workers == 1 or throughput > baseline_throughput)
        )
        measurements.append(
            {
                "workers": workers,
                "elapsed_seconds": round(elapsed, 3),
                "throughput_cases_per_second": round(throughput, 4),
                "latency_p95_ms": p95,
                "provider_failure_count": failures,
                "transport_error_count": transport_errors,
                "eligible": eligible,
            }
        )
    eligible_workers = [item["workers"] for item in measurements if item["eligible"]]
    selected = max(eligible_workers) if eligible_workers else 1
    report = {"ok": True, "selected_workers": selected, "measurements": measurements}
    _write_private(
        output_dir / "concurrency-sweep.json",
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
    )
    return report


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
    policy_path: Path = DEFAULT_POLICY_PATH,
    case_runner: CaseRunner = run_official_case,
) -> dict[str, Any]:
    if not 1 <= workers <= 4:
        raise ValueError("workers must be between 1 and 4")
    selected_arms = tuple(Arm(value) for value in arms)
    if len(set(selected_arms)) != len(selected_arms):
        raise ValueError("arms must not contain duplicates")
    cases = load_manifest(manifest_path)
    if dry_run:
        cases = _dry_run_cases(cases)
    agent_model_fingerprint = "injected-test-backend"
    reviewer_model_fingerprint = "injected-test-reviewer"
    if backend_factory is None:
        agent_config = resolve_llm_gate_config(config_path=llm_config_path)
        agent_model_fingerprint = _hash_json(
            {
                "base_url": agent_config.base_url,
                "model": FLASH_MODEL,
                "max_output_tokens": max(
                    agent_config.max_output_tokens, FLASH_MIN_OUTPUT_TOKENS
                ),
                "timeout": max(agent_config.timeout, BENCHMARK_MIN_TIMEOUT_SECONDS),
            }
        )
        backend_local = threading.local()

        def configured_backend(_: ResolvedASBCase, __: Arm) -> AgentBackend:
            backend = getattr(backend_local, "agent", None)
            if backend is None:
                backend = OpenAICompatibleAgentBackend(
                    base_url=agent_config.base_url,
                    api_key=agent_config.api_key,
                    model=FLASH_MODEL,
                    timeout=max(agent_config.timeout, BENCHMARK_MIN_TIMEOUT_SECONDS),
                    max_output_tokens=max(
                        agent_config.max_output_tokens, FLASH_MIN_OUTPUT_TOKENS
                    ),
                )
                backend_local.agent = backend
            return backend

        backend_factory = configured_backend
    if reviewer_factory is None and Arm.HYBRID in selected_arms:
        gate_config = resolve_llm_gate_config(config_path=llm_config_path)
        reviewer_model_fingerprint = _hash_json(
            {
                "base_url": gate_config.base_url,
                "model": FLASH_MODEL,
                "max_output_tokens": max(
                    gate_config.max_output_tokens, FLASH_MIN_OUTPUT_TOKENS
                ),
                "timeout": max(gate_config.timeout, BENCHMARK_MIN_TIMEOUT_SECONDS),
            }
        )
        reviewer_local = threading.local()

        def configured_reviewer() -> ResultReviewer:
            reviewer = getattr(reviewer_local, "reviewer", None)
            if reviewer is None:
                reviewer = CoreToolResultReviewer(
                    OpenAICompatibleToolResultReviewer(
                        base_url=gate_config.base_url,
                        api_key=gate_config.api_key,
                        model=FLASH_MODEL,
                        timeout=max(gate_config.timeout, BENCHMARK_MIN_TIMEOUT_SECONDS),
                        max_output_tokens=max(
                            gate_config.max_output_tokens, FLASH_MIN_OUTPUT_TOKENS
                        ),
                    )
                )
                reviewer_local.reviewer = reviewer
            return reviewer

        reviewer_factory = configured_reviewer
    cache_path = output_dir / "case-cache.jsonl"
    journal = AppendOnlyCaseJournal(cache_path)
    cached = journal.load() if resume else {}
    policy = PolicyEngine.from_file(policy_path)
    policy_sha256 = hashlib.sha256(policy_path.read_bytes()).hexdigest()
    manifest_sha256 = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    worktree_sha256 = _worktree_fingerprint()
    ordered_results: dict[tuple[int, int], CaseResult] = {}
    jobs: list[tuple[int, int, Arm, ASBCase, str]] = []
    new_model_calls = 0
    new_case_runs = 0
    for arm_index, arm in enumerate(selected_arms):
        for case_index, case in enumerate(cases):
            cache_key = _cache_key(
                case,
                arm,
                agent_model_fingerprint=agent_model_fingerprint,
                reviewer_model_fingerprint=reviewer_model_fingerprint,
                policy_sha256=policy_sha256,
                manifest_sha256=manifest_sha256,
                worktree_sha256=worktree_sha256,
            )
            cached_result = cached.get(cache_key)
            if cached_result is not None:
                ordered_results[(arm_index, case_index)] = CaseResult(**cached_result)
                continue
            jobs.append((arm_index, case_index, arm, case, cache_key))

    def execute(job: tuple[int, int, Arm, ASBCase, str]) -> tuple[int, int, str, CaseResult]:
        arm_index, case_index, arm, case, cache_key = job
        resolved = resolve_case(asb_root, case)
        reviewer = reviewer_factory() if arm is Arm.HYBRID and reviewer_factory else None
        result = case_runner(
            case,
            resolved,
            asb_root=asb_root,
            arm=arm,
            backend=backend_factory(resolved, arm),
            policy=policy,
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
        cache_started = __import__("time").monotonic()
        journal.append(cache_key, result.as_dict())
        cache_latency = int((__import__("time").monotonic() - cache_started) * 1000)
        ordered_results[(arm_index, case_index)] = replace(
            result, cache_write_latency_ms=cache_latency
        )

    if workers == 1:
        for job in jobs:
            record(execute(job))
    else:
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="zeroadr-asb") as pool:
            futures = [pool.submit(execute, job) for job in jobs]
            for future in as_completed(futures):
                record(future.result())
    journal.compact()
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
        "agent_model": FLASH_MODEL,
        "reviewer_model": FLASH_MODEL,
        "agent_model_fingerprint": agent_model_fingerprint,
        "reviewer_model_fingerprint": reviewer_model_fingerprint,
        "prompt_version": TOOL_RESULT_REVIEW_PROMPT_VERSION,
        "policy_sha256": (
            policy_sha256
        ),
        "manifest_sha256": manifest_sha256,
        "official_harness": True,
        "metric": "official_asr_only",
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


def _cache_key(
    case: ASBCase,
    arm: Arm,
    *,
    agent_model_fingerprint: str,
    reviewer_model_fingerprint: str,
    policy_sha256: str,
    manifest_sha256: str,
    worktree_sha256: str,
) -> str:
    return _hash_json(
        {
            "adapter_version": ADAPTER_VERSION,
            "prompt_version": TOOL_RESULT_REVIEW_PROMPT_VERSION,
            "asb_commit": case.asb_commit,
            "case": case.as_dict(),
            "arm": arm.value,
            "agent_model_fingerprint": agent_model_fingerprint,
            "reviewer_model_fingerprint": reviewer_model_fingerprint,
            "policy_sha256": policy_sha256,
            "manifest_sha256": manifest_sha256,
            "worktree_sha256": worktree_sha256,
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
