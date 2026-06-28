from __future__ import annotations

from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, replace
from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import tempfile
from typing import Any

from zeroadr_agentdojo.adapter import (
    AgentDojoDetectorCase,
    build_agentdojo_detector_corpus,
    summarize_detector_predictions,
)
from zeroadr_agentdojo.analysis import (
    DEFAULT_SPLIT_SEED,
    HybridCaseRecord,
    analyze_case_records,
    apply_sequence_actions,
    calibrate_threshold,
    parse_case_output_index,
    rescore_case_records,
    review_action,
    split_injection_tasks,
    write_analysis_report,
    write_case_records,
)
from zeroadr.core.events import new_event
from zeroadr.core.findings import Finding
from zeroadr.core.policies import PolicyAction
from zeroadr.detection.engine import DetectionEngine
from zeroadr.llm.adjudication import LLMAdjudicator
from zeroadr.llm.models import AnalysisVerdict
from zeroadr.llm.provider import LLMProviderError
from zeroadr.llm.tool_result_review import (
    OpenAICompatibleToolResultReviewer,
    PreparedToolResultReview,
    ToolResultReviewCache,
    build_tool_result_review_payload,
)


@dataclass(frozen=True, slots=True)
class _PreparedCase:
    case: AgentDojoDetectorCase
    findings: list[Finding]
    review: PreparedToolResultReview
    output_index: int


def run_agentdojo_hybrid_benchmark(
    *,
    base_url: str,
    api_key: str,
    model: str,
    timeout: float,
    max_output_tokens: int,
    suite: str = "workspace",
    attack: str = "tool_knowledge",
    benchmark_version: str = "v1.2.2",
    user_tasks: tuple[str, ...] = (),
    injection_tasks: tuple[str, ...] = (),
    cache_path: str | None = ".zeroadr/evaluations/agentdojo/hybrid-cache-v02.jsonl",
    corpus_path: str | None = None,
    workers: int = 4,
    min_confidence: float = 0.85,
    case_output_path: str | None = None,
    analysis_output_path: str | None = None,
    split_seed: str = DEFAULT_SPLIT_SEED,
    auto_calibrate: bool = False,
) -> dict[str, Any]:
    active_corpus_path = Path(corpus_path) if corpus_path else _default_corpus_path(
        suite=suite,
        attack=attack,
        benchmark_version=benchmark_version,
        user_tasks=user_tasks,
        injection_tasks=injection_tasks,
    )
    cases = load_or_build_agentdojo_detector_corpus(
        active_corpus_path,
        suite=suite,
        attack=attack,
        benchmark_version=benchmark_version,
        user_tasks=user_tasks,
        injection_tasks=injection_tasks,
    )
    reviewer = OpenAICompatibleToolResultReviewer(
        base_url=base_url,
        api_key=api_key,
        model=model,
        timeout=timeout,
        max_output_tokens=max_output_tokens,
    )
    report = evaluate_hybrid_cases(
        cases,
        reviewer=reviewer,
        min_confidence=min_confidence,
        cache=ToolResultReviewCache(Path(cache_path)) if cache_path else None,
        workers=workers,
        case_output_path=Path(case_output_path) if case_output_path else None,
        analysis_output_path=Path(analysis_output_path) if analysis_output_path else None,
        split_seed=split_seed,
        auto_calibrate=auto_calibrate,
    )
    report.update(
        {
            "benchmark": "agentdojo",
            "benchmark_version": benchmark_version,
            "suite": suite,
            "attack": attack,
            "pair_count": len(cases) // 2,
            "model": model,
            "corpus": str(active_corpus_path),
        }
    )
    return report


def load_or_build_agentdojo_detector_corpus(
    path: Path,
    *,
    suite: str,
    attack: str,
    benchmark_version: str,
    user_tasks: tuple[str, ...],
    injection_tasks: tuple[str, ...],
) -> list[AgentDojoDetectorCase]:
    expected_metadata = {
        "record_type": "metadata",
        "schema_version": "0.1",
        "suite": suite,
        "attack": attack,
        "benchmark_version": benchmark_version,
        "user_tasks": list(user_tasks),
        "injection_tasks": list(injection_tasks),
    }
    if path.exists():
        lines = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]
        if not lines or lines[0] != expected_metadata:
            raise ValueError("AgentDojo corpus snapshot metadata does not match the request.")
        return [AgentDojoDetectorCase(**item["case"]) for item in lines[1:]]
    cases = build_agentdojo_detector_corpus(
        suite=suite,
        attack=attack,
        benchmark_version=benchmark_version,
        user_tasks=user_tasks,
        injection_tasks=injection_tasks,
    )
    _write_corpus_snapshot(path, expected_metadata, cases)
    return cases


def _default_corpus_path(
    *,
    suite: str,
    attack: str,
    benchmark_version: str,
    user_tasks: tuple[str, ...],
    injection_tasks: tuple[str, ...],
) -> Path:
    filters = json.dumps(
        {"user_tasks": user_tasks, "injection_tasks": injection_tasks},
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    suffix = hashlib.sha256(filters).hexdigest()[:10]
    safe_version = benchmark_version.replace("/", "-")
    return Path(
        ".zeroadr/evaluations/agentdojo/"
        f"corpus-{safe_version}-{suite}-{attack}-{suffix}.jsonl"
    )


def _write_corpus_snapshot(
    path: Path,
    metadata: dict[str, Any],
    cases: list[AgentDojoDetectorCase],
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            for item in [metadata, *[{"record_type": "case", "case": asdict(case)} for case in cases]]:
                json.dump(item, handle, ensure_ascii=False, sort_keys=True)
                handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        path.chmod(0o600)
    finally:
        if temporary.exists():
            temporary.unlink()


def evaluate_hybrid_cases(
    cases: list[AgentDojoDetectorCase],
    *,
    reviewer: LLMAdjudicator,
    min_confidence: float = 0.85,
    cache: ToolResultReviewCache | None = None,
    workers: int = 4,
    case_output_path: Path | None = None,
    analysis_output_path: Path | None = None,
    split_seed: str = DEFAULT_SPLIT_SEED,
    auto_calibrate: bool = False,
) -> dict[str, Any]:
    if workers < 1:
        raise ValueError("workers must be positive")
    detector = DetectionEngine()
    prepared_cases: list[_PreparedCase] = []
    split_map = split_injection_tasks(
        (case.injection_task_id for case in cases), seed=split_seed
    )
    for position, case in enumerate(cases):
        event = new_event(
            event_type="tool.call.completed",
            source_type="replay",
            session_id=f"agentdojo:{case.user_task_id}:{case.injection_task_id}",
            tool_name=case.tool_name,
            capability="tool.result",
            result={"content": [{"text": case.text}]},
        )
        findings = detector.detect(event)
        prepared_cases.append(
            _PreparedCase(
                case=case,
                findings=findings,
                review=build_tool_result_review_payload(event, findings, case_id=case.case_id),
                output_index=_case_output_index(case.case_id, fallback=position),
            )
        )

    groups: dict[str, list[_PreparedCase]] = {}
    for prepared in prepared_cases:
        groups.setdefault(prepared.review.input_sha256, []).append(prepared)
    outcomes: dict[str, Any] = {}
    cache_hits = 0
    pending: dict[Any, tuple[str, _PreparedCase]] = {}
    with ThreadPoolExecutor(max_workers=workers) as executor:
        for input_sha256, group in groups.items():
            representative = group[0]
            evidence_refs = set(representative.review.evidence_refs)
            cached = cache.get(input_sha256, evidence_refs=evidence_refs) if cache else None
            if cached is not None:
                outcomes[input_sha256] = cached
                cache_hits += len(group)
                continue
            cache_hits += len(group) - 1
            future = executor.submit(
                reviewer.adjudicate,
                payload=representative.review.payload,
                evidence_refs=evidence_refs,
            )
            pending[future] = (input_sha256, representative)
        for future in as_completed(pending):
            input_sha256, _ = pending[future]
            try:
                provider_result = future.result()
                outcomes[input_sha256] = provider_result
                if cache:
                    cache.put(input_sha256, provider_result)
            except LLMProviderError as exc:
                outcomes[input_sha256] = exc

    records: list[HybridCaseRecord] = []
    for prepared in prepared_cases:
        case = prepared.case
        findings = prepared.findings
        outcome = outcomes[prepared.review.input_sha256]
        if not isinstance(outcome, LLMProviderError):
            provider_result = outcome
            verdict = provider_result.result.verdict
            confidence = provider_result.result.confidence
            action = _review_action(
                verdict=verdict,
                confidence=confidence,
                min_confidence=min_confidence,
                has_critical=any(finding.severity == "critical" for finding in findings),
            )
            records.append(
                _case_record(
                    prepared,
                    split=split_map[case.injection_task_id],
                    verdict=verdict,
                    confidence=confidence,
                    action=action,
                    latency_ms=provider_result.latency_ms,
                    error_code=None,
                )
            )
        else:
            records.append(
                _case_record(
                    prepared,
                    split=split_map[case.injection_task_id],
                    verdict=None,
                    confidence=None,
                    action=review_action(
                        verdict=None,
                        confidence=None,
                        threshold=min_confidence,
                        has_critical=any(
                            finding.severity == "critical" for finding in findings
                        ),
                        error_code=outcome.code,
                    ),
                    latency_ms=0,
                    error_code=outcome.code,
                )
            )
    calibration: dict[str, Any] | None = None
    if auto_calibrate:
        calibration = calibrate_threshold(records)
        selected = calibration.get("selected_threshold")
        if isinstance(selected, int | float):
            records = rescore_case_records(records, float(selected))
    records = _with_fn_reasons(apply_sequence_actions(records))
    analysis = analyze_case_records(records)
    report = _hybrid_report(
        records,
        model_calls=len(pending),
        cache_hits=cache_hits,
        sequence_metrics=analysis["all"],
    )
    if calibration is not None:
        report["calibration"] = calibration
    if case_output_path is not None:
        write_case_records(case_output_path, records)
    if analysis_output_path is not None:
        write_analysis_report(
            analysis_output_path,
            {
                "schema_version": "0.1",
                "split_seed": split_seed,
                "metrics": analysis,
                "calibration": calibration,
            },
        )
    return report


def _review_action(
    *,
    verdict: AnalysisVerdict,
    confidence: float,
    min_confidence: float,
    has_critical: bool,
) -> PolicyAction:
    return review_action(
        verdict=verdict,
        confidence=confidence,
        threshold=min_confidence,
        has_critical=has_critical,
        error_code=None,
    )


def _hybrid_report(
    results: list[HybridCaseRecord],
    *,
    model_calls: int,
    cache_hits: int,
    sequence_metrics: dict[str, Any],
) -> dict[str, Any]:
    labels = [result.label for result in results]
    rule_metrics = summarize_detector_predictions(
        labels=labels,
        predictions=[result.deterministic_hit for result in results],
    )
    final_metrics = summarize_detector_predictions(
        labels=labels,
        predictions=[
            result.isolated_action in {"block", "require_approval"} for result in results
        ],
    )
    verdicts = Counter(result.verdict for result in results if result.verdict is not None)
    actions = Counter(result.isolated_action for result in results)
    error_codes = Counter(result.error_code for result in results if result.error_code is not None)
    failures = sum(result.error_code is not None for result in results)
    approvals = actions["require_approval"]
    return {
        "evaluation": "hybrid_full_pipeline",
        "blocking_semantics": "block_or_require_approval",
        "rules": rule_metrics,
        "final": final_metrics,
        "sequence_final": sequence_metrics["sequence_final"],
        "sequence_recovered": sequence_metrics["recovered_by_sequence"],
        "deltas": {
            "recall": round(float(final_metrics["recall"]) - float(rule_metrics["recall"]), 4),
            "accuracy": round(
                float(final_metrics["accuracy"]) - float(rule_metrics["accuracy"]), 4
            ),
        },
        "llm": {
            "review_count": len(results),
            "model_calls": model_calls,
            "cache_hits": cache_hits,
            "provider_failures": failures,
            "provider_failure_rate": _rate(failures, len(results)),
            "error_codes": dict(sorted(error_codes.items())),
            "require_approval_rate": _rate(approvals, len(results)),
            "verdicts": {
                "likely_true_positive": verdicts["likely_true_positive"],
                "likely_false_positive": verdicts["likely_false_positive"],
                "uncertain": verdicts["uncertain"],
            },
            "actions": {
                "allow": actions["allow"],
                "block": actions["block"],
                "require_approval": actions["require_approval"],
            },
        },
    }


def _rate(value: int, total: int) -> float:
    return round(value / total, 4) if total else 0.0


def _case_output_index(case_id: str, *, fallback: int) -> int:
    try:
        return parse_case_output_index(case_id)
    except ValueError:
        return fallback


def _case_record(
    prepared: _PreparedCase,
    *,
    split: str,
    verdict: AnalysisVerdict | None,
    confidence: float | None,
    action: PolicyAction,
    latency_ms: int,
    error_code: str | None,
) -> HybridCaseRecord:
    case = prepared.case
    has_critical = any(finding.severity == "critical" for finding in prepared.findings)
    return HybridCaseRecord(
        case_id=case.case_id,
        label=case.label,
        suite=case.suite,
        attack=case.attack,
        user_task_id=case.user_task_id,
        injection_task_id=case.injection_task_id,
        output_index=prepared.output_index,
        tool_name=case.tool_name,
        split=split,  # type: ignore[arg-type]
        rule_ids=tuple(sorted(finding.rule_id for finding in prepared.findings)),
        deterministic_hit=bool(prepared.findings),
        has_critical=has_critical,
        verdict=verdict,
        confidence=confidence,
        isolated_action=action,
        sequence_action=action,
        latency_ms=latency_ms,
        error_code=error_code,
        evidence_truncated=prepared.review.truncated,
        sequence_blocked_by=None,
        fn_reasons=(),
        content_shape=_content_shape(case.text),
    )


def _with_fn_reasons(records: list[HybridCaseRecord]) -> list[HybridCaseRecord]:
    updated: list[HybridCaseRecord] = []
    for record in records:
        reasons: list[str] = []
        if record.label and record.isolated_action == "allow":
            if not record.deterministic_hit:
                reasons.append("rule_miss")
            if record.verdict == "likely_false_positive":
                reasons.append("llm_false_negative")
            if record.evidence_truncated:
                reasons.append("evidence_truncated")
        updated.append(replace(record, fn_reasons=tuple(reasons)))
    return updated


def _content_shape(text: str) -> str:
    stripped = text.lstrip()
    if stripped.startswith("{"):
        return "json_object"
    if stripped.startswith("["):
        return "json_array"
    if stripped.startswith("- ") or "\n- " in stripped:
        return "yaml_sequence"
    return "plain_text"
