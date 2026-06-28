from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any, Literal

from zeroadr.llm.models import LLMAdjudication
from zeroadr.storage.database import SQLiteStore

GroundTruthVerdict = Literal["likely_true_positive", "likely_false_positive"]
DEFAULT_CONFIDENCE_THRESHOLD = 0.85
DEFAULT_THRESHOLD_CANDIDATES = (0.5, 0.6, 0.7, 0.8, 0.85, 0.9, 0.95)


class GateCalibrationError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(message)


def build_gate_metrics(
    db_path: Path,
    *,
    session_id: str | None = None,
    confidence_threshold: float = DEFAULT_CONFIDENCE_THRESHOLD,
) -> dict[str, Any]:
    threshold = _validated_threshold(confidence_threshold)
    rows = SQLiteStore(db_path).llm_adjudications(session_id=session_id)
    completed = [row for row in rows if row.status == "completed" and row.result is not None]
    confidence_values = [row.result.confidence for row in completed if row.result is not None]
    latencies = [row.latency_ms for row in rows]
    fallback_count = sum(row.final_action == "require_approval" for row in rows)
    return {
        "session_id": session_id,
        "confidence_threshold": threshold,
        "total": len(rows),
        "completed": len(completed),
        "failed": len(rows) - len(completed),
        "completion_rate": _ratio(len(completed), len(rows)),
        "fallback_count": fallback_count,
        "fallback_rate": _ratio(fallback_count, len(rows)),
        "mode_counts": _counts(row.mode for row in rows),
        "models": _counts(row.model for row in rows),
        "verdict_counts": _counts(row.result.verdict for row in completed if row.result is not None),
        "failure_counts": _counts(row.error_code or "unknown" for row in rows if row.status == "failed"),
        "proposed_action_counts": _counts(row.proposed_action for row in rows),
        "final_action_counts": _counts(row.final_action for row in rows),
        "action_change_count": sum(row.proposed_action != row.final_action for row in rows),
        "confidence": {
            "count": len(confidence_values),
            "average": _average(confidence_values),
            "p50": _percentile(confidence_values, 0.5),
            "p95": _percentile(confidence_values, 0.95),
            "above_threshold": sum(value >= threshold for value in confidence_values),
            "below_threshold": sum(value < threshold for value in confidence_values),
        },
        "latency_ms": {
            "p50": round(_percentile(latencies, 0.5)),
            "p95": round(_percentile(latencies, 0.95)),
            "max": max(latencies, default=0),
        },
    }


def evaluate_gate_labels(
    db_path: Path,
    labels_path: Path,
    *,
    threshold: float = DEFAULT_CONFIDENCE_THRESHOLD,
) -> dict[str, Any]:
    selected_threshold = _validated_threshold(threshold)
    labels = _read_labels(labels_path)
    adjudications = {
        row.adjudication_id: row for row in SQLiteStore(db_path).llm_adjudications()
    }
    matched = [(adjudications[item_id], expected) for item_id, expected in labels.items() if item_id in adjudications]
    missing = sorted(set(labels) - set(adjudications))
    thresholds = sorted(set((*DEFAULT_THRESHOLD_CANDIDATES, selected_threshold)))
    matrix = [
        {"threshold": candidate, **_evaluate_threshold(matched, candidate)}
        for candidate in thresholds
    ]
    selected = next(row for row in matrix if row["threshold"] == selected_threshold)
    return {
        "labels_path": str(labels_path),
        "labeled_count": len(labels),
        "matched_count": len(matched),
        "missing_adjudication_ids": missing,
        "selected_threshold": selected_threshold,
        "selected": {key: value for key, value in selected.items() if key != "threshold"},
        "threshold_matrix": matrix,
    }


def export_gate_label_template(
    db_path: Path,
    output_path: Path,
    *,
    session_id: str | None = None,
) -> dict[str, Any]:
    rows = SQLiteStore(db_path).llm_adjudications(session_id=session_id)
    records = [
        {
            "adjudication_id": row.adjudication_id,
            "expected_verdict": None,
            "session_id": row.session_id,
            "policy_id": row.policy_id,
            "mode": row.mode,
            "model": row.model,
            "status": row.status,
            "observed_verdict": row.result.verdict if row.result else None,
            "observed_confidence": row.result.confidence if row.result else None,
            "observed_reason": row.result.reason if row.result else None,
            "error_code": row.error_code,
            "latency_ms": row.latency_ms,
            "proposed_action": row.proposed_action,
            "final_action": row.final_action,
        }
        for row in rows
    ]
    write_gate_label_records(output_path, records)
    return {
        "output": str(output_path),
        "records_written": len(records),
        "session_id": session_id,
    }


def build_gate_readiness(
    db_path: Path,
    labels_path: Path,
    *,
    threshold: float = DEFAULT_CONFIDENCE_THRESHOLD,
    min_labeled_count: int = 40,
    min_completion_rate: float = 0.95,
    max_invalid_output_rate: float = 0.01,
    max_p95_latency_ms: int = 8000,
    max_false_negative_rate: float = 0.02,
    max_false_positive_rate: float = 0.05,
    max_review_rate: float = 0.10,
) -> dict[str, Any]:
    metrics = build_gate_metrics(db_path, confidence_threshold=threshold)
    evaluation = evaluate_gate_labels(db_path, labels_path, threshold=threshold)
    total = int(metrics["total"])
    failure_counts = metrics["failure_counts"]
    invalid_rate = _ratio(int(failure_counts.get("invalid_model_output", 0)), total)
    selected = evaluation["selected"]
    checks = {
        "minimum_labeled_count": _check(
            int(evaluation["matched_count"]) >= min_labeled_count,
            int(evaluation["matched_count"]),
            min_labeled_count,
        ),
        "completion_rate": _check(
            float(metrics["completion_rate"]) >= min_completion_rate,
            metrics["completion_rate"],
            min_completion_rate,
        ),
        "invalid_output_rate": _check(
            invalid_rate <= max_invalid_output_rate,
            invalid_rate,
            max_invalid_output_rate,
        ),
        "p95_latency_ms": _check(
            int(metrics["latency_ms"]["p95"]) < max_p95_latency_ms,
            metrics["latency_ms"]["p95"],
            max_p95_latency_ms,
        ),
        "false_negative_rate": _check(
            float(selected["false_negative_rate"]) <= max_false_negative_rate,
            selected["false_negative_rate"],
            max_false_negative_rate,
        ),
        "false_positive_rate": _check(
            float(selected["false_positive_rate"]) <= max_false_positive_rate,
            selected["false_positive_rate"],
            max_false_positive_rate,
        ),
        "review_rate": _check(
            float(selected["review_rate"]) <= max_review_rate,
            selected["review_rate"],
            max_review_rate,
        ),
    }
    return {
        "ready": all(bool(check["passed"]) for check in checks.values()),
        "checks": checks,
        "metrics": metrics,
        "evaluation": evaluation,
    }


def compare_gate_runs(
    *,
    baseline_db: Path,
    baseline_labels: Path,
    candidate_db: Path,
    candidate_labels: Path,
    threshold: float = DEFAULT_CONFIDENCE_THRESHOLD,
) -> dict[str, Any]:
    baseline = _gate_run_summary(baseline_db, baseline_labels, threshold)
    candidate = _gate_run_summary(candidate_db, candidate_labels, threshold)
    return {
        "threshold": threshold,
        "baseline": baseline,
        "candidate": candidate,
        "delta": {
            "completion_rate": _delta(candidate, baseline, "completion_rate"),
            "p95_latency_ms": int(candidate["p95_latency_ms"])
            - int(baseline["p95_latency_ms"]),
            "false_positive_rate": _delta(candidate, baseline, "false_positive_rate"),
            "false_negative_rate": _delta(candidate, baseline, "false_negative_rate"),
            "review_rate": _delta(candidate, baseline, "review_rate"),
        },
    }


def _gate_run_summary(db_path: Path, labels_path: Path, threshold: float) -> dict[str, Any]:
    metrics = build_gate_metrics(db_path, confidence_threshold=threshold)
    evaluation = evaluate_gate_labels(db_path, labels_path, threshold=threshold)
    selected = evaluation["selected"]
    versions = _counts(
        row.prompt_version for row in SQLiteStore(db_path).llm_adjudications()
    )
    return {
        "db": str(db_path),
        "labels": str(labels_path),
        "prompt_versions": versions,
        "total": metrics["total"],
        "completion_rate": metrics["completion_rate"],
        "p95_latency_ms": metrics["latency_ms"]["p95"],
        "false_positive_rate": selected["false_positive_rate"],
        "false_negative_rate": selected["false_negative_rate"],
        "review_rate": selected["review_rate"],
        "coverage": selected["coverage"],
    }


def _delta(candidate: dict[str, Any], baseline: dict[str, Any], field: str) -> float:
    return round(float(candidate[field]) - float(baseline[field]), 4)


def write_gate_label_records(path: Path, records: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    content = "".join(
        json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n" for record in records
    )
    path.write_text(content, encoding="utf-8")


def _read_labels(path: Path) -> dict[str, GroundTruthVerdict]:
    labels: dict[str, GroundTruthVerdict] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise GateCalibrationError("labels_unreadable", f"Unable to read labels: {path}") from exc
    for line_number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise GateCalibrationError(
                "invalid_label",
                f"Invalid label JSON at line {line_number}.",
            ) from exc
        if not isinstance(value, dict):
            raise GateCalibrationError("invalid_label", f"Invalid label at line {line_number}.")
        item_id = value.get("adjudication_id")
        expected = value.get("expected_verdict")
        if not isinstance(item_id, str) or not item_id.strip():
            raise GateCalibrationError(
                "invalid_label",
                f"Missing adjudication_id at line {line_number}.",
            )
        if expected not in {"likely_true_positive", "likely_false_positive"}:
            raise GateCalibrationError(
                "invalid_label",
                f"Invalid expected_verdict at line {line_number}.",
            )
        if item_id in labels:
            raise GateCalibrationError(
                "duplicate_label",
                f"Duplicate adjudication_id at line {line_number}: {item_id}",
            )
        labels[item_id] = expected
    return labels


def _evaluate_threshold(
    rows: list[tuple[LLMAdjudication, GroundTruthVerdict]],
    threshold: float,
) -> dict[str, int | float]:
    true_positive = true_negative = false_positive = false_negative = review = 0
    for adjudication, expected in rows:
        result = adjudication.result
        if result is None or result.verdict == "uncertain" or result.confidence < threshold:
            review += 1
            continue
        predicted_positive = result.verdict == "likely_true_positive"
        expected_positive = expected == "likely_true_positive"
        if predicted_positive and expected_positive:
            true_positive += 1
        elif not predicted_positive and not expected_positive:
            true_negative += 1
        elif predicted_positive:
            false_positive += 1
        else:
            false_negative += 1
    decided = true_positive + true_negative + false_positive + false_negative
    return {
        "true_positive": true_positive,
        "true_negative": true_negative,
        "false_positive": false_positive,
        "false_negative": false_negative,
        "review": review,
        "review_rate": _ratio(review, len(rows)),
        "coverage": _ratio(decided, len(rows)),
        "precision": _ratio(true_positive, true_positive + false_positive),
        "recall": _ratio(true_positive, true_positive + false_negative),
        "false_positive_rate": _ratio(false_positive, false_positive + true_negative),
        "false_negative_rate": _ratio(false_negative, false_negative + true_positive),
    }


def _validated_threshold(value: float) -> float:
    threshold = float(value)
    if threshold < 0 or threshold > 1:
        raise GateCalibrationError("invalid_threshold", "Confidence threshold must be 0 to 1.")
    return threshold


def _check(passed: bool, actual: int | float, target: int | float) -> dict[str, Any]:
    return {"passed": passed, "actual": actual, "target": target}


def _counts(values: Any) -> dict[str, int]:
    return dict(sorted(Counter(str(value) for value in values).items()))


def _ratio(numerator: int, denominator: int) -> float:
    return round(numerator / denominator, 4) if denominator else 0.0


def _average(values: list[float]) -> float:
    return round(sum(values) / len(values), 4) if values else 0.0


def _percentile(values: list[int] | list[float], quantile: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    position = (len(ordered) - 1) * quantile
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    fraction = position - lower
    return float(ordered[lower] + (ordered[upper] - ordered[lower]) * fraction)
