from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any

from zeroadr.storage.database import SQLiteStore


def build_tool_result_gates(db_path: Path, session_id: str) -> dict[str, Any]:
    records = SQLiteStore(db_path).tool_result_gate_records_for_session(session_id)
    return {
        "session_id": session_id,
        "tool_result_gates": [record.model_dump(mode="json") for record in records],
    }


def build_tool_result_gate_metrics(db_path: Path) -> dict[str, Any]:
    records = SQLiteStore(db_path).tool_result_gate_records()
    total = len(records)
    latencies = [record.latency_ms for record in records]
    effective = Counter(record.effective_action for record in records)
    proposed = Counter(record.proposed_action for record in records)
    modes = Counter(record.mode for record in records)
    reviews = Counter(record.review for record in records)
    verdicts = Counter(record.verdict or "not_reviewed" for record in records)
    failures = sum(record.error_code is not None for record in records)
    approvals = sum(record.proposed_action == "require_approval" for record in records)
    return {
        "total": total,
        "by_mode": dict(sorted(modes.items())),
        "by_review": dict(sorted(reviews.items())),
        "by_verdict": dict(sorted(verdicts.items())),
        "by_proposed_action": dict(sorted(proposed.items())),
        "by_effective_action": dict(sorted(effective.items())),
        "failures": failures,
        "approval_rate": approvals / total if total else 0.0,
        "latency_ms": {
            "min": min(latencies) if latencies else 0,
            "max": max(latencies) if latencies else 0,
            "average": sum(latencies) / total if total else 0.0,
        },
    }
