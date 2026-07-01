from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any

from zeroadr.storage.database import SQLiteStore


def build_runtime_gates(db_path: Path, session_id: str) -> dict[str, Any]:
    records = SQLiteStore(db_path).runtime_gate_records_for_session(session_id)
    return {
        "session_id": session_id,
        "runtime_gates": [record.model_dump(mode="json") for record in records],
    }


def build_runtime_gate_metrics(db_path: Path) -> dict[str, Any]:
    records = SQLiteStore(db_path).runtime_gate_records()
    latencies = [record.latency_ms for record in records]
    return {
        "total": len(records),
        "by_stage": dict(sorted(Counter(record.stage for record in records).items())),
        "by_mode": dict(sorted(Counter(record.mode for record in records).items())),
        "by_review": dict(sorted(Counter(record.review for record in records).items())),
        "by_effective_action": dict(
            sorted(Counter(record.effective_action for record in records).items())
        ),
        "by_verdict": dict(
            sorted(Counter(record.verdict or "not_reviewed" for record in records).items())
        ),
        "failures": sum(record.error_code is not None for record in records),
        "compromised": sum(record.session_compromised for record in records),
        "latency_ms": {
            "min": min(latencies) if latencies else 0,
            "max": max(latencies) if latencies else 0,
            "average": sum(latencies) / len(latencies) if latencies else 0.0,
        },
    }
