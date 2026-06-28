from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from zeroadr.endpoint.lite import EndpointIngestResult, persist_endpoint_record
from zeroadr.storage.database import SQLiteStore


def tail_endpoint_jsonl(
    input_path: Path,
    *,
    trace_path: Path,
    db_path: Path | None = None,
    checkpoint_path: Path | None = None,
    stop_after_idle: float | None = None,
    poll_interval: float = 0.1,
    strict: bool = False,
) -> EndpointIngestResult:
    store = SQLiteStore(db_path) if db_path else None
    session_ids: set[str] = set()
    events_written = 0
    records_read = 0
    checkpoint = _read_checkpoint(checkpoint_path)
    offset = checkpoint["offset"]
    line_number = checkpoint["line_number"]
    last_activity = time.monotonic()

    input_path.parent.mkdir(parents=True, exist_ok=True)
    input_path.touch(exist_ok=True)
    with input_path.open("r", encoding="utf-8") as handle:
        handle.seek(offset)
        while True:
            line = handle.readline()
            if not line:
                if stop_after_idle is not None and time.monotonic() - last_activity >= stop_after_idle:
                    break
                time.sleep(poll_interval)
                continue
            last_activity = time.monotonic()
            stripped = line.strip()
            if not stripped:
                continue
            payload = json.loads(stripped)
            if not isinstance(payload, dict):
                raise ValueError("endpoint JSONL records must be JSON objects")
            records_read += 1
            line_number += 1
            event = persist_endpoint_record(
                _record(payload),
                trace_path=trace_path,
                store=store,
                strict=strict,
                line_number=line_number,
            )
            session_ids.add(event.session_id)
            events_written += 1
            _write_checkpoint(checkpoint_path, offset=handle.tell(), line_number=line_number)

    return {
        "events_written": events_written,
        "records_read": records_read,
        "session_ids": sorted(session_ids),
    }


def _record(value: dict[str, Any]) -> dict[str, Any]:
    return value


def _read_checkpoint(checkpoint_path: Path | None) -> dict[str, int]:
    if checkpoint_path is None or not checkpoint_path.exists():
        return {"offset": 0, "line_number": 0}
    payload = json.loads(checkpoint_path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        return {"offset": 0, "line_number": 0}
    offset = payload.get("offset")
    line_number = payload.get("line_number")
    return {
        "offset": offset if isinstance(offset, int) and offset >= 0 else 0,
        "line_number": line_number if isinstance(line_number, int) and line_number >= 0 else 0,
    }


def _write_checkpoint(checkpoint_path: Path | None, *, offset: int, line_number: int) -> None:
    if checkpoint_path is None:
        return
    checkpoint_path.parent.mkdir(parents=True, exist_ok=True)
    checkpoint_path.write_text(
        json.dumps(
            {
                "line_number": line_number,
                "offset": offset,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
