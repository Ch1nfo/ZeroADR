from __future__ import annotations

import json
import os
import signal
import tempfile
import threading
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from types import FrameType
from typing import Any, Callable, Iterator, Literal, Protocol

from zeroadr.endpoint.collectors.base import EndpointCollector
from zeroadr.endpoint.collectors.linux import LinuxEbpfCollector
from zeroadr.endpoint.collectors.mock import MockEndpointCollector
from zeroadr.endpoint.contracts import EndpointRecord, endpoint_record_to_mapping
from zeroadr.endpoint.lite import persist_endpoint_record
from zeroadr.storage.database import SQLiteStore

DEFAULT_AGENT_STATUS_FILE = Path(".zeroadr/endpoint-agent-status.json")


class _RotatableOutput(Protocol):
    def tell(self) -> int: ...


class _WritableOutput(Protocol):
    def write(self, line: str) -> object: ...
    def flush(self) -> object: ...


@dataclass(frozen=True)
class EndpointAgentConfig:
    collector: Literal["mock", "linux"]
    output_path: Path
    status_path: Path | None = None
    trace_path: Path | None = None
    db_path: Path | None = None
    session_id: str = "sess_endpoint_agent"
    host_id: str | None = None
    limit: int | None = None
    stop_after_idle: float | None = None
    poll_interval: float = 0.1
    strict_ingest: bool = False
    rotate_bytes: int | None = None
    max_rotated_files: int = 5
    max_output_bytes: int | None = None
    write_retry_count: int = 0
    write_retry_delay: float = 0.05
    heartbeat_interval: float | None = None
    pid_path: Path | None = None
    sensitive_path_prefixes: tuple[str, ...] | None = None
    bcc_poll_timeout_ms: int = 100
    bcc_max_queue: int = 4096


def run_endpoint_agent(config: EndpointAgentConfig) -> dict[str, Any]:
    pid_written = False
    try:
        try:
            collector = _build_agent_collector(config)
        except Exception as exc:
            collector_available = not isinstance(exc, RuntimeError)
            stopped_reason = "collector_unavailable" if isinstance(exc, RuntimeError) else "error"
            _write_initial_error_status(
                config,
                stopped_reason=stopped_reason,
                last_error=str(exc),
                collector_available=collector_available,
            )
            raise
        if config.pid_path is not None:
            write_pid_file(config.pid_path)
            pid_written = True
        status_refresh: list[Callable[[], None]] = []
        if isinstance(collector, LinuxEbpfCollector):
            collector._on_status_update = lambda: status_refresh[0]() if status_refresh else None
        collector_status_provider = _build_collector_status_provider(collector)
        return stream_endpoint_records(
            collector.iter_records(),
            output_path=config.output_path,
            collector_name=config.collector,
            status_path=config.status_path,
            trace_path=config.trace_path,
            db_path=config.db_path,
            limit=config.limit,
            stop_after_idle=config.stop_after_idle,
            poll_interval=config.poll_interval,
            strict_ingest=config.strict_ingest,
            rotate_bytes=config.rotate_bytes,
            max_rotated_files=config.max_rotated_files,
            max_output_bytes=config.max_output_bytes,
            write_retry_count=config.write_retry_count,
            write_retry_delay=config.write_retry_delay,
            heartbeat_interval=config.heartbeat_interval,
            install_signal_handlers=True,
            collector_status_provider=collector_status_provider,
            on_stop_collector=_build_collector_stop_handler(collector),
            status_refresh_hook=status_refresh,
        )
    finally:
        if pid_written and config.pid_path is not None:
            remove_pid_file(config.pid_path)


def stream_endpoint_records(
    records: Iterator[EndpointRecord | dict[str, Any]],
    *,
    output_path: Path,
    collector_name: str,
    status_path: Path | None = None,
    trace_path: Path | None = None,
    db_path: Path | None = None,
    limit: int | None = None,
    stop_after_idle: float | None = None,
    poll_interval: float = 0.1,
    strict_ingest: bool = False,
    rotate_bytes: int | None = None,
    max_rotated_files: int = 5,
    max_output_bytes: int | None = None,
    write_retry_count: int = 0,
    write_retry_delay: float = 0.05,
    heartbeat_interval: float | None = None,
    install_signal_handlers: bool = False,
    collector_status_provider: Callable[[], dict[str, Any] | None] | None = None,
    on_stop_collector: Callable[[], None] | None = None,
    status_refresh_hook: list[Callable[[], None]] | None = None,
) -> dict[str, Any]:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    store = SQLiteStore(db_path) if db_path else None
    started_at = _utc_now()
    records_written = 0
    records_read = 0
    events_written = 0
    rotations = 0
    dropped_rotated_files = 0
    backpressure_events = 0
    last_backpressure_at: str | None = None
    retained_bytes = _output_family_size(output_path)
    session_ids: set[str] = set()
    stopped_reason = "exhausted"
    last_error: str | None = None
    last_record_at: str | None = None
    last_activity = time.monotonic()
    last_status_at = 0.0
    restore_signals = _install_signal_handlers() if install_signal_handlers else None
    state_lock = threading.Lock()
    status_write_lock = threading.Lock()
    heartbeat_stop = threading.Event()
    heartbeat_thread: threading.Thread | None = None

    def write_status(reason: str, *, force: bool = False) -> None:
        nonlocal last_status_at
        with status_write_lock:
            now = time.monotonic()
            if not force and reason == "running" and heartbeat_interval is not None and last_status_at:
                if now - last_status_at < heartbeat_interval:
                    return
            last_status_at = now
            with state_lock:
                snapshot_records_written = records_written
                snapshot_records_read = records_read
                snapshot_events_written = events_written
                snapshot_rotations = rotations
                snapshot_dropped_rotated_files = dropped_rotated_files
                snapshot_retained_bytes = retained_bytes
                snapshot_backpressure_events = backpressure_events
                snapshot_last_backpressure_at = last_backpressure_at
                snapshot_session_ids = set(session_ids)
                snapshot_last_error = last_error
                snapshot_last_record_at = last_record_at
            collector_extra = collector_status_provider() if collector_status_provider else None
            _write_status_file(
                status_path,
                collector=collector_name,
                started_at=started_at,
                output_path=output_path,
                trace_path=trace_path,
                db_path=db_path,
                records_written=snapshot_records_written,
                records_read=snapshot_records_read,
                events_written=snapshot_events_written,
                rotations=snapshot_rotations,
                dropped_rotated_files=snapshot_dropped_rotated_files,
                retained_bytes=snapshot_retained_bytes,
                backpressure_events=snapshot_backpressure_events,
                last_backpressure_at=snapshot_last_backpressure_at,
                session_ids=snapshot_session_ids,
                stopped_reason=reason,
                last_error=snapshot_last_error,
                last_record_at=snapshot_last_record_at,
                collector_available=True,
                collector_extra=collector_extra,
            )

    def stop_heartbeat() -> None:
        heartbeat_stop.set()
        if heartbeat_thread is not None:
            heartbeat_thread.join()

    write_status("running")
    if status_refresh_hook is not None:
        status_refresh_hook.clear()
        status_refresh_hook.append(lambda: write_status("running"))
    if status_path is not None and heartbeat_interval is not None and heartbeat_interval > 0:

        def heartbeat() -> None:
            while not heartbeat_stop.wait(heartbeat_interval):
                write_status("running", force=True)

        heartbeat_thread = threading.Thread(
            target=heartbeat,
            name="zeroadr-endpoint-heartbeat",
            daemon=True,
        )
        heartbeat_thread.start()
    output: Any | None = None
    try:
        output = output_path.open("a", encoding="utf-8")
        for record in records:
            if limit is not None and records_written >= limit:
                stopped_reason = "limit"
                break
            normalized = endpoint_record_to_mapping(record)
            line = json.dumps(normalized, sort_keys=True) + "\n"
            if _should_rotate(output, line, rotate_bytes):
                output.close()
                _rotate_output_files(output_path, max_rotated_files=max_rotated_files)
                output = output_path.open("a", encoding="utf-8")
                with state_lock:
                    rotations += 1

            def record_backpressure() -> None:
                nonlocal backpressure_events, last_backpressure_at
                with state_lock:
                    backpressure_events += 1
                    last_backpressure_at = _utc_now()

            _write_line_with_retries(
                output,
                line,
                retry_count=write_retry_count,
                retry_delay=write_retry_delay,
                on_backpressure=record_backpressure,
            )
            retention_result = _enforce_output_retention(
                output_path,
                max_output_bytes=max_output_bytes,
            )
            with state_lock:
                dropped_rotated_files += retention_result["dropped_files"]
                retained_bytes = retention_result["retained_bytes"]
                last_record_at = _utc_now()
                records_written += 1
                session_id = normalized.get("session_id")
                if isinstance(session_id, str):
                    session_ids.add(session_id)
            if trace_path or store:
                with state_lock:
                    records_read += 1
                event = persist_endpoint_record(
                    normalized,
                    trace_path=trace_path,
                    store=store,
                    strict=strict_ingest,
                    line_number=records_read,
                )
                with state_lock:
                    session_ids.add(event.session_id)
                    events_written += 1
            last_activity = time.monotonic()
            write_status("running")

        if limit is not None and records_written >= limit:
            stopped_reason = "limit"
        elif stop_after_idle is not None and time.monotonic() - last_activity >= stop_after_idle:
            stopped_reason = "idle"
        time.sleep(0 if poll_interval < 0 else min(poll_interval, 0))
    except KeyboardInterrupt:
        stopped_reason = "signal"
        if on_stop_collector is not None:
            on_stop_collector()
    except Exception as exc:
        stopped_reason = "error"
        with state_lock:
            last_error = str(exc)
        stop_heartbeat()
        write_status(stopped_reason)
        if restore_signals:
            restore_signals()
        raise
    finally:
        stop_heartbeat()
        if output is not None:
            output.close()

    write_status(stopped_reason)
    if restore_signals:
        restore_signals()
    return _agent_result(
        collector_name=collector_name,
        output_path=output_path,
        records_written=records_written,
        records_read=records_read,
        events_written=events_written,
        rotations=rotations,
        dropped_rotated_files=dropped_rotated_files,
        retained_bytes=retained_bytes,
        backpressure_events=backpressure_events,
        last_backpressure_at=last_backpressure_at,
        session_ids=session_ids,
        stopped_reason=stopped_reason,
    )


def _agent_result(
    *,
    collector_name: str,
    output_path: Path,
    records_written: int,
    records_read: int,
    events_written: int,
    rotations: int,
    dropped_rotated_files: int,
    retained_bytes: int,
    backpressure_events: int,
    last_backpressure_at: str | None,
    session_ids: set[str],
    stopped_reason: str,
) -> dict[str, Any]:
    return {
        "backpressure_events": backpressure_events,
        "collector": collector_name,
        "dropped_rotated_files": dropped_rotated_files,
        "events_written": events_written,
        "last_backpressure_at": last_backpressure_at,
        "output": str(output_path),
        "records_read": records_read,
        "records_written": records_written,
        "retained_bytes": retained_bytes,
        "rotations": rotations,
        "session_ids": sorted(session_ids),
        "stopped_reason": stopped_reason,
    }


def _write_status_file(
    status_path: Path | None,
    *,
    collector: str,
    started_at: str,
    output_path: Path,
    trace_path: Path | None,
    db_path: Path | None,
    records_written: int,
    records_read: int,
    events_written: int,
    rotations: int,
    dropped_rotated_files: int,
    retained_bytes: int,
    backpressure_events: int,
    last_backpressure_at: str | None,
    session_ids: set[str],
    stopped_reason: str,
    last_error: str | None,
    last_record_at: str | None,
    collector_available: bool,
    collector_extra: dict[str, Any] | None = None,
) -> None:
    if status_path is None:
        return
    status_path.parent.mkdir(parents=True, exist_ok=True)
    updated_at = _utc_now()
    payload = {
        "backpressure_events": backpressure_events,
        "collector": collector,
        "collector_available": collector_available,
        "db_path": str(db_path) if db_path else None,
        "dropped_rotated_files": dropped_rotated_files,
        "started_at": started_at,
        "updated_at": updated_at,
        "state": _status_state(stopped_reason),
        "output_path": str(output_path),
        "trace_path": str(trace_path) if trace_path else None,
        "records_written": records_written,
        "retained_bytes": retained_bytes,
        "records_read": records_read,
        "events_written": events_written,
        "rotations": rotations,
        "session_ids": sorted(session_ids),
        "stopped_reason": stopped_reason,
        "last_error": last_error,
        "last_backpressure_at": last_backpressure_at,
        "last_record_at": last_record_at,
        "uptime_seconds": _elapsed_seconds(started_at, updated_at),
    }
    if collector == "linux" and collector_extra is not None:
        payload["bcc"] = collector_extra
    serialized = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=status_path.parent,
            prefix=f".{status_path.name}.",
            suffix=".tmp",
            delete=False,
        ) as temporary:
            temporary.write(serialized)
            temporary.flush()
            os.fsync(temporary.fileno())
            temporary_path = Path(temporary.name)
        temporary_path.replace(status_path)
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def _write_initial_error_status(
    config: EndpointAgentConfig,
    *,
    stopped_reason: str,
    last_error: str,
    collector_available: bool,
) -> None:
    started_at = _utc_now()
    _write_status_file(
        config.status_path,
        collector=config.collector,
        started_at=started_at,
        output_path=config.output_path,
        trace_path=config.trace_path,
        db_path=config.db_path,
        records_written=0,
        records_read=0,
        events_written=0,
        rotations=0,
        dropped_rotated_files=0,
        retained_bytes=_output_family_size(config.output_path),
        backpressure_events=0,
        last_backpressure_at=None,
        session_ids=set(),
        stopped_reason=stopped_reason,
        last_error=last_error,
        last_record_at=None,
        collector_available=collector_available,
        collector_extra=None,
    )


def read_agent_health(status_path: Path, *, stale_after: float | None = None) -> dict[str, Any]:
    status = json.loads(status_path.read_text(encoding="utf-8"))
    return _evaluate_agent_health(status, status_path=status_path, stale_after=stale_after)


def build_agent_health(status_path: Path, *, stale_after: float | None = None) -> dict[str, Any]:
    if not status_path.exists():
        return {
            "agent": {
                "state": "unknown",
                "stopped_reason": "status_file_missing",
                "updated_at": None,
            },
            "healthy": False,
            "reason": "unknown",
            "status_file": str(status_path),
        }
    return read_agent_health(status_path, stale_after=stale_after)


def write_pid_file(pid_path: Path) -> None:
    pid_path.parent.mkdir(parents=True, exist_ok=True)
    pid_path.write_text(f"{os.getpid()}\n", encoding="utf-8")


def remove_pid_file(pid_path: Path) -> None:
    pid_path.unlink(missing_ok=True)


def _evaluate_agent_health(
    status: dict[str, Any],
    *,
    status_path: Path,
    stale_after: float | None,
) -> dict[str, Any]:
    reason = "ok"
    healthy = True
    if status.get("collector_available") is False:
        reason = "collector_unavailable"
        healthy = False
    elif status.get("state") == "error" or status.get("last_error"):
        reason = "error"
        healthy = False
    elif stale_after is not None and _status_age_seconds(status.get("updated_at")) > stale_after:
        reason = "stale"
        healthy = False
    return {
        "agent": status,
        "healthy": healthy,
        "reason": reason,
        "status_file": str(status_path),
    }


def _status_state(stopped_reason: str) -> str:
    if stopped_reason == "running":
        return "running"
    if stopped_reason in {"collector_unavailable", "error"}:
        return "error"
    return "stopped"


def _elapsed_seconds(started_at: str, updated_at: str) -> float:
    return max(0.0, (_parse_utc(updated_at) - _parse_utc(started_at)).total_seconds())


def _status_age_seconds(updated_at: object) -> float:
    if not isinstance(updated_at, str):
        return float("inf")
    return max(0.0, (datetime.now(UTC) - _parse_utc(updated_at)).total_seconds())


def _parse_utc(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _should_rotate(output: _RotatableOutput, line: str, rotate_bytes: int | None) -> bool:
    if rotate_bytes is None or rotate_bytes <= 0:
        return False
    current_size = output.tell()
    if current_size <= 0:
        return False
    return current_size + len(line.encode("utf-8")) > rotate_bytes


def _rotate_output_files(output_path: Path, *, max_rotated_files: int) -> None:
    if max_rotated_files <= 0:
        output_path.unlink(missing_ok=True)
        return
    oldest = output_path.with_name(f"{output_path.name}.{max_rotated_files}")
    oldest.unlink(missing_ok=True)
    for index in range(max_rotated_files - 1, 0, -1):
        source = output_path.with_name(f"{output_path.name}.{index}")
        if source.exists():
            source.replace(output_path.with_name(f"{output_path.name}.{index + 1}"))
    if output_path.exists():
        output_path.replace(output_path.with_name(f"{output_path.name}.1"))


def _write_line_with_retries(
    output: _WritableOutput,
    line: str,
    *,
    retry_count: int,
    retry_delay: float,
    on_backpressure: Callable[[], None],
) -> int:
    retries = 0
    while True:
        try:
            output.write(line)
            output.flush()
            return retries
        except OSError:
            if retries >= retry_count:
                raise
            retries += 1
            on_backpressure()
            if retry_delay > 0:
                time.sleep(retry_delay)


def _enforce_output_retention(
    output_path: Path,
    *,
    max_output_bytes: int | None,
) -> dict[str, int]:
    retained_bytes = _output_family_size(output_path)
    if max_output_bytes is None or max_output_bytes <= 0:
        return {"dropped_files": 0, "retained_bytes": retained_bytes}
    dropped_files = 0
    for rotated_file in _rotated_output_files_oldest_first(output_path):
        if retained_bytes <= max_output_bytes:
            break
        file_size = rotated_file.stat().st_size
        rotated_file.unlink()
        retained_bytes -= file_size
        dropped_files += 1
    return {"dropped_files": dropped_files, "retained_bytes": retained_bytes}


def _output_family_size(output_path: Path) -> int:
    return sum(path.stat().st_size for path in _output_family_files(output_path))


def _output_family_files(output_path: Path) -> list[Path]:
    paths = [output_path] if output_path.exists() else []
    paths.extend(_rotated_output_files_oldest_first(output_path))
    return paths


def _rotated_output_files_oldest_first(output_path: Path) -> list[Path]:
    rotated_files: list[tuple[int, Path]] = []
    for path in output_path.parent.glob(f"{output_path.name}.*"):
        suffix = path.name.removeprefix(f"{output_path.name}.")
        if suffix.isdigit():
            rotated_files.append((int(suffix), path))
    return [path for _, path in sorted(rotated_files, reverse=True)]


def _install_signal_handlers() -> Callable[[], None]:
    previous_int = signal.getsignal(signal.SIGINT)
    previous_term = signal.getsignal(signal.SIGTERM)

    def handle_signal(signum: int, frame: FrameType | None) -> None:
        raise KeyboardInterrupt

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    def restore() -> None:
        signal.signal(signal.SIGINT, previous_int)
        signal.signal(signal.SIGTERM, previous_term)

    return restore


def _utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _build_agent_collector(config: EndpointAgentConfig) -> EndpointCollector:
    if config.collector == "mock":
        return MockEndpointCollector(
            session_id=config.session_id,
            host_id=config.host_id or "host_mock",
        )
    if config.collector == "linux":
        collector = LinuxEbpfCollector(
            session_id=config.session_id,
            host_id=config.host_id,
            limit=config.limit,
            sensitive_path_prefixes=config.sensitive_path_prefixes,
            poll_timeout_ms=config.bcc_poll_timeout_ms,
            max_queue=config.bcc_max_queue,
        )
        collector.check_available()
        return collector
    raise ValueError(f"unknown endpoint agent collector: {config.collector}")


def _build_collector_status_provider(
    collector: EndpointCollector,
) -> Callable[[], dict[str, Any] | None] | None:
    if isinstance(collector, LinuxEbpfCollector):
        return collector.status_snapshot
    return None


def _build_collector_stop_handler(collector: EndpointCollector) -> Callable[[], None] | None:
    if isinstance(collector, LinuxEbpfCollector):
        return collector.stop
    return None
