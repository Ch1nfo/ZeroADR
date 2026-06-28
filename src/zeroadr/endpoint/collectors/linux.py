from __future__ import annotations

import threading
from typing import Any, Callable, Iterator

from zeroadr.endpoint.collectors.base import EndpointCollector
from zeroadr.endpoint.collectors.linux_bcc import (
    BccCollectorSession,
    BccCollectorUnavailable,
    DEFAULT_MAX_QUEUE,
    DEFAULT_POLL_TIMEOUT_MS,
    DEFAULT_SENSITIVE_PATH_PREFIXES,
    check_bcc_available,
    iter_bcc_records,
)
from zeroadr.endpoint.contracts import EndpointRecord


class LinuxCollectorUnavailable(RuntimeError):
    pass


class LinuxEbpfCollector(EndpointCollector):
    def __init__(
        self,
        *,
        session_id: str = "sess_linux_bcc",
        host_id: str | None = None,
        limit: int | None = None,
        sensitive_path_prefixes: tuple[str, ...] | None = None,
        poll_timeout_ms: int = DEFAULT_POLL_TIMEOUT_MS,
        max_queue: int = DEFAULT_MAX_QUEUE,
        stop_event: threading.Event | None = None,
        on_status_update: Callable[[], None] | None = None,
    ) -> None:
        self.session_id = session_id
        self.host_id = host_id
        self.limit = limit
        self.sensitive_path_prefixes = sensitive_path_prefixes or DEFAULT_SENSITIVE_PATH_PREFIXES
        self.poll_timeout_ms = poll_timeout_ms
        self.max_queue = max_queue
        self._stop_event = stop_event or threading.Event()
        self._on_status_update = on_status_update
        self._session: BccCollectorSession | None = None
        self._degrade_reason: str | None = None

    def check_available(self) -> None:
        try:
            check_bcc_available()
        except BccCollectorUnavailable as exc:
            raise LinuxCollectorUnavailable(str(exc)) from exc

    def stop(self) -> None:
        self._stop_event.set()
        if self._session is not None:
            self._session.stop()

    def status_snapshot(self) -> dict[str, Any] | None:
        if self._session is None:
            if self._degrade_reason:
                return {
                    "enabled": False,
                    "reason": self._degrade_reason,
                    "probes": {},
                    "dropped_events": 0,
                    "last_event_at": None,
                }
            return None
        return self._session.status_snapshot()

    def iter_records(self) -> Iterator[EndpointRecord]:
        try:
            self.check_available()
        except LinuxCollectorUnavailable as exc:
            self._degrade_reason = str(exc)
            return
        session = BccCollectorSession(
            session_id=self.session_id,
            host_id=self.host_id,
            limit=self.limit,
            sensitive_path_prefixes=self.sensitive_path_prefixes,
            poll_timeout_ms=self.poll_timeout_ms,
            max_queue=self.max_queue,
            stop_event=self._stop_event,
            on_status_update=self._on_status_update,
        )
        self._session = session
        try:
            yield from session.iter_records()
        except BccCollectorUnavailable as exc:
            self._degrade_reason = str(exc)
            raise LinuxCollectorUnavailable(str(exc)) from exc


def iter_linux_bcc_records(
    *,
    session_id: str,
    host_id: str | None = None,
    limit: int | None = None,
    sensitive_path_prefixes: tuple[str, ...] | None = None,
    poll_timeout_ms: int = DEFAULT_POLL_TIMEOUT_MS,
    max_queue: int = DEFAULT_MAX_QUEUE,
) -> Iterator[EndpointRecord]:
    yield from iter_bcc_records(
        session_id=session_id,
        host_id=host_id,
        limit=limit,
        sensitive_path_prefixes=sensitive_path_prefixes or DEFAULT_SENSITIVE_PATH_PREFIXES,
        poll_timeout_ms=poll_timeout_ms,
        max_queue=max_queue,
    )
