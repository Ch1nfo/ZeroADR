from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from zeroadr.core.approvals import ApprovalRequest
from zeroadr.runtime.approvals import (
    DEFAULT_APPROVAL_TIMEOUT_SECONDS,
    expire_stale_pending_approvals,
    mark_approval_expired_with_audit,
)
from zeroadr.storage.database import SQLiteStore


def effective_action_for_status(status: str) -> str:
    if status == "approved":
        return "allow"
    if status in {"denied", "expired"}:
        return "block"
    return status


def build_wait_approval_response(request: ApprovalRequest) -> dict[str, Any]:
    return {
        "approval_id": request.approval_id,
        "decision_id": request.decision_id,
        "session_id": request.session_id,
        "event_id": request.event_id,
        "status": request.status,
        "effective_action": effective_action_for_status(request.status),
        "resolved_at": request.resolved_at.isoformat() if request.resolved_at else None,
        "resolved_by": request.resolved_by,
        "resolution_comment": request.resolution_comment,
    }


def wait_for_approval_resolution(
    db_path: Path,
    approval_id: str,
    *,
    timeout: float,
    poll_interval: float,
    trace_path: Path | None = None,
    max_age_seconds: float = DEFAULT_APPROVAL_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    store = SQLiteStore(db_path)
    deadline = time.monotonic() + timeout
    while True:
        expire_stale_pending_approvals(store, max_age_seconds=max_age_seconds)
        request = store.get_approval_request(approval_id)
        if request is None:
            raise KeyError(approval_id)
        if request.status != "pending":
            return build_wait_approval_response(request)
        if time.monotonic() >= deadline:
            try:
                expired = mark_approval_expired_with_audit(
                    store,
                    approval_id,
                    trace_path=trace_path,
                )
            except Exception:
                request = store.get_approval_request(approval_id)
                if request is None:
                    raise KeyError(approval_id) from None
                return build_wait_approval_response(request)
            return build_wait_approval_response(expired)
        time.sleep(poll_interval)
