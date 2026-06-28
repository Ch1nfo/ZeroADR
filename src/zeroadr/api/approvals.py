from __future__ import annotations

from pathlib import Path
from typing import Any

from zeroadr.core.approvals import ApprovalRequest, ResolvedApprovalStatus
from zeroadr.core.events import SourceType
from zeroadr.runtime.approvals import expire_stale_pending_approvals, resolve_approval_with_audit
from zeroadr.storage.database import SQLiteStore


def build_approvals_index(
    db_path: Path,
    *,
    status: str | None = None,
    limit: int | None = None,
    offset: int = 0,
    max_age_seconds: float | None = None,
) -> dict[str, Any]:
    store = SQLiteStore(db_path)
    if max_age_seconds is not None:
        expire_stale_pending_approvals(store, max_age_seconds=max_age_seconds)
    requests = store.list_approval_requests(
        status=status,  # type: ignore[arg-type]
        limit=limit,
        offset=offset,
    )
    return {
        "approvals": [_approval_payload(store, request) for request in requests],
        "pending_count": store.pending_approval_count(),
        "limit": limit,
        "offset": offset,
    }


def build_approval_detail(db_path: Path, approval_id: str, *, max_age_seconds: float | None = None) -> dict[str, Any] | None:
    store = SQLiteStore(db_path)
    if max_age_seconds is not None:
        expire_stale_pending_approvals(store, max_age_seconds=max_age_seconds)
    request = store.get_approval_request(approval_id)
    if request is None:
        return None
    return _approval_payload(store, request)


def resolve_approval(
    db_path: Path,
    approval_id: str,
    *,
    status: ResolvedApprovalStatus,
    resolved_by: str = "console",
    comment: str | None = None,
    source_type: SourceType = "hook",
    trace_path: Path | None = None,
    max_age_seconds: float | None = None,
) -> ApprovalRequest:
    store = SQLiteStore(db_path)
    if max_age_seconds is not None:
        expire_stale_pending_approvals(store, max_age_seconds=max_age_seconds)
    return resolve_approval_with_audit(
        store,
        approval_id,
        status=status,
        resolved_by=resolved_by,
        comment=comment,
        source_type=source_type,
        trace_path=trace_path,
    )


def _approval_payload(store: SQLiteStore, request: ApprovalRequest) -> dict[str, Any]:
    findings = {
        finding.finding_id: finding.model_dump(mode="json")
        for finding in store.findings_for_session(request.session_id)
        if finding.finding_id in request.finding_ids
    }
    event = next(
        (
            event.model_dump(mode="json")
            for event in store.events_for_session(request.session_id)
            if event.event_id == request.event_id
        ),
        None,
    )
    return {
        "approval": request.model_dump(mode="json"),
        "related_event": event,
        "related_findings": list(findings.values()),
    }
