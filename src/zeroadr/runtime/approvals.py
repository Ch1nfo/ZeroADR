from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

from zeroadr.core.approvals import ApprovalRequest, ResolvedApprovalStatus
from zeroadr.core.events import RuntimeEvent, SourceType, new_event
from zeroadr.security.redaction import redact_event
from zeroadr.storage.database import ApprovalAlreadyResolvedError, SQLiteStore
from zeroadr.storage.jsonl import write_event_jsonl

DEFAULT_APPROVAL_TIMEOUT_SECONDS = 300.0


def expire_stale_pending_approvals(
    store: SQLiteStore,
    *,
    max_age_seconds: float = DEFAULT_APPROVAL_TIMEOUT_SECONDS,
    source_type: SourceType = "hook",
    trace_path: Path | None = None,
) -> list[ApprovalRequest]:
    cutoff = datetime.now(UTC) - timedelta(seconds=max_age_seconds)
    expired: list[ApprovalRequest] = []
    for request in store.list_approval_requests(status="pending"):
        if request.created_at <= cutoff:
            try:
                expired.append(
                    mark_approval_expired_with_audit(
                        store,
                        request.approval_id,
                        source_type=source_type,
                        trace_path=trace_path,
                    )
                )
            except ApprovalAlreadyResolvedError:
                continue
    return expired


def resolve_approval_with_audit(
    store: SQLiteStore,
    approval_id: str,
    *,
    status: ResolvedApprovalStatus,
    resolved_by: str,
    comment: str | None = None,
    source_type: SourceType = "hook",
    trace_path: Path | None = None,
) -> ApprovalRequest:
    expire_stale_pending_approvals(store)
    resolved = store.resolve_approval_request(
        approval_id,
        status=status,
        resolved_by=resolved_by,
        comment=comment,
    )
    record_approval_resolution(
        resolved,
        store=store,
        source_type=source_type,
        trace_path=trace_path,
    )
    return resolved


def mark_approval_expired_with_audit(
    store: SQLiteStore,
    approval_id: str,
    *,
    source_type: SourceType = "hook",
    trace_path: Path | None = None,
) -> ApprovalRequest:
    expired = store.mark_approval_expired(approval_id)
    record_approval_resolution(
        expired,
        store=store,
        source_type=source_type,
        trace_path=trace_path,
    )
    return expired


def record_approval_resolution(
    request: ApprovalRequest,
    *,
    store: SQLiteStore | None,
    source_type: SourceType,
    trace_path: Path | None = None,
) -> RuntimeEvent:
    event = new_event(
        event_type="approval.resolved",
        source_type=source_type,
        session_id=request.session_id,
        request_id=request.request_id,
        tool_name=request.tool_name,
        capability=request.capability,
        arguments=request.arguments,
        result={
            "approval_id": request.approval_id,
            "decision_id": request.decision_id,
            "status": request.status,
            "resolved_by": request.resolved_by,
        },
        raw=request.model_dump(mode="json"),
    )
    stored_event = redact_event(event)
    if trace_path is not None:
        write_event_jsonl(trace_path, stored_event)
    if store is not None:
        store.save_event(stored_event)
    return stored_event
