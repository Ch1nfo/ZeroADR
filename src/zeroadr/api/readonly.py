from __future__ import annotations

from pathlib import Path
from typing import Any

from zeroadr.reconstruction.agent_bom import bom_from_context
from zeroadr.reconstruction.session import reconstruct_from_sqlite
from zeroadr.reconstruction.summary import summary_from_context
from zeroadr.storage.database import SQLiteStore

API_VERSION = "0.1"


def build_api_index(db_path: Path, *, limit: int | None = None, offset: int = 0) -> dict[str, Any]:
    store = SQLiteStore(db_path)
    session_ids = store.list_sessions()
    selected_session_ids = _slice_values(session_ids, limit=limit, offset=offset)
    sessions = [_session_index_item(session_id, db_path, store) for session_id in selected_session_ids]
    return {
        "api_version": API_VERSION,
        "source": {"type": "sqlite", "path": str(db_path)},
        "session_count": len(session_ids),
        "limit": limit,
        "offset": offset,
        "returned_count": len(sessions),
        "sessions": sessions,
    }


def build_api_session(session_id: str, db_path: Path, *, compact: bool = False) -> dict[str, Any]:
    context = reconstruct_from_sqlite(session_id, db_path)
    summary = summary_from_context(context)
    if compact:
        return {
            "api_version": API_VERSION,
            "source": {"type": "sqlite", "path": str(db_path)},
            "session_id": session_id,
            "summary": summary,
            "risk": summary.get("risk_summary", {}),
            "timeline": context.get("timeline", []),
            "inventory": _inventory_from_summary(summary),
        }
    return {
        "api_version": API_VERSION,
        "source": {"type": "sqlite", "path": str(db_path)},
        "session_id": session_id,
        "context": context,
        "summary": summary,
        "agent_bom": bom_from_context(context, generated_from="api"),
    }


def _session_index_item(session_id: str, db_path: Path, store: SQLiteStore) -> dict[str, Any]:
    context = reconstruct_from_sqlite(session_id, db_path)
    events = store.events_for_session(session_id)
    findings = store.findings_for_session(session_id)
    decisions = store.policy_decisions_for_session(session_id)
    latest_event = events[-1] if events else None
    return {
        "session_id": session_id,
        "event_count": len(events),
        "finding_count": len(findings),
        "decision_count": len(decisions),
        "pending_approval_count": store.pending_approval_count(session_id=session_id),
        "latest_event_id": latest_event.event_id if latest_event else None,
        "latest_event_time": latest_event.event_time.isoformat() if latest_event else None,
        "risk_summary": context["risk_summary"],
    }


def _slice_values(values: list[str], *, limit: int | None, offset: int) -> list[str]:
    safe_offset = max(0, offset)
    if limit is None:
        return values[safe_offset:]
    return values[safe_offset : safe_offset + max(0, limit)]


def _inventory_from_summary(summary: dict[str, Any]) -> dict[str, Any]:
    return {
        "source_types": summary.get("source_types", []),
        "servers": summary.get("servers", []),
        "tools": summary.get("tools", []),
        "capabilities": summary.get("capabilities", []),
        "targets": summary.get("targets", []),
        "sensitive_targets": summary.get("sensitive_targets", []),
        "external_targets": summary.get("external_targets", []),
        "endpoint_event_count": summary.get("endpoint_event_count", 0),
        "process_count": summary.get("process_count", 0),
    }
