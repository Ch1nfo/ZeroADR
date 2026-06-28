from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any

from zeroadr.endpoint.lite import ingest_endpoint_jsonl
from zeroadr.runtime.approvals import resolve_approval_with_audit
from zeroadr.hook.adapter import HookRuntime
from zeroadr.hook.models import HookEvent
from zeroadr.policy.engine import PolicyEngine
from zeroadr.replay.runner import replay_trace
from zeroadr.storage.database import SQLiteStore

DEFAULT_DEMO_RUNTIME_TRACES = [
    Path("examples/traces/09_injection_to_sensitive_file_chain.jsonl"),
    Path("examples/traces/10_injection_to_dangerous_shell_chain.jsonl"),
    Path("examples/traces/12_sensitive_file_to_external_post.jsonl"),
    Path("examples/traces/14_normal_network_after_readme.jsonl"),
]
DEFAULT_DEMO_ENDPOINT_JSONL = [
    Path("examples/endpoint/01_sensitive_file_to_external_network.jsonl"),
]


def seed_demo_database(
    db_path: Path,
    *,
    runtime_traces: list[Path] | None = None,
    endpoint_jsonl: list[Path] | None = None,
    policy_path: Path = Path("policies/strict.yaml"),
) -> dict[str, Any]:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    db_path.unlink(missing_ok=True)
    store = SQLiteStore(db_path)
    policy = PolicyEngine.from_file(policy_path) if policy_path.exists() else PolicyEngine()
    seeded_sources: list[str] = []

    for trace_path in runtime_traces or DEFAULT_DEMO_RUNTIME_TRACES:
        if not trace_path.exists():
            continue
        _persist_trace(store, replay_trace(trace_path, policy))
        seeded_sources.append(str(trace_path))

    for endpoint_path in endpoint_jsonl or DEFAULT_DEMO_ENDPOINT_JSONL:
        if not endpoint_path.exists():
            continue
        with tempfile.TemporaryDirectory(prefix="zeroadr-demo-") as temp_dir:
            runtime_trace_path = Path(temp_dir) / "endpoint-runtime.jsonl"
            ingest_endpoint_jsonl(
                endpoint_path,
                trace_path=runtime_trace_path,
                db_path=None,
                strict=True,
            )
            _persist_trace(store, replay_trace(runtime_trace_path, policy))
        seeded_sources.append(str(endpoint_path))

    approval_sources = _seed_approval_demo(db_path)
    seeded_sources.extend(approval_sources)

    session_ids = store.list_sessions()
    return {
        "db": str(db_path),
        "session_count": len(session_ids),
        "session_ids": session_ids,
        "sources": seeded_sources,
    }


def _persist_trace(store: SQLiteStore, trace: Any) -> None:
    for event in trace.events:
        store.save_event(event)
    for finding in trace.findings:
        store.save_finding(finding)
    for decision in trace.policy_decisions:
        store.save_policy_decision(decision)


def _seed_approval_demo(db_path: Path) -> list[str]:
    policy_path = Path("policies/approval.yaml")
    if not policy_path.exists():
        return []
    runtime = HookRuntime(policy_engine=PolicyEngine.from_file(policy_path), db_path=db_path)
    pending_event = HookEvent(
        hook_event_type="pre_tool_use",
        session_id="sess_demo_approval_pending",
        request_id="demo_pending",
        tool_name="read_file",
        arguments={"path": ".env"},
        raw={"source": "demo"},
    )
    resolved_event = HookEvent(
        hook_event_type="pre_tool_use",
        session_id="sess_demo_approval_resolved",
        request_id="demo_resolved",
        tool_name="read_file",
        arguments={"path": ".env"},
        raw={"source": "demo"},
    )
    pending_response = runtime.handle(pending_event)
    resolved_response = runtime.handle(resolved_event)
    store = SQLiteStore(db_path)
    if resolved_response.approval_id:
        resolve_approval_with_audit(
            store,
            resolved_response.approval_id,
            status="approved",
            resolved_by="demo",
            comment="Seeded resolved approval for Console history.",
        )
    sources = [str(policy_path), "approval:pending"]
    if pending_response.approval_id:
        sources.append(f"approval:{pending_response.approval_id}")
    return sources
