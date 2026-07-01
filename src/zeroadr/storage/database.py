from __future__ import annotations

import sqlite3
from datetime import UTC, datetime
from pathlib import Path

from zeroadr.core.approvals import ApprovalRequest, ApprovalStatus, ResolvedApprovalStatus
from zeroadr.core.events import RuntimeEvent
from zeroadr.core.findings import Finding
from zeroadr.core.policies import PolicyDecision
from zeroadr.core.tool_result_gate import ToolResultGateRecord
from zeroadr.core.runtime_gate import RuntimeGateRecord
from zeroadr.llm.models import LLMAdjudication, LLMAnalysis


class ApprovalAlreadyResolvedError(Exception):
    def __init__(self, request: ApprovalRequest) -> None:
        self.request = request
        super().__init__(f"Approval already resolved: {request.approval_id}")


class SQLiteStore:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._init()

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.path)

    def _init(self) -> None:
        with self._connect() as conn:
            conn.execute("create table if not exists sessions (session_id text primary key)")
            conn.execute(
                "create table if not exists events "
                "(event_id text primary key, session_id text not null, event_json text not null)"
            )
            conn.execute(
                "create table if not exists findings "
                "(finding_id text primary key, session_id text not null, finding_json text not null)"
            )
            conn.execute(
                "create table if not exists policy_decisions "
                "(decision_id text primary key, session_id text not null, decision_json text not null)"
            )
            conn.execute(
                "create table if not exists approval_requests "
                "(approval_id text primary key, session_id text not null, decision_id text not null, "
                "status text not null, request_json text not null)"
            )
            conn.execute(
                "create table if not exists llm_analyses "
                "(analysis_id text primary key, session_id text not null, created_at text not null, "
                "status text not null, analysis_json text not null)"
            )
            conn.execute(
                "create index if not exists idx_llm_analyses_session_created "
                "on llm_analyses(session_id, created_at, analysis_id)"
            )
            conn.execute(
                "create table if not exists llm_adjudications "
                "(adjudication_id text primary key, session_id text not null, event_id text not null, "
                "created_at text not null, status text not null, adjudication_json text not null)"
            )
            conn.execute(
                "create index if not exists idx_llm_adjudications_session_created "
                "on llm_adjudications(session_id, created_at, adjudication_id)"
            )
            conn.execute(
                "create table if not exists tool_result_gate_records "
                "(gate_record_id text primary key, session_id text not null, event_id text not null, "
                "created_at text not null, record_json text not null)"
            )
            conn.execute(
                "create index if not exists idx_tool_result_gate_session_created "
                "on tool_result_gate_records(session_id, created_at, gate_record_id)"
            )
            conn.execute(
                "create table if not exists runtime_gate_records "
                "(gate_record_id text primary key, session_id text not null, event_id text not null, "
                "created_at text not null, record_json text not null)"
            )
            conn.execute(
                "create index if not exists idx_runtime_gate_session_created "
                "on runtime_gate_records(session_id, created_at, gate_record_id)"
            )

    def save_event(self, event: RuntimeEvent) -> None:
        with self._connect() as conn:
            conn.execute("insert or ignore into sessions(session_id) values (?)", (event.session_id,))
            conn.execute(
                "insert or replace into events(event_id, session_id, event_json) values (?, ?, ?)",
                (event.event_id, event.session_id, event.model_dump_json()),
            )

    def save_finding(self, finding: Finding) -> None:
        with self._connect() as conn:
            conn.execute("insert or ignore into sessions(session_id) values (?)", (finding.session_id,))
            conn.execute(
                "insert or replace into findings(finding_id, session_id, finding_json) values (?, ?, ?)",
                (finding.finding_id, finding.session_id, finding.model_dump_json()),
            )

    def save_policy_decision(self, decision: PolicyDecision) -> None:
        with self._connect() as conn:
            conn.execute("insert or ignore into sessions(session_id) values (?)", (decision.session_id,))
            conn.execute(
                "insert or replace into policy_decisions(decision_id, session_id, decision_json) "
                "values (?, ?, ?)",
                (decision.decision_id, decision.session_id, decision.model_dump_json()),
            )

    def save_llm_analysis(self, analysis: LLMAnalysis) -> None:
        with self._connect() as conn:
            conn.execute("insert or ignore into sessions(session_id) values (?)", (analysis.session_id,))
            conn.execute(
                "insert or replace into llm_analyses"
                "(analysis_id, session_id, created_at, status, analysis_json) values (?, ?, ?, ?, ?)",
                (
                    analysis.analysis_id,
                    analysis.session_id,
                    analysis.created_at.isoformat(),
                    analysis.status,
                    analysis.model_dump_json(),
                ),
            )

    def llm_analyses_for_session(self, session_id: str) -> list[LLMAnalysis]:
        with self._connect() as conn:
            rows = conn.execute(
                "select analysis_json from llm_analyses where session_id = ? "
                "order by created_at, analysis_id",
                (session_id,),
            )
            return [LLMAnalysis.model_validate_json(row[0]) for row in rows]

    def save_llm_adjudication(self, adjudication: LLMAdjudication) -> None:
        with self._connect() as conn:
            conn.execute(
                "insert or ignore into sessions(session_id) values (?)",
                (adjudication.session_id,),
            )
            conn.execute(
                "insert or replace into llm_adjudications"
                "(adjudication_id, session_id, event_id, created_at, status, adjudication_json) "
                "values (?, ?, ?, ?, ?, ?)",
                (
                    adjudication.adjudication_id,
                    adjudication.session_id,
                    adjudication.event_id,
                    adjudication.created_at.isoformat(),
                    adjudication.status,
                    adjudication.model_dump_json(),
                ),
            )

    def save_tool_result_gate_record(self, record: ToolResultGateRecord) -> None:
        with self._connect() as conn:
            conn.execute("insert or ignore into sessions(session_id) values (?)", (record.session_id,))
            conn.execute(
                "insert or replace into tool_result_gate_records"
                "(gate_record_id, session_id, event_id, created_at, record_json) values (?, ?, ?, ?, ?)",
                (
                    record.gate_record_id,
                    record.session_id,
                    record.event_id,
                    record.created_at.isoformat(),
                    record.model_dump_json(),
                ),
            )

    def tool_result_gate_records_for_session(self, session_id: str) -> list[ToolResultGateRecord]:
        with self._connect() as conn:
            rows = conn.execute(
                "select record_json from tool_result_gate_records where session_id = ? "
                "order by created_at, gate_record_id",
                (session_id,),
            )
            return [ToolResultGateRecord.model_validate_json(row[0]) for row in rows]

    def tool_result_gate_records(self) -> list[ToolResultGateRecord]:
        with self._connect() as conn:
            rows = conn.execute(
                "select record_json from tool_result_gate_records order by created_at, gate_record_id"
            )
            return [ToolResultGateRecord.model_validate_json(row[0]) for row in rows]

    def save_runtime_gate_record(self, record: RuntimeGateRecord) -> None:
        with self._connect() as conn:
            conn.execute("insert or ignore into sessions(session_id) values (?)", (record.session_id,))
            conn.execute(
                "insert or replace into runtime_gate_records"
                "(gate_record_id, session_id, event_id, created_at, record_json) values (?, ?, ?, ?, ?)",
                (
                    record.gate_record_id,
                    record.session_id,
                    record.event_id,
                    record.created_at.isoformat(),
                    record.model_dump_json(),
                ),
            )

    def runtime_gate_records_for_session(self, session_id: str) -> list[RuntimeGateRecord]:
        with self._connect() as conn:
            rows = conn.execute(
                "select record_json from runtime_gate_records where session_id = ? "
                "order by created_at, gate_record_id",
                (session_id,),
            )
            return [RuntimeGateRecord.model_validate_json(row[0]) for row in rows]

    def runtime_gate_records(self) -> list[RuntimeGateRecord]:
        with self._connect() as conn:
            rows = conn.execute(
                "select record_json from runtime_gate_records order by created_at, gate_record_id"
            )
            return [RuntimeGateRecord.model_validate_json(row[0]) for row in rows]

    def llm_adjudications_for_session(self, session_id: str) -> list[LLMAdjudication]:
        return self.llm_adjudications(session_id=session_id)

    def llm_adjudications(self, *, session_id: str | None = None) -> list[LLMAdjudication]:
        with self._connect() as conn:
            if session_id is None:
                rows = conn.execute(
                    "select adjudication_json from llm_adjudications "
                    "order by created_at, adjudication_id"
                )
            else:
                rows = conn.execute(
                    "select adjudication_json from llm_adjudications where session_id = ? "
                    "order by created_at, adjudication_id",
                    (session_id,),
                )
            return [LLMAdjudication.model_validate_json(row[0]) for row in rows]

    def list_sessions(self) -> list[str]:
        with self._connect() as conn:
            return [row[0] for row in conn.execute("select session_id from sessions order by session_id")]

    def events_for_session(self, session_id: str) -> list[RuntimeEvent]:
        with self._connect() as conn:
            rows = conn.execute(
                "select event_json from events where session_id = ? order by rowid",
                (session_id,),
            )
            return [RuntimeEvent.model_validate_json(row[0]) for row in rows]

    def findings_for_session(self, session_id: str) -> list[Finding]:
        with self._connect() as conn:
            rows = conn.execute(
                "select finding_json from findings where session_id = ? order by rowid",
                (session_id,),
            )
            return [Finding.model_validate_json(row[0]) for row in rows]

    def policy_decisions_for_session(self, session_id: str) -> list[PolicyDecision]:
        with self._connect() as conn:
            rows = conn.execute(
                "select decision_json from policy_decisions where session_id = ? order by rowid",
                (session_id,),
            )
            return [PolicyDecision.model_validate_json(row[0]) for row in rows]

    def save_approval_request(self, request: ApprovalRequest) -> None:
        with self._connect() as conn:
            conn.execute("insert or ignore into sessions(session_id) values (?)", (request.session_id,))
            conn.execute(
                "insert or replace into approval_requests"
                "(approval_id, session_id, decision_id, status, request_json) values (?, ?, ?, ?, ?)",
                (
                    request.approval_id,
                    request.session_id,
                    request.decision_id,
                    request.status,
                    request.model_dump_json(),
                ),
            )

    def get_approval_request(self, approval_id: str) -> ApprovalRequest | None:
        with self._connect() as conn:
            row = conn.execute(
                "select request_json from approval_requests where approval_id = ?",
                (approval_id,),
            ).fetchone()
            if row is None:
                return None
            return ApprovalRequest.model_validate_json(row[0])

    def list_approval_requests(
        self,
        *,
        status: ApprovalStatus | None = None,
        session_id: str | None = None,
        limit: int | None = None,
        offset: int = 0,
    ) -> list[ApprovalRequest]:
        # Build query parts safely - all dynamic parts use placeholders
        query_parts = ["select request_json from approval_requests"]
        params: list[object] = []

        # Build WHERE clause with parameterized conditions
        where_conditions: list[str] = []
        if status is not None:
            where_conditions.append("status = ?")
            params.append(status)
        if session_id is not None:
            where_conditions.append("session_id = ?")
            params.append(session_id)

        if where_conditions:
            query_parts.append("where")
            query_parts.append(" and ".join(where_conditions))

        # Add ordering
        query_parts.append("order by rowid")

        # Add pagination with placeholders
        if limit is not None:
            query_parts.append("limit ? offset ?")
            params.extend([limit, offset])

        query = " ".join(query_parts)

        with self._connect() as conn:
            rows = conn.execute(query, params)
            return [ApprovalRequest.model_validate_json(row[0]) for row in rows]

    def resolve_approval_request(
        self,
        approval_id: str,
        *,
        status: ResolvedApprovalStatus,
        resolved_by: str,
        comment: str | None = None,
    ) -> ApprovalRequest:
        return self._transition_approval_request(
            approval_id,
            status=status,
            resolved_by=resolved_by,
            comment=comment,
        )

    def mark_approval_expired(self, approval_id: str) -> ApprovalRequest:
        return self._transition_approval_request(
            approval_id,
            status="expired",
            resolved_by="system",
            comment="Approval expired before human resolution.",
        )

    def _transition_approval_request(
        self,
        approval_id: str,
        *,
        status: ApprovalStatus,
        resolved_by: str,
        comment: str | None,
    ) -> ApprovalRequest:
        with self._connect() as conn:
            # Use a single atomic operation to prevent race conditions
            # First, read the current state
            row = conn.execute(
                "select request_json from approval_requests where approval_id = ?",
                (approval_id,),
            ).fetchone()
            if row is None:
                raise KeyError(approval_id)
            request = ApprovalRequest.model_validate_json(row[0])

            # Build the transitioned request
            transitioned = request.model_copy(
                update={
                    "status": status,
                    "resolved_at": datetime.now(UTC),
                    "resolved_by": resolved_by,
                    "resolution_comment": comment,
                }
            )

            # Atomic update with status check - only succeeds if still pending
            # This prevents concurrent modifications from succeeding
            cursor = conn.execute(
                "update approval_requests set status = ?, request_json = ? "
                "where approval_id = ? and status = 'pending'",
                (transitioned.status, transitioned.model_dump_json(), approval_id),
            )

            # Check if the update succeeded
            if cursor.rowcount == 1:
                conn.commit()
                return transitioned

            # Update failed - either already resolved or deleted
            current_row = conn.execute(
                "select request_json from approval_requests where approval_id = ?",
                (approval_id,),
            ).fetchone()
            if current_row is None:
                raise KeyError(approval_id)

            # Already resolved by another request
            raise ApprovalAlreadyResolvedError(
                ApprovalRequest.model_validate_json(current_row[0])
            )

    def pending_approval_count(self, *, session_id: str | None = None) -> int:
        query = "select count(*) from approval_requests where status = 'pending'"
        params: list[object] = []
        if session_id is not None:
            query += " and session_id = ?"
            params.append(session_id)
        with self._connect() as conn:
            row = conn.execute(query, params).fetchone()
            return int(row[0]) if row is not None else 0
