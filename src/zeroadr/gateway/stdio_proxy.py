from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from zeroadr.core.events import RuntimeEvent, new_event
from zeroadr.core.approvals import ApprovalRequest, new_approval_request
from zeroadr.core.findings import Finding
from zeroadr.core.ids import new_ulid
from zeroadr.core.policies import PolicyAction, new_policy_decision
from zeroadr.core.tool_result_gate import ToolResultGateRecord, new_tool_result_gate_record
from zeroadr.gateway.jsonrpc import encode_jsonrpc, encode_mcp_frame
from zeroadr.hook.approval_wait import wait_for_approval_resolution
from zeroadr.llm.adjudication import LLMAdjudicator, build_llm_adjudicator
from zeroadr.llm.models import LLMAdjudication
from zeroadr.llm.provider import LLMProviderError
from zeroadr.llm.tool_result_review import (
    PreparedToolResultReview,
    build_tool_result_review_payload,
    build_tool_result_reviewer,
)
from zeroadr.normalization.capability_mapper import map_capability
from zeroadr.policy.engine import PolicyEngine
from zeroadr.runtime.approvals import DEFAULT_APPROVAL_TIMEOUT_SECONDS
from zeroadr.runtime.service import RuntimeDecisionService


@dataclass(frozen=True)
class PendingCall:
    request_id: str | int
    tool_name: str | None
    arguments: dict[str, Any]
    event: RuntimeEvent


@dataclass(frozen=True)
class FramedMessage:
    message: dict[str, Any]
    raw: bytes
    framing: Literal["line", "mcp"]


@dataclass(frozen=True)
class ClientInspectionResult:
    block_response: dict[str, Any] | None = None
    approval_id: str | None = None
    pending: PendingCall | None = None


@dataclass(frozen=True)
class ToolResultInspectionResult:
    action: PolicyAction = "allow"
    error_code: int | None = None
    approval_request: ApprovalRequest | None = None
    adjudication: LLMAdjudication | None = None
    gate_record: ToolResultGateRecord | None = None


@dataclass(frozen=True)
class PreparedShadowToolResult:
    event: RuntimeEvent
    findings: list[Finding]
    review: PreparedToolResultReview


class GatewayRuntime:
    def __init__(
        self,
        *,
        session_id: str | None = None,
        server_name: str | None = None,
        policy_engine: PolicyEngine | None = None,
        trace_path: Path | None = None,
        db_path: Path | None = None,
        adjudicator: LLMAdjudicator | None = None,
        tool_result_reviewer: LLMAdjudicator | None = None,
    ) -> None:
        self.session_id = session_id or f"sess_{new_ulid()}"
        self.server_name = server_name
        self.policy_engine = policy_engine or PolicyEngine()
        self.trace_path = trace_path
        self.db_path = db_path
        self.decision_service = RuntimeDecisionService(
            source_type="mcp_gateway",
            policy_engine=self.policy_engine,
            trace_path=trace_path,
            db_path=db_path,
            adjudicator=adjudicator,
        )
        self.pending: dict[str | int, PendingCall] = {}
        self.tool_result_reviewer = tool_result_reviewer
        self.decision_service.record(
            new_event(
                event_type="session.start",
                source_type="mcp_gateway",
                session_id=self.session_id,
                server_name=self.server_name,
                raw={},
            )
        )

    def inspect_client_message(self, message: dict[str, Any]) -> ClientInspectionResult:
        if message.get("method") != "tools/call":
            return ClientInspectionResult()
        request_id = message.get("id")

        # Validate request_id type - must be string or int per JSON-RPC spec
        if request_id is not None and not isinstance(request_id, (str, int)):
            # Invalid request_id type - block with error
            error_response = {
                "jsonrpc": "2.0",
                "id": None,
                "error": {
                    "code": -32600,
                    "message": "Invalid Request",
                    "data": {"reason": "request id must be a string, number, or null"},
                },
            }
            return ClientInspectionResult(block_response=error_response)

        params_obj = message.get("params")
        params: dict[str, Any] = params_obj if isinstance(params_obj, dict) else {}
        tool_name_obj = params.get("name")
        tool_name = tool_name_obj if isinstance(tool_name_obj, str) else None
        arguments_obj = params.get("arguments")
        arguments: dict[str, Any] = arguments_obj if isinstance(arguments_obj, dict) else {}
        mapping = map_capability(tool_name, arguments)
        event = new_event(
            event_type="tool.call.requested",
            source_type="mcp_gateway",
            session_id=self.session_id,
            request_id=request_id,
            server_name=self.server_name,
            tool_name=tool_name,
            capability=mapping.capability,
            arguments=arguments,
            raw=message,
        )
        result = self.decision_service.evaluate(event)
        decision = result.decision
        if decision.action == "block":
            return ClientInspectionResult(
                block_response=self.policy_engine.render_jsonrpc_error(request_id, decision)
            )
        if decision.action == "require_approval":
            approval_id = result.approval_request.approval_id if result.approval_request else None
            pending = (
                PendingCall(request_id, tool_name, arguments, event)
                if isinstance(request_id, (str, int))
                else None
            )
            return ClientInspectionResult(approval_id=approval_id, pending=pending)
        pending = PendingCall(request_id, tool_name, arguments, event) if isinstance(request_id, (str, int)) else None
        if pending is not None:
            self.pending[pending.request_id] = pending
        return ClientInspectionResult(pending=pending)

    def inspect_server_message(
        self,
        message: dict[str, Any],
        *,
        response_byte_count: int = 0,
        resource_limit_exceeded: bool = False,
    ) -> ToolResultInspectionResult:
        request_id = message.get("id")
        if not isinstance(request_id, str | int):
            return ToolResultInspectionResult()
        pending = self.pending.pop(request_id, None)
        if not pending:
            return ToolResultInspectionResult()
        event = self._server_event(message, pending)
        gate = self.policy_engine.tool_result_gate
        if event.event_type != "tool.call.completed" or gate is None:
            self.decision_service.record(event)
            return ToolResultInspectionResult()
        return self._inspect_tool_result(
            event,
            response_byte_count=response_byte_count,
            resource_limit_exceeded=resource_limit_exceeded,
        )

    def _server_event(self, message: dict[str, Any], pending: PendingCall) -> RuntimeEvent:
        request_id = pending.request_id
        event_type: Literal["tool.call.failed", "tool.call.completed"] = (
            "tool.call.failed" if "error" in message else "tool.call.completed"
        )
        return new_event(
            event_type=event_type,
            source_type="mcp_gateway",
            session_id=self.session_id,
            request_id=request_id,
            server_name=self.server_name,
            tool_name=pending.tool_name,
            capability=pending.event.capability,
            arguments=pending.arguments,
            result=message.get("result"),
            error=message.get("error") if isinstance(message.get("error"), dict) else None,
            raw=message,
        )

    def prepare_shadow_tool_result(
        self, message: dict[str, Any]
    ) -> PreparedShadowToolResult | None:
        request_id = message.get("id")
        if not isinstance(request_id, str | int):
            return None
        pending = self.pending.pop(request_id, None)
        if pending is None:
            return None
        event = self._server_event(message, pending)
        if event.event_type != "tool.call.completed":
            self.decision_service.record(event)
            return None
        findings = self.decision_service.detector.detect(event)
        prepared = build_tool_result_review_payload(event, findings, case_id=event.event_id)
        sanitized_event = event.model_copy(
            update={"result": prepared.payload["event"]["result"], "raw": {}}
        )
        return PreparedShadowToolResult(
            event=sanitized_event,
            findings=findings,
            review=prepared,
        )

    def inspect_prepared_shadow_tool_result(
        self,
        prepared: PreparedShadowToolResult,
        *,
        response_byte_count: int,
    ) -> ToolResultInspectionResult:
        return self._inspect_tool_result(
            prepared.event,
            response_byte_count=response_byte_count,
            findings_override=prepared.findings,
            prepared_override=prepared.review,
        )

    def _inspect_tool_result(
        self,
        event: RuntimeEvent,
        *,
        response_byte_count: int,
        resource_limit_exceeded: bool = False,
        findings_override: list[Finding] | None = None,
        prepared_override: PreparedToolResultReview | None = None,
    ) -> ToolResultInspectionResult:
        started = time.monotonic()
        gate = self.policy_engine.tool_result_gate
        assert gate is not None
        findings = (
            findings_override
            if findings_override is not None
            else self.decision_service.detector.detect(event)
        )
        prepared = prepared_override or build_tool_result_review_payload(
            event, findings, case_id=event.event_id
        )
        preview = prepared.payload["event"]["result"]
        stored_event = event.model_copy(update={"result": preview, "raw": {}})
        self.decision_service.record(stored_event)
        if self.decision_service.store:
            for finding in findings:
                self.decision_service.store.save_finding(finding)
        base_decision = self.policy_engine.evaluate(event, findings)
        proposed_action = base_decision.action
        effective_action: PolicyAction
        adjudication: LLMAdjudication | None = None
        approval_request: ApprovalRequest | None = None
        error_code: str | None = None
        verdict: str | None = None
        confidence: float | None = None
        has_critical = any(finding.severity == "critical" for finding in findings)
        if resource_limit_exceeded:
            error_code = "resource_limit"
            proposed_action = "block" if gate.mode == "enforce" else "allow"
        elif gate.review == "hybrid":
            if has_critical:
                proposed_action = gate.true_positive_action
            else:
                adjudication_id = new_ulid()
                try:
                    if self.tool_result_reviewer is None:
                        raise LLMProviderError(
                            "missing_llm_config", "Tool Result reviewer is not configured."
                        )
                    provider_result = self.tool_result_reviewer.adjudicate(
                        payload=prepared.payload,
                        evidence_refs=set(prepared.evidence_refs),
                    )
                    verdict = provider_result.result.verdict
                    confidence = provider_result.result.confidence
                    if confidence < gate.min_confidence or verdict == "uncertain":
                        proposed_action = "require_approval"
                    elif verdict == "likely_true_positive":
                        proposed_action = gate.true_positive_action
                    else:
                        proposed_action = gate.false_positive_action
                    adjudication = LLMAdjudication(
                        adjudication_id=adjudication_id,
                        session_id=event.session_id,
                        event_id=event.event_id,
                        finding_ids=[finding.finding_id for finding in findings],
                        policy_id=base_decision.policy_id or "tool-result-gate",
                        created_at=datetime.now(UTC),
                        status="completed",
                        mode=gate.mode,
                        stage="tool_result",
                        provider="openai-compatible",
                        model=self.tool_result_reviewer.model,
                        prompt_version=getattr(
                            self.tool_result_reviewer,
                            "prompt_version",
                            "tool-result-review-v0.2",
                        ),
                        input_sha256=prepared.input_sha256,
                        result=provider_result.result,
                        proposed_action=proposed_action,
                        final_action=(proposed_action if gate.mode == "enforce" else "allow"),
                        latency_ms=provider_result.latency_ms,
                        token_usage=provider_result.token_usage,
                        provider_request_id=provider_result.provider_request_id,
                    )
                except Exception as exc:
                    error_code = (
                        exc.code if isinstance(exc, LLMProviderError) else "review_internal_error"
                    )
                    proposed_action = "require_approval"
                    adjudication = LLMAdjudication(
                        adjudication_id=adjudication_id,
                        session_id=event.session_id,
                        event_id=event.event_id,
                        finding_ids=[finding.finding_id for finding in findings],
                        policy_id=base_decision.policy_id or "tool-result-gate",
                        created_at=datetime.now(UTC),
                        status="failed",
                        mode=gate.mode,
                        stage="tool_result",
                        provider="openai-compatible",
                        model=(self.tool_result_reviewer.model if self.tool_result_reviewer else "unconfigured"),
                        prompt_version=getattr(
                            self.tool_result_reviewer,
                            "prompt_version",
                            "tool-result-review-v0.2",
                        ),
                        input_sha256=prepared.input_sha256,
                        proposed_action="require_approval",
                        final_action=("require_approval" if gate.mode == "enforce" else "allow"),
                        latency_ms=0,
                        error_code=error_code,
                        error_message="Tool Result review failed safely.",
                    )
        effective_action = proposed_action if gate.mode == "enforce" else "allow"
        decision = new_policy_decision(
            policy_id=base_decision.policy_id,
            action=effective_action,
            reason=(
                "Tool Result Gate shadow observation."
                if gate.mode == "shadow"
                else "Tool Result Gate enforced the reviewed result."
            ),
            session_id=event.session_id,
            event_id=event.event_id,
            finding_ids=[finding.finding_id for finding in findings],
        )
        if self.decision_service.store:
            self.decision_service.store.save_policy_decision(decision)
            if adjudication is not None:
                self.decision_service.store.save_llm_adjudication(adjudication)
            if effective_action == "require_approval":
                approval_request = new_approval_request(
                    decision_id=decision.decision_id,
                    session_id=event.session_id,
                    event_id=event.event_id,
                    request_id=event.request_id,
                    policy_id=decision.policy_id,
                    reason=decision.reason,
                    finding_ids=decision.finding_ids,
                    tool_name=event.tool_name,
                    capability=event.capability,
                    arguments=None,
                    stage="tool_result",
                    result_preview=preview,
                )
                self.decision_service.store.save_approval_request(approval_request)
        record = new_tool_result_gate_record(
            session_id=event.session_id,
            event_id=event.event_id,
            request_id=event.request_id,
            mode=gate.mode,
            review=gate.review,
            base_action=base_decision.action,
            proposed_action=proposed_action,
            effective_action=effective_action,
            finding_ids=[finding.finding_id for finding in findings],
            rule_ids=[finding.rule_id for finding in findings],
            adjudication_id=adjudication.adjudication_id if adjudication else None,
            approval_id=approval_request.approval_id if approval_request else None,
            approval_status="pending" if approval_request else None,
            verdict=verdict,
            confidence=confidence,
            response_byte_count=response_byte_count,
            evidence_truncated=prepared.truncated,
            latency_ms=max(0, round((time.monotonic() - started) * 1000)),
            error_code=error_code,
            result_preview=preview,
        )
        if self.decision_service.store:
            self.decision_service.store.save_tool_result_gate_record(record)
        return ToolResultInspectionResult(
            action=effective_action,
            error_code=(
                -32004
                if resource_limit_exceeded and gate.mode == "enforce"
                else (-32001 if effective_action == "block" else None)
            ),
            approval_request=approval_request,
            adjudication=adjudication,
            gate_record=record,
        )

    def render_approval_block_response(
        self,
        request_id: str | int | None,
        *,
        outcome: dict[str, Any],
    ) -> dict[str, Any]:
        status = str(outcome.get("status", "denied"))
        if status == "expired":
            return self.policy_engine.render_approval_jsonrpc_error(
                request_id,
                message="Approval expired before human resolution",
                reason="Approval request expired.",
                code=-32003,
            )
        return self.policy_engine.render_approval_jsonrpc_error(
            request_id,
            message="Denied by ZeroADR approval",
            reason=str(outcome.get("resolution_comment") or "Approval denied."),
        )

    def render_tool_result_error(
        self,
        request_id: str | int | None,
        *,
        code: int,
        message: str,
        reason: str,
    ) -> dict[str, Any]:
        return self.policy_engine.render_approval_jsonrpc_error(
            request_id,
            code=code,
            message=message,
            reason=reason,
        )

    def expire_pending_tool_result_approvals(self) -> None:
        store = self.decision_service.store
        if store is None:
            return
        records_by_approval = {
            record.approval_id: record
            for record in store.tool_result_gate_records_for_session(self.session_id)
            if record.approval_id
        }
        for request in store.list_approval_requests(
            status="pending", session_id=self.session_id
        ):
            if request.stage != "tool_result":
                continue
            try:
                store.mark_approval_expired(request.approval_id)
                record = records_by_approval.get(request.approval_id)
                if record is not None:
                    self.finalize_tool_result_approval(record, status="expired")
            except Exception:
                continue

    def finalize_tool_result_approval(
        self,
        record: ToolResultGateRecord,
        *,
        status: Literal["approved", "denied", "expired"],
    ) -> ToolResultGateRecord:
        updated = record.model_copy(
            update={
                "approval_status": status,
                "effective_action": "allow" if status == "approved" else "block",
            }
        )
        if self.decision_service.store:
            self.decision_service.store.save_tool_result_gate_record(updated)
        return updated


async def run_stdio_proxy(
    command: list[str],
    *,
    policy_path: Path,
    trace_path: Path,
    db_path: Path,
    approval_timeout: float = DEFAULT_APPROVAL_TIMEOUT_SECONDS,
    approval_poll_interval: float = 0.5,
    llm_config_path: Path = Path(".zeroadr/llm-config.json"),
) -> int:
    policy_engine = PolicyEngine.from_file(policy_path)
    runtime = GatewayRuntime(
        policy_engine=policy_engine,
        trace_path=trace_path,
        db_path=db_path,
        adjudicator=(
            build_llm_adjudicator(llm_config_path)
            if policy_engine.has_llm_adjudication()
            else None
        ),
        tool_result_reviewer=(
            build_tool_result_reviewer(llm_config_path)
            if policy_engine.tool_result_gate is not None
            and policy_engine.tool_result_gate.review == "hybrid"
            else None
        ),
    )
    process = await asyncio.create_subprocess_exec(
        *command,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    assert process.stdin is not None
    assert process.stdout is not None
    assert process.stderr is not None
    proc_stdin = process.stdin
    proc_stdout = process.stdout
    proc_stderr = process.stderr
    response_order: list[str | int] = []
    blocked_responses: dict[str | int, bytes] = {}
    server_responses: dict[str | int, bytes] = {}
    output_lock = asyncio.Lock()
    responses_drained = asyncio.Event()
    responses_drained.set()
    response_slot_released = asyncio.Event()

    async def flush_ordered_responses() -> None:
        # Process responses without holding the lock while waiting
        while True:
            request_id = None
            response_to_write = None

            async with output_lock:
                if not response_order:
                    return

                request_id = response_order[0]
                if request_id in blocked_responses:
                    response_to_write = blocked_responses.pop(request_id)
                elif request_id in server_responses:
                    response_to_write = server_responses.pop(request_id)
                else:
                    # Response not ready yet, exit without holding lock
                    return

                # Remove from order now that we have the response
                response_order.pop(0)

            # Write response outside the lock
            if response_to_write is not None:
                sys.stdout.buffer.write(response_to_write)
                sys.stdout.buffer.flush()
                response_slot_released.set()

                # Check if all responses are drained
                async with output_lock:
                    if not response_order:
                        responses_drained.set()

            # Continue to next response
            await asyncio.sleep(0)

    async def client_to_server() -> None:
        while True:
            framed = await asyncio.to_thread(read_framed_message, sys.stdin.buffer)
            if not framed:
                if process.stdin:
                    proc_stdin.close()
                return
            message = framed.message
            request_id = message.get("id")
            ordered_id = request_id if isinstance(request_id, str | int) else None
            if ordered_id is not None:
                if ordered_id in response_order or ordered_id in runtime.pending:
                    duplicate = {
                        "jsonrpc": "2.0",
                        "id": ordered_id,
                        "error": {
                            "code": -32600,
                            "message": "Duplicate in-flight JSON-RPC request id",
                            "data": {"reason": "Request IDs must be unique until completion."},
                        },
                    }
                    async with output_lock:
                        sys.stdout.buffer.write(encode_framed_response(duplicate, framed.framing))
                        sys.stdout.buffer.flush()
                    continue
                gate = policy_engine.tool_result_gate
                while gate is not None and len(response_order) >= gate.max_pending_responses:
                    response_slot_released.clear()
                    await response_slot_released.wait()
                response_order.append(ordered_id)
                responses_drained.clear()
            inspection = await asyncio.to_thread(
                runtime.inspect_client_message,
                message,
            )
            if inspection.block_response is not None:
                if ordered_id is not None:
                    blocked_responses[ordered_id] = encode_framed_response(
                        inspection.block_response, framed.framing
                    )
                    await flush_ordered_responses()
                else:
                    sys.stdout.buffer.write(
                        encode_framed_response(inspection.block_response, framed.framing)
                    )
                    sys.stdout.buffer.flush()
                continue
            if inspection.approval_id and db_path:
                outcome = await asyncio.to_thread(
                    wait_for_approval_resolution,
                    db_path,
                    inspection.approval_id,
                    timeout=approval_timeout,
                    poll_interval=approval_poll_interval,
                    trace_path=trace_path,
                )
                if outcome.get("effective_action") != "allow":
                    block_response = runtime.render_approval_block_response(ordered_id, outcome=outcome)
                    if ordered_id is not None:
                        blocked_responses[ordered_id] = encode_framed_response(
                            block_response, framed.framing
                        )
                        await flush_ordered_responses()
                    else:
                        sys.stdout.buffer.write(encode_framed_response(block_response, framed.framing))
                        sys.stdout.buffer.flush()
                    continue
                if inspection.pending is not None:
                    runtime.pending[inspection.pending.request_id] = inspection.pending
            proc_stdin.write(framed.raw)
            await proc_stdin.drain()

    async def server_to_client() -> None:
        while True:
            framed = await read_async_framed_message(proc_stdout)
            if not framed:
                return
            message = framed.message
            request_id = message.get("id")
            if isinstance(request_id, str | int):
                if request_id not in response_order:
                    runtime.inspect_server_message(message, response_byte_count=len(framed.raw))
                    async with output_lock:
                        sys.stdout.buffer.write(framed.raw)
                        sys.stdout.buffer.flush()
                    continue
                gate = (
                    policy_engine.tool_result_gate
                    if request_id in runtime.pending
                    else None
                )
                projected_buffer_bytes = len(framed.raw) + sum(
                    len(response) for response in server_responses.values()
                )
                if gate is not None and projected_buffer_bytes > gate.max_buffer_bytes:
                    inspection = await asyncio.to_thread(
                        runtime.inspect_server_message,
                        message,
                        response_byte_count=len(framed.raw),
                        resource_limit_exceeded=True,
                    )
                    if gate.mode == "enforce":
                        resource_error = runtime.render_tool_result_error(
                            request_id,
                            code=-32004,
                            message="Tool Result Gate resource limit",
                            reason="Buffered MCP response exceeded the configured byte limit.",
                        )
                        server_responses[request_id] = encode_framed_response(
                            resource_error, framed.framing
                        )
                    else:
                        server_responses[request_id] = framed.raw
                    await flush_ordered_responses()
                    continue
                if gate is not None and gate.mode == "shadow" and gate.review == "hybrid":
                    prepared_shadow = runtime.prepare_shadow_tool_result(message)
                    server_responses[request_id] = framed.raw
                    await flush_ordered_responses()
                    if prepared_shadow is None:
                        continue
                    task = asyncio.create_task(
                        asyncio.to_thread(
                            runtime.inspect_prepared_shadow_tool_result,
                            prepared_shadow,
                            response_byte_count=len(framed.raw),
                        )
                    )
                    shadow_review_tasks.add(task)
                    task.add_done_callback(shadow_review_tasks.discard)
                    continue
                inspection = await asyncio.to_thread(
                    runtime.inspect_server_message,
                    message,
                    response_byte_count=len(framed.raw),
                )
                if inspection.action == "block":
                    response = runtime.render_tool_result_error(
                        request_id,
                        code=-32001,
                        message="Blocked by ZeroADR Tool Result Gate",
                        reason="The MCP tool result was blocked by policy.",
                    )
                    server_responses[request_id] = encode_framed_response(response, framed.framing)
                elif inspection.action == "require_approval" and inspection.approval_request:
                    outcome = await asyncio.to_thread(
                        wait_for_approval_resolution,
                        db_path,
                        inspection.approval_request.approval_id,
                        timeout=approval_timeout,
                        poll_interval=approval_poll_interval,
                        trace_path=trace_path,
                    )
                    outcome_status = str(outcome.get("status", "denied"))
                    if outcome_status not in {"approved", "denied", "expired"}:
                        outcome_status = "denied"
                    if inspection.gate_record is not None:
                        runtime.finalize_tool_result_approval(
                            inspection.gate_record,
                            status=outcome_status,  # type: ignore[arg-type]
                        )
                    if outcome.get("effective_action") == "allow":
                        server_responses[request_id] = framed.raw
                    else:
                        expired = outcome.get("status") == "expired"
                        response = runtime.render_tool_result_error(
                            request_id,
                            code=-32003 if expired else -32002,
                            message=(
                                "Tool Result approval expired"
                                if expired
                                else "Tool Result approval denied"
                            ),
                            reason=str(
                                outcome.get("resolution_comment")
                                or "The untrusted result was not approved."
                            ),
                        )
                        server_responses[request_id] = encode_framed_response(
                            response, framed.framing
                        )
                else:
                    server_responses[request_id] = framed.raw
                await flush_ordered_responses()
            else:
                runtime.inspect_server_message(message, response_byte_count=len(framed.raw))
                sys.stdout.buffer.write(framed.raw)
                sys.stdout.buffer.flush()

    async def stderr_to_log() -> None:
        while True:
            line = await proc_stderr.readline()
            if not line:
                return
            sys.stderr.buffer.write(line)
            sys.stderr.buffer.flush()

    client_task = asyncio.create_task(client_to_server())
    server_task = asyncio.create_task(server_to_client())
    stderr_task = asyncio.create_task(stderr_to_log())
    shadow_review_tasks: set[asyncio.Task[Any]] = set()
    try:
        await client_task
        try:
            await asyncio.wait_for(responses_drained.wait(), timeout=10.0)
        except TimeoutError:
            process.terminate()
            response_order.clear()
            responses_drained.set()
        try:
            return_code = await asyncio.wait_for(process.wait(), timeout=1.0)
        except TimeoutError:
            process.terminate()
            return_code = await process.wait()
        await server_task
        await stderr_task
        if shadow_review_tasks:
            done, pending_tasks = await asyncio.wait(shadow_review_tasks, timeout=10.0)
            for task in pending_tasks:
                task.cancel()
    except KeyboardInterrupt:
        process.terminate()
        return_code = await process.wait()
    finally:
        runtime.expire_pending_tool_result_approvals()
        for task in (client_task, server_task, stderr_task):
            if not task.done():
                task.cancel()
    return return_code


def build_proxy_parser(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--policy", default="policies/default.yaml")
    parser.add_argument("--trace", default=".zeroadr/traces/latest.jsonl")
    parser.add_argument("--db", default=".zeroadr/zeroadr.sqlite")
    parser.add_argument("--approval-timeout", type=float, default=DEFAULT_APPROVAL_TIMEOUT_SECONDS)
    parser.add_argument("--approval-poll-interval", type=float, default=0.5)
    parser.add_argument("--llm-config", default=".zeroadr/llm-config.json")
    parser.add_argument("command", nargs=argparse.REMAINDER)


def encode_framed_response(message: dict[str, Any], framing: Literal["line", "mcp"]) -> bytes:
    if framing == "mcp":
        return encode_mcp_frame(message)
    return encode_jsonrpc(message).encode("utf-8")


def read_framed_message(stream: Any) -> FramedMessage | None:
    """Read a framed message from stream. Returns None on EOF or protocol errors."""
    try:
        first_line = stream.readline()
        if not first_line:
            return None
        if first_line.lower().startswith(b"content-length:"):
            headers = [first_line]
            content_length = _parse_content_length(first_line)
            while True:
                header_line = stream.readline()
                if not header_line:
                    return None
                headers.append(header_line)
                if header_line in {b"\r\n", b"\n"}:
                    break
                if header_line.lower().startswith(b"content-length:"):
                    content_length = _parse_content_length(header_line)
            if content_length is None:
                # Missing Content-Length header - protocol error
                return None
            body = stream.read(content_length)
            if len(body) != content_length:
                return None
            raw = b"".join(headers) + body
            message = json.loads(body.decode("utf-8"))
            if not isinstance(message, dict):
                # Invalid JSON-RPC message format
                return None
            return FramedMessage(message=message, raw=raw, framing="mcp")
        message = json.loads(first_line.decode("utf-8"))
        if not isinstance(message, dict):
            # Invalid JSON-RPC message format
            return None
        return FramedMessage(message=message, raw=first_line, framing="line")
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
        # Protocol errors: return None instead of raising
        return None


async def read_async_framed_message(stream: asyncio.StreamReader) -> FramedMessage | None:
    """Read a framed message from async stream. Returns None on EOF or protocol errors."""
    try:
        first_line = await stream.readline()
        if not first_line:
            return None
        if first_line.lower().startswith(b"content-length:"):
            headers = [first_line]
            content_length = _parse_content_length(first_line)
            while True:
                header_line = await stream.readline()
                if not header_line:
                    return None
                headers.append(header_line)
                if header_line in {b"\r\n", b"\n"}:
                    break
                if header_line.lower().startswith(b"content-length:"):
                    content_length = _parse_content_length(header_line)
            if content_length is None:
                # Missing Content-Length header - protocol error
                return None
            body = await stream.readexactly(content_length)
            raw = b"".join(headers) + body
            message = json.loads(body.decode("utf-8"))
            if not isinstance(message, dict):
                # Invalid JSON-RPC message format
                return None
            return FramedMessage(message=message, raw=raw, framing="mcp")
        message = json.loads(first_line.decode("utf-8"))
        if not isinstance(message, dict):
            # Invalid JSON-RPC message format
            return None
        return FramedMessage(message=message, raw=first_line, framing="line")
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError, asyncio.IncompleteReadError):
        # Protocol errors: return None instead of raising
        return None


def _parse_content_length(header_line: bytes) -> int | None:
    _, _, value = header_line.decode("ascii").partition(":")
    value = value.strip()
    return int(value) if value else None
