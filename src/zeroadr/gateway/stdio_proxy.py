from __future__ import annotations

import argparse
import asyncio
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from zeroadr.core.events import RuntimeEvent, new_event
from zeroadr.core.ids import new_ulid
from zeroadr.gateway.jsonrpc import encode_jsonrpc, encode_mcp_frame
from zeroadr.hook.approval_wait import wait_for_approval_resolution
from zeroadr.llm.adjudication import LLMAdjudicator, build_llm_adjudicator
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
                if isinstance(request_id, str | int)
                else None
            )
            return ClientInspectionResult(approval_id=approval_id, pending=pending)
        pending = PendingCall(request_id, tool_name, arguments, event) if isinstance(request_id, str | int) else None
        if pending is not None:
            self.pending[pending.request_id] = pending
        return ClientInspectionResult(pending=pending)

    def inspect_server_message(self, message: dict[str, Any]) -> None:
        request_id = message.get("id")
        if not isinstance(request_id, str | int):
            return
        pending = self.pending.pop(request_id, None)
        if not pending:
            return
        event_type: Literal["tool.call.failed", "tool.call.completed"] = (
            "tool.call.failed" if "error" in message else "tool.call.completed"
        )
        event = new_event(
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
        self.decision_service.record(event)

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

    async def flush_ordered_responses() -> None:
        async with output_lock:
            while response_order:
                request_id = response_order[0]
                if request_id in blocked_responses:
                    response = blocked_responses.pop(request_id)
                    sys.stdout.buffer.write(response)
                    sys.stdout.buffer.flush()
                    response_order.pop(0)
                    if not response_order:
                        responses_drained.set()
                    continue
                if request_id in server_responses:
                    line = server_responses.pop(request_id)
                    sys.stdout.buffer.write(line)
                    sys.stdout.buffer.flush()
                    response_order.pop(0)
                    if not response_order:
                        responses_drained.set()
                    continue
                return

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
            runtime.inspect_server_message(message)
            request_id = message.get("id")
            if isinstance(request_id, str | int):
                server_responses[request_id] = framed.raw
                await flush_ordered_responses()
            else:
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
    try:
        await client_task
        await asyncio.wait_for(responses_drained.wait(), timeout=10.0)
        try:
            return_code = await asyncio.wait_for(process.wait(), timeout=1.0)
        except TimeoutError:
            process.terminate()
            return_code = await process.wait()
        await server_task
        await stderr_task
    except KeyboardInterrupt:
        process.terminate()
        return_code = await process.wait()
    finally:
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
            raise ValueError("MCP frame missing Content-Length header")
        body = stream.read(content_length)
        if len(body) != content_length:
            return None
        raw = b"".join(headers) + body
        message = json.loads(body.decode("utf-8"))
        if not isinstance(message, dict):
            raise ValueError("JSON-RPC message must be an object")
        return FramedMessage(message=message, raw=raw, framing="mcp")
    message = json.loads(first_line.decode("utf-8"))
    if not isinstance(message, dict):
        raise ValueError("JSON-RPC message must be an object")
    return FramedMessage(message=message, raw=first_line, framing="line")


async def read_async_framed_message(stream: asyncio.StreamReader) -> FramedMessage | None:
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
            raise ValueError("MCP frame missing Content-Length header")
        body = await stream.readexactly(content_length)
        raw = b"".join(headers) + body
        message = json.loads(body.decode("utf-8"))
        if not isinstance(message, dict):
            raise ValueError("JSON-RPC message must be an object")
        return FramedMessage(message=message, raw=raw, framing="mcp")
    message = json.loads(first_line.decode("utf-8"))
    if not isinstance(message, dict):
        raise ValueError("JSON-RPC message must be an object")
    return FramedMessage(message=message, raw=first_line, framing="line")


def _parse_content_length(header_line: bytes) -> int | None:
    _, _, value = header_line.decode("ascii").partition(":")
    value = value.strip()
    return int(value) if value else None
