from __future__ import annotations

import json
from ipaddress import ip_address
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse

from zeroadr.api.approvals import build_approval_detail, build_approvals_index, resolve_approval
from zeroadr.api.agent_health import build_agent_health, resolve_agent_status_path
from zeroadr.api.console import ConsoleAsset, ConsoleAssetNotFound, get_console_asset
from zeroadr.api.llm_settings import build_llm_config_view, test_llm_config, update_llm_config
from zeroadr.api.readonly import API_VERSION, build_api_index, build_api_session
from zeroadr.api.tool_result_gate import build_tool_result_gate_metrics, build_tool_result_gates
from zeroadr.llm.config import DEFAULT_LLM_CONFIG_PATH, LLMConfigurationError
from zeroadr.llm.calibration import build_gate_metrics
from zeroadr.llm.provider import LLMProviderError
from zeroadr.reconstruction.evidence import evidence_from_context
from zeroadr.reconstruction.session import reconstruct_from_sqlite
from zeroadr.runtime.approvals import DEFAULT_APPROVAL_TIMEOUT_SECONDS
from zeroadr.storage.database import ApprovalAlreadyResolvedError, SQLiteStore


def validate_api_bind_host(host: str, *, allow_insecure_non_loopback: bool) -> None:
    if allow_insecure_non_loopback or host.lower() == "localhost":
        return
    try:
        is_loopback = ip_address(host).is_loopback
    except ValueError as exc:
        raise ValueError(
            "API host must be a loopback address unless --allow-insecure-non-loopback is set."
        ) from exc
    if not is_loopback:
        raise ValueError(
            "API host must be a loopback address unless --allow-insecure-non-loopback is set."
        )


class ReadOnlyApiServer(ThreadingHTTPServer):
    def __init__(
        self,
        server_address: tuple[str, int],
        db_path: Path,
        *,
        agent_status_path: Path | None = None,
        trace_path: Path | None = None,
        approval_max_age_seconds: float = DEFAULT_APPROVAL_TIMEOUT_SECONDS,
        llm_config_path: Path = DEFAULT_LLM_CONFIG_PATH,
        llm_management_enabled: bool = True,
        llm_transport: Any | None = None,
    ) -> None:
        self.db_path = db_path
        self.agent_status_path = agent_status_path
        self.trace_path = trace_path
        self.approval_max_age_seconds = approval_max_age_seconds
        self.llm_config_path = llm_config_path
        self.llm_management_enabled = llm_management_enabled
        self.llm_transport = llm_transport
        super().__init__(server_address, ReadOnlyApiHandler)


class ReadOnlyApiHandler(BaseHTTPRequestHandler):
    server: ReadOnlyApiServer

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)
        try:
            if parsed.path in {"/console", "/console/"}:
                self._write_asset(200, get_console_asset(""))
                return
            console_prefix = "/console/assets/"
            if parsed.path.startswith(console_prefix):
                asset_name = unquote(parsed.path[len(console_prefix) :])
                try:
                    self._write_asset(200, get_console_asset(asset_name))
                except ConsoleAssetNotFound:
                    self._write_error(404, "asset_not_found", "Console asset not found.")
                return
            if parsed.path == "/health":
                self._write_json(200, {"api_version": API_VERSION, "status": "ok"}, enveloped=False)
                return
            if parsed.path == "/api/v0/endpoint-agent/health":
                status_path = resolve_agent_status_path(self.server.agent_status_path)
                payload = build_agent_health(status_path)
                self._write_json(200, payload)
                return
            if parsed.path == "/api/v0/llm/config":
                if not self._llm_management_allowed():
                    return
                self._write_json(200, build_llm_config_view(self.server.llm_config_path))
                return
            if parsed.path == "/api/v0/llm/adjudications/metrics":
                self._write_json(
                    200,
                    build_gate_metrics(
                        self.server.db_path,
                        session_id=_optional_str(query.get("session_id")),
                        confidence_threshold=_optional_float(
                            query.get("confidence_threshold")
                        )
                        or 0.85,
                    ),
                )
                return
            if parsed.path == "/api/v0/tool-result-gate/metrics":
                self._write_json(200, build_tool_result_gate_metrics(self.server.db_path))
                return
            if parsed.path == "/api/v0/approvals":
                payload = build_approvals_index(
                    self.server.db_path,
                    status=_optional_str(query.get("status")),
                    limit=_optional_int(query.get("limit")),
                    offset=_optional_int(query.get("offset")) or 0,
                    max_age_seconds=self.server.approval_max_age_seconds,
                )
                self._write_json(200, payload)
                return
            approval_prefix = "/api/v0/approvals/"
            if parsed.path.startswith(approval_prefix):
                approval_id = unquote(parsed.path[len(approval_prefix) :]).rstrip("/")
                if not approval_id or "/" in approval_id:
                    self._write_error(404, "not_found", "Route not found.")
                    return
                detail = build_approval_detail(
                    self.server.db_path,
                    approval_id,
                    max_age_seconds=self.server.approval_max_age_seconds,
                )
                if detail is None:
                    self._write_error(404, "approval_not_found", f"Approval not found: {approval_id}")
                    return
                self._write_json(200, detail)
                return
            if parsed.path == "/api/v0/sessions":
                payload = build_api_index(
                    self.server.db_path,
                    limit=_optional_int(query.get("limit")),
                    offset=_optional_int(query.get("offset")) or 0,
                )
                self._write_json(200, payload)
                return
            prefix = "/api/v0/sessions/"
            if parsed.path.startswith(prefix):
                remainder = unquote(parsed.path[len(prefix) :]).rstrip("/")
                session_id, subresource = _split_session_subresource(remainder)
                if not session_id:
                    self._write_error(404, "not_found", "Route not found.")
                    return
                store = SQLiteStore(self.server.db_path)
                if session_id not in store.list_sessions():
                    self._write_error(404, "session_not_found", f"Session not found: {session_id}")
                    return
                if subresource == "evidence":
                    payload = evidence_from_context(
                        reconstruct_from_sqlite(session_id, self.server.db_path),
                        finding_id=_optional_str(query.get("finding_id")),
                        rule_id=_optional_str(query.get("rule_id")),
                    )
                    self._write_json(200, payload)
                    return
                if subresource == "events":
                    self._write_json(
                        200,
                        {
                            "session_id": session_id,
                            "events": [event.model_dump(mode="json") for event in store.events_for_session(session_id)],
                        },
                    )
                    return
                if subresource == "findings":
                    self._write_json(
                        200,
                        {
                            "session_id": session_id,
                            "findings": [
                                finding.model_dump(mode="json") for finding in store.findings_for_session(session_id)
                            ],
                        },
                    )
                    return
                if subresource == "decisions":
                    self._write_json(
                        200,
                        {
                            "session_id": session_id,
                            "policy_decisions": [
                                decision.model_dump(mode="json")
                                for decision in store.policy_decisions_for_session(session_id)
                            ],
                        },
                    )
                    return
                if subresource == "adjudications":
                    self._write_json(
                        200,
                        {
                            "session_id": session_id,
                            "llm_adjudications": [
                                item.model_dump(mode="json")
                                for item in store.llm_adjudications_for_session(session_id)
                            ],
                        },
                    )
                    return
                if subresource == "tool-result-gates":
                    self._write_json(200, build_tool_result_gates(self.server.db_path, session_id))
                    return
                if subresource is not None:
                    self._write_error(404, "not_found", "Route not found.")
                    return
                payload = build_api_session(
                    session_id,
                    self.server.db_path,
                    compact=_truthy(query.get("compact")),
                )
                self._write_json(200, payload)
                return
            self._write_error(404, "not_found", "Route not found.")
        except LLMConfigurationError as exc:
            self._write_error(500, exc.code, str(exc))
        except Exception as exc:
            self._write_error(500, "internal_error", str(exc))

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        try:
            if parsed.path == "/api/v0/llm/config/test":
                if not self._llm_management_allowed():
                    return
                if not self._require_json_request():
                    return
                body = self._read_json_body()
                if body is None:
                    self._write_error(400, "invalid_json", "Request body must be valid JSON.")
                    return
                self._write_json(
                    200,
                    test_llm_config(
                        self.server.llm_config_path,
                        target=str(body.get("target") or "triage"),
                        transport=self.server.llm_transport,
                    ),
                )
                return
            resolve_suffix = "/resolve"
            if parsed.path.startswith("/api/v0/approvals/") and parsed.path.endswith(resolve_suffix):
                approval_id = unquote(
                    parsed.path[len("/api/v0/approvals/") : -len(resolve_suffix)]
                ).rstrip("/")
                if not approval_id:
                    self._write_error(404, "not_found", "Route not found.")
                    return
                body = self._read_json_body()
                if body is None:
                    self._write_error(400, "invalid_json", "Request body must be valid JSON.")
                    return
                status = body.get("status")
                if status not in {"approved", "denied"}:
                    self._write_error(
                        400,
                        "invalid_status",
                        "Field status must be 'approved' or 'denied'.",
                    )
                    return
                try:
                    request = resolve_approval(
                        self.server.db_path,
                        approval_id,
                        status=status,
                        resolved_by=str(body.get("resolved_by") or "console"),
                        comment=body.get("comment") if isinstance(body.get("comment"), str) else None,
                        trace_path=self.server.trace_path,
                        max_age_seconds=self.server.approval_max_age_seconds,
                    )
                except KeyError:
                    self._write_error(404, "approval_not_found", f"Approval not found: {approval_id}")
                    return
                except ApprovalAlreadyResolvedError:
                    self._write_error(
                        409,
                        "approval_already_resolved",
                        f"Approval already resolved: {approval_id}",
                    )
                    return
                payload = build_approval_detail(self.server.db_path, request.approval_id)
                self._write_json(200, payload or {"approval": request.model_dump(mode="json")})
                return
            self._write_error(404, "not_found", "Route not found.")
        except LLMConfigurationError as exc:
            self._write_error(400, exc.code, str(exc))
        except LLMProviderError as exc:
            status = 504 if exc.code == "provider_timeout" else 502
            self._write_error(status, exc.code, str(exc))
        except Exception as exc:
            self._write_error(500, "internal_error", str(exc))

    def do_PUT(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        try:
            if parsed.path != "/api/v0/llm/config":
                self._write_error(404, "not_found", "Route not found.")
                return
            if not self._llm_management_allowed():
                return
            if not self._require_json_request():
                return
            body = self._read_json_body()
            if body is None:
                self._write_error(400, "invalid_json", "Request body must be valid JSON.")
                return
            self._write_json(200, update_llm_config(self.server.llm_config_path, body))
        except (LLMConfigurationError, ValueError) as exc:
            code = exc.code if isinstance(exc, LLMConfigurationError) else "invalid_config"
            self._write_error(400, code, "LLM configuration is invalid.")
        except Exception:
            self._write_error(500, "internal_error", "Unable to save LLM configuration.")

    def log_message(self, format: str, *args: object) -> None:
        return None

    def _llm_management_allowed(self) -> bool:
        if self.server.llm_management_enabled:
            return True
        self._write_error(
            403,
            "llm_config_management_disabled",
            "LLM configuration management is available only on loopback API servers.",
        )
        return False

    def _require_json_request(self) -> bool:
        content_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        if content_type == "application/json":
            return True
        self._write_error(
            415,
            "unsupported_media_type",
            "LLM configuration requests require application/json.",
        )
        return False

    def _write_json(self, status: int, payload: dict[str, Any], *, enveloped: bool = True) -> None:
        body = {"ok": True, "data": payload} if enveloped else payload
        encoded = json.dumps(body, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def _read_json_body(self) -> dict[str, Any] | None:
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0:
            return {}
        raw = self.rfile.read(length)
        try:
            payload = json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError:
            return None
        if not isinstance(payload, dict):
            return None
        return payload

    def _write_asset(self, status: int, asset: ConsoleAsset) -> None:
        self.send_response(status)
        self.send_header("Content-Type", asset.content_type)
        self.send_header("Content-Length", str(len(asset.body)))
        self.end_headers()
        self.wfile.write(asset.body)

    def _write_error(self, status: int, code: str, message: str) -> None:
        encoded = json.dumps(
            {
                "ok": False,
                "error": {
                    "code": code,
                    "message": message,
                },
            },
            sort_keys=True,
        ).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)


def create_api_server(
    *,
    db_path: Path,
    host: str = "127.0.0.1",
    port: int = 8765,
    agent_status_path: Path | None = None,
    trace_path: Path | None = None,
    approval_max_age_seconds: float = DEFAULT_APPROVAL_TIMEOUT_SECONDS,
    llm_config_path: Path = DEFAULT_LLM_CONFIG_PATH,
    llm_management_enabled: bool | None = None,
    llm_transport: Any | None = None,
) -> ReadOnlyApiServer:
    management_enabled = (
        _is_loopback_host(host) if llm_management_enabled is None else llm_management_enabled
    )
    return ReadOnlyApiServer(
        (host, port),
        db_path,
        agent_status_path=agent_status_path,
        trace_path=trace_path,
        approval_max_age_seconds=approval_max_age_seconds,
        llm_config_path=llm_config_path,
        llm_management_enabled=management_enabled,
        llm_transport=llm_transport,
    )


def _is_loopback_host(host: str) -> bool:
    if host.lower() == "localhost":
        return True
    try:
        return ip_address(host).is_loopback
    except ValueError:
        return False


def _optional_int(values: list[str] | None) -> int | None:
    if not values:
        return None
    try:
        return int(values[0])
    except ValueError:
        return None


def _optional_float(values: list[str] | None) -> float | None:
    if not values:
        return None
    try:
        return float(values[0])
    except ValueError:
        return None


def _optional_str(values: list[str] | None) -> str | None:
    if not values:
        return None
    return values[0] or None


def _truthy(values: list[str] | None) -> bool:
    if not values:
        return False
    return values[0].lower() in {"1", "true", "yes", "on"}


def _split_session_subresource(remainder: str) -> tuple[str, str | None]:
    for subresource in ("evidence", "events", "findings", "decisions", "adjudications"):
        suffix = f"/{subresource}"
        if remainder.endswith(suffix):
            return remainder[: -len(suffix)], subresource
    return remainder, None
