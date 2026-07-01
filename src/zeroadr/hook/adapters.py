from __future__ import annotations

from typing import Any, Literal

from zeroadr.hook.models import HookEvent

HookClient = Literal["generic", "claude-code", "codex"]


def hook_event_from_client_payload(payload: dict[str, Any], *, client: HookClient) -> HookEvent:
    if client == "generic":
        return HookEvent.model_validate(payload)
    if client == "claude-code":
        return _claude_code_hook_event(payload)
    if client == "codex":
        return _codex_hook_event(payload)
    raise ValueError(f"Unsupported hook client: {client}")


def _claude_code_hook_event(payload: dict[str, Any]) -> HookEvent:
    hook_event_name = str(payload.get("hook_event_name", ""))
    if hook_event_name == "UserPromptSubmit":
        return HookEvent(
            hook_event_type="agent_input",
            session_id=str(payload.get("session_id", "unknown-session")),
            request_id=payload.get("request_id"),
            arguments={"content": str(payload.get("prompt", ""))},
            raw=payload,
        )
    hook_event_type = "post_tool_use" if hook_event_name == "PostToolUse" else "pre_tool_use"
    tool_input = payload.get("tool_input")
    arguments = _normalize_tool_input(tool_input if isinstance(tool_input, dict) else {})
    tool_response = payload.get("tool_response")
    error = tool_response if _is_error_response(tool_response) else None
    result = None if error is not None else tool_response
    return HookEvent(
        hook_event_type=hook_event_type,  # type: ignore[arg-type]
        session_id=str(payload.get("session_id", "unknown-session")),
        request_id=payload.get("tool_call_id") or payload.get("request_id"),
        tool_name=str(payload["tool_name"]) if payload.get("tool_name") is not None else None,
        arguments=arguments,
        result=result,
        error=error,
        raw=payload,
    )


def _normalize_tool_input(tool_input: dict[str, Any]) -> dict[str, Any]:
    arguments = dict(tool_input)
    file_path = arguments.pop("file_path", None)
    if file_path is not None and "path" not in arguments:
        arguments["path"] = file_path
    return arguments


def _is_error_response(value: Any) -> bool:
    return isinstance(value, dict) and isinstance(value.get("error"), dict)


def _codex_hook_event(payload: dict[str, Any]) -> HookEvent:
    event_name = str(payload.get("event", ""))
    hook_event_type = "post_tool_use" if event_name == "post_tool_use" else "pre_tool_use"
    tool = payload.get("tool")
    tool_payload = tool if isinstance(tool, dict) else {}
    arguments = tool_payload.get("arguments")
    return HookEvent(
        hook_event_type=hook_event_type,  # type: ignore[arg-type]
        session_id=str(payload.get("session_id", "unknown-session")),
        request_id=payload.get("call_id") or payload.get("request_id"),
        tool_name=str(tool_payload["name"]) if tool_payload.get("name") is not None else None,
        arguments=arguments if isinstance(arguments, dict) else {},
        result=payload.get("result") if payload.get("error") is None else None,
        error=payload.get("error") if isinstance(payload.get("error"), dict) else None,
        raw=payload,
    )
