from __future__ import annotations

import json
from typing import Any


def encode_jsonrpc(message: dict[str, Any]) -> str:
    return json.dumps(message, separators=(",", ":")) + "\n"


def decode_jsonrpc_lines(payload: str) -> list[dict[str, Any]]:
    messages: list[dict[str, Any]] = []
    for line in payload.splitlines():
        stripped = line.strip()
        if stripped:
            parsed = json.loads(stripped)
            if isinstance(parsed, dict):
                messages.append(parsed)
    return messages


def encode_mcp_frame(message: dict[str, Any]) -> bytes:
    body = json.dumps(message, separators=(",", ":")).encode("utf-8")
    return b"Content-Length: " + str(len(body)).encode("ascii") + b"\r\n\r\n" + body


def decode_mcp_frames(payload: bytes) -> list[dict[str, Any]]:
    messages: list[dict[str, Any]] = []
    offset = 0
    while offset < len(payload):
        header_end = payload.find(b"\r\n\r\n", offset)
        if header_end == -1:
            break
        header = payload[offset:header_end].decode("ascii")
        content_length: int | None = None
        for line in header.split("\r\n"):
            name, _, value = line.partition(":")
            if name.lower() == "content-length":
                content_length = int(value.strip())
                break
        if content_length is None:
            raise ValueError("MCP frame missing Content-Length header")
        body_start = header_end + 4
        body_end = body_start + content_length
        if body_end > len(payload):
            break
        parsed = json.loads(payload[body_start:body_end].decode("utf-8"))
        if isinstance(parsed, dict):
            messages.append(parsed)
        offset = body_end
    return messages
