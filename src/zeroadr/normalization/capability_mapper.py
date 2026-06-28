from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class CapabilityMapping:
    capability: str | None
    target: str | None


READ_NAMES = ("read", "get", "open", "cat")
WRITE_NAMES = ("write", "edit", "save", "put")
SHELL_NAMES = ("run", "exec", "shell", "bash", "spawn")
NETWORK_NAMES = ("fetch", "request", "http", "curl", "wget", "navigate")
NETWORK_POST_NAMES = ("post", "http_post", "webhook")
MESSAGE_SEND_NAMES = ("send_message", "message_send")
EMAIL_SEND_NAMES = ("send_email", "email_send")
TARGET_KEYS = ("path", "file", "filename", "command", "cmd", "url", "uri", "endpoint")


def map_capability(
    tool_name: str | None,
    arguments: dict[str, Any] | None,
    description: str | None = None,
) -> CapabilityMapping:
    haystack = " ".join(value for value in [tool_name, description] if value).lower()
    capability: str | None = None
    if any(name in haystack for name in EMAIL_SEND_NAMES):
        capability = "email.send"
    elif any(name in haystack for name in MESSAGE_SEND_NAMES):
        capability = "message.send"
    elif any(name in haystack for name in NETWORK_POST_NAMES):
        capability = "network.http_post"
    elif any(name in haystack for name in NETWORK_NAMES):
        capability = "network.connect"
    elif any(name in haystack for name in WRITE_NAMES):
        capability = "filesystem.write"
    elif any(name in haystack for name in READ_NAMES) or "filesystem_read" in haystack:
        capability = "filesystem.read"
    elif any(name in haystack for name in SHELL_NAMES):
        capability = "shell.exec"
    return CapabilityMapping(capability=capability, target=extract_target(arguments))


def extract_target(arguments: dict[str, Any] | None) -> str | None:
    if not arguments:
        return None
    for key in TARGET_KEYS:
        value = arguments.get(key)
        if isinstance(value, str):
            return value
    for value in arguments.values():
        if isinstance(value, dict):
            nested = extract_target(value)
            if nested:
                return nested
    return None


def normalize_path_display(path_value: str) -> str:
    if path_value.startswith("~/"):
        return path_value
    try:
        return str(Path(path_value))
    except TypeError:
        return path_value
