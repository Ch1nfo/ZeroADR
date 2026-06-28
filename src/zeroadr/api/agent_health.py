from __future__ import annotations

import os
from pathlib import Path

from zeroadr.endpoint.agent import DEFAULT_AGENT_STATUS_FILE, build_agent_health

__all__ = ["DEFAULT_AGENT_STATUS_FILE", "build_agent_health", "resolve_agent_status_path"]


def resolve_agent_status_path(explicit: Path | None = None) -> Path:
    if explicit is not None:
        return explicit
    env_path = os.environ.get("ZEROADR_AGENT_STATUS_FILE")
    if env_path:
        return Path(env_path)
    return DEFAULT_AGENT_STATUS_FILE
