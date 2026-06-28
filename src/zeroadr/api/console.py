from __future__ import annotations

from dataclasses import dataclass
from importlib import resources


class ConsoleAssetNotFound(Exception):
    pass


@dataclass(frozen=True)
class ConsoleAsset:
    name: str
    content_type: str
    body: bytes


_ASSET_TYPES = {
    "console.html": "text/html; charset=utf-8",
    "console.css": "text/css; charset=utf-8",
    "console.js": "application/javascript; charset=utf-8",
}


def get_console_asset(asset_name: str) -> ConsoleAsset:
    name = "console.html" if asset_name in {"", "console.html"} else asset_name

    # Validate asset name to prevent path traversal
    if (
        ".." in name
        or "/" in name
        or "\\" in name
        or name.startswith(".")
        or not name
    ):
        raise ConsoleAssetNotFound(name)

    if name not in _ASSET_TYPES:
        raise ConsoleAssetNotFound(name)
    body = resources.files("zeroadr.api.static").joinpath(name).read_bytes()
    return ConsoleAsset(name=name, content_type=_ASSET_TYPES[name], body=body)
