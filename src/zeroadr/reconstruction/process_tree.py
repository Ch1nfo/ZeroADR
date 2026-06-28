from __future__ import annotations

from typing import Any

from zeroadr.core.events import RuntimeEvent

ProcessTree = dict[str, list[dict[str, Any]]]


def build_process_tree(events: list[RuntimeEvent]) -> ProcessTree:
    endpoint_events = [
        event
        for event in events
        if event.source_type == "endpoint_sensor" and isinstance(event.arguments, dict)
    ]
    nodes_by_key: dict[str, dict[str, Any]] = {}
    pid_index: dict[tuple[str, str, str], str] = {}
    for event in endpoint_events:
        arguments = event.arguments or {}
        pid = arguments.get("pid")
        if pid is None:
            continue
        key = process_key(event)
        node = nodes_by_key.setdefault(
            key,
            {
                "process_key": key,
                "session_id": event.session_id,
                "host_id": str(arguments.get("host_id") or ""),
                "pid": pid,
                "ppid": arguments.get("ppid"),
                "process": arguments.get("process"),
                "process_start_time": arguments.get("process_start_time"),
                "executable": arguments.get("executable"),
                "cwd": arguments.get("cwd"),
                "user": arguments.get("user"),
                "event_ids": [],
            },
        )
        node["event_ids"].append(event.event_id)
        pid_index[(_session_scope(event), str(arguments.get("host_id") or ""), str(pid))] = key

    edges: list[dict[str, Any]] = []
    seen_edges: set[tuple[str, str]] = set()
    for event in endpoint_events:
        arguments = event.arguments or {}
        child_pid = arguments.get("pid")
        parent_pid = arguments.get("ppid")
        if child_pid is None or parent_pid is None:
            continue
        child_key = process_key(event)
        parent_key = pid_index.get(
            (_session_scope(event), str(arguments.get("host_id") or ""), str(parent_pid))
        )
        if parent_key is None or parent_key == child_key:
            continue
        edge_key = (parent_key, child_key)
        if edge_key in seen_edges:
            continue
        seen_edges.add(edge_key)
        edges.append(
            {
                "parent_key": parent_key,
                "child_key": child_key,
                "relationship": "parent_process",
            }
        )

    return {
        "nodes": sorted(nodes_by_key.values(), key=lambda node: str(node["process_key"])),
        "edges": sorted(edges, key=lambda edge: (edge["parent_key"], edge["child_key"])),
    }


def process_key(event: RuntimeEvent) -> str:
    arguments = event.arguments if isinstance(event.arguments, dict) else {}
    pid = arguments.get("pid")
    host_id = arguments.get("host_id")
    process_start_time = arguments.get("process_start_time")
    if host_id is not None and pid is not None and process_start_time is not None:
        return f"{host_id}:{pid}:{process_start_time}"
    return f"{event.session_id}:{pid}"


def _session_scope(event: RuntimeEvent) -> str:
    return event.session_id
