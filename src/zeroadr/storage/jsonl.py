from __future__ import annotations

from pathlib import Path

from zeroadr.core.events import RuntimeEvent


def write_event_jsonl(path: Path, event: RuntimeEvent) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(event.model_dump_json() + "\n")


def read_events_jsonl(path: Path) -> list[RuntimeEvent]:
    events: list[RuntimeEvent] = []
    if not path.exists():
        return events
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            stripped = line.strip()
            if stripped:
                events.append(RuntimeEvent.model_validate_json(stripped))
    return events
