from __future__ import annotations

import json
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Iterator, TypedDict

from zeroadr.endpoint.contracts import EndpointRecord, endpoint_record_to_mapping


class CollectorWriteResult(TypedDict):
    records_written: int
    output: str


class EndpointCollector(ABC):
    @abstractmethod
    def iter_records(self) -> Iterator[EndpointRecord | dict[str, Any]]:
        raise NotImplementedError

    def write_jsonl(self, output_path: Path, *, limit: int | None = None) -> CollectorWriteResult:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        records_written = 0
        with output_path.open("w", encoding="utf-8") as output:
            for record in self.iter_records():
                if limit is not None and records_written >= limit:
                    break
                output.write(json.dumps(endpoint_record_to_mapping(record), sort_keys=True) + "\n")
                records_written += 1
        return {"records_written": records_written, "output": str(output_path)}
