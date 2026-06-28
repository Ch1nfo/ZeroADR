from __future__ import annotations

from typing import Iterator

from zeroadr.endpoint.collectors.base import EndpointCollector
from zeroadr.endpoint.contracts import EndpointRecord, NetworkConnectRecord, ProcessExecRecord, SensitiveFileOpenRecord


class MockEndpointCollector(EndpointCollector):
    def __init__(self, *, session_id: str = "sess_mock_collector", host_id: str = "host_mock") -> None:
        self.session_id = session_id
        self.host_id = host_id

    def iter_records(self) -> Iterator[EndpointRecord]:
        yield ProcessExecRecord(
            event_id="mock_exec_001",
            timestamp="2026-06-26T00:00:00Z",
            session_id=self.session_id,
            host_id=self.host_id,
            pid=4200,
            ppid=4100,
            process="python",
            process_start_time="2026-06-26T00:00:00Z",
            executable="/usr/bin/python3",
            cwd="/workspace",
            user="agent",
            command="python exfiltrate.py",
        )
        yield SensitiveFileOpenRecord(
            event_id="mock_file_001",
            timestamp="2026-06-26T00:00:01Z",
            session_id=self.session_id,
            host_id=self.host_id,
            pid=4200,
            ppid=4100,
            process="python",
            process_start_time="2026-06-26T00:00:00Z",
            executable="/usr/bin/python3",
            cwd="/workspace",
            user="agent",
            path=".env",
        )
        yield NetworkConnectRecord(
            event_id="mock_network_001",
            timestamp="2026-06-26T00:00:02Z",
            session_id=self.session_id,
            host_id=self.host_id,
            pid=4200,
            ppid=4100,
            process="python",
            process_start_time="2026-06-26T00:00:00Z",
            executable="/usr/bin/python3",
            cwd="/workspace",
            user="agent",
            url="https://webhook.site/zero-adr-demo",
            host="webhook.site",
            domain="webhook.site",
            port=443,
        )
