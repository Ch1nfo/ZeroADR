from __future__ import annotations

import importlib
import importlib.util
import os
import platform
import pwd
import socket
import struct
import threading
from collections import deque
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable, Iterator

from zeroadr.core.ids import new_ulid
from zeroadr.endpoint.contracts import EndpointRecord, NetworkConnectRecord, ProcessExecRecord, SensitiveFileOpenRecord

ENABLE_ENV = "ZEROADR_ENABLE_BCC"
LEGACY_OPT_IN_ENV = "ZEROADR_RUN_EBPF_TESTS"
CAP_BPF = 39
CAP_PERFMON = 38
CAP_SYS_ADMIN = 21

DEFAULT_SENSITIVE_PATH_PREFIXES: tuple[str, ...] = (
    "/etc/shadow",
    "/etc/sudoers",
    "/root/.ssh",
    "/.ssh",
    ".env",
    ".env.",
)

DEFAULT_POLL_TIMEOUT_MS = 100
DEFAULT_MAX_QUEUE = 4096


class BccCollectorUnavailable(RuntimeError):
    pass


@dataclass(frozen=True)
class BccExecEvent:
    pid: int
    process: str
    executable: str | None = None
    command: str | None = None
    ppid: int | None = None


@dataclass(frozen=True)
class BccFileOpenEvent:
    pid: int
    process: str
    path: str
    ppid: int | None = None


@dataclass(frozen=True)
class BccNetworkConnectEvent:
    pid: int
    process: str
    host: str
    port: int | None = None
    ppid: int | None = None


@dataclass(frozen=True)
class ProcessEnrichment:
    user: str | None = None
    cwd: str | None = None
    process_start_time: str | None = None


@dataclass
class BccProbeState:
    name: str
    attached: bool = False
    events: int = 0
    errors: int = 0
    last_error: str | None = None


@dataclass(frozen=True)
class BccProbePrograms:
    exec: str = ""
    file_open: str = ""
    network_connect: str = ""

    def __init__(self) -> None:
        object.__setattr__(self, "exec", _BCC_EXEC_PROGRAM)
        object.__setattr__(self, "file_open", _BCC_FILE_OPEN_PROGRAM)
        object.__setattr__(self, "network_connect", _BCC_NETWORK_CONNECT_PROGRAM)


class BccRecordMultiplexer:
    def __init__(self, streams: list[Iterator[EndpointRecord]]) -> None:
        self.streams = streams

    def iter_records(self) -> Iterator[EndpointRecord]:
        active = list(self.streams)
        while active:
            next_active: list[Iterator[EndpointRecord]] = []
            for stream in active:
                try:
                    yield next(stream)
                except StopIteration:
                    continue
                next_active.append(stream)
            active = next_active


@dataclass
class _AttachedProbe:
    name: str
    bpf: Any
    events_table: Any
    queue: deque[Any]
    state: BccProbeState


class BccCollectorSession:
    def __init__(
        self,
        *,
        session_id: str,
        host_id: str | None = None,
        limit: int | None = None,
        sensitive_path_prefixes: tuple[str, ...] = DEFAULT_SENSITIVE_PATH_PREFIXES,
        poll_timeout_ms: int = DEFAULT_POLL_TIMEOUT_MS,
        max_queue: int = DEFAULT_MAX_QUEUE,
        stop_event: threading.Event | None = None,
        on_status_update: Callable[[], None] | None = None,
    ) -> None:
        self.session_id = session_id
        self.host_id = host_id or platform.node()
        self.limit = limit
        self.sensitive_path_prefixes = sensitive_path_prefixes
        self.poll_timeout_ms = poll_timeout_ms
        self.max_queue = max_queue
        self._stop_event = stop_event or threading.Event()
        self._on_status_update = on_status_update
        self._probes: list[_AttachedProbe] = []
        self._attached = False
        self.dropped_events = 0
        self.last_event_at: str | None = None
        self._lock = threading.Lock()

    def attach(self) -> None:
        if self._attached:
            return
        check_bcc_available()
        bcc_module = importlib.import_module("bcc")
        self._probes = [
            self._attach_exec_probe(bcc_module),
            self._attach_file_probe(bcc_module),
            self._attach_network_probe(bcc_module),
        ]
        if not self._active_probes():
            errors = "; ".join(
                f"{probe.name}: {probe.state.last_error or 'probe did not attach'}"
                for probe in self._probes
            )
            self.cleanup()
            raise BccCollectorUnavailable(f"BCC collector could not attach any probes: {errors}")
        self._attached = True
        self._notify_status()

    def cleanup(self) -> None:
        for probe in self._probes:
            try:
                probe.bpf.cleanup()
            except Exception as exc:
                probe.state.errors += 1
                probe.state.last_error = str(exc)
        self._probes = []
        self._attached = False
        self._notify_status()

    def stop(self) -> None:
        self._stop_event.set()

    def status_snapshot(self) -> dict[str, Any]:
        probes = {
            probe.name: {
                "attached": probe.state.attached,
                "events": probe.state.events,
                "errors": probe.state.errors,
                **({"last_error": probe.state.last_error} if probe.state.last_error else {}),
            }
            for probe in self._probes
        }
        return {
            "enabled": True,
            "probes": probes,
            "dropped_events": self.dropped_events,
            "last_event_at": self.last_event_at,
        }

    def iter_records(self) -> Iterator[EndpointRecord]:
        if not self._attached:
            self.attach()
        emitted = 0
        try:
            while not self._stop_event.is_set():
                if self.limit is not None and emitted >= self.limit:
                    break
                polled_any = False
                for probe in self._active_probes():
                    if self._stop_event.is_set():
                        break
                    if self.limit is not None and emitted >= self.limit:
                        break
                    try:
                        probe.bpf.perf_buffer_poll(timeout=self.poll_timeout_ms)
                        polled_any = True
                    except Exception as exc:
                        probe.state.errors += 1
                        probe.state.last_error = str(exc)
                        self._notify_status()
                    for record in self._drain_probe(probe):
                        emitted += 1
                        yield record
                        if self.limit is not None and emitted >= self.limit:
                            break
                if not polled_any and not any(probe.queue for probe in self._active_probes()):
                    if self.limit is not None:
                        break
        finally:
            self.cleanup()

    def _active_probes(self) -> list[_AttachedProbe]:
        return [probe for probe in self._probes if probe.state.attached]

    def _attach_exec_probe(self, bcc_module: Any) -> _AttachedProbe:
        state = BccProbeState(name="exec")
        probe = _AttachedProbe(name="exec", bpf=None, events_table=None, queue=deque(), state=state)
        try:
            bpf = bcc_module.BPF(text=_BCC_EXEC_PROGRAM)
            events = bpf["events"]
            probe.bpf = bpf
            probe.events_table = events

            def handle_event(cpu: int, data: Any, size: int) -> None:
                raw = events.event(data)
                self._enqueue(
                    probe,
                    BccExecEvent(
                        pid=int(raw.pid),
                        ppid=int(raw.ppid),
                        process=_decode(raw.comm),
                        executable=_decode(raw.filename),
                        command=_decode(raw.filename),
                    ),
                )

            events.open_perf_buffer(handle_event)
            bpf.attach_tracepoint(tp="sched:sched_process_exec", fn_name="trace_exec")
            state.attached = True
        except Exception as exc:
            state.last_error = str(exc)
            state.errors += 1
        return probe

    def _attach_file_probe(self, bcc_module: Any) -> _AttachedProbe:
        state = BccProbeState(name="file")
        probe = _AttachedProbe(name="file", bpf=None, events_table=None, queue=deque(), state=state)
        try:
            bpf = bcc_module.BPF(text=_BCC_FILE_OPEN_PROGRAM)
            events = bpf["events"]
            probe.bpf = bpf
            probe.events_table = events

            def handle_event(cpu: int, data: Any, size: int) -> None:
                raw = events.event(data)
                path = _decode(raw.path)
                if not path_matches_sensitive_prefix(path, self.sensitive_path_prefixes):
                    return
                self._enqueue(
                    probe,
                    BccFileOpenEvent(
                        pid=int(raw.pid),
                        ppid=int(raw.ppid),
                        process=_decode(raw.comm),
                        path=path,
                    ),
                )

            events.open_perf_buffer(handle_event)
            syscall = bpf.get_syscall_fnname("openat")
            bpf.attach_kprobe(event=syscall, fn_name="trace_openat")
            state.attached = True
        except Exception as exc:
            state.last_error = str(exc)
            state.errors += 1
        return probe

    def _attach_network_probe(self, bcc_module: Any) -> _AttachedProbe:
        state = BccProbeState(name="network")
        probe = _AttachedProbe(name="network", bpf=None, events_table=None, queue=deque(), state=state)
        try:
            bpf = bcc_module.BPF(text=_BCC_NETWORK_CONNECT_PROGRAM)
            events = bpf["events"]
            probe.bpf = bpf
            probe.events_table = events

            def handle_event(cpu: int, data: Any, size: int) -> None:
                raw = events.event(data)
                self._enqueue(
                    probe,
                    BccNetworkConnectEvent(
                        pid=int(raw.pid),
                        ppid=int(raw.ppid),
                        process=_decode(raw.comm),
                        host=_ipv4_from_kernel_value(int(raw.daddr)),
                        port=socket.ntohs(int(raw.dport)),
                    ),
                )

            events.open_perf_buffer(handle_event)
            bpf.attach_kprobe(event="tcp_v4_connect", fn_name="trace_tcp_v4_connect")
            state.attached = True
        except Exception as exc:
            state.last_error = str(exc)
            state.errors += 1
        return probe

    def _enqueue(self, probe: _AttachedProbe, event: Any) -> None:
        with self._lock:
            if len(probe.queue) >= self.max_queue:
                self.dropped_events += 1
                self._notify_status()
                return
            probe.queue.append(event)

    def _drain_probe(self, probe: _AttachedProbe) -> list[EndpointRecord]:
        records: list[EndpointRecord] = []
        while True:
            with self._lock:
                if not probe.queue:
                    break
                event = probe.queue.popleft()
            record = self._event_to_record(probe.name, event)
            probe.state.events += 1
            self.last_event_at = _utc_now()
            records.append(record)
            self._notify_status()
        return records

    def _event_to_record(self, probe_name: str, event: Any) -> EndpointRecord:
        enrichment = enrich_process(getattr(event, "pid", 0))
        if probe_name == "exec" and isinstance(event, BccExecEvent):
            return bcc_exec_event_to_record(
                event,
                session_id=self.session_id,
                host_id=self.host_id,
                enrichment=enrichment,
            )
        if probe_name == "file" and isinstance(event, BccFileOpenEvent):
            return bcc_file_open_event_to_record(
                event,
                session_id=self.session_id,
                host_id=self.host_id,
                enrichment=enrichment,
            )
        if probe_name == "network" and isinstance(event, BccNetworkConnectEvent):
            return bcc_network_connect_event_to_record(
                event,
                session_id=self.session_id,
                host_id=self.host_id,
                enrichment=enrichment,
            )
        raise ValueError(f"unsupported probe event: {probe_name}")

    def _notify_status(self) -> None:
        if self._on_status_update is not None:
            self._on_status_update()


def parse_sensitive_path_prefixes(raw: str | None) -> tuple[str, ...]:
    if raw is None or not raw.strip():
        return DEFAULT_SENSITIVE_PATH_PREFIXES
    return tuple(part.strip() for part in raw.split(",") if part.strip())


def path_matches_sensitive_prefix(path: str, prefixes: tuple[str, ...]) -> bool:
    normalized = os.path.normpath(os.path.expanduser(path))
    for prefix in prefixes:
        expanded = os.path.normpath(os.path.expanduser(prefix))
        if expanded.startswith("."):
            if normalized.endswith(expanded) or normalized.endswith(f"/{expanded.lstrip('.')}"):
                return True
            if expanded.endswith(".") and os.path.basename(normalized).startswith(expanded):
                return True
            continue
        if normalized == expanded or normalized.startswith(expanded + os.sep):
            return True
    return False


def _effective_capabilities() -> int:
    try:
        status = Path("/proc/self/status").read_text(encoding="utf-8")
    except OSError:
        return 0
    for line in status.splitlines():
        if line.startswith("CapEff:"):
            return int(line.split(":", 1)[1].strip(), 16)
    return 0


def _capability_is_effective(capability: int) -> bool:
    mask = 1 << capability
    return (_effective_capabilities() & mask) != 0


def _has_ebpf_privileges() -> bool:
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        return True
    return any(
        _capability_is_effective(cap)
        for cap in (CAP_BPF, CAP_PERFMON, CAP_SYS_ADMIN)
    )


def _bcc_enabled() -> bool:
    return os.environ.get(ENABLE_ENV) == "1" or os.environ.get(LEGACY_OPT_IN_ENV) == "1"


def check_bcc_available() -> None:
    if platform.system() != "Linux":
        raise BccCollectorUnavailable("BCC collector requires a Linux host.")
    if not _bcc_enabled():
        raise BccCollectorUnavailable(
            f"BCC collector requires {ENABLE_ENV}=1 for real probe execution."
        )
    if not _has_ebpf_privileges():
        raise BccCollectorUnavailable(
            "BCC collector requires root or equivalent eBPF capabilities (CAP_BPF, CAP_PERFMON, or CAP_SYS_ADMIN)."
        )
    if importlib.util.find_spec("bcc") is None:
        raise BccCollectorUnavailable("BCC collector requires the optional 'bcc' Python module.")


def enrich_process(pid: int) -> ProcessEnrichment:
    if pid <= 0:
        return ProcessEnrichment()
    return ProcessEnrichment(
        user=_read_process_user(pid),
        cwd=_read_process_cwd(pid),
        process_start_time=_read_process_start_time(pid),
    )


def bcc_exec_event_to_record(
    event: BccExecEvent,
    *,
    session_id: str,
    host_id: str | None = None,
    event_id: str | None = None,
    timestamp: str | None = None,
    enrichment: ProcessEnrichment | None = None,
) -> ProcessExecRecord:
    command = event.command or event.executable or event.process
    extra = enrichment or ProcessEnrichment()
    return ProcessExecRecord(
        event_id=event_id or new_ulid(),
        timestamp=timestamp or _utc_now(),
        session_id=session_id,
        host_id=host_id,
        pid=event.pid,
        ppid=event.ppid,
        process=event.process,
        executable=event.executable,
        command=command,
        user=extra.user,
        cwd=extra.cwd,
        process_start_time=extra.process_start_time,
    )


def bcc_file_open_event_to_record(
    event: BccFileOpenEvent,
    *,
    session_id: str,
    host_id: str | None = None,
    event_id: str | None = None,
    timestamp: str | None = None,
    enrichment: ProcessEnrichment | None = None,
) -> SensitiveFileOpenRecord:
    extra = enrichment or ProcessEnrichment()
    return SensitiveFileOpenRecord(
        event_id=event_id or new_ulid(),
        timestamp=timestamp or _utc_now(),
        session_id=session_id,
        host_id=host_id,
        pid=event.pid,
        ppid=event.ppid,
        process=event.process,
        path=event.path,
        user=extra.user,
        cwd=extra.cwd,
        process_start_time=extra.process_start_time,
    )


def bcc_network_connect_event_to_record(
    event: BccNetworkConnectEvent,
    *,
    session_id: str,
    host_id: str | None = None,
    event_id: str | None = None,
    timestamp: str | None = None,
    enrichment: ProcessEnrichment | None = None,
) -> NetworkConnectRecord:
    extra = enrichment or ProcessEnrichment()
    return NetworkConnectRecord(
        event_id=event_id or new_ulid(),
        timestamp=timestamp or _utc_now(),
        session_id=session_id,
        host_id=host_id,
        pid=event.pid,
        ppid=event.ppid,
        process=event.process,
        host=event.host,
        port=event.port,
        user=extra.user,
        cwd=extra.cwd,
        process_start_time=extra.process_start_time,
    )


def iter_bcc_records(
    *,
    session_id: str,
    host_id: str | None = None,
    limit: int | None = None,
    sensitive_path_prefixes: tuple[str, ...] = DEFAULT_SENSITIVE_PATH_PREFIXES,
    poll_timeout_ms: int = DEFAULT_POLL_TIMEOUT_MS,
    max_queue: int = DEFAULT_MAX_QUEUE,
    stop_event: threading.Event | None = None,
    on_status_update: Callable[[], None] | None = None,
) -> Iterator[EndpointRecord]:
    session = BccCollectorSession(
        session_id=session_id,
        host_id=host_id,
        limit=limit,
        sensitive_path_prefixes=sensitive_path_prefixes,
        poll_timeout_ms=poll_timeout_ms,
        max_queue=max_queue,
        stop_event=stop_event,
        on_status_update=on_status_update,
    )
    yield from session.iter_records()


def _read_process_user(pid: int) -> str | None:
    try:
        status = Path(f"/proc/{pid}/status").read_text(encoding="utf-8")
    except OSError:
        return None
    for line in status.splitlines():
        if line.startswith("Uid:"):
            uid_text = line.split(":", 1)[1].strip().split()[0]
            try:
                return pwd.getpwuid(int(uid_text)).pw_name
            except (KeyError, ValueError):
                return uid_text
    return None


def _read_process_cwd(pid: int) -> str | None:
    try:
        return os.readlink(f"/proc/{pid}/cwd")
    except OSError:
        return None


def _read_process_start_time(pid: int) -> str | None:
    try:
        stat = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
        boot_time = _system_boot_time()
    except OSError:
        return None
    close_paren = stat.rfind(")")
    if close_paren == -1:
        return None
    fields = stat[close_paren + 2 :].split()
    if len(fields) < 20:
        return None
    try:
        starttime_ticks = int(fields[19])
        clock_ticks = os.sysconf(os.sysconf_names["SC_CLK_TCK"])
        started = boot_time + (starttime_ticks / clock_ticks)
        return datetime.fromtimestamp(started, UTC).isoformat().replace("+00:00", "Z")
    except (OSError, ValueError):
        return None


def _system_boot_time() -> float:
    for line in Path("/proc/stat").read_text(encoding="utf-8").splitlines():
        if line.startswith("btime "):
            return float(line.split()[1])
    raise OSError("btime not found in /proc/stat")


def _decode(value: Any) -> str:
    if isinstance(value, bytes):
        return value.split(b"\x00", 1)[0].decode("utf-8", errors="replace")
    return str(value).split("\x00", 1)[0]


def _ipv4_from_kernel_value(value: int) -> str:
    return socket.inet_ntoa(struct.pack("<I", value))


def _utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


_BCC_EXEC_PROGRAM = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct exec_event_t {
    u32 pid;
    u32 ppid;
    char comm[TASK_COMM_LEN];
    char filename[256];
};

BPF_PERF_OUTPUT(events);

TRACEPOINT_PROBE(sched, sched_process_exec) {
    struct exec_event_t event = {};
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.ppid = task->real_parent->tgid;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_probe_read_kernel_str(&event.filename, sizeof(event.filename), args->filename);
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}
"""


_BCC_FILE_OPEN_PROGRAM = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct file_open_event_t {
    u32 pid;
    u32 ppid;
    char comm[TASK_COMM_LEN];
    char path[256];
};

BPF_PERF_OUTPUT(events);

int trace_openat(struct pt_regs *ctx, int dfd, const char __user *filename) {
    struct file_open_event_t event = {};
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.ppid = task->real_parent->tgid;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_probe_read_user_str(&event.path, sizeof(event.path), filename);
    events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}
"""


_BCC_NETWORK_CONNECT_PROGRAM = r"""
#include <uapi/linux/ptrace.h>
#include <net/sock.h>

struct network_connect_event_t {
    u32 pid;
    u32 ppid;
    u32 daddr;
    u16 dport;
    char comm[TASK_COMM_LEN];
};

BPF_PERF_OUTPUT(events);

int trace_tcp_v4_connect(struct pt_regs *ctx, struct sock *sk) {
    struct network_connect_event_t event = {};
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.ppid = task->real_parent->tgid;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_probe_read_kernel(&event.daddr, sizeof(event.daddr), &sk->__sk_common.skc_daddr);
    bpf_probe_read_kernel(&event.dport, sizeof(event.dport), &sk->__sk_common.skc_dport);
    events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}
"""
