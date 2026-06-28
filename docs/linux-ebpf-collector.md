# Linux eBPF Collector

ZeroADR v0.4 introduced a contract-first endpoint collector design. v0.8
productionizes the BCC Python collector for long-running Linux endpoint agents.

Native collectors emit versioned endpoint JSONL records, and the existing
`endpoint ingest` / `endpoint tail` path remains responsible for normalization,
redaction, persistence, replay, and reconstruction.

## Endpoint JSONL Contract

Native collector records use `schema_version: "0.1"` and one of these event
types:

- `process_exec`
- `sensitive_file_open`
- `network_connect`

Common fields:

- `schema_version`
- `event_type`
- `event_id`
- `timestamp`
- `session_id`
- `host_id`
- `pid`
- `ppid`
- `process`
- `process_start_time`
- `executable`
- `cwd`
- `user`

Target fields:

- `command` for `process_exec`
- `path` for `sensitive_file_open`
- `url`, `host`, `domain`, and `port` for `network_connect`

The Python models live in `zeroadr.endpoint.contracts`. Existing legacy JSONL
records without `schema_version` are still accepted by the ingest path.

## Mock Collector

The mock collector is deterministic and rootless:

```bash
zeroadr endpoint collect \
  --collector mock \
  --output examples/endpoint/03_mock_collector_output.jsonl \
  --limit 3
```

## Linux Collector (v0.8 Production)

`zeroadr endpoint collect --collector linux` and `zeroadr endpoint agent
--collector linux` use a unified `BccCollectorSession` with:

- one fair poll loop across exec, file-open, and network probes
- graceful BPF attach/detach lifecycle
- user-space sensitive path filtering
- `/proc` enrichment for `user`, `cwd`, and `process_start_time`
- probe health metrics in the agent status file

### Enable BCC

Production and staging hosts must opt in explicitly:

```bash
sudo apt-get install -y python3-bpfcc bpfcc-tools linux-headers-$(uname -r)
export ZEROADR_ENABLE_BCC=1
python3 -m pip install -e .
```

The PyPI project named `bcc` is unrelated to iovisor/BCC. Install the BCC
Python bindings from the operating-system packages above, or build iovisor/BCC
from source for the Python interpreter used by the endpoint agent.

Requirements:

- Linux host with BCC/bpfcc (`linux-headers`, `bpfcc-tools`, Python `bcc` module)
- root **or** effective `CAP_BPF`, `CAP_PERFMON`, or `CAP_SYS_ADMIN`

`ZEROADR_RUN_EBPF_TESTS=1` remains accepted as a legacy alias for local tests.

### Long-Running Agent

```bash
ZEROADR_ENABLE_BCC=1 zeroadr endpoint agent \
  --collector linux \
  --output .zeroadr/endpoint-agent.jsonl \
  --status-file .zeroadr/endpoint-agent-status.json \
  --pid-file .zeroadr/endpoint-agent.pid \
  --trace .zeroadr/traces/endpoint-agent.jsonl \
  --db .zeroadr/zeroadr.sqlite \
  --strict-ingest \
  --heartbeat-interval 5 \
  --sensitive-path-prefixes "/etc/shadow,/etc/sudoers,/root/.ssh,.env" \
  --bcc-poll-timeout-ms 100 \
  --bcc-max-queue 4096
```

Finite batch collection:

```bash
ZEROADR_ENABLE_BCC=1 zeroadr endpoint collect \
  --collector linux \
  --output /tmp/zeroadr-bcc-endpoint.jsonl \
  --limit 10
```

### Sensitive Path Filtering

File-open probes capture all `openat` events in kernel space, but the collector
only emits `sensitive_file_open` records when the path matches configured
prefixes. Defaults include `/etc/shadow`, `/etc/sudoers`, `/root/.ssh`, and
`.env`.

Override with `--sensitive-path-prefixes` (comma-separated) on `endpoint agent`.

### Agent Status and Health

When `--collector linux` is running, the status file includes a `bcc` object:

```json
{
  "collector": "linux",
  "bcc": {
    "enabled": true,
    "probes": {
      "exec": {"attached": true, "events": 120, "errors": 0},
      "file": {"attached": true, "events": 45, "errors": 0},
      "network": {"attached": true, "events": 12, "errors": 0}
    },
    "dropped_events": 0,
    "last_event_at": "2026-06-26T12:00:00Z"
  }
}
```

Console reads this through `GET /api/v0/endpoint-agent/health`.

### systemd Deployment

Use [`deploy/systemd/zeroadr-endpoint-agent-linux.service`](../deploy/systemd/zeroadr-endpoint-agent-linux.service)
for privileged Linux hosts. See [`docs/endpoint-agent-deployment.md`](endpoint-agent-deployment.md).

## Example Records

Process exec:

```json
{
  "schema_version": "0.1",
  "event_type": "process_exec",
  "event_id": "01J...",
  "timestamp": "2026-06-26T00:00:00Z",
  "session_id": "sess_linux_bcc",
  "host_id": "linux-host",
  "pid": 1234,
  "ppid": 1000,
  "process": "python3",
  "executable": "/usr/bin/python3",
  "command": "/usr/bin/python3 script.py",
  "user": "agent",
  "cwd": "/workspace",
  "process_start_time": "2026-06-26T00:00:00Z"
}
```

Sensitive file open:

```json
{
  "schema_version": "0.1",
  "event_type": "sensitive_file_open",
  "event_id": "01J...",
  "timestamp": "2026-06-26T00:00:01Z",
  "session_id": "sess_linux_bcc",
  "host_id": "linux-host",
  "pid": 1234,
  "process": "python3",
  "path": "/workspace/.env",
  "user": "agent",
  "cwd": "/workspace"
}
```

Network connect:

```json
{
  "schema_version": "0.1",
  "event_type": "network_connect",
  "event_id": "01J...",
  "timestamp": "2026-06-26T00:00:02Z",
  "session_id": "sess_linux_bcc",
  "host_id": "linux-host",
  "pid": 1234,
  "process": "python3",
  "host": "203.0.113.20",
  "port": 443
}
```

## Troubleshooting

| Symptom | Likely cause |
|---------|----------------|
| `ZEROADR_ENABLE_BCC=1` missing | BCC not enabled for this host |
| `requires the optional 'bcc' Python module` | Install `python3-bpfcc` or build iovisor/BCC Python bindings for the agent interpreter |
| `requires root or equivalent eBPF capabilities` | Run as root or grant `CAP_BPF` |
| `network` probe detached | Kernel lacks `tcp_v4_connect` kprobe support |
| High `dropped_events` | Increase `--bcc-max-queue` or reduce probe noise |

## Current Limitations

- BCC Python only; no libbpf/CO-RE rewrite yet
- IPv4 TCP connect only for network probe
- User-space path filtering only
- No Kubernetes DaemonSet packaging

Default CI does not load eBPF programs. Opt-in live tests use
`ZEROADR_ENABLE_BCC=1` on privileged Linux workers.
