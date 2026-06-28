# Endpoint Lite Sensor

ZeroADR v0.4 starts with an endpoint JSONL ingest path and a contract-first
collector boundary. Native collectors emit endpoint JSONL, then ZeroADR converts
those records into `RuntimeEvent` records with `source_type: endpoint_sensor`.

## Ingest

```bash
zeroadr endpoint ingest \
  --input examples/endpoint/01_sensitive_file_to_external_network.jsonl \
  --trace .zeroadr/traces/endpoint.jsonl \
  --db .zeroadr/zeroadr.sqlite
```

The command writes redacted RuntimeEvents to JSONL and SQLite. Detection and
policy evaluation are performed later with `zeroadr replay`.

By default, ingest runs in lenient mode for compatibility with early collector
prototypes. Use `--strict` to enforce the Endpoint JSONL Contract:

```bash
zeroadr endpoint ingest \
  --strict \
  --input examples/endpoint/01_sensitive_file_to_external_network.jsonl \
  --trace .zeroadr/traces/endpoint.jsonl
```

Strict mode requires `schema_version: "0.1"`, `event_id`, `timestamp`,
`session_id`, and the event-specific target field. Validation errors include
the JSONL line number.

## Tail Mode

For local development and lightweight daemon-like deployments, ZeroADR can follow
an endpoint JSONL file and persist new events as they are appended:

```bash
zeroadr endpoint tail \
  --strict \
  --input /tmp/zeroadr-endpoint.jsonl \
  --trace .zeroadr/traces/endpoint.jsonl \
  --checkpoint-file .zeroadr/endpoint-tail.checkpoint.json \
  --db .zeroadr/zeroadr.sqlite
```

`--checkpoint-file` stores the last processed byte offset and JSONL line number.
After restart, tail resumes from that offset and avoids re-ingesting old lines.
The checkpoint advances only after a record is successfully persisted.

For tests and bounded smoke runs, use `--stop-after-idle`:

```bash
zeroadr endpoint tail \
  --input examples/endpoint/02_process_lineage.jsonl \
  --trace .zeroadr/traces/endpoint-lineage.jsonl \
  --stop-after-idle 0.1
```

## Collector Mode

The current rootless collector implementation is deterministic and intended for
tests, demos, and contract validation:

```bash
zeroadr endpoint collect \
  --collector mock \
  --output examples/endpoint/03_mock_collector_output.jsonl \
  --limit 3
```

Add `--trace` and `--db` to ingest immediately after collection:

```bash
zeroadr endpoint collect \
  --collector mock \
  --output /tmp/zeroadr-mock-endpoint.jsonl \
  --trace /tmp/zeroadr-mock-runtime.jsonl \
  --strict-ingest \
  --limit 3
```

## Agent Mode

`endpoint agent` is the long-running endpoint collection path. It appends
endpoint JSONL one record at a time, flushes after each write, and can optionally
ingest records immediately into RuntimeEvent trace/SQLite:

```bash
zeroadr endpoint agent \
  --collector mock \
  --output examples/endpoint/07_agent_mock_output.jsonl \
  --limit 3
```

Immediate ingest:

```bash
zeroadr endpoint agent \
  --collector mock \
  --output /tmp/zeroadr-agent-endpoint.jsonl \
  --status-file /tmp/zeroadr-agent-status.json \
  --trace /tmp/zeroadr-agent-runtime.jsonl \
  --session-id sess_endpoint_agent \
  --strict-ingest \
  --rotate-bytes 104857600 \
  --max-rotated-files 5 \
  --max-output-bytes 536870912 \
  --write-retry-count 2 \
  --write-retry-delay 0.05 \
  --heartbeat-interval 5 \
  --limit 3
```

`--status-file` writes a JSON status snapshot at startup, after each record, and
before exit. It includes `collector`, `started_at`, `updated_at`,
`records_written`, `records_read`, `events_written`, `session_ids`,
`state`, `stopped_reason`, `last_error`, `last_record_at`, `uptime_seconds`,
paths, and collector availability.

Inspect agent health from the status file:

```bash
zeroadr endpoint status \
  --status-file /tmp/zeroadr-agent-status.json \
  --stale-after 30
```

The command returns `healthy: false` and a non-zero exit code for stale or error
status files.

Collector initialization failures, strict ingest failures, and endpoint JSONL
write failures update the same status contract with `state: "error"`,
`stopped_reason`, and `last_error`. The CLI prints the reason to stderr and
returns a non-zero exit code.

`--rotate-bytes` rotates the endpoint JSONL output before writing a record that
would exceed the configured size. Rotated files use `.1`, `.2`, and so on, up to
`--max-rotated-files`. The agent status and final result include `rotations`.
`--max-output-bytes` bounds the active output plus rotated files by deleting the
oldest rotated files first. Status and final result include `retained_bytes` and
`dropped_rotated_files`.

`--write-retry-count` and `--write-retry-delay` provide a minimal local
backpressure baseline for transient endpoint JSONL write failures. Retry events
are recorded as `backpressure_events` with `last_backpressure_at`.

Current stopped reasons:

- `limit`
- `exhausted`
- `idle`
- `signal`
- `error`

Use `endpoint collect` for finite collector output, `endpoint tail` to ingest an
already-appended JSONL file, and `endpoint agent` when one process should collect
and optionally ingest at the same time.

The Linux collector is scaffolded behind explicit platform, privilege, and
optional dependency checks. The current BCC prototype path covers process exec,
sensitive file open, and outbound network connect events. It requires
`ZEROADR_RUN_EBPF_TESTS=1` for real probe execution:

```bash
ZEROADR_RUN_EBPF_TESTS=1 zeroadr endpoint collect \
  --collector linux \
  --output /tmp/zeroadr-bcc-endpoint.jsonl \
  --session-id sess_linux_bcc \
  --limit 1
```

Production eBPF daemon behavior is not implemented yet.

## Supported Events

- `process_exec` -> `shell.exec`
- `sensitive_file_open` -> `filesystem.read`
- `network_connect` -> `network.connect`

Required fields:

- `schema_version` for strict/native collector records
- `event_type`
- `event_id` in strict mode
- `timestamp` in strict mode
- `session_id`

Recommended fields:

- `host_id`
- `pid`
- `ppid`
- `process`
- `process_start_time`
- `executable`
- `cwd`
- `user`
- `command` for `process_exec`
- `path` for `sensitive_file_open`
- `url`, `host`, or `domain` for `network_connect`

Lenient mode still accepts legacy records without `schema_version` so older
collector prototypes can continue to feed ZeroADR during development.

## Process Identity

ZeroADR builds a stable process key with:

```text
host_id + pid + process_start_time
```

When `process_start_time` is missing, it falls back to:

```text
session_id + pid
```

Parent-child edges are created when endpoint events share the same session/host
and a child event's `ppid` matches a known parent `pid`.

## Session Correlation

Session reconstruction exposes:

- `process_tree`: endpoint process nodes and parent-child edges.
- `endpoint_correlations`: deterministic relationships from MCP/hook runtime
  events to endpoint observations.

Current correlation is intentionally conservative. ZeroADR links endpoint events
to runtime events only when they share `session_id` and either the same
`request_id` or the same normalized target.

## Replay

```bash
zeroadr replay .zeroadr/traces/endpoint.jsonl
```

Endpoint events reuse the existing detector chain. For example, a
`sensitive_file_open` followed by a `network_connect` to an external destination
can produce an `external-data-exfiltration` finding.

## Current Limitations

- Native Linux/eBPF collection currently has a BCC exec/file/network spike only.
- No macOS Endpoint Security or Windows ETW collector yet.
- No production Linux/BCC daemon yet. See [`docs/endpoint-agent-deployment.md`](endpoint-agent-deployment.md) for v0.6 systemd/launchd templates.
- Process correlation is deterministic and local to the available JSONL fields.
