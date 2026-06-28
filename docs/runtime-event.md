# RuntimeEvent v0.1

`RuntimeEvent` is the normalized event schema used by detectors, policy, trace
storage, and replay. Detectors should read normalized fields instead of client
or MCP-specific raw payloads.

## Event Types

The v0.1 schema supports:

- `session.start`
- `tool.call.requested`
- `tool.call.completed`
- `tool.call.failed`
- `policy.evaluated`

## Fields

- `spec_version`: schema version, currently `0.1`.
- `event_id`: ULID-like event identifier.
- `event_type`: normalized runtime event type.
- `event_time`: UTC event timestamp.
- `ingest_time`: UTC time when ZeroADR ingested the event.
- `source_type`: `mcp_gateway` or `replay`.
- `session_id`: ZeroADR session identifier.
- `request_id`: JSON-RPC request id when available.
- `server_name`: MCP server name when known.
- `tool_name`: MCP tool name when known.
- `capability`: normalized capability such as `filesystem.read`.
- `arguments`: normalized tool arguments.
- `result`: tool result for completed calls.
- `error`: JSON-RPC error object for failed calls.
- `raw`: original source event for reconstruction.

## Storage

Events can be serialized to JSONL and restored without losing schema fields.
SQLite storage keeps the event JSON as the canonical row payload for replay and
export.
