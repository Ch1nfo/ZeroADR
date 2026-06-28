# Console API

ZeroADR v0.5 includes a dependency-free local read-only API contract and a
minimal browser Console for local investigation. The HTTP server binds to
localhost by default.

## CLI

Recommended local demo:

```bash
zeroadr api demo
```

The command regenerates `.zeroadr/console-demo.sqlite`, starts the localhost
API server, and prints the Console URL.

Run the same flow step by step:

```bash
zeroadr api seed-demo --db .zeroadr/console-demo.sqlite
```

```bash
zeroadr api serve \
  --db .zeroadr/console-demo.sqlite \
  --agent-status-file .zeroadr/endpoint-agent-status.json \
  --host 127.0.0.1 \
  --port 8765
```

Use `--agent-status-file` when the Console should read endpoint agent health
from a local status file.

The approval API is unauthenticated and is restricted to loopback binding by
default. Binding to a non-loopback address requires an explicit acknowledgement:

```bash
zeroadr api serve --host 0.0.0.0 --allow-insecure-non-loopback
```

This flag does not add authentication. Do not expose this mode to an untrusted
network.

Existing local JSON commands remain available:

```bash
zeroadr api dump --db .zeroadr/zeroadr.sqlite
zeroadr api session <session_id> --db .zeroadr/zeroadr.sqlite
```

Open the local Console:

```text
http://127.0.0.1:8765/console
```

## Routes

### `GET /console`

Returns the local read-only Web Console shell. The page uses built-in static
HTML, CSS, and JavaScript and calls the read-only API routes below.

The Console currently renders:

- session inventory with search and risk filters.
- risk and finding summaries.
- compact session timeline with event detail drilldown and capability filters.
- evidence highlights and finding evidence chains with rule filters.
- policy decision history with action filters.
- a local LLM settings panel with connection testing.
- inventory and Agent-BOM-oriented fields.
- endpoint agent health with collector state, record counts, and error hints.
- pending approval inbox with approve/deny actions.

### `GET /api/v0/endpoint-agent/health`

Returns the current endpoint agent health envelope read from the configured
status file.

Resolution order:

- `zeroadr api serve --agent-status-file`
- `ZEROADR_AGENT_STATUS_FILE`
- default `.zeroadr/endpoint-agent-status.json`

When the status file is missing, the API returns `state: "unknown"` instead of
an HTTP 500.

### `GET /console/assets/{asset}`

Returns built-in Console static assets. Only known asset names are served.

### `GET /health`

Returns:

```json
{
  "api_version": "0.1",
  "status": "ok"
}
```

### `GET /api/v0/sessions`

Returns a session inventory envelope:

```json
{
  "ok": true,
  "data": {
    "api_version": "0.1",
    "session_count": 1,
    "limit": 25,
    "offset": 0,
    "returned_count": 1,
    "sessions": []
  }
}
```

Query parameters:

- `limit`
- `offset`

### `GET /api/v0/sessions/{session_id}`

Returns reconstructed context, compact summary, and Agent-BOM by default.

Use compact mode for lighter console views:

```bash
curl 'http://127.0.0.1:8765/api/v0/sessions/sess_123?compact=1'
```

Compact responses include `summary`, `risk`, `timeline`, and `inventory` without
the full raw reconstructed context.

### `GET /api/v0/sessions/{session_id}/evidence`

Returns one focused evidence payload for the selected session.

Query parameters:

- `finding_id`
- `rule_id`

The response includes the selected finding, related events, and related policy
decisions. Unknown finding or rule filters return an empty evidence payload,
not a server error.

### `GET /api/v0/sessions/{session_id}/events`

Returns all stored `RuntimeEvent` records for the session in a stable envelope.

### `GET /api/v0/sessions/{session_id}/findings`

Returns all stored findings for the session in a stable envelope.

### `GET /api/v0/sessions/{session_id}/decisions`

Returns all stored policy decisions for the session in a stable envelope.

### `GET /api/v0/sessions/{session_id}/adjudications`

Returns the session's sanitized online LLM Gate audit records, including mode,
verdict, confidence, proposed action, final action, model, and latency.

The Console uses these session subresources for timeline drilldown, evidence
drilldown, policy history, and capability/rule/action filters.

### `GET /api/v0/approvals`

Returns the cross-session approval queue.

Query parameters:

- `status` (`pending`, `approved`, `denied`, `expired`)
- `limit`
- `offset`

Example:

```bash
curl 'http://127.0.0.1:8765/api/v0/approvals?status=pending'
```

### `GET /api/v0/approvals/{approval_id}`

Returns one approval request plus related event/finding summaries.

### `POST /api/v0/approvals/{approval_id}/resolve`

Resolves a pending approval request from the local Console or another localhost
client.

Request body:

```json
{
  "status": "approved",
  "comment": "Reviewed in Console",
  "resolved_by": "console"
}
```

Allowed `status` values:

- `approved`
- `denied`

### `GET /api/v0/llm/config`

Returns the effective and saved OpenAI-compatible provider configuration. API
keys are never returned; the response contains only configured state and a mask.

### `PUT /api/v0/llm/config`

Validates and saves provider configuration to `.zeroadr/llm-config.json`. An
empty or omitted `api_key` retains the saved key; `clear_api_key: true` removes
it. The file is written atomically with `0600` permissions.

### `POST /api/v0/llm/config/test`

Sends a minimal JSON-mode Chat Completions request and returns connection status,
latency, model, and provider request ID without returning model content.

All LLM configuration routes are disabled when the API server is bound to a
non-loopback host, including when `--allow-insecure-non-loopback` is used.

Already-resolved requests return HTTP `409` with
`approval_already_resolved`.

See [`console-approvals.md`](console-approvals.md) for the end-to-end approval
loop and `zeroadr hook wait-approval` resume protocol.

## Error Envelope

Errors use a stable envelope:

```json
{
  "ok": false,
  "error": {
    "code": "session_not_found",
    "message": "Session not found: sess_missing"
  }
}
```

## Current Limitations

- Localhost-oriented API and local Console only.
- No authentication, CORS policy, or remote deployment mode.
- Approval resolution and loopback-only LLM settings are the only write operations.
- No WebSocket or streaming API.
- SQLite access is synchronous and local.
