# MCP Tool Result Gate Operations

ZeroADR 1.1 can hold a successful MCP `tools/call` response before it reaches
the Agent. The gate is disabled when `tool_result_gate` is absent from the
selected policy file.

## Rollout

1. Start with `policies/tool-result-gate-shadow.yaml`. Shadow mode never changes
   the response on the wire.
2. Change `review` to `hybrid` and monitor provider failures, confidence,
   latency, approvals, and evidence truncation.
3. Freeze the confidence threshold, then use
   `policies/tool-result-gate-enforce.yaml`.

`rules` uses deterministic findings and the normal policy engine. `hybrid`
reviews every successful, non-critical result with `tool-result-review-v0.2`.
Critical deterministic findings cannot be downgraded by the model. Low
confidence, uncertainty, timeouts, provider errors, and invalid output require
human approval (`require_approval`) in enforce mode.

## Wire behavior

- `allow`, `alert`, and approval success return the original MCP frame.
- policy block returns JSON-RPC error `-32001`;
- approval denial returns `-32002`;
- approval expiry returns `-32003`;
- response-buffer overflow returns `-32004` in enforce mode.

Responses retain request order. A held response therefore delays later
responses. Approving a Tool Result request exposes the original untrusted
result to the Agent.

## Data handling

The original response exists only in process memory while the gate decides.
SQLite, traces, approvals, API responses, and model payloads receive redacted,
bounded evidence. Result-review payloads are limited to 16 KiB and long strings
use deterministic head, middle, and tail windows.

## API

- `GET /api/v0/tool-result-gate/metrics`
- `GET /api/v0/sessions/{session_id}/tool-result-gates`

The Web Console displays result-stage approvals and warns before approval.

## Scope

The production gate applies only to MCP `tool.call.completed`. Hook post-tool,
Endpoint, and Replay remain observational.
