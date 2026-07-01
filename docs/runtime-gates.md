# Multi-stage Runtime Gates

ZeroADR 1.2 adds four opt-in stages around the existing MCP Tool Result Gate:
Agent input, tool metadata, tool request, and an online session guard. If a
section is absent from policy, that stage is disabled and v1.1 behavior is
preserved.

```yaml
agent_input_gate:
  mode: shadow
  review: rules
  min_confidence: 0.85
  true_positive_action: block
  false_positive_action: allow

tool_metadata_gate:
  mode: shadow
  review: rules
  min_confidence: 0.85
  true_positive_action: block
  false_positive_action: allow

tool_request_gate:
  mode: shadow
  review: rules
  min_confidence: 0.85
  true_positive_action: block
  false_positive_action: allow

session_guard:
  mode: shadow
  compromised_action: require_approval
```

Use `policies/runtime-gates-shadow.yaml` first. After inspecting gate metrics,
provider failures, false positives, and approval load, explicitly switch the
required stages to `enforce`.

Agent input requires a Generic `agent_input` hook or Claude Code
`UserPromptSubmit`. An MCP-only gateway cannot see the initial user prompt.
Metadata enforcement filters only blocked entries from `tools/list`; allowed
schemas are returned byte-for-byte at the object level. Request review is
risk-triggered. Session state is bounded to 256 summaries, expires after one
hour idle, and is removed on session shutdown.

Critical deterministic findings cannot be downgraded by a reviewer. Low
confidence, invalid output, unknown evidence references, timeouts, and provider
failures map to approval in enforce mode. ASB evaluation treats approval as a
block; production integrations retain human approval behavior.

The runtime-gate APIs are:

- `GET /api/v0/runtime-gates/metrics`
- `GET /api/v0/sessions/{session_id}/runtime-gates`

Only structured redacted records are persisted. Raw prompts, raw tool results,
provider bodies, API keys, and Authorization headers are excluded.
