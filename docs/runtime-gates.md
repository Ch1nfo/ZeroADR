# Runtime Security Gates

ZeroADR supports three opt-in runtime review points plus an online Session Guard:

- `agent_input_gate`: inspect agent-visible input before execution.
- `tool_request_gate`: inspect risky or unknown tool requests before execution.
- `tool_result_gate`: inspect tool output before delivery to the agent.
- `session_guard`: restrict risky actions after trusted injection evidence.

All gates are disabled when absent. A policy with no gate configuration retains the
v1.1 audit behavior.

```yaml
agent_input_gate:
  mode: enforce
  review: hybrid
  min_confidence: 0.85
  true_positive_action: block
  false_positive_action: allow

tool_request_gate:
  mode: enforce
  review: hybrid
  min_confidence: 0.85
  true_positive_action: block
  false_positive_action: allow

tool_result_gate:
  mode: enforce
  review: hybrid
  min_confidence: 0.85
  true_positive_action: block
  false_positive_action: allow

session_guard:
  mode: enforce
  compromised_action: require_approval
```

`rules` uses deterministic findings only. `hybrid` uses the same findings plus the
configured Reviewer. Invalid output, unknown evidence references after one correction
retry, Provider errors, low confidence, and uncertain verdicts fail safe to approval.

Input and Request share a bounded, redacted Stage Reviewer. Tool Result uses its own
bounded Reviewer and cache. Audit records contain hashes, safe error codes, verdicts,
confidence, actions, latency, and execution/delivery state; raw secrets are not stored.

`tool_metadata_gate` is no longer supported. Policies containing it are rejected with
an explicit configuration error.
