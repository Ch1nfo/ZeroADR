# Generic Hooks

ZeroADR v0.2 introduces a client-agnostic hook contract. It lets local agent
clients ask ZeroADR for a policy decision before running a tool and submit tool
results after execution.

## Command

```bash
zeroadr hook decide \
  --client generic \
  --policy policies/default.yaml \
  --trace .zeroadr/traces/hooks.jsonl \
  --db .zeroadr/zeroadr.sqlite
```

The command reads one JSON object from stdin and prints one JSON object to
stdout. It does not print logs to stdout.

Supported `--client` values:

- `generic`: expects the ZeroADR hook schema below.
- `claude-code`: accepts Claude Code-style hook payloads and maps them into the
  ZeroADR hook schema before policy evaluation.
- `codex`: accepts ZeroADR's Codex bridge payload format and maps it into the
  ZeroADR hook schema before policy evaluation.

## Input

```json
{
  "hook_event_type": "pre_tool_use",
  "session_id": "sess_demo",
  "request_id": 1,
  "tool_name": "read_file",
  "arguments": {
    "path": "README.md"
  },
  "raw": {}
}
```

Supported `hook_event_type` values:

- `pre_tool_use`: mapped to `tool.call.requested`; suitable for inline control.
- `post_tool_use`: mapped to `tool.call.completed` or `tool.call.failed`;
  suitable for result inspection and evidence capture.

For `post_tool_use`, include `result` for successful tools or `error` for failed
tools.

## Claude Code Input Adapter

With `--client claude-code`, ZeroADR accepts payloads with these fields:

```json
{
  "hook_event_name": "PreToolUse",
  "session_id": "sess_demo",
  "tool_name": "Read",
  "tool_input": {
    "file_path": ".env"
  }
}
```

Mapping rules:

- `hook_event_name: PreToolUse` -> `pre_tool_use`
- `hook_event_name: PostToolUse` -> `post_tool_use`
- `tool_input` -> `arguments`
- `tool_input.file_path` -> `arguments.path`
- `tool_response` -> `result`, unless it contains an `error` object
- original payload -> `raw`

The output remains the ZeroADR decision JSON shown below.

## Codex Input Adapter

With `--client codex`, ZeroADR accepts this bridge payload:

```json
{
  "event": "pre_tool_use",
  "session_id": "sess_demo",
  "call_id": "call_1",
  "tool": {
    "name": "read_file",
    "arguments": {
      "path": ".env"
    }
  }
}
```

Mapping rules:

- `event: pre_tool_use` -> `pre_tool_use`
- `event: post_tool_use` -> `post_tool_use`
- `call_id` -> `request_id`
- `tool.name` -> `tool_name`
- `tool.arguments` -> `arguments`
- `result` -> `result`
- `error` -> `error`
- original payload -> `raw`

## Output

```json
{
  "action": "allow",
  "policy_id": null,
  "reason": "No findings matched.",
  "finding_ids": [],
  "event_id": "01J...",
  "decision_id": "01J...",
  "approval_id": null
}
```

When the policy action is `require_approval`, ZeroADR also creates a pending
`ApprovalRequest` in SQLite and returns a non-null `approval_id`.

Actions currently match the policy engine:

- `allow`
- `alert`
- `block`
- `require_approval`

`require_approval` is intended for hook-based clients that can pause before
tool execution and ask a human to approve or deny the operation. ZeroADR v0.7
adds a Console approval inbox and a minimal resume command:

```bash
zeroadr hook wait-approval \
  --approval-id <approval_id> \
  --db .zeroadr/zeroadr.sqlite \
  --timeout 300 \
  --poll-interval 1
```

Recommended client flow:

```text
decision = hook decide ...
if decision.action == require_approval:
    outcome = hook wait-approval --approval-id decision.approval_id
    if outcome.effective_action == "block":
        abort tool call
    else:
        proceed
```

See [`console-approvals.md`](console-approvals.md) for the Console workflow and
API routes.

### Decide And Wait

```bash
zeroadr hook decide-and-wait --client generic --policy policies/approval.yaml \
  --db .zeroadr/zeroadr.sqlite \
  < examples/hooks/generic_env_approval.json
```

When the policy action is `require_approval`, the command waits for human resolution
and prints a combined JSON payload with a `wait` object.

## Behavior

ZeroADR converts hook input into `RuntimeEvent` with `source_type: hook`, maps
tool names and arguments into capabilities, runs deterministic detectors, applies
policy, and writes both the runtime event and `policy.evaluated` event to JSONL
and SQLite when configured.

Detection and policy evaluation use the original hook payload. Before ZeroADR
writes events to JSONL or SQLite, it redacts sensitive fields in `arguments`,
`result`, `error`, and `raw`.

Default redaction covers recursive keys containing:

- `token`
- `api_key`
- `password`
- `secret`
- `authorization`
- `credential`
- `private_key`

Private key blocks and `.env`-style sensitive assignments are also redacted from
string content before persistence.
