# Policy

ZeroADR separates detection from response.

Detectors produce `Finding` records that describe what happened, how severe it
is, and which event ids support the conclusion. The policy engine decides what
to do with those findings.

## Actions

- `allow`: no matching finding or policy requires action.
- `alert`: finding exists but the request is allowed to continue.
- `block`: request is not forwarded to the MCP server.
- `require_approval`: hook clients should pause and ask a human before
  continuing.

## YAML Format

```yaml
mode: audit
policies:
  - id: block-private-keys
    match:
      rule_id: sensitive-file-access
      severity: critical
      capability: filesystem.read
    action: block
```

## Match Fields

Policies can match:

- `capability`
- `event_type`
- `tool_name`
- `server_name`
- `severity`
- `rule_id`
- `target`
- `target_contains`

## MCP Blocking

When policy returns `block`, ZeroADR returns a valid JSON-RPC error:

```json
{
  "jsonrpc": "2.0",
  "id": 12,
  "error": {
    "code": -32001,
    "message": "Blocked by ZeroADR policy",
    "data": {
      "policy_id": "block-private-keys",
      "reason": "Tool call requested access to sensitive path ~/.ssh/id_rsa."
    }
  }
}
```

`require_approval` is recorded and returned by hook decisions. The v0.1 MCP
stdio proxy does not implement an interactive approval flow.
