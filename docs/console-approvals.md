# Console Approvals

ZeroADR v0.7 adds a localhost human approval loop on top of the existing
`require_approval` policy action and v0.5 Console.

## What v0.7 Adds

- `ApprovalRequest` queue persisted in SQLite
- Console **Pending Approvals** panel with Approve / Deny actions
- Read/write localhost API routes under `/api/v0/approvals`
- `zeroadr hook wait-approval` for hook clients to resume after human action

## Boundaries

This is a **local development baseline**, not an enterprise approval platform.

- localhost only
- no authentication
- no WebSocket push
- no MCP `proxy` pause on `require_approval`
- original `PolicyDecision` rows remain immutable audit records

## Recommended Flow

```text
hook client
  -> zeroadr hook decide
  -> if action == require_approval:
       zeroadr hook wait-approval --approval-id <id>
       if effective_action == block: abort tool
       else: proceed
human operator
  -> open http://127.0.0.1:8765/console
  -> approve or deny pending request
```

## Demo

Terminal 1:

```bash
zeroadr api demo
```

The demo database includes one pending approval and one already-resolved approval.

Terminal 2:

```bash
zeroadr hook decide --client generic --policy policies/approval.yaml \
  --db .zeroadr/console-demo.sqlite \
  < examples/hooks/generic_env_approval.json
```

Copy the returned `approval_id`, approve it in Console, then:

```bash
zeroadr hook wait-approval \
  --approval-id <approval_id> \
  --db .zeroadr/console-demo.sqlite \
  --timeout 60 \
  --poll-interval 1
```

Approved requests return:

```json
{
  "status": "approved",
  "effective_action": "allow"
}
```

Denied requests return:

```json
{
  "status": "denied",
  "effective_action": "block"
}
```

## API

See [`console-api.md`](console-api.md) for route details.

- `GET /api/v0/approvals?status=pending`
- `GET /api/v0/approvals/{approval_id}`
- `POST /api/v0/approvals/{approval_id}/resolve`

## Hook Output Changes

`zeroadr hook decide` now returns:

```json
{
  "action": "require_approval",
  "policy_id": "approve-env-read",
  "reason": "...",
  "finding_ids": ["..."],
  "event_id": "...",
  "decision_id": "...",
  "approval_id": "..."
}
```

Only `require_approval` responses include `approval_id`.

## v0.7.1 Polish

- stale pending approvals are marked `expired` during API reads and wait polling
- approval resolve writes `approval.resolved` audit events to SQLite and optional JSONL trace
- MCP `proxy` pauses on `require_approval` until approval, deny, or timeout
- `zeroadr hook decide-and-wait` combines decide + wait in one stdout payload
- Console timeline links `require_approval` events to the approvals inbox

### MCP Proxy Approval Pause

```bash
zeroadr proxy \
  --policy policies/approval.yaml \
  --trace .zeroadr/traces/proxy.jsonl \
  --db .zeroadr/zeroadr.sqlite \
  --approval-timeout 300 \
  --approval-poll-interval 0.5 \
  -- \
  your-mcp-server-command
```

When policy returns `require_approval`, the proxy waits for Console/API approval before
forwarding the tool call. Denied or expired approvals return JSON-RPC errors instead of
calling the MCP server.

### Decide And Wait

```bash
zeroadr hook decide-and-wait --client generic --policy policies/approval.yaml \
  --db .zeroadr/zeroadr.sqlite \
  < examples/hooks/generic_env_approval.json
```

When approval is required, stdout includes both the initial decision and a `wait`
object with the final `effective_action`.

## Related Docs

- [`hooks.md`](hooks.md)
- [`console-api.md`](console-api.md)
- [`policy.md`](policy.md)
