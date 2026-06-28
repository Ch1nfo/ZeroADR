# Migrating To ZeroADR 1.0

## AgentDojo evaluation

AgentDojo is no longer part of the production `zeroadr` distribution. Install
the independent companion package and use its CLI:

| Before 1.0 | 1.0 companion |
| --- | --- |
| `zeroadr benchmark agentdojo` | `zeroadr-agentdojo agent` |
| `zeroadr benchmark agentdojo-detector` | `zeroadr-agentdojo detector` |
| `zeroadr benchmark agentdojo-hybrid` | `zeroadr-agentdojo hybrid` |

The old commands have no compatibility shim because the boundary is changing
before the stable 1.0 API contract.

Existing private artifacts are not moved. Reuse them explicitly:

```bash
zeroadr-agentdojo hybrid \
  --corpus-cache .zeroadr/agentdojo-workspace-tool-knowledge-v122-corpus.jsonl \
  --cache .zeroadr/agentdojo-hybrid-cache-v02.jsonl
```

New artifacts default to `.zeroadr/evaluations/agentdojo/`.

## Stable runtime boundary

The core runtime retains RuntimeEvent, detection, redaction, policy, LLM tool
result review, gateway, hook, Endpoint, storage, reconstruction, and API
contracts. No security decision semantics change during this migration.
