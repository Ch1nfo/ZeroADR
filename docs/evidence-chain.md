# Evidence Chain

ZeroADR can export focused evidence for a single finding from a reconstructed
session. This is the v0.3 basis for future alert detail views and report export.

## From JSONL Trace

```bash
zeroadr session evidence \
  --trace examples/traces/09_injection_to_sensitive_file_chain.jsonl \
  --rule-id injection-to-action-chain
```

## Selectors

Use one selector:

- `--finding-id <finding_id>`
- `--rule-id <rule_id>`

If no selector is provided, ZeroADR selects the highest severity finding in the
session.

## Output

The command prints pretty JSON with:

- `session_id`
- `finding`
- `events`
- `timeline`
- `related_decisions`
- `risk_summary`
