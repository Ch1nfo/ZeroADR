# Session Reconstruction

ZeroADR v0.3 starts with a JSONL client adapter and session reconstruction
service. It rebuilds a session context from either RuntimeEvent JSONL traces or
SQLite persistence.

## JSONL Trace Input

```bash
zeroadr session reconstruct \
  --trace examples/traces/09_injection_to_sensitive_file_chain.jsonl
```

This path reads RuntimeEvent JSONL and re-runs replay detection and policy. It
is the baseline JSONL client adapter for future client log import.

## SQLite Input

```bash
zeroadr session reconstruct sess_example \
  --db .zeroadr/zeroadr.sqlite
```

This path reads stored events, findings, and policy decisions for the session.
It does not re-run detectors.

## Compact Summary

```bash
zeroadr session summary \
  --trace examples/traces/12_sensitive_file_to_external_post.jsonl
```

```bash
zeroadr session summary sess_example \
  --db .zeroadr/zeroadr.sqlite
```

The summary command consumes reconstructed context and prints a compact JSON
inventory for Console, Agent-BOM, and report views. It includes:

- `source_types`
- `clients`
- `workspaces`
- `prompts_present`
- `servers`
- `tools`
- `capabilities`
- `targets`
- `sensitive_targets`
- `external_targets`
- `finding_rules`
- `risk_summary`

It does not include raw event arguments or raw payloads.

## Agent-BOM Export

```bash
zeroadr session bom \
  --trace examples/traces/12_sensitive_file_to_external_post.jsonl
```

```bash
zeroadr session bom sess_example \
  --db .zeroadr/zeroadr.sqlite
```

Agent-BOM v0.1 is a machine-readable session artifact for audit and reporting
workflows. It includes:

- `bom_version`
- `session_id`
- `generated_from`
- `inventory`
- `tool_calls`
- `risk.summary`
- `risk.findings`
- `risk.decisions`

The BOM preserves finding-to-event and decision-to-finding relationships, but
does not include raw event payloads.

## Output

The reconstruct command prints pretty JSON with:

- `session_id`
- `events`
- `findings`
- `policy_decisions`
- `timeline`
- `risk_summary`
- `context_metadata`

Timeline entries group `tool.call.requested`, terminal tool events, policy
events, findings, and decisions by `request_id`.

`context_metadata` is a redacted, allowlisted view of client, workspace, and
prompt metadata. Prompt text and raw secrets are not included.
