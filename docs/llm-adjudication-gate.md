# Hybrid LLM Adjudication Gate

ZeroADR can run a bounded LLM adjudication after deterministic rules match and
before the final policy decision. The Gate is opt-in per policy and supports MCP
`tools/call` and Hook `pre_tool_use` only.

## Safety Model

- The model returns a verdict, confidence, reason, and evidence references. It
  never returns an allow or block action.
- Policy maps the structured verdict to an action.
- Critical findings bypass the Gate and retain their original deterministic
  policy action.
- In enforce mode, timeout, provider failure, invalid output, unknown evidence
  references, uncertain verdicts, and confidence below the threshold all become
  `require_approval`.
- Shadow mode records the proposed action but preserves the original policy
  action, including when the provider fails.
- Endpoint and post-tool events are not inline enforcement points.
- Gate v0.2 evaluates whether a deterministic finding is a true security event;
  a sensitive target or policy match alone is not treated as proof.
- Authorization and task context use typed internal RuntimeEvent metadata. MCP
  and tool arguments cannot claim trusted authorization context.

## Policy

```yaml
policies:
  - id: llm-review-env
    match:
      rule_id: sensitive-file-access
      severity: high
    action: alert
    llm_adjudication:
      mode: enforce
      min_confidence: 0.85
      true_positive_action: block
      false_positive_action: allow
```

Start with [`llm-gate-shadow.yaml`](../policies/llm-gate-shadow.yaml), review
recorded adjudications, and then opt into
[`llm-gate-enforce.yaml`](../policies/llm-gate-enforce.yaml).

## Runtime

```bash
zeroadr proxy \
  --policy policies/llm-gate-shadow.yaml \
  --llm-config .zeroadr/llm-config.json \
  -- <mcp-server-command>
```

```bash
cat hook.json | zeroadr hook decide \
  --policy policies/llm-gate-enforce.yaml \
  --llm-config .zeroadr/llm-config.json
```

Gate defaults are an 8-second single request and 256 output tokens. Configure a
fast `gate_model` in the Console LLM settings. If it is empty, the full triage
model is reused. The inline provider does not retry, keeping the deadline
bounded.

Adjudications are stored separately from full session analyses in SQLite. API
keys, complete prompts, provider response bodies, and unredacted payloads are
never persisted.

Before enabling enforce mode, collect shadow traffic and evaluate independently
reviewed labels with `zeroadr gate metrics` and `zeroadr gate evaluate`. See
[`llm-gate-calibration.md`](llm-gate-calibration.md).
