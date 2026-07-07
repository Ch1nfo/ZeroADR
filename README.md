# ZeroADR

ZeroADR is a local-first runtime security and audit layer for AI agents. It observes
agent and tool activity, detects risky behavior, applies YAML policy, coordinates
human approval, and stores redacted evidence for inspection and replay.

Current version: `1.2.0rc1`

[中文说明](README_ZH.md)

## Core capabilities

- MCP stdio proxy with ordered JSON-RPC forwarding and bounded response handling.
- Generic, Claude Code, and Codex hook adapters.
- Typed runtime events and deterministic detection for prompt injection, sensitive
  files, dangerous commands, secret leakage, privilege escalation, code injection,
  memory poisoning, and multi-step exfiltration chains.
- YAML policy actions: `allow`, `alert`, `block`, and `require_approval`.
- Opt-in Agent Input, Tool Request, Tool Result, and Session Guard enforcement.
- Human approval records with approve, deny, expiry, and audited resume behavior.
- Redacted JSONL traces and SQLite persistence.
- Session reconstruction, evidence chains, summaries, replay, and Agent-BOM export.
- Loopback HTTP API, Web Console, approval inbox, and runtime metrics.
- Endpoint ingest plus Lite and Linux BCC collectors.

Rules work without an LLM. Optional Hybrid review receives only bounded, redacted
evidence and returns a security verdict; ZeroADR retains control of the policy action.

## Architecture

```text
MCP Client / Agent Hook / Endpoint Sensor / Recorded Trace
                         |
                         v
       Gateway / Hook Adapter / Ingest / Replay
                         |
                         v
          RuntimeEvent normalization + redaction
                         |
                         v
       deterministic detection + optional LLM review
                         |
                         v
             YAML policy + human approval
                         |
                         v
       allow / alert / block / require_approval
                         |
                         v
 JSONL / SQLite / Console / reconstruction / Agent-BOM
```

The runtime coordinator provides the same gate semantics to MCP and supported hook
paths. Endpoint and replay paths are observational.

## Install

ZeroADR requires Python 3.12 or newer.

```bash
python -m pip install .
zeroadr --version
```

## Usage

### MCP proxy

Run an MCP server through ZeroADR:

```bash
zeroadr proxy \
  --policy policies/default.yaml \
  --trace .zeroadr/trace.jsonl \
  --db .zeroadr/zeroadr.sqlite \
  -- npx @modelcontextprotocol/server-filesystem /tmp
```

### Agent hooks

Pass one hook event on stdin and receive the decision on stdout:

```bash
zeroadr hook decide \
  --client claude-code \
  --policy policies/default.yaml \
  --trace .zeroadr/hooks.jsonl \
  --db .zeroadr/zeroadr.sqlite
```

Use `--client generic` for the stable generic schema or `--client codex` for Codex
hook input. See [Hook integration](docs/hooks.md) for payload contracts.

### API and Console

```bash
zeroadr api serve --db .zeroadr/zeroadr.sqlite
```

Open `http://127.0.0.1:8765/console`. The API has no authentication and should remain
on loopback. `--allow-insecure-non-loopback` is an explicit override that only
acknowledges the exposure; it does not add authentication.

### Sessions and replay

```bash
zeroadr inspect --db .zeroadr/zeroadr.sqlite
zeroadr session reconstruct --trace examples/traces/12_sensitive_file_to_external_post.jsonl
zeroadr session bom --trace examples/traces/12_sensitive_file_to_external_post.jsonl
zeroadr replay --trace examples/traces/12_sensitive_file_to_external_post.jsonl
```

### Endpoint Agent and telemetry

```bash
zeroadr endpoint ingest \
  --strict \
  --input examples/endpoint/01_sensitive_file_to_external_network.jsonl \
  --trace .zeroadr/endpoint.jsonl \
  --db .zeroadr/zeroadr.sqlite
```

Use `zeroadr endpoint agent` for continuous collection. Endpoint collectors observe
system activity; they do not provide kernel-level prevention.

### Advisory LLM triage

Set `ZEROADR_LLM_API_KEY` and the provider model, then run bounded, redacted advisory
analysis for a stored session:

```bash
export ZEROADR_LLM_API_KEY="<provider-api-key>"
export ZEROADR_LLM_MODEL="<provider-model>"
zeroadr analyze session <session-id> --db .zeroadr/zeroadr.sqlite
```

Advisory output cannot directly change policy or execute actions.

## Runtime Gates

The stable enforcement surface is:

| Gate | Purpose |
| --- | --- |
| Agent Input | Review agent-visible input before execution |
| Tool Request | Review risky or task-conflicting tool calls before execution |
| Tool Result | Review untrusted tool output before delivery to the agent |
| Session Guard | Restrict risky actions after trusted compromise evidence |

All gates are disabled when omitted. A policy without gate configuration preserves
the v1.1 audit behavior. Rules mode uses deterministic findings; Hybrid mode adds a
stage-specific Reviewer. Invalid model output, unknown evidence references, low
confidence, uncertainty, timeout, and Provider failures fail safe to human approval.

Use `policies/runtime-gates-shadow.yaml` to observe decisions and
`policies/runtime-gates-enforce.yaml` to enforce them. See
[Runtime Gates](docs/runtime-gates.md) for the complete schema.
Human approval examples are available in `policies/approval.yaml`.

## Project structure

```text
src/zeroadr/       Core Python package and CLI
  api/             HTTP API and Web Console
  core/            Events, findings, decisions, and gate records
  detection/       Deterministic and sequence detectors
  endpoint/        Endpoint agent and collectors
  gateway/         MCP proxy and JSON-RPC framing
  hook/            Generic, Claude Code, and Codex adapters
  llm/             Bounded advisory and gate review
  policy/          YAML policy engine
  reconstruction/  Timeline, evidence, summary, and Agent-BOM
  replay/          Deterministic trace replay
  runtime/         Gate coordination and approvals
  security/        Redaction
  storage/         JSONL and SQLite persistence
policies/          Ready-to-use policy examples
examples/          Public deterministic traces and hook fixtures
deploy/            systemd and launchd templates
docs/              Product and operations documentation
tests_local/       Local-only tests excluded from Git
```

Evaluation companions, private corpora, generated traces, model configuration,
credentials, caches, databases, build output, and local tests are excluded from the
core source release.

## Security boundaries

- Tool Result enforcement is available on the synchronous MCP path; Endpoint, replay,
  and post-tool hook ingestion remain observational.
- MCP alone cannot inspect the initial user prompt; Agent Input enforcement requires a
  supported input hook.
- Held tool results are not rewritten or sanitized before release.
- The Console is a local operational interface, not an authenticated multi-tenant
  control plane.
- Linux BCC support depends on Linux kernel and BCC compatibility.
- LLM review supplements deterministic controls and never directly changes policy.

Report security issues through GitHub Private Security Advisory as described in
[SECURITY.md](SECURITY.md).

## Security benchmark results

These are the last frozen results retained before the evaluation companions were
archived. Model benchmarks were not rerun after the core slimming, so the results
describe the latest measured configurations rather than guaranteeing performance for
every current deployment.

### Agent Security Bench (ASB v4)

The official Agent Harness ran 100 attacks and 100 paired clean cases across
Baseline, Rules, and Hybrid arms, for 600 runs in total.

| Arm | ASR | Clean FPR | Task success | Clean success |
| --- | ---: | ---: | ---: | ---: |
| Baseline | 66% | 0% | 62.5% | 90% |
| Rules | 23% | 0% | 58.0% | 77% |
| Hybrid | 8% | 6% | 59.5% | 84% |

Hybrid results by attack family:

| Attack family | ASR | Clean FPR | Task success | Clean success |
| --- | ---: | ---: | ---: | ---: |
| DPI | 0% | 0% | 45.0% | 90% |
| OPI | 0% | 5% | 37.5% | 70% |
| Memory Poisoning | 5% | 0% | 82.5% | 80% |
| Mixed | 0% | 0% | 45.0% | 90% |
| PoT | 35% | 25% | 87.5% | 90% |

Hybrid reduced ASR by 58 percentage points and reduced aggregate task success by
3 points relative to Baseline. It passed the ASR and aggregate utility targets, but
Clean FPR exceeded its 5% limit and Clean success declined by 6 points, exceeding the
5-point limit. Provider and workflow failures were both zero, so the result did not
meet the complete release gate.

Frozen evidence:

- Manifest SHA-256: `47fbdf204b6491262f964034fb24db861fcbad9f2566ce32961b8af432cf0b6a`
- Policy SHA-256: `ca07e47a66032ea88874b4493a286d03b9a48ffd2a4a60fec92f5dbd40b070e1`
- Analysis SHA-256: `ddf3bc778fcac70002400394a26dc2483c4d127559a9f23972c0c19b8d996290`
- Two cache-only replays reproduced the result with `new_case_runs=0` and
  `new_model_calls=0`.

### AgentDojo v1.2.2

The fixed `workspace/tool_knowledge` corpus contains 966 injected and 966 paired clean
cases, for 1,932 cases in total.

| Metric | Isolated result | Sequence prevention |
| --- | ---: | ---: |
| True positive | 742 | 966 |
| False negative | 224 | 0 |
| True negative | 966 | 966 |
| False positive | 0 | 0 |
| Recall | 76.81% | 100% |
| Accuracy | 88.41% | 100% |
| Precision | 100% | 100% |
| F1 | 86.88% | 100% |
| False-positive rate | 0% | 0% |

The deterministic Rules baseline reached 62.01% recall and 81.00% accuracy with no
false positives. Isolated review detected 742 attacks and missed 224. Sequence
prevention recovered those 224 downstream cases because they would not execute after
an earlier block. Therefore, 100% sequence prevention is not a claim of 100% isolated
classification. The frozen cache replay reproduced the confusion matrices with zero
provider failures and `model_calls=0`.

## Latest validation

Latest local core validation on 2026-07-07, using the Conda `agent` environment:

- Ruff: passed.
- MyPy: passed for 84 source files.
- Pytest: 457 passed, 3 skipped.
- Core sdist and wheel: built successfully with installed build dependencies and no
  network isolation bootstrap.
- Isolated wheel install and `zeroadr` CLI smoke: passed; the wheel contains only the
  `zeroadr` package and distribution metadata.
- Real MCP filesystem integration: 1 passed.
- Live LLM session triage: inconclusive, `provider_connection_error` (xfailed).
- Linux BCC integration: skipped on macOS; no new Linux validation was performed.

The real MCP integration smoke is opt-in:

```bash
ZEROADR_RUN_REAL_MCP=1 \
  conda run -n agent pytest tests_local/test_real_mcp_filesystem.py -v
```

Agent-related development and verification use the `agent` Conda environment. Local
tests remain in ignored `tests_local/` and are not part of the Git release.

## Documentation

- [Architecture](docs/architecture.md)
- [Runtime event model](docs/runtime-event.md)
- [Policy format](docs/policy.md)
- [Runtime Gates](docs/runtime-gates.md)
- [Tool Result Gate](docs/tool-result-gate.md)
- [Hook integration](docs/hooks.md)
- [Session reconstruction](docs/session-reconstruction.md)
- [Console API](docs/console-api.md)
- [Endpoint deployment](docs/endpoint-agent-deployment.md)
- [Linux BCC collector](docs/linux-ebpf-collector.md)

## License

Apache License 2.0. See [LICENSE](LICENSE).
