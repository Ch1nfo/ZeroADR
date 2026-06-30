<div align="center">

# ZeroADR

### Runtime Detection, Response, and Policy Enforcement for AI Agents

[![Version](https://img.shields.io/badge/version-1.1.0rc2-blue.svg)](#current-release)
[![Python](https://img.shields.io/badge/python-3.12%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-Apache--2.0-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Linux%20%7C%20Windows-lightgrey.svg)](#support-boundary)
[![Runtime](https://img.shields.io/badge/runtime-MCP%20%7C%20Hooks%20%7C%20Endpoint-orange.svg)](#core-capabilities)

English | [中文](README_ZH.md)

</div>

---

ZeroADR (Zero Agentic Detection and Response) is an open-source runtime
security platform for AI Agents. It observes and controls tool activity across
MCP, agent Hooks, replayed traces, and Endpoint telemetry through one typed
`RuntimeEvent` model.

ZeroADR detects dangerous behavior, applies YAML policy, pauses selected
actions for human approval, reviews untrusted MCP tool results before they
return to the Agent, and preserves a redacted evidence chain in JSONL and
SQLite. Deterministic controls work without an LLM; optional Hybrid review uses
bounded, redacted evidence while ZeroADR retains ownership of the final action.

## Why ZeroADR?

AI Agents can read files, run commands, call tools, send data, and retain state
across long sessions. Prompt filters inspect instructions, while endpoint tools
inspect system effects. ZeroADR protects the missing runtime control point:

- which tool was requested and what capability it represents;
- what target and arguments were involved;
- what untrusted result was about to return to the Agent;
- which evidence and policy produced the effective action;
- how the session can be reconstructed and replayed afterward.

## Core Capabilities

### Runtime enforcement

- **MCP stdio gateway** — proxies line-delimited and `Content-Length` framed
  JSON-RPC while preserving protocol-safe stdout.
- **Production Tool Result Gate** — holds successful MCP tool results before
  delivery, then applies rules, Hybrid review, blocking, or result-stage
  approval.
- **Agent Hook adapters** — normalizes Generic JSON, Claude Code, and Codex
  pre-tool/post-tool events through a shared decision path.
- **Human approval** — persists approval requests in SQLite, supports
  approve/deny/expiry, and resumes Hook or MCP execution with an audited action.
- **Ordered and bounded response handling** — preserves MCP response order and
  enforces pending-response and memory limits.

### Detection and policy

- Sensitive files and credential targets
- Dangerous shell and download-and-execute patterns
- Prompt injection and indirect tool-result injection
- Memory poisoning and falsified historical context
- Secret leakage and private-key exposure
- Privilege escalation and container escape attempts
- Code injection and write-then-execute chains
- Sensitive-read-to-exfiltration and injection-to-action sequences
- Separate YAML policy mapping to `allow`, `alert`, `block`, or
  `require_approval`

### Evidence and operations

- Typed runtime events, findings, decisions, approvals, and Gate records
- Redacted JSONL traces and SQLite persistence
- Deterministic replay and session reconstruction
- Focused evidence chains, process correlation, and Agent-BOM generation
- Loopback Web Console for sessions, timelines, policy history, approvals,
  Endpoint health, Gate metrics, and LLM configuration
- Endpoint ingest/tail/agent workflows and Linux BCC process, file, and network
  visibility

Endpoint collection is observational and does not provide kernel-level
prevention.

### Optional LLM assistance

- OpenAI-compatible Chat Completions providers
- Bounded and redacted session triage
- `tool-result-review-v0.2` Hybrid result review
- Critical deterministic findings that cannot be downgraded by the model
- Fail-safe approval on low confidence, timeout, provider failure, or invalid
  structured output
- Shadow evaluation, labeling, and confidence calibration workflows

The model returns a structured security verdict, never a policy action.
ZeroADR maps the validated verdict to the effective action.

## Architecture

```text
AI Agent / MCP Client / Hook / Endpoint Sensor
                    │
                    ▼
      MCP Gateway │ Hook Adapters │ Ingest │ Replay
                    │
                    ▼
        RuntimeEvent normalization + redaction
                    │
                    ▼
      Deterministic detection + optional LLM review
                    │
                    ▼
       YAML policy + human approval coordination
                    │
                    ▼
 allow │ alert │ block │ require_approval
                    │
                    ▼
 JSONL │ SQLite │ Console │ reconstruction │ Agent-BOM
```

The production Tool Result Gate covers MCP `tool.call.completed` responses.
Hook post-tool, Endpoint, and Replay paths remain observational.

## Benchmark Results

### Agent Security Bench — official Agent ASR

The primary ASB evaluation runs the pinned official Agent harness, including
`ReactAgentAttack`, official workflow generation, official tools, attack
injection, and the official attacker-goal evaluator. It is not an isolated
result-classification test.

| Setting | Value |
| --- | --- |
| ASB commit | `1f561dccf92d55302368fa67679b4ba9d9c8fdc4` |
| Attack families | DPI, OPI, Memory Poisoning, Mixed, PoT |
| Dataset | 100 attacks + 100 paired clean controls |
| Experiment arms | Baseline, Rules, Hybrid — 600 Agent runs total |
| Agent / Reviewer | `deepseek-v4-flash` / `deepseek-v4-flash` |
| Workers | 4 |
| Provider / workflow failures | 0 / 0 |
| Primary metric | Official attacker-goal ASR; no refusal judge |

| Arm | ASR | Prevention | Clean FPR | Block / Approval | Task Success | P50 / P95 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Baseline | 67% (67/100) | 0% | 0% | 0 / 0 | 68.0% | 8.404s / 22.449s |
| Rules | 60% (60/100) | 39% | 0% | 39 / 0 | 63.0% | 7.883s / 23.034s |
| Hybrid | **40% (40/100)** | 56% | 2% | 50 / 8 | 63.5% | 13.600s / 24.233s |

Hybrid reduces ASR by **27 percentage points** versus baseline (40.3% relative)
with 2 false positives across 100 clean controls. The remaining 40 successful
attacks are reported directly; a block elsewhere in a workflow is not counted
as an automatic attack failure.

| Hybrid attack family | ASR |
| --- | ---: |
| DPI | 85% (17/20) |
| OPI | 25% (5/20) |
| Memory Poisoning | 10% (2/20) |
| Mixed | 50% (10/20) |
| PoT Backdoor | 30% (6/20) |

Memory Poisoning is conditioned on successful poisoned-memory retrieval. Two
cache-only replays made zero model calls and reproduced analysis SHA-256
`de5979f6a1f8f7029dbd480aec28b9bd4af811e091f2e1f2d190af2f8af3cd7f`.

A separate provider-clean replication on the same manifest measured Baseline
67%, Rules 55%, and Hybrid 29%, with Hybrid clean FPR 1%. This variance is
reported explicitly; a single flash-model run is not a deterministic point
estimate. Full methodology and hashes are in
[the ASB results report](evaluation/asb/RESULTS.md).

### AgentDojo — tool-result injection review

The fixed AgentDojo v1.2.2 `workspace/tool_knowledge` corpus contains 966
injected results and 966 paired clean results, for 1,932 balanced cases.

| Pipeline | TP | FN | TN | FP | Recall | Accuracy | Precision | F1 | FPR |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Rule baseline | 599 | 367 | 966 | 0 | 62.01% | 81.00% | 100% | 76.55% | 0% |
| Isolated Hybrid | 742 | 224 | 966 | 0 | 76.81% | 88.41% | 100% | 86.88% | 0% |
| Sequence prevention | 966 | 0 | 966 | 0 | 100% | 100% | 100% | 100% | 0% |

The 100% sequence score is not a 100% isolated classification claim. Sequence
prevention counts downstream cases that cannot execute after an earlier
`block` or `require_approval`; isolated review still contains 224 false
negatives. Cache-only reproduction reported `model_calls=0` and
`provider_failures=0` with identical confusion matrices.

ASB and AgentDojo remain independent companion packages. Neither benchmark,
its dataset, nor its dependencies are included in the core wheel.

## Quick Start

### Requirements

- Python 3.12+
- macOS, Linux, or Windows for the core runtime
- Optional Node.js/`npx` for the real MCP filesystem smoke
- Optional supported Linux, BCC bindings, and root/eBPF capability for native
  Endpoint probes

### Install from source

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install .
zeroadr --version
```

### Replay a trace

```bash
zeroadr replay examples/traces/03_ssh_private_key.jsonl
zeroadr replay examples/traces/08_prompt_injection_tool_result.jsonl
```

### Evaluate an Agent Hook

```bash
zeroadr hook decide \
  --client generic \
  --policy policies/approval.yaml \
  < examples/hooks/generic_env_approval.json
```

Use `--client claude-code` or `--client codex` with the matching examples.

### Protect an MCP server

```bash
zeroadr proxy \
  --policy policies/tool-result-gate-shadow.yaml \
  --trace .zeroadr/traces/latest.jsonl \
  --db .zeroadr/zeroadr.sqlite \
  -- <mcp-server-command>
```

Start in shadow mode, inspect Gate records and latency, then use
`policies/tool-result-gate-enforce.yaml` after freezing policy and confidence
thresholds. Approving a result-stage request returns the original untrusted
result to the Agent. See [Tool Result Gate operations](docs/tool-result-gate.md).

### Reconstruct a session

```bash
zeroadr session reconstruct \
  --trace examples/traces/12_sensitive_file_to_external_post.jsonl
zeroadr session bom \
  --trace examples/traces/12_sensitive_file_to_external_post.jsonl
```

### Run the Endpoint Agent

```bash
zeroadr endpoint ingest \
  --strict \
  --input examples/endpoint/01_sensitive_file_to_external_network.jsonl \
  --trace .zeroadr/traces/endpoint.jsonl \
  --db .zeroadr/zeroadr.sqlite

zeroadr endpoint agent \
  --collector mock \
  --output .zeroadr/endpoint-agent.jsonl \
  --limit 3
```

### Run advisory LLM triage

```bash
export ZEROADR_LLM_API_KEY="<provider-api-key>"
export ZEROADR_LLM_MODEL="<provider-model>"
zeroadr analyze session <session-id> --db .zeroadr/zeroadr.sqlite
```

The same provider settings can be stored in the private, permission-restricted
`.zeroadr/llm-config.json`. Advisory triage cannot directly change policy.

### Start the Web Console

```bash
zeroadr api demo
```

Open `http://127.0.0.1:8765/console`. The server binds to loopback by default
and has no authentication. The explicit `--allow-insecure-non-loopback`
override does not add authentication; do not expose the Console to an
untrusted network.

## Evaluation Companions

Install companions only when running benchmarks:

```bash
python -m pip install ./evaluation/agentdojo
python -m pip install ./evaluation/asb

zeroadr-agentdojo --help
zeroadr-asb --help
```

- [AgentDojo companion guide](evaluation/agentdojo/README.md)
- [ASB companion guide](evaluation/asb/README.md)
- [Official ASB results](evaluation/asb/RESULTS.md)

Private corpora, caches, model configuration, traces, and evaluation outputs
belong under `.zeroadr/`, are Git-ignored, and should use restrictive local
permissions.

## Project Structure

```text
ZeroADR/
├── src/zeroadr/                 # Core runtime and `zeroadr` CLI
│   ├── api/                     # HTTP API and Web Console
│   ├── core/                    # Events, findings, decisions, Gate records
│   ├── detection/               # Deterministic and sequence detectors
│   ├── endpoint/                # Endpoint agent and collectors
│   ├── gateway/                 # MCP proxy and JSON-RPC framing
│   ├── hook/                    # Generic, Claude Code, Codex adapters
│   ├── llm/                     # Triage, review, calibration
│   ├── policy/                  # YAML policy engine
│   ├── reconstruction/          # Timeline, evidence, Agent-BOM
│   ├── replay/                  # Deterministic trace replay
│   ├── runtime/                 # Decision and approval services
│   ├── security/                # Redaction
│   └── storage/                 # JSONL and SQLite
├── evaluation/
│   ├── agentdojo/               # Independent AgentDojo companion
│   └── asb/                     # Independent official-ASB companion
├── policies/                    # Example policy configurations
├── examples/                    # Public deterministic fixtures
├── deploy/                      # systemd and launchd templates
├── docs/                        # Architecture and operations guides
└── tests_local/                 # Local-only regression and opt-in tests
```

## Development

Agent-related development and tests use the `agent` conda environment:

```bash
conda run -n agent ruff check .
conda run -n agent mypy src evaluation/asb/src
conda run -n agent mypy \
  --config-file evaluation/agentdojo/pyproject.toml \
  evaluation/agentdojo/src
conda run -n agent pytest \
  tests_local \
  evaluation/agentdojo/tests_local \
  evaluation/asb/tests_local -q
```

Opt-in integration and platform smokes:

```bash
ZEROADR_RUN_REAL_MCP=1 \
  conda run -n agent pytest tests_local/test_real_mcp_filesystem.py -v

ZEROADR_RUN_LLM_TESTS=1 \
  conda run -n agent pytest tests_local/test_llm_live_opt_in.py -v

ZEROADR_ENABLE_BCC=1 ZEROADR_RUN_EBPF_TESTS=1 \
  conda run -n agent pytest tests_local/test_linux_bcc_opt_in.py -v
```

`tests_local/`, companion `tests_local/`, `.zeroadr/`, build output, databases,
logs, credentials, and model configuration are intentionally excluded from Git.

## Current Release

`1.1.0rc2` provides the current core runtime, production MCP Tool Result Gate,
Hook enforcement, approval workflows, reconstruction, Console, Endpoint/BCC
visibility, and optional Hybrid review. Linux BCC real-machine validation has
passed. Release history is maintained in [CHANGELOG.md](CHANGELOG.md).

## Support Boundary

ZeroADR currently supports local runtime enforcement and evidence workflows.
It does not provide:

- Tool Result rewriting or sanitization;
- synchronous result blocking for Hook post-tool, Endpoint, or Replay paths;
- kernel-level prevention through the Endpoint collector;
- authentication or remote multi-tenant control-plane deployment;
- a guarantee that benchmark results generalize to every Agent, model, tool,
  or production environment.

Report vulnerabilities through a private GitHub Security Advisory as described
in [SECURITY.md](SECURITY.md).

## Documentation

- [Architecture](docs/architecture.md)
- [RuntimeEvent schema](docs/runtime-event.md)
- [Policy format](docs/policy.md)
- [MCP Tool Result Gate](docs/tool-result-gate.md)
- [Hook integration](docs/hooks.md)
- [Session reconstruction](docs/session-reconstruction.md)
- [Evidence chains](docs/evidence-chain.md)
- [Console API](docs/console-api.md)
- [Console approvals](docs/console-approvals.md)
- [Endpoint deployment](docs/endpoint-agent-deployment.md)
- [Linux BCC collector](docs/linux-ebpf-collector.md)
- [LLM adjudication gate](docs/llm-adjudication-gate.md)
- [Migration to the 1.0 package boundary](docs/migration-v1.md)

## Contributing

Keep source-specific inputs behind the `RuntimeEvent` normalization boundary,
separate detection evidence from policy action, preserve protocol-safe stdout,
and add replayable local tests for behavior changes.

Before submitting changes:

```bash
conda run -n agent make check-all PYTHON=python
```

## License

Apache License 2.0. See [LICENSE](LICENSE).

## Contact

- Email: ch1nfo@foxmail.com

---

<div align="center">

**If ZeroADR is useful to you, consider giving the project a Star.**

</div>
