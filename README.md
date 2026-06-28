<div align="center">

# ZeroADR

### Agent Runtime Detection, Response, and Policy Enforcement

[![Version](https://img.shields.io/badge/version-1.1.0rc1-blue.svg)](#)
[![Python](https://img.shields.io/badge/python-3.12%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-Apache--2.0-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Linux%20%7C%20Windows-lightgrey.svg)](#)
[![Runtime](https://img.shields.io/badge/runtime-MCP%20%7C%20Hooks%20%7C%20Endpoint-orange.svg)](#)

English | [中文](README_ZH.md)

</div>

---

## Why ZeroADR?

AI agents do more than generate text. They read files, execute shell commands,
call MCP tools, send data to external services, and act across long-running
sessions. Prompt filters see instructions, while endpoint security sees system
effects. The missing control point is the agent runtime itself: which tool was
called, what target it touched, what evidence led to the action, and whether
the action matched policy before execution.

**ZeroADR** (Zero Agentic Detection and Response) is an agent runtime security
platform for that control layer. It normalizes MCP, Hook, replay, and Endpoint
activity into a common `RuntimeEvent` model, detects risky behavior, applies
policy actions, pauses selected operations for human approval, and preserves a
replayable evidence chain in JSONL and SQLite.

- **Runtime-aware enforcement** — inspect MCP requests and agent Hook events at
  the point where tools are invoked.
- **Deterministic security controls** — detect sensitive access, dangerous
  commands, prompt injection, injection-to-action chains, and exfiltration.
- **Human-in-the-loop decisions** — route uncertain or explicitly governed
  actions to a local approval queue.
- **Replayable evidence** — reconstruct sessions, export focused evidence, and
  generate an Agent-BOM from persisted activity.
- **Local operations** — use the read-only Web Console, endpoint health views,
  and private local LLM configuration without introducing a hosted control
  plane.
- **LLM-assisted, policy-controlled review** — use bounded redacted evidence for
  session triage or Hybrid Gate adjudication while ZeroADR retains final action
  mapping.

## Core Capabilities

### Runtime Control

- **MCP stdio gateway** — proxies line-delimited and `Content-Length` framed
  JSON-RPC, inspects `tools/call` requests and successful tool responses, and
  returns protocol-safe block responses.
- **Production Tool Result Gate** — holds MCP results before the Agent receives
  them, applies rules or Hybrid LLM review, and supports shadow, block, and
  result-stage approval flows without rewriting allowed content.
- **Agent Hook adapters** — accepts Generic JSON, Claude Code, and Codex-style
  pre-tool and post-tool events through one normalized decision path.
- **Approval and resume** — persists `require_approval` requests in SQLite,
  supports Console approve/deny operations, expires stale requests, and resumes
  Hook or MCP execution with an audited effective action.
- **Protocol isolation** — keeps diagnostics away from stdout so MCP framing and
  Hook JSON responses remain valid.

### Detection and Policy

- **Sensitive file detection** — covers environment files, SSH keys, AWS
  credentials, kubeconfig, `.npmrc`, `.pypirc`, and related credential targets.
- **Dangerous execution detection** — identifies destructive shell patterns,
  download-and-execute chains, unsafe permission changes, decoding-and-execute
  flows, and reverse shells.
- **Prompt-injection detection** — reviews tool results for English, Chinese,
  and structured instruction-redirection signals.
- **Sequence detectors** — identify injection followed by sensitive access or
  dangerous execution, and sensitive reads followed by external transfer.
- **Separated policy engine** — detectors describe risk; YAML policy maps that
  evidence to `allow`, `alert`, `block`, or `require_approval`.

### Evidence and Operations

- **Open runtime schema** — represents sessions, tool requests, tool results,
  failures, policy evaluations, approvals, and Endpoint observations through
  typed records.
- **JSONL and SQLite persistence** — stores sessions, events, findings,
  decisions, approvals, LLM analyses, and Gate adjudications locally.
- **Trace replay** — re-runs deterministic and sequence detection against saved
  evidence without contacting an agent or model.
- **Session reconstruction** — produces timelines, risk summaries, focused
  evidence chains, process correlations, and Agent-BOM inventories.
- **local Web Console** — provides session inventory, timeline inspection,
  evidence, policy history, approval operations, Endpoint health, and LLM
  configuration on a loopback-only server.

### Endpoint Visibility

- **Endpoint ingest and tail** — normalizes `process_exec`,
  `sensitive_file_open`, and `network_connect` JSONL records.
- **Long-running Endpoint Agent** — supports PID/status files, heartbeat,
  rotation, retention, checkpoints, health reporting, and mock collection.
- **Linux BCC collector** — multiplexes process, file, and network probes with
  sensitive-path filtering, process enrichment, and probe-health metrics.
- **Process-aware reconstruction** — correlates endpoint events with runtime
  sessions and exposes parent/child process relationships.

Endpoint collection is observational. It does not provide kernel-level
prevention.

### LLM Assistance

- **Session triage** — sends only bounded, redacted session evidence to an
  OpenAI-compatible Chat Completions provider and stores a structured advisory
  result.
- **Hybrid LLM Gate** — combines deterministic findings with a structured model
  verdict; timeout, invalid output, provider failure, or low confidence falls
  back to `require_approval`.
- **MCP result review** — reviews every successful result in Hybrid mode while
  deterministic critical findings bypass model downgrade.
- **Deterministic action ownership** — the model never returns the policy
  action. ZeroADR maps a validated verdict to the final action.
- **Calibration workflow** — supports shadow labels, confidence scans,
  readiness metrics, and fixed-cache evaluation without exposing API keys or
  raw provider bodies.

## AgentDojo Evaluation

ZeroADR's prompt-injection result review was evaluated on the fixed
**AgentDojo v1.2.2** corpus using the `workspace` suite and the
`tool_knowledge` attack. The evaluation pairs every injected result with its
clean counterpart at the same tool-call position.

| Setting | Value |
| --- | --- |
| Benchmark | AgentDojo v1.2.2 |
| Suite | `workspace` |
| Attack | `tool_knowledge` |
| Injected cases | 966 |
| Paired clean cases | 966 |
| Total | 1,932 balanced cases |
| Review prompt | `tool-result-review-v0.2` |
| Calibrated confidence threshold | `0.50` |

### Results

| Pipeline | TP | FN | TN | FP | Recall | Accuracy | Precision | F1 | FPR |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Rule baseline | 599 | 367 | 966 | 0 | 62.01% | 81.00% | 100% | 76.55% | 0% |
| Isolated Hybrid | 742 | 224 | 966 | 0 | 76.81% | 88.41% | 100% | 86.88% | 0% |
| Sequence prevention | 966 | 0 | 966 | 0 | 100% | 100% | 100% | 100% | 0% |

The Hybrid pipeline improves isolated recall by **14.80 percentage points**
and isolated accuracy by **7.41 percentage points** over the strengthened rule
baseline, with no false positives in this fixed corpus.

**The 100% sequence score is not a 100% isolated classification score.** The
isolated evaluator still reports 224 false negatives. Sequence prevention
reconstructs each execution branch and marks a downstream result as prevented
when the current or an earlier action is `block` or `require_approval`. Those
224 downstream cases would not execute after the earlier prevention point; the
sequence metric therefore measures end-to-end attack prevention rather than
per-result injection classification.

### Reproducibility

- Fixed corpus:
  `.zeroadr/agentdojo-workspace-tool-knowledge-v122-corpus.jsonl`
- Fixed Hybrid cache: `.zeroadr/agentdojo-hybrid-cache-v02.jsonl`
- Cache replay: `model_calls=0`
- provider failures: 0
- Two consecutive cache-only runs produced identical rule, isolated, and
  sequence confusion matrices.
- Corpus, cache, case records, and analysis output are private local artifacts
  with `0600` permissions and remain under the Git-ignored `.zeroadr/` tree.

AgentDojo evaluation is intentionally outside the production package. The core
`zeroadr` wheel contains no benchmark modules or AgentDojo/OpenAI benchmark
dependencies; the independent companion lives in
[`evaluation/agentdojo`](evaluation/agentdojo).

## Architecture Overview

```text
┌────────────────────────────────────────────────────────────────────┐
│ Agent / MCP Client / Generic Hook / Claude Code / Codex / Endpoint │
└───────────────────────────────┬────────────────────────────────────┘
                                ▼
┌────────────────────────────────────────────────────────────────────┐
│ Collection and Adapters                                            │
│ MCP request/result gateway │ Hook adapters │ Replay │ Endpoint/BCC │
└───────────────────────────────┬────────────────────────────────────┘
                                ▼
┌────────────────────────────────────────────────────────────────────┐
│ RuntimeEvent Normalization                                         │
│ capability mapping │ target extraction │ redaction │ correlation   │
└───────────────────────────────┬────────────────────────────────────┘
                                ▼
┌────────────────────────────────────────────────────────────────────┐
│ Detection and Review                                               │
│ deterministic rules │ sequence detectors │ optional bounded LLM    │
└───────────────────────────────┬────────────────────────────────────┘
                                ▼
┌────────────────────────────────────────────────────────────────────┐
│ Policy and Human Control                                           │
│ allow │ alert │ block │ require_approval                           │
└───────────────────────────────┬────────────────────────────────────┘
                                ▼
┌────────────────────────────────────────────────────────────────────┐
│ Evidence and Operations                                            │
│ JSONL │ SQLite │ replay │ reconstruction │ Agent-BOM │ Console     │
└────────────────────────────────────────────────────────────────────┘
```

Core design principles:

- **Normalize before detection** — source-specific payloads become typed
  runtime events before detectors or policy evaluate them.
- **Separate evidence from response** — findings describe observed risk;
  policy owns enforcement and approval behavior.
- **Keep inline control fail-safe** — deterministic critical findings cannot be
  downgraded by the LLM, and semantic-review failures require human approval.
- **Minimize untrusted result retention** — original MCP results remain in
  process memory; persistent Gate evidence is redacted and bounded.
- **Treat replay as a product primitive** — saved traces are executable test
  cases, incident evidence, and regression inputs.

Main components:

- `GatewayRuntime` — MCP request and result inspection, blocking, approval
  waiting, ordered response release, and bounded audit recording.
- `HookRuntime` — Generic, Claude Code, and Codex event adaptation.
- `RuntimeDecisionService` — shared detection, policy, persistence, and approval
  coordination.
- `DetectionEngine` / `PolicyEngine` — risk detection and response mapping.
- `SQLiteStore` — durable local state for sessions, evidence, decisions, and
  approvals.
- Read-only API and Console — loopback inventory, evidence, approval, and health
  workflows.

The production Tool Result Gate covers MCP `tool.call.completed`. Hook
post-tool, Endpoint, and Replay paths remain observational and do not claim
synchronous result blocking.

## Quick Start

### Requirements

- Python 3.12+
- macOS, Linux, or Windows for the core runtime
- Optional: Node.js and `npx` for the real MCP filesystem smoke test
- Optional: supported Linux, BCC Python bindings, and root/eBPF capability for
  native BCC collection

### Install from source

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install .
zeroadr --version
```

### Replay a saved trace

```bash
zeroadr replay examples/traces/03_ssh_private_key.jsonl
```

The example produces a `block` decision for `~/.ssh/id_rsa`. Compare it with
the normal and alert examples:

```bash
zeroadr replay examples/traces/01_normal_file_read.jsonl
zeroadr replay examples/traces/02_env_file_read.jsonl
```

### Evaluate an agent Hook

```bash
zeroadr hook decide --client generic --policy policies/approval.yaml \
  < examples/hooks/generic_env_approval.json
```

Use `--client claude-code` or `--client codex` with the corresponding payloads
under `examples/hooks/`.

### Protect an MCP server

```bash
zeroadr proxy \
  --policy policies/tool-result-gate-shadow.yaml \
  --trace .zeroadr/traces/latest.jsonl \
  --db .zeroadr/zeroadr.sqlite \
  -- <mcp-server-command>
```

Start with the Shadow policy, then use
`policies/tool-result-gate-enforce.yaml` after reviewing metrics and freezing
the confidence threshold. Hybrid mode reads the private LLM configuration.
Approving a result-stage request returns the original untrusted result to the
Agent. See [`docs/tool-result-gate.md`](docs/tool-result-gate.md).

### Reconstruct a session

```bash
zeroadr session reconstruct \
  --trace examples/traces/12_sensitive_file_to_external_post.jsonl

zeroadr session bom \
  --trace examples/traces/12_sensitive_file_to_external_post.jsonl
```

### Ingest Endpoint records

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

The same provider settings can be stored privately in
`.zeroadr/llm-config.json` with `0600` permissions.

### Start the local Console

```bash
zeroadr api demo
```

Open `http://127.0.0.1:8765/console`. The Console is local and loopback-only by
default. API commands reject non-loopback binding unless the operator explicitly
passes `--allow-insecure-non-loopback`; this override does not add
authentication.

## AgentDojo Companion

Install the independent evaluation package after installing core ZeroADR:

```bash
python -m pip install ./evaluation/agentdojo
zeroadr-agentdojo --help
```

Run a cache-only reproduction with the existing private artifacts:

```bash
zeroadr-agentdojo hybrid \
  --suite workspace \
  --attack tool_knowledge \
  --corpus-cache .zeroadr/agentdojo-workspace-tool-knowledge-v122-corpus.jsonl \
  --cache .zeroadr/agentdojo-hybrid-cache-v02.jsonl \
  --min-confidence 0.5 \
  --auto-calibrate \
  --case-output .zeroadr/evaluations/agentdojo/cases.jsonl \
  --analysis-output .zeroadr/evaluations/agentdojo/analysis.json
```

The companion also exposes:

```text
zeroadr-agentdojo agent
zeroadr-agentdojo detector
zeroadr-agentdojo hybrid
```

See [the companion README](evaluation/agentdojo/README.md) for task filters,
live model execution, cache semantics, and metric definitions.

## Project Structure

```text
ZeroADR/
├── pyproject.toml                 # Core distribution and `zeroadr` CLI
├── src/zeroadr/
│   ├── api/                       # Read-only API, approvals, Console assets
│   ├── cli/                       # Core command-line interface
│   ├── core/                      # RuntimeEvent, Finding, PolicyDecision
│   ├── detection/                 # Deterministic detectors
│   ├── endpoint/                  # Endpoint agent and collectors
│   ├── gateway/                   # MCP stdio proxy and JSON-RPC framing
│   ├── hook/                      # Hook models and client adapters
│   ├── llm/                       # Triage, Hybrid Gate, calibration
│   ├── normalization/             # Capability and target mapping
│   ├── policy/                    # YAML policy engine
│   ├── reconstruction/            # Timeline, evidence, process tree, Agent-BOM
│   ├── replay/                    # Trace replay
│   ├── runtime/                   # Shared decision and approval services
│   ├── security/                  # Redaction
│   └── storage/                   # JSONL and SQLite persistence
├── evaluation/agentdojo/          # Independently built benchmark companion
│   ├── pyproject.toml
│   ├── src/zeroadr_agentdojo/
│   └── tests_local/
├── tests_local/                   # Local regression and opt-in smoke tests
├── policies/                      # Example YAML policies
├── examples/                      # Replay, Hook, Endpoint, and LLM fixtures
├── deploy/                        # systemd and launchd templates
└── docs/                          # Architecture and operational guides
```

## Development and Verification

Agent-related development uses the `agent` conda environment:

```bash
conda run -n agent ruff check .
conda run -n agent mypy src
conda run -n agent mypy \
  --config-file evaluation/agentdojo/pyproject.toml \
  evaluation/agentdojo/src
conda run -n agent pytest tests_local -q
conda run -n agent pytest \
  -c evaluation/agentdojo/pyproject.toml \
  evaluation/agentdojo/tests_local -q
```

Opt-in release smokes:

```bash
ZEROADR_RUN_REAL_MCP=1 \
  conda run -n agent pytest tests_local/test_real_mcp_filesystem.py -v

ZEROADR_RUN_LLM_TESTS=1 \
  conda run -n agent pytest tests_local/test_llm_live_opt_in.py -v

ZEROADR_ENABLE_BCC=1 ZEROADR_RUN_EBPF_TESTS=1 \
  conda run -n agent pytest tests_local/test_linux_bcc_opt_in.py -v
```

Local test directories and `.zeroadr/` private artifacts are Git-ignored.

## Security and Support Boundary

ZeroADR currently supports:

- local MCP request-time policy enforcement;
- production MCP Tool Result Gate enforcement with rules, Hybrid review, and
  result-stage approval;
- Generic, Claude Code, and Codex Hook decisions;
- local approval, trace, replay, reconstruction, evidence, and Console flows;
- observational Endpoint collection and supported Linux BCC probes;
- optional OpenAI-compatible triage and Hybrid Gate review.

It does not currently provide:

- Tool Result content rewriting or sanitization;
- kernel-level prevention through the Endpoint collector;
- authentication, multi-user access, or remote multi-tenant deployment;
- a guarantee that benchmark results generalize to every model, agent,
  injection style, or production environment.

Linux BCC validation passed for the 1.0 line; `1.0.0` GA was intentionally
skipped. Current release readiness is tracked in
[`docs/release/1.1.0rc1-readiness.md`](docs/release/1.1.0rc1-readiness.md).

Report vulnerabilities through a private GitHub Security Advisory as described
in [`SECURITY.md`](SECURITY.md).

## FAQ

<details>
<summary><strong>Is ZeroADR a prompt firewall?</strong></summary>

No. Prompt-injection detection is one signal. ZeroADR focuses on runtime tool
behavior, targets, result evidence, policy decisions, approvals, and attack
sequences.

</details>

<details>
<summary><strong>Does the core runtime require an LLM?</strong></summary>

No. Deterministic detection, policy, MCP blocking, Hooks, approvals, replay,
Endpoint observation, and the Console operate without a remote model. LLM
triage and Hybrid review are optional.

</details>

<details>
<summary><strong>Why are there isolated and sequence AgentDojo metrics?</strong></summary>

Isolated metrics classify each tool result independently. Sequence prevention
also accounts for earlier blocks or approvals that stop later tool calls from
executing. Both are reported because they answer different security questions.

</details>

<details>
<summary><strong>Does ZeroADR replace EDR?</strong></summary>

No. It adds agent-runtime context and policy control. Endpoint collection is a
local correlation source, not a replacement for an endpoint protection
platform.

</details>

<details>
<summary><strong>Where is local state stored?</strong></summary>

Runtime state defaults to `.zeroadr/`, including traces, SQLite databases,
private LLM configuration, approvals, and local evaluation artifacts.

</details>

## Documentation

- [Architecture](docs/architecture.md)
- [RuntimeEvent schema](docs/runtime-event.md)
- [Policy format](docs/policy.md)
- [Hook contract](docs/hooks.md)
- [Session reconstruction](docs/session-reconstruction.md)
- [Evidence chains](docs/evidence-chain.md)
- [Console API](docs/console-api.md)
- [Console approvals](docs/console-approvals.md)
- [Endpoint deployment](docs/endpoint-agent-deployment.md)
- [Linux BCC collector](docs/linux-ebpf-collector.md)
- [LLM adjudication gate](docs/llm-adjudication-gate.md)
- [Migration to the 1.0 package boundary](docs/migration-v1.md)

## Contributing

Issues and detector proposals are welcome. Keep source-specific input behind
the `RuntimeEvent` normalization boundary, keep detection separate from policy,
preserve protocol-safe stdout, and add replayable local tests for behavior
changes.

Run `conda run -n agent make check-all PYTHON=python` before submitting a
change.

## License

Apache License 2.0. See [LICENSE](LICENSE).

## Contact

- Email: ch1nfo@foxmail.com

---

<div align="center">

**If ZeroADR is useful to you, consider giving the project a Star.**

</div>
