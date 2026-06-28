# Roadmap

## v1.0 Release Candidate

Status: `1.0.0rc1` ready; external publication not performed.

- production runtime and benchmark packaging are separated;
- AgentDojo validation lives in `evaluation/agentdojo`;
- final `1.0.0` requires the privileged Linux BCC release gate.

## v0.1 MCP Runtime MVP

Goal: complete the local MCP runtime security loop.

- MCP stdio wrapper.
- RuntimeEvent v0.1.
- Capability Mapping v0.1.
- Sensitive file, dangerous shell, prompt injection, exfiltration, and
  injection-chain detectors.
- Policy actions: `allow`, `alert`, `block`.
- JSONL and SQLite trace storage.
- CLI replay, inspect, and export.

## v0.2 Hooks and Policy Control

- Generic JSON hook decision command.
- PreToolUse and PostToolUse event mapping.
- Hook-originated RuntimeEvent persistence.
- `require_approval`.
- argument and result redaction.
- first agent-specific hook adapter.

## v0.3 Client Adapters

Status: v0.3 completed.

- Session context reconstruction from JSONL traces and SQLite sessions.
- Focused evidence chain export for individual findings.
- Compact session summary for inventory and risk views.
- Agent-BOM v0.1 export for audit and reporting workflows.
- Claude Code hook adapter.
- Codex hook adapter.
- Generic JSONL adapter.
- prompt, workspace, and client context reconstruction.

## v0.4 Endpoint Lite Sensor

Status: v0.4 endpoint runtime baseline completed; production deployment moved to v0.6.

- Endpoint JSONL ingest for `process_exec`, `sensitive_file_open`, and
  `network_connect`.
- RuntimeEvent normalization with `source_type: endpoint_sensor`.
- JSONL and SQLite persistence for endpoint-originated events.
- Bounded endpoint JSONL tail/follow command for daemon-like local ingestion.
- Tail checkpoint/resume to avoid duplicate ingest after restart.
- Endpoint agent command for long-running collection with optional immediate
  ingest.
- Endpoint agent status file with stopped reason and last error.
- Endpoint agent health inspection from status files with stale/error checks.
- Endpoint agent output rotation by byte threshold with bounded rotated files.
- Endpoint agent output retention byte budget and minimal write backpressure
  retry metrics.
- Endpoint agent runtime error status contract for collector initialization,
  ingest, and output write failures.
- Process identity normalization with `pid`, `ppid`, `host_id`, and
  `process_start_time`.
- Session reconstruction process tree and deterministic endpoint-to-runtime
  correlation.
- Replay correlation with ZeroADR sessions and existing detectors.
- Versioned endpoint JSONL contract for native collectors.
- Strict endpoint contract validation with lenient legacy compatibility.
- Pluggable collector boundary with deterministic mock collector output.
- Linux/eBPF collector scaffold with explicit platform, privilege, and optional
  dependency gating.
- BCC-first exec/file/network spike behind opt-in native test/runtime gates.
- Production eBPF daemon behavior remains future work beyond the BCC opt-in spike.

## v0.6 Endpoint Agent Production

Status: v0.6 completed.

- endpoint agent PID file support via `--pid-file`.
- default endpoint agent status file at `.zeroadr/endpoint-agent-status.json`.
- read-only agent health contract via `build_agent_health`.
- `GET /api/v0/endpoint-agent/health` exposed by `zeroadr api serve`.
- `zeroadr api serve --agent-status-file` for Console agent health integration.
- Console endpoint agent health panel with manual and periodic refresh.
- systemd and launchd deployment templates.
- documented cross-platform agent + api serve + console production demo flow.
- localhost-only, read-only, no authentication, and no remote deployment mode.

## v0.7 Console Approval Loop

Status: v0.7 completed.

- `ApprovalRequest` queue persisted in SQLite.
- pending approval creation when policy action is `require_approval`.
- hook stdout includes `decision_id` and `approval_id`.
- `zeroadr hook wait-approval` resume command with `effective_action`.
- `GET /api/v0/approvals` and `GET /api/v0/approvals/{approval_id}`.
- `POST /api/v0/approvals/{approval_id}/resolve` for localhost approve/deny.
- Console pending approvals panel with badge, refresh, and action buttons.
- demo database seeds one pending and one resolved approval example.
- localhost-only, no authentication, no WebSocket, and no MCP proxy pause.

## v0.7.1 Console Approval Polish

Status: v0.7.1 completed.

- stale pending approvals auto-expire during API reads and wait polling.
- approval resolve writes `approval.resolved` audit events to SQLite and optional JSONL.
- MCP `proxy` pauses on `require_approval` with `--approval-timeout`.
- `zeroadr hook decide-and-wait` combines decide and wait in one stdout payload.
- Console timeline deep-links `require_approval` events to the approvals inbox.
- `api serve --trace` and `--approval-max-age` support approval audit and expiry.

## v0.8 Linux/BCC Endpoint Production

Status: v0.8 completed.

- unified `BccCollectorSession` with fair multiplex poll loop and BPF cleanup.
- production gate via `ZEROADR_ENABLE_BCC=1` with CAP_BPF/root privilege checks.
- sensitive path prefix filtering for `sensitive_file_open` events.
- `/proc` enrichment for `user`, `cwd`, and `process_start_time`.
- agent status `bcc` probe metrics and Console read-only probe panel.
- `endpoint agent` flags: `--sensitive-path-prefixes`, `--bcc-poll-timeout-ms`,
  `--bcc-max-queue`.
- distro-managed iovisor/BCC Python bindings such as `python3-bpfcc`.
- systemd template: `deploy/systemd/zeroadr-endpoint-agent-linux.service`.
- documented production enablement in `docs/linux-ebpf-collector.md` and
  `docs/endpoint-agent-deployment.md`.
- libbpf/CO-RE rewrite, IPv6/UDP probes, and remote deployment remain out of scope.

## v0.8.1 Runtime Hardening

Status: v0.8.1 completed.

- atomic approval resolution under concurrent API requests.
- audited automatic approval expiry.
- loopback-only unauthenticated approval API unless explicitly overridden.
- zero-active-probe BCC failure with partial attachment still supported.
- independent endpoint heartbeat and atomic status-file replacement.
- bounded MCP pending-call state after terminal responses.
- corrected Linux BCC installation guidance without the unrelated PyPI package.
- real MCP and privileged Linux/BCC smoke tests remain opt-in release gates.

## v0.9 LLM-Assisted Session Triage

Status: v0.9 step 2I completed.

- on-demand `zeroadr analyze session` CLI over SQLite sessions.
- OpenAI-compatible Chat Completions provider configured with
  `ZEROADR_LLM_API_KEY`, `ZEROADR_LLM_MODEL`, and optional base URL.
- bounded and redacted evidence payload without complete traces or `raw` fields.
- strict structured result for verdict, risk, attack chain, and recommendations.
- completed and failed analysis audit history in SQLite.
- advisory-only output that cannot create policy actions or change enforcement.
- default Chinese output with optional English output.
- local Console LLM settings panel with persisted provider configuration.
- loopback-only configuration and JSON-mode connection test API.
- `.zeroadr/llm-config.json` private local storage with environment overrides.
- opt-in Hybrid LLM Adjudication Gate for MCP and pre-tool Hook paths.
- shadow/enforce policy modes with deterministic verdict-to-action mapping.
- failure, timeout, invalid output, and low confidence fallback to human approval.
- separate Gate audit records, session reconstruction, API, and Console history.
- global Gate completion, fallback, verdict, action, confidence, and latency metrics.
- JSONL human-label contract and offline multi-threshold calibration report.
- Console Gate health summary without automatic policy mutation.
- balanced 40-case shadow dogfood dataset and live runner.
- review-template export for real shadow traffic and a combined readiness gate.
- Gate v0.2 prompt semantics and typed trusted context signals.
- baseline/candidate comparison for quality, review load, and latency deltas.
- optional AgentDojo v1.2.2 pipeline adapter with baseline/ZeroADR comparison.
- detector-only AgentDojo evaluation with paired injected/clean tool results and
  confusion-matrix, recall, precision, accuracy, F1, and false-positive metrics.
- hybrid AgentDojo evaluation combining the real DetectionEngine, redacted
  OpenAI-compatible semantic review, deterministic policy mapping, fail-safe
  approval semantics, deduplication, and sanitized resumable caching.
- AgentDojo FN analysis with private per-case records, stable template-level
  tuning/holdout splits, reason/tool/task/result-shape clusters, and tuning-only
  confidence calibration.
- sequence-prevention metrics that distinguish current-result injection from
  downstream results already prevented by an earlier block.
- bounded head/middle/tail tool-result evidence, prompt review v0.2, and a
  structured priority-redirect deterministic rule.
- fixed 1932-case v0.2 result: sequence TP 966, FN 0, TN 966, FP 0, with zero
  provider failures and an identical zero-model-call cache rerun.
- official utility, attack-success, and derived security metrics with local logs.
- Console session analysis, automatic background analysis, and JSONL input remain future work.

## v0.5 Console and Inventory

Status: v0.5 completed.

- dependency-free local read-only JSON API contract.
- `zeroadr api demo` one-command local Console demo.
- `zeroadr api seed-demo` deterministic SQLite demo database generation.
- `zeroadr api dump` session inventory and risk summaries from SQLite.
- `zeroadr api session` reconstructed context, summary, and Agent-BOM payload.
- dependency-free localhost HTTP API via `zeroadr api serve`.
- `GET /health`, `GET /api/v0/sessions`, `GET /api/v0/sessions/{session_id}`,
  and session subresources for evidence, events, findings, and decisions.
- pagination and compact session payload options for console-friendly reads.
- local Web Console at `/console` served by the same dependency-free HTTP server.
- session inventory with search and risk filters.
- session timeline with event drilldown and capability filters.
- alert evidence chain with finding drilldown and rule filters.
- agent, MCP server, and tool inventory.
- policy decision history with action filters.
- runtime Agent-BOM.
- localhost-only, read-only, no authentication, no WebSocket, and no remote
  deployment mode.

## Not in v0.1

ZeroADR v0.1 does not include a web console, full approval flow, client log
adapters, endpoint sensors, LLM detectors, multi-tenancy, distributed gateways,
or external SIEM integrations.
