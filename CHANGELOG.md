# Changelog

## [1.2.0rc1] - 2026-06-30

### Added

- Opt-in Agent Input, Tool Metadata, Tool Request, and online Session Guard
  stages coordinated by one core `RuntimeSecurityCoordinator`.
- Stage-specific bounded and redacted Hybrid reviews, structured runtime gate
  audit records, SQLite persistence, metrics/session APIs, and ASB step
  journals.
- MCP `tools/list` schema inspection and filtering, real capability mapping,
  bounded session compromise state, and deterministic metadata review caching.
- Official ASB v1.2 adapter support for multi-stage gates without exposing
  attack labels, attacker tools, or attacker-goal outcomes to the defense.

### Evaluation

- Official ASB v3 holdout: Baseline 70% ASR, Rules 22%, Hybrid 7%; Hybrid
  Clean FPR 4%, with zero final Provider and workflow failures.
- Hybrid task success is 54.5% versus Baseline 66.0%. The 11.5-point decline
  misses the release utility target by 1.5 points, so readiness remains
  explicitly incomplete despite passing the security targets.
- Two cache-only replays made zero case runs and zero model calls and reproduced
  analysis SHA-256
  `42d8cc195623a19fd7304018353af6293d9799d35fa2e2135babef92f379a8e5`.

### Compatibility

- Every new gate is disabled when its policy section is absent, preserving the
  v1.1 wire behavior and model-call profile.
- Hook post-tool, Endpoint, and Replay remain observational; MCP-only
  deployments cannot inspect the initial Agent input.

### Security

- Runtime gate records store hashes, bounded previews, findings, actions, and
  latency only. Raw prompts, raw tool results, provider bodies, API keys, and
  Authorization headers are not persisted.

## [1.1.0rc2] - 2026-06-30

### Benchmark correction

- The previously published ASB claim of 0% ASR is withdrawn. That run used a
  simplified loop and an attacker-tool ground-truth shortcut, so it did not
  measure the production-visible ZeroADR decision boundary.
- The corrected evaluation runs the pinned official ASB `ReactAgentAttack`,
  workflow generation, simulated tools, and attacker-goal evaluator.
- Corrected primary 100-attack results: Baseline 67% ASR, Rules 60%, Hybrid
  40%; clean FPR is 0% for Rules and 2% for Hybrid. A second provider-clean
  replication measured 67%/55%/29%, documenting material model-run variance.
- Provider failures and workflow failures are both zero. Two cache-only replays
  made zero model calls and reproduced the same analysis SHA-256.

### Added

- Independent ASB companion with official-agent instrumentation for pre-tool
  and tool-result gates without exposing labels or expected attacker tools to
  ZeroADR.
- Stable paired manifest, deterministic direct-hit memory evaluation,
  append-only private cache, concurrency sweep, and stage-level telemetry.
- Memory Poisoning detector and additional prompt-injection compound signals.

### Fixed

- Plain UUID values no longer trigger the Heroku API-key detector without
  explicit Heroku key context.
- Completed events inspect result evidence without rescanning request arguments.
- Recursive evidence extraction is bounded to 16 KiB with depth and node
  budgets.
- Flash reasoning-model runs use sufficient output budget and reusable clients,
  eliminating truncation-driven retry storms.

## [1.1.0rc1] - 2026-06-28

### Added

- Production MCP Tool Result Gate with rules and Hybrid LLM review modes.
- Result-stage human approvals, bounded redacted previews, dedicated SQLite
  audit records, metrics API, session API, and Console visibility.
- Strict response ordering, duplicate request-ID rejection, pending-response
  backpressure, and bounded response buffering.

### Changed

- Successful MCP tool results can now be held and mapped to allow, alert,
  block, or approval before they reach the Agent.
- Core version advances directly from `1.0.0rc1` to `1.1.0rc1`; `1.0.0` GA was
  intentionally skipped after its Linux BCC gate passed.

### Security

- Original MCP responses remain process-memory only while held. Persistent
  records and LLM inputs contain redacted, bounded evidence.

## 1.0.0rc1 - 2026-06-28

### Added

- MCP gateway, hooks, approvals, trace/replay, session evidence, Agent-BOM,
  Console, LLM triage/gate, Endpoint agent, and Linux BCC collector.

### Changed

- AgentDojo evaluation is the independently buildable
  `zeroadr-agentdojo-bench` companion package.
- Package version is sourced from `zeroadr.__version__`.
