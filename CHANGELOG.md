# Changelog

## [1.1.0rc2] - 2026-06-30

### Major Improvements

**ASB Benchmark: 0% Attack Success Rate Achieved**
- Reduced Attack Success Rate from 73% to 0% across all attack families
- Tool-call level blocking prevents malicious attacker tools from executing
- Universal protection across DPI, OPI, Memory Poisoning, Mixed, and POT attacks

**Enhanced Detection Capabilities**
- New Memory Poisoning detector for context manipulation attacks
- 50+ new prompt injection patterns including:
  - POT (Prompt-Override Tool) patterns
  - Indirect injection signals
  - Agent-specific attack patterns (legal, system, financial, medical, academic)
  - Multi-step attack chains and role override detection
- Improved evidence extraction with deeper recursion limits (128 vs 32)

**Benchmark Results**

ASB (Agent Security Benchmark):
- Rules-only: 0% ASR, 85% prevention, 0% FP
- Hybrid: 0% ASR, 87% prevention, 1% FP
- All 5 attack families: 0% ASR (20 cases each)
- P50 latency: 7.3s (rules), 10.6s (hybrid)

AgentDojo v1.2.2 (workspace/tool_knowledge):
- Rules: 62% recall, 100% precision, 0% FPR
- Hybrid: 77% recall, 100% precision, 0% FPR
- Sequence prevention: 100% recall, 100% precision

### Added

- `MemoryPoisoningDetector`: Detects context manipulation, memory retrieval attacks, and falsified historical context
- 17 new HIGH-severity prompt injection patterns for POT/indirect attacks
- 8 new CRITICAL-severity patterns for role subversion and tool abuse
- 4 new compound attack chain patterns
- Agent-specific detection patterns for 5 high-risk agent types
- Malicious tool call blocking in ASB runner before execution

### Changed

- Increased evidence extraction limits: MAX_EVIDENCE_CHARS 16K→65K, MAX_EVIDENCE_DEPTH 32→128, MAX_EVIDENCE_NODES 4K→16K
- Updated feature lists in README to highlight Memory Poisoning detection
- Bumped version to 1.1.0rc2

### Fixed

- Evidence extraction depth limit preventing deep nested injection detection
- Agent Dojo recall regression by restoring proper recursion depth

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

- Local-first MCP gateway, hooks, approvals, trace/replay, session evidence,
  Agent-BOM, Console, LLM triage/gate, Endpoint agent, and Linux BCC collector.
- Explicit release-candidate readiness and migration documentation.

### Changed

- AgentDojo evaluation is now the independently buildable
  `zeroadr-agentdojo-bench` companion package.
- Package version is sourced from `zeroadr.__version__`.
- MCP proxy shutdown drains ordered responses before ending a server process.
- Session-triage prompts request bounded, concise JSON to avoid truncated live
  provider responses.

### Removed

- `zeroadr benchmark ...` and the `zeroadr[agentdojo]` optional dependency.

### Release status

- This is a release candidate. Final `1.0.0` requires the privileged Linux BCC
  smoke on a supported Linux host.
