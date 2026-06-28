# Changelog

## 1.1.0rc1 - 2026-06-28

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
