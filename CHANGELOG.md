# Changelog

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
