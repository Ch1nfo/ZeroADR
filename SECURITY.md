# Security Policy

## Supported versions

Security fixes target the latest ZeroADR release candidate and the latest
stable release after 1.0 GA.

## Reporting a vulnerability

Do not open a public issue containing exploit details, credentials, private
traces, or tool results. Use the repository's private GitHub Security Advisory
workflow to report vulnerabilities. Include the affected version, platform,
minimal reproduction, impact, and whether secrets may have been exposed.

ZeroADR stores sensitive local configuration and evaluation artifacts under
`.zeroadr/`. Reports must redact those files before sharing them.

## Scope boundary

`1.1.0rc1` covers MCP request-time enforcement, production MCP Tool Result
Gate behavior, hooks, approval state, local APIs, LLM triage/review, and
Endpoint collection. Tool Result rewriting, kernel-level prevention, and
remote multi-tenant operation are outside the supported contract.
