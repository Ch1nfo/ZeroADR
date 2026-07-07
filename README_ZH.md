# ZeroADR

ZeroADR 是一个本地优先的 AI Agent 运行时安全与审计层。它观察 Agent 和工具活动、
检测风险行为、执行 YAML 策略、协调人工审批，并保存经过脱敏的证据用于检查和回放。

当前版本：`1.2.0rc1`

[English](README.md)

## 核心能力

- MCP stdio Proxy，支持有序 JSON-RPC 转发和有界响应处理。
- Generic、Claude Code 和 Codex Hook Adapter。
- 统一 Runtime Event，以及针对 Prompt Injection、敏感文件、危险命令、Secret
  Leakage、Privilege Escalation、Code Injection、Memory Poisoning 和多阶段外传链的
  确定性检测。
- YAML Policy Action：`allow`、`alert`、`block` 和 `require_approval`。
- 可选的 Agent Input、Tool Request、Tool Result 和 Session Guard 执行面。
- 支持批准、拒绝、过期和审计恢复的人工审批记录。
- 脱敏 JSONL Trace 和 SQLite 持久化。
- Session 重建、证据链、摘要、Replay 和 Agent-BOM 导出。
- Loopback HTTP API、Web Console、审批 Inbox 和 Runtime Metrics。
- Endpoint Ingest，以及 Lite 和 Linux BCC Collector。

Rules 不依赖 LLM。可选 Hybrid Review 只接收有界、脱敏的证据并返回安全 Verdict；
最终 Policy Action 始终由 ZeroADR 决定。

## 架构

```text
MCP Client / Agent Hook / Endpoint Sensor / Recorded Trace
                         |
                         v
       Gateway / Hook Adapter / Ingest / Replay
                         |
                         v
          RuntimeEvent 归一化与脱敏
                         |
                         v
          确定性检测 + 可选 LLM Review
                         |
                         v
              YAML Policy + 人工审批
                         |
                         v
       allow / alert / block / require_approval
                         |
                         v
 JSONL / SQLite / Console / Session 重建 / Agent-BOM
```

Runtime Coordinator 为 MCP 和受支持的 Hook 路径提供一致的 Gate 语义。Endpoint 和
Replay 路径只进行观察。

## 安装

ZeroADR 需要 Python 3.12 或更高版本。

```bash
python -m pip install .
zeroadr --version
```

## 使用方式

### MCP Proxy

通过 ZeroADR 运行 MCP Server：

```bash
zeroadr proxy \
  --policy policies/default.yaml \
  --trace .zeroadr/trace.jsonl \
  --db .zeroadr/zeroadr.sqlite \
  -- npx @modelcontextprotocol/server-filesystem /tmp
```

### Agent Hook

从标准输入传入一个 Hook Event，并从标准输出获取 Decision：

```bash
zeroadr hook decide \
  --client claude-code \
  --policy policies/default.yaml \
  --trace .zeroadr/hooks.jsonl \
  --db .zeroadr/zeroadr.sqlite
```

稳定的通用 Schema 使用 `--client generic`，Codex Hook 输入使用 `--client codex`。
Payload Contract 详见 [Hook 集成](docs/hooks.md)。

### API 与 Console

```bash
zeroadr api serve --db .zeroadr/zeroadr.sqlite
```

打开 `http://127.0.0.1:8765/console`。API 不提供 Authentication，应保持 Loopback
绑定。`--allow-insecure-non-loopback` 是显式 Override，只确认暴露风险，不会增加
Authentication。

### Session 与 Replay

```bash
zeroadr inspect --db .zeroadr/zeroadr.sqlite
zeroadr session reconstruct --trace examples/traces/12_sensitive_file_to_external_post.jsonl
zeroadr session bom --trace examples/traces/12_sensitive_file_to_external_post.jsonl
zeroadr replay --trace examples/traces/12_sensitive_file_to_external_post.jsonl
```

### Endpoint Agent 与遥测

```bash
zeroadr endpoint ingest \
  --strict \
  --input examples/endpoint/01_sensitive_file_to_external_network.jsonl \
  --trace .zeroadr/endpoint.jsonl \
  --db .zeroadr/zeroadr.sqlite
```

持续采集使用 `zeroadr endpoint agent`。Endpoint Collector 观察系统活动，但不提供
内核级 Prevention。

### Advisory LLM 辅助研判

设置 `ZEROADR_LLM_API_KEY` 和 Provider Model 后，可以对已存储 Session 执行有界、
脱敏的辅助研判：

```bash
export ZEROADR_LLM_API_KEY="<provider-api-key>"
export ZEROADR_LLM_MODEL="<provider-model>"
zeroadr analyze session <session-id> --db .zeroadr/zeroadr.sqlite
```

辅助研判结果不能直接修改 Policy 或执行动作。

## Runtime Gate

稳定的执行面包括：

| Gate | 用途 |
| --- | --- |
| Agent Input | 在执行前审查 Agent 可见输入 |
| Tool Request | 在执行前审查高风险或与任务冲突的工具调用 |
| Tool Result | 在结果交付给 Agent 前审查不可信工具输出 |
| Session Guard | 在存在可信失陷证据后限制高风险动作 |

所有 Gate 在缺少配置时默认关闭。没有 Gate 配置的 Policy 保持 v1.1 审计行为。
Rules 模式使用确定性 Finding；Hybrid 模式增加分阶段 Reviewer。无效模型输出、未知
Evidence Reference、低置信度、不确定结果、Timeout 和 Provider Failure 均 fail-safe
到人工审批。

使用 `policies/runtime-gates-shadow.yaml` 观察 Decision，使用
`policies/runtime-gates-enforce.yaml` 执行 Decision。完整 Schema 详见
[Runtime Gates](docs/runtime-gates.md)。
人工审批示例位于 `policies/approval.yaml`。

## 项目结构

```text
src/zeroadr/       核心 Python Package 与 CLI
  api/             HTTP API 与 Web Console
  core/            Event、Finding、Decision 与 Gate Record
  detection/       确定性与序列 Detector
  endpoint/        Endpoint Agent 与 Collector
  gateway/         MCP Proxy 与 JSON-RPC Framing
  hook/            Generic、Claude Code 与 Codex Adapter
  llm/             有界辅助研判与 Gate Review
  policy/          YAML Policy Engine
  reconstruction/  Timeline、Evidence、Summary 与 Agent-BOM
  replay/          确定性 Trace Replay
  runtime/         Gate 协调与审批
  security/        Redaction
  storage/         JSONL 与 SQLite 持久化
policies/          可直接使用的 Policy 示例
examples/          公开的确定性 Trace 与 Hook Fixture
deploy/            systemd 与 launchd 模板
docs/              产品与运维文档
tests_local/       Git Ignore 的本地测试
```

评测 Companion、私有 Corpus、生成的 Trace、模型配置、凭据、Cache、数据库、Build
Output 和本地测试均不进入核心源码发布。

## 安全边界

- Tool Result Enforcement 可用于同步 MCP 路径；Endpoint、Replay 和 Post-tool Hook
  Ingest 仍只进行观察。
- MCP 本身无法检查初始用户 Prompt；Agent Input Enforcement 需要受支持的输入 Hook。
- 被暂存的 Tool Result 在放行前不会被改写或净化。
- Console 是本地运维界面，不是具备身份认证的多租户 Control Plane。
- Linux BCC 支持取决于 Linux Kernel 与 BCC 兼容性。
- LLM Review 只补充确定性控制，不能直接修改 Policy。

安全问题请按照 [SECURITY.md](SECURITY.md) 通过 GitHub Private Security Advisory
报告。

## 最新验证结果

2026-07-07 使用 Conda `agent` 环境完成的最新本地核心验证结果：

- Ruff：通过。
- MyPy：84 个源码文件通过。
- Pytest：457 passed，3 skipped。
- 核心 sdist 与 wheel：使用环境中已有的构建依赖并跳过联网隔离环境初始化后，构建
  成功。
- 隔离安装与 `zeroadr` CLI Smoke：通过；wheel 只包含 `zeroadr` Package 和
  Distribution Metadata。
- 真实 MCP Filesystem 集成：1 passed。
- Live LLM Session Triage：inconclusive，`provider_connection_error`（xfailed）。
- Linux BCC 集成：在 macOS 上 skipped，本轮未执行新的 Linux 验证。

真实 MCP 集成 Smoke 为 Opt-in 测试：

```bash
ZEROADR_RUN_REAL_MCP=1 \
  conda run -n agent pytest tests_local/test_real_mcp_filesystem.py -v
```

Agent 相关开发与验证统一使用 `agent` Conda 环境。本地测试保存在 Git Ignore 的
`tests_local/`，不进入 Git 发布内容。

## 文档

- [架构](docs/architecture.md)
- [Runtime Event 模型](docs/runtime-event.md)
- [Policy 格式](docs/policy.md)
- [Runtime Gates](docs/runtime-gates.md)
- [Tool Result Gate](docs/tool-result-gate.md)
- [Hook 集成](docs/hooks.md)
- [Session 重建](docs/session-reconstruction.md)
- [Console API](docs/console-api.md)
- [Endpoint 部署](docs/endpoint-agent-deployment.md)
- [Linux BCC Collector](docs/linux-ebpf-collector.md)

## 许可证

Apache License 2.0，详见 [LICENSE](LICENSE)。
