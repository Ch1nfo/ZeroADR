<div align="center">

# ZeroADR

### Agent 运行时检测、响应与策略控制平台

[![版本](https://img.shields.io/badge/version-1.1.0rc1-blue.svg)](#)
[![Python](https://img.shields.io/badge/python-3.12%2B-blue.svg)](https://www.python.org/)
[![许可证](https://img.shields.io/badge/license-Apache--2.0-green.svg)](LICENSE)
[![平台](https://img.shields.io/badge/platform-macOS%20%7C%20Linux%20%7C%20Windows-lightgrey.svg)](#)
[![运行时](https://img.shields.io/badge/runtime-MCP%20%7C%20Hooks%20%7C%20Endpoint-orange.svg)](#)

[English](README.md) | 中文

</div>

---

## 为什么需要 ZeroADR？

AI Agent 已经不只是生成文本。它们会读取文件、执行 Shell 命令、调用
MCP 工具、向外部服务发送数据，并在长时间运行的 Session 中持续采取动作。
Prompt 过滤器看到的是指令，Endpoint 安全产品看到的是系统结果，中间缺少的
控制点正是 Agent Runtime：调用了什么工具、访问了什么目标、什么证据导致了
这个动作，以及动作执行前是否符合安全策略。

**ZeroADR**（Zero Agentic Detection and Response）是面向这一控制层的
Agent 运行时安全平台。它把 MCP、Hook、Replay 和 Endpoint 行为归一化为统一的
`RuntimeEvent`，检测危险行为，应用策略动作，将部分操作暂停并交给人工审批，
同时在 JSONL 和 SQLite 中保留可回放的完整证据链。

- **运行时感知控制** — 在 Agent 调用工具的控制点检查 MCP Request 和 Hook
  Event。
- **确定性安全检测** — 识别敏感访问、危险命令、Prompt Injection、注入到动作
  链路以及数据外传链路。
- **人机协同决策** — 将不确定或明确需要治理的动作送入本地审批队列。
- **可回放证据** — 重建 Session、导出聚焦证据链，并从已保存的行为生成
  Agent-BOM。
- **本地化运维** — 使用只读 Web Console、Endpoint 健康视图和私有 LLM 配置，
  无需依赖托管控制平面。
- **LLM 辅助、策略控权** — 使用经过脱敏和长度限制的证据进行 Session Triage
  或 Hybrid Gate 复核，最终动作始终由 ZeroADR 映射。

## 核心能力

### 运行时控制

- **MCP stdio Gateway** — 代理行分隔与 `Content-Length` framed JSON-RPC，
  检查 `tools/call` Request 与成功的 Tool Result，并返回协议兼容的阻断响应。
- **生产级 Tool Result Gate** — 在 MCP Result 返回 Agent 前暂停响应，通过规则或
  Hybrid LLM Review 决策，支持 Shadow、Block 和 Result-stage Approval，允许时不
  改写原始内容。
- **Agent Hook Adapter** — 通过统一决策链处理 Generic JSON、Claude Code 和
  Codex 风格的 pre-tool / post-tool Event。
- **审批与恢复** — 在 SQLite 中保存 `require_approval` 请求，支持 Console
  批准/拒绝、过期清理，并让 Hook 或 MCP 按审计后的有效动作继续执行。
- **协议隔离** — 诊断信息不写入 stdout，保证 MCP framing 和 Hook JSON 响应
  不被日志污染。

### 检测与策略

- **敏感文件检测** — 覆盖环境变量文件、SSH Key、AWS Credential、kubeconfig、
  `.npmrc`、`.pypirc` 等凭据目标。
- **危险执行检测** — 识别破坏性 Shell、下载后执行、不安全权限修改、解码后执行
  和反弹 Shell 等模式。
- **Prompt Injection 检测** — 检查 Tool Result 中的英文、中文和结构化任务重定向
  信号。
- **序列检测** — 识别注入后访问敏感资源或执行危险命令，以及敏感读取后向外部
  传输数据的行为链。
- **检测与策略分离** — Detector 只描述风险；YAML Policy 将证据映射为
  `allow`、`alert`、`block` 或 `require_approval`。

### 证据与运维

- **开放运行时 Schema** — 使用类型化记录表示 Session、Tool Request、Tool
  Result、失败、策略评估、审批和 Endpoint Observation。
- **JSONL 与 SQLite 持久化** — 在本地保存 Session、Event、Finding、Decision、
  Approval、LLM Analysis 和 Gate Adjudication。
- **Trace Replay** — 对保存的证据重新运行确定性与序列检测，无需连接 Agent 或
  远程模型。
- **Session Reconstruction** — 生成时间线、风险摘要、聚焦证据链、进程关联和
  Agent-BOM 资产清单。
- **本地只读 Web Console** — 在 loopback-only Server 上提供 Session Inventory、
  Timeline、Evidence、Policy History、Approval、Endpoint Health 和 LLM 配置。

### Endpoint 可见性

- **Endpoint Ingest 与 Tail** — 归一化 `process_exec`、`sensitive_file_open`
  和 `network_connect` JSONL 记录。
- **长运行 Endpoint Agent** — 支持 PID/Status File、Heartbeat、Rotation、
  Retention、Checkpoint、Health Reporting 和 Mock Collector。
- **Linux BCC Collector** — 对进程、文件和网络 Probe 进行 Multiplex，支持敏感
  路径过滤、进程 Enrichment 和 Probe Health Metric。
- **进程感知重建** — 将 Endpoint Event 与 Runtime Session 关联，并展示父子进程
  关系。

Endpoint 采集属于观测能力，不提供内核级阻断。

### LLM 辅助能力

- **Session Triage** — 只向 OpenAI-compatible Chat Completions Provider 发送
  经过脱敏和长度限制的 Session 证据，并保存结构化建议结果。
- **Hybrid LLM Gate** — 将确定性 Finding 与结构化 Model Verdict 组合；Timeout、
  非法输出、Provider Failure 或低置信度统一回退到 `require_approval`。
- **MCP Result Review** — Hybrid 模式审查所有成功 Result；确定性 Critical Finding
  不允许被 Model 降级。
- **确定性的动作所有权** — Model 不返回 Policy Action；ZeroADR 将校验后的
  Verdict 映射为最终动作。
- **Calibration Workflow** — 支持 Shadow Label、Confidence Scan、Readiness
  Metric 和固定 Cache Evaluation，不保存 API Key 或原始 Provider Body。

## AgentDojo 评测

ZeroADR 的 Prompt Injection Tool Result Review 使用固定的
**AgentDojo v1.2.2** Corpus 进行评估，Suite 为 `workspace`，Attack 为
`tool_knowledge`。每个注入结果都与同一 Tool Call 位置上的 Clean Result 成对。

| 配置 | 数值 |
| --- | --- |
| Benchmark | AgentDojo v1.2.2 |
| Suite | `workspace` |
| Attack | `tool_knowledge` |
| 注入样本 | 966 |
| 配对 Clean 样本 | 966 |
| 总样本数 | 1,932 个平衡样本 |
| Review Prompt | `tool-result-review-v0.2` |
| 校准后的 Confidence Threshold | `0.50` |

### 评测结果

| Pipeline | TP | FN | TN | FP | Recall | Accuracy | Precision | F1 | FPR |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Rule Baseline | 599 | 367 | 966 | 0 | 62.01% | 81.00% | 100% | 76.55% | 0% |
| Isolated Hybrid | 742 | 224 | 966 | 0 | 76.81% | 88.41% | 100% | 86.88% | 0% |
| Sequence Prevention | 966 | 0 | 966 | 0 | 100% | 100% | 100% | 100% | 0% |

与强化后的 Rule Baseline 相比，Hybrid Pipeline 的孤立样本 Recall 提升
**14.80 个百分点**，Accuracy 提升 **7.41 个百分点**，并且在该固定 Corpus
上没有产生 False Positive。

**100% 的序列指标并不代表逐条孤立分类达到了 100%。** Isolated Evaluator
仍然有 224 个 False Negative。Sequence Prevention 会重建每条执行分支；当当前
或前序 Action 已经是 `block` 或 `require_approval` 时，后续结果会被标记为已被
前序动作阻止。这 224 个下游 Case 在更早的阻断点之后不会继续执行，因此序列
指标衡量的是端到端攻击阻止效果，而不是每条 Tool Result 的注入分类能力。

### 可复现性

- 固定 Corpus：
  `.zeroadr/agentdojo-workspace-tool-knowledge-v122-corpus.jsonl`
- 固定 Hybrid Cache：`.zeroadr/agentdojo-hybrid-cache-v02.jsonl`
- Cache Replay：`model_calls=0`
- provider failures: 0
- 连续两次纯 Cache 复跑得到完全一致的 Rule、Isolated 和 Sequence
  Confusion Matrix。
- Corpus、Cache、Case Record 和 Analysis Output 都是权限为 `0600` 的本地
  私有产物，并保存在 Git 忽略的 `.zeroadr/` 目录中。

AgentDojo 评测与生产包明确解耦。核心 `zeroadr` Wheel 不包含 Benchmark Module，
也不包含 AgentDojo/OpenAI Benchmark Dependency；独立 Companion 位于
[`evaluation/agentdojo`](evaluation/agentdojo)。

## 架构总览

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

核心设计原则：

- **检测前先归一化** — 来源特定的 Payload 会先变为类型化 RuntimeEvent，再进入
  Detector 和 Policy。
- **证据与响应分离** — Finding 描述观察到的风险，Policy 决定 Enforcement 与
  Approval 行为。
- **内联控制 Fail-safe** — 确定性的 Critical Finding 不会被 LLM 降级，语义复核
  失败时必须进入人工审批。
- **最小化不可信 Result 留存** — 原始 MCP Result 仅存在于进程内存，持久化 Gate
  证据经过脱敏与长度限制。
- **将 Replay 作为产品原语** — 保存的 Trace 同时是可执行测试、事件证据和回归
  输入。

主要组件：

- `GatewayRuntime` — MCP Request/Result 检查、阻断、审批等待、有序响应释放和
  有界审计记录。
- `HookRuntime` — Generic、Claude Code 和 Codex Event 适配。
- `RuntimeDecisionService` — 统一协调检测、策略、持久化和审批。
- `DetectionEngine` / `PolicyEngine` — 风险识别与响应动作映射。
- `SQLiteStore` — 保存 Session、Evidence、Decision 和 Approval 的本地状态。
- Read-only API 与 Console — 提供 loopback Inventory、Evidence、Approval 和
  Health Workflow。

生产 Tool Result Gate 覆盖 MCP `tool.call.completed`。Hook post-tool、Endpoint
和 Replay 保持观测性质，不声明同步 Result 阻断能力。

## 快速开始

### 环境要求

- Python 3.12+
- 核心 Runtime 支持 macOS、Linux 和 Windows
- 可选：真实 MCP filesystem smoke 需要 Node.js 和 `npx`
- 可选：原生 BCC 采集需要受支持的 Linux、BCC Python Binding 和 root/eBPF
  Capability

### 从源码安装

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install .
zeroadr --version
```

### 回放 Trace

```bash
zeroadr replay examples/traces/03_ssh_private_key.jsonl
```

该示例会对 `~/.ssh/id_rsa` 产生 `block` Decision。还可以对比正常与告警场景：

```bash
zeroadr replay examples/traces/01_normal_file_read.jsonl
zeroadr replay examples/traces/02_env_file_read.jsonl
```

### 执行 Agent Hook 决策

```bash
zeroadr hook decide --client generic --policy policies/approval.yaml \
  < examples/hooks/generic_env_approval.json
```

对 `examples/hooks/` 中相应 Payload 使用 `--client claude-code` 或
`--client codex`，即可接入两类 Client Adapter。

### 保护 MCP Server

```bash
zeroadr proxy \
  --policy policies/tool-result-gate-shadow.yaml \
  --trace .zeroadr/traces/latest.jsonl \
  --db .zeroadr/zeroadr.sqlite \
  -- <mcp-server-command>
```

先使用 Shadow Policy，确认指标并冻结 Confidence Threshold 后，再切换到
`policies/tool-result-gate-enforce.yaml`。Hybrid 模式读取私有 LLM 配置。
批准 Result-stage Approval 会把原始、不受信任的 Result 返回 Agent。详见
[`docs/tool-result-gate.md`](docs/tool-result-gate.md)。

### 重建 Session

```bash
zeroadr session reconstruct \
  --trace examples/traces/12_sensitive_file_to_external_post.jsonl

zeroadr session bom \
  --trace examples/traces/12_sensitive_file_to_external_post.jsonl
```

### 接入 Endpoint Record

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

### 运行 LLM 辅助研判

```bash
export ZEROADR_LLM_API_KEY="<provider-api-key>"
export ZEROADR_LLM_MODEL="<provider-model>"
zeroadr analyze session <session-id> --db .zeroadr/zeroadr.sqlite
```

相同的 Provider 配置也可以使用 `0600` 权限私密保存在
`.zeroadr/llm-config.json`。

### 启动本地 Console

```bash
zeroadr api demo
```

访问 `http://127.0.0.1:8765/console`。Console 默认只监听本机 Loopback。
API Command 会拒绝非 Loopback 绑定，除非 Operator 明确传入
`--allow-insecure-non-loopback`；该 Override 不会增加 Authentication。

## AgentDojo Companion

安装核心 ZeroADR 后，再安装独立评测包：

```bash
python -m pip install ./evaluation/agentdojo
zeroadr-agentdojo --help
```

使用现有私有产物执行纯 Cache 复现：

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

Companion 提供三个入口：

```text
zeroadr-agentdojo agent
zeroadr-agentdojo detector
zeroadr-agentdojo hybrid
```

任务过滤、Live Model、Cache Semantics 和 Metric Definition 参见
[Companion README](evaluation/agentdojo/README.md)。

## 项目结构

```text
ZeroADR/
├── pyproject.toml                 # 核心 Distribution 与 `zeroadr` CLI
├── src/zeroadr/
│   ├── api/                       # Read-only API、Approval、Console Asset
│   ├── cli/                       # 核心 CLI
│   ├── core/                      # RuntimeEvent、Finding、PolicyDecision
│   ├── detection/                 # 确定性 Detector
│   ├── endpoint/                  # Endpoint Agent 与 Collector
│   ├── gateway/                   # MCP stdio Proxy 与 JSON-RPC Framing
│   ├── hook/                      # Hook Model 与 Client Adapter
│   ├── llm/                       # Triage、Hybrid Gate、Calibration
│   ├── normalization/             # Capability 与 Target Mapping
│   ├── policy/                    # YAML Policy Engine
│   ├── reconstruction/            # Timeline、Evidence、Process Tree、Agent-BOM
│   ├── replay/                    # Trace Replay
│   ├── runtime/                   # 统一 Decision 与 Approval Service
│   ├── security/                  # Redaction
│   └── storage/                   # JSONL 与 SQLite Persistence
├── evaluation/agentdojo/          # 独立构建的 Benchmark Companion
│   ├── pyproject.toml
│   ├── src/zeroadr_agentdojo/
│   └── tests_local/
├── tests_local/                   # 本地 Regression 与 Opt-in Smoke Test
├── policies/                      # YAML Policy 示例
├── examples/                      # Replay、Hook、Endpoint、LLM Fixture
├── deploy/                        # systemd 与 launchd Template
└── docs/                          # 架构与运维文档
```

## 开发与验证

Agent 相关开发统一使用 `agent` Conda Environment：

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

Opt-in Release Smoke：

```bash
ZEROADR_RUN_REAL_MCP=1 \
  conda run -n agent pytest tests_local/test_real_mcp_filesystem.py -v

ZEROADR_RUN_LLM_TESTS=1 \
  conda run -n agent pytest tests_local/test_llm_live_opt_in.py -v

ZEROADR_ENABLE_BCC=1 ZEROADR_RUN_EBPF_TESTS=1 \
  conda run -n agent pytest tests_local/test_linux_bcc_opt_in.py -v
```

本地 `tests_local/` 与 `.zeroadr/` 私有产物均已被 Git 忽略。

## 安全与支持边界

ZeroADR 当前支持：

- 本地 MCP Request-time Policy Enforcement；
- 基于规则、Hybrid Review 和 Result-stage Approval 的生产 MCP Tool Result Gate；
- Generic、Claude Code 和 Codex Hook Decision；
- 本地 Approval、Trace、Replay、Reconstruction、Evidence 和 Console；
- Endpoint Observation 与受支持 Linux 上的 BCC Probe；
- 可选 OpenAI-compatible Triage 和 Hybrid Gate Review。

当前不提供：

- Tool Result 内容改写或净化；
- 通过 Endpoint Collector 实现内核级阻断；
- Authentication、多用户访问或远程多租户部署；
- Benchmark 结果对所有 Model、Agent、Injection Style 和生产环境的泛化保证。

1.0 线的 Linux BCC 验证已经通过，`1.0.0` GA 按发布决策跳过。当前 Release
Readiness 见
[`docs/release/1.1.0rc1-readiness.md`](docs/release/1.1.0rc1-readiness.md)。

安全漏洞请通过私有 GitHub Security Advisory 报告，具体流程见
[`SECURITY.md`](SECURITY.md)。

## FAQ

<details>
<summary><strong>ZeroADR 是 Prompt Firewall 吗？</strong></summary>

不是。Prompt Injection Detection 只是其中一个信号。ZeroADR 关注 Runtime Tool
Behavior、Target、Result Evidence、Policy Decision、Approval 和 Attack Sequence。

</details>

<details>
<summary><strong>核心 Runtime 是否依赖 LLM？</strong></summary>

不依赖。确定性检测、策略、MCP 阻断、Hook、Approval、Replay、Endpoint Observation
和 Console 都可以在没有远程 Model 的情况下运行。LLM Triage 与 Hybrid Review
属于可选能力。

</details>

<details>
<summary><strong>为什么同时报告 Isolated 与 Sequence AgentDojo 指标？</strong></summary>

Isolated Metric 独立分类每条 Tool Result；Sequence Prevention 还会计算更早的
Block 或 Approval 对后续 Tool Call 的阻止效果。两组指标回答不同的安全问题，
因此必须同时披露。

</details>

<details>
<summary><strong>ZeroADR 能替代 EDR 吗？</strong></summary>

不能。ZeroADR 增加的是 Agent Runtime Context 与 Policy Control。Endpoint 采集
是本地关联数据源，不是 Endpoint Protection Platform 的替代品。

</details>

<details>
<summary><strong>本地状态保存在哪里？</strong></summary>

Runtime State 默认位于 `.zeroadr/`，包括 Trace、SQLite Database、私有 LLM
Configuration、Approval 和本地 Evaluation Artifact。

</details>

## 文档

- [架构](docs/architecture.md)
- [RuntimeEvent Schema](docs/runtime-event.md)
- [Policy Format](docs/policy.md)
- [Hook Contract](docs/hooks.md)
- [Session Reconstruction](docs/session-reconstruction.md)
- [Evidence Chain](docs/evidence-chain.md)
- [Console API](docs/console-api.md)
- [Console Approval](docs/console-approvals.md)
- [Endpoint Deployment](docs/endpoint-agent-deployment.md)
- [Linux BCC Collector](docs/linux-ebpf-collector.md)
- [LLM Adjudication Gate](docs/llm-adjudication-gate.md)
- [迁移到 1.0 Package Boundary](docs/migration-v1.md)

## 贡献

欢迎提交 Issue 和 Detector Proposal。请将来源特定输入保留在 `RuntimeEvent`
归一化边界之外，保持 Detection 与 Policy 分离，维护协议安全的 stdout，并为行为
变更添加可 Replay 的本地测试。

提交变更前运行：

```bash
conda run -n agent make check-all PYTHON=python
```

## License

Apache License 2.0。详见 [LICENSE](LICENSE)。

## 联系方式

- Email: ch1nfo@foxmail.com

---

<div align="center">

**如果 ZeroADR 对你有帮助，欢迎为项目点一个 Star。**

</div>
