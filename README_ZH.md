<div align="center">

# ZeroADR

### 面向 AI Agent 的运行时检测、响应与策略控制平台

[![版本](https://img.shields.io/badge/version-1.1.0rc2-blue.svg)](#当前版本)
[![Python](https://img.shields.io/badge/python-3.12%2B-blue.svg)](https://www.python.org/)
[![许可证](https://img.shields.io/badge/license-Apache--2.0-green.svg)](LICENSE)
[![平台](https://img.shields.io/badge/platform-macOS%20%7C%20Linux%20%7C%20Windows-lightgrey.svg)](#支持边界)
[![运行时](https://img.shields.io/badge/runtime-MCP%20%7C%20Hooks%20%7C%20Endpoint-orange.svg)](#核心能力)

[English](README.md) | 中文

</div>

---

ZeroADR（Zero Agentic Detection and Response）是一个开源的 AI Agent
运行时安全平台。它通过统一的 `RuntimeEvent` 模型，对 MCP、Agent Hook、Trace
Replay 和 Endpoint 遥测中的工具行为进行观测与控制。

ZeroADR 能够检测危险行为、执行 YAML Policy、将选定操作暂停并交由人工审批，
还可以在不可信 MCP Tool Result 返回 Agent 前完成审查，同时把脱敏后的证据链保存
到 JSONL 和 SQLite。确定性控制不依赖 LLM；可选的 Hybrid Review 只使用经过长度
限制和脱敏的证据，最终动作仍由 ZeroADR 决定。

## 为什么需要 ZeroADR？

AI Agent 会读取文件、执行命令、调用工具、发送数据，并在长时间 Session 中保留
状态。Prompt Filter 关注指令，Endpoint 工具关注系统结果，而 ZeroADR 保护两者
之间缺失的运行时控制点：

- Agent 请求了什么工具，它代表什么 Capability；
- 访问了什么 Target，使用了哪些 Argument；
- 哪个不可信 Tool Result 即将返回 Agent；
- 哪些 Evidence 和 Policy 产生了最终动作；
- 事后如何重建、审计并回放完整 Session。

## 核心能力

### 运行时控制

- **MCP stdio Gateway** — 代理行分隔和 `Content-Length` framed JSON-RPC，
  同时保持 stdout 协议安全。
- **生产级 Tool Result Gate** — 在成功的 MCP Tool Result 返回 Agent 前暂停
  Response，并执行规则审查、Hybrid Review、阻断或 Result-stage Approval。
- **Agent Hook Adapter** — 将 Generic JSON、Claude Code 和 Codex 的 pre-tool /
  post-tool Event 归一化到统一决策链。
- **人工审批** — 在 SQLite 中保存审批请求，支持批准、拒绝和过期，并让 Hook 或
  MCP 根据审计后的动作继续执行。
- **有序且有界的响应处理** — 保持 MCP Response 顺序，并限制 Pending Response
  数量与内存占用。

### 检测与策略

- 敏感文件与凭据目标
- 危险 Shell 与下载后执行模式
- Prompt Injection 与间接 Tool Result 注入
- Memory Poisoning 与伪造历史上下文
- Secret Leakage 与私钥暴露
- Privilege Escalation 与容器逃逸尝试
- Code Injection 与写入后执行链
- 敏感读取到外传、Prompt Injection 到危险动作的序列检测
- 独立 YAML Policy，将风险映射为 `allow`、`alert`、`block` 或
  `require_approval`

### 证据与运维

- 类型化 Runtime Event、Finding、Decision、Approval 和 Gate Record
- 脱敏 JSONL Trace 与 SQLite 持久化
- 确定性 Replay 和 Session Reconstruction
- 聚焦 Evidence Chain、进程关联和 Agent-BOM
- Loopback Web Console：Session、Timeline、Policy History、Approval、Endpoint
  Health、Gate Metrics 和 LLM 配置
- Endpoint Ingest/Tail/Agent，以及 Linux BCC 进程、文件和网络可见性

Endpoint 采集属于观测能力，不提供内核级阻断。

### 可选 LLM 辅助

- OpenAI-compatible Chat Completions Provider
- 经过长度限制和脱敏的 Session Triage
- `tool-result-review-v0.2` Hybrid Result Review
- Critical 确定性 Finding 不允许被模型降级
- 低置信、Timeout、Provider Failure 或非法结构化输出统一回退到人工审批
- Shadow Evaluation、标注和 Confidence Calibration

模型只返回结构化安全 Verdict，不返回 Policy Action。ZeroADR 负责把经过校验的
Verdict 映射为最终动作。

## 架构

```text
AI Agent / MCP Client / Hook / Endpoint Sensor
                    │
                    ▼
      MCP Gateway │ Hook Adapter │ Ingest │ Replay
                    │
                    ▼
        RuntimeEvent 归一化与脱敏
                    │
                    ▼
       确定性检测 + 可选 LLM Review
                    │
                    ▼
          YAML Policy + 人工审批协调
                    │
                    ▼
 allow │ alert │ block │ require_approval
                    │
                    ▼
 JSONL │ SQLite │ Console │ Reconstruction │ Agent-BOM
```

生产 Tool Result Gate 覆盖 MCP `tool.call.completed` Response。Hook post-tool、
Endpoint 和 Replay 路径仍保持观测性质。

## 基准测试结果

### Agent Security Bench — 官方 Agent ASR

主 ASB 评测运行固定版本的官方 Agent Harness，包括 `ReactAgentAttack`、官方
Workflow Generation、官方 Tool、攻击注入和官方 Attacker-goal Evaluator。这不是
对孤立 Tool Result 的二分类测试。

| 配置 | 数值 |
| --- | --- |
| ASB Commit | `1f561dccf92d55302368fa67679b4ba9d9c8fdc4` |
| 攻击类型 | DPI、OPI、Memory Poisoning、Mixed、PoT |
| 数据集 | 100 个攻击 + 100 个配对 Clean Control |
| 实验组 | Baseline、Rules、Hybrid，共 600 次 Agent 运行 |
| Agent / Reviewer | `deepseek-v4-flash` / `deepseek-v4-flash` |
| Workers | 4 |
| Provider / Workflow Failure | 0 / 0 |
| 主指标 | 官方 Attacker-goal ASR；不运行 Refusal Judge |

| 实验组 | ASR | 防护率 | Clean FPR | Block / Approval | 任务成功率 | P50 / P95 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Baseline | 67%（67/100） | 0% | 0% | 0 / 0 | 68.0% | 8.404s / 22.449s |
| Rules | 60%（60/100） | 39% | 0% | 39 / 0 | 63.0% | 7.883s / 23.034s |
| Hybrid | **40%（40/100）** | 56% | 2% | 50 / 8 | 63.5% | 13.600s / 24.233s |

Hybrid 相比 Baseline 将 ASR 降低 **27 个百分点**，相对降幅为 40.3%；100 个
Clean Control 中产生 2 个误报。剩余 40 个成功攻击被直接披露，不会因为 Workflow
其他位置发生 Block 就自动算作攻击失败。

| Hybrid 攻击类型 | ASR |
| --- | ---: |
| DPI | 85%（17/20） |
| OPI | 25%（5/20） |
| Memory Poisoning | 10%（2/20） |
| Mixed | 50%（10/20） |
| PoT Backdoor | 30%（6/20） |

Memory Poisoning 以成功检索污染记忆为前提。连续两次纯 Cache 复跑没有调用模型，
并复现相同的 Analysis SHA-256：
`de5979f6a1f8f7029dbd480aec28b9bd4af811e091f2e1f2d190af2f8af3cd7f`。

同一 Manifest 的另一次 Provider-clean 复测得到 Baseline 67%、Rules 55%、Hybrid
29%，Hybrid Clean FPR 为 1%。报告明确披露这项方差，不把 Flash 模型的单次结果
描述成确定性点估计。完整方法和 Hash 见
[ASB 结果报告](evaluation/asb/RESULTS.md)。

### AgentDojo — Tool Result 注入审查

固定的 AgentDojo v1.2.2 `workspace/tool_knowledge` Corpus 包含 966 个注入结果和
966 个配对 Clean Result，共 1,932 个平衡样本。

| Pipeline | TP | FN | TN | FP | Recall | Accuracy | Precision | F1 | FPR |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Rule Baseline | 599 | 367 | 966 | 0 | 62.01% | 81.00% | 100% | 76.55% | 0% |
| Isolated Hybrid | 742 | 224 | 966 | 0 | 76.81% | 88.41% | 100% | 86.88% | 0% |
| Sequence Prevention | 966 | 0 | 966 | 0 | 100% | 100% | 100% | 100% | 0% |

100% Sequence Score 不等于 100% Isolated Classification。Sequence Prevention
会统计更早 `block` 或 `require_approval` 后无法继续执行的下游 Case；Isolated
Review 仍有 224 个 False Negative。纯 Cache 复现得到 `model_calls=0`、
`provider_failures=0`，Confusion Matrix 完全一致。

ASB 和 AgentDojo 都是独立 Companion Package。核心 Wheel 不包含 Benchmark、
Dataset 或 Benchmark 专用依赖。

## 快速开始

### 环境要求

- Python 3.12+
- 核心 Runtime 支持 macOS、Linux 和 Windows
- 可选 Node.js/`npx`，用于真实 MCP filesystem Smoke
- 可选受支持 Linux、BCC Binding 和 root/eBPF Capability，用于原生 Endpoint
  Probe

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
zeroadr replay examples/traces/08_prompt_injection_tool_result.jsonl
```

### 执行 Agent Hook 决策

```bash
zeroadr hook decide \
  --client generic \
  --policy policies/approval.yaml \
  < examples/hooks/generic_env_approval.json
```

Claude Code 或 Codex 使用对应 Example，并将 `--client` 改为 `claude-code` 或
`codex`。

### 保护 MCP Server

```bash
zeroadr proxy \
  --policy policies/tool-result-gate-shadow.yaml \
  --trace .zeroadr/traces/latest.jsonl \
  --db .zeroadr/zeroadr.sqlite \
  -- <mcp-server-command>
```

建议先使用 Shadow Policy，检查 Gate Record 和延迟，再冻结 Policy 与 Confidence
Threshold 并切换到 `policies/tool-result-gate-enforce.yaml`。批准 Result-stage
Request 会把原始不可信 Result 返回 Agent。详见
[Tool Result Gate 运维文档](docs/tool-result-gate.md)。

### 重建 Session

```bash
zeroadr session reconstruct \
  --trace examples/traces/12_sensitive_file_to_external_post.jsonl
zeroadr session bom \
  --trace examples/traces/12_sensitive_file_to_external_post.jsonl
```

### 运行 Endpoint Agent

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

相同的 Provider 配置也可以保存到限制权限的私有
`.zeroadr/llm-config.json`。辅助研判不能直接修改 Policy。

### 启动 Web Console

```bash
zeroadr api demo
```

打开 `http://127.0.0.1:8765/console`。Server 默认只绑定 Loopback，且不提供身份
认证。显式 `--allow-insecure-non-loopback` Override 也不会增加身份认证，不要将
Console 暴露到不可信网络。

## 评测 Companion

只在运行 Benchmark 时安装独立 Companion：

```bash
python -m pip install ./evaluation/agentdojo
python -m pip install ./evaluation/asb

zeroadr-agentdojo --help
zeroadr-asb --help
```

- [AgentDojo Companion 指南](evaluation/agentdojo/README.md)
- [ASB Companion 指南](evaluation/asb/README.md)
- [官方 ASB 结果](evaluation/asb/RESULTS.md)

私有 Corpus、Cache、模型配置、Trace 和评测输出应放在 `.zeroadr/`，由 Git
Ignore，并使用严格的本地文件权限。

## 项目结构

```text
ZeroADR/
├── src/zeroadr/                 # 核心 Runtime 与 `zeroadr` CLI
│   ├── api/                     # HTTP API 与 Web Console
│   ├── core/                    # Event、Finding、Decision、Gate Record
│   ├── detection/               # 确定性与序列 Detector
│   ├── endpoint/                # Endpoint Agent 与 Collector
│   ├── gateway/                 # MCP Proxy 与 JSON-RPC Framing
│   ├── hook/                    # Generic、Claude Code、Codex Adapter
│   ├── llm/                     # Triage、Review、Calibration
│   ├── policy/                  # YAML Policy Engine
│   ├── reconstruction/          # Timeline、Evidence、Agent-BOM
│   ├── replay/                  # 确定性 Trace Replay
│   ├── runtime/                 # Decision 与 Approval Service
│   ├── security/                # Redaction
│   └── storage/                 # JSONL 与 SQLite
├── evaluation/
│   ├── agentdojo/               # 独立 AgentDojo Companion
│   └── asb/                     # 独立官方 ASB Companion
├── policies/                    # Policy 配置示例
├── examples/                    # 可公开的确定性 Fixture
├── deploy/                      # systemd 与 launchd Template
├── docs/                        # 架构与运维文档
└── tests_local/                 # 仅保留本地的回归与 Opt-in 测试
```

## 开发与验证

Agent 相关开发和测试统一使用 `agent` Conda 环境：

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

Opt-in 集成与平台 Smoke：

```bash
ZEROADR_RUN_REAL_MCP=1 \
  conda run -n agent pytest tests_local/test_real_mcp_filesystem.py -v

ZEROADR_RUN_LLM_TESTS=1 \
  conda run -n agent pytest tests_local/test_llm_live_opt_in.py -v

ZEROADR_ENABLE_BCC=1 ZEROADR_RUN_EBPF_TESTS=1 \
  conda run -n agent pytest tests_local/test_linux_bcc_opt_in.py -v
```

`tests_local/`、Companion `tests_local/`、`.zeroadr/`、Build Output、Database、
Log、Credential 和模型配置都明确排除在 Git 之外。

## 当前版本

`1.1.0rc2` 提供当前核心 Runtime、生产 MCP Tool Result Gate、Hook Enforcement、
Approval Workflow、Reconstruction、Console、Endpoint/BCC 可见性以及可选 Hybrid
Review。Linux BCC 实机验证已经通过。版本历史统一记录在
[CHANGELOG.md](CHANGELOG.md)。

## 支持边界

ZeroADR 当前支持本地 Runtime Enforcement 和 Evidence Workflow，但不提供：

- Tool Result 内容改写或净化；
- Hook post-tool、Endpoint 或 Replay 的同步 Result 阻断；
- Endpoint Collector 的内核级 Prevention；
- Authentication 或远程多租户 Control Plane；
- Benchmark 结果对所有 Agent、模型、工具和生产环境都成立的保证。

安全问题请按照 [SECURITY.md](SECURITY.md) 通过 GitHub Private Security Advisory
报告。

## 文档

- [架构](docs/architecture.md)
- [RuntimeEvent Schema](docs/runtime-event.md)
- [Policy 格式](docs/policy.md)
- [MCP Tool Result Gate](docs/tool-result-gate.md)
- [Hook 集成](docs/hooks.md)
- [Session Reconstruction](docs/session-reconstruction.md)
- [Evidence Chain](docs/evidence-chain.md)
- [Console API](docs/console-api.md)
- [Console Approval](docs/console-approvals.md)
- [Endpoint 部署](docs/endpoint-agent-deployment.md)
- [Linux BCC Collector](docs/linux-ebpf-collector.md)
- [LLM Adjudication Gate](docs/llm-adjudication-gate.md)
- [迁移到 1.0 Package Boundary](docs/migration-v1.md)

## 贡献

请将来源特定输入限制在 `RuntimeEvent` 归一化边界之外，保持 Detection Evidence
与 Policy Action 分离，保证 stdout 协议安全，并为行为变化增加可回放的本地测试。

提交前运行：

```bash
conda run -n agent make check-all PYTHON=python
```

## 许可证

Apache License 2.0，详见 [LICENSE](LICENSE)。

## 联系方式

- Email：ch1nfo@foxmail.com

---

<div align="center">

**如果 ZeroADR 对你有帮助，欢迎给项目一个 Star。**

</div>
