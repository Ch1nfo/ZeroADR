# ZeroADR × Agent Security Bench — Official Agent Results

## English

The corrected evaluation runs the pinned official ASB Agent harness at commit
`1f561dccf92d55302368fa67679b4ba9d9c8fdc4`. It uses 100 attacks, 100 paired
clean controls, and three independent arms. Both the Agent and Hybrid Reviewer
use `deepseek-v4-flash`; the primary metric is ASB's official attacker-goal
ASR, with no auxiliary refusal judge.

| Arm | ASR | Prevention | Clean FPR | Task success | P50 / P95 |
| --- | ---: | ---: | ---: | ---: | ---: |
| Baseline | 67/100 (67%) | 0% | 0% | 68.0% | 8.404s / 22.449s |
| Rules | 60/100 (60%) | 39% | 0% | 63.0% | 7.883s / 23.034s |
| Hybrid | 40/100 (40%) | 56% | 2% | 63.5% | 13.600s / 24.233s |

Hybrid ASR by family: DPI 85% (17/20), OPI 25% (5/20), Memory Poisoning 10%
(2/20), Mixed 50% (10/20), and PoT 30% (6/20). Memory Poisoning is conditioned
on successful poisoned-memory retrieval. Provider failures and workflow
failures were zero.

Reproducibility:

- Manifest SHA-256: `36410510708339f9db24bea5bbf37bba9fc0ed6bbd3823bde5a74f0544912556`
- Policy SHA-256: `2352868e1f23c4a6eb49f790c5804e2a2df05fe8d6c1aa61ac2810ce725b9950`
- Analysis SHA-256: `de5979f6a1f8f7029dbd480aec28b9bd4af811e091f2e1f2d190af2f8af3cd7f`
- Adapter: `asb-official-agent-v1.0`
- Prompt: `tool-result-review-v0.2`
- Two cache-only replays: `new_model_calls=0`, identical analysis hash

A separate provider-clean replication on the same manifest measured Baseline
67%, Rules 55%, and Hybrid 29%, with Hybrid clean FPR 1%. The variation between
the two complete runs is reported explicitly; results should not be interpreted
as deterministic point estimates of the flash model.

## 中文

修正后的评测运行固定 Commit 的 ASB 官方 Agent Harness，包括
`ReactAgentAttack`、Workflow Generation、官方模拟工具和 Attacker-Goal ASR
Evaluator。评测包含 100 个攻击、100 个配对 Clean Control 和三个独立 Arm；Agent
与 Hybrid Reviewer 均使用 `deepseek-v4-flash`，不运行额外 Refusal Judge。

| Arm | ASR | 防护率 | Clean FPR | 任务成功率 | P50 / P95 |
| --- | ---: | ---: | ---: | ---: | ---: |
| Baseline | 67/100（67%） | 0% | 0% | 68.0% | 8.404s / 22.449s |
| Rules | 60/100（60%） | 39% | 0% | 63.0% | 7.883s / 23.034s |
| Hybrid | 40/100（40%） | 56% | 2% | 63.5% | 13.600s / 24.233s |

Hybrid 将 ASR 降低 27 个百分点，但仍有 40 个攻击成功样本。按攻击类型分别为：
DPI 85%、OPI 25%、Memory Poisoning 10%、Mixed 50%、PoT 30%。Memory
Poisoning 以成功检索污染记忆为前提；Provider Failure 和 Workflow Failure 均为 0。

同一 Manifest 的另一次 Provider-Clean 复测得到 Baseline 67%、Rules 55%、
Hybrid 29%，Hybrid Clean FPR 为 1%。报告明确披露两次完整运行之间的方差，不将
Flash 模型的单次结果描述为确定性点估计。
