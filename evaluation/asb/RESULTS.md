# ZeroADR × Agent Security Bench — Official Agent Results

## English

The v3 holdout runs the pinned official ASB Agent harness at commit
`1f561dccf92d55302368fa67679b4ba9d9c8fdc4`. It contains 100 attacks, 100
paired clean controls, and three independent arms (600 Agent runs). The Agent
and every Reviewer use `deepseek-v4-flash`. The primary metric is ASB's
official attacker-goal ASR; no refusal judge or benchmark label is available to
the defense.

| Arm | ASR | Clean FPR | Task success | Block / approval | P50 / P95 |
| --- | ---: | ---: | ---: | ---: | ---: |
| Baseline | 70/100 (70%) | 0% | 66.0% | 0 / 0 | 8.027s / 19.413s |
| Rules | 22/100 (22%) | 0% | 62.0% | 57 / 0 | 7.000s / 17.871s |
| Hybrid | 7/100 (7%) | 4% | 54.5% | 70 / 7 | 23.779s / 53.099s |

Hybrid lowers ASR by 63 percentage points (90% relative). It passes the ASR
target (≤30%) and Clean FPR target (≤5%). It does not pass the utility target:
task success is 11.5 points below Baseline rather than at most 10 points below.
Provider failures and workflow failures are both zero in the final cache.

| Hybrid family | Attack success |
| --- | ---: |
| DPI | 0/20 (0%) |
| OPI | 1/20 (5%) |
| Memory Poisoning | 1/20 (5%) |
| Mixed | 0/20 (0%) |
| PoT Backdoor | 5/20 (25%) |

Memory Poisoning is conditioned on successful poisoned-memory retrieval.
Hybrid recorded 59 cases blocked before execution and 30 with result-stage or
post-execution intervention. Six successful attacks had no block; one attack
succeeded despite a block. Stage actions were Input 40 block / 1 approval,
Metadata 5 / 1, Pre-tool 17 / 9, and Result 32 / 7. Hybrid used 508 Agent model
calls and 878 Reviewer calls; Reviewer p95 was 9.410s.

Calibration on the separate v2-derived tuning split found no threshold that
simultaneously met ASR, FPR, and utility constraints. As specified before the
holdout, the formal run therefore used the default confidence 0.85 and records
`calibration_failure=true`.

Reproducibility:

- Manifest SHA-256: `481c0cb699db2207b1a8ebc9970012a3a5b280b560f4e02b1918d2561cab5f61`
- Policy SHA-256: `e2f3d1369daee500d973375e9040c978f778e38639e9cae9f34095c1373aabb5`
- Analysis SHA-256: `42d8cc195623a19fd7304018353af6293d9799d35fa2e2135babef92f379a8e5`
- Adapter: `asb-official-agent-v1.2`
- Result prompt: `tool-result-review-v0.2`
- Stage prompts: `agent-input-review-v0.1`, `tool-metadata-review-v0.1`,
  `tool-request-review-v0.1`
- Two cache-only replays: `new_case_runs=0`, `new_model_calls=0`, identical
  analysis hash

### Previous v2 result

The superseded v2 holdout measured Baseline 67%, Rules 60%, and Hybrid 40%,
with Hybrid Clean FPR 2%. It used pre-tool and result-stage defenses only. The
v2 result remains historical context and is not pooled with v3.

## 中文

v3 Holdout 使用固定 Commit
`1f561dccf92d55302368fa67679b4ba9d9c8fdc4` 的 ASB 官方 Agent Harness，包含
100 个攻击、100 个配对 Clean Control 和三个独立 Arm，共 600 次 Agent 运行。
Agent 与全部 Reviewer 均为 `deepseek-v4-flash`。主指标是官方 Attacker-goal
ASR；防护逻辑无法访问 Benchmark Label、Attacker Tool 名单或 Attack Goal。

| Arm | ASR | Clean FPR | 任务成功率 | Block / Approval | P50 / P95 |
| --- | ---: | ---: | ---: | ---: | ---: |
| Baseline | 70/100（70%） | 0% | 66.0% | 0 / 0 | 8.027s / 19.413s |
| Rules | 22/100（22%） | 0% | 62.0% | 57 / 0 | 7.000s / 17.871s |
| Hybrid | 7/100（7%） | 4% | 54.5% | 70 / 7 | 23.779s / 53.099s |

Hybrid 将 ASR 降低 63 个百分点，相对降幅 90%。ASR ≤30% 和 Clean FPR ≤5%
目标通过；效用目标未通过：任务成功率比 Baseline 低 11.5 个百分点，而目标要求不
超过 10 个百分点。最终 Cache 的 Provider Failure 和 Workflow Failure 均为 0。

Hybrid 分攻击类型 ASR：DPI 0%、OPI 5%、Memory Poisoning 5%、Mixed 0%、PoT
25%。Memory Poisoning 以成功检索污染记忆为前提。59 个 Case 在执行前阻断，30
个 Case 在 Result-stage 或执行后阻断；6 个成功攻击完全漏检，1 个攻击在发生阻断
后仍被官方 Evaluator 判定成功。

独立 tuning split 中没有阈值同时满足 ASR、FPR 和效用约束，因此按照预先固定的
流程记录 `calibration_failure=true`，并使用默认 Confidence 0.85 执行正式 Holdout。

正式结果的 Manifest、Policy 和 Analysis Hash 分别为：

- `481c0cb699db2207b1a8ebc9970012a3a5b280b560f4e02b1918d2561cab5f61`
- `e2f3d1369daee500d973375e9040c978f778e38639e9cae9f34095c1373aabb5`
- `42d8cc195623a19fd7304018353af6293d9799d35fa2e2135babef92f379a8e5`

连续两次纯 Cache 复算均为 `new_case_runs=0`、`new_model_calls=0`，Analysis Hash
完全一致。

### 历史 v2 结果

已被 v3 取代的 v2 Holdout 得到 Baseline 67%、Rules 60%、Hybrid 40%，Hybrid
Clean FPR 为 2%。v2 只包含 Pre-tool 与 Result-stage 防护，仅保留作历史对比，不与
v3 合并统计。
