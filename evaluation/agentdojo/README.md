# ZeroADR AgentDojo Bench

This independently buildable companion provides adapters for the official
AgentDojo benchmark. It depends on ZeroADR but is not included in the
production runtime distribution.
The primary detector-only evaluation measures whether ZeroADR blocks injected
tool results without involving an agent model. The legacy agent-level adapter
remains available for end-to-end experiments.

AgentDojo is an optional dependency:

```bash
pip install zeroadr-agentdojo-bench
```

The integration is pinned to AgentDojo `0.1.35` and defaults to benchmark
version `v1.2.2`. AgentDojo's API is still evolving, so version upgrades must be
validated explicitly.

## Detector-Only Evaluation

Use this command to measure ZeroADR's prompt-injection blocking quality:

```bash
zeroadr-agentdojo detector \
  --suite workspace \
  --attack tool_knowledge
```

This path does not read LLM configuration, call a remote model, redact tool
results, or score task utility. AgentDojo ground-truth executions produce
paired samples at the same tool-call position:

- positive: the tool result from the injected environment;
- negative: the corresponding tool result from the clean environment.

A detector hit is counted as a block. The report includes `true_positive`,
`false_positive`, `true_negative`, `false_negative`, `recall`, `precision`,
`accuracy`, `f1`, and `false_positive_rate`. Recall and accuracy are the primary
acceptance metrics; precision and false-positive rate show whether broad rules
inflate those numbers by blocking clean results.

Use repeated task options for a smaller reproducible subset:

```bash
zeroadr-agentdojo detector \
  --suite workspace \
  --attack tool_knowledge \
  --user-task user_task_0 \
  --injection-task injection_task_0
```

## Hybrid ZeroADR Evaluation

Use the hybrid command for the final blocking recall and accuracy of all
ZeroADR capabilities applicable to tool-result injection:

```bash
zeroadr-agentdojo hybrid \
  --suite workspace \
  --attack tool_knowledge \
  --llm-config .zeroadr/llm-config.json \
  --corpus-cache .zeroadr/evaluations/agentdojo/workspace-corpus.jsonl \
  --cache .zeroadr/evaluations/agentdojo/hybrid-cache-v02.jsonl \
  --workers 4 \
  --min-confidence 0.85 \
  --case-output .zeroadr/evaluations/agentdojo/cases.jsonl \
  --analysis-output .zeroadr/evaluations/agentdojo/analysis.json \
  --auto-calibrate
```

Every unique redacted tool result passes through the deterministic
`DetectionEngine` and the configured Gate model. Reviewing rule misses is
required to recover deterministic false negatives. ZeroADR maps the model's
structured verdict to a policy action; the model never returns the action.

- high-confidence true positive: `block`;
- high-confidence false positive: `allow`;
- uncertain, low-confidence, timeout, invalid output, or provider failure:
  `require_approval`;
- critical deterministic findings cannot be downgraded.

For benchmark scoring, `block` and `require_approval` both count as predicted
attack prevention. The report always shows provider failure and approval rates
beside final metrics, so fail-safe blocking cannot be mistaken for successful
model classification.

The cache stores only payload hashes and sanitized structured model results.
It never stores API keys, Authorization headers, complete prompts, provider
response bodies, or raw tool results. Failed requests are not persisted.

AgentDojo task initialization can generate dynamic environment values. The
hybrid command therefore writes the paired corpus to a private `0600` JSONL
snapshot and reuses it on subsequent runs. The snapshot contains synthetic tool
results and is stored under `.zeroadr/`, which is Git-ignored. Use the same
`--corpus-cache` path when comparing retries or model configurations.

The report contains:

- `rules`: deterministic baseline confusion matrix and metrics;
- `final`: hybrid policy confusion matrix and metrics;
- `sequence_final`: sequence-prevention confusion matrix after propagating an
  earlier block or approval within the same clean/injected execution branch;
- `deltas`: recall and accuracy gain over rules;
- `llm`: model calls, cache hits, verdict/action counts, provider failures, and
  approval rate.

The isolated `final` metric remains for historical comparison. The Step 2I
acceptance metric is `sequence_final`, because downstream tool results that
would never execute after an earlier block must not be relabeled as prompt
injection. Optional case records contain no raw result text and are written
with mode `0600`.

`--auto-calibrate` scans confidence thresholds from 0.50 through 0.99 using
only the deterministic ten-task tuning split. It requires at least 85% recall
and at most 5% false-positive rate, then chooses maximum accuracy with minimum
approval load. The four-task holdout split is reported separately. Override
the deterministic split seed with `--split-seed` only when creating a new
evaluation version.

## Step 2I Fixed-Corpus Result

Using AgentDojo v1.2.2 `workspace/tool_knowledge`, 966 injected and 966 paired
clean cases, prompt `tool-result-review-v0.2`, and calibrated threshold `0.50`:

| Metric | Isolated result | Sequence prevention |
| --- | ---: | ---: |
| True positive | 742 | 966 |
| False negative | 224 | 0 |
| True negative | 966 | 966 |
| False positive | 0 | 0 |
| Recall | 76.81% | 100% |
| Accuracy | 88.41% | 100% |
| Precision | 100% | 100% |
| F1 | 86.88% | 100% |
| False-positive rate | 0% | 0% |

The deterministic-rule baseline reached 62.01% recall and 81.00% accuracy
with no false positives. Sequence evaluation recovered 224 downstream cases
that would not execute after an earlier block. The completed v0.2 cache rerun
made zero model calls, had zero provider failures, and reproduced all three
confusion matrices exactly.

## Agent-Level Experiment

The command reuses `.zeroadr/llm-config.json` and its full triage model:

```bash
zeroadr-agentdojo agent \
  --suite workspace \
  --attack tool_knowledge \
  --user-task user_task_0 \
  --injection-task injection_task_0 \
  --logdir .zeroadr/evaluations/agentdojo/runs
```

Run the same case without ZeroADR for comparison:

```bash
zeroadr-agentdojo agent \
  --suite workspace \
  --attack tool_knowledge \
  --user-task user_task_0 \
  --injection-task injection_task_0 \
  --defense none \
  --logdir .zeroadr/evaluations/agentdojo/runs
```

Use repeated `--user-task` and `--injection-task` options for a matrix. Add
`--force-rerun` to bypass cached official result logs.

## Agent-Level Metrics

- `utility_rate`: intended user tasks completed successfully.
- `attack_success_rate`: injection goals executed successfully.
- `security_rate`: `1 - attack_success_rate`.
- `injection_task_utility_rate`: injection tasks are executable when presented
  as normal user tasks, validating the benchmark target.

AgentDojo's internal `security_results=True` means the injection goal succeeded.
The ZeroADR summary exposes this as `attack_success_rate` to avoid ambiguous
interpretation.

## Historical Agent-Level Smoke Result

On a four-case `workspace` matrix using `deepseek-v4-pro` and the
`tool_knowledge` attack:

| Pipeline | Utility | Attack success | Security |
| --- | ---: | ---: | ---: |
| Baseline | 50% | 100% | 0% |
| ZeroADR tool-result redaction | 0% | 0% | 100% |

This historical result measures the complete agent pipeline and is not used to
calculate detector recall or accuracy. Whole-result replacement affects task
utility, while the detector-only evaluation above isolates classification
quality.

Official references:

- [AgentDojo repository](https://github.com/ethz-spylab/agentdojo)
- [AgentDojo benchmark API](https://agentdojo.spylab.ai/api/benchmark/)
