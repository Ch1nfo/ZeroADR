# LLM Gate Shadow Calibration

Use shadow mode before enabling LLM Gate enforcement. ZeroADR records the model
verdict, confidence, latency, failure category, proposed action, and final
deterministic action without changing the base policy action.

## Runtime Metrics

Inspect all stored adjudications:

```bash
zeroadr gate metrics --db .zeroadr/zeroadr.sqlite
```

Filter one session or inspect a different confidence boundary:

```bash
zeroadr gate metrics \
  --db .zeroadr/zeroadr.sqlite \
  --session-id <session-id> \
  --confidence-threshold 0.85
```

The report includes completion and human-fallback rates, verdict and failure
distributions, action changes, confidence distribution, and latency P50/P95.
The Console LLM settings panel displays the main global health indicators.

## Human Labels

Create a JSONL file with one reviewer label per adjudication. Labels represent
ground truth, not the action that the model or policy selected:

```json
{"adjudication_id":"<id>","expected_verdict":"likely_true_positive"}
{"adjudication_id":"<id>","expected_verdict":"likely_false_positive"}
```

Only these two ground-truth values are accepted. Duplicate IDs and malformed
records fail with a line-numbered error. Keep labels separate from SQLite so
runtime audit records remain immutable.

Export a review template from real shadow traffic:

```bash
zeroadr gate labels export \
  --db .zeroadr/zeroadr.sqlite \
  --output .zeroadr/gate-labels.jsonl
```

The exported context contains only adjudication audit fields. Fill each
`expected_verdict` before evaluation.

## Controlled Dogfood

The v0.1 controlled dataset contains 40 balanced `.env` access scenarios. Run
a small live smoke first, then the complete set:

```bash
zeroadr gate dogfood \
  --limit 2 \
  --db .zeroadr/gate-dogfood.sqlite \
  --labels-output .zeroadr/gate-dogfood-labels.jsonl

zeroadr gate dogfood \
  --db .zeroadr/gate-dogfood.sqlite \
  --labels-output .zeroadr/gate-dogfood-labels.jsonl
```

Dogfood refuses enforce policies. Ground-truth labels remain outside the event
payload sent to the model. Use a fresh database for each run to keep reports
unambiguous.

Gate `gate-v0.2` separates finding semantics from target sensitivity and adds
four typed context signals: user consent, task alignment, data handling, and
injection evidence. These signals live on ZeroADR's internal `RuntimeEvent`
context. Tool arguments cannot set or override them.

## Threshold Evaluation

Evaluate labels against the stored model outputs:

```bash
zeroadr gate evaluate \
  --db .zeroadr/zeroadr.sqlite \
  --labels examples/llm/gate-labels.example.jsonl \
  --threshold 0.85
```

The selected report and threshold matrix include coverage, precision, recall,
false-positive rate, false-negative rate, and review count. Failed calls,
uncertain verdicts, and results below the threshold remain in the review bucket.
The command never modifies policy YAML or approval state.

Compare a baseline and candidate run:

```bash
zeroadr gate compare \
  --baseline-db .zeroadr/gate-dogfood-v01.sqlite \
  --baseline-labels .zeroadr/gate-dogfood-v01-labels.jsonl \
  --candidate-db .zeroadr/gate-dogfood-v02.sqlite \
  --candidate-labels .zeroadr/gate-dogfood-v02-labels.jsonl
```

The report includes prompt versions and deltas for completion, P95 latency,
false positives, false negatives, and human review.

Run the combined release gate after evaluation:

```bash
zeroadr gate readiness \
  --db .zeroadr/gate-dogfood.sqlite \
  --labels .zeroadr/gate-dogfood-labels.jsonl
```

The default checks require at least 40 matched labels, 95% provider completion,
at most 1% invalid output, P95 latency below 8 seconds, at most 2% false
negatives, at most 5% false positives, and at most 10% human review. A failed
readiness report returns a non-zero process status.

## Enforce Gate

Do not choose a threshold from model confidence alone. Collect representative
shadow traffic, label it independently, and review both false negatives and
provider reliability. Before enabling enforce mode, define acceptable limits
for false-negative rate, P95 latency, provider failure rate, and human-fallback
capacity. Continue mapping all provider failures to `require_approval`.
