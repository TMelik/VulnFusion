# Dedup Evaluation

This repository includes a small labeled evaluation suite for dedup quality and
history stability.

Datasets:

- `tests/fixtures/dedup_eval_cases.json`
  Baseline deterministic, gray-zone, and guardrail dedup cases.
- `tests/fixtures/dedup_eval_clusters.json`
  Multi-finding cluster cases plus degraded/provenance-sensitive merges.
- `tests/fixtures/dedup_history_eval_cases.json`
  Current-vs-previous comparison cases for fixed, added, changed, and stable matches.

Run the full built-in benchmark with:

```bash
python -m utils.dedup_evaluation
```

Or point the runner at an explicit history dataset while keeping the built-in
dedup datasets:

```bash
python -m utils.dedup_evaluation --history-dataset tests/fixtures/dedup_history_eval_cases.json
```

The evaluation uses:

- the real `LLMDuplicateResolver`
- an oracle yes/no client instead of live LLM calls
- the real `compare_scans` history comparison flow

That keeps runs deterministic while still exercising:

- same-scanner exact premerge
- deterministic cross-scanner premerge
- gray-zone LLM-path clustering
- low-similarity no-merge guardrails
- provenance and degraded-scanner handling
- current-vs-previous finding stability

The summary reports:

- pairwise precision, recall, false merge rate, and false split rate
- cluster partition match rate, merge-count accuracy, overmerge count, and undersplit count
- provenance, confirmation-quality, and degraded-merge pass rates
- per-bucket metrics for `deterministic`, `gray_zone`, and `guardrail`
- tagged metrics for `cluster` and `provenance`
- history classification accuracy for `fixed`, `added`, `removed`, `changed`, and `unchanged`
- failed case ids with short reasons when something regresses

When extending the datasets:

- add cases that represent a real boundary, regression risk, or tuning question
- prefer exact, inspectable expected groups or diff labels over fuzzy scoring
- keep gray-zone fixtures free of deterministic anchors
- refresh fixtures when deterministic rules expand instead of weakening resolver logic
- add new history cases when identity matching rules or metadata semantics change
