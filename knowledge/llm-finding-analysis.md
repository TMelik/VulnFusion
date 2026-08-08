---
type: Pipeline Stage
title: Structured LLM Finding Analysis
description: Bounded, evidence-cited applicability, summary, priority, and remediation advice after deterministic scoring.
resource: utils/llm_finding_analyzer.py
tags: [vulnfusion, llm, applicability, remediation, evaluation, safety]
status: stable
sources:
  - id: evaluator
    title: Advisory AI Evaluation
    resource: /utils/ai_evaluation.py
generated:
  by: codex/gpt-5
  at: 2026-08-08
---

# Structured LLM Finding Analysis

After deterministic risk scoring, VulnFusion automatically selects the highest
priority findings and asks the configured OpenAI-compatible provider for four
strict advisory objects:

- `applicability`: status, model-reported confidence, reason, and cited
  evidence IDs;
- `ai_priority`: a separate P0-P4 recommendation, confidence, rationale,
  context revision, and cited evidence IDs;
- `ai_summary`: consolidated technical description, business impact, and cited
  evidence IDs;
- `ai_remediation`: one to five steps and one to five verification steps.

Allowed applicability statuses are `likely_false_positive`,
`valid_but_not_applicable`, `likely_valid`, and `needs_review`. Exact fields,
types, ranges, list sizes, and evidence IDs are validated. The only accepted
response is one JSON object, optionally inside a JSON Markdown fence.

## Guardrails

- The prompt is bounded and secret-sanitized immediately before transmission.
- Scanner title, description, evidence, remediation, technical anchors, and up
  to three merged-source records remain separately cited.
- A human-confirmed site profile may be included as context; its revision is
  part of the cache identity.
- The default cap is the deterministic top 25 (`--ai-analysis-limit`). Other
  findings get `ai_analysis_status=skipped_limit`.
- Provider, timeout, or malformed response sets
  `ai_analysis_status=unavailable` for that finding. Cache read/write failure
  disables reuse or persistence but does not discard an otherwise valid live
  decision.
- The stage never deletes/suppresses a finding, overwrites scanner
  remediation, changes `vulnerability_name`, or changes deterministic
  `risk_score`/`priority`; an AI priority disagreement stays separately visible.
- `--no-ai-analysis` disables the stage. Missing provider settings produce an
  explicit `disabled_not_configured` run summary.

Cache keys include normalized finding evidence, model, prompt/schema/cache
semantics, and confirmed context revision. Run diagnostics are stored in
`ai_analysis_metrics.json`: selected/analyzed/cached/unavailable/skipped/review
counts, sanitizer redactions, token usage, latency, and estimated cost when
pricing environment variables are configured.

## Reproducible evaluation

`utils.ai_evaluation` does not call an LLM. It matches exported findings to
human labels using public technical anchors and reports applicability
agreement/coverage, review and failure rates, wrong false-positive decisions,
and human remediation ratings for supported/actionable/verifiable advice.

```bash
uv run python -m utils.ai_evaluation --results normalized.json \
  --write-label-template labels.json

uv run python -m utils.ai_evaluation --results normalized.json \
  --labels labels.json --output ai_evaluation.json
```

Confidence is the model's statement, not a proven or calibrated probability.
The report labels this layer as advisory and preserves the scanner/deterministic
result beside it.
