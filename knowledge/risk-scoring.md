---
type: Scoring Model
title: Runtime Risk Scoring
description: Deterministic risk_score/priority/risk_factors/risk_rationale computed per finding after dedupe, comparison, and asset context.
resource: utils/risk_scorer.py
tags: [vulnfusion, risk, scoring]
status: stable
sources:
  - id: risk_model
    title: Runtime Risk Model
    resource: /docs/risk_model.md
generated:
  by: claude/sonnet-5
  at: 2026-08-08
---

# Runtime Risk Scoring

`utils/risk_scorer.py` runs after
[/llm-duplicate-resolution.md](/llm-duplicate-resolution.md), comparison, and
optional `--asset-context-file` rules, so the scorer can use preserved
repeatability/history context and business-context adjustments (see
[/pipeline.md](/pipeline.md)).

## Exported public fields

- `risk_score`: deterministic integer, 0-100
- `priority`: `P0`-`P4`
- `risk_factors`: structured scoring inputs, e.g.
  `technical_severity`, `exploit_likelihood`, `business_context`,
  `evidence_quality`, `final_score`, `final_priority`
- `risk_rationale`: concise human-readable explanation

When at least one finding is scored, the exported summary also includes
`summary.by_priority`.

## CVE intelligence input

`utils/vuln_intel.py` provides offline CVSS/EPSS/KEV enrichment from local
CSV/JSON sources, feeding `technical_severity` and `exploit_likelihood`.
Disable the whole stage with `--no-risk-scoring` / `--no-score` /
`global.risk_scoring: false`.

Internal scoring caches and canonical CVSS/EPSS/KEV sidecars are not part of
the export contract — see [/schema.md](/schema.md) for what actually ships.
