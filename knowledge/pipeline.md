---
type: Pipeline
title: Scan Pipeline
description: Bounded context, scan/import, normalize, correlate, compare, score, advise, sanitize, and report for one target.
resource: main.py
tags: [vulnfusion, pipeline, llm, safety]
status: stable
sources:
  - id: walkthrough
    title: VulnFusion Pipeline Walkthrough
    resource: /docs/walkthrough.md
generated:
  by: codex/gpt-5
  at: 2026-08-08
---

# Scan Pipeline

`main.py` runs the normal workflow in this order:

```text
optional context discovery/reuse
  -> scan or offline ZAP import
  -> normalize
  -> structured LLM duplicate resolution
  -> optional comparison
  -> manual + confirmed site context
  -> deterministic risk scoring
  -> structured advisory LLM analysis
  -> export sanitization / validation / save / HTML report
```

1. **Site context** — `--discover-context` gathers bounded same-site HTTP,
   DNS, and TLS evidence and proposes a strict profile. Human confirmation
   writes an isolated OKF revision. A fresh confirmed profile is otherwise
   reused automatically; `--no-context-reuse` opts out. See
   [/pre-scan-context.md](/pre-scan-context.md).
2. **Scan / normalize** — `ScannerOrchestrator` runs selected scanners and
   converts their native output to [/schema.md](/schema.md). With the polite
   profile, `--with-zap` explicitly enables a conservative passive ZAP plan;
   `--zap-report` imports an existing Traditional JSON report instead.
3. **Correlation** — the resolver uses deterministic candidate gates plus a
   strict structured LLM decision. Only `same=true` at confidence `>= 0.85`
   merges; uncertainty remains reviewable. See
   [/llm-duplicate-resolution.md](/llm-duplicate-resolution.md).
4. **Comparison** — with `--compare`, `utils/comparator.py` adds history state
   and refuses a baseline from a different target.
5. **Context and risk** — optional `--asset-context-file` rules and supported
   fields from a human-confirmed site profile feed the deterministic scorer.
   Site context never changes dedup identity. See
   [/risk-scoring.md](/risk-scoring.md).
6. **Advisory finding analysis** — when an LLM provider is configured, the top
   25 priority findings receive strict applicability, summary, separate
   AI-priority, and remediation advice. It is
   cached, bounded, secret-sanitized, and fail-open. Use
   `--no-ai-analysis` or `--ai-analysis-limit`. See
   [/llm-finding-analysis.md](/llm-finding-analysis.md).
7. **Export / report** — `utils/export_sanitizer.py` allowlists public
   structured data, `utils/schema.py` validates it, and the run writes
   `normalized.json`, `report.html`, and sanitized
   `ai_analysis_metrics.json`.

Utility flows such as `--probe-only` and `--list-scanners` exit before final
save/report. A provider failure never removes scanner findings or deterministic
risk results.
