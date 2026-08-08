---
type: Evaluation Guide
title: LLM Effectiveness Evidence
description: How VulnFusion should prove that limited LLM reasoning improves duplicate resolution over raw scanners, fixed rules, and one large prompt.
resource: docs/llm_effectiveness_evidence.md
tags: [vulnfusion, llm, evaluation, benchmark, dedupe]
status: draft
sources:
  - id: bilingual-guide
    title: Proving the Value of LLM Deduplication
    resource: /docs/llm_effectiveness_evidence.md
  - id: evaluation-runner
    title: Dedup Evaluation Runner
    resource: /utils/dedup_evaluation.py
generated:
  by: codex/gpt-5
  at: 2026-08-08
---

# LLM Effectiveness Evidence

VulnFusion is not one large prompt over scanner output. It is a deterministic
security pipeline that uses an LLM only for ambiguous duplicate candidates.

## Evidence model

Run the same labeled findings through four baselines:

1. raw scanner findings;
2. deterministic deduplication only;
3. one large prompt asking a model to deduplicate the whole report;
4. VulnFusion Structured LLM Dedup.

Measure false merges, false splits, exact cluster matches, review cases,
analyst time, model calls, latency, cache hits, and estimated cost. False
merges are the most important safety metric because they can hide separate
vulnerabilities inside one record.

## Where the LLM helps

- Different scanners can use different titles for the same vulnerability.
- Similar titles can still refer to different endpoints, parameters, methods,
  ports, services, CVEs, or scanner identities.
- Low-confidence positive decisions stay separate and receive `needs_review`.

Deterministic rules should continue to handle obvious duplicates. The LLM
should only reason about the remaining gray-zone pairs.

## Why a single prompt is not the product

A single prompt does not provide stable IDs, scanner normalization, preserved
evidence, provenance, deterministic premerge, a strict response contract,
confidence thresholds, versioned caching, failure handling, history
comparison, or safe exports. These system guarantees are part of VulnFusion's
value.

## Current proof boundary

`utils/dedup_evaluation` currently uses an Oracle client that knows the labels.
It proves that the pipeline, clustering, provenance, and metrics behave
correctly. It does not yet prove the decision quality of a live LLM.

A live benchmark should contain 50–100 labeled pairs and 10–20 labeled cluster
cases from multiple scanners. It should record the model, input dataset,
outputs, latency, calls, and cost so another person can repeat the experiment.

The full explanation and simple English and Armenian versions are in
[/docs/llm_effectiveness_evidence.md](/docs/llm_effectiveness_evidence.md).
