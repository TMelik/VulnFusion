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

Use two connected evaluations.

The main product evaluation is deliberately simple:

1. a human creates a report from raw scanner evidence;
2. a human reviews and corrects a VulnFusion report made from matched evidence.

Measure total time, known vulnerabilities found, missed vulnerabilities, false
merges, false splits, manual corrections, and preserved source links. Use two
matched datasets so that remembering the first answer does not make the second
run faster. The ground truth is the list of vulnerabilities deliberately
seeded in a controlled application or frozen fixture.

This comparison answers the practical question: does VulnFusion save scarce
analyst time without hiding known vulnerabilities?

To isolate the LLM's contribution, label 5–10 ambiguous duplicate pairs and
compare the deterministic result, the structured LLM decision, and the human
label. Count correct decisions, review escalations, and incorrect automatic
merges.

A larger follow-up benchmark can run the same labeled findings through four
modes:

1. raw scanner findings;
2. deterministic deduplication only;
3. one large prompt asking a model to deduplicate the whole report;
4. VulnFusion Structured LLM Dedup.

Measure false merges, false splits, exact cluster matches, review cases,
analyst time, model calls, latency, cache hits, and estimated cost. False
merges are the most important safety metric because they can hide separate
vulnerabilities inside one record.

## Armenia-specific public evidence

The local-need claim does not depend on a survey that the team cannot complete.
Use these public sources:

- [USAID Armenia Digital Ecosystem Country Assessment](https://www.usaid.gov/sites/default/files/2024-07/USAID_DECA_Armenia.pdf):
  reports a gap between cybersecurity needs and available expertise;
- Armenia's official [Law on Cybersecurity](https://hightech.gov.am/articles/laws/%D5%AF%D5%AB%D5%A2%D5%A5%D5%BC%D5%A1%D5%B6%D5%BE%D5%BF%D5%A1%D5%B6%D5%A3%D5%B8%D6%82%D5%A9%D5%B5%D5%A1%D5%B6-%D5%B4%D5%A1%D5%BD%D5%AB%D5%B6-%D6%85%D6%80%D5%A5%D5%B6%D6%84):
  shows the national importance of vital sectors and critical information
  infrastructure;
- the official [Cybersecurity Hackathon announcement](https://old.hightech.gov.am/en/tegekatvakan-kentron/ayl/norutyunner/cybersecurity-hackathon):
  identifies specialist capacity and critical-infrastructure cooperation as
  priorities;
- CyberHUB-AM's [2024](https://mdi.am/en/archives/2183) and
  [2025](https://mdi.am/en/archives/42043) publications: provide public local
  threat examples.

Together they support this careful problem statement: Armenia is expanding
digital services while cybersecurity expertise is scarce and threats are
active. VulnFusion helps small teams spend less time turning noisy scanner
output into a traceable report.

They do not prove that companies refuse to hire security engineers, that
VulnFusion replaces experts, or that it protects all critical infrastructure.
Product effectiveness must come from the controlled human comparison above.

## Where the LLM helps

- Different scanners can use different titles for the same vulnerability.
- Similar titles can still refer to different endpoints, parameters, methods,
  ports, services, CVEs, or scanner identities.
- Low-confidence positive decisions stay separate and receive `needs_review`.

Deterministic rules should continue to handle obvious duplicates. The LLM
should only reason about the remaining gray-zone pairs.

## Visual evidence in the report

The final HTML report renders an AI Correlation Graph only when structured LLM
decisions exist. It connects preserved scanner source findings to the final
merged record with a solid green path. Low-confidence candidates use a dashed
amber path to a `needs_review` result, making it clear that they remained
separate. The graph is capped at 10 cases and all detailed evidence remains in
the finding cards.

This visualization supports the LLM-value claim because it shows the actual
semantic merges, provenance, confidence, and human escalation. It is not a
generic severity chart and it does not change any deduplication decision.

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

For the hackathon, a credible minimum is two controlled matched datasets, a
human-only versus VulnFusion-assisted timing comparison, and 5–10 ambiguous
pairs for the LLM-role check. A later full benchmark should contain 50–100
labeled pairs and 10–20 labeled cluster cases from multiple scanners. It should
record the model, input dataset, outputs, latency, calls, and cost so another
person can repeat the experiment.

The full explanation and simple English and Armenian versions are in
[/docs/llm_effectiveness_evidence.md](/docs/llm_effectiveness_evidence.md).

The judging criteria, current score estimate, and evidence gaps are tracked in
[/hackathon-evaluation-rubric.md](/hackathon-evaluation-rubric.md).
