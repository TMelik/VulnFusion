---
type: Evaluation Rubric
title: Hackathon Evaluation Rubric and Self-Assessment
description: Criterion-specific evidence anchors, current VulnFusion evidence, honest score estimate, and the work required for exceptional results.
resource: docs/llm_effectiveness_evidence.md
tags: [vulnfusion, hackathon, evaluation, evidence, llm, armenia]
status: draft
sources:
  - id: effectiveness-guide
    title: Proving the Value of LLM Deduplication
    resource: /docs/llm_effectiveness_evidence.md
  - id: project-roadmap
    title: Hackathon Roadmap
    resource: /docs/hackathon_roadmap.md
generated:
  by: codex/gpt-5
  at: 2026-08-08
---

# Hackathon Evaluation Rubric and Self-Assessment

This is an internal estimate, not an official judge score. It records what the
repository can prove today and what evidence is still missing.

## Criterion-specific evidence anchors

| Criterion | 0 points | 3 points — adequate | 5 points — exceptional |
|---|---|---|---|
| 1. Idea quality and public-interest fit | The problem is unclear, out of scope, or has no identified user. | A clear Armenia-relevant problem and user are identified, and the benefit is plausible. | The local need and user workflow are well understood, with specific and measurable potential impact. |
| 2. Working prototype and appropriate LLM use | There is no working prototype, or the LLM/VLM is only decorative. | The main workflow works on a representative case, and the model has a credible role. | The system works end to end across varied cases and shows why an LLM/VLM is better than a simpler alternative. |
| 3. Evaluation and supporting evidence | There is no meaningful evaluation evidence. | An appropriate test set, examples, metric, or rubric is used and results are reported. | Evaluation is realistic and reproducible, includes a baseline or error analysis, and supports the team's claims. |
| 4. Model limitations, failure modes, and safety | Relevant limitations, failure modes, or safety risks are not identified. | Important risks and failures are identified, with basic safeguards or human escalation. | Risky cases are tested systematically, and effective mitigation, abstention, escalation, or monitoring is demonstrated. |
| 5. Real-world feasibility and reproducibility | The project uses toy assumptions, cannot be reproduced, or has no credible path beyond the demo. | It uses realistic data or labeled stand-ins, documents setup, and describes a plausible deployment path. | It fits real workflows and covers integration, cost, latency, privacy, and maintenance; reproduction is straightforward. |

## Current VulnFusion estimate

| Criterion | Estimate | Evidence already present | Main gap before 5 points |
|---|---:|---|---|
| 1. Idea quality and public-interest fit | 3/5 | Scanner noise and duplicate findings are a clear security problem. VulnFusion has a plausible user: a security analyst or small security team combining several scanners. Public USAID, Armenian government, and CyberHUB-AM sources support the local skills-gap, critical-infrastructure, and threat context. | Connect those public facts to a concrete scanner-review workflow and demonstrate a measurable reduction in analyst work without hiding known vulnerabilities. |
| 2. Working prototype and appropriate LLM use | 3/5 | The end-to-end pipeline scans, normalizes, deduplicates, compares, scores, exports, and renders reports. Structured LLM decisions are limited to ambiguous pairs. | Show 5–10 ambiguous pairs where deterministic logic is insufficient, with human labels, structured LLM decisions, review escalation, and incorrect-merge counts. |
| 3. Evaluation and supporting evidence | 3/5 | The repository includes labeled pair and cluster fixtures, pair/cluster metrics, provenance checks, history checks, and a reproducible Oracle evaluation. | Run a timed human-only versus VulnFusion-assisted comparison on matched controlled datasets and publish the results, errors, model/version details, latency, and cost. |
| 4. Model limitations, failure modes, and safety | 5/5 | Strict JSON parsing, a `0.85` merge threshold, no-merge behavior on invalid responses and provider failures, `needs_review` escalation, versioned cache semantics, secret sanitization, and tests for risky cases are implemented. | Demonstrate these safeguards clearly during the presentation and keep a small monitoring summary in the report. |
| 5. Real-world feasibility and reproducibility | 3/5 | Five real scanner integrations, Docker support, DefectDojo integration, caching, retry/failure handling, timing data, and documented configuration provide a credible deployment path. | Publish a safe reproducible demo dataset and one-command benchmark; report privacy assumptions, live cost, latency, and maintenance needs. |

**Working estimate: 17/25.**

The strongest current area is model safety. Public sources can establish the
Armenia-specific need without a new survey. The largest remaining gap is a
small, realistic human workflow comparison that measures VulnFusion's effect.

## Evidence needed for an exceptional result

### 1. Prove the local need

- Use the [USAID Armenia Digital Ecosystem Country Assessment](https://www.usaid.gov/sites/default/files/2024-07/USAID_DECA_Armenia.pdf)
  for the mismatch between cybersecurity needs and available expertise.
- Use Armenia's official [Law on Cybersecurity](https://hightech.gov.am/articles/laws/%D5%AF%D5%AB%D5%A2%D5%A5%D5%BC%D5%A1%D5%B6%D5%BE%D5%BF%D5%A1%D5%B6%D5%A3%D5%B8%D6%82%D5%A9%D5%B5%D5%A1%D5%B6-%D5%B4%D5%A1%D5%BD%D5%AB%D5%B6-%D6%85%D6%80%D5%A5%D5%B6%D6%84)
  and the official [Cybersecurity Hackathon announcement](https://old.hightech.gov.am/en/tegekatvakan-kentron/ayl/norutyunner/cybersecurity-hackathon)
  for critical-infrastructure relevance and specialist-capacity priorities.
- Use CyberHUB-AM's [2024](https://mdi.am/en/archives/2183) and
  [2025](https://mdi.am/en/archives/42043) reporting for examples of the local
  threat environment.
- Identify the user narrowly: an analyst or small team processing output from
  several scanners.
- Demonstrate the workflow pain through the controlled evaluation: raw finding
  count, duplicate decisions, report time, and manual corrections.
- Claim assistance, not replacement: the system helps scarce specialists work
  faster but does not replace security engineers or solve all cyber risk.

### 2. Prove that the LLM is necessary

Use 5–10 ambiguous duplicate pairs. For each pair, record the deterministic
result, the structured LLM decision, and a human label. Report agreement,
review escalations, and incorrect automatic merges. Show one useful semantic
merge, one dangerous merge that was prevented, and one uncertain pair
escalated to human review.

The four-mode raw/deterministic/one-prompt/VulnFusion benchmark is useful later,
but the small ambiguous-pair panel is enough to explain the LLM's specific role
in the hackathon demo.

### 3. Make the evaluation realistic

- Prepare two matched controlled datasets with known seeded vulnerabilities.
- Compare a human creating a report from raw evidence with a human reviewing
  and correcting VulnFusion's report.
- Use two participants with an A/B crossover when possible. With one
  participant, use separate matched datasets and vary the mode order.
- Record total time, final unique findings, known vulnerabilities found,
  misses, false merges, false splits, manual corrections, and preserved source
  links.
- Record the model name and version, calls, cache hits, latency, and cost.
- Publish the task instructions and error analysis, not only the best number.

### 4. Demonstrate safety

During the demo, show that:

- malformed JSON does not merge findings;
- a timeout or provider error does not merge findings;
- confidence below `0.85` creates `needs_review`;
- an external uncertain candidate does not change a merged cluster's status;
- scanner-native names and evidence remain unchanged.

### 5. Make reproduction easy

- Provide a safe dataset that contains no private targets or secrets.
- Add one command that prepares or runs the reproducible system side of the
  comparison.
- Produce a small HTML or Markdown comparison report with human-only and
  VulnFusion-assisted time, accuracy/safety metrics, latency, and cost.
- Document provider configuration, privacy assumptions, and expected failure
  behavior.

Related evidence planning is in
[/llm-effectiveness-evidence.md](/llm-effectiveness-evidence.md).
