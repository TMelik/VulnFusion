---
type: Index
title: VulnFusion Knowledge Bundle
description: Open Knowledge Format (OKF) map of VulnFusion's core concepts for LLM/agent consumption.
tags: [vulnfusion, okf, index]
status: stable
generated:
  by: claude/sonnet-5
  at: 2026-08-08
---

# VulnFusion Knowledge Bundle

This bundle is an [Open Knowledge Format](https://github.com/GoogleCloudPlatform/knowledge-catalog/blob/main/okf/SPEC.md)
(OKF v0.2) map of VulnFusion's core concepts, intended for agent/LLM
navigation. It complements — and does not replace — the prose documentation
in [`/docs`](../docs/walkthrough.md) and the source code itself. Each concept
file here is short, links to its authoritative source file, and points to
deeper prose docs where they exist.

## Concepts

| File | Type | Summary |
|------|------|---------|
| [pipeline.md](pipeline.md) | Pipeline | Context → scan/import → correlate → score → advise → save/report flow |
| [schema.md](schema.md) | Data Schema | Scanner-native schema plus strict correlation, risk, and advisory AI fields |
| [unified-vulnerability-db.md](unified-vulnerability-db.md) | Knowledge Store | YAML-backed scanner knowledge and versioned structured LLM decision caches |
| [llm-duplicate-resolution.md](llm-duplicate-resolution.md) | Pipeline Stage | Cross-scanner duplicate resolution via a cheap filter + strict structured LLM decision |
| [llm-finding-analysis.md](llm-finding-analysis.md) | Pipeline Stage | Bounded evidence-cited applicability/remediation advice, cache, metrics, and evaluation |
| [llm-effectiveness-evidence.md](llm-effectiveness-evidence.md) | Evaluation Guide | How to compare raw, deterministic, single-prompt, and VulnFusion LLM deduplication |
| [hackathon-evaluation-rubric.md](hackathon-evaluation-rubric.md) | Evaluation Rubric | Five judging criteria, current evidence, estimated score, and gaps to exceptional results |
| [pre-scan-context.md](pre-scan-context.md) | Pipeline Stage | Implemented bounded HTTP/DNS/TLS context, human confirmation, and isolated OKF reuse |
| [polite-scanning.md](polite-scanning.md) | Safety Control | Polite default profile plus explicit passive ZAP and offline-import routes |
| [risk-scoring.md](risk-scoring.md) | Scoring Model | Deterministic risk score / priority / rationale computed per finding |
| [defectdojo-integration.md](defectdojo-integration.md) | Integration | Raw-per-scan and merged upload paths to DefectDojo |
| [scanners/index.md](scanners/index.md) | Index | The five scanner integrations (Nmap, Nuclei, Wapiti, Nikto, ZAP) |

## Conventions

- Every concept file's frontmatter has a `resource` field pointing to the
  primary source file it documents.
- Links between concept files are bundle-relative (start with `/`), per OKF
  convention, e.g. `/schema.md`.
- See [log.md](log.md) for the bundle's update history.
