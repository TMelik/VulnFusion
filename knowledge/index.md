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
| [pipeline.md](pipeline.md) | Pipeline | End-to-end scan → normalize → dedupe → compare → score → save/report flow |
| [schema.md](schema.md) | Data Schema | The normalized finding schema (v2.0) and its validator |
| [unified-vulnerability-db.md](unified-vulnerability-db.md) | Knowledge Store | YAML-backed store caching LLM dedupe decisions and synced scanner vulnerability metadata |
| [llm-duplicate-resolution.md](llm-duplicate-resolution.md) | Pipeline Stage | Cross-scanner duplicate resolution via a cheap filter + strict structured LLM decision |
| [llm-effectiveness-evidence.md](llm-effectiveness-evidence.md) | Evaluation Guide | How to compare raw, deterministic, single-prompt, and VulnFusion LLM deduplication |
| [hackathon-evaluation-rubric.md](hackathon-evaluation-rubric.md) | Evaluation Rubric | Five judging criteria, current evidence, estimated score, and gaps to exceptional results |
| [pre-scan-context.md](pre-scan-context.md) | Design Note | Current Asset Context boundary and a safe bounded-OSINT plan for source-backed pre-scan context |
| [polite-scanning.md](polite-scanning.md) | Safety Control | Conservative Nmap + rate-limited Nuclei profile for authorized demos |
| [risk-scoring.md](risk-scoring.md) | Scoring Model | Deterministic risk score / priority / rationale computed per finding |
| [defectdojo-integration.md](defectdojo-integration.md) | Integration | Raw-per-scan and merged upload paths to DefectDojo |
| [scanners/index.md](scanners/index.md) | Index | The five scanner integrations (Nmap, Nuclei, Wapiti, Nikto, ZAP) |

## Conventions

- Every concept file's frontmatter has a `resource` field pointing to the
  primary source file it documents.
- Links between concept files are bundle-relative (start with `/`), per OKF
  convention, e.g. `/schema.md`.
- See [log.md](log.md) for the bundle's update history.
