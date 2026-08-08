---
type: Pipeline
title: Scan Pipeline
description: Orchestrates scan, normalize, dedupe, compare, score, and save/report stages for one target.
resource: orchestrator.py
tags: [vulnfusion, pipeline]
status: stable
sources:
  - id: walkthrough
    title: Scanner-Native Pipeline Walkthrough
    resource: /docs/walkthrough.md
generated:
  by: claude/sonnet-5
  at: 2026-08-08
---

# Scan Pipeline

`main.py` drives `orchestrator.py:ScannerOrchestrator` through a fixed stage
order for every run:

```text
scan / normalize -> llm duplicate resolution -> compare -> asset context -> risk scoring -> save / report
```

1. **Scan / Normalize** — `ScannerOrchestrator` runs the selected scanners
   (see [/scanners/index.md](/scanners/index.md)) and each scanner's
   `normalize()` converts raw output into the shared finding shape defined in
   [/schema.md](/schema.md).
2. **LLM Duplicate Resolution** — see [/llm-duplicate-resolution.md](/llm-duplicate-resolution.md).
3. **Compare** — `utils/comparator.py` assigns `status` (`NEW` / `PERSISTENT`
   / `CHANGED` / `FIXED`) and `changed_fields` against the previous scan when
   `--compare` is passed. Hard-fails if the target slug of the baseline and
   current run don't match (`COMPARATOR SAFETY CHECK FAILED`).
4. **Asset Context** — optional `--asset-context-file` rules
   (`utils/asset_context.py`) are applied before scoring.
5. **Risk Scoring** — see [/risk-scoring.md](/risk-scoring.md).
6. **Save / Report** — findings are export-sanitized (`utils/export_sanitizer.py`),
   validated (`utils/schema.py:validate_finding`), written to
   `data/<target_slug>/<timestamp>/normalized.json`, and rendered to
   `report.html` by `utils/report_generator.py`.

Every run folder also contains `scan_results.json` (raw aggregation) and,
optionally, `defectdojo_generic.json` — see
[/defectdojo-integration.md](/defectdojo-integration.md).

Utility flows `--probe-only` and `--list-scanners` exit before the save/report
stage.
