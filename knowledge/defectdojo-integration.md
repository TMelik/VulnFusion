---
type: Integration
title: DefectDojo Integration
description: Uploads scan findings to DefectDojo, either raw-per-scanner or as a merged Generic Findings export.
resource: utils/defectdojo_client.py
tags: [vulnfusion, defectdojo, integration]
status: stable
generated:
  by: claude/sonnet-5
  at: 2026-08-08
---

# DefectDojo Integration

Two upload modes, controlled by `VULN_MANAGER_DEFECTDOJO_UPLOAD_MODE` /
`--defectdojo-upload-mode`:

- **`raw-per-scan`** (default) — uploads one scanner-native raw artifact per
  scanner execution to `/api/v2/reimport-scan/`, using DefectDojo's own
  parser for that scanner. Does not use normalized findings, dedupe, risk
  scoring, or `defectdojo_generic.json`.
- **`merged`** — exports the final normalized, deduplicated, scored,
  export-sanitized view (`normalized.json`, see [/schema.md](/schema.md) and
  [/risk-scoring.md](/risk-scoring.md)) to `defectdojo_generic.json` via
  `utils/defectdojo_export.py`, then uploads that JSON.

## Config resolution

`utils/config_loader.py:load_defectdojo_config` reads `configs/defectdojo.config`
(INI) for defaults: Product Type / Product / Engagement names, per-scanner
scan-type/parser mapping (`[defectdojo.scan_types]`), expected raw artifact
format per scanner (`[defectdojo.artifacts]`), and test-title mapping. CLI
flags and `VULN_MANAGER_DEFECTDOJO_*` env vars override the config file.

Name resolution against real DefectDojo objects prefers exact matches; safe
case/whitespace-only mismatches resolve automatically unless
`--defectdojo-strict-names` is set. `auto_create_context=true` (default)
lets DefectDojo create missing Product Type/Product/Engagement on import.

See the README's "DefectDojo Integration" section for the full CLI/env
reference and troubleshooting table.
