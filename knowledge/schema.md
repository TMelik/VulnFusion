---
type: Data Schema
title: Normalized Finding Schema (v2.0)
description: The unified per-finding JSON shape every scanner's normalize() output conforms to, plus its validator.
resource: utils/schema.py
tags: [vulnfusion, schema]
status: stable
generated:
  by: claude/sonnet-5
  at: 2026-08-08
---

# Normalized Finding Schema (v2.0)

`utils/schema.py` defines `SCHEMA_VERSION = "2.0"` and
`validate_finding(finding) -> (is_valid: bool, errors: list[str])`. Validation
is pipeline-stage aware: only base fields are required on raw pre-normalized
findings; optional fields are checked when present, so post-processed
findings get deeper validation.

## Required base fields

| Field | Rule |
|-------|------|
| `vulnerability_name` | non-empty string |
| `severity` | one of `critical \| high \| medium \| low \| info` |
| `asset_id` | string (empty allowed for host-level findings) |
| `description` | string |
| `remediation` | string |
| `meta` | dict (sub-fields optional) |

## Fields added by later pipeline stages

- Dedup fields (from [/llm-duplicate-resolution.md](/llm-duplicate-resolution.md)):
  `match_level`, `merge_confidence`, `found_by`, `duplicate_count`,
  `source_findings`, and the public structured LLM `correlation` advisory.
- Comparison fields (`utils/comparator.py`): `status`, `changed_fields`.
- Risk fields (from [/risk-scoring.md](/risk-scoring.md)): `risk_score`,
  `priority`, `risk_factors`, `risk_rationale`.

## Structured `meta` sub-fields

`scanner`, `timestamp`, `host`, `scheme`, `path`, `parameter`, `method`,
`raw_id`, `cve_id` (strings); `port` (`int` or `None`); `query_keys`,
`cve_ids` (`list[str]`); `cwe` (`str` or `int`).

## Top-level output envelope

```json
{
  "schema_version": "2.0",
  "generated_at": "2026-02-22T11:34:31Z",
  "target": "example.com",
  "all_findings": [...]
}
```

When at least one finding is scored, the envelope also includes
`summary.by_priority` alongside the severity summary.
