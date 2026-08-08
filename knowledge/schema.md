---
type: Data Schema
title: Normalized Finding Schema (v2.0)
description: Scanner-native finding contract plus strictly validated correlation, risk, and advisory AI extensions.
resource: utils/schema.py
tags: [vulnfusion, schema, llm, validation]
status: stable
generated:
  by: codex/gpt-5
  at: 2026-08-08
---

# Normalized Finding Schema (v2.0)

`utils/schema.py` defines `SCHEMA_VERSION = "2.0"` and
`validate_finding(finding) -> (is_valid, errors)`. Base fields remain
scanner-native; later pipeline fields are validated when present.

## Required scanner fields

| Field | Rule |
|---|---|
| `vulnerability_name` | non-empty string |
| `severity` | `critical`, `high`, `medium`, `low`, or `info` |
| `asset_id` | string |
| `description` | string |
| `remediation` | string |
| `meta` | object |

Common `meta` anchors include scanner, host, scheme, port, path, parameter,
method, raw scanner ID, CVE IDs, and CWE. Merged `source_findings` retain
scanner provenance.

## Fields from later stages

- correlation: `match_level`, `merge_confidence`, `found_by`,
  `duplicate_count`, `source_findings`, and the safe public `correlation`
  object;
- comparison: `status`, `changed_fields`;
- deterministic risk: `risk_score`, `priority`, `risk_factors`,
  `risk_rationale`;
- advisory AI: `ai_analysis_status`, `applicability`, `ai_remediation`.

For `completed` or `cached` AI advice, the strict contract is:

```json
{
  "ai_analysis_status": "completed",
  "applicability": {
    "status": "likely_valid",
    "confidence": 0.88,
    "reason": "Evidence-grounded explanation",
    "evidence_ids": ["finding-evidence"]
  },
  "ai_remediation": {
    "steps": ["One to five advisory steps"],
    "verification": ["One to five verification steps"]
  }
}
```

Allowed applicability statuses are `likely_false_positive`,
`valid_but_not_applicable`, `likely_valid`, and `needs_review`. Confidence is
numeric in `0..1`; nested objects have exact fields and bounded non-empty
lists. `unavailable` and `skipped_limit` carry no fabricated advice.

## Top-level envelope

```json
{
  "schema_version": "2.0",
  "generated_at": "2026-08-08T11:34:31Z",
  "target": "example.com",
  "asset_knowledge": {
    "profile_revision": "...",
    "description": "Human-confirmed site description",
    "risk_context": {}
  },
  "ai_analysis_summary": {},
  "all_findings": []
}
```

When scoring is active, `summary.by_priority` is included. The export sanitizer
strictly allowlists `asset_knowledge`, `correlation`, per-finding advice, and
the run summary before final validation/reporting. Internal prompts, raw model
responses, cache keys, secret values, and scoring sidecars are not public
contract fields.
