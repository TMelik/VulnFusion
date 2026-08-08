# Scanner-Native Pipeline Walkthrough

## Summary

The active pipeline keeps scanner-native finding text as the source of truth,
then adds deterministic prioritization before export. The final JSON and HTML
report are built from normalized scanner fields, dedupe/comparison state, and
public runtime risk fields rather than internal debug structures.

The report content comes directly from the normalized scanner fields, including
`vulnerability_name`, `severity`, `asset_id`, `description`, `remediation`, and
other scanner-derived fields. Runtime scoring adds public fields such as
`risk_score`, `priority`, `risk_rationale`, and `risk_factors`.

## Current Pipeline Order

```text
scan / normalize → llm duplicate resolution → compare → asset context → risk scoring → save / report
```

This matches `main.py`:

1. Scan and normalize findings from the selected scanners.
2. Apply LLM duplicate resolution and preserve merged provenance without
   exporting duplicate traces.
3. Apply comparison state when `--compare` is enabled so repeatability/history
   can inform later scoring.
4. Apply optional `--asset-context-file` rules to current findings.
5. Score findings with the runtime risk model.
6. Sanitize export payloads, validate them, save JSON, and render the report.

Normal scan runs render the HTML report automatically after save. Utility flows
such as `--probe-only` and `--list-scanners` exit before the save/report stage.

The YAML knowledge store remains in the project as a duplicate-resolution cache
for LLM decisions and related provenance data.

## Source Of Truth

The report content comes directly from the normalized scanner fields.

Important consequences:

- `Description:` in the HTML report comes from the normalized `description` field.
- `Remediation:` in the HTML report comes from the normalized `remediation` field.
- Exported scanner-derived fields remain the source of truth for user-visible
  finding content.
- Scanner metadata remains in `meta` and can still carry useful identifiers
  such as `raw_id`, `cve_id`, `cve_ids`, and `cwe`.
- Merged `source_findings` still preserve source evidence and provenance.
- Runtime risk fields are exported, but duplicate traces, transport internals,
  and other debug-only sidecars are still stripped.

Removed from the exported runtime/output flow:

- duplicate-resolution traces used only for debugging
- transport/probe execution overlays
- internal fingerprints and matching helpers
- raw meta sidecars used to derive scoring inputs

## Exported Contract

`utils/schema.py` now documents the active exported finding contract, including:

- scanner-native finding fields
- dedupe/provenance fields
- comparison status/change-tracking labels
- public runtime risk fields
- `summary.by_priority` when scoring is present

Validation stays strict. Malformed `risk_score`, `priority`, `risk_rationale`,
or other unsupported exported fields are rejected instead of being silently accepted.

## Report Rendering

`utils/report_generator.py` keeps the report readable while surfacing risk:

- finding title and severity
- affected asset
- scanner provenance
- normalized description and remediation
- comparison status when present
- priority and risk score badges
- `Why this is prioritized` from `risk_rationale`
- `Priority Distribution` when scored findings are present

Higher-priority findings naturally sort first when scoring is active.

## Programmatic Example

```python
import json

with open("data/example.com/latest/normalized.json", encoding="utf-8") as handle:
    results = json.load(handle)

for finding in results["all_findings"]:
    print(f"Title: {finding['vulnerability_name']}")
    print(f"Severity: {finding['severity']}")
    print(f"Priority: {finding.get('priority')}")
    print(f"Risk: {finding.get('risk_score')}")
    print(f"Why prioritized: {finding.get('risk_rationale')}")
```

## Relevant Files

1. `main.py`
2. `utils/asset_context.py`
3. `utils/risk_scorer.py`
4. `utils/report_generator.py`
5. `utils/schema.py`
6. `utils/export_sanitizer.py`
7. `utils/result_summary.py`

## Conclusion

The runtime pipeline keeps scanner-derived finding content intact while using
LLM duplicate resolution, comparison, optional asset context, and deterministic
risk scoring to improve prioritization before save/report. Exported JSON and
HTML now include public risk fields while continuing to strip internal-only
debug structures.
