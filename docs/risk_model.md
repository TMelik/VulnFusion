# Runtime Risk Model

`utils/risk_scorer.py` is now part of the active runtime pipeline.

Current pipeline order:

```text
scan / normalize -> llm duplicate resolution -> compare -> apply asset context -> risk scoring -> validate -> save / report
```

`main.py` applies risk scoring after duplicate resolution and comparison so the
scorer can use preserved repeatability/history context, and after optional
`--asset-context-file` rules so business context can influence the final score.

## What Gets Exported

When scoring runs, each exported finding may include these public fields:

- `risk_score`: deterministic integer from 0 to 100
- `priority`: `P0` to `P4`
- `risk_factors`: structured scoring inputs and adjustments
- `risk_rationale`: concise explanation of why the finding was prioritized

When at least one scored finding is present, the exported summary also includes:

- `summary.by_priority`

These fields are present in:

- `normalized.json`
- JSON stdout from `uv run python main.py --json`
- `report.html`

Internal tracing fields are still stripped before export.

## Inputs Used By The Scorer

The scorer is deterministic and rule-based. It combines:

- technical severity from CVSS when present, otherwise normalized scanner severity
- exploit likelihood from EPSS and public exploit indicators when available
- KEV presence as an active-exploitation floor
- business context such as asset criticality, environment, internet exposure,
  sensitive-data handling, and auth requirements
- evidence quality such as confidence, degraded execution, and repeatability
  against previous scans when `--compare` provides history
- low-signal guardrails so generic header/banner/cookie-hardening findings do
  not inflate into urgent remediation items without stronger technical evidence

## Asset Context File

Use `--asset-context-file <path>` to provide optional JSON or YAML rules before
risk scoring. Supported shapes are:

```yaml
rules:
  - host: app.example.com
    path_prefix: /admin
    asset_criticality: high
    environment: production
    sensitive_data: true
```

or a top-level list with the same rule objects.

Each rule must match by at least one of:

- `asset_id`
- `host`
- `host_suffix`

Optional `path_prefix` narrows the match further.

If the file is missing or invalid, `main.py` fails clearly before scanning.

## Example Runtime Output

```json
{
  "vulnerability_name": "SQL Injection",
  "severity": "high",
  "asset_id": "https://app.example.com/login?id=1",
  "description": "The scanner detected injectable user-controlled input.",
  "remediation": "Use parameterized queries and validate user input.",
  "risk_score": 94,
  "priority": "P0",
  "risk_rationale": "Technical severity: CVSS v3.1 9.8 (64 points) and SQL injection class (+14) | Exposure and reachability: internet-exposed +6 -> +6 | Business impact: asset criticality high +4, environment production +3, sensitive data +4 -> +10 | Final score: 94/100 -> P0",
  "risk_factors": {
    "technical_severity": 78,
    "exploit_likelihood": 0,
    "business_context": 16,
    "evidence_quality": 0,
    "final_score": 94,
    "final_priority": "P0"
  }
}
```

Example summary fragment:

```json
{
  "summary": {
    "total_findings": 3,
    "by_severity": {"critical": 1, "high": 1, "medium": 1, "low": 0, "info": 0},
    "by_priority": {"P0": 1, "P1": 1, "P2": 1, "P3": 0, "P4": 0}
  }
}
```

## Report Behavior

When scored findings are present, the HTML report:

- shows priority and risk score badges on each finding card
- sorts higher-priority findings first
- renders `Why this is prioritized` from `risk_rationale`
- keeps the scanner-native or normalized scanner description text as the finding description
- shows scanner provenance with `Found by`
- adds a `Priority Distribution` summary section

## Compatibility Notes

- `--risk-scoring` and `--no-risk-scoring` control runtime risk scoring.
  `--no-score` is retained as a backwards-compatible alias for
  `--no-risk-scoring`.
- Older saved results that do not contain risk fields still validate and render.
- Export sanitization keeps public risk fields while continuing to remove
  duplicate-resolution traces and transport internals.
