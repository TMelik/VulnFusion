---
type: Safety Control
title: Polite Demo Scanning
description: Conservative request and scanner selection profile for authorized hackathon demos.
resource: configs/examples/polite_demo_config.yaml
tags: [vulnfusion, scanning, safety, rate-limit, demo]
status: stable
generated:
  by: codex/gpt-5
  at: 2026-08-08
---

# Polite Demo Scanning

Use `configs/examples/polite_demo_config.yaml` for an authorized public-site
demo. It keeps the existing sequential orchestrator and limits the run to:

- Nmap discovery on common web ports, with bounded probe rate and retries.
- Nuclei medium-to-critical templates, capped at 5 requests per second, with
  concurrency 2, bulk size 1, and no failed-request retry.

Wapiti, Nikto, and ZAP are disabled because running several overlapping DAST
engines increases total target traffic even when the engines run sequentially.
Use them only in a separately authorized deep scan, preferably against staging.

Run the profile with:

```bash
uv run python main.py --target example.com --scanner all \
  --scan-config configs/examples/polite_demo_config.yaml
```

If a manual ZAP scan already exists, add its Traditional JSON report without
starting ZAP again:

```bash
uv run python main.py --target example.com --scanner all \
  --scan-config configs/examples/polite_demo_config.yaml \
  --zap-report reports/manual-zap-report.json
```

`--zap-report` implies that the ZAP source is enabled, imports the report once
outside the per-service live scan plan, validates the report host, and copies
the source into the run's `raw/` directory. The imported findings then use the
normal ZAP normalizer and participate in deduplication, risk scoring, and the
combined report. The MVP accepts ZAP Traditional JSON, not HTML/XML/SARIF.

The profile reduces blocking risk but cannot discover or guarantee a site's
private or adaptive threshold. It does not bypass rate limits by changing IP or
identity. Target-side `429`/`Retry-After` detection and safe cancellation of
later live web scanners remain a separate follow-up increment.
