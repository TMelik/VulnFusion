---
type: Safety Control
title: Polite Demo Scanning
description: Conservative scanner profile and explicit live/offline ZAP choices for authorized demos.
resource: configs/examples/polite_demo_config.yaml
tags: [vulnfusion, scanning, safety, rate-limit, zap, demo]
status: stable
generated:
  by: codex/gpt-5
  at: 2026-08-08
---

# Polite Demo Scanning

Use `configs/examples/polite_demo_config.yaml` only against an authorized
target. Its default live path is deliberately small:

- Nmap discovery on common web ports with bounded rate/retries;
- Nuclei medium-to-critical templates at 5 requests/second, concurrency 2,
  bulk size 1, and no failed-request retry;
- Wapiti, Nikto, and ZAP disabled to avoid overlapping DAST traffic.

```bash
uv run python main.py --target https://example.com --scanner all \
  --scan-config configs/examples/polite_demo_config.yaml
```

## Explicit ZAP choices

Enable one conservative live ZAP pass with:

```bash
uv run python main.py --target https://example.com --scanner all \
  --scan-config configs/examples/polite_demo_config.yaml \
  --with-zap
```

`--with-zap` activates `configs/examples/polite_zap_template.yaml`: a
passive-only plan with a traditional spider limited to one thread, depth 2,
10 children, no form processing, and a 120-second profile timeout. Active
scanning remains off unless the operator separately adds
`--zap-active-scan`. `--with-zap` requires `--scanner all`.

If an authorized manual ZAP scan already exists, import its Traditional JSON
report without sending another ZAP request sequence:

```bash
uv run python main.py --target https://example.com --scanner all \
  --scan-config configs/examples/polite_demo_config.yaml \
  --zap-report reports/manual-zap-report.json
```

The importer validates target-host consistency, copies the report to the run's
`raw/` folder, normalizes it, and includes it in correlation, scoring, advisory
analysis, and the final report. It accepts ZAP Traditional JSON, not
HTML/XML/SARIF. `--zap-report` and `--with-zap` are mutually exclusive.

## Rate-limit boundary

The profile lowers load; it cannot discover or guarantee an unknown private or
adaptive target threshold. It never tries to bypass limits with identity/IP
rotation. Keep the run sequential, prefer frozen/offline evidence for judge
reproduction, and use staging for active DAST. A target response such as `429`
must be treated as a reason to stop or reschedule, not a challenge to evade.

Pre-scan context discovery is separately bounded to three successful same-site
pages and a small maximum request queue/attempt count. It is context gathering,
not another scanner.
