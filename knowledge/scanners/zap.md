---
type: Scanner
title: OWASP ZAP Scanner
description: Headless ZAP scans driven by generated Automation Framework plans, run via Docker or a validated local binary.
resource: scanners/zap_scanner.py
tags: [vulnfusion, scanner, zap, owasp]
status: stable
generated:
  by: claude/sonnet-5
  at: 2026-08-08
---

# OWASP ZAP Scanner

The most complex scanner integration (by far the largest file). Runs
headlessly via a generated ZAP Automation Framework (AF) plan, resolved by
default from `configs/zap_test_template.yaml`, with runtime-owned fields
(context URLs, job parameters, report settings) patched in per target.
Executes via Docker (primary) or a local `zap.sh`/`zaproxy` binary after a
capability check.

Default jobs: `spider`, `spiderAjax`, `passiveScan-wait`. `--zap-active-scan`
adds an `activeScan` job if the resolved template doesn't already have one.
`report.template` is always forced to `traditional-json`, since that's the
format the pipeline's ZAP parser expects.

`--zap-report <path>` provides an offline alternative for a completed manual
scan. It accepts a ZAP Traditional JSON report, does not check or start a ZAP
runtime, validates that the requested target host is present, copies the input
into the current run's raw artifacts, and imports it exactly once. Those
findings use the same normalizer and downstream dedup/risk/report pipeline as a
live ZAP result.

Adapter-dependent like Wapiti/Nikto (see [/scanners/index.md](/scanners/index.md)).
ZAP risk `High` maps to unified severity `high`, not `critical` — see the
severity mapping table in the README's OWASP ZAP section. If Docker is
unavailable and no valid local binary is found, the scanner degrades
gracefully (clear error, pipeline continues) instead of crashing.
