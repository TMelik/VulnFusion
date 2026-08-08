---
type: Scanner
title: Nmap Scanner
description: Network/port scanner; no HTTP/2 compatibility routing needed since it operates below the HTTP layer.
resource: scanners/nmap_scanner.py
tags: [vulnfusion, scanner, nmap]
status: stable
generated:
  by: claude/sonnet-5
  at: 2026-08-08
---

# Nmap Scanner

Fastest scanner path, requires no web server on the target. Native output is
XML, parsed and normalized into [/schema.md](/schema.md) findings. Options:
`--ports <spec>` (e.g. `"22,80,443"` or `"1-1000"`), plus NSE scripts and
extra args via `--scan-config`. Unaffected by HTTP/2 compatibility routing
(see [/scanners/index.md](/scanners/index.md)) — it operates below HTTP.

DefectDojo raw-per-scan uploads use native nmap XML with the `Nmap Scan`
parser (see [/defectdojo-integration.md](/defectdojo-integration.md)).
