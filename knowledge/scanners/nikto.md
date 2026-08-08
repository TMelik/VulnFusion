---
type: Scanner
title: Nikto Scanner
description: Web server scanner, routed through the HTTP/2 compatibility adapter when needed; supports degraded/partial reporting.
resource: scanners/nikto_scanner.py
tags: [vulnfusion, scanner, nikto]
status: stable
generated:
  by: claude/sonnet-5
  at: 2026-08-08
---

# Nikto Scanner

Native output is JSON. Adapter-dependent like Wapiti (see
[/scanners/index.md](/scanners/index.md)). Options: `--nikto-timeout`,
`--nikto-tuning`, `--nikto-args`. Soft-failure markers (e.g. error-limit
termination) are surfaced in scanner execution metadata and reports as
degraded/partial rather than a silent clean success — see
`utils/knowledge_sync.py`'s `NiktoKnowledgeAdapter`, which uses OSVDB IDs as
`category`.
