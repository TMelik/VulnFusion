---
type: Scanner
title: Wapiti Scanner
description: Web application vulnerability scanner, routed through the HTTP/2 compatibility adapter when needed.
resource: scanners/wapiti_scanner.py
tags: [vulnfusion, scanner, wapiti]
status: stable
generated:
  by: claude/sonnet-5
  at: 2026-08-08
---

# Wapiti Scanner

Native output is JSON. An adapter-dependent scanner: on HTTP/2-only targets
it is routed through the shared compatibility adapter (proxy or built-in
Python bridge) rather than talking HTTP/2 directly — see
[/scanners/index.md](/scanners/index.md). Options: `--wapiti-level`,
`--wapiti-modules`, `--wapiti-timeout`, `--wapiti-args`.
