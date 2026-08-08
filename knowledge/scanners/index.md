---
type: Index
title: Scanner Integrations
description: The five scanner integrations, all implementing the common BaseScanner interface.
resource: scanners/base.py
tags: [vulnfusion, scanners, index]
status: stable
generated:
  by: claude/sonnet-5
  at: 2026-08-08
---

# Scanner Integrations

Every scanner subclasses `scanners/base.py:BaseScanner` (ABC) and implements
`scan(target, options) -> raw_results` and
`normalize(raw_results) -> list[finding]`, where each finding matches
[/schema.md](/schema.md). `BaseScanner` also declares transport capability
flags used by the HTTP/2 compatibility routing in `orchestrator.py`:
`supports_http2_direct`, `supports_http1_force`, `supports_proxy`,
`supports_http2_bridge`.

| File | Scanner | Native output |
|------|---------|----------------|
| [nmap.md](nmap.md) | Nmap | XML |
| [nuclei.md](nuclei.md) | Nuclei | JSONL |
| [wapiti.md](wapiti.md) | Wapiti | JSON |
| [nikto.md](nikto.md) | Nikto | JSON |
| [zap.md](zap.md) | OWASP ZAP | traditional JSON (via Automation Framework) |

Select scanners with `--scanner {all,nmap,nuclei,wapiti,nikto,zap}`, or via
`scanners:` entries in a `--scan-config` file. `--list-scanners` reports
availability and versions.
