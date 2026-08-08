---
type: Scanner
title: Nuclei Scanner
description: Template-based vulnerability scanner with direct native HTTP/2 support.
resource: scanners/nuclei_scanner.py
tags: [vulnfusion, scanner, nuclei]
status: stable
generated:
  by: claude/sonnet-5
  at: 2026-08-08
---

# Nuclei Scanner

Native output is JSONL. Nuclei is the only scanner with direct native HTTP/2
support (`-fh2` flag on HTTPS HTTP/2-only targets), so it stays on its direct
path even when other scanners need the compatibility bridge (see
[/scanners/index.md](/scanners/index.md)). Findings carry `raw_id`
(template ID), CVE/CWE identifiers, and tags used as `category` by
`utils/knowledge_sync.py`'s `NucleiKnowledgeAdapter` (see
[/unified-vulnerability-db.md](/unified-vulnerability-db.md)).

Pinned version is set via `NUCLEI_VERSION` in the `Dockerfile`; templates are
fetched at image build time. `--severity` filters findings.
