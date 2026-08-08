---
type: Pipeline Stage
title: Pre-scan Site Context and Bounded OSINT
description: Fail-open local discovery, strict risk proposal, human confirmation, and isolated reusable OKF profiles.
resource: utils/site_context.py
tags: [vulnfusion, asset-context, osint, llm, safety, okf]
status: stable
sources:
  - id: site-context
    title: Bounded Site Context Workflow
    resource: /utils/site_context.py
  - id: asset-context
    title: Deterministic Asset Context Loader
    resource: /utils/asset_context.py
generated:
  by: codex/gpt-5
  at: 2026-08-08
---

# Pre-scan Site Context and Bounded OSINT

## Implemented flow

`--discover-context` runs before scanner execution:

1. Crawl at most three same-site HTML pages, with bounded bytes, text, queued
   links, attempts, and timeout.
2. Reuse allowlisted HTTP response metadata from those requests.
3. Resolve bounded DNS A/AAAA addresses without reverse lookup.
4. For HTTPS, collect allowlisted certificate and connection metadata: common
   names, dates, SAN DNS names, serial, TLS version, and cipher.
5. Send the bounded, secret-sanitized evidence in one strict LLM request.
6. Show the description, business processes, sources, uncertainties, and risk
   proposal to the user.
7. Only after confirmation, write the target's isolated OKF bundle and allow
   its supported values to influence deterministic scoring.

There is no external search API, ASN lookup, deep crawl, reverse DNS, or
cross-domain organization merge. HTTP, DNS, TLS, and provider failures are
recorded as uncertainty and do not block the scan. If the LLM is absent or
fails, a visible title/meta-description fallback is used.

## Strict risk proposal

The LLM must return this source-cited object as part of the context response:

```json
{
  "asset_criticality": "high|medium|low|unknown",
  "environment": "production|staging|development|test|unknown",
  "sensitive_data": true,
  "requires_auth": true,
  "confidence": 0.78,
  "reason": "Short source-grounded explanation",
  "evidence_ids": ["page-1"]
}
```

`sensitive_data` and `requires_auth` may be `null`. Unknown/null fallback
values never alter the score. Extra fields, invalid enums/types, out-of-range
confidence, or unknown evidence IDs invalidate the LLM response and trigger
the safe fallback.

The CLI confirms the description and proposed risk context together:

- Enter accepts the shown proposal;
- `--context-accept` provides non-interactive confirmation;
- `--context-description TEXT` replaces the description while confirming the
  displayed proposal;
- `skip` continues without confirmed context.

The displayed model/fallback source and uncertainty remain visible so a user
does not mistake inferred public context for owner-supplied fact.

## Scoring and dedup boundary

Only a human-confirmed profile can supply `asset_criticality`, `environment`,
`sensitive_data`, and `requires_auth` to deterministic risk scoring. Manual
`--asset-context-file` rules remain supported as a separate source.

Broad organization/site context never participates in duplicate identity.
Deduplication still depends on technical instance anchors: endpoint/path,
parameter, method, port/service, CVE, or scanner identity. This prevents two
similar business descriptions from merging unrelated findings.

## Per-site OKF isolation and history

Runtime knowledge is stored outside this repository bundle:

```text
data/asset_knowledge/
  example-com--<stable-hash>/
    index.md
    profile.md
    log.md
    revisions/
      <full-profile-sha256>.md
```

The stable key uses normalized host/service identity. HTTP and HTTPS default
ports for the same host share a bundle; different hosts, subdomains, or
non-default ports are isolated by default.

Each profile records human reviewer, sources, analysis source, risk context,
revision hash, and `stale_after`. Revision Markdown is immutable; `profile.md`
points to the current content and `log.md` appends updates/verifications.
Legacy human-verified profiles can be loaded safely, with missing risk context
normalized to unknown values.

Later runs automatically reuse a non-stale, human-confirmed profile and record
its revision in `asset_knowledge`. A stale profile is shown but does not affect
the run. Use `--no-context-reuse` to opt out or `--discover-context` to refresh.

## Safe uses

- explain what the service appears to do;
- improve evidence-grounded applicability/remediation advice;
- supply confirmed business inputs to deterministic scoring;
- make the report and evaluation reproducible through a profile revision.

It is not authorization to scan, proof of exploitability, proof of business
criticality, or shared organization truth.
