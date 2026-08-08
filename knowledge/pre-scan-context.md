---
type: Design Note
title: Pre-scan Asset Context and Bounded OSINT
description: Current implementation boundary and a safe plan for building source-backed target context before scanning.
resource: utils/site_context.py
tags: [vulnfusion, asset-context, osint, llm, safety]
status: active
sources:
  - id: site-context
    title: Bounded Site Context Workflow
    resource: /utils/site_context.py
  - id: asset-context
    title: Deterministic Asset Context Loader
    resource: /utils/asset_context.py
  - id: target-probe
    title: Target Transport Probe
    resource: /utils/target_probe.py
generated:
  by: codex/gpt-5
  at: 2026-08-08
---

# Pre-scan Asset Context and Bounded OSINT

## Current state

The bounded hackathon path is implemented in `utils/site_context.py`:

- `--discover-context` crawls the starting page and at most two same-site
  links before scanner execution;
- bounded title, meta description, and visible text are sent in one strict
  structured LLM request when the provider is configured;
- the CLI shows the suggested description, business processes, and sources;
- the user can accept, replace the description, or skip;
- confirmation creates an isolated OKF v0.2 bundle under
  `data/asset_knowledge/<site-key>/` before the scanners run;
- the final HTML report shows the confirmed description, reviewer, and profile
  revision without changing risk scoring or duplicate anchors;
- provider failure falls back to a reviewable title/meta description rather
  than blocking the scan.

The older deterministic Asset Context remains separate:

- `--asset-context-file` accepts local JSON/YAML rules for
  `asset_criticality`, `internet_exposed`, `environment`, `sensitive_data`, and
  `requires_auth`.
- Those rules are applied after duplicate resolution and history comparison,
  immediately before deterministic risk scoring.
- The pre-scan target probe detects reachability, URL scheme, and HTTP/1.1 or
  HTTP/2 support. It is a transport check, not OSINT.
- There is no DNS/TLS/ASN enrichment, Wikipedia or general web search, deep
  crawl, or shared cross-domain organization knowledge in the demo path.
- Structured LLM dedup currently receives only finding-local technical fields.
  It does not receive the manual business context or external OSINT.
- The unified vulnerability database stores normalized finding knowledge and
  duplicate-decision cache records. It is not a website or organization wiki.

## Context needed before a scan

Start with owner-supplied facts because public OSINT cannot reliably determine
business criticality:

- exact authorized targets and excluded targets;
- organization/service name and short purpose;
- production, staging, or development environment;
- public, authenticated, or internal access;
- important user journeys and critical functions;
- expected data classes, without copying real sensitive data;
- known technology and hosting information;
- maintenance owner and preferred remediation constraints.

Then add a small passive public profile:

- canonical host, DNS records, IP/ASN, and TLS certificate names and dates;
- redirect chain, HTTP headers, page title, and declared technology hints;
- `robots.txt`, `security.txt`, sitemap, and public API/documentation links;
- official About, service-description, privacy, and contact pages;
- optional Wikipedia/Wikidata and web-search results when they clearly refer to
  the same organization.

Do not turn this into aggressive reconnaissance. Respect scan authorization,
request limits, robots/policy constraints where applicable, and provider terms.

## Safe context object

Store facts and inferences separately in the review draft. Every external claim
needs provenance:

```yaml
asset_profile:
  target: https://service.example.am
  generated_at: 2026-08-08T10:00:00Z
  facts:
    - key: service_purpose
      value: Citizen appointment portal
      source_url: https://service.example.am/about
      fetched_at: 2026-08-08T09:58:00Z
      confidence: 1.0
  inferences:
    - key: likely_authentication
      value: true
      reason: Public page links to a sign-in flow
      source_urls:
        - https://service.example.am/
      confidence: 0.72
      needs_review: true
```

The LLM may summarize or propose context, but inferred facts must remain marked
as inference. An inference must not automatically increase asset criticality or
the deterministic risk score. In the final OKF Markdown, use OKF's `sources`,
`generated`, `verified`, and `stale_after` trust fields. If model confidence is
retained, keep it on an inference as a producer extension; do not present it as
source credibility.

## Where this context helps

- **Scan planning:** choose allowed scanners and avoid irrelevant checks.
- **Applicability:** explain whether a finding matches the observed stack or
  reachable feature.
- **Remediation:** make advice fit the observed service while citing evidence.
- **Prioritization:** provide reviewer-visible business context after a human
  confirms it.
- **Reporting:** explain what the service appears to do and why a finding may
  matter.

General organization OSINT is not a strong duplicate anchor. Deduplication must
still depend mainly on endpoint/path, parameter, method, port/service, CVE, and
scanner identity. Only narrow technical facts such as a source-backed product
or service version should be added to the pair payload, and they must never
override a conflicting instance anchor.

## Recommended minimal increment

For the hackathon, implement only the stable demo path:

1. Add an optional bounded `context` stage before scanner execution.
2. Crawl the homepage and at most two same-origin links.
3. Extract bounded title, meta description, and visible text with source URLs.
4. Ask the LLM for one short description and several business processes, tied
   to those source IDs.
5. Show the result and let the user accept, replace the description, or skip.
6. Only after confirmation, write a separate Google OKF v0.2 Markdown bundle
   for the site/domain and record human verification.
7. Run the scan and record the confirmed bundle revision.

Do not block the demo on web-search APIs, DNS/ASN enrichment, deep crawling, or
a sophisticated cache. They can be provider adapters after the core workflow
is demonstrated. Unconfirmed suggestions remain outside deterministic scoring.

Evaluate whether context improves results with the same findings twice:
without context and with the source-backed context. Human reviewers should
score applicability/remediation correctness and count unsupported claims.

## Per-site knowledge isolation

Target knowledge must not be written into the repository's general
`knowledge/` bundle and must not be mixed across customers or domains. Store it
under the runtime data directory:

```text
data/asset_knowledge/
  example-com--<stable-hash>/
    index.md
    site-profile.md
    business-processes.md
    log.md
```

Each directory is one independent OKF v0.2 knowledge bundle. Its stable key is
derived from the normalized hostname plus a short hash of the canonical site
identity. HTTP and HTTPS variants of the same hostname share a bundle. A
different hostname, subdomain, non-default service port, or domain gets a
different bundle by default.

An optional, human-confirmed `organization_id` may state that several bundles
belong to the same company, but it must not cause their facts, crawl results,
or LLM context to merge automatically. Search snippets or a similar company
name are never enough to join bundles. Scan results may reference the confirmed
bundle and record a snapshot identifier, but each site remains the authority
for its own context.
