# Update Log

## 2026-08-08

- Created the initial OKF knowledge bundle (`generated/by: claude/sonnet-5`),
  covering the pipeline, normalized schema, unified vulnerability DB, LLM
  duplicate resolution, risk scoring, DefectDojo integration, and the five
  scanner integrations.
- Added the LLM effectiveness evidence guide, including the four-way benchmark
  design, safety metrics, the limits of Oracle evaluation, and a link to the
  bilingual English/Armenian explanation.
- Added the five criterion-specific judging anchors and an honest VulnFusion
  self-assessment, with current evidence and the work needed to reach the
  exceptional level for each criterion.
- Replaced the unavailable interview requirement with an Armenia-specific
  public-evidence package: USAID's digital ecosystem assessment, Armenia's
  cybersecurity law, the official cybersecurity hackathon announcement, and
  CyberHUB-AM threat reporting.
- Simplified the minimum evaluation to a timed human-only versus
  VulnFusion-assisted report task on matched controlled datasets, plus a small
  5–10 pair check that isolates the structured LLM's role.
- Implemented bounded pre-scan context: at most three same-site pages,
  allowlisted HTTP metadata, DNS A/AAAA, and allowlisted TLS metadata, all
  fail-open and source-cited. No external search API or deep crawler is used.
- Defined strict tenant/site isolation for generated target knowledge: one
  independent Google OKF v0.2 bundle per normalized host/service identity,
  stored outside the repository knowledge bundle, with cross-domain company
  relationships allowed only as explicit human-confirmed metadata.
- Added a strict LLM risk-context proposal and confirmation gate. Only
  human-confirmed context may affect deterministic scoring, while duplicate
  identity remains technical and context-independent.
- Added automatic reuse of non-stale confirmed site profiles, immutable
  `revisions/<sha256>.md` snapshots, and append-only per-site verification logs.
- Added a bounded AI Correlation Graph to the end of HTML reports. It visualizes
  preserved scanner sources, confirmed LLM merges, and dashed `needs_review`
  relationships while remaining hidden when no structured decisions exist.
- Added the `polite_demo_config.yaml` safety profile: sequential Nmap discovery,
  Nuclei capped at 5 requests per second with reduced concurrency and no retry,
  and overlapping DAST scanners disabled by default.
- Added `--with-zap` and `polite_zap_template.yaml` for an explicit bounded
  passive ZAP route; active scanning still requires `--zap-active-scan`.
- Added `--zap-report` for an existing manual ZAP Traditional JSON report. It
  enables the ZAP source without running ZAP, imports the report once, checks
  target-host consistency, and preserves a copy inside the run artifacts.
- Added automatic strict applicability/remediation analysis for the top 10
  deterministic findings, including context-aware cache semantics,
  `--no-ai-analysis`, `--ai-analysis-limit`, fail-open statuses, secret
  sanitization, token/latency/cost diagnostics, and report rendering.
- Added `utils.ai_evaluation`, which creates a human-label template and measures
  applicability agreement/coverage plus supported, actionable, and verifiable
  remediation ratings without making another model call.
- Updated the schema/export contract and knowledge pages so public
  `asset_knowledge`, `correlation`, advisory fields, and aggregate diagnostics
  survive strict sanitization while internal prompts/cache/debug data do not.
