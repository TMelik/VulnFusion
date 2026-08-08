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
- Documented that current Asset Context is manual and post-dedup, and added a
  proposed bounded pre-scan OSINT design with provenance, fact/inference
  separation, an OKF run artifact, and a rule that unconfirmed inference cannot
  change deterministic risk scoring.
- Defined strict tenant/site isolation for generated target knowledge: one
  independent Google OKF v0.2 bundle per normalized host/service identity,
  stored outside the repository knowledge bundle, with cross-domain company
  relationships allowed only as explicit human-confirmed metadata.
- Implemented the small hackathon context path: crawl at most three same-site
  pages, request a short structured summary, let the user accept/edit/skip, and
  write one human-verified OKF profile before scanner execution. External web
  search and deeper OSINT remain optional follow-up work.
- Added a bounded AI Correlation Graph to the end of HTML reports. It visualizes
  preserved scanner sources, confirmed LLM merges, and dashed `needs_review`
  relationships while remaining hidden when no structured decisions exist.
- Added the `polite_demo_config.yaml` safety profile: sequential Nmap discovery,
  Nuclei capped at 5 requests per second with reduced concurrency and no retry,
  and deeper overlapping DAST scanners disabled for the public-site demo path.
- Added `--zap-report` for an existing manual ZAP Traditional JSON report. It
  enables the ZAP source without running ZAP, imports the report once, checks
  target-host consistency, and preserves a copy inside the run artifacts.
