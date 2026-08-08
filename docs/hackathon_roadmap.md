# Hackathon Roadmap (24h) — Safe AI Triage for Armenian Public-Interest Systems

## Hackathon rubric

One rubric applies to every team:

1. **Idea quality & fit** — solve a real Armenian public-interest problem.
2. **Evaluation & evidence** — test the system and show measured results.
3. **Model limits & safety** — identify model failure modes and mitigate them.
4. **Real-world plausibility** — use realistic data and make the result
   reproducible and deployable.

Every committed feature below must produce evidence for at least one of these
criteria. A feature that is merely impressive in a demo belongs in Tier B.

## Problem and defense story

### Problem hypothesis to validate

Armenia is expanding digital services while facing a shortage of cybersecurity
expertise and active cyber threats. Public-interest organizations and smaller
teams therefore need to use scarce specialist time carefully. Vulnerability
scanners help, but their overlapping output still requires manual analysis:
the analyst must find duplicates, preserve evidence, decide what needs review,
and turn many tool-specific records into one report.

Support the Armenia-specific part of this statement with public sources:

- the [USAID Armenia Digital Ecosystem Country Assessment](https://www.usaid.gov/sites/default/files/2024-07/USAID_DECA_Armenia.pdf)
  describes a mismatch between cybersecurity needs and available expertise;
- Armenia's official [Law on Cybersecurity](https://hightech.gov.am/articles/laws/%D5%AF%D5%AB%D5%A2%D5%A5%D5%BC%D5%A1%D5%B6%D5%BE%D5%BF%D5%A1%D5%B6%D5%A3%D5%B8%D6%82%D5%A9%D5%B5%D5%A1%D5%B6-%D5%B4%D5%A1%D5%BD%D5%AB%D5%B6-%D6%85%D6%80%D5%A5%D5%B6%D6%84)
  establishes the importance of vital sectors and critical information
  infrastructure;
- the Ministry of High-Tech Industry's [Cybersecurity Hackathon announcement](https://old.hightech.gov.am/en/tegekatvakan-kentron/ayl/norutyunner/cybersecurity-hackathon)
  explicitly calls for stronger specialist capacity and cooperation among
  critical-infrastructure actors;
- CyberHUB-AM's public [2024](https://mdi.am/en/archives/2183) and
  [2025](https://mdi.am/en/archives/42043) reports provide local examples of
  the changing threat environment.

These sources establish the public need, not VulnFusion's effectiveness. The
demo evaluation must separately test the narrower product claim: VulnFusion
can reduce an analyst's reporting time while preserving known vulnerabilities
and exposing uncertain merges for review.

Use careful language. VulnFusion assists existing specialists; it does not
replace security engineers, protect all critical infrastructure, or solve most
cybersecurity risk by itself.

### One-sentence solution

**VulnFusion turns overlapping scanner output into safe, evidence-grounded,
reviewable remediation guidance for Armenian public-interest services without
letting the LLM delete findings or directly control the risk score.**

### What existed before the hackathon

- scanner execution for Nmap, Nuclei, Wapiti, Nikto, and ZAP;
- normalization and comparison across scan runs;
- deterministic risk scoring and basic Asset Context;
- the active LLM-assisted duplicate path;
- HTML reporting and DefectDojo integration;
- the static OKF knowledge bundle in `knowledge/`.

### What the team adds in 24 hours

- secret sanitization before every external LLM boundary;
- structured and conservative semantic dedup decisions;
- evidence-grounded applicability and remediation fields;
- a report that separates deterministic risk from AI analysis;
- a small but real evaluation with quality, safety, latency, token, and cost
  measurements.

Scanner execution, normalization, comparison, and the deterministic scorer are
not rewritten.

## Reproducible demo scenario

Use only an authorized target. Prefer a local intentionally vulnerable service
or frozen scanner fixtures representing a fictional Armenian municipal/civic
portal. Do not scan a real Armenian public website without explicit permission.

The scenario should contain a small, understandable Asset Context:

```yaml
rules:
  - host: citizen-portal.demo.am
    path_prefix: /applications
    asset_criticality: high
    environment: production
    internet_exposed: true
    sensitive_data: true
    requires_auth: true
```

Keep two demo paths:

1. **Reproducible path:** frozen normalized findings and deterministic expected
   outputs for judges and local tests.
2. **Live path:** an authorized local scan plus configured LLM provider.

For a low-load public demo, use
`configs/examples/polite_demo_config.yaml`: Nmap discovery plus Nuclei capped at
5 requests per second. If a manual ZAP scan has already been completed, pass
its Traditional JSON report with `--zap-report`; this adds ZAP evidence to the
same pipeline without sending a second ZAP request sequence to the target.

The defense should work even if a scanner or LLM provider is temporarily
unavailable. A provider failure must leave the original findings and
deterministic risk results intact.

## Tier 0 — establish a trustworthy baseline

1. Fix or explicitly isolate the current DefectDojo configuration cascade so
   the repository has a known test baseline. At the time this plan was written,
   `uv run pytest -q` produced `671 passed, 47 failed, 3 skipped`, largely
   because DefectDojo is enabled without an API token.
2. Freeze one small demo dataset and record baseline output before AI changes.
3. Create a labeled evaluation sample before tuning prompts so the team does
   not grade only examples that already work.
4. Record the exact commands, model name, prompt/schema version, and fixture
   revision used for evaluation.

Tier 0 is part of **Evaluation & evidence** and **Real-world plausibility**. Do
not claim that the new work caused pre-existing tests to pass.

## Tier A — committed

### 1. Secret sanitizer at every outbound LLM boundary

Add `utils/secret_sanitizer.py` with recursive text sanitization for:

- `Authorization` and Bearer values;
- cookies and session identifiers;
- JWTs;
- common API-key formats and API-key headers;
- passwords in headers, JSON, form bodies, URLs, and curl examples.

Apply it immediately before constructing or sending every external LLM
request. Export/report sanitization remains a second defense-in-depth pass; it
is not the primary LLM safety boundary.

Use typed placeholders such as `[REDACTED:JWT]` and `[REDACTED:COOKIE]` so the
model still understands the evidence shape. Never log the original secret.

Evidence to show:

- a small corpus containing positive and negative redaction cases;
- redaction rate for seeded secrets;
- false-redaction count on benign evidence;
- a captured sanitized request preview containing no seeded secrets.

Estimated implementation time: **2–3h**.

Rubric: **Model limits & safety**, **Real-world plausibility**.

### 2. Structured, conservative semantic dedup

Replace the provider's unstructured `yes/no` payload with:

```json
{
  "same_vulnerability": true,
  "confidence": 0.92,
  "reason": "Same SQL injection on the same endpoint and parameter",
  "canonical_title": "SQL Injection in application lookup parameter"
}
```

Keep current candidate generation and merge materialization. Only the provider
decision adapter changes:

- `same_vulnerability=true` and `confidence >= 0.85` -> current merge path;
- `same_vulnerability=true` and lower confidence -> do not merge and mark
  `needs_review`;
- `same_vulnerability=false` -> do not merge;
- invalid JSON, timeout, or provider failure -> do not merge.

The same vulnerability class is not enough. Require at least one instance
anchor in the prompt/rules: matching endpoint/path, parameter, method,
port/service, CVE, or scanner-native identity. Keep thresholds as named
constants so they can be evaluated rather than hidden in prompt prose.

Evidence to show:

- precision, recall, F1, and false-merge count on the existing dedup fixtures;
- a small comparison of the previous decision path and structured path;
- at least two known failure/ambiguous cases rendered as `needs_review`.

Estimated implementation time: **2–3h**.

Rubric: **Evaluation & evidence**, **Model limits & safety**.

### 3. Applicability and evidence-grounded remediation

Use one structured LLM call per selected finding to add only these fields:

```json
{
  "applicability": {
    "status": "likely_valid",
    "confidence": 0.88,
    "reason": "The scanner evidence identifies the affected parameter"
  },
  "ai_remediation": {
    "steps": ["Use parameterized database queries"],
    "verification": ["Repeat the request with a safe SQL metacharacter corpus"]
  }
}
```

Allowed applicability statuses:

- `likely_false_positive`;
- `valid_but_not_applicable`;
- `likely_valid`;
- `needs_review`.

Guardrails:

- never delete or suppress the original finding;
- never modify deterministic `risk_score` or `priority`;
- retain scanner-native evidence and remediation separately;
- sanitize the prompt before transmission;
- cache by finding fingerprint + prompt/schema version;
- cap live analysis to a configurable number, defaulting to the top 10
  deterministic findings for the demo;
- fail open: retain the finding and record `ai_analysis_status=unavailable`;
- reject unknown enums, out-of-range confidence, or malformed JSON.

Evidence to show on a labeled sample of 15–30 findings:

- applicability accuracy or agreement with the human labels;
- malformed/failed response count;
- remediation groundedness scored with a simple human rubric: supported by
  evidence, actionable, and verifiable;
- latency, token usage, and estimated API cost per finding and per demo run.

Estimated implementation time: **3–4h**.

Rubric: all four criteria.

### 4. Report and evidence artifact

Update `report.html` to show the existing deterministic result and AI analysis
as separate layers:

```text
Canonical vulnerability
Found by: ZAP, Nuclei

Correlation confidence: 92%
Technical risk: 68 / P2

Applicability: Likely valid — 88%
Why: ...

Suggested remediation
...

Verification
...

AI limitation: advisory only; original finding retained
```

Add a compact run-level section with:

- number of findings analyzed and skipped;
- number requiring review;
- sanitizer redaction count, without secret values;
- LLM failures/fallbacks;
- total latency, tokens, and estimated cost when available.

Write the evaluation results to a versioned JSON or Markdown artifact so the
defense uses actual measured numbers rather than verbal claims.

Estimated implementation time: **2–3h**.

Rubric: **Evaluation & evidence**, **Model limits & safety**, **Real-world
plausibility**.

## Tier B — only after Tier A evidence is complete

### 5. Grounded `--ask "question"`

Add simple natural-language Q&A over a small set of relevant `knowledge/`
pages plus sanitized latest findings. Do not add a vector database during the
hackathon: keyword retrieval or a fixed top-k document selection is enough.

The answer must:

- cite the finding IDs and knowledge files it used;
- distinguish scanner evidence from AI inference;
- say that information is insufficient instead of inventing an answer;
- receive only sanitized findings;
- use bounded context and expose latency/token/cost diagnostics.

Evaluate it with 5–10 prepared questions, expected source documents, and a
small answer-groundedness rubric.

Estimated implementation time: **2–3h**.

### 6. OKF run page

When a scan needs an OKF run page, write it inside that site's independent
bundle as `runs/<run-id>.md`, with links to canonical findings, provenance,
prompt/schema version, the exact profile revision, and trust status. Never put
run pages from different sites into one target-knowledge bundle. Prefer one run
page over a large new file lifecycle with a page for every finding.

Keep this in Tier A only if OKF generation is an explicit judging requirement.

Estimated implementation time: **1–2h**.

### 7. Additional Asset Context

The current implementation is manual and post-dedup: `--asset-context-file`
adds five business fields before risk scoring. It does not perform OSINT or
feed a site profile into the LLM.

For the hackathon demo, keep the pre-scan context stage small:

1. crawl the homepage and at most two same-site links;
2. extract page title, meta description, and bounded visible text;
3. ask the configured LLM for one short description and a short list of
   business processes, with source IDs;
4. show the result in the CLI and let the user accept it, replace the
   description, or skip;
5. after confirmation, generate a separate
   Google OKF v0.2 bundle under
   `data/asset_knowledge/<domain-slug>--<stable-hash>/` with `index.md`,
   `profile.md`, and `log.md`;
6. run the scanners and record which confirmed profile revision was used.

Never mix target knowledge into the repository's general `knowledge/` bundle.
HTTP and HTTPS on the same host may share one target bundle, but different
hosts, subdomains, non-default service ports, and domains are isolated by
default. Multiple domain bundles may carry the same human-confirmed
`organization_id`; that relationship must not automatically merge their facts
or crawl data.

Do not use broad organization descriptions as duplicate evidence. Only narrow
technical context such as a source-backed product/version may supplement the
existing endpoint, parameter, method, port/service, CVE, and scanner anchors.

External web search, DNS/ASN enrichment, deep crawling, and a context cache are
follow-up work, not demo dependencies. [Google Custom Search JSON API](https://developers.google.com/custom-search/v1/overview)
is not a good new dependency because it is closed to new customers and
scheduled for shutdown for existing customers in 2027.

For a quick check, run one site with and without the confirmed description and
ask a human whether the context makes the report easier to understand. A larger
accuracy evaluation comes after the hackathon.

Estimated implementation time: **1–2h for the demo path**.

## Tier C — out of scope

- hybrid LLM risk adjustment and new score guardrails;
- full rewrite of dedup identity rules;
- dashboard or multi-user service;
- vector database/RAG infrastructure;
- large-scale evaluation or automated LLM-as-judge evaluation;
- automatic finding deletion or risk-score changes based on LLM output.

## 24-hour execution schedule

```text
00:00–01:30  Tier 0: baseline, fixture, labels, problem evidence
01:30–04:00  Secret sanitizer + safety tests
04:00–07:00  Structured dedup + dedup evaluation
07:00–11:00  Applicability/remediation + fail-open/cache/limits
11:00–14:00  Report integration and run diagnostics
14:00–18:00  Evaluation runs and evidence artifact
18:00–21:00  Reproducible demo, README, defense narrative
21:00–24:00  Buffer; Tier B only if Tier A is green
```

## Minimal evaluation design

Use fixed labels and report both successes and failures. Keep the main
evaluation understandable: compare a human working from raw evidence with a
human reviewing VulnFusion's report.

### Main workflow comparison: human-only vs VulnFusion-assisted

Prepare two small, matched datasets from a controlled vulnerable application
or frozen scanner fixtures. Seed and document the known vulnerabilities before
the test.

1. **Human-only:** give the analyst raw scanner evidence. Ask them to identify
   unique vulnerabilities, remove duplicates, prioritize them, preserve source
   evidence, and create the final report.
2. **VulnFusion-assisted:** run the matched evidence through VulnFusion. Ask the
   analyst to review merges and `needs_review` cases, correct mistakes, and
   approve the final report.
3. Record total time, final unique findings, known vulnerabilities found,
   missed vulnerabilities, false merges, false splits, manual corrections, and
   preserved evidence/source links.

Prefer two participants with an A/B crossover. If only one participant is
available, use two independent matched datasets and change which mode is run
first. Do not let a participant repeat the same dataset in both modes, because
memory would make the second run artificially faster.

The strongest simple result has this form: "review time fell from X to Y while
all N seeded vulnerabilities remained visible and no additional false merges
were introduced." Report the real result even if it is weaker.

### Small LLM-role check

The workflow comparison proves product value but does not isolate the LLM.
Add a panel of 5–10 ambiguous candidate pairs and compare:

- the deterministic result;
- the structured LLM decision;
- a human label made from the same evidence.

Report how many LLM decisions match the human label, how many are escalated to
review, and how many incorrect automatic merges occur. Show at least one useful
semantic merge, one prevented dangerous merge, and one uncertain review case.

The older four-mode comparison (raw, deterministic-only, one large prompt, and
VulnFusion) remains useful follow-up evidence, but it is not required for the
minimal hackathon evaluation.

### Component metrics

| Capability | Baseline | New system | Minimum metrics |
|---|---|---|---|
| Dedup | current deterministic/LLM decision | structured conservative decision | precision, recall, F1, false merges, review rate |
| Applicability | no AI applicability | structured advisory result | label agreement, coverage, review rate |
| Remediation | scanner text | evidence-grounded steps | supported/actionable/verifiable human ratings |
| Safety | no secret scrub at LLM boundary | outbound sanitizer | seeded-secret recall, false redactions |
| Operations | current timing | bounded AI layer | latency, tokens, estimated cost, failures |

The evaluation report must include:

- dataset size and label definitions;
- the human-only and VulnFusion-assisted task instructions;
- analyst time and manual corrections for both modes;
- model and prompt/schema version;
- exact command/configuration;
- aggregate metrics and several case-level examples;
- known limitations and observed failure modes;
- no fabricated measurements or hidden excluded cases.

## Explicit model limitations for the defense

- Scanner evidence can be incomplete or wrong; the LLM cannot prove
  exploitability.
- Similar titles can describe different vulnerability instances.
- Confidence is model-reported and not a calibrated probability unless the
  evaluation demonstrates calibration.
- Sanitization is pattern-based and cannot guarantee detection of every secret.
- Remediation may be generic or incompatible with an unknown implementation.
- Provider availability, latency, context limits, and cost constrain scale.

Mitigations used in the demo:

- deterministic candidate gates and conservative no-merge fallback;
- `needs_review` for ambiguity;
- original findings retained;
- deterministic risk score remains authoritative;
- typed structured outputs with strict validation;
- sanitization, bounded context, caching, call caps, and fail-open behavior;
- visible provenance and limitation text in the report.

## Definition of done

Tier A is complete only when:

1. A fresh clone can reproduce the demo from documented commands and frozen
   fixtures.
2. The known test baseline does not regress; ideally the full suite is green.
3. Seeded secrets are absent from captured outbound LLM request previews.
4. Provider failure does not remove findings or erase deterministic scoring.
5. Evaluation produces real saved metrics, including failures and review cases.
6. The report clearly separates evidence, deterministic outputs, and AI advice.
7. The defense identifies what existed before the hackathon and what the team
   implemented during the 24 hours.
