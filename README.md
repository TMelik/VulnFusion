# Vulnerability Scanner — Thesis-Ready Pipeline

A production-oriented vulnerability scanning pipeline with scanner-native normalized findings, change tracking, and a comprehensive pytest suite. The core pipeline is production-ready; experimental transport paths remain clearly marked.

## Features

✅ **Multi-Scanner**: Nmap, Nuclei, Wapiti, Nikto, ZAP (OWASP)  
✅ **Schema v2.0**: Versioned output with mandatory field validation  
✅ **Change Tracking**: Field-level diffs (CHANGED/NEW/PERSISTENT/FIXED)  
✅ **Target Validation**: Hard-fail on baseline mismatches  
✅ **No Data Loss**: Duplicate fingerprints preserved via `defaultdict(list)`  
✅ **Scanner-Native Findings**: Reports and JSON output come directly from normalized scanner fields  
✅ **DefectDojo Integration**: Default raw per-scanner uploads plus optional merged Generic Findings export/upload  
✅ **ZAP Automation Framework**: OWASP ZAP runs headlessly via generated Automation Framework plans with Docker or a validated local ZAP binary fallback  
✅ **Production-Oriented Core**: Self-contained HTML reports built from normalized scanner data, with experimental transport paths called out explicitly  
✅ **Docker**: Single Kali Linux container with all scanners and Python-based adapter tooling pre-installed  

---

## Running with Docker

### Prerequisites

- [Docker](https://docs.docker.com/get-docker/) installed and running
- (Optional) [Docker Compose](https://docs.docker.com/compose/) v2+

### 1. Build the image

```bash
cd vuln-manager
docker build -t vuln-manager:latest .
```

Build time: ~3–7 min on first run (downloads Kali packages, Python dependencies, the pinned nuclei binary, and templates).

### 2. Verify scanner availability

```bash
# Safe default — lists all scanners and their status
docker run --rm vuln-manager:latest

# Equivalent explicit form
docker run --rm vuln-manager:latest python3 main.py --list-scanners
```

Expected output — all scanners should show **Available**:

```
Available Scanners:
  nmap:    Available
  nuclei:  Available  (v3.7.1)
  wapiti:  Available
  nikto:   Available
  zap:     Available

HTTP/2 Compatibility Adapters:
  bridge:   Available
```

### 3. Run a scan (one-shot)

```bash
docker run --rm \
  --env-file .env \
  -v "$(pwd)/data:/app/data" \
  vuln-manager:latest \
  python3 main.py --target example.com --scanner all
```

Results land in `./data/<target>/<timestamp>/` on the host.
Normal scan runs write `report.html` automatically; use `--no-report` or `global.report: false` when you want to skip it.
The image does not bake `.env` into `/app`; pass secrets at runtime with `--env-file .env` or explicit `-e` flags.

### 4. Scan specific scanners

```bash
# Nmap only (fastest, no web server required)
docker run --rm -v "$(pwd)/data:/app/data" \
  vuln-manager:latest \
  python3 main.py --target scanme.nmap.org --scanner nmap

# ZAP passive web scan (headless Automation Framework plan)
docker run --rm -v "$(pwd)/data:/app/data" \
  vuln-manager:latest \
  python3 main.py --target https://example.com --scanner zap --zap-timeout 600
```

### 5. Using Docker Compose

```bash
# List scanners (default)
docker compose run --rm vuln-manager

# Run a full scan
docker compose run --rm vuln-manager \
  python3 main.py --target example.com --scanner all --compare
```

`docker-compose.yml` forwards the local project `.env` values into the runtime container environment for the generic LLM settings under `VULN_MANAGER_LLM_*`. This keeps Docker Compose behavior aligned with local Python execution.

### Volume / output folder layout

| Host path | Container path | Purpose |
|-----------|---------------|---------|
| `./data/` | `/app/data/`  | All scan run folders, JSON results, HTML reports |

After a scan:

```
./data/<target_slug>/<timestamp>/
├── raw/                   # Raw scanner outputs
├── effective_scan_config.json
├── scan_results.json      # Aggregated raw findings
├── normalized.json        # Fully processed pipeline output
├── defectdojo_generic.json # Optional DefectDojo Generic Findings Import export
└── report.html            # HTML vulnerability report
```

### ZAP in the container

For automation, the ZAP scanner resolves `configs/zap_test_template.yaml` by default, patches the runtime-owned fields for the current target, writes a per-run ZAP Automation Framework plan, and executes it headlessly with the ZAP stable image. Passing `--zap-af-plan` swaps in your own template instead. If Docker is unavailable, the same resolved plan can be run by a local `zap.sh`/`zaproxy` binary only after a lightweight local capability check confirms command-mode/autorun support.

### Optional: Host networking (LAN / localhost targets, Linux only)

By default the container uses standard Docker bridge networking (works for all internet targets). If you need to scan `localhost` or a LAN host, use the provided host-network override:

```bash
# One-shot docker run
docker run --rm --network host \
  -v "$(pwd)/data:/app/data" \
  vuln-manager:latest \
  python3 main.py --target 192.168.1.1 --scanner nmap

# Docker Compose with override
docker compose -f docker-compose.yml -f docker-compose.host-net.yml \
  run --rm vuln-manager \
  python3 main.py --target 192.168.1.1 --scanner nmap
```

> **Note**: `--network host` is not supported on Docker Desktop for macOS or Windows.

### Limitations

| Limitation | Notes |
|-----------|-------|
| ZAP direct HTTP/2 | Not claimed; HTTP/2-only targets use the built-in Python bridge when needed |
| ZAP is slow | Allow 10–20 min via `--zap-timeout 1200` (default) |
| Nuclei version | Pinned to `v3.7.1`; update `NUCLEI_VERSION` in Dockerfile to upgrade |
| Nuclei templates | Fetched at build time; update inside container with `nuclei -update-templates` |
| LAN/localhost scanning | Requires `--network host` (Linux only — see above) |
| Windows Docker Desktop | Host networking not supported |


## Quick Start

### Installation

```bash
git clone <repo-url> && cd vuln-manager
curl -LsSf https://astral.sh/uv/install.sh | sh
uv sync

# Install scanners (at least one required)
# Nuclei:  https://github.com/projectdiscovery/nuclei
# Nmap:    sudo apt install nmap
# Wapiti:  install the wapiti CLI package for your OS
# Nikto:   sudo apt install nikto
# ZAP:     Docker (see "OWASP ZAP Scanner" section below)
```

### Simple Usage

For web targets, the tool now probes the target automatically:
- tries `https://` first
- falls back to `http://` only if HTTPS could not be confirmed
- detects whether HTTPS supports HTTP/2, HTTP/1.1, or both, and prefers HTTP/1.1 when both are available
- keeps direct-capable scanners on their native path
- starts a local compatibility adapter automatically when an adapter-dependent scanner needs one

Examples:

```bash
# Simplest web scan: scheme + HTTP version are auto-detected
uv run python main.py --target example.com

# Run only ZAP against an explicit URL
uv run python main.py --target https://example.com --scanner zap

# Probe only: print normalized target + detected HTTP behavior
uv run python main.py --target example.com --probe-only

# Conservative repeatable demo: Nmap discovery + Nuclei capped at 5 requests/second
uv run python main.py --target example.com --scanner all \
  --scan-config configs/examples/polite_demo_config.yaml

# Add a completed manual ZAP scan without starting ZAP again
uv run python main.py --target example.com --scanner all \
  --scan-config configs/examples/polite_demo_config.yaml \
  --zap-report reports/manual-zap-report.json

# Require an HTTP/1.1-compatible path
uv run python main.py --target https://example.com --http-mode http1

# Require HTTP/2; this fails clearly if the selected scanner path cannot guarantee it
uv run python main.py --target https://example.com --http-mode http2

# Force the built-in bridge for adapter-dependent scanners
uv run python main.py --target https://example.com --scanner zap --http2-adapter-mode bridge
```

You usually do not need to pass `--http2-bridge-url` for normal runs. In `auto` mode the tool prefers HTTP/1.1 when the target accepts both HTTP/1.1 and HTTP/2, and starts the built-in bridge only for scanners that need compatibility on HTTP/2-only targets.
Normal scan runs write `report.html` automatically. `--probe-only` and `--list-scanners` exit before the save/report stage, and you can opt out of the HTML report with `--no-report` or `global.report: false`.

### Basic Usage

```bash
# Single scan (web targets are probed automatically and report.html is written by default)
uv run python main.py --target example.com --scanner all

# With comparison to previous scan
uv run python main.py --target example.com --scanner all --compare

# Probe only
uv run python main.py --target example.com --probe-only

# Integration demo (baseline → comparison → diff)
uv run python demo_integration.py --target example.com
```

---

## Run Folder Structure

Every scan produces an isolated folder:

```
data/<target_slug>/<timestamp>/
├── raw/
│   ├── nuclei_<target>_<ts>.json
│   ├── nmap_<target>_<ts>.json
│   └── ...
├── scan_results.json    # Raw aggregation  (schema_version: "2.0")
├── normalized.json      # Fully processed  (schema_version: "2.0")
├── defectdojo_generic.json  # Optional Generic Findings Import export
└── report.html          # HTML visualization
```

Both JSON files include `schema_version: "2.0"` and `generated_at` (ISO 8601 UTC).

---

## Pipeline Stages

| # | Stage | Output |
|---|-------|--------|
| 0 | **Optional Site Context** | `--discover-context` crawls up to three same-site pages, proposes a short description, asks for human confirmation, and writes an isolated per-site OKF bundle |
| 1 | **Scan / Normalize** | Normalized findings collected from the selected scanners |
| 2 | **LLM Duplicate Resolution** | Same-target cross-scanner findings that pass a cheap similarity gate are compared through a strict structured LLM decision flow; final output preserves merged scanner provenance, not duplicate traces |
| 3 | **Compare** | Status: NEW / PERSISTENT / CHANGED / FIXED, plus repeatability/history context for later scoring |
| 4 | **Asset Context** | Optional JSON/YAML rules from `--asset-context-file` are applied to current findings before scoring |
| 5 | **Risk Scoring** | Deterministic `risk_score`, `priority`, `risk_factors`, `risk_rationale`, and `summary.by_priority` are derived |
| 6 | **Save** | `normalized.json` with normalized scanner findings plus public risk/prioritization fields |
| 7 | **Report** | `report.html` built from scanner-derived finding fields plus runtime priority/risk presentation |

---

## Output Contract

The active runtime exports normalized scanner findings plus deterministic public
prioritization fields. The pipeline still treats scanner-native text as the
source of truth, then adds additive risk context after duplicate resolution,
comparison, and optional asset-context application.

Allowed exported content:
- scanner-originated finding text and identifiers such as `vulnerability_name`,
  `description`, `remediation`, `severity`, `references`, `evidence`, `cve_id`,
  `cve_ids`, `raw_id`, and target location fields
- dedupe provenance such as `found_by` and preserved `source_findings`
- comparison state labels such as `status` and `changed_fields`
- public runtime risk fields: `risk_score`, `priority`, `risk_factors`,
  and `risk_rationale`
- summary buckets including `summary.by_priority` when scoring is present
- a compact `asset_knowledge` reference when a human-confirmed site profile was
  created before the scan
- minimal execution/report organization metadata such as `generated_at`,
  `tool_versions`, and file paths

Removed from exported JSON/HTML/CLI payloads:
- duplicate-resolution traces and other internal-only matching diagnostics
- transport/probe execution sidecars that are useful for orchestration but not
  part of the public finding contract
- internal fingerprints and duplicate-matching helpers
- raw post-processing sidecars stored under `meta` for scoring internals such as
  canonical CVSS/EPSS/KEV/business-context cache fields

---

## Active Duplicate Flow

- The legacy fingerprint-based deduplicator still exists in `utils/deduplicator.py`, but the normal CLI flow does not call it.
- The active path uses same-target matching from the normalized finding fields already present in the project: `host`, `scheme`, `port`, `path`, `query_keys`, and `parameter`.
- Same-target cross-scanner candidates go through a cheap pre-LLM filter that checks overlap such as shared CVE/CWE identifiers and normalized title similarity before the API is called.
- Only same-target pairs that pass that cheap filter are sent to the configured LLM endpoint.
- The LLM must return one strict structured JSON decision containing
  `same_vulnerability`, `confidence`, `reason`, and `canonical_title`.
- Duplicate decisions are cached in the unified YAML-backed knowledge store, and the final merged finding preserves `source_findings` provenance without exporting raw comparison traces.
- When structured LLM correlations exist, the end of `report.html` contains a
  bounded AI Correlation Graph. Solid green links show scanner findings merged
  into one result; dashed amber links show findings retained for human review.
  The section is omitted when there are no LLM decisions.

## Unified Vulnerability Database

- Default path: `./data/unified_vulnerabilities.yaml`
- Acts as the project's YAML-backed duplicate-resolution cache
- Persisted as human-readable YAML while keeping records as plain JSON-compatible dict/list/scalar values
- Stores cached LLM duplicate decisions and related provenance records
- Safe re-import behavior: unchanged records are skipped instead of duplicated


## DefectDojo Integration

This project supports two DefectDojo upload modes:

- `raw-per-scan` (default): uploads one scanner-native raw artifact per scanner execution
  to `/api/v2/reimport-scan/`, using the scanner's DefectDojo parser.
- `merged`: exports final normalized results to `defectdojo_generic.json`
  using DefectDojo Generic Findings Import JSON, then uploads that JSON to
  `/api/v2/reimport-scan/`.

Merged mode uses the final merged, deduplicated, scored, and export-sanitized
view from `normalized.json`. Raw-per-scan mode does not use normalized findings,
deduplication, risk scoring, prioritization, `defectdojo_generic.json`, or
project-enriched impact/rationale fields.

Raw-per-scan mode only uses scanner-native artifacts:
- nmap: native XML from nmap stdout
- nuclei: native JSONL stdout saved as `.jsonl`
- wapiti: native JSON report
- nikto: native JSON report
- zap: native traditional JSON report from the ZAP Automation Framework

Project-generated files such as `normalized.json`, `defectdojo_generic.json`,
`report.html`, and generic XML wrappers from `utils/xml_artifacts.py` are not
valid raw parser inputs and are skipped.

Name-based uploads resolve the configured Product Type, Product, and Engagement
against real DefectDojo objects before upload. Exact matches are preferred. By
default, safe case-only or whitespace-only mismatches are resolved to the
canonical DefectDojo name, so `Research and development` can resolve to
`Research and Development`. Ambiguous matches still fail. Set
`VULN_MANAGER_DEFECTDOJO_STRICT_NAMES=true` or pass
`--defectdojo-strict-names` to require exact names.

When `auto_create_context=false`, the client validates that Product Type,
Product, and Engagement already exist and fails before upload when they do not.
When `auto_create_context=true`, the client verifies authentication, reuses safe
canonical matches when they exist, and does not block missing context. The upload
request sends `auto_create_context=true` to `/api/v2/reimport-scan/`, letting
DefectDojo create missing Product Type, Product, and Engagement objects during
import if the token has permission. Exact names are still recommended to avoid
accidental duplicates. `VULN_MANAGER_DEFECTDOJO_TEST_ID` and
`VULN_MANAGER_DEFECTDOJO_ENGAGEMENT_ID` are preferred when provided.

The upload `scan_date` is always normalized to `YYYY-MM-DD` before the request.
By default it comes from the final scan `generated_at` timestamp, so a value like
`2026-04-23T08:10:28.707927Z` is sent to DefectDojo as `2026-04-23`. You can
override it with `--defectdojo-scan-date 2026-04-23`; ISO datetimes are also
accepted.

Token format: set `VULN_MANAGER_DEFECTDOJO_API_TOKEN` to the raw token only.
Do not include the word `Token` in `.env`. The client tolerates an accidental
`Token ...` prefix, but the clean value is just the API key.

### DefectDojo Environment Variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `VULN_MANAGER_DEFECTDOJO_URL` | off | DefectDojo base URL |
| `VULN_MANAGER_DEFECTDOJO_API_TOKEN` | off | Raw DefectDojo API token, without `Token` prefix |
| `VULN_MANAGER_DEFECTDOJO_UPLOAD_MODE` | `raw-per-scan` | `merged` or `raw-per-scan` |
| `VULN_MANAGER_DEFECTDOJO_PRODUCT_TYPE` | off | Product Type name |
| `VULN_MANAGER_DEFECTDOJO_PRODUCT` | off | Product name |
| `VULN_MANAGER_DEFECTDOJO_ENGAGEMENT` | off | Engagement name |
| `VULN_MANAGER_DEFECTDOJO_TEST_ID` | off | Optional Test ID for direct reimport targeting |
| `VULN_MANAGER_DEFECTDOJO_ENGAGEMENT_ID` | off | Optional Engagement ID for context targeting |
| `VULN_MANAGER_DEFECTDOJO_TEST_TITLE` | off | Optional test title for reimport matching |
| `VULN_MANAGER_DEFECTDOJO_MINIMUM_SEVERITY` | `Info` | Minimum severity sent on upload |
| `VULN_MANAGER_DEFECTDOJO_ENVIRONMENT` | off | Optional environment name |
| `VULN_MANAGER_DEFECTDOJO_AUTO_CREATE_CONTEXT` | `true` | Auto-create Product Type / Product / Engagement when needed |
| `VULN_MANAGER_DEFECTDOJO_DO_NOT_REACTIVATE` | `false` | Keep previously closed findings closed on reimport |
| `VULN_MANAGER_DEFECTDOJO_CLOSE_OLD_FINDINGS` | `false` | Close findings missing from the new upload |
| `VULN_MANAGER_DEFECTDOJO_BACKGROUND_IMPORT` | `false` | Send `background_import=true` for large uploads |
| `VULN_MANAGER_DEFECTDOJO_STRICT_NAMES` | `false` | Require exact Product Type / Product / Engagement names |
| `VULN_MANAGER_DEFECTDOJO_SCAN_TYPE` | `Generic Findings Import` | Merged mode scan type |
| `VULN_MANAGER_DEFECTDOJO_VERIFY_TLS` | `true` | TLS verification for uploads |
| `VULN_MANAGER_DEFECTDOJO_SCAN_TYPE_NMAP` | `Nmap Scan` | Raw mode parser override |
| `VULN_MANAGER_DEFECTDOJO_SCAN_TYPE_NUCLEI` | `Nuclei Scan` | Raw mode parser override |
| `VULN_MANAGER_DEFECTDOJO_SCAN_TYPE_WAPITI` | `Wapiti Scan` | Raw mode parser override |
| `VULN_MANAGER_DEFECTDOJO_SCAN_TYPE_NIKTO` | `Nikto Scan` | Raw mode parser override |
| `VULN_MANAGER_DEFECTDOJO_SCAN_TYPE_ZAP` | `ZAP Scan` | Raw mode parser override |

Minimal `.env` for default raw-per-scan upload with auto-created context:

```env
VULN_MANAGER_DEFECTDOJO_URL=http://localhost:8080
VULN_MANAGER_DEFECTDOJO_API_TOKEN=your_raw_defectdojo_token
VULN_MANAGER_DEFECTDOJO_PRODUCT_TYPE=Research and Development
VULN_MANAGER_DEFECTDOJO_PRODUCT=Test
VULN_MANAGER_DEFECTDOJO_ENGAGEMENT=Test engagment
VULN_MANAGER_DEFECTDOJO_AUTO_CREATE_CONTEXT=true
VULN_MANAGER_DEFECTDOJO_STRICT_NAMES=false
```

### DefectDojo Examples

Export only:

```bash
uv run python main.py \
  --target https://example.com \
  --scanner all \
  --defectdojo-export
```

Upload scanner-native raw artifacts separately:

```bash
uv run python main.py \
  --target https://example.com \
  --scanner all \
  --defectdojo-upload \
  --defectdojo-url https://dojo.example \
  --defectdojo-api-token "$VULN_MANAGER_DEFECTDOJO_API_TOKEN" \
  --defectdojo-product-type "Research and Development" \
  --defectdojo-product "Test" \
  --defectdojo-engagement "Test engagment" \
  --defectdojo-no-auto-create-context \
  --defectdojo-scan-date 2026-04-23
```

Export and upload merged results explicitly:

```bash
uv run python main.py \
  --target https://example.com \
  --scanner all \
  --defectdojo-upload \
  --defectdojo-upload-mode merged \
  --defectdojo-url https://dojo.example \
  --defectdojo-api-token "$VULN_MANAGER_DEFECTDOJO_API_TOKEN" \
  --defectdojo-product-type "Research and Development" \
  --defectdojo-product "Test" \
  --defectdojo-engagement "Test engagment" \
  --defectdojo-no-auto-create-context
```

Target an existing Test directly with merged upload:

```bash
uv run python main.py \
  --target https://example.com \
  --scanner all \
  --defectdojo-upload \
  --defectdojo-upload-mode merged \
  --defectdojo-url https://dojo.example \
  --defectdojo-api-token "$VULN_MANAGER_DEFECTDOJO_API_TOKEN" \
  --defectdojo-test-id 123
```

For large reports, opt into DefectDojo background processing:

```bash
uv run python main.py \
  --target https://example.com \
  --scanner all \
  --defectdojo-upload \
  --defectdojo-background-import
```

### DefectDojo Troubleshooting

- Wrong engagement name: check that `VULN_MANAGER_DEFECTDOJO_ENGAGEMENT` or
  `--defectdojo-engagement` matches an Engagement under the configured Product.
  Case and whitespace-only differences are auto-resolved by default; ambiguous
  or truly missing names fail with close matches when available. You can also
  use `--defectdojo-engagement-id`.
- Wrong Product Type or Product: check the names in DefectDojo. For the current
  lab hierarchy, the values are Product Type `Research and Development`,
  Product `Test`, and Engagement `Test engagment`. Use
  `--defectdojo-strict-names` only when you want case-sensitive exact matching.
- Invalid `scan_date`: pass `YYYY-MM-DD`, for example
  `--defectdojo-scan-date 2026-04-23`. Full ISO timestamps are accepted but are
  sent as `YYYY-MM-DD`.
- Raw upload skipped: the scanner either has no raw parser mapping, did not
  produce a scanner-native artifact, or only has a project-generated XML wrapper.
  Set `VULN_MANAGER_DEFECTDOJO_SCAN_TYPE_<SCANNER>` only when DefectDojo has a
  parser that accepts that scanner's native output format.
- Duplicate or malformed token: store only the raw API key in `.env`, not
  `Token <key>`. The outgoing header is always built as `Authorization: Token <key>`.
- Auto-create permission issues: if `auto_create_context=true`, the DefectDojo
  token must be allowed to create Product Types, Products, Engagements, Tests,
  and import scans. Invalid tokens still fail before upload. Invalid payloads or
  insufficient create/import permissions fail during upload with the DefectDojo
  response body included. If you want existing-context-only behavior, pass
  `--defectdojo-no-auto-create-context`.
- Large report uploads: pass `--defectdojo-background-import` or set
  `VULN_MANAGER_DEFECTDOJO_BACKGROUND_IMPORT=true` so DefectDojo can process the
  upload asynchronously.
- Groq/LLM 401 errors are separate from DefectDojo upload. They affect optional
  LLM duplicate-resolution, not DefectDojo token validation.


## CLI Reference

```bash
uv run python main.py [OPTIONS]
```

### Core Options

| Flag | Default | Description |
|------|---------|-------------|
| `--target <URL>` / `-t` | — | Target to scan (required) |
| `--scanner {all,nuclei,nmap,wapiti,nikto,zap}` / `-s` | `all` | Scanner selection |
| `--scan-config <path>` | off | Optional YAML/JSON scan config file with global settings and per-scanner options |
| `--report` | auto | Force HTML report generation (already on for normal scan runs) |
| `--no-report` | off | Disable HTML report generation for this run |
| `--compare` | off | Compare with most recent previous scan |
| `--probe-only` | off | Probe the target, print scheme/HTTP behavior, and exit |

### Output Options

| Flag | Default | Description |
|------|---------|-------------|
| `--output <file>` / `-o` | auto | Custom output filename |
| `--data-dir <path>` | `./data` | Directory for saving results |
| `--verbose` / `-v` | off | Show descriptions + remediation |
| `--json` | off | Output results as JSON only (no banner) |

### DefectDojo Options

| Flag | Default | Description |
|------|---------|-------------|
| `--defectdojo-export` | off | Write `defectdojo_generic.json` beside the normal run artifacts |
| `--defectdojo-upload` | off | Upload scanner-native raw scanner artifacts to DefectDojo by default |
| `--defectdojo-upload-mode <mode>` | `raw-per-scan` | `merged` or `raw-per-scan` |
| `--defectdojo-url <url>` | env | DefectDojo base URL |
| `--defectdojo-api-token <token>` | env | DefectDojo API token |
| `--defectdojo-product-type <name>` | env | Product Type name |
| `--defectdojo-product <name>` | env | Product name |
| `--defectdojo-engagement <name>` | env | Engagement name |
| `--defectdojo-test-id <id>` | env | Optional Test ID for direct reimport targeting |
| `--defectdojo-engagement-id <id>` | env | Optional Engagement ID for context targeting |
| `--defectdojo-test-title <name>` | env | Optional test title |
| `--defectdojo-minimum-severity <severity>` | `Info` | Minimum severity sent to DefectDojo |
| `--defectdojo-scan-type-nmap <name>` | env/default | Raw mode parser override |
| `--defectdojo-scan-type-nuclei <name>` | env/default | Raw mode parser override |
| `--defectdojo-scan-type-wapiti <name>` | env/default | Raw mode parser override |
| `--defectdojo-scan-type-nikto <name>` | env/default | Raw mode parser override |
| `--defectdojo-scan-type-zap <name>` | env/default | Raw mode parser override |
| `--defectdojo-environment <name>` | env | Optional DefectDojo environment |
| `--defectdojo-no-auto-create-context` | off | Disable DefectDojo auto-create context |
| `--defectdojo-do-not-reactivate` | off | Keep previously closed findings closed on reimport |
| `--defectdojo-close-old-findings` | off | Close findings absent from the latest upload |
| `--defectdojo-background-import` | off | Send `background_import=true` for large uploads |
| `--defectdojo-strict-names` | off | Require exact Product Type / Product / Engagement names |
| `--defectdojo-scan-date <date>` | report timestamp | Optional `scan_date` override; normalized to `YYYY-MM-DD` |
| `--defectdojo-insecure` | off | Disable TLS certificate verification for upload only |

### Processing Options

| Flag | Default | Description |
|------|---------|-------------|
| `--no-save` | off | Skip saving raw scanner output |
| `--normalize` / `--no-normalize` | on | Disable normalization for raw scanner results only; raw-only mode skips duplicate resolution, comparison, asset context, risk scoring, HTML report, and merged DefectDojo export |
| `--no-dedupe` | off | Skip active duplicate resolution; the legacy dedupe code remains disabled in the normal pipeline |
| `--risk-scoring` / `--no-risk-scoring` | on | Enable or disable runtime risk scoring and priority fields |
| `--no-score` | off | Backwards-compatible alias for `--no-risk-scoring` |
| `--strict-scanners` | off | Exit with code 1 if any selected scanner is unavailable |
| `--merge-by-host` | off | Legacy compatibility flag retained for the old dedupe path; ignored by the active LLM duplicate flow |
| `--duplicate-mode {llm,off}` | env-aware | Active duplicate-handling mode |
| `--llm-api-url <url>` | off | OpenAI-compatible chat completions endpoint used for duplicate decisions |
| `--llm-api-key <key>` | off | API key for the configured LLM duplicate endpoint |
| `--llm-model <name>` | off | Model name sent to the configured LLM duplicate endpoint |
| `--llm-timeout <seconds>` | `15` | Timeout for one LLM duplicate comparison request |
| `--llm-debug` | off | Enable extra internal duplicate-resolution diagnostics before export sanitization |
| `--no-llm-cache` | off | Disable reuse of cached LLM duplicate decisions |
| `--knowledge-db <path>` | `./data/unified_vulnerabilities.yaml` | Path to the YAML store used for LLM duplicate-resolution cache data |
| `--asset-context-file <path>` | off | Optional JSON/YAML asset-context rules file applied before runtime risk scoring |
| `--discover-context` | off | Before scanning, crawl at most three same-site pages and propose a short website/business-process context |
| `--context-accept` | off | Explicitly accept the proposed description without an interactive prompt |
| `--context-description <text>` | off | Replace the proposed description with user-reviewed text without prompting |
| `--context-reviewer <id>` | `local-user` | Human reviewer ID recorded in the generated site OKF bundle |
| `--http-mode {auto,http1,http2}` | `auto` | Auto-detect by default, or require HTTP/1.1 / HTTP/2 with honest failure when unsupported |
| `--http-probe-timeout <seconds>` | `8` | Timeout for scheme + HTTP version probing |

Example: configure LLM duplicate resolution with a local `.env` file:

```bash
cp .env.example .env

# Edit .env and set your own provider values:
# VULN_MANAGER_LLM_API_KEY=your_api_key_here
# VULN_MANAGER_LLM_API_URL=https://api.example.com/v1/chat/completions
# VULN_MANAGER_LLM_MODEL=your_model_name

uv run python main.py --target https://example.com --scanner nuclei
```

### Quick site-context demo

Run the interactive flow:

```bash
uv run python main.py \
  --target https://example.com \
  --scanner nuclei \
  --discover-context
```

VulnFusion prints the suggested description, business processes, and source
URLs. Press Enter to accept it, type a replacement description, or type
`skip`. A confirmed profile is written before scanner execution to:

```text
data/asset_knowledge/<host-slug>--<stable-hash>/
  index.md
  profile.md
  log.md
```

Each host/service identity gets an independent Google Open Knowledge Format
v0.2 bundle. Different domains and subdomains are never merged automatically.
The confirmed description is advisory and does not change deterministic risk
scoring or LLM duplicate anchors. The final HTML report shows the confirmed
description, reviewer, and short OKF revision so the demo remains traceable.

For a non-interactive demo, add `--context-accept`. If the LLM provider is not
configured or fails, the page title/meta description is shown as a reviewable
fallback instead of blocking the scan.

`main.py`, `demo_integration.py`, and `scripts/test_llm_provider.py` load `.env` automatically at startup via `python-dotenv`. Existing environment variables still work, and CLI flags still take precedence over `.env` values. The generic contract is `VULN_MANAGER_LLM_API_KEY`, `VULN_MANAGER_LLM_API_URL`, and `VULN_MANAGER_LLM_MODEL`. Any compatible provider can be used as long as you supply all three values explicitly.

### Live LLM Smoke Tests

Live provider checks stay opt-in. Normal `uv run pytest` runs do not require credentials. The same `VULN_MANAGER_LLM_API_URL`, `VULN_MANAGER_LLM_API_KEY`, and `VULN_MANAGER_LLM_MODEL` values are reused for both the standalone script and the pytest smoke path. Missing values keep the pytest smoke test skipped and make the standalone script exit with a masked configuration summary instead of printing secrets.

```bash
# Healthcheck only
uv run python scripts/test_llm_provider.py

# Healthcheck + one real duplicate-resolution comparison
uv run python scripts/test_llm_provider.py --duplicate-smoke

# Run only the live pytest smoke test
uv run pytest -q -m live_llm --run-live-llm tests/test_llm_duplicate_resolver.py
```

### Scan Config Files

Prefer `--scan-config` when you want repeatable scanner settings without adding more scanner-specific CLI flags. For an authorized public-site demo, start with [`configs/examples/polite_demo_config.yaml`](configs/examples/polite_demo_config.yaml). It runs Nmap discovery followed by Nuclei at a hard five-request-per-second ceiling, reduces Nuclei concurrency and retries, and disables the three deeper overlapping web scanners.

```bash
uv run python main.py --target example.com --scanner all \
  --scan-config configs/examples/polite_demo_config.yaml
```

This profile lowers the chance of triggering a target-side rate limit; it cannot
guarantee that a site will accept the scan. Use it only against an authorized
target. A target may enforce a lower or adaptive limit, and VulnFusion does not
rotate IP addresses or identities to bypass that control. Use a staging target
and an explicitly agreed request budget for Wapiti, Nikto, or ZAP deep scans.

If ZAP was already run manually, export its **Traditional JSON** report and add
`--zap-report <path>`. The flag enables the otherwise-disabled ZAP source,
imports that report exactly once, and does not require Docker, a local ZAP
binary, target probing, or another ZAP scan. VulnFusion validates that the
report contains the requested target host, copies it into the run's `raw/`
folder, then sends its findings through the same normalization, deduplication,
risk, and HTML-report stages. ZAP XML/HTML/SARIF imports are not supported by
this small demo path.

Supported shape:

```yaml
version: 1
global:
  scan_mode: automatic
  http_mode: auto
  save_raw: true
  normalize: true
  risk_scoring: true
  # report defaults to true for normal scan runs; set report: false to suppress report.html

scanners:
  nmap:
    enabled: true
    options:
      ports: "80,443"
      scripts: ["vulners", "http-title"]
      extra_args: ["-Pn"]
  zap:
    enabled: true
    options:
      timeout: 1800
      active_scan: true
      af_plan_path: ../zap_test_template.yaml
```

Rules:
- Precedence is: scanner built-in defaults → `--scan-config` values → direct CLI flags → runtime/orchestrator-added values.
- `global.report` defaults to `true` for normal scan runs. Set `global.report: false` or pass `--no-report` when you want to suppress `report.html`.
- `global.normalize: false` runs raw-only mode. It writes raw scan output and allows raw-per-scan DefectDojo upload, but skips normalized-only stages and rejects HTML report, comparison, and merged DefectDojo export requests.
- `global.risk_scoring` defaults to `true`. Use `global.risk_scoring: false`, `--no-risk-scoring`, or the legacy `--no-score` alias to omit runtime risk fields.
- `effective_scan_config.json` records the defaults + config + CLI view of each scanner. Runtime-only values that the orchestrator injects during execution are not folded back into that artifact.
- Scanner names under `scanners:` must match the registered scanner IDs exactly: `nmap`, `nuclei`, `wapiti`, `nikto`, `zap`.
- A scanner with `enabled: false` stays disabled. Selecting it explicitly with `--scanner <name>` fails early instead of silently overriding the config.
- `extra_args` must be a YAML/JSON list of individual arguments, not a shell string.
- Reserved/internal flags that would override targets, output formats, or report generation are blocked by scanner-specific validation.
- Structured options should be preferred first; use `extra_args` only for advanced flags the current schema does not expose.
- Scanner-declared path options such as `zap.af_plan_path` are resolved relative to the config file.
- Every real scan run writes the merged artifact to `<run_dir>/effective_scan_config.json` before scanner execution begins.

### Scanner-Specific Options

Prefer `--scan-config` for repeatable scanner tuning. These direct CLI flags still work and override config-file values when both are provided.

| Flag | Description |
|------|-------------|
| `--ports <spec>` | Nmap port spec, e.g. `"22,80,443"` or `"1-1000"` |
| `--severity {critical,high,medium,low,info}` | Filter Nuclei/Wapiti by severity |
| `--wapiti-level <int>` | Wapiti scan depth level |
| `--wapiti-modules <list>` | Wapiti modules to run |
| `--wapiti-timeout <seconds>` | Wapiti scan timeout |
| `--wapiti-args "<args>"` | Extra args forwarded to Wapiti |
| `--nikto-timeout <seconds>` | Nikto scan timeout |
| `--nikto-tuning <string>` | Nikto tuning string |
| `--nikto-args "<args>"` | Extra args forwarded to Nikto |
| `--zap-timeout <seconds>` | ZAP scan timeout (default: 1200) |
| `--zap-active-scan` | Add a ZAP AF `activeScan` job before reporting when the resolved template does not already include one |
| `--zap-report <path>` | Import an existing ZAP Traditional JSON report instead of starting ZAP; also enables ZAP when the scan config disables it |
| `--zap-args "<args>"` | Extra args forwarded to the ZAP runtime before `-cmd -autorun` |
| `--zap-af-plan <path>` | Optional custom ZAP AF YAML template. If omitted, vuln-manager uses `configs/zap_test_template.yaml`. |
| `--http2-proxy-url <url>` | Optional upstream HTTP proxy override for HTTP/2-only routing when a scanner uses proxy mode |
| `--http2-bridge-url <url>` | Optional local bridge override for HTTP/2-only routing; the built-in bridge starts automatically when needed |
| `--http2-adapter-mode {auto,bridge}` | Compatibility adapter policy for adapter-dependent HTTP/2-only web scans. `auto` preserves direct HTTP/2 where supported and starts the built-in bridge only when needed. |
| `--http-probe-timeout <seconds>` | HTTP transport probe timeout |

### Info Options

| Flag | Description |
|------|-------------|
| `--list-scanners` | List available scanners with version info, then exit |

---

## OWASP ZAP Scanner

### Prerequisites

ZAP uses **headless Automation Framework plans** for reliable execution. By default vuln-manager resolves `configs/zap_test_template.yaml`, patches the runtime-owned fields for the current target, and writes that resolved plan into the run folder. The default template runs the traditional `spider`, `spiderAjax`, and `passiveScan-wait` jobs so modern JS-heavy targets get broader crawl coverage than the old passive-only baseline. If `--zap-active-scan` is set and the resolved template does not already include an `activeScan` job, vuln-manager injects one before the report stage. Docker is the primary execution path, and a local `zap.sh`/`zaproxy` binary can run the same resolved plan only when a lightweight validation check confirms the binary supports command-mode autorun. Findings still land in the same run folder, pass through LLM duplicate resolution, optional comparison, and report generation, and appear in `report.html`:

```bash
# Check Docker is installed and running
docker info

# Pull the ZAP image (first run only, ~400 MB)
docker pull ghcr.io/zaproxy/zaproxy:stable
```

If Docker is unavailable, the automated wrapper looks for a local ZAP binary with Automation Framework support.

### Real ZAP Docker Smoke Test

The end-to-end Docker smoke test is also opt-in so normal test runs stay fast and predictable. It requires a reachable Docker daemon. If `ghcr.io/zaproxy/zaproxy:stable` is missing locally, the test skips with a clear message unless you explicitly allow a pull. On SELinux-enabled Linux hosts, vuln-manager relabels the `/zap/wrk` bind mount so the container can write the Automation Framework report back to the host run folder.

```bash
# Run only the real ZAP Docker smoke test
uv run pytest -q -m zap_docker --run-zap-docker \
  tests/test_targeted_scanner_fixes.py -k zap_docker_automation_smoke_end_to_end

# Same command, but allow the test to pull the stable image if needed
uv run pytest -q -m zap_docker --run-zap-docker --zap-docker-pull-image \
  tests/test_targeted_scanner_fixes.py -k zap_docker_automation_smoke_end_to_end
```

### Usage

```bash
# Run the default AF template; bare targets are probed and normalized automatically
uv run python main.py --target example.com --scanner zap

# Reuse a completed manual ZAP scan without running ZAP again
uv run python main.py --target example.com --scanner zap \
  --zap-report reports/manual-zap-report.json

# With custom timeout (default: 1200 s = 20 min)
uv run python main.py --target https://example.com --scanner zap --zap-timeout 600

# Pass extra ZAP runtime flags (for example a runtime config)
uv run python main.py --target https://example.com --scanner zap --zap-args "-config api.disablekey=true"

# Add AF active scanning after spidering
uv run python main.py --target https://example.com --scanner zap --zap-active-scan

# Swap in a custom AF template instead of configs/zap_test_template.yaml
uv run python main.py --target https://example.com --scanner zap --zap-af-plan configs/my_zap_plan.yaml

# Run ZAP with AF active scanning; HTTP/2-only targets are bridged automatically when needed
uv run python main.py --target https://example.com --scanner zap \
  --zap-active-scan

# Optional explicit proxy-assisted ZAP mode (real target preserved in normalized output)
uv run python main.py --target https://proxy.local --scanner zap \
  --zap-use-proxy \
  --zap-proxy-url http://127.0.0.1:8081 \
  --zap-proxy-original-target https://example.com

# Include ZAP in a full multi-scanner run
uv run python main.py --target example.com --scanner all

# Check if ZAP is available on this system
uv run python main.py --list-scanners
```

### Template behavior

If you do not pass `--zap-af-plan`, vuln-manager uses `configs/zap_test_template.yaml` automatically. Passing `--zap-af-plan` replaces that default template with your own YAML, but vuln-manager still owns the target-specific fields needed to keep the plan safe and parseable.

Preserved template fields:
- `env.parameters` values you set explicitly
- extra fields on the first context beyond `name`, `urls`, and `includePaths` such as authentication, session management, users, and exclude paths
- additional contexts after the first
- unmanaged jobs and unmanaged parameters on managed jobs

Runtime-controlled template fields:
- `env.contexts[0].name`, `urls`, and `includePaths`
- `spider.parameters.context`, `url`, and `maxDuration`
- `spiderAjax.parameters.context`, `url`, and `maxDuration`
- `passiveScan-wait.parameters.maxDuration`
- `activeScan.parameters.context`, `url`, `maxRuleDurationInMins`, and `maxScanDurationInMins`
- `report.parameters.template`, `reportDir`, `reportFile`, `reportTitle`, and `reportDescription`

The primary context URL strips default ports like `:80` and `:443` before vuln-manager builds `urls` and `includePaths`, which keeps ZAP scope matching aligned with the real origin. `report.template` is always forced to `traditional-json` because the current normalization flow parses ZAP's traditional JSON report.

Use `spider` for fast coverage of simple link-driven apps and static sites. Keep `spiderAjax` when the target relies on client-side routing, DOM-triggered navigation, or JavaScript-rendered content. Active scanning is opt-in through `--zap-active-scan`; if your template already contains an `activeScan` job, vuln-manager preserves that job and only rewrites its runtime-owned fields.

### Output

ZAP findings are saved to the same canonical run folder as all other scanners:

```
data/<target_slug>/<timestamp>/
├── raw/
│   ├── zap_https___example_com_<ts>.yaml   # generated AF plan
│   └── zap_https___example_com_<ts>.json   # ZAP traditional JSON report
├── scan_results.json
├── normalized.json                          # Includes ZAP findings
└── report.html
```

### Severity Mapping

| ZAP Risk | Unified Severity |
|----------|------------------|
| Informational | `info` |
| Low | `low` |
| Medium | `medium` |
| High | `high` |

> **Note**: ZAP Risk "High" maps to `high`, not `critical`, per the pipeline's severity policy.

### Graceful Degradation

If Docker is not running and no validated local `zap.sh`/`zaproxy` binary is found, the scanner emits a clear error and the pipeline continues with other scanners — **no crash, no traceback**.

Direct Automation Framework scanning is still best-effort. Some targets may reject the containerized client/request profile or fail during spidering or active scanning. ZAP does not claim guaranteed direct HTTP/2 to the origin. For HTTP/2-only targets, the orchestrator keeps direct-capable scanners direct, uses a configured generic proxy in `auto` mode when available, or starts the built-in bridge for scanners that need compatibility. Findings still remain mapped to the original target. Explicit `--http2-bridge-url` is still available when you want to point the run at your own bridge endpoint, and `--zap-use-proxy` remains available when you intentionally want ZAP to scan a separate URL and keep normalization tied to the real target. If a timeout happens after ZAP has already written a report, the scanner now preserves that partial report and returns partial results instead of discarding them. When the report file is not created, inspect the saved raw scanner JSON for the full `command`, `exit_code`, `stdout`, and `stderr` fields.

---

## HTTP/2 Compatibility Adapter Options

For scanners such as ZAP, Wapiti, and Nikto, this project supports a **single-origin local compatibility adapter** from scanner-friendly local HTTP traffic to an upstream HTTP/2 origin.

In normal CLI use, you do not need to start any adapter manually. When the probe shows the target is HTTP/2-only and the selected scanner depends on a compatibility layer, the orchestrator keeps direct-capable scanners on their native path and routes adapter-dependent scanners through one shared adapter policy:

- `auto`: keep scanners with direct HTTP/2 support on their native path. For adapter-dependent scanners, use an explicit bridge override first, then a configured generic proxy in `auto` mode, then the built-in Python bridge.
- `bridge`: force the built-in Python reverse bridge for adapter-dependent scanners.

Why this shape:
- the adapter is configured for one upstream origin per run
- ZAP, Wapiti, and Nikto only need a normal local HTTP endpoint
- the same scanner interfaces still work whether routing is direct, proxied, or bridge-backed

### Optional manual bridge control

```bash
uv run python scripts/run_python_http2_bridge.py \
  --origin https://example.com \
  --listen-host 127.0.0.1 \
  --listen-port 3000
```

By default the bridge listens on `http://127.0.0.1:3000` from the host.

### Default scan flow

Most runs should just use the normal command:

```bash
uv run python main.py --target example.com --scanner all
```

If the target turns out to be HTTP/2-only, direct-capable scanners stay direct and adapter-dependent scanners follow the configured compatibility adapter policy. Nuclei uses its direct HTTP/2 mode on supported HTTPS targets.

### Run through your own bridge

```bash
uv run python main.py \
  --target example.com \
  --scanner all \
  --http2-bridge-url http://127.0.0.1:3000
```

Expected use:
- ZAP, Wapiti, and Nikto: routed through the configured local bridge on HTTP/2-only targets
- Nmap: unaffected
- Nuclei: uses native `-fh2` when the target is HTTPS and HTTP/2-only; a custom bridge is usually unnecessary

### Force bridge mode

```bash
uv run python main.py \
  --target https://example.com \
  --scanner all \
  --http2-adapter-mode bridge
```

This keeps direct HTTP/2 scanners direct, but routes adapter-dependent scanners such as Wapiti, Nikto, and ZAP through the built-in bridge instead of using proxy fallback.

Protocol-mode note:
- `--http-mode auto` is the default and probes HTTPS first, then HTTP if needed
- `--http-mode http2` only uses paths that can honestly satisfy HTTP/2 in this project (for example, Nuclei native `-fh2` or the built-in bridge adapter)
- a generic upstream proxy is treated as compatibility routing in `auto` mode, not as verified native HTTP/2 support

Degraded execution note:
- a scanner that exits but clearly stopped early is now reported as degraded instead of a clean zero-finding success
- Nikto soft-failure markers such as error-limit termination are surfaced in scanner execution metadata and reports
- partial reports remain visible as partial/degraded results instead of being silently treated as complete success

Limitations:
- this is a single-origin compatibility layer, not a general proxy
- the adapter is for one target origin per run
- the Python bridge is not meant for websockets or advanced streaming cases
- transport detection is still best-effort
- h2c is not actively handled

---

## Faster Scans

For quicker web scans, reduce scope and timeout explicitly:

```bash
uv run python main.py \
  --target https://example.com \
  --scanner wapiti \
  --wapiti-level 1 \
  --wapiti-modules sql xss \
  --wapiti-timeout 120
```

For Nikto, keep tuning narrow and the timeout short:

```bash
uv run python main.py \
  --target https://example.com \
  --scanner nikto \
  --nikto-tuning 123b \
  --nikto-timeout 120
```

Press `Ctrl+C` to cancel a run cleanly. The tool exits without a Python traceback and prints `Scan cancelled by user.`

---

## Scanner-Native Findings

The final JSON and HTML report use the normalized scanner findings directly,
with deterministic runtime prioritization added on top.

The report content comes directly from the normalized scanner fields:

- `vulnerability_name`
- `severity`
- `asset_id`
- `description`
- `remediation`
- `meta`
- dedupe/provenance fields when present
- comparison fields when present
- `risk_score`
- `priority`
- `risk_factors`
- `risk_rationale`

The HTML report renders the scanner-normalized `description` field and `remediation` directly. It also preserves scanner provenance, merged source evidence, and comparison labels. When scoring is present it surfaces higher-priority findings first, shows `Priority` and `Risk` badges on each finding card, and adds a compact `Why this is prioritized` block from `risk_rationale`. It does not add duplicate-resolution traces, transport/probe internals, or other debug-only sidecars.

---

## Normalized Schema v2.0

Every finding after normalization has this structure:

```json
{
  "vulnerability_name": "SQL Injection",
  "severity": "critical",
  "asset_id": "https://example.com/search?id=1",
  "description": "...",
  "remediation": "...",
  "risk_score": 92,
  "priority": "P0",
  "risk_rationale": "Technical severity: CVSS v3.1 9.8 -> 54 points | ... | Final score: 92/100 -> P0",
  "meta": {
    "scanner": "nuclei",
    "timestamp": "2026-03-25T18:00:00Z",
    "host": "example.com",
    "scheme": "https",
    "path": "/search",
    "port": null,
    "query_keys": ["id"],
    "parameter": "id",
    "method": "GET",
    "raw_id": "sql-injection-template",
    "cve_id": "CVE-2021-1234",
    "cve_ids": ["CVE-2021-1234"],
    "cwe": "CWE-89"
  },
  "risk_factors": {
    "technical_severity": 54,
    "exploit_likelihood": 8,
    "business_context": 15,
    "evidence_quality": 5,
    "final_score": 92,
    "final_priority": "P0"
  }
}
```

When scoring is present, `summary.by_priority` is also exported alongside the
existing severity summary. Internal fingerprints and duplicate-analysis traces
still exist for normalization/comparison, but they are not part of exported
JSON or HTML output.


The top-level output envelope always includes:

```json
{
  "schema_version": "2.0",
  "generated_at": "2026-02-22T11:34:31Z",
  "target": "example.com",
  "all_findings": [...]
}
```

### Schema Validation — `validate_finding()` in `utils/schema.py`

`validate_finding(finding)` returns `(is_valid: bool, errors: list[str])`.

> [!NOTE]
> Validation is **pipeline-stage aware**: raw pre-normalized findings are only checked against required fields. Optional fields are validated only **when present** — so minimal raw findings always pass, while post-processed findings are checked more deeply.

#### A. Required base fields (always checked)

| Field | Rule |
|-------|------|
| `vulnerability_name` | non-empty string |
| `severity` | non-empty string, must be `critical \| high \| medium \| low \| info` |
| `asset_id` | string (empty allowed for host-level findings) |
| `description` | string |
| `remediation` | string |
| `meta` | dict (sub-fields are all optional) |

#### B. Optional deduplication fields (validated when present)

Added by the deduplicator after merging.

| Field | Rule |
|-------|------|
| `match_level` | string, one of `strict \| general \| host_only \| single` |
| `merge_confidence` | `float`, 0.0–1.0 |
| `found_by` | `list[str]` — scanner names that contributed |
| `duplicate_count` | `int` ≥ 1 — number of raw findings merged |

#### C. Structured `meta` sub-fields (validated when present)

| Field | Rule |
|-------|------|
| `meta.scanner`, `timestamp`, `host`, `scheme`, `path`, `parameter`, `method`, `raw_id`, `cve_id` | string |
| `meta.port` | `int` or `None` |
| `meta.query_keys`, `meta.cve_ids` | `list[str]` |
| `meta.cwe` | `str` or `int` |

Error messages always include the full field path (e.g. `meta.query_keys must be a list of strings`).


### 2. Change Tracking

```json
{
  "status": "CHANGED",
  "changed_fields": ["severity"]
}
```

### 3. Comparator Correctness

```python
# No fingerprint overwriting — all duplicates preserved:
findings_by_fp = defaultdict(list)
findings_by_fp[fp].append(finding)

# Hard-fail on target mismatch:
if create_target_slug(baseline) != create_target_slug(current):
    raise ValueError("COMPARATOR SAFETY CHECK FAILED")
```

---

## Key Files

### Core Pipeline
| File | Purpose |
|------|---------|
| `main.py` | CLI entry point |
| `orchestrator.py` | Scanner coordination + run folders |
| `utils/normalizer.py` | Fingerprinting (`fp_strict`, `fp_general`, `fp_host_only`) |
| `utils/deduplicator.py` | Finding deduplication |
| `utils/comparator.py` | Change tracking |
| `utils/report_generator.py` | HTML report generation |
| `utils/schema.py` | Unified schema, `validate_finding()`, `normalize_severity()` |
| `utils/run_folder.py` | Run folder utilities |

### Scanners
| File | Scanner |
|------|---------|
| `scanners/nuclei_scanner.py` | Nuclei |
| `scanners/nmap_scanner.py` | Nmap |
| `scanners/wapiti_scanner.py` | Wapiti |
| `scanners/nikto_scanner.py` | Nikto |
| `scanners/zap_scanner.py` | OWASP ZAP (Automation Framework) |



### Demos
| File | Purpose |
|------|---------|
| `demo_integration.py` | ⭐ Baseline + comparison demo |

---

## Integration Demo

```bash
uv run python demo_integration.py --target example.com
```

Runs two full pipeline passes and shows NEW/PERSISTENT/CHANGED/FIXED status with field-level diffs:

```
RUN 1: BASELINE SCAN
  Total Findings: 15

RUN 2: COMPARISON SCAN
  NEW:        3    PERSISTENT: 10    CHANGED: 2    FIXED: 0

  Changed Findings:
  1. SQL Injection — severity: high → critical
```

---

## Documentation

| Document | Contents |
|----------|---------|
| [docs/walkthrough.md](docs/walkthrough.md) | Implementation details, design decisions, output examples |
| [docs/risk_model.md](docs/risk_model.md) | Internal/experimental scoring notes; not part of exported runtime output |
| [REQUIREMENTS_VERIFIED.md](REQUIREMENTS_VERIFIED.md) | Verified requirements checklist |
| [knowledge/index.md](knowledge/index.md) | OKF-format LLM/agent knowledge bundle |

---

## For Thesis Documentation

| Metric | Value |
|--------|-------|
| Schema version | 2.0 |
| Scanners integrated | 5 |
| Vulnerability types in KB | 36 |
| OWASP Top 10 coverage | 8/10 |
| DeprecationWarnings | Zero |

**Academic citations:**
- `defaultdict(list)` no-overwrite: [utils/comparator.py](utils/comparator.py)
- Target validation hard-fail: [utils/comparator.py](utils/comparator.py)
- Structured `changed_fields`: [utils/comparator.py](utils/comparator.py)
- Schema validation: [utils/schema.py](utils/schema.py) — `validate_finding()`

---

**Status**: ✅ Production-Oriented Core | **Experimental Paths**: Clearly marked | **DeprecationWarnings**: Zero
