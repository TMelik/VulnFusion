# Dedup Testing Rules

This repository uses a deterministic-first dedup flow:

`raw finding -> unified schema -> canonical taxonomy -> candidate blocking -> deterministic rules -> gray-zone handling -> LLM only for gray zone -> merge cluster`

The LLM is not the primary deduplicator. Tests should assume that obvious duplicates merge before any healthcheck, cache lookup, or live LLM comparison.

## Test Buckets

`deterministic merge coverage`
- Use findings that should merge before pairing.
- Assert no healthcheck call, no compare call, and no `llm_duplicate_comparisons` when everything merged up front.
- Assert `duplicate_analysis["deterministic_fallback_merges"]` increments and final summary counts match `all_findings`.

`gray-zone LLM coverage`
- Use findings that are similar enough to reach the cheap similarity gate but do not have a deterministic anchor.
- Assert healthcheck/compare, cache reuse, provider failure handling, debug payload behavior, and final merge vs no-merge outcomes.
- Live-provider smoke tests should also reuse a gray-zone pair so the run proves the real provider boundary instead of short-circuiting through deterministic merges.
- Assert `duplicate_analysis["deterministic_fallback_merges"] == 0`.

`guardrail / no-merge coverage`
- Use findings that should stay separate.
- Assert either deterministic premerge does not happen or the cheap similarity gate skips the pair.
- Keep these tests focused on proving that unsafe merges do not happen.

## Obvious Duplicates

These belong in deterministic tests, not LLM-path tests:

- Same CVE on the same effective target.
- Same header family on the same endpoint.
- Same strong injection family on the same path, parameter, and method.

Examples:
- `CVE-2024-1111` on the same effective web target from service and URL views.
- CSP/header-family findings on the same endpoint.
- SQL injection findings on the same path with the same parameter and method.

## Gray-Zone LLM Cases

These are acceptable LLM-path fixtures because they are similar but not deterministically obvious:

- Same family but different parameters.
- Same family but different nearby paths.
- Service-vs-URL contextual overlap without a shared CVE.
- Ambiguous wording with contextual overlap but no deterministic anchor.

Examples:
- SQL injection on `/login?q` vs `/login?account`.
- Similar SQL injection findings on `/db/get` vs `/db/list`.
- CMS exposure on `example.com:443` vs a CMS SQLi finding on `https://example.com/login` without a shared CVE.
- Anti-framing/clickjacking wording overlap on the same endpoint without matching a deterministic header family rule.

## Guardrails

These should stay separate unless a stronger anchor is added:

- Different header families on the same endpoint.
- Same family on different parameters where merge is unsafe.
- Same family on different paths without a stronger identity anchor.
- Generic `Internal Server Error` findings with weak endpoint identity.

## What Not To Use In LLM-Path Tests

Do not use these fixtures to test cache, provider failures, debug payloads, or live LLM comparisons:

- Same CVE on the same effective target.
- Same header family on the same endpoint.
- Same strong parameterized family on the same path, parameter, and method.

If deterministic rules expand, older gray-zone fixtures may become deterministic. In that case, refresh the test fixtures instead of weakening production logic to force those pairs back through the LLM.
