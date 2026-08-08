"""Practical benchmark helpers for dedup runtime and pair reduction."""

from __future__ import annotations

import argparse
import copy
import json
import time
from collections import Counter
from pathlib import Path
from random import Random
from typing import Any, Dict, List, Mapping, Sequence

from utils.dedup_evaluation import OracleLLMClient
from utils.llm_duplicate_resolver import LLMDuplicateConfig, LLMDuplicateResolver


DEFAULT_BENCHMARK_DATASET_PATH = (
    Path(__file__).resolve().parents[1]
    / "tests"
    / "fixtures"
    / "dedup_benchmark_cases.json"
)

GROUP_FINDING_SIZES = {
    "same_scanner_exact": 2,
    "deterministic_cve": 2,
    "deterministic_header": 2,
    "deterministic_parameterized": 2,
    "gray_zone_parameter": 2,
    "gray_zone_nearby_path": 2,
    "gray_zone_service_overlap": 2,
    "gray_zone_antiframing": 2,
    "guardrail_header_family": 2,
    "guardrail_path_identity": 2,
    "same_host_unrelated": 2,
    "multi_cluster": 3,
    "noise_singleton": 1,
}


def _ordered_unique(values: Sequence[str]) -> List[str]:
    """Return first-seen unique strings."""
    seen: set[str] = set()
    ordered: List[str] = []
    for value in values:
        text = str(value or "").strip()
        if not text or text in seen:
            continue
        seen.add(text)
        ordered.append(text)
    return ordered


def _rate_or_default(numerator: int, denominator: int, *, default: float) -> float:
    """Return a stable ratio with explicit empty-denominator behavior."""
    if denominator <= 0:
        return default
    return numerator / denominator


def load_benchmark_specs(
    path: str | Path = DEFAULT_BENCHMARK_DATASET_PATH,
) -> List[Dict[str, Any]]:
    """Load and validate the synthetic benchmark dataset specifications."""
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    datasets = payload.get("datasets", payload) if isinstance(payload, dict) else payload
    if not isinstance(datasets, list):
        raise ValueError("benchmark dataset must contain a list of datasets")

    loaded: List[Dict[str, Any]] = []
    seen_ids: set[str] = set()
    for raw_dataset in datasets:
        if not isinstance(raw_dataset, dict):
            raise ValueError("benchmark dataset entries must be objects")

        dataset = copy.deepcopy(raw_dataset)
        dataset_id = str(dataset.get("dataset_id") or "").strip()
        if not dataset_id:
            raise ValueError("benchmark datasets must include dataset_id")
        if dataset_id in seen_ids:
            raise ValueError(f"duplicate benchmark dataset_id: {dataset_id}")
        seen_ids.add(dataset_id)

        size = int(dataset.get("size") or 0)
        seed = int(dataset.get("seed") or 0)
        host_pool = int(dataset.get("host_pool") or 0)
        if size <= 0:
            raise ValueError(f"{dataset_id}: size must be positive")
        if host_pool <= 0:
            raise ValueError(f"{dataset_id}: host_pool must be positive")

        group_plan = dataset.get("group_plan")
        if not isinstance(group_plan, dict):
            raise ValueError(f"{dataset_id}: group_plan must be an object")

        unknown_keys = sorted(set(group_plan) - set(GROUP_FINDING_SIZES))
        if unknown_keys:
            raise ValueError(f"{dataset_id}: unsupported group_plan keys: {unknown_keys}")

        normalized_plan: Dict[str, int] = {}
        planned_findings = 0
        for group_name, finding_size in GROUP_FINDING_SIZES.items():
            count = int(group_plan.get(group_name) or 0)
            if count < 0:
                raise ValueError(f"{dataset_id}: group_plan counts must be non-negative")
            normalized_plan[group_name] = count
            planned_findings += count * finding_size

        if planned_findings != size:
            raise ValueError(
                f"{dataset_id}: group_plan expands to {planned_findings} findings, expected {size}"
            )

        dataset["mix"] = str(dataset.get("mix") or "balanced").strip() or "balanced"
        dataset["seed"] = seed
        dataset["size"] = size
        dataset["host_pool"] = host_pool
        dataset["group_plan"] = normalized_plan
        dataset["planned_findings"] = planned_findings
        loaded.append(dataset)

    return loaded


class _SyntheticDatasetBuilder:
    """Generate one inspectable synthetic benchmark dataset from a fixed seed."""

    def __init__(self, spec: Mapping[str, Any]) -> None:
        self.dataset_id = str(spec["dataset_id"])
        self.size = int(spec["size"])
        self.seed = int(spec["seed"])
        self.mix = str(spec.get("mix") or "balanced")
        self.host_pool = int(spec["host_pool"])
        self.group_plan = {key: int(value) for key, value in spec["group_plan"].items()}
        self.rng = Random(self.seed)
        self.hosts = [f"app-{index:03d}.example.test" for index in range(self.host_pool)]
        self.group_counter = 0
        self.finding_counter = 0
        self.findings: List[Dict[str, Any]] = []
        self.expected_groups: List[List[str]] = []

    def build(self) -> Dict[str, Any]:
        """Return the generated dataset payload."""
        schedule: List[str] = []
        for group_name, count in self.group_plan.items():
            schedule.extend([group_name] * count)
        self.rng.shuffle(schedule)

        generators = {
            "same_scanner_exact": self._same_scanner_exact_group,
            "deterministic_cve": self._deterministic_cve_group,
            "deterministic_header": self._deterministic_header_group,
            "deterministic_parameterized": self._deterministic_parameterized_group,
            "gray_zone_parameter": self._gray_zone_parameter_group,
            "gray_zone_nearby_path": self._gray_zone_nearby_path_group,
            "gray_zone_service_overlap": self._gray_zone_service_overlap_group,
            "gray_zone_antiframing": self._gray_zone_antiframing_group,
            "guardrail_header_family": self._guardrail_header_family_group,
            "guardrail_path_identity": self._guardrail_path_identity_group,
            "same_host_unrelated": self._same_host_unrelated_group,
            "multi_cluster": self._multi_cluster_group,
            "noise_singleton": self._noise_singleton_group,
        }

        for group_name in schedule:
            generators[group_name]()

        if len(self.findings) != self.size:
            raise ValueError(
                f"{self.dataset_id}: generated {len(self.findings)} findings, expected {self.size}"
            )

        return {
            "dataset_id": self.dataset_id,
            "size": self.size,
            "seed": self.seed,
            "mix": self.mix,
            "host_pool": self.host_pool,
            "group_plan": dict(self.group_plan),
            "findings": copy.deepcopy(self.findings),
            "expected_groups": copy.deepcopy(self.expected_groups),
        }

    def _allocate_group(self) -> tuple[int, str]:
        """Return the next stable synthetic group index and host."""
        group_index = self.group_counter
        self.group_counter += 1
        host = self.hosts[group_index % self.host_pool]
        return group_index, host

    def _next_finding_id(self, label: str) -> str:
        """Return a stable finding id."""
        finding_id = f"{self.dataset_id}-{label}-{self.finding_counter:05d}"
        self.finding_counter += 1
        return finding_id

    def _web_finding(
        self,
        *,
        label: str,
        scanner: str,
        host: str,
        path: str,
        title: str,
        description: str,
        severity: str,
        remediation: str,
        parameter: str = "",
        method: str = "GET",
        query_keys: Sequence[str] | None = None,
        meta_extra: Mapping[str, Any] | None = None,
    ) -> Dict[str, Any]:
        """Return a normalized web finding."""
        query_keys = list(query_keys or ([parameter] if parameter else []))
        query_suffix = ""
        if query_keys:
            query_suffix = "?" + "&".join(f"{query_key}=1" for query_key in query_keys)

        finding = {
            "finding_id": self._next_finding_id(label),
            "vulnerability_name": title,
            "severity": severity,
            "asset_id": f"https://{host}{path}{query_suffix}",
            "description": description,
            "remediation": remediation,
            "meta": {
                "scanner": scanner,
                "host": host,
                "scheme": "https",
                "port": 443,
                "path": path,
                "parameter": parameter,
                "method": method,
                "protocol": "",
                "query_keys": query_keys,
                "raw_id": f"{scanner}-{label}-{self.finding_counter:05d}",
                "synthetic_template": label,
            },
        }
        if meta_extra:
            finding["meta"].update(copy.deepcopy(dict(meta_extra)))
        return finding

    def _service_finding(
        self,
        *,
        label: str,
        scanner: str,
        host: str,
        title: str,
        description: str,
        severity: str,
        remediation: str,
        meta_extra: Mapping[str, Any] | None = None,
    ) -> Dict[str, Any]:
        """Return a normalized service-level finding."""
        finding = {
            "finding_id": self._next_finding_id(label),
            "vulnerability_name": title,
            "severity": severity,
            "asset_id": f"{host}:443",
            "description": description,
            "remediation": remediation,
            "meta": {
                "scanner": scanner,
                "host": host,
                "scheme": "",
                "port": 443,
                "path": "",
                "parameter": "",
                "method": "",
                "protocol": "tcp",
                "service": "https",
                "query_keys": [],
                "raw_id": f"{scanner}-{label}-{self.finding_counter:05d}",
                "synthetic_template": label,
            },
        }
        if meta_extra:
            finding["meta"].update(copy.deepcopy(dict(meta_extra)))
        return finding

    def _push_group(self, findings: Sequence[Dict[str, Any]], *, duplicate_group: bool) -> None:
        """Append one synthetic group to the dataset."""
        self.findings.extend(copy.deepcopy(list(findings)))
        if duplicate_group and len(findings) > 1:
            self.expected_groups.append([str(finding["finding_id"]) for finding in findings])

    def _same_scanner_exact_group(self) -> None:
        group_index, host = self._allocate_group()
        scanner = self.rng.choice(["zap", "nuclei", "wapiti"])
        parameter = self.rng.choice(["q", "search", "term"])
        path = f"/repeat/{group_index}"
        raw_id = f"{scanner}-repeat-{group_index}"
        common_meta = {
            "raw_id": raw_id,
            "category": "SQL Injection",
        }
        findings = [
            self._web_finding(
                label="same-scanner",
                scanner=scanner,
                host=host,
                path=path,
                parameter=parameter,
                method="GET",
                query_keys=[parameter],
                title="SQL Injection",
                severity="medium",
                description="Repeated same-scanner SQL injection record.",
                remediation="Use parameterized queries.",
                meta_extra=common_meta,
            ),
            self._web_finding(
                label="same-scanner",
                scanner=scanner,
                host=host,
                path=path,
                parameter=parameter,
                method="GET",
                query_keys=[parameter],
                title="SQL Injection",
                severity="medium",
                description="Repeated same-scanner SQL injection record.",
                remediation="Use parameterized queries.",
                meta_extra=common_meta,
            ),
        ]
        self._push_group(findings, duplicate_group=True)

    def _deterministic_cve_group(self) -> None:
        group_index, host = self._allocate_group()
        cve_id = f"CVE-2026-{5000 + group_index:04d}"
        findings = [
            self._service_finding(
                label="det-cve",
                scanner="nmap",
                host=host,
                title=cve_id,
                severity="high",
                description="Service-level CVE match.",
                remediation="Patch the affected service.",
                meta_extra={
                    "cve_id": cve_id,
                    "cve_ids": [cve_id],
                },
            ),
            self._web_finding(
                label="det-cve",
                scanner="nuclei",
                host=host,
                path=f"/cve/{group_index}",
                title="Generic CMS SQLi",
                severity="medium",
                description="Web endpoint wording for the same CVE.",
                remediation="Patch the affected service.",
                meta_extra={
                    "category": "SQL Injection",
                    "cve_id": cve_id,
                    "cve_ids": [cve_id],
                },
            ),
        ]
        self._push_group(findings, duplicate_group=True)

    def _deterministic_header_group(self) -> None:
        group_index, host = self._allocate_group()
        path = f"/headers/{group_index}"
        findings = [
            self._web_finding(
                label="det-header",
                scanner="zap",
                host=host,
                path=path,
                title="CSP Header Missing",
                severity="medium",
                description="Missing CSP header on the endpoint.",
                remediation="Set the header.",
            ),
            self._web_finding(
                label="det-header",
                scanner="nuclei",
                host=host,
                path=path,
                title="Content Security Policy Configuration",
                severity="low",
                description="The same endpoint is missing the CSP protection.",
                remediation="Set the header.",
            ),
        ]
        self._push_group(findings, duplicate_group=True)

    def _deterministic_parameterized_group(self) -> None:
        group_index, host = self._allocate_group()
        path = f"/api/item-{group_index}"
        findings = [
            self._web_finding(
                label="det-param",
                scanner="zap",
                host=host,
                path=path,
                parameter="id",
                method="POST",
                query_keys=["id"],
                title="SQL Injection",
                severity="high",
                description="Injectable id input on the API endpoint.",
                remediation="Use parameterized queries.",
                meta_extra={"category": "SQL Injection"},
            ),
            self._web_finding(
                label="det-param",
                scanner="wapiti",
                host=host,
                path=path,
                parameter="id",
                method="POST",
                query_keys=["id"],
                title="SQL Injection",
                severity="medium",
                description="The same parameter-level SQL injection was confirmed.",
                remediation="Use parameterized queries.",
                meta_extra={"category": "SQL Injection"},
            ),
        ]
        self._push_group(findings, duplicate_group=True)

    def _gray_zone_parameter_group(self) -> None:
        group_index, host = self._allocate_group()
        path = f"/login/{group_index}"
        findings = [
            self._web_finding(
                label="gray-param",
                scanner="zap",
                host=host,
                path=path,
                parameter="q",
                method="GET",
                query_keys=["q"],
                title="SQL Injection in search parameter",
                severity="medium",
                description="Search field may be injectable.",
                remediation="Use parameterized queries.",
                meta_extra={"category": "SQL Injection"},
            ),
            self._web_finding(
                label="gray-param",
                scanner="nuclei",
                host=host,
                path=path,
                parameter="account",
                method="GET",
                query_keys=["account"],
                title="SQL Injection",
                severity="medium",
                description="Generic SQL injection finding on a nearby login input.",
                remediation="Use parameterized queries.",
                meta_extra={"category": "SQL Injection"},
            ),
        ]
        self._push_group(findings, duplicate_group=True)

    def _gray_zone_nearby_path_group(self) -> None:
        group_index, host = self._allocate_group()
        findings = [
            self._web_finding(
                label="gray-path",
                scanner="zap",
                host=host,
                path=f"/portal/{group_index}/login",
                parameter="q",
                method="GET",
                query_keys=["q"],
                title="SQL Injection in search parameter",
                severity="medium",
                description="Input handling on one login path looked injectable.",
                remediation="Use parameterized queries.",
                meta_extra={"category": "SQL Injection"},
            ),
            self._web_finding(
                label="gray-path",
                scanner="nuclei",
                host=host,
                path=f"/auth/{group_index}/login",
                parameter="account",
                method="GET",
                query_keys=["account"],
                title="SQL Injection in account parameter",
                severity="medium",
                description="Generic SQL injection match on a nearby login endpoint.",
                remediation="Use parameterized queries.",
                meta_extra={"category": "SQL Injection"},
            ),
        ]
        self._push_group(findings, duplicate_group=True)

    def _gray_zone_service_overlap_group(self) -> None:
        group_index, host = self._allocate_group()
        technology = f"AcmeCMS-{group_index}"
        findings = [
            self._service_finding(
                label="gray-service",
                scanner="nmap",
                host=host,
                title="Potential CMS Exposure",
                severity="medium",
                description="HTTPS service exposes a CMS login surface.",
                remediation="Review the exposed service.",
                meta_extra={"technology": technology},
            ),
            self._web_finding(
                label="gray-service",
                scanner="nuclei",
                host=host,
                path=f"/cms/{group_index}/login",
                title="Generic CMS SQLi",
                severity="medium",
                description="Generic SQL injection match on the CMS login endpoint.",
                remediation="Patch the application.",
                meta_extra={
                    "technology": technology,
                    "category": "SQL Injection",
                },
            ),
        ]
        self._push_group(findings, duplicate_group=True)

    def _gray_zone_antiframing_group(self) -> None:
        group_index, host = self._allocate_group()
        path = f"/frame/{group_index}"
        findings = [
            self._web_finding(
                label="gray-frame",
                scanner="zap",
                host=host,
                path=path,
                title="Clickjacking policy check",
                severity="low",
                description="Endpoint may not enforce anti-framing controls.",
                remediation="Review browser security controls.",
                meta_extra={"category": "Browser Security"},
            ),
            self._web_finding(
                label="gray-frame",
                scanner="nuclei",
                host=host,
                path=path,
                title="Framing protections review",
                severity="low",
                description="Template flagged potentially missing anti-framing controls.",
                remediation="Review browser security controls.",
                meta_extra={"category": "Browser Security"},
            ),
        ]
        self._push_group(findings, duplicate_group=True)

    def _guardrail_header_family_group(self) -> None:
        group_index, host = self._allocate_group()
        path = f"/guard/{group_index}"
        findings = [
            self._web_finding(
                label="guard-header",
                scanner="zap",
                host=host,
                path=path,
                title="CSP Header Missing",
                severity="low",
                description="Missing CSP header.",
                remediation="Set the correct header.",
            ),
            self._web_finding(
                label="guard-header",
                scanner="nuclei",
                host=host,
                path=path,
                title="Content-Type Header Missing",
                severity="low",
                description="Missing Content-Type header.",
                remediation="Set the correct header.",
            ),
        ]
        self._push_group(findings, duplicate_group=False)

    def _guardrail_path_identity_group(self) -> None:
        group_index, host = self._allocate_group()
        if group_index % 2 == 0:
            findings = [
                self._web_finding(
                    label="guard-path",
                    scanner="zap",
                    host=host,
                    path=f"/db/get/{group_index}",
                    parameter="id",
                    method="GET",
                    query_keys=["id"],
                    title="SQL Injection",
                    severity="medium",
                    description="Potential SQL injection on one endpoint.",
                    remediation="Use parameterized queries.",
                    meta_extra={"category": "SQL Injection"},
                ),
                self._web_finding(
                    label="guard-path",
                    scanner="nuclei",
                    host=host,
                    path=f"/db/list/{group_index}",
                    parameter="id",
                    method="GET",
                    query_keys=["id"],
                    title="SQL Injection",
                    severity="medium",
                    description="Potential SQL injection on a nearby but distinct endpoint.",
                    remediation="Use parameterized queries.",
                    meta_extra={"category": "SQL Injection"},
                ),
            ]
        else:
            findings = [
                self._web_finding(
                    label="guard-ise",
                    scanner="zap",
                    host=host,
                    path=f"/api/get/{group_index}",
                    parameter="id",
                    method="GET",
                    query_keys=["id"],
                    title="Internal Server Error",
                    severity="low",
                    description="500 response on one handler.",
                    remediation="Review server-side error handling.",
                ),
                self._web_finding(
                    label="guard-ise",
                    scanner="nuclei",
                    host=host,
                    path=f"/api/list/{group_index}",
                    parameter="id",
                    method="GET",
                    query_keys=["id"],
                    title="Internal Server Error",
                    severity="low",
                    description="500 response on a different handler.",
                    remediation="Review server-side error handling.",
                ),
            ]
        self._push_group(findings, duplicate_group=False)

    def _same_host_unrelated_group(self) -> None:
        group_index, host = self._allocate_group()
        path = f"/same-host/{group_index}"
        findings = [
            self._web_finding(
                label="same-host-header",
                scanner="zap",
                host=host,
                path=path,
                title="Missing X-Frame-Options Header",
                severity="low",
                description="Header issue on the endpoint.",
                remediation="Set the header.",
            ),
            self._web_finding(
                label="same-host-sqli",
                scanner="nuclei",
                host=host,
                path=path,
                title="SQL Injection",
                severity="high",
                description="SQL injection issue on the same host.",
                remediation="Use parameterized queries.",
                meta_extra={"category": "SQL Injection"},
            ),
        ]
        self._push_group(findings, duplicate_group=False)

    def _multi_cluster_group(self) -> None:
        group_index, host = self._allocate_group()
        if group_index % 2 == 0:
            path = f"/cluster/{group_index}"
            findings = [
                self._web_finding(
                    label="multi-det",
                    scanner="zap",
                    host=host,
                    path=path,
                    title="CSP Header Missing",
                    severity="medium",
                    description="Missing CSP header on the endpoint.",
                    remediation="Set the header.",
                ),
                self._web_finding(
                    label="multi-det",
                    scanner="nuclei",
                    host=host,
                    path=path,
                    title="Content Security Policy Configuration",
                    severity="low",
                    description="The same endpoint is missing the CSP protection.",
                    remediation="Set the header.",
                ),
                self._web_finding(
                    label="multi-det",
                    scanner="nikto",
                    host=host,
                    path=path,
                    title="Suggested security header missing: content-security-policy.",
                    severity="low",
                    description="A third scanner also flagged the missing CSP header.",
                    remediation="Set the header.",
                ),
            ]
        else:
            path = f"/hybrid/{group_index}"
            common_meta = {"raw_id": f"zap-hybrid-{group_index}", "category": "SQL Injection"}
            findings = [
                self._web_finding(
                    label="multi-hybrid",
                    scanner="zap",
                    host=host,
                    path=path,
                    parameter="q",
                    method="GET",
                    query_keys=["q"],
                    title="SQL Injection in search parameter",
                    severity="medium",
                    description="Repeated same-scanner record for the search parameter.",
                    remediation="Use parameterized queries.",
                    meta_extra=common_meta,
                ),
                self._web_finding(
                    label="multi-hybrid",
                    scanner="zap",
                    host=host,
                    path=path,
                    parameter="q",
                    method="GET",
                    query_keys=["q"],
                    title="SQL Injection in search parameter",
                    severity="medium",
                    description="Repeated same-scanner record for the search parameter.",
                    remediation="Use parameterized queries.",
                    meta_extra=common_meta,
                ),
                self._web_finding(
                    label="multi-hybrid",
                    scanner="nuclei",
                    host=host,
                    path=path,
                    parameter="account",
                    method="GET",
                    query_keys=["account"],
                    title="SQL Injection",
                    severity="medium",
                    description="Generic SQL injection finding on a nearby login input.",
                    remediation="Use parameterized queries.",
                    meta_extra={"category": "SQL Injection"},
                ),
            ]
        self._push_group(findings, duplicate_group=True)

    def _noise_singleton_group(self) -> None:
        group_index, host = self._allocate_group()
        templates = [
            {
                "label": "noise-csp",
                "scanner": "zap",
                "path": f"/noise/{group_index}",
                "title": "CSP Header Missing",
                "severity": "low",
                "description": "Single header issue without a matching duplicate.",
                "remediation": "Set the header.",
                "meta_extra": {},
            },
            {
                "label": "noise-sqli",
                "scanner": "nuclei",
                "path": f"/noise/{group_index}/search",
                "parameter": "term",
                "query_keys": ["term"],
                "title": "SQL Injection",
                "severity": "medium",
                "description": "Standalone SQL injection candidate.",
                "remediation": "Use parameterized queries.",
                "meta_extra": {"category": "SQL Injection"},
            },
            {
                "label": "noise-service",
                "scanner": "nmap",
                "service": True,
                "title": "Potential CMS Exposure",
                "severity": "low",
                "description": "Standalone service observation.",
                "remediation": "Review the service.",
                "meta_extra": {"technology": f"StandaloneCMS-{group_index}"},
            },
        ]
        template = templates[group_index % len(templates)]
        if template.get("service"):
            finding = self._service_finding(
                label=str(template["label"]),
                scanner=str(template["scanner"]),
                host=host,
                title=str(template["title"]),
                severity=str(template["severity"]),
                description=str(template["description"]),
                remediation=str(template["remediation"]),
                meta_extra=template.get("meta_extra"),
            )
        else:
            finding = self._web_finding(
                label=str(template["label"]),
                scanner=str(template["scanner"]),
                host=host,
                path=str(template["path"]),
                parameter=str(template.get("parameter") or ""),
                query_keys=template.get("query_keys"),
                title=str(template["title"]),
                severity=str(template["severity"]),
                description=str(template["description"]),
                remediation=str(template["remediation"]),
                meta_extra=template.get("meta_extra"),
            )
        self._push_group([finding], duplicate_group=False)


def generate_benchmark_dataset(spec: Mapping[str, Any]) -> Dict[str, Any]:
    """Generate one synthetic benchmark dataset from a validated specification."""
    return _SyntheticDatasetBuilder(spec).build()


def _group_source_records(finding: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Return the source records represented by one final finding."""
    source_findings = finding.get("source_findings")
    if isinstance(source_findings, list) and source_findings:
        return [source for source in source_findings if isinstance(source, dict)]
    return [finding]


def _final_group_mode(finding: Dict[str, Any]) -> str:
    """Classify one final finding into deterministic, hybrid, llm, or no_merge."""
    source_records = _group_source_records(finding)
    if len(source_records) <= 1:
        return "no_merge"

    duplicate_resolution = finding.get("duplicate_resolution")
    mode = ""
    if isinstance(duplicate_resolution, dict):
        mode = str(duplicate_resolution.get("mode") or "").strip().lower()
    if mode == "deterministic":
        return "deterministic"

    if mode == "llm":
        scanners = [
            str(
                source.get("scanner")
                or (
                    source.get("meta", {}).get("scanner")
                    if isinstance(source.get("meta"), dict)
                    else ""
                )
                or ""
            ).strip()
            for source in source_records
        ]
        scanner_counts = Counter(scanner for scanner in scanners if scanner)
        if any(count > 1 for count in scanner_counts.values()):
            return "hybrid"
        return "llm"

    return "no_merge"


def _lineage_count(finding: Dict[str, Any]) -> int:
    """Return how many original findings are represented by one final finding."""
    return len(_group_source_records(finding))


def benchmark_dataset(dataset: Mapping[str, Any]) -> Dict[str, Any]:
    """Run the real resolver flow on one synthetic benchmark dataset."""
    findings = copy.deepcopy(list(dataset["findings"]))
    resolver = LLMDuplicateResolver(
        LLMDuplicateConfig(
            mode="llm",
            api_url="https://benchmark.example/v1/chat/completions",
            api_key="benchmark-key",
            model_name="benchmark-oracle",
        ),
        client=OracleLLMClient(expected_groups=dataset.get("expected_groups") or []),
    )

    started_at = time.perf_counter()
    results = resolver.apply({"all_findings": findings, "summary": {}})
    runtime_seconds = time.perf_counter() - started_at

    duplicate_analysis = results.get("duplicate_analysis", {})
    profiling = (
        copy.deepcopy(duplicate_analysis.get("profiling"))
        if isinstance(duplicate_analysis.get("profiling"), dict)
        else {}
    )
    final_findings = results.get("all_findings", [])
    total_findings = int(dataset["size"])
    total_final_findings = len(final_findings)
    naive_pair_count = total_findings * (total_findings - 1) // 2
    candidate_pairs_after_blocking = int(
        duplicate_analysis.get("same_target_pairs_considered") or 0
    )
    pairs_skipped_by_similarity_gate = int(
        duplicate_analysis.get("low_similarity_pairs_skipped") or 0
    )
    deterministic_merges = int(
        duplicate_analysis.get("deterministic_same_scanner_merges") or 0
    ) + int(duplicate_analysis.get("deterministic_fallback_merges") or 0)
    pairs_sent_to_llm_path = int(
        duplicate_analysis.get("pairs_sent_to_llm") or 0
    ) + int(duplicate_analysis.get("pairs_reused_from_cache") or 0)
    llm_or_cached_comparisons = int(
        duplicate_analysis.get("total_compared_pairs") or 0
    )

    mode_counts = {mode: 0 for mode in ("deterministic", "hybrid", "llm", "no_merge")}
    deterministic_resolved_findings = 0
    gray_zone_handled_findings = 0
    for finding in final_findings:
        mode = _final_group_mode(finding)
        mode_counts[mode] += 1
        represented_findings = _lineage_count(finding)
        if mode == "deterministic":
            deterministic_resolved_findings += represented_findings
        elif mode in {"hybrid", "llm"}:
            gray_zone_handled_findings += represented_findings

    resolved_findings = deterministic_resolved_findings + gray_zone_handled_findings

    return {
        "dataset_id": str(dataset["dataset_id"]),
        "mix": str(dataset.get("mix") or "balanced"),
        "seed": int(dataset["seed"]),
        "host_pool": int(dataset["host_pool"]),
        "client_kind": "oracle",
        "live_provider_used": False,
        "total_findings": total_findings,
        "total_final_findings": total_final_findings,
        "naive_pair_count": naive_pair_count,
        "candidate_pairs_before_blocking": naive_pair_count,
        "candidate_pairs_after_same_target_blocking": candidate_pairs_after_blocking,
        "pairs_skipped_by_similarity_gate": pairs_skipped_by_similarity_gate,
        "deterministic_merges": deterministic_merges,
        "deterministic_same_scanner_merges": int(
            duplicate_analysis.get("deterministic_same_scanner_merges") or 0
        ),
        "deterministic_cross_scanner_merges": int(
            duplicate_analysis.get("deterministic_fallback_merges") or 0
        ),
        "pairs_sent_to_llm_path": pairs_sent_to_llm_path,
        "llm_or_cached_comparisons": llm_or_cached_comparisons,
        "cache_hits": int(duplicate_analysis.get("cache_hits") or 0),
        "runtime_seconds": runtime_seconds,
        "blocking_reduction_ratio": 1.0
        - _rate_or_default(
            candidate_pairs_after_blocking,
            naive_pair_count,
            default=0.0,
        ),
        "comparison_reduction_ratio": 1.0
        - _rate_or_default(
            llm_or_cached_comparisons,
            naive_pair_count,
            default=0.0,
        ),
        "deterministic_resolution_share": _rate_or_default(
            deterministic_resolved_findings,
            resolved_findings,
            default=0.0,
        ),
        "gray_zone_share": _rate_or_default(
            gray_zone_handled_findings,
            resolved_findings,
            default=0.0,
        ),
        "mode_counts": mode_counts,
        "profiling": profiling,
        "duplicate_analysis": {
            "same_target_pairs_considered": candidate_pairs_after_blocking,
            "low_similarity_pairs_skipped": pairs_skipped_by_similarity_gate,
            "pairs_blocked_by_same_target": int(
                duplicate_analysis.get("pairs_blocked_by_same_target") or 0
            ),
            "pairs_reused_from_cache": int(
                duplicate_analysis.get("pairs_reused_from_cache") or 0
            ),
            "llm_calls": int(duplicate_analysis.get("llm_calls") or 0),
            "provider_healthcheck_status": duplicate_analysis.get(
                "provider_healthcheck_status"
            ),
        },
    }


def benchmark_from_spec(spec: Mapping[str, Any]) -> Dict[str, Any]:
    """Generate and benchmark one synthetic dataset specification."""
    return benchmark_dataset(generate_benchmark_dataset(spec))


def benchmark_all_datasets(
    path: str | Path = DEFAULT_BENCHMARK_DATASET_PATH,
) -> Dict[str, Any]:
    """Load, generate, and benchmark every configured synthetic dataset."""
    specs = load_benchmark_specs(path)
    dataset_results = [benchmark_from_spec(spec) for spec in specs]
    return {
        "datasets": dataset_results,
        "summary": {
            "dataset_count": len(dataset_results),
            "total_findings": sum(result["total_findings"] for result in dataset_results),
            "total_llm_or_cached_comparisons": sum(
                result["llm_or_cached_comparisons"] for result in dataset_results
            ),
        },
    }


def _format_profiling_lines(result: Mapping[str, Any]) -> List[str]:
    """Render one dataset's profiling details and top hot spots."""
    profiling = result.get("profiling")
    if not isinstance(profiling, dict) or not profiling:
        return []

    lines = [
        "Dedup Profiling Summary",
        f"- dataset: {result['dataset_id']}",
        f"- total runtime: {profiling.get('total_runtime_seconds', 0.0):.3f}s",
        f"- same-scanner premerge: {profiling.get('same_scanner_exact_premerge_seconds', 0.0):.3f}s",
        f"- deterministic cross-scanner premerge: {profiling.get('deterministic_cross_scanner_premerge_seconds', 0.0):.3f}s",
        f"- candidate pair generation: {profiling.get('candidate_pair_generation_seconds', 0.0):.3f}s",
        f"- same-target filtering: {profiling.get('same_target_filtering_seconds', 0.0):.3f}s",
        f"- cheap similarity gate: {profiling.get('cheap_similarity_gate_seconds', 0.0):.3f}s",
        f"- gray-zone compare loop: {profiling.get('gray_zone_compare_loop_seconds', 0.0):.3f}s",
        f"- final merge/materialization: {profiling.get('final_merge_materialization_seconds', 0.0):.3f}s",
        f"- summary recompute: {profiling.get('summary_recompute_seconds', 0.0):.3f}s",
    ]

    hot_spots = sorted(
        (
            (stage, seconds)
            for stage, seconds in profiling.items()
            if stage.endswith("_seconds") and stage != "total_runtime_seconds"
        ),
        key=lambda item: item[1],
        reverse=True,
    )[:3]
    if hot_spots:
        lines.append(
            "- top hot spots: "
            + ", ".join(
                f"{stage.replace('_seconds', '')}={seconds:.3f}s"
                for stage, seconds in hot_spots
            )
        )
    return lines


def format_benchmark_summary(
    report: Mapping[str, Any],
    *,
    include_profiling: bool = False,
) -> str:
    """Render a readable multi-dataset benchmark summary."""
    lines = ["Dedup Benchmark Summary"]
    for result in report["datasets"]:
        lines.extend(
            [
                f"Dataset {result['dataset_id']}",
                f"- mix: {result['mix']}",
                f"- llm client: {result['client_kind']}",
                f"- findings: {result['total_findings']}",
                f"- final findings: {result['total_final_findings']}",
                f"- naive pair count: {result['naive_pair_count']}",
                f"- candidate pairs after blocking: {result['candidate_pairs_after_same_target_blocking']}",
                f"- pairs skipped by similarity gate: {result['pairs_skipped_by_similarity_gate']}",
                f"- deterministic merges: {result['deterministic_merges']}",
                f"- pairs sent to LLM path: {result['pairs_sent_to_llm_path']}",
                f"- llm/cached comparisons: {result['llm_or_cached_comparisons']}",
                f"- runtime: {result['runtime_seconds']:.3f}s",
                f"- comparison reduction ratio: {result['comparison_reduction_ratio'] * 100:.2f}%",
                f"- deterministic resolution share: {result['deterministic_resolution_share'] * 100:.1f}%",
                f"- gray-zone share: {result['gray_zone_share'] * 100:.1f}%",
                "- mode distribution: "
                f"deterministic={result['mode_counts']['deterministic']} "
                f"hybrid={result['mode_counts']['hybrid']} "
                f"llm={result['mode_counts']['llm']} "
                f"no_merge={result['mode_counts']['no_merge']}",
                "",
            ]
        )
        if include_profiling:
            lines.extend(_format_profiling_lines(result))
            lines.append("")
    return "\n".join(lines).rstrip()


def main(argv: Sequence[str] | None = None) -> int:
    """Run the synthetic benchmark fixture set and print readable summaries."""
    parser = argparse.ArgumentParser(
        description="Run the synthetic dedup scalability benchmark."
    )
    parser.add_argument(
        "dataset_path",
        nargs="?",
        default=str(DEFAULT_BENCHMARK_DATASET_PATH),
        help="Path to the benchmark dataset JSON file.",
    )
    parser.add_argument(
        "--profile",
        action="store_true",
        help="Include per-stage profiling details in the printed benchmark summary.",
    )
    args = parser.parse_args(argv)

    report = benchmark_all_datasets(args.dataset_path)
    print(format_benchmark_summary(report, include_profiling=args.profile))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
