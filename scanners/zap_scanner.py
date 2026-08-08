"""
OWASP ZAP Scanner Integration

Runs headless ZAP Automation Framework plans using Docker as the primary
execution path and a local ZAP binary as a fallback. Each run writes a
reproducible per-scan YAML plan into the raw output directory, executes
``zap.sh -cmd -autorun <plan>``, and normalizes the traditional JSON
report into the unified finding schema.
"""

from copy import deepcopy
import json
import re
import socket
import shlex
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from math import ceil
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse, urlunparse

import yaml

from .base import BaseScanner
from utils.normalizer import create_fingerprints, normalize_web_target, parse_target

ZAP_DOCKER_IMAGE = "ghcr.io/zaproxy/zaproxy:stable"
ZAP_DOCKER_WORK_DIR = "/zap/wrk"
ZAP_AUTOMATION_CONTEXT = "scan-target"
ZAP_AUTOMATION_REPORT_TEMPLATE = "traditional-json"
ZAP_DEFECTDOJO_REPORT_TEMPLATE = "traditional-xml"
ZAP_LOCAL_BINARIES = ("zap.sh", "zaproxy", "zaproxy.sh", "zap")
ZAP_DEFAULT_AUTOMATION_TEMPLATE = (
    Path(__file__).resolve().parent.parent / "configs" / "zap_test_template.yaml"
)
ZAP_AUTOMATION_RUNTIME_OWNED_FIELDS: Dict[str, Any] = {
    "env.contexts[0]": ["name", "urls", "includePaths"],
    "jobs.spider.parameters": ["context", "url", "maxDuration"],
    "jobs.spiderAjax.parameters": ["context", "url", "maxDuration"],
    "jobs.passiveScan-wait.parameters": ["maxDuration"],
    "jobs.activeScan.parameters": [
        "context",
        "url",
        "maxRuleDurationInMins",
        "maxScanDurationInMins",
    ],
    "jobs.report.parameters": [
        "template",
        "reportDir",
        "reportFile",
        "reportTitle",
        "reportDescription",
    ],
}
ZAP_AUTOMATION_RUNTIME_CONTROL_NOTES = (
    "Only these fields are rewritten at runtime; other template content is preserved as supplied.",
    "Primary context URLs are canonicalized without default ports and without query or fragment components.",
    "The primary report job is forced to traditional-json for normalization; an XML report is added for DefectDojo.",
)
ZAP_OUTPUT_NOISE_PATTERNS = (
    re.compile(r"^Found Java version\b", re.IGNORECASE),
    re.compile(r"^Available memory:", re.IGNORECASE),
    re.compile(r"^Using JVM args:", re.IGNORECASE),
    re.compile(r"^\d+\s+\[[^\]]+\]\s+INFO\b", re.IGNORECASE),
)
ZAP_OUTPUT_SIGNAL_PATTERNS = (
    re.compile(
        r"\b("
        r"error|warn(?:ing)?|failed|failure|exception|unable|denied|"
        r"timeout|timed out|missing|invalid|refused|not found|no such|"
        r"could not|cannot"
        r")\b",
        re.IGNORECASE,
    ),
)

_SEVERITY_MAP: Dict[str, str] = {
    "informational": "info",
    "low": "low",
    "medium": "medium",
    "high": "high",
}


class ZapScanner(BaseScanner):
    """
    OWASP ZAP headless scanner.

    Uses ZAP Automation Framework plans executed through Docker by default,
    with a local ZAP binary fallback when Docker is unavailable.
    """

    def __init__(self) -> None:
        super().__init__("zap")
        self.scanner_type = "web"
        self.supports_http2_direct = False
        self.supports_proxy = True
        self.supports_http2_bridge = True
        self._docker_available: Optional[bool] = None
        self._local_zap_binary_cache: Optional[str] = None
        self._local_zap_binary_checked = False

    def _check_docker(self) -> bool:
        """Return True if Docker daemon is reachable."""
        if self._docker_available is not None:
            return self._docker_available
        if shutil.which("docker") is None:
            self._docker_available = False
            return False
        try:
            result = subprocess.run(
                ["docker", "info"],
                capture_output=True,
                timeout=3,
            )
            self._docker_available = result.returncode == 0
        except (subprocess.TimeoutExpired, Exception):
            self._docker_available = False
        return self._docker_available

    def is_available(self) -> bool:
        """
        Return True if ZAP can be run through the supported automation path.

        Docker is preferred. A local Automation Framework capable ZAP binary
        is also acceptable.
        """
        return self._check_docker() or self._local_zap_binary() is not None

    def _local_zap_binary(self) -> Optional[str]:
        """Return a validated local ZAP executable for AF execution, or None."""
        if self._local_zap_binary_checked:
            return self._local_zap_binary_cache

        for name in ZAP_LOCAL_BINARIES:
            binary = shutil.which(name)
            if not binary:
                continue
            if self._validate_local_zap_binary(binary):
                self._local_zap_binary_cache = binary
                break

        self._local_zap_binary_checked = True
        return self._local_zap_binary_cache

    def _validate_local_zap_binary(self, binary: str) -> bool:
        """
        Confirm a local ZAP binary is callable and advertises AF-style autorun support.

        The check is intentionally conservative: the binary must execute in command
        mode and its help output must mention Automation Framework-style autorun.
        """
        try:
            result = subprocess.run(
                [binary, "-cmd", "-help"],
                capture_output=True,
                text=True,
                timeout=10,
            )
        except (subprocess.TimeoutExpired, OSError, ValueError):
            return False

        output = "\n".join(
            part.strip()
            for part in (result.stdout, result.stderr)
            if part and part.strip()
        )
        if not output:
            return False

        lowered = output.lower()
        if "autorun" not in lowered and "automation framework" not in lowered:
            return False

        return result.returncode in (0, 1, 2)

    def get_version(self) -> Optional[str]:
        """Return a version/image string for the supported execution path."""
        if self._check_docker():
            return f"docker:{ZAP_DOCKER_IMAGE}"

        binary = self._local_zap_binary()
        if binary is not None:
            return f"local:{Path(binary).name}"

        return None

    def get_proxy_options(self, proxy_url: str) -> Dict[str, Any]:
        """Return proxy settings used for HTTP/2 compatibility routing."""
        return {
            "use_proxy": True,
            "proxy_url": proxy_url,
        }

    def get_default_options(self) -> Dict[str, Any]:
        """Return documented ZAP defaults exposed through scan config."""
        return {
            "timeout": 1200,
            "use_proxy": False,
        }

    def get_supported_options(self) -> set[str]:
        """Return supported user-facing ZAP option keys."""
        return {
            "timeout",
            "active_scan",
            "af_plan_path",
            "report_path",
            "use_proxy",
            "proxy_url",
            "original_target",
            "args",
            "extra_args",
        }

    def get_transport_option_keys(self) -> set[str]:
        """Declare transport-affecting options reserved for orchestrated routing."""
        return super().get_transport_option_keys() | {"use_proxy", "original_target"}

    def get_path_option_keys(self) -> set[str]:
        """Resolve user-supplied plan paths relative to the config file."""
        return {"af_plan_path", "report_path"}

    def uses_offline_input(self, options: Optional[Dict[str, Any]] = None) -> bool:
        """Return True when an existing ZAP report replaces live scanner execution."""
        return bool(isinstance(options, dict) and options.get("report_path"))

    def validate_options(self, options: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Validate and normalize user-supplied ZAP options."""
        normalized = super().validate_options(options)
        self._validate_int_option(normalized, "timeout", minimum=1)
        self._validate_bool_option(normalized, "active_scan")
        self._validate_bool_option(normalized, "use_proxy")
        if normalized.get("proxy_url") is None:
            normalized.pop("proxy_url", None)
        else:
            self._validate_string_option(normalized, "proxy_url")
        if normalized.get("original_target") is None:
            normalized.pop("original_target", None)
        else:
            self._validate_string_option(normalized, "original_target")
        self._normalize_path_option(normalized, "af_plan_path")
        self._normalize_path_option(normalized, "report_path")
        self._normalize_extra_args(
            normalized,
            forbidden_flags={
                "-autorun",
                "-cmd",
            },
        )
        report_path = normalized.get("report_path")
        if report_path:
            conflicting = [
                key
                for key in ("active_scan", "af_plan_path", "args", "proxy_url", "original_target")
                if normalized.get(key)
            ]
            if normalized.get("use_proxy"):
                conflicting.append("use_proxy")
            if conflicting:
                raise ValueError(
                    "zap option 'report_path' cannot be combined with live execution option(s): "
                    + ", ".join(sorted(conflicting))
                )
            _, _, valid, issue = self._read_report_file(Path(str(report_path)))
            if not valid:
                raise ValueError(
                    "zap option 'report_path' must be an OWASP ZAP traditional JSON report: "
                    f"{issue}"
                )
        return normalized

    def _make_safe_slug(self, target: str) -> str:
        """Create a filesystem-safe slug from a target URL."""
        slug = re.sub(r"[^\w.-]", "_", target)
        return slug[:60]

    def _summarize_process_output(
        self,
        stdout: str = "",
        stderr: str = "",
        limit: int = 240,
    ) -> str:
        """Return a short human-readable stderr/stdout summary for error messages."""
        parts: List[str] = []
        for label, value in (("stderr", stderr), ("stdout", stdout)):
            text = self._summarize_process_stream(label, value, limit)
            if not text:
                continue
            parts.append(text)
        return " | ".join(parts)

    def _summarize_process_stream(
        self,
        label: str,
        value: str = "",
        limit: int = 240,
    ) -> str:
        """
        Extract a compact, high-signal summary from one process stream.

        ZAP often writes JVM startup and INFO logs before the lines that explain
        why the run was degraded. Prefer the final warning/error lines and drop
        pure startup chatter when it adds no diagnostic value.
        """
        lines = [
            " ".join(line.split())
            for line in (value or "").splitlines()
            if line and line.strip()
        ]
        if not lines:
            return ""

        filtered = [
            line
            for line in lines
            if not any(pattern.search(line) for pattern in ZAP_OUTPUT_NOISE_PATTERNS)
        ]
        if not filtered:
            return ""

        signal_lines = [
            line
            for line in filtered
            if any(pattern.search(line) for pattern in ZAP_OUTPUT_SIGNAL_PATTERNS)
        ]
        selected = signal_lines[-2:] if signal_lines else filtered[-1:]
        text = " | ".join(dict.fromkeys(selected))
        if len(text) > limit:
            text = text[: limit - 3] + "..."
        return f"{label}: {text}"

    def _empty_result(
        self,
        target: str,
        timestamp: str,
        error: str,
        **extra: Any,
    ) -> Dict[str, Any]:
        """Return a stable empty-result payload for early validation failures."""
        result = {
            "scanner": self.name,
            "target": target,
            "timestamp": timestamp,
            "command": None,
            "raw_output": None,
            "raw_output_path": None,
            "stdout": "",
            "stderr": "",
            "exit_code": None,
            "error": error,
            "findings": [],
        }
        result.update(extra)
        return result

    def scan(
        self,
        target: str,
        options: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Run a headless ZAP scan against *target*.

        Args:
            target: Target URL or local bridge/proxy endpoint. The orchestrator
                is expected to pass a probed, normalized URL with scheme.
            options: Optional dict with:
                - ``output_dir`` (str | Path): Directory to write raw ZAP
                  artifacts into.
                - ``timeout`` (int): Subprocess timeout in seconds
                  (default 1200).
                - ``active_scan`` (bool): When True, include the AF
                  ``activeScan`` job after spidering.
                - ``args`` (str | list): Extra arguments forwarded to the
                  ZAP runtime before ``-cmd -autorun``.
                - ``af_plan_path`` (str | Path): Optional custom Automation
                  Framework YAML plan template resolved into the raw output
                  directory before execution.
                - ``origin_target`` (str): Original target URL preserved when
                  scanning through the local HTTP/2 bridge.
                - ``use_proxy`` / ``proxy_url`` / ``original_target``:
                  explicit proxy-assisted ZAP mode for scanning an alternate
                  URL while keeping findings tied to the real target.
        """
        options = options or {}
        defaults = self.get_default_options()
        timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

        report_path = options.get("report_path")
        if report_path:
            return self._import_existing_report(
                target=target,
                report_path=Path(str(report_path)),
                timestamp=timestamp,
                output_dir=(Path(str(options["output_dir"])) if options.get("output_dir") else None),
            )

        direct_target = self._require_target_url(target, field_name="target")
        if direct_target is None:
            return self._empty_result(
                target=target,
                timestamp=timestamp,
                error=(
                    "ZAP requires a normalized http:// or https:// target. "
                    "Run it through the target probe/orchestrator path first."
                ),
            )

        active_scan = bool(options.get("active_scan"))
        use_proxy = bool(options.get("use_proxy", defaults.get("use_proxy", False)))
        proxy_url = options.get("proxy_url")
        origin_target = options.get("origin_target")
        if origin_target:
            origin_target = self._require_target_url(
                origin_target,
                field_name="origin_target",
            )
        original_target = self._require_target_url(
            options.get("original_target") or origin_target or direct_target,
            field_name="original_target",
        )
        if original_target is None:
            return self._empty_result(
                target=direct_target,
                timestamp=timestamp,
                error=(
                    "ZAP requires a normalized original target URL when proxy "
                    "or bridge metadata is supplied."
                ),
            )

        bridge_mode = bool(origin_target) and not use_proxy
        effective_target = (
            self._require_target_url(proxy_url, field_name="proxy_url")
            if use_proxy and proxy_url
            else direct_target
        )
        if use_proxy and proxy_url and effective_target is None:
            return self._empty_result(
                target=direct_target,
                timestamp=timestamp,
                error="ZAP proxy mode requires a normalized proxy URL with http:// or https://.",
            )

        target = effective_target
        scan_mode = "active" if active_scan else "baseline"
        af_plan_path = options.get("af_plan_path")
        automation_plan_runtime_controls = self._automation_plan_runtime_controls()
        default_template_path = self._default_automation_plan_template_path()
        template_path_str: Optional[str] = None
        if af_plan_path:
            template_path_str = str(Path(str(af_plan_path)).expanduser().resolve())
            requested_plan_source = "user template"
        elif default_template_path.exists():
            template_path_str = str(default_template_path.resolve())
            requested_plan_source = "default template"
        else:
            requested_plan_source = "built-in generated plan"

        ts_file = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        slug = self._make_safe_slug(original_target)
        report_filename = f"zap_{slug}_{ts_file}.json"
        xml_report_filename = f"zap_{slug}_{ts_file}.xml"
        plan_filename = f"zap_{slug}_{ts_file}.yaml"

        output_dir = options.get("output_dir")
        raw_dir = Path(output_dir) if output_dir else Path("data") / "zap_tmp"
        raw_dir.mkdir(parents=True, exist_ok=True)
        try:
            raw_dir.chmod(0o777)
        except OSError:
            pass

        report_path = raw_dir / report_filename
        xml_report_path = raw_dir / xml_report_filename
        plan_path = raw_dir / plan_filename
        timeout = int(options.get("timeout", defaults.get("timeout", 1200)))
        plan_source = "built-in generated plan"

        extra_args = options.get("args", [])
        if isinstance(extra_args, str):
            extra_args = shlex.split(extra_args)

        use_docker = self._check_docker()
        plan_target = target
        plan_report_dir = str(raw_dir.resolve())
        if use_docker:
            plan_target, _ = self._docker_target_and_network_args(target)
            plan_report_dir = ZAP_DOCKER_WORK_DIR

        try:
            plan, plan_source, template_path_str = self._resolve_automation_plan(
                target=plan_target,
                report_filename=report_filename,
                xml_report_filename=xml_report_filename,
                active_scan=active_scan,
                timeout=timeout,
                report_dir=plan_report_dir,
                af_plan_path=af_plan_path,
            )
        except ValueError as exc:
            return self._empty_result(
                target=target,
                timestamp=timestamp,
                error=str(exc),
                original_target=original_target,
                origin_target=origin_target,
                proxy_mode=use_proxy,
                bridge_mode=bridge_mode,
                proxy_url=proxy_url if use_proxy else None,
                scan_mode=scan_mode,
                automation_plan_source=requested_plan_source,
                automation_plan_template_path=template_path_str,
                automation_plan_runtime_controls=automation_plan_runtime_controls,
            )

        plan_has_active_scan = self._plan_has_job(plan, "activeScan")
        scan_mode = "active" if plan_has_active_scan else "baseline"

        try:
            self._write_automation_plan(plan_path, plan)
        except Exception as exc:
            return self._empty_result(
                target=target,
                timestamp=timestamp,
                error=f"Failed to write ZAP Automation Framework plan: {exc}",
                original_target=original_target,
                origin_target=origin_target,
                proxy_mode=use_proxy,
                bridge_mode=bridge_mode,
                proxy_url=proxy_url if use_proxy else None,
                scan_mode=scan_mode,
                automation_plan_source=plan_source,
                automation_plan_template_path=template_path_str,
                automation_plan_runtime_controls=automation_plan_runtime_controls,
            )

        if use_docker:
            result = self._scan_docker(
                target=target,
                raw_dir=raw_dir,
                plan_filename=plan_filename,
                report_path=report_path,
                timestamp=timestamp,
                timeout=timeout,
                extra_args=list(extra_args),
            )
        else:
            binary = self._local_zap_binary()
            if not binary:
                return self._empty_result(
                    target=target,
                    timestamp=timestamp,
                    error=(
                        "ZAP is not available: Docker daemon is not running and "
                        "no local ZAP Automation Framework binary was found."
                    ),
                    original_target=original_target,
                    origin_target=origin_target,
                    proxy_mode=use_proxy,
                    bridge_mode=bridge_mode,
                    proxy_url=proxy_url if use_proxy else None,
                    scan_mode=scan_mode,
                    automation_plan_path=str(plan_path),
                    automation_plan_source=plan_source,
                    automation_plan_template_path=template_path_str,
                    automation_plan_runtime_controls=automation_plan_runtime_controls,
                )
            result = self._scan_local(
                binary=binary,
                target=target,
                plan_path=plan_path,
                report_path=report_path,
                timestamp=timestamp,
                timeout=timeout,
                extra_args=list(extra_args),
            )

        result["original_target"] = original_target
        result["origin_target"] = origin_target
        result["proxy_mode"] = use_proxy
        result["bridge_mode"] = bridge_mode
        result["proxy_url"] = proxy_url if use_proxy else None
        result["scan_mode"] = scan_mode
        result["automation_plan_path"] = str(plan_path)
        result["automation_plan_source"] = plan_source
        if template_path_str:
            result["automation_plan_template_path"] = template_path_str
        result["automation_plan_runtime_controls"] = automation_plan_runtime_controls
        result["expected_zap_xml_report_path"] = str(xml_report_path)
        self._attach_defectdojo_xml_artifact(result, xml_report_path)
        return result

    def _import_existing_report(
        self,
        *,
        target: str,
        report_path: Path,
        timestamp: str,
        output_dir: Optional[Path] = None,
    ) -> Dict[str, Any]:
        """Load a validated traditional-JSON report without starting ZAP."""
        raw_data, findings, valid, issue = self._read_report_file(report_path)
        if not valid:
            return self._empty_result(
                target=target,
                timestamp=timestamp,
                error=f"Could not import existing ZAP report: {issue}",
                raw_output_path=str(report_path),
                imported_report=False,
            )

        normalized_target = normalize_web_target(target)
        report_sites = raw_data.get("site", [])
        if isinstance(report_sites, dict):
            report_sites = [report_sites]
        report_hosts = {
            str(urlparse(str(site.get("@name") or "")).hostname or "").lower()
            for site in report_sites
            if isinstance(site, dict)
        }
        report_hosts.discard("")
        target_host = str(urlparse(normalized_target).hostname or "").lower()
        if report_hosts and target_host not in report_hosts:
            hosts = ", ".join(sorted(report_hosts))
            return self._empty_result(
                target=normalized_target,
                timestamp=timestamp,
                error=(
                    "Existing ZAP report does not contain the requested target host "
                    f"'{target_host}'. Report host(s): {hosts}"
                ),
                imported_report=False,
            )

        artifact_path = report_path.resolve()
        if output_dir is not None:
            try:
                output_dir.mkdir(parents=True, exist_ok=True)
                candidate = output_dir / f"zap_imported_{report_path.name}"
                suffix = 1
                while candidate.exists() and candidate.resolve() != artifact_path:
                    candidate = output_dir / f"zap_imported_{report_path.stem}_{suffix}{report_path.suffix}"
                    suffix += 1
                if candidate.resolve() != artifact_path:
                    shutil.copy2(artifact_path, candidate)
                artifact_path = candidate.resolve()
            except OSError as exc:
                return self._empty_result(
                    target=normalized_target,
                    timestamp=timestamp,
                    error=f"Could not copy existing ZAP report into the run artifact directory: {exc}",
                    imported_report=False,
                )

        return {
            "scanner": self.name,
            "target": normalized_target,
            "original_target": normalized_target,
            "timestamp": timestamp,
            "command": f"import-zap-report {artifact_path}",
            "raw_output": raw_data,
            "raw_output_path": str(artifact_path),
            "stdout": "",
            "stderr": "",
            "exit_code": 0,
            "findings": findings,
            "imported_report": True,
            "imported_report_path": str(artifact_path),
            "report_format": "traditional-json",
        }

    def _build_automation_plan(
        self,
        target: str,
        report_filename: str,
        active_scan: bool,
        timeout: int,
        report_dir: str = ".",
        xml_report_filename: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Build a per-run ZAP Automation Framework plan."""
        context_url = self._context_url(target)
        start_url = self._automation_start_url(target)
        timeout_minutes = self._timeout_minutes(timeout)

        jobs: List[Dict[str, Any]] = [
            {
                "type": "passiveScan-config",
                "parameters": {
                    "scanOnlyInScope": True,
                },
            },
            {
                "type": "spider",
                "parameters": {
                    "context": ZAP_AUTOMATION_CONTEXT,
                    "url": start_url,
                    "maxDuration": timeout_minutes,
                },
            },
            {
                "type": "spiderAjax",
                "parameters": {
                    "context": ZAP_AUTOMATION_CONTEXT,
                    "url": start_url,
                    "maxDuration": timeout_minutes,
                },
            },
            {
                "type": "passiveScan-wait",
                "parameters": {
                    "maxDuration": timeout_minutes,
                },
            },
        ]

        if active_scan:
            jobs.append(
                {
                    "type": "activeScan",
                    "parameters": {
                        "context": ZAP_AUTOMATION_CONTEXT,
                        "url": start_url,
                        "maxRuleDurationInMins": timeout_minutes,
                        "maxScanDurationInMins": timeout_minutes,
                    },
                }
            )
            jobs.append(
                {
                    "type": "passiveScan-wait",
                    "parameters": {
                        "maxDuration": timeout_minutes,
                    },
                }
            )

        jobs.append(
            {
                "type": "report",
                "parameters": {
                    "template": ZAP_AUTOMATION_REPORT_TEMPLATE,
                    "reportDir": report_dir,
                    "reportFile": report_filename,
                    "reportTitle": f"ZAP {'active' if active_scan else 'baseline'} scan for {context_url}",
                    "reportDescription": (
                        "Generated by vuln-manager using the ZAP Automation Framework."
                    ),
                },
            }
        )
        if xml_report_filename:
            jobs.append(
                self._build_report_job(
                    report_filename=xml_report_filename,
                    report_dir=report_dir,
                    active_scan=active_scan,
                    context_url=context_url,
                    report_template=ZAP_DEFECTDOJO_REPORT_TEMPLATE,
                )
            )

        return {
            "env": {
                "contexts": [
                    {
                        "name": ZAP_AUTOMATION_CONTEXT,
                        "urls": [context_url],
                        "includePaths": [self._scope_pattern(target)],
                    }
                ],
                "parameters": {
                    "failOnError": False,
                    "failOnWarning": False,
                    "continueOnFailure": True,
                    "progressToStdout": True,
                },
            },
            "jobs": jobs,
        }

    def _resolve_automation_plan(
        self,
        target: str,
        report_filename: str,
        xml_report_filename: Optional[str],
        active_scan: bool,
        timeout: int,
        report_dir: str = ".",
        af_plan_path: Optional[str] = None,
    ) -> Tuple[Dict[str, Any], str, Optional[str]]:
        """Return the resolved default/custom AF template or a built-in fallback plan."""
        template_path: Optional[Path] = None
        plan_source = "built-in generated plan"

        if af_plan_path:
            template_path = Path(str(af_plan_path)).expanduser()
            plan_source = "user template"
        else:
            default_template_path = self._default_automation_plan_template_path()
            if default_template_path.exists():
                template_path = default_template_path
                plan_source = "default template"

        if template_path is not None:
            template_path_str = (
                str(template_path.resolve())
                if template_path.exists()
                else str(template_path)
            )
            template = self._load_automation_plan_template(template_path)
            resolved = self._resolve_template_automation_plan(
                template,
                target=target,
                report_filename=report_filename,
                xml_report_filename=xml_report_filename,
                active_scan=active_scan,
                timeout=timeout,
                report_dir=report_dir,
            )
            return resolved, plan_source, template_path_str

        return (
            self._build_automation_plan(
                target=target,
                report_filename=report_filename,
                xml_report_filename=xml_report_filename,
                active_scan=active_scan,
                timeout=timeout,
                report_dir=report_dir,
            ),
            plan_source,
            None,
        )

    def _load_automation_plan_template(self, template_path: Path) -> Dict[str, Any]:
        """Load and validate a user-supplied Automation Framework template."""
        if not template_path.exists():
            raise ValueError(f"ZAP AF plan template does not exist: {template_path}")
        if not template_path.is_file():
            raise ValueError(f"ZAP AF plan template must be a regular file: {template_path}")

        try:
            with open(template_path, "r", encoding="utf-8") as fh:
                template = yaml.safe_load(fh)
        except yaml.YAMLError as exc:
            raise ValueError(
                f"Could not parse ZAP AF plan template YAML: {template_path}: {exc}"
            ) from exc
        except OSError as exc:
            raise ValueError(
                f"Could not read ZAP AF plan template: {template_path}: {exc}"
            ) from exc

        if not isinstance(template, dict):
            raise ValueError("ZAP AF plan template must be a YAML object at the top level.")
        if "jobs" in template and not isinstance(template.get("jobs"), list):
            raise ValueError("ZAP AF plan template 'jobs' must be a YAML list.")

        return template

    def _resolve_template_automation_plan(
        self,
        template: Dict[str, Any],
        *,
        target: str,
        report_filename: str,
        xml_report_filename: Optional[str],
        active_scan: bool,
        timeout: int,
        report_dir: str,
    ) -> Dict[str, Any]:
        """
        Patch a user-supplied template with runtime-controlled values.

        The runtime always controls the primary context identity/scope, report
        destination, and timeout-derived values for the small set of managed AF
        jobs. Other template sections are preserved as supplied.
        """
        resolved = deepcopy(template)
        context_url = self._context_url(target)
        start_url = self._automation_start_url(target)
        scope_pattern = self._scope_pattern(target)
        timeout_minutes = self._timeout_minutes(timeout)

        env = resolved.get("env")
        if not isinstance(env, dict):
            env = {}
        parameters = env.get("parameters")
        if not isinstance(parameters, dict):
            parameters = {}
        parameters.setdefault("failOnError", False)
        parameters.setdefault("failOnWarning", False)
        parameters.setdefault("continueOnFailure", True)
        parameters.setdefault("progressToStdout", True)
        env["parameters"] = parameters
        env["contexts"] = self._resolve_template_contexts(
            env.get("contexts"),
            context_url=context_url,
            scope_pattern=scope_pattern,
        )
        resolved["env"] = env

        jobs = resolved.get("jobs", [])
        resolved["jobs"] = self._resolve_template_jobs(
            jobs,
            start_url=start_url,
            timeout_minutes=timeout_minutes,
            report_dir=report_dir,
            report_filename=report_filename,
            xml_report_filename=xml_report_filename,
            context_url=context_url,
            active_scan_requested=active_scan,
        )
        return resolved

    def _resolve_template_contexts(
        self,
        contexts: Any,
        *,
        context_url: str,
        scope_pattern: str,
    ) -> List[Any]:
        """
        Build the runtime-managed primary context while preserving template extras.

        The first valid user context is deep-copied and only its runtime-critical
        fields are forced: ``name``, ``urls``, and ``includePaths``. Any other
        fields on that context and any additional contexts are kept as-is so
        richer AF templates do not lose authentication/session settings.
        """
        source_context: Optional[Dict[str, Any]] = None
        preserved_contexts: List[Any] = []

        if isinstance(contexts, list):
            source_index: Optional[int] = None
            for index, context in enumerate(contexts):
                if source_index is None and isinstance(context, dict):
                    source_index = index
                    source_context = deepcopy(context)
                    continue
                preserved_contexts.append(deepcopy(context))

        managed_context = source_context or {}
        managed_context["name"] = ZAP_AUTOMATION_CONTEXT
        managed_context["urls"] = [context_url]
        managed_context["includePaths"] = [scope_pattern]
        return [managed_context, *preserved_contexts]

    def _resolve_template_jobs(
        self,
        jobs: List[Any],
        *,
        start_url: str,
        timeout_minutes: int,
        report_dir: str,
        report_filename: str,
        xml_report_filename: Optional[str],
        context_url: str,
        active_scan_requested: bool,
    ) -> List[Any]:
        """
        Patch the runtime-managed AF jobs and preserve the rest of the template.

        Only the runtime-owned crawl/scan/report parameters are rewritten
        directly. Other AF job types and unrelated parameters remain
        template-owned.
        """
        resolved_jobs: List[Any] = []
        first_report_index: Optional[int] = None
        has_active_scan = False
        has_report = False

        for job in jobs:
            resolved_job = deepcopy(job)
            if not isinstance(resolved_job, dict):
                resolved_jobs.append(resolved_job)
                continue

            job_type = str(resolved_job.get("type") or "").strip()
            parameters = self._ensure_job_parameters(resolved_job)

            # Keep the runtime-managed scope and timing aligned for the job
            # types that directly depend on them, while preserving everything
            # else from the user template.
            if job_type == "spider":
                parameters["context"] = ZAP_AUTOMATION_CONTEXT
                parameters["url"] = start_url
                parameters["maxDuration"] = timeout_minutes
            elif job_type == "spiderAjax":
                parameters["context"] = ZAP_AUTOMATION_CONTEXT
                parameters["url"] = start_url
                parameters["maxDuration"] = timeout_minutes
            elif job_type == "passiveScan-wait":
                parameters["maxDuration"] = timeout_minutes
            elif job_type == "activeScan":
                has_active_scan = True
                parameters["context"] = ZAP_AUTOMATION_CONTEXT
                parameters["url"] = start_url
                parameters["maxRuleDurationInMins"] = timeout_minutes
                parameters["maxScanDurationInMins"] = timeout_minutes
            elif job_type == "report":
                has_report = True
                if first_report_index is None:
                    first_report_index = len(resolved_jobs)

            resolved_jobs.append(resolved_job)

        insert_index = first_report_index if first_report_index is not None else len(resolved_jobs)
        if active_scan_requested and not has_active_scan:
            resolved_jobs.insert(
                insert_index,
                self._build_active_scan_job(start_url, timeout_minutes),
            )
            resolved_jobs.insert(
                insert_index + 1,
                self._build_passive_scan_wait_job(timeout_minutes),
            )
            has_active_scan = True

        report_title = (
            f"ZAP {'active' if has_active_scan else 'baseline'} scan for {context_url}"
        )
        report_description = (
            "Generated by vuln-manager using the ZAP Automation Framework."
        )

        for resolved_job in resolved_jobs:
            if not isinstance(resolved_job, dict):
                continue
            if str(resolved_job.get("type") or "").strip() != "report":
                continue
            self._patch_report_job(
                resolved_job,
                report_dir=report_dir,
                report_filename=report_filename,
                report_title=report_title,
                report_description=report_description,
            )

        if not has_report:
            resolved_jobs.append(
                self._build_report_job(
                    report_filename=report_filename,
                    report_dir=report_dir,
                    active_scan=has_active_scan,
                    context_url=context_url,
                )
            )
        if xml_report_filename:
            resolved_jobs.append(
                self._build_report_job(
                    report_filename=xml_report_filename,
                    report_dir=report_dir,
                    active_scan=has_active_scan,
                    context_url=context_url,
                    report_template=ZAP_DEFECTDOJO_REPORT_TEMPLATE,
                )
            )

        return resolved_jobs

    @staticmethod
    def _ensure_job_parameters(job: Dict[str, Any]) -> Dict[str, Any]:
        """Return a mutable job parameter mapping, creating one when needed."""
        parameters = job.get("parameters")
        if not isinstance(parameters, dict):
            parameters = {}
            job["parameters"] = parameters
        return parameters

    @staticmethod
    def _plan_has_job(plan: Dict[str, Any], job_type: str) -> bool:
        """Return True when the plan includes a job of *job_type*."""
        jobs = plan.get("jobs", [])
        if not isinstance(jobs, list):
            return False
        return any(
            isinstance(job, dict) and str(job.get("type") or "").strip() == job_type
            for job in jobs
        )

    def _build_active_scan_job(self, start_url: str, timeout_minutes: int) -> Dict[str, Any]:
        """Build one active scan job using the standard runtime context."""
        return {
            "type": "activeScan",
            "parameters": {
                "context": ZAP_AUTOMATION_CONTEXT,
                "url": start_url,
                "maxRuleDurationInMins": timeout_minutes,
                "maxScanDurationInMins": timeout_minutes,
            },
        }

    @staticmethod
    def _build_passive_scan_wait_job(timeout_minutes: int) -> Dict[str, Any]:
        """Build one passive wait job using the runtime timeout budget."""
        return {
            "type": "passiveScan-wait",
            "parameters": {
                "maxDuration": timeout_minutes,
            },
        }

    def _build_report_job(
        self,
        *,
        report_filename: str,
        report_dir: str,
        active_scan: bool,
        context_url: str,
        report_template: str = ZAP_AUTOMATION_REPORT_TEMPLATE,
    ) -> Dict[str, Any]:
        """Build one ZAP Automation Framework report job."""
        return {
            "type": "report",
            "parameters": {
                "template": report_template,
                "reportDir": report_dir,
                "reportFile": report_filename,
                "reportTitle": f"ZAP {'active' if active_scan else 'baseline'} scan for {context_url}",
                "reportDescription": (
                    "Generated by vuln-manager using the ZAP Automation Framework."
                ),
            },
        }

    def _patch_report_job(
        self,
        job: Dict[str, Any],
        *,
        report_dir: str,
        report_filename: str,
        report_title: str,
        report_description: str,
    ) -> None:
        """Patch a template report job with the runtime-controlled output settings."""
        parameters = self._ensure_job_parameters(job)
        parameters["template"] = ZAP_AUTOMATION_REPORT_TEMPLATE
        parameters["reportDir"] = report_dir
        parameters["reportFile"] = report_filename
        parameters["reportTitle"] = report_title
        parameters["reportDescription"] = report_description

    @staticmethod
    def _attach_defectdojo_xml_artifact(result: Dict[str, Any], xml_report_path: Path) -> None:
        """Expose the ZAP XML report as the scanner-native DefectDojo import file."""
        if not xml_report_path.exists() or not xml_report_path.is_file():
            return

        artifact = {
            "path": str(xml_report_path),
            "artifact_format": "xml",
            "native": True,
            "role": "defectdojo-native-parser-input",
            "source": "zap-traditional-xml-report",
        }
        result["defectdojo_raw_artifact"] = artifact

        raw_artifacts = result.setdefault("raw_artifacts", [])
        if isinstance(raw_artifacts, list):
            for existing in raw_artifacts:
                if isinstance(existing, dict) and str(existing.get("path") or "") == str(xml_report_path):
                    existing.update(artifact)
                    break
            else:
                raw_artifacts.append(artifact)

    @staticmethod
    def _default_automation_plan_template_path() -> Path:
        """Return the repo-shipped AF template used when no custom plan is supplied."""
        return ZAP_DEFAULT_AUTOMATION_TEMPLATE

    @staticmethod
    def _automation_plan_runtime_controls() -> Dict[str, Any]:
        """Expose the runtime-managed AF fields for scan metadata and debugging."""
        return {
            "runtime_owned_fields": deepcopy(ZAP_AUTOMATION_RUNTIME_OWNED_FIELDS),
            "notes": list(ZAP_AUTOMATION_RUNTIME_CONTROL_NOTES),
        }

    def _write_automation_plan(self, plan_path: Path, plan: Dict[str, Any]) -> None:
        """Persist a generated AF plan next to the raw report artifacts."""
        with open(plan_path, "w", encoding="utf-8") as fh:
            yaml.safe_dump(plan, fh, sort_keys=False)

    @staticmethod
    def _selinux_enforce_path() -> Path:
        """Return the Linux SELinux state file used for Docker bind-mount relabel checks."""
        return Path("/sys/fs/selinux/enforce")

    @classmethod
    def _docker_bind_mount_spec(cls, raw_dir: Path) -> str:
        """
        Build the /zap/wrk bind mount spec.

        On SELinux-enabled Linux hosts, add a private relabel so the ZAP
        container can write raw artifacts into the mounted directory.
        """
        options = ["rw"]
        if sys.platform.startswith("linux"):
            try:
                if cls._selinux_enforce_path().exists():
                    options.append("Z")
            except OSError:
                pass
        return f"{raw_dir.resolve()}:{ZAP_DOCKER_WORK_DIR}:{','.join(options)}"

    @staticmethod
    def _artifact_dir_entries(report_path: Path, *, limit: int = 12) -> List[str]:
        """Return a compact snapshot of sibling artifacts near the expected report."""
        parent = report_path.parent
        if not parent.exists():
            return []

        entries: List[str] = []
        for entry in sorted(parent.iterdir(), key=lambda item: item.name):
            label = entry.name
            if entry.is_dir():
                label = f"{label}/"
            entries.append(label)

        if len(entries) <= limit:
            return entries
        hidden_count = len(entries) - limit
        return [*entries[:limit], f"... ({hidden_count} more)"]

    @staticmethod
    def _pick_unused_loopback_port() -> int:
        """Return an ephemeral loopback port for host-network Docker ZAP runs."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(("127.0.0.1", 0))
            return int(sock.getsockname()[1])

    @staticmethod
    def _has_explicit_proxy_port(extra_args: List[str]) -> bool:
        """Return True when the caller already chose a ZAP proxy port."""
        for index, arg in enumerate(extra_args):
            if arg == "-port":
                return True
            if arg.startswith("proxy.port="):
                return True
            if arg == "-config" and index + 1 < len(extra_args):
                if str(extra_args[index + 1]).startswith("proxy.port="):
                    return True
        return False

    @classmethod
    def _docker_runtime_args(
        cls,
        docker_network_args: List[str],
        extra_args: List[str],
    ) -> List[str]:
        """
        Return Docker-only runtime args prepended ahead of user-supplied ones.

        Linux host-network mode is required for loopback-host scans, but ZAP's
        default proxy port can collide with services already bound on the host.
        Pick an ephemeral port unless the caller already provided one.
        """
        if docker_network_args != ["--network", "host"]:
            return list(extra_args)
        if cls._has_explicit_proxy_port(extra_args):
            return list(extra_args)
        proxy_port = cls._pick_unused_loopback_port()
        return ["-config", f"proxy.port={proxy_port}", *extra_args]

    def _scan_docker(
        self,
        target: str,
        raw_dir: Path,
        plan_filename: str,
        report_path: Path,
        timestamp: str,
        timeout: int,
        extra_args: List[str],
    ) -> Dict[str, Any]:
        """Execute a ZAP Automation Framework plan via Docker."""
        docker_target, docker_network_args = self._docker_target_and_network_args(target)
        mount_spec = self._docker_bind_mount_spec(raw_dir)
        runtime_args = self._docker_runtime_args(docker_network_args, extra_args)

        cmd = [
            "docker",
            "run",
            "--rm",
            *docker_network_args,
            "-v",
            mount_spec,
            "-t",
            ZAP_DOCKER_IMAGE,
            "zap.sh",
            *runtime_args,
            "-cmd",
            "-autorun",
            f"{ZAP_DOCKER_WORK_DIR}/{plan_filename}",
        ]

        return self._run_subprocess(cmd, docker_target, report_path, timestamp, timeout)

    def _scan_local(
        self,
        binary: str,
        target: str,
        plan_path: Path,
        report_path: Path,
        timestamp: str,
        timeout: int,
        extra_args: List[str],
    ) -> Dict[str, Any]:
        """Execute a ZAP Automation Framework plan via a local ZAP binary."""
        cmd = [
            binary,
            *extra_args,
            "-cmd",
            "-autorun",
            str(plan_path),
        ]

        return self._run_subprocess(cmd, target, report_path, timestamp, timeout)

    def _run_subprocess(
        self,
        cmd: List[str],
        target: str,
        report_path: Path,
        timestamp: str,
        timeout: int,
    ) -> Dict[str, Any]:
        """Run *cmd* and return a normalized result dict."""
        cmd_str = " ".join(cmd)
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            self.last_scan_time = datetime.now(timezone.utc)

            raw_data, findings, report_exists, actual_report_path, report_issue = (
                self._load_report_output(report_path)
            )

            if not report_exists:
                artifact_entries = self._artifact_dir_entries(report_path)
                summary = self._summarize_process_output(result.stdout, result.stderr)
                error = (
                    f"ZAP did not create the expected report file: {report_path}. "
                    f"Command: {cmd_str}"
                )
                if report_issue:
                    error = f"{error}. Report load issue: {report_issue}"
                if artifact_entries:
                    error = f"{error}. Artifact dir entries: {', '.join(artifact_entries)}"
                if summary:
                    error = f"{error}. {summary}"
                return {
                    "scanner": self.name,
                    "target": target,
                    "timestamp": timestamp,
                    "command": cmd_str,
                    "raw_output": None,
                    "raw_output_path": None,
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                    "exit_code": result.returncode,
                    "error": error,
                    "scanner_error": error,
                    "expected_raw_output_path": str(report_path),
                    "report_load_issue": report_issue,
                    "raw_artifact_dir_entries": artifact_entries,
                    "degraded_execution": True,
                    "findings": [],
                }

            effective_exit_code = result.returncode
            partial_error: Optional[str] = None
            if result.returncode in (1, 2):
                effective_exit_code = 0
                status = "errors" if result.returncode == 1 else "warnings"
                summary = self._summarize_process_output(result.stdout, result.stderr)
                partial_error = (
                    "ZAP Automation Framework reported "
                    f"{status} but still produced a report."
                )
                if summary:
                    partial_error = f"{partial_error} {summary}"

            payload = {
                "scanner": self.name,
                "target": target,
                "timestamp": timestamp,
                "command": cmd_str,
                "raw_output": raw_data,
                "raw_output_path": str(actual_report_path),
                "stdout": result.stdout,
                "stderr": result.stderr,
                "exit_code": effective_exit_code,
                "raw_exit_code": result.returncode,
                "findings": findings,
            }
            if actual_report_path != report_path:
                payload["expected_raw_output_path"] = str(report_path)
                payload["report_recovered"] = True
            if partial_error:
                payload["error"] = partial_error
                payload["scanner_error"] = partial_error
                payload["degraded_execution"] = True
            return payload

        except subprocess.TimeoutExpired as exc:
            self.last_scan_time = datetime.now(timezone.utc)
            stdout = self._coerce_timeout_stream(exc.stdout)
            stderr = self._coerce_timeout_stream(exc.stderr)
            raw_data, findings, report_exists, actual_report_path, report_issue = (
                self._load_report_output(report_path)
            )

            if report_exists:
                summary = self._summarize_process_output(stdout, stderr)
                error = (
                    f"Scan timed out after {timeout} seconds, but partial results were recovered "
                    f"from {actual_report_path}."
                )
                if summary:
                    error = f"{error} {summary}"
                payload = {
                    "scanner": self.name,
                    "target": target,
                    "timestamp": timestamp,
                    "command": cmd_str,
                    "raw_output": raw_data,
                    "raw_output_path": str(actual_report_path),
                    "stdout": stdout,
                    "stderr": stderr,
                    "exit_code": None,
                    "error": error,
                    "scanner_error": error,
                    "degraded_execution": True,
                    "findings": findings,
                    "partial_results": True,
                }
                if actual_report_path != report_path:
                    payload["expected_raw_output_path"] = str(report_path)
                    payload["report_recovered"] = True
                return payload

            artifact_entries = self._artifact_dir_entries(report_path)
            error = f"Scan timed out after {timeout} seconds."
            if report_issue:
                error = f"{error} Report load issue: {report_issue}"
            if artifact_entries:
                error = f"{error} Artifact dir entries: {', '.join(artifact_entries)}"
            return {
                "scanner": self.name,
                "target": target,
                "timestamp": timestamp,
                "command": cmd_str,
                "raw_output": None,
                "raw_output_path": None,
                "stdout": stdout,
                "stderr": stderr,
                "exit_code": None,
                "error": error,
                "scanner_error": error,
                "expected_raw_output_path": str(report_path),
                "report_load_issue": report_issue,
                "raw_artifact_dir_entries": artifact_entries,
                "degraded_execution": True,
                "findings": [],
            }
        except Exception as exc:
            error = str(exc)
            return {
                "scanner": self.name,
                "target": target,
                "timestamp": timestamp,
                "command": cmd_str,
                "raw_output": None,
                "raw_output_path": None,
                "stdout": "",
                "stderr": "",
                "exit_code": None,
                "error": error,
                "scanner_error": error,
                "degraded_execution": True,
                "findings": [],
            }

    @staticmethod
    def _coerce_timeout_stream(value: Any) -> str:
        """Normalize TimeoutExpired stdout/stderr into a safe text value."""
        if value is None:
            return ""
        if isinstance(value, bytes):
            return value.decode("utf-8", errors="replace")
        return str(value)

    def _load_report_output(
        self,
        report_path: Path,
    ) -> Tuple[Dict[str, Any], List[Dict[str, Any]], bool, Path, Optional[str]]:
        """
        Read the expected report, or safely recover a valid alternate report.

        ZAP AF should write the exact reportFile requested in the YAML plan. If
        a run wrote another valid traditional JSON report in the same raw
        artifact directory, recover that path instead of discarding the scan.
        """
        raw_data, findings, ok, issue = self._read_report_file(report_path)
        if ok:
            return raw_data, findings, True, report_path, None

        alternate = self._find_alternate_report(report_path)
        if alternate is not None:
            alt_path, alt_raw_data, alt_findings = alternate
            return alt_raw_data, alt_findings, True, alt_path, issue

        return {}, [], False, report_path, issue

    def _find_alternate_report(
        self,
        expected_report_path: Path,
    ) -> Optional[Tuple[Path, Dict[str, Any], List[Dict[str, Any]]]]:
        """Return a valid alternate ZAP JSON report from the same raw directory."""
        parent = expected_report_path.parent
        if not parent.exists():
            return None

        candidates: List[Tuple[float, Path, Dict[str, Any], List[Dict[str, Any]]]] = []
        for candidate in parent.glob("*.json"):
            if candidate == expected_report_path:
                continue
            raw_data, findings, ok, _ = self._read_report_file(candidate)
            if not ok:
                continue
            try:
                mtime = candidate.stat().st_mtime
            except OSError:
                mtime = 0.0
            candidates.append((mtime, candidate, raw_data, findings))

        if not candidates:
            return None

        zap_named = [candidate for candidate in candidates if candidate[1].name.startswith("zap_")]
        pool = zap_named or candidates
        _, path, raw_data, findings = sorted(pool, key=lambda item: item[0], reverse=True)[0]
        return path, raw_data, findings

    def _read_report_file(
        self,
        report_path: Path,
    ) -> Tuple[Dict[str, Any], List[Dict[str, Any]], bool, Optional[str]]:
        """Read one ZAP traditional JSON report and validate its basic shape."""
        if not report_path.exists():
            return {}, [], False, f"Report file does not exist: {report_path}"

        try:
            with open(report_path, "r", encoding="utf-8") as f:
                raw_data = json.load(f)
        except OSError as exc:
            return {}, [], False, f"Could not read report file {report_path}: {exc}"
        except json.JSONDecodeError as exc:
            return {}, [], False, f"Report file is not valid JSON: {report_path}: {exc}"

        if not isinstance(raw_data, dict):
            return {}, [], False, f"Report file is not a JSON object: {report_path}"
        if "site" not in raw_data:
            return {}, [], False, f"Report file is not a ZAP traditional JSON report: {report_path}"

        sites = raw_data.get("site")
        if isinstance(sites, dict):
            sites = [sites]
        if not isinstance(sites, list):
            return {}, [], False, f"ZAP report field 'site' must be an object or array: {report_path}"
        for site in sites:
            if not isinstance(site, dict):
                return {}, [], False, f"ZAP report contains a non-object site entry: {report_path}"
            alerts = site.get("alerts", [])
            if not isinstance(alerts, list):
                return {}, [], False, f"ZAP report site field 'alerts' must be an array: {report_path}"
            if not all(isinstance(alert, dict) for alert in alerts):
                return {}, [], False, f"ZAP report contains a non-object alert entry: {report_path}"

        findings = self._extract_findings_from_raw(raw_data)
        return raw_data, findings, True, None

    def _extract_findings_from_raw(
        self,
        raw_data: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """
        Flatten ZAP traditional JSON report into a list of alert dicts.
        """
        findings: List[Dict[str, Any]] = []
        sites = raw_data.get("site", [])
        if isinstance(sites, dict):
            sites = [sites]
        for site in sites:
            site_url = site.get("@name", "")
            alerts = site.get("alerts", [])
            if isinstance(alerts, list):
                for alert in alerts:
                    alert["_site_url"] = site_url
                    findings.append(alert)
        return findings

    def normalize(self, raw_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Convert raw ZAP results to the unified finding schema."""
        normalized: List[Dict[str, Any]] = []
        timestamp = raw_results.get(
            "timestamp",
            datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        )
        effective_target = raw_results.get("target", "")
        origin_target = raw_results.get("origin_target")
        if origin_target:
            origin_target = normalize_web_target(origin_target)
        original_target = normalize_web_target(
            raw_results.get("original_target") or origin_target or effective_target
        )
        proxy_mode = bool(raw_results.get("proxy_mode"))
        bridge_mode = bool(raw_results.get("bridge_mode")) or (
            bool(origin_target) and not proxy_mode
        )
        proxy_url = raw_results.get("proxy_url")
        adapter_mode = raw_results.get("adapter_mode")
        degraded_execution = bool(raw_results.get("degraded_execution"))
        scanner_error = raw_results.get("scanner_error")

        findings = raw_results.get("findings") or []
        if not findings:
            raw_output_path = raw_results.get("raw_output_path")
            if raw_output_path and Path(raw_output_path).exists():
                with open(raw_output_path, "r", encoding="utf-8") as fh:
                    try:
                        raw_data = json.load(fh)
                    except json.JSONDecodeError:
                        raw_data = {}
                findings = self._extract_findings_from_raw(raw_data)
            else:
                legacy = raw_results.get("raw_output", {})
                if isinstance(legacy, dict):
                    findings = self._extract_findings_from_raw(legacy)

        for alert in findings:
            name = alert.get("name") or alert.get("alert") or "ZAP Finding"
            severity = self._normalize_severity(
                alert.get("riskdesc") or alert.get("risk") or ""
            )

            instances = alert.get("instances", [])
            if instances and isinstance(instances, list):
                first_instance = instances[0]
                instance_url = (
                    first_instance.get("uri")
                    or first_instance.get("url")
                    or alert.get("_site_url")
                    or effective_target
                )
                asset_id = self._resolve_asset_id(
                    instance_url,
                    original_target=original_target,
                    effective_target=effective_target,
                    proxy_mode=proxy_mode,
                    bridge_mode=bridge_mode,
                )
                method = first_instance.get("method", "")
                param = first_instance.get("param", "")
                evidence = first_instance.get("evidence", "")
            else:
                asset_id = self._resolve_asset_id(
                    alert.get("_site_url") or effective_target,
                    original_target=original_target,
                    effective_target=effective_target,
                    proxy_mode=proxy_mode,
                    bridge_mode=bridge_mode,
                )
                method = ""
                param = ""
                evidence = alert.get("evidence", "")

            parsed = parse_target(asset_id)
            query_keys = sorted(parsed.get("query", {}).keys())

            cwe_raw = alert.get("cweid") or ""
            cwe = (
                f"CWE-{cwe_raw}"
                if str(cwe_raw).isdigit()
                else (str(cwe_raw) if cwe_raw else None)
            )

            description = self._strip_html(alert.get("desc", name))
            remediation = self._strip_html(
                alert.get("solution")
                or alert.get("otherinfo")
                or "Refer to ZAP alert documentation for remediation guidance."
            )

            meta: Dict[str, Any] = {
                "scanner": self.name,
                "timestamp": timestamp,
                "host": parsed["host"],
                "scheme": parsed["scheme"],
                "path": parsed["path"],
                "port": parsed["port"],
                "query_keys": query_keys,
                "method": method or None,
                "parameter": param or None,
                "confidence": alert.get("confidence") or alert.get("confidencedesc"),
                "risk": alert.get("riskdesc") or alert.get("risk"),
                "plugin_id": alert.get("pluginid") or alert.get("alertRef"),
                "cwe": cwe,
                "wasc_id": alert.get("wascid") or None,
                "evidence": evidence or None,
                "reference": alert.get("reference") or None,
                "proxy_mode": proxy_mode,
                "bridge_mode": True if bridge_mode else None,
                "adapter_mode": adapter_mode or None,
                "effective_target": effective_target,
                "original_target": original_target,
                "origin_target": origin_target if origin_target else None,
                "proxy_url": proxy_url if proxy_mode else None,
                "degraded_execution": True if degraded_execution else None,
                "scanner_error": scanner_error or None,
            }
            meta = {k: v for k, v in meta.items() if v is not None}

            finding: Dict[str, Any] = {
                "vulnerability_name": name,
                "severity": severity,
                "asset_id": asset_id,
                "description": description,
                "remediation": remediation,
                "meta": meta,
            }

            fps = create_fingerprints(finding)
            finding["fp_strict"] = fps["fp_strict"]
            finding["fp_general"] = fps["fp_general"]
            finding["fp_host_only"] = fps["fp_host_only"]

            normalized.append(finding)

        return normalized

    @classmethod
    def _docker_target_and_network_args(cls, target: str) -> Tuple[str, List[str]]:
        """
        Make host-loopback proxy targets reachable from Docker ZAP.

        - Linux: use host networking so 127.0.0.1/localhost resolves to the host.
        - Other OSes: rewrite loopback hostnames to host.docker.internal.
        """
        normalized_target = cls._require_target_url(target, field_name="target")
        if normalized_target is None:
            raise ValueError("ZAP Docker execution requires a target URL with scheme.")
        parsed = urlparse(normalized_target)
        if not cls._is_loopback_host(parsed.hostname):
            return normalized_target, []

        if sys.platform.startswith("linux"):
            return normalized_target, ["--network", "host"]

        rewritten = cls._replace_url_hostname(parsed, "host.docker.internal")
        return rewritten, []

    @staticmethod
    def _require_target_url(target: Optional[str], field_name: str) -> Optional[str]:
        """Return a URL with explicit scheme, or None when the value is not usable."""
        if target is None:
            return None
        target = str(target).strip()
        if not target:
            return None
        if target.startswith(("http://", "https://")):
            return target
        return None

    @classmethod
    def _automation_start_url(cls, target: str) -> str:
        """Return the runtime-managed crawl start URL with default ports canonicalized."""
        return cls._canonicalize_target_url(target, keep_query=True)

    @classmethod
    def _context_url(cls, target: str) -> str:
        """Return the scoped context URL with default ports stripped for ZAP matching."""
        return cls._canonicalize_target_url(target, keep_query=False)

    @classmethod
    def _scope_pattern(cls, target: str) -> str:
        """Return an AF includePaths regex matching the target subtree."""
        parsed = urlparse(cls._context_url(target))
        base = f"{parsed.scheme}://{parsed.netloc}"
        scoped_prefix = f"{base}{parsed.path or ''}".rstrip("/") or base
        return rf"^{re.escape(scoped_prefix)}(?:/.*)?(?:\?.*)?$"

    @classmethod
    def _canonicalize_target_url(
        cls,
        target: str,
        *,
        keep_query: bool,
    ) -> str:
        """
        Normalize a ZAP plan URL while stripping default ports from the authority.

        ZAP context matching is sensitive to literal host:port identity, so
        ``https://example.com:443/`` and ``https://example.com/`` should resolve
        to the same canonical value inside AF-managed context and job settings.
        """
        normalized_target = cls._require_target_url(target, field_name="target")
        if normalized_target is None:
            raise ValueError(
                "ZAP Automation Framework plans require a target URL with scheme."
            )

        parsed = urlparse(normalized_target)
        return urlunparse(
            (
                parsed.scheme,
                cls._canonicalize_netloc(parsed),
                parsed.path or "/",
                "",
                parsed.query if keep_query else "",
                "",
            )
        )

    @staticmethod
    def _canonicalize_netloc(parsed_url) -> str:
        """Return an authority value with default ports removed and auth preserved."""
        try:
            port = parsed_url.port
        except ValueError as exc:
            raise ValueError(
                f"ZAP Automation Framework target URL has an invalid port: {parsed_url.geturl()}"
            ) from exc

        hostname = parsed_url.hostname or ""
        if ":" in hostname and not hostname.startswith("["):
            hostname = f"[{hostname}]"

        auth = ""
        if parsed_url.username:
            auth = parsed_url.username
            if parsed_url.password:
                auth += f":{parsed_url.password}"
            auth += "@"

        default_port = {"http": 80, "https": 443}.get((parsed_url.scheme or "").lower())
        if port is not None and port != default_port:
            hostname = f"{hostname}:{port}"
        return f"{auth}{hostname}"

    @staticmethod
    def _timeout_minutes(timeout: int) -> int:
        """Convert the external timeout to AF minute-based limits."""
        if timeout <= 0:
            return 0
        return max(1, ceil(timeout / 60))

    @staticmethod
    def _replace_url_hostname(parsed_url, hostname: str) -> str:
        """Return a URL with only the hostname replaced, preserving port."""
        port = f":{parsed_url.port}" if parsed_url.port is not None else ""
        auth = ""
        if parsed_url.username:
            auth = parsed_url.username
            if parsed_url.password:
                auth += f":{parsed_url.password}"
            auth += "@"
        replaced = parsed_url._replace(netloc=f"{auth}{hostname}{port}")
        return urlunparse(replaced)

    @staticmethod
    def _resolve_asset_id(
        instance_url: str,
        *,
        original_target: str,
        effective_target: str,
        proxy_mode: bool,
        bridge_mode: bool = False,
    ) -> str:
        """Map a ZAP instance URL onto the original target in proxy or bridge mode."""
        preserve_original_identity = proxy_mode or bridge_mode
        if not instance_url:
            return original_target if preserve_original_identity else effective_target
        if not preserve_original_identity:
            return instance_url

        original = urlparse(normalize_web_target(original_target))
        effective = urlparse(normalize_web_target(effective_target))

        if instance_url.startswith(("http://", "https://")):
            parsed = urlparse(instance_url)
            if ZapScanner._is_proxy_instance_url(parsed, effective):
                return ZapScanner._replace_url_identity(parsed, original)
            return instance_url

        path = instance_url if instance_url.startswith("/") else f"/{instance_url}"
        base = f"{original.scheme}://{original.netloc}"
        return urljoin(base, path)

    @staticmethod
    def _replace_url_identity(parsed_url, replacement_base) -> str:
        """Rebuild a URL with the original target identity and instance path/query."""
        path = parsed_url.path or replacement_base.path or "/"
        replaced = parsed_url._replace(
            scheme=replacement_base.scheme,
            netloc=replacement_base.netloc,
            path=path,
            params="",
            fragment="",
        )
        return urlunparse(replaced)

    @staticmethod
    def _is_proxy_instance_url(parsed_url, effective_base) -> bool:
        """Return True when an instance URL still points at the effective scan endpoint."""
        if not parsed_url.scheme or not parsed_url.hostname:
            return False

        if parsed_url.netloc == effective_base.netloc:
            return True

        parsed_port = parsed_url.port or ZapScanner._default_port(parsed_url.scheme)
        effective_port = effective_base.port or ZapScanner._default_port(effective_base.scheme)
        same_scheme = parsed_url.scheme == effective_base.scheme
        same_port = parsed_port == effective_port
        same_host = parsed_url.hostname == effective_base.hostname
        same_loopback = (
            ZapScanner._is_loopback_host(parsed_url.hostname)
            and ZapScanner._is_loopback_host(effective_base.hostname)
        )

        return same_scheme and same_port and (same_host or same_loopback)

    @staticmethod
    def _default_port(scheme: str) -> Optional[int]:
        if scheme == "https":
            return 443
        if scheme == "http":
            return 80
        return None

    @staticmethod
    def _is_loopback_host(hostname: Optional[str]) -> bool:
        if not hostname:
            return False
        host = hostname.lower()
        return host == "localhost" or host == "127.0.0.1" or host == "::1"

    @staticmethod
    def _normalize_severity(risk_label: str) -> str:
        """
        Map a ZAP risk description to the unified severity string.
        """
        key = risk_label.strip().lower().split()[0] if risk_label.strip() else ""
        return _SEVERITY_MAP.get(key, "info")

    @staticmethod
    def _strip_html(text: str) -> str:
        """Remove HTML tags from ZAP alert description/solution strings."""
        if not text:
            return ""
        clean = re.sub(r"<[^>]+>", " ", text)
        clean = re.sub(r"&amp;", "&", clean)
        clean = re.sub(r"&lt;", "<", clean)
        clean = re.sub(r"&gt;", ">", clean)
        clean = re.sub(r"&nbsp;", " ", clean)
        clean = re.sub(r"\s+", " ", clean).strip()
        return clean
