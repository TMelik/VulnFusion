"""
Wapiti Scanner Integration

Runs wapiti web vulnerability scans using subprocess and normalizes JSON output to unified schema.
"""

import subprocess
import shutil
import json
import re
import tempfile
from xml.dom.minidom import Document
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pathlib import Path

from .base import BaseScanner
from utils.normalizer import normalize_web_target, parse_target, remap_absolute_asset_to_origin

class WapitiScanner(BaseScanner):
    """Wapiti scanner implementation for web vulnerability detection."""

    def __init__(self):
        super().__init__('wapiti')
        self.scanner_type = 'web'
        self.supports_http2_direct = False
        self.supports_proxy = True
        self.supports_http2_bridge = True

    def is_available(self) -> bool:
        """Check if wapiti is installed."""
        return shutil.which('wapiti') is not None

    def get_version(self) -> Optional[str]:
        """Get wapiti version — returns only the clean semver string."""
        import re
        try:
            result = subprocess.run(
                ['wapiti', '--version'],
                capture_output=True,
                text=True,
                timeout=10
            )
            output = result.stdout.strip() or result.stderr.strip()
            match = re.search(r'wapiti\s+(\d+\.\d+[.\d]*)', output, re.IGNORECASE)
            if match:
                return match.group(1)
            lines = [l.strip() for l in output.splitlines() if l.strip()]
            return lines[-1] if lines else None
        except Exception:
            return None

    def get_default_options(self) -> Dict[str, Any]:
        """Return documented wapiti defaults exposed through scan config."""
        return {
            'timeout': 1800,
        }

    def get_supported_options(self) -> set[str]:
        """Return supported user-facing Wapiti option keys."""
        return {
            'modules',
            'severity',
            'level',
            'timeout',
            'proxy_url',
            'args',
            'extra_args',
        }

    def validate_options(self, options: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Validate and normalize user-supplied Wapiti options."""
        normalized = super().validate_options(options)
        self._validate_string_list_option(normalized, 'modules')
        self._validate_string_list_option(normalized, 'severity')
        self._validate_int_option(normalized, 'level', minimum=1, maximum=3)
        self._validate_int_option(normalized, 'timeout', minimum=1)
        self._validate_string_option(normalized, 'proxy_url')
        if 'severity' in normalized:
            normalized['severity'] = [str(level).lower() for level in normalized['severity']]
        self._normalize_extra_args(
            normalized,
            forbidden_flags={
                '--flush-session',
                '--level',
                '-f',
                '-m',
                '-o',
                '-p',
                '-u',
            },
        )
        return normalized

    def scan(self, target: str, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Run wapiti scan against target URL.

        Args:
            target: URL to scan
            options: Optional dict with:
                - modules: List[str] - specific modules to use
                - severity: List[str] - keep only selected severities
                - level: int - scan level (1-3)
                - proxy_url: str - optional upstream HTTP proxy URL
                - args: List[str] - additional wapiti arguments

        Returns:
            Dict with raw scan results
        """
        options = options or {}
        defaults = self.get_default_options()

        target = normalize_web_target(target)
        origin_target = normalize_web_target(options.get('origin_target', target))
        timeout = options.get('timeout')
        if timeout is None:
            timeout = int(defaults.get('timeout', 1800))
            if origin_target != target:
                timeout = max(timeout, 3600)

        timestamp = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
        temp_output, preserve_raw_output = self._raw_output_path(target, options, timestamp)

        cmd = ['wapiti', '-u', target, '-f', 'json', '-o', str(temp_output), '--flush-session']

        if 'modules' in options:
            cmd.extend(['-m', ','.join(options['modules'])])

        if 'level' in options:
            cmd.extend(['--level', str(options['level'])])

        if 'proxy_url' in options:
            # Upstream proxy hook for a local translation proxy. This is not
            # native Wapiti HTTP/2 support.
            cmd.extend(['-p', options['proxy_url']])

        if 'args' in options:
            cmd.extend(options['args'])

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )

            self.last_scan_time = datetime.now(timezone.utc)

            raw_data, findings = self._load_raw_output(
                temp_output,
                options,
                preserve_output=preserve_raw_output,
            )

            result_dict = {
                'scanner': self.name,
                'target': target,
                'origin_target': origin_target,
                'timestamp': timestamp,
                'command': ' '.join(cmd),
                'raw_output': raw_data,
                'stderr': result.stderr,
                'exit_code': result.returncode,
                'findings': findings
            }
            if preserve_raw_output and temp_output.exists():
                result_dict['raw_output_path'] = str(temp_output)
                self._attach_defectdojo_xml_artifact(result_dict, temp_output, raw_data)
            # BUG-04 fix: thread severity filter through as a private metadata key
            # so normalize() can apply it AFTER unified severity labels are assigned.
            if 'severity' in options:
                result_dict['_severity_filter'] = options['severity']
            return result_dict

        except subprocess.TimeoutExpired as exc:
            raw_data, findings = self._load_raw_output(
                temp_output,
                options,
                preserve_output=preserve_raw_output,
            )
            result_dict = {
                'scanner': self.name,
                'target': target,
                'origin_target': origin_target,
                'timestamp': timestamp,
                'command': ' '.join(cmd),
                'error': 'Scan timeout',
                'raw_output': raw_data,
                'stdout': self._coerce_timeout_stream(exc.stdout),
                'stderr': self._coerce_timeout_stream(exc.stderr),
                'exit_code': None,
                'findings': findings,
                'partial_results': bool(findings),
            }
            if preserve_raw_output and temp_output.exists():
                result_dict['raw_output_path'] = str(temp_output)
                self._attach_defectdojo_xml_artifact(result_dict, temp_output, raw_data)
            if 'severity' in options:
                result_dict['_severity_filter'] = options['severity']
            return result_dict
        except Exception as e:
            if temp_output.exists() and not preserve_raw_output:
                temp_output.unlink()
            return {
                'scanner': self.name,
                'target': target,
                'origin_target': origin_target,
                'timestamp': timestamp,
                'command': ' '.join(cmd),
                'error': str(e),
                'findings': []
            }

    def _raw_output_path(self, target: str, options: Dict[str, Any], timestamp: str) -> tuple[Path, bool]:
        """Return the native Wapiti JSON output path and whether it should be preserved."""
        output_dir = options.get('output_dir')
        if output_dir:
            raw_dir = Path(str(output_dir))
            raw_dir.mkdir(parents=True, exist_ok=True)
            safe_target = re.sub(r"[^\w.-]+", "_", target)[:80] or "target"
            stamp = timestamp.replace(":", "").replace("-", "").replace(".", "").replace("Z", "Z")
            return raw_dir / f"wapiti_{safe_target}_{stamp}.json", True

        tmp_file = tempfile.NamedTemporaryFile(
            prefix='wapiti_raw_', suffix='.json', delete=False
        )
        temp_output = Path(tmp_file.name)
        tmp_file.close()
        return temp_output, False

    def _attach_defectdojo_xml_artifact(
        self,
        result: Dict[str, Any],
        json_output_path: Path,
        raw_data: Dict[str, Any],
    ) -> None:
        """Expose a Wapiti XML report as the DefectDojo-native import file."""
        xml_output_path = Path(json_output_path).with_suffix('.xml')
        if not self._write_wapiti_xml_report(raw_data, xml_output_path):
            return

        artifact = {
            'path': str(xml_output_path),
            'artifact_format': 'xml',
            'native': True,
            'safe_importable': True,
            'role': 'defectdojo-native-parser-input',
            'source': 'wapiti-xml-report',
        }
        result['defectdojo_raw_artifact'] = artifact
        result['raw_artifacts'] = [
            {
                'path': str(json_output_path),
                'artifact_format': 'json',
                'native': True,
                'role': 'scanner-native-report',
                'source': 'raw_output_path',
            },
            artifact,
        ]

    def _write_wapiti_xml_report(self, raw_data: Dict[str, Any], output_path: Path) -> bool:
        """Render Wapiti JSON report data using Wapiti's XML report schema."""
        if not isinstance(raw_data, dict):
            return False

        try:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            xml_text = self._render_wapiti_xml_report(raw_data)
            output_path.write_text(xml_text, encoding='utf-8')
        except OSError:
            return False
        return output_path.exists() and output_path.is_file()

    def _render_wapiti_xml_report(self, raw_data: Dict[str, Any]) -> str:
        """Return XML matching Wapiti's native XML report structure."""
        doc = Document()
        report = doc.createElement('report')
        report.setAttribute('type', 'security')
        report.setAttribute('xmlns:xsi', 'http://www.w3.org/2001/XMLSchema-instance')
        doc.appendChild(report)

        report.appendChild(self._wapiti_report_infos_node(doc, raw_data.get('infos') or {}))

        vulnerabilities = doc.createElement('vulnerabilities')
        anomalies = doc.createElement('anomalies')
        additionals = doc.createElement('additionals')

        classifications = raw_data.get('classifications') or {}
        self._append_wapiti_flaws(
            doc,
            vulnerabilities,
            'vulnerability',
            raw_data.get('vulnerabilities') or {},
            classifications,
        )
        self._append_wapiti_flaws(
            doc,
            anomalies,
            'anomaly',
            raw_data.get('anomalies') or {},
            classifications,
        )
        self._append_wapiti_flaws(
            doc,
            additionals,
            'additional',
            raw_data.get('additionals') or {},
            classifications,
        )

        report.appendChild(vulnerabilities)
        report.appendChild(anomalies)
        report.appendChild(additionals)
        return doc.toprettyxml(indent='   ')

    def _wapiti_report_infos_node(self, doc: Document, infos: Dict[str, Any]) -> Any:
        report_infos = doc.createElement('report_infos')

        self._append_named_info(doc, report_infos, 'generatorName', 'wapiti')
        self._append_named_info(
            doc,
            report_infos,
            'generatorVersion',
            infos.get('version') or infos.get('generatorVersion') or 'Wapiti',
        )
        self._append_named_info(doc, report_infos, 'scope', infos.get('scope') or '')
        self._append_named_info(doc, report_infos, 'dateOfScan', infos.get('date') or '')
        self._append_named_info(doc, report_infos, 'target', infos.get('target') or '')
        self._append_named_info(
            doc,
            report_infos,
            'crawledPages',
            infos.get('crawled_pages_nbr') or infos.get('crawledPages') or '0',
        )

        auth_node = doc.createElement('info')
        auth_node.setAttribute('name', 'auth')
        auth_node.setAttribute('xsi:nil', 'true')
        report_infos.appendChild(auth_node)
        return report_infos

    @staticmethod
    def _append_named_info(doc: Document, parent: Any, name: str, value: Any) -> None:
        node = doc.createElement('info')
        node.setAttribute('name', name)
        node.appendChild(doc.createTextNode(str(value or '')))
        parent.appendChild(node)

    def _append_wapiti_flaws(
        self,
        doc: Document,
        parent: Any,
        flaw_node_name: str,
        entries_by_category: Any,
        classifications: Any,
    ) -> None:
        if not isinstance(entries_by_category, dict):
            return

        for category, entries in entries_by_category.items():
            if not isinstance(entries, list):
                continue

            classification = classifications.get(category, {}) if isinstance(classifications, dict) else {}
            if not isinstance(classification, dict):
                classification = {}

            flaw_node = doc.createElement(flaw_node_name)
            flaw_node.setAttribute('name', str(category))
            self._append_cdata_element(doc, flaw_node, 'description', classification.get('desc') or '')
            self._append_cdata_element(doc, flaw_node, 'solution', classification.get('sol') or '')
            flaw_node.appendChild(self._wapiti_references_node(doc, classification))

            entries_node = doc.createElement('entries')
            for entry in entries:
                if isinstance(entry, dict):
                    entries_node.appendChild(self._wapiti_entry_node(doc, entry, classification))
            flaw_node.appendChild(entries_node)
            parent.appendChild(flaw_node)

    def _wapiti_references_node(self, doc: Document, classification: Dict[str, Any]) -> Any:
        references_node = doc.createElement('references')
        references = classification.get('ref') or {}
        if isinstance(references, dict):
            items = references.items()
        elif isinstance(references, list):
            items = ((str(ref), str(ref)) for ref in references)
        else:
            items = ()

        wstg_codes = self._coerce_wstg_codes(classification.get('wstg'))
        for title, url in items:
            reference_node = doc.createElement('reference')
            self._append_text_element(doc, reference_node, 'title', title)
            self._append_text_element(doc, reference_node, 'url', url)
            wstg_node = doc.createElement('wstg')
            for code in wstg_codes:
                self._append_text_element(doc, wstg_node, 'code', code)
            reference_node.appendChild(wstg_node)
            references_node.appendChild(reference_node)
        return references_node

    def _wapiti_entry_node(self, doc: Document, entry: Dict[str, Any], classification: Dict[str, Any]) -> Any:
        entry_node = doc.createElement('entry')
        self._append_text_element(doc, entry_node, 'method', entry.get('method') or '')
        self._append_text_element(doc, entry_node, 'path', entry.get('path') or entry.get('url') or '')
        self._append_text_element(doc, entry_node, 'level', entry.get('level') or entry.get('severity') or '')
        self._append_text_element(doc, entry_node, 'parameter', entry.get('parameter') or '')
        self._append_text_element(doc, entry_node, 'info', entry.get('info') or entry.get('description') or '')
        self._append_text_element(doc, entry_node, 'referer', entry.get('referer') or '')
        self._append_text_element(doc, entry_node, 'module', entry.get('module') or '')
        self._append_cdata_element(doc, entry_node, 'http_request', entry.get('http_request') or '')
        self._append_cdata_element(doc, entry_node, 'curl_command', entry.get('curl_command') or '')

        wstg_node = doc.createElement('wstg')
        wstg_codes = self._coerce_wstg_codes(entry.get('wstg') or classification.get('wstg'))
        for code in wstg_codes:
            self._append_text_element(doc, wstg_node, 'code', code)
        entry_node.appendChild(wstg_node)
        return entry_node

    @staticmethod
    def _append_text_element(doc: Document, parent: Any, name: str, value: Any) -> None:
        node = doc.createElement(name)
        node.appendChild(doc.createTextNode(str(value or '')))
        parent.appendChild(node)

    @staticmethod
    def _append_cdata_element(doc: Document, parent: Any, name: str, value: Any) -> None:
        node = doc.createElement(name)
        node.appendChild(doc.createCDATASection(str(value or '')))
        parent.appendChild(node)

    @staticmethod
    def _coerce_wstg_codes(value: Any) -> List[str]:
        if isinstance(value, list):
            return [str(item) for item in value if item]
        if isinstance(value, str) and value.strip():
            return [value.strip()]
        return []

    @staticmethod
    def _coerce_timeout_stream(value: Any) -> str:
        """Normalize TimeoutExpired stdout/stderr into a safe text value."""
        if value is None:
            return ''
        if isinstance(value, bytes):
            return value.decode('utf-8', errors='replace')
        return str(value)

    def _load_raw_output(
        self,
        temp_output: Path,
        options: Dict[str, Any],
        *,
        preserve_output: bool = False,
    ) -> tuple[Dict[str, Any], List[Dict[str, Any]]]:
        """Read the JSON output file when available and extract findings."""
        raw_data: Dict[str, Any] = {}
        findings: List[Dict[str, Any]] = []

        if not temp_output.exists():
            return raw_data, findings

        try:
            with open(temp_output, 'r') as f:
                raw_data = json.load(f)
        except (OSError, json.JSONDecodeError):
            raw_data = {}
        else:
            findings = self._extract_findings_from_raw(raw_data)
            # BUG-04 fix: severity filtering is NOT applied here against the raw
            # finding shape.  Raw Wapiti findings use integer 'level' and missing
            # severities for categories like 'informations', so filtering against
            # the raw data would silently drop valid findings.  The filter is now
            # applied in normalize() after unified severity labels are assigned.
        finally:
            if not preserve_output:
                try:
                    temp_output.unlink()
                except OSError:
                    pass

        return raw_data, findings

    def _extract_findings_from_raw(self, raw_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Flatten Wapiti's nested JSON structure into a list of findings."""
        findings = []

        for category_type in ["vulnerabilities", "anomalies", "additionals", "informations"]:
            container = raw_data.get(category_type, {})
            if isinstance(container, dict):
                for category_name, issue_list in container.items():
                    if isinstance(issue_list, list):
                        for issue in issue_list:
                            if isinstance(issue, dict):
                                issue['_category'] = category_name
                                issue['_type'] = category_type
                                findings.append(issue)
            elif isinstance(container, list):
                 for issue in container:
                    if isinstance(issue, dict):
                        issue['_type'] = category_type
                        findings.append(issue)

        return findings

    def normalize(self, raw_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Convert wapiti results to unified schema format."""
        return self._normalize_raw(raw_results)

    def _normalize_raw(self, raw_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        normalized: List[Dict[str, Any]] = []  # BUG-04 split: was in normalize(), moved here
        timestamp = raw_results.get('timestamp', datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'))
        raw_data = raw_results.get('raw_output', {})

        scanned_target = raw_results.get('target') or raw_data.get('target') or ''
        origin_target = raw_results.get('origin_target') or raw_data.get('target') or raw_results.get('target', '')
        original_target = raw_results.get('original_target') or origin_target or raw_results.get('target', '')
        adapter_mode = raw_results.get('adapter_mode')
        degraded_execution = bool(raw_results.get('degraded_execution'))
        scanner_error = raw_results.get('scanner_error')
        base_url = origin_target or raw_data.get('target') or raw_results.get('target', '')

        if scanned_target:
            scanned_target = normalize_web_target(scanned_target)
        if origin_target:
            origin_target = normalize_web_target(origin_target)
        if original_target:
            original_target = normalize_web_target(original_target)
        if base_url:
            base_url = normalize_web_target(base_url)

        classifications = raw_data.get('classifications', {})

        for finding in raw_results.get('findings', []):
            category = finding.get('_category', 'Generic')
            name = finding.get('name') or category
            internal_server_error = self._classify_internal_server_error(category, finding)
            if internal_server_error and internal_server_error.get('action') == 'skip':
                continue

            severity = self._normalize_severity(finding.get('severity') or finding.get('level'))
            if internal_server_error and internal_server_error.get('severity'):
                severity = str(internal_server_error['severity'])

            path_raw = finding.get('path') or finding.get('url') or ''
            path_raw = remap_absolute_asset_to_origin(path_raw, scanned_target, origin_target)
            asset_id = path_raw if path_raw.startswith('http') else (base_url.rstrip('/') + '/' + path_raw.lstrip('/'))

            # Parse asset_id URL into structured components once.
            parsed = parse_target(asset_id)
            query_keys = sorted(parsed.get('query', {}).keys())

            classification = classifications.get(category, {})
            description = str(
                finding.get('description')
                or finding.get('info')
                or ''
            ).strip()
            remediation = str(
                finding.get('remediation')
                or finding.get('solution')
                or finding.get('fix')
                or ''
            ).strip()

            meta = {
                'scanner': self.name,
                'timestamp': timestamp,
                # Structured location fields (v2.0 contract)
                'host': parsed['host'],
                'scheme': parsed['scheme'],
                'path': parsed['path'],
                'port': parsed['port'],
                'query_keys': query_keys,
                # Wapiti-specific fields
                'category': category,
                'type': finding.get('_type'),
                'module': finding.get('module'),
                'wstg': finding.get('wstg'),
                'method': finding.get('method'),
                'parameter': finding.get('parameter'),
                'http_request': finding.get('http_request'),
                'curl_command': finding.get('curl_command'),
                'references': self._extract_references(classification, finding),
                'classification_description': classification.get('desc') or None,
                'classification_solution': classification.get('sol') or None,
                'effective_target': scanned_target or None,
                'origin_target': origin_target or None,
                'original_target': original_target or None,
                'adapter_mode': adapter_mode or None,
                'degraded_execution': True if degraded_execution else None,
                'scanner_error': scanner_error or None,
            }
            if internal_server_error:
                meta['internal_server_error_classification'] = internal_server_error.get('classification')
                meta['reproducible'] = bool(internal_server_error.get('reproducible'))
                if internal_server_error.get('response_error_pattern'):
                    meta['response_error_pattern'] = internal_server_error.get('response_error_pattern')
                if internal_server_error.get('confidence'):
                    meta['confidence'] = internal_server_error.get('confidence')

            meta = {key: value for key, value in meta.items() if value is not None}

            normalized.append({
                'vulnerability_name': name,
                'severity': severity,
                'asset_id': asset_id,
                'description': description,
                'remediation': remediation,
                'meta': meta
            })

        return normalized

    def _apply_severity_filter(
        self,
        normalized: List[Dict[str, Any]],
        allowed_severities: List[str],
    ) -> List[Dict[str, Any]]:
        """Filter normalized findings by unified severity label.

        BUG-04 fix: filtering is now applied against the already-normalized
        'severity' field rather than the raw Wapiti level/category data.
        """
        allowed = {
            self._normalize_severity(s)
            for s in allowed_severities
            if s is not None
        }
        return [f for f in normalized if f.get('severity') in allowed]

    def normalize(self, raw_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Convert wapiti results to unified schema format, then apply any
        severity filter that was requested via options."""
        normalized = self._normalize_raw(raw_results)
        # BUG-04 fix: filter after normalization so that unified severity labels
        # (computed from raw integer levels + category names) are used, not the
        # raw Wapiti-internal representation.
        severity_filter = raw_results.get('_severity_filter')
        if severity_filter:
            normalized = self._apply_severity_filter(normalized, severity_filter)
        return normalized

    def _classify_internal_server_error(self, category: Any, finding: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Classify Wapiti 500-style anomalies into noise, generic errors, or stronger candidates."""
        if str(category).strip().lower() != 'internal server error':
            return None

        path_or_url = finding.get('path') or finding.get('url')
        text = ' '.join(
            str(finding.get(field) or '')
            for field in ('name', 'description', 'info', '_category')
        ).lower()
        has_error_context = bool(
            '500' in text
            or 'internal server error' in text
            or 'http error' in text
        )
        has_parameter = bool(finding.get('parameter'))
        has_request_replay = bool(finding.get('http_request') or finding.get('curl_command'))
        has_method = bool(finding.get('method'))
        has_module = bool(finding.get('module'))
        has_payload_context = any(
            token in text
            for token in (
                'payload',
                'inject',
                'injection',
                'exec',
                'command',
                'sql',
                'template',
                'traversal',
                'xss',
                'parameter ',
            )
        )

        if not path_or_url or not has_error_context:
            return {
                'action': 'skip',
                'classification': 'context_free_server_error',
                'reproducible': False,
                'response_error_pattern': 'generic_500',
                'confidence': 'low',
            }

        if has_parameter and has_request_replay and has_payload_context:
            return {
                'action': 'keep',
                'classification': 'probable_input_triggered_server_error',
                'severity': self._normalize_severity(finding.get('severity') or finding.get('level')),
                'reproducible': True,
                'response_error_pattern': 'input_triggered_500',
                'confidence': 'high',
            }

        if has_parameter or has_request_replay or has_method or has_module:
            return {
                'action': 'keep',
                'classification': 'generic_input_triggered_server_error',
                'severity': 'low',
                'reproducible': has_request_replay,
                'response_error_pattern': 'generic_500',
                'confidence': 'low',
            }

        return {
            'action': 'skip',
            'classification': 'context_free_server_error',
            'reproducible': False,
            'response_error_pattern': 'generic_500',
            'confidence': 'low',
        }

    def _normalize_severity(self, val: Any) -> str:
        """Map wapiti severity/level to standard levels."""
        if isinstance(val, int):
            mapping = {1: 'low', 2: 'medium', 3: 'high'}
            return mapping.get(val, 'info')

        s = str(val).lower()
        if 'crit' in s: return 'critical'
        if 'high' in s: return 'high'
        if 'med' in s: return 'medium'
        if 'low' in s: return 'low'
        return 'info'

    def _filter_findings_by_severity(
        self,
        findings: List[Dict[str, Any]],
        allowed_severities: List[str],
    ) -> List[Dict[str, Any]]:
        """Filter raw Wapiti findings using unified severity labels."""
        allowed = {
            self._normalize_severity(severity)
            for severity in allowed_severities
            if severity is not None
        }
        return [
            finding for finding in findings
            if self._normalize_severity(finding.get('severity') or finding.get('level')) in allowed
        ]

    def _extract_references(self, classification: Dict, finding: Dict) -> List[str]:
        """Extract reference URLs from classification and finding."""
        refs = []
        c_refs = classification.get('ref', {})
        if isinstance(c_refs, dict):
            refs.extend(c_refs.values())
        elif isinstance(c_refs, list):
            refs.extend(c_refs)

        f_refs = finding.get('references') or finding.get('refs')
        if isinstance(f_refs, list):
            refs.extend(f_refs)
        elif isinstance(f_refs, str):
            refs.append(f_refs)

        return list(set(str(r) for r in refs if r))

    def get_proxy_options(self, proxy_url: str) -> Dict[str, Any]:
        """Return proxy settings for routed execution."""
        return {'proxy_url': proxy_url}
