"""
Nikto Scanner Integration

Runs Nikto web server vulnerability scans using subprocess and normalizes JSON output to unified schema.
"""

import subprocess
import shutil
import json
import tempfile
import ipaddress
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pathlib import Path
from urllib.parse import urlparse, urlunparse

from .base import BaseScanner
from utils.normalizer import normalize_web_target, parse_target, remap_absolute_asset_to_origin

class NiktoScanner(BaseScanner):
    """Nikto scanner implementation for web server vulnerability detection."""

    _LOCAL_ADAPTER_MODES = frozenset({
        "bridge",
    })
    _SOFT_FAILURE_MARKERS = (
        "error limit (",
        "giving up",
        "scan terminated:",
    )
    _SOFT_FAILURE_CONTEXT_MARKERS = (
        "0 items reported on the remote host",
    )

    def __init__(self):
        super().__init__('nikto')
        self.scanner_type = 'web'
        self.supports_http2_direct = False
        self.supports_proxy = True
        self.supports_http2_bridge = True

    @classmethod
    def _uses_local_adapter(cls, options: Dict[str, Any]) -> bool:
        """Return True when Nikto is scanning a local compatibility adapter."""
        return str(options.get('adapter_mode') or '').strip().lower() in cls._LOCAL_ADAPTER_MODES

    @staticmethod
    def _args_include_flag(args: Any, flag: str) -> bool:
        """Return True when one passthrough arg already sets a reserved Nikto flag."""
        if not isinstance(args, list):
            return False
        normalized_flag = str(flag or '').strip().lower()
        if not normalized_flag:
            return False
        for arg in args:
            token = str(arg or '').strip().lower()
            if not token:
                continue
            if token == normalized_flag or token.startswith(f"{normalized_flag}="):
                return True
        return False

    @classmethod
    def _adapter_vhost(cls, options: Dict[str, Any]) -> Optional[str]:
        """Return the origin host identity Nikto should preserve through a local bridge."""
        if not cls._uses_local_adapter(options):
            return None

        origin_target = str(options.get('origin_target') or '').strip()
        if not origin_target:
            return None

        parsed = urlparse(normalize_web_target(origin_target))
        host = parsed.hostname or ''
        if not host:
            return None
        if ':' in host and not host.startswith('['):
            host = f'[{host}]'

        port = parsed.port
        default_port = 443 if parsed.scheme == 'https' else 80 if parsed.scheme == 'http' else None
        if port is not None and port != default_port:
            return f"{host}:{port}"
        return host

    @classmethod
    def _build_scan_target(cls, target: str, options: Dict[str, Any]) -> str:
        """
        Fold Nikto connection options into one URL target.

        Nikto rejects ``-port`` when ``-h`` already receives a full URI, so we
        keep scheme/port in the URL instead of mixing URI and legacy flags.
        """
        normalized = normalize_web_target(target)
        parsed = urlparse(normalized)

        scheme = parsed.scheme or 'https'
        if options.get('ssl') and not cls._uses_local_adapter(options):
            scheme = 'https'

        host = parsed.hostname or parsed.netloc
        if not host:
            return normalized

        auth = ''
        if parsed.username:
            auth = parsed.username
            if parsed.password:
                auth += f":{parsed.password}"
            auth += '@'

        port = parsed.port
        if port is None and options.get('port') is not None:
            try:
                port = int(options['port'])
            except (TypeError, ValueError):
                port = None

        netloc = f"{auth}{host}"
        if port is not None:
            netloc = f"{netloc}:{port}"

        return urlunparse((
            scheme,
            netloc,
            parsed.path,
            parsed.params,
            parsed.query,
            '',
        ))

    def is_available(self) -> bool:
        """Check if nikto is installed."""
        return shutil.which('nikto') is not None

    def get_version(self) -> Optional[str]:
        """Get nikto version."""
        try:
            result = subprocess.run(
                ['nikto', '-Version'],
                capture_output=True,
                text=True,
                timeout=10
            )
            output = result.stdout.strip() or result.stderr.strip()
            for line in output.split('\n'):
                if 'Nikto' in line or 'version' in line.lower():
                    return line.strip()
            return output
        except Exception:
            return None

    def get_default_options(self) -> Dict[str, Any]:
        """Return documented Nikto defaults exposed through scan config."""
        return {
            'timeout': 1800,
        }

    def get_supported_options(self) -> set[str]:
        """Return supported user-facing Nikto option keys."""
        return {
            'ssl',
            'port',
            'tuning',
            'timeout',
            'proxy_url',
            'args',
            'extra_args',
        }

    def validate_options(self, options: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Validate and normalize user-supplied Nikto options."""
        normalized = super().validate_options(options)
        self._validate_bool_option(normalized, 'ssl')
        self._validate_int_option(normalized, 'port', minimum=1, maximum=65535)
        self._validate_string_option(normalized, 'tuning')
        self._validate_int_option(normalized, 'timeout', minimum=1)
        self._validate_string_option(normalized, 'proxy_url')
        self._normalize_extra_args(
            normalized,
            forbidden_flags={
                '-Format',
                '-Tuning',
                '-h',
                '-output',
                '-port',
                '-ssl',
                '-useproxy',
            },
        )
        return normalized

    def scan(self, target: str, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Run nikto scan against target URL.

        Args:
            target: URL to scan
            options: Optional dict with:
                - ssl: bool - Force SSL mode
                - port: int - Port to scan
                - tuning: str - Tuning options (e.g., '1 2 3')
                - timeout: int - Timeout in seconds
                - proxy_url: str - optional upstream HTTP proxy URL
                - args: List[str] - additional nikto arguments

        Returns:
            Dict with raw scan results
        """
        options = options or {}
        defaults = self.get_default_options()

        target = self._build_scan_target(target, options)
        origin_target = normalize_web_target(options.get('origin_target', target))

        timestamp = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
        temp_output, preserve_raw_output = self._raw_output_path(target, options, timestamp)

        cmd = ['nikto', '-h', target, '-Format', 'json', '-output', str(temp_output)]
        bridge_vhost = self._adapter_vhost(options)
        if bridge_vhost and not self._args_include_flag(options.get('args'), '-vhost'):
            cmd.extend(['-vhost', bridge_vhost])

        if 'tuning' in options:
            cmd.extend(['-Tuning', str(options['tuning'])])

        if 'proxy_url' in options:
            # Upstream proxy hook for a local translation proxy. This is not
            # native Nikto HTTP/2 support.
            cmd.extend(['-useproxy', options['proxy_url']])

        if 'args' in options:
            cmd.extend(options['args'])

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=options.get('timeout', defaults.get('timeout', 1800))
            )

            self.last_scan_time = datetime.now(timezone.utc)

            findings = []
            raw_data = {}
            if temp_output.exists():
                with open(temp_output, 'r') as f:
                    content = f.read()
                    try:
                        raw_data = json.loads(content)
                    except json.JSONDecodeError:
                        raw_data = {'scans': []}
                        for line in content.strip().split('\n'):
                            if line.strip():
                                try:
                                    raw_data['scans'].append(json.loads(line))
                                except json.JSONDecodeError:
                                    pass

                findings = self._extract_findings_from_raw(raw_data)
                if not preserve_raw_output:
                    temp_output.unlink()

            result_dict = {
                'scanner': self.name,
                'target': target,
                'origin_target': origin_target,
                'timestamp': timestamp,
                'command': ' '.join(cmd),
                'raw_output': raw_data,
                'stderr': result.stderr,
                'stdout': result.stdout,
                'exit_code': result.returncode,
                'findings': findings
            }
            if preserve_raw_output and temp_output.exists():
                result_dict['raw_output_path'] = str(temp_output)
            return result_dict

        except subprocess.TimeoutExpired:
            # BUG-05 fix: attempt to read whatever Nikto wrote before the timeout
            # so that partial findings are not silently discarded.  Wapiti uses the
            # same pattern.  The result is flagged as partial/degraded.
            _partial_raw: Dict[str, Any] = {}
            _partial_findings: List[Dict[str, Any]] = []
            if temp_output.exists():
                try:
                    with open(temp_output, 'r') as _f:
                        _content = _f.read()
                    try:
                        _partial_raw = json.loads(_content)
                    except json.JSONDecodeError:
                        _partial_raw = {'scans': []}
                        for _line in _content.strip().split('\n'):
                            if _line.strip():
                                try:
                                    _partial_raw['scans'].append(json.loads(_line))
                                except json.JSONDecodeError:
                                    pass
                    _partial_findings = self._extract_findings_from_raw(_partial_raw)
                except OSError:
                    pass
                finally:
                    if not preserve_raw_output:
                        try:
                            temp_output.unlink()
                        except OSError:
                            pass
            result_dict = {
                'scanner': self.name,
                'target': target,
                'origin_target': origin_target,
                'timestamp': timestamp,
                'command': ' '.join(cmd),
                'error': 'Scan timeout',
                'raw_output': _partial_raw,
                'findings': _partial_findings,
                'partial_results': bool(_partial_findings),
            }
            if preserve_raw_output and temp_output.exists():
                result_dict['raw_output_path'] = str(temp_output)
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
        """Return the native Nikto JSON output path and whether it should be preserved."""
        output_dir = options.get('output_dir')
        if output_dir:
            raw_dir = Path(str(output_dir))
            raw_dir.mkdir(parents=True, exist_ok=True)
            safe_target = re.sub(r"[^\w.-]+", "_", target)[:80] or "target"
            stamp = timestamp.replace(":", "").replace("-", "").replace(".", "").replace("Z", "Z")
            return raw_dir / f"nikto_{safe_target}_{stamp}.json", True

        tmp_file = tempfile.NamedTemporaryFile(
            prefix='nikto_raw_', suffix='.json', delete=False
        )
        temp_output = Path(tmp_file.name)
        tmp_file.close()
        return temp_output, False

    def _extract_findings_from_raw(self, raw_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Flatten Nikto's JSON structure into a list of findings."""
        findings = []

        scans = []
        if isinstance(raw_data, dict):
            if 'vulnerabilities' in raw_data:
                scans.append(raw_data)
            elif 'scans' in raw_data:
                scans = raw_data.get('scans', [])
            else:
                scans.append(raw_data)
        elif isinstance(raw_data, list):
            scans = raw_data

        for scan in scans:
            if isinstance(scan, dict):
                vulns = scan.get('vulnerabilities', [])
                if isinstance(vulns, list):
                    findings.extend(vulns)

                items = scan.get('items', [])
                if isinstance(items, list):
                    findings.extend(items)

        return findings

    @staticmethod
    def _iter_raw_scans(raw_output: Any) -> List[Dict[str, Any]]:
        """Return normalized raw Nikto scan entries for execution analysis."""
        if isinstance(raw_output, list):
            scans = raw_output
        elif isinstance(raw_output, dict):
            if isinstance(raw_output.get('scans'), list):
                scans = raw_output.get('scans', [])
            else:
                scans = [raw_output]
        else:
            scans = []
        return [scan for scan in scans if isinstance(scan, dict)]

    @staticmethod
    def _is_loopback_host(value: Any) -> bool:
        """Return True when one host-like value refers to a local loopback adapter."""
        host = str(value or '').strip().strip('[]')
        if not host:
            return False
        if host.lower() == 'localhost':
            return True
        try:
            return ipaddress.ip_address(host).is_loopback
        except ValueError:
            return False

    @classmethod
    def _adapter_identity_signals(cls, raw_results: Dict[str, Any]) -> List[str]:
        """Collect signs that Nikto fingerprinted the local adapter instead of the origin."""
        if str(raw_results.get('adapter_mode') or '').strip().lower() not in cls._LOCAL_ADAPTER_MODES:
            return []

        signals: List[str] = []
        for scan in cls._iter_raw_scans(raw_results.get('raw_output')):
            host = scan.get('host')
            if cls._is_loopback_host(host):
                signal = f"reported host {host}"
                if signal not in signals:
                    signals.append(signal)
            ip = scan.get('ip')
            if cls._is_loopback_host(ip):
                signal = f"reported ip {ip}"
                if signal not in signals:
                    signals.append(signal)

        stdout = str(raw_results.get('stdout') or '')
        for line in stdout.splitlines():
            normalized_line = line.strip().lower()
            if not normalized_line.startswith('+ target hostname:'):
                continue
            reported_host = line.split(':', 1)[1].strip().split()[0] if ':' in line else ''
            if cls._is_loopback_host(reported_host):
                signal = f"reported host {reported_host}"
                if signal not in signals:
                    signals.append(signal)

        if 'server: uvicorn' in stdout.lower() and "server banner 'uvicorn'" not in signals:
            signals.append("server banner 'uvicorn'")

        return signals

    def assess_execution(self, raw_results: Dict[str, Any]) -> Dict[str, Any]:
        """Detect soft-failure cases that should not be reported as clean success."""
        stdout = str(raw_results.get('stdout') or '')
        stderr = str(raw_results.get('stderr') or '')
        combined = f"{stdout}\n{stderr}".lower()

        found_markers = [
            marker for marker in self._SOFT_FAILURE_MARKERS
            if marker in combined
        ]
        if not found_markers:
            return {}

        context_markers = [
            marker for marker in self._SOFT_FAILURE_CONTEXT_MARKERS
            if marker in combined
        ]
        marker_summary = found_markers + context_markers

        message = (
            "Nikto reported a degraded execution and the result is not trustworthy as a clean scan."
        )
        if marker_summary:
            message += f" Markers: {', '.join(marker_summary)}."
        adapter_identity_signals = self._adapter_identity_signals(raw_results)
        if adapter_identity_signals:
            message += (
                " Nikto appears to have fingerprinted the local compatibility adapter "
                "instead of the origin server."
            )
            message += f" Signals: {', '.join(adapter_identity_signals)}."

        assessment = {
            'degraded_execution': True,
            'scanner_error': message,
            'degraded_markers': marker_summary,
        }
        if adapter_identity_signals:
            assessment['adapter_identity_signals'] = adapter_identity_signals
        if raw_results.get('findings'):
            assessment['partial_results'] = True
        return assessment

    def normalize(self, raw_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Convert nikto results to unified schema format."""
        normalized = []
        timestamp = raw_results.get('timestamp', datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'))
        scanned_target = raw_results.get('target', '')
        target = raw_results.get('origin_target') or scanned_target
        original_target = raw_results.get('original_target') or target
        adapter_mode = raw_results.get('adapter_mode')
        degraded_execution = bool(raw_results.get('degraded_execution'))
        scanner_error = raw_results.get('scanner_error')
        if scanned_target:
            scanned_target = normalize_web_target(scanned_target)
        if target:
            target = normalize_web_target(target)
        if original_target:
            original_target = normalize_web_target(original_target)

        for finding in raw_results.get('findings', []):
            name = finding.get('msg') or finding.get('description') or finding.get('message') or 'Nikto Finding'

            severity = self._normalize_severity(finding)

            uri = finding.get('uri') or finding.get('url') or ''
            uri = remap_absolute_asset_to_origin(uri, scanned_target, target)
            if uri and not uri.startswith('http'):
                asset_id = target.rstrip('/') + uri
            elif uri:
                asset_id = uri
            else:
                asset_id = target

            # Derive structured location fields from the final normalized asset.
            parsed_asset = parse_target(asset_id)

            description = str(
                finding.get('description')
                or finding.get('message')
                or finding.get('msg')
                or ''
            ).strip()

            osvdb = finding.get('OSVDB') or finding.get('osvdb') or ''
            raw_id = str(osvdb) if osvdb else ''

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
                'host': parsed_asset['host'],
                'scheme': parsed_asset['scheme'],
                'path': parsed_asset['path'] or uri or '',
                'port': parsed_asset['port'],
                # Nikto-specific fields
                'raw_id': raw_id or None,
                'osvdb_id': osvdb or None,
                'method': finding.get('method'),
                'uri': uri or None,
                'references': self._extract_references(finding),
                'effective_target': scanned_target or None,
                'origin_target': target or None,
                'original_target': original_target or None,
                'adapter_mode': adapter_mode or None,
                'degraded_execution': True if degraded_execution else None,
                'scanner_error': scanner_error or None,
            }

            meta = {k: v for k, v in meta.items() if v is not None}

            normalized.append({
                'vulnerability_name': name,
                'severity': severity,
                'asset_id': asset_id,
                'description': description,
                'remediation': remediation,
                'meta': meta
            })

        return normalized

    def _normalize_severity(self, finding: Dict[str, Any]) -> str:
        """
        Map Nikto messages to standard severity levels.

        Nikto reports many informational checks. Unknown or weakly classified
        messages fall back to ``info`` on purpose so we do not overstate risk.
        """
        msg = " ".join(
            str(finding.get(field, ''))
            for field in ('msg', 'description', 'message')
        ).lower()

        if any(keyword in msg for keyword in [
            'remote code execution', 'code execution', 'rce',
            'sql injection', 'command injection',
            'authentication bypass', 'auth bypass',
        ]):
            return 'critical'

        if any(keyword in msg for keyword in [
            'xss', 'cross-site scripting',
            'directory traversal', 'path traversal',
            'file inclusion', 'local file inclusion', 'remote file inclusion',
            'arbitrary file upload', 'source disclosure',
        ]):
            return 'high'

        if any(keyword in msg for keyword in [
            'default credentials', 'default password',
            'outdated', 'end of life', 'unpatched',
            'misconfiguration', 'information disclosure',
            'directory indexing', 'admin interface',
            'backup', 'debug',
        ]):
            return 'medium'

        if any(keyword in msg for keyword in [
            'information', 'header', 'banner', 'cookie',
            'version disclosure', 'server leaks',
        ]):
            return 'low'

        return 'info'

    def _extract_references(self, finding: Dict[str, Any]) -> List[str]:
        """Extract reference URLs from finding."""
        refs = []

        osvdb = finding.get('OSVDB') or finding.get('osvdb')
        if osvdb:
            refs.append(f"OSVDB-{osvdb}")

        ref_field = finding.get('references') or finding.get('refs')
        if isinstance(ref_field, list):
            refs.extend(ref_field)
        elif isinstance(ref_field, str):
            refs.append(ref_field)

        return refs

    def get_proxy_options(self, proxy_url: str) -> Dict[str, Any]:
        """Return proxy settings for routed execution."""
        return {'proxy_url': proxy_url}
