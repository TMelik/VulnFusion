"""
Nuclei Scanner Integration

Runs nuclei vulnerability scans using subprocess and normalizes JSONL output to unified schema.
"""

import subprocess
import shutil
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, urlunparse

from .base import BaseScanner
from utils.normalizer import normalize_web_target, parse_target

class NucleiScanner(BaseScanner):
    """Nuclei scanner implementation for template-based vulnerability detection."""

    def __init__(self):
        super().__init__('nuclei')
        self.scanner_type = 'web'
        self.supports_http2_direct = True
        self.supports_proxy = True
        self.supports_http2_bridge = True

    def is_available(self) -> bool:
        """Check if nuclei is installed."""
        return shutil.which('nuclei') is not None

    def get_version(self) -> Optional[str]:
        """Get nuclei version — returns only the engine version string."""
        import re
        try:
            result = subprocess.run(
                ['nuclei', '-version'],
                capture_output=True,
                text=True,
                timeout=10
            )
            output = result.stdout.strip() or result.stderr.strip()
            match = re.search(r'Engine Version:\s*(v[\d.]+)', output)
            if match:
                return match.group(1)
            match = re.search(r'v(\d+\.\d+\.\d+)', output)
            return f"v{match.group(1)}" if match else output.splitlines()[0] if output else None
        except Exception:
            return None

    def get_default_options(self) -> Dict[str, Any]:
        """Return documented nuclei defaults exposed through scan config."""
        return {
            'timeout': 600,
        }

    def get_supported_options(self) -> set[str]:
        """Return supported user-facing nuclei option keys."""
        return {
            'templates',
            'severity',
            'tags',
            'rate_limit',
            'timeout',
            'proxy_url',
            'force_http2',
            'args',
            'extra_args',
        }

    def get_transport_option_keys(self) -> set[str]:
        """Declare transport-affecting options reserved for orchestrated routing."""
        return super().get_transport_option_keys() | {'force_http2'}

    def validate_options(self, options: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Validate and normalize user-supplied nuclei options."""
        normalized = super().validate_options(options)
        self._validate_string_list_option(normalized, 'templates')
        self._validate_string_list_option(normalized, 'severity')
        self._validate_string_list_option(normalized, 'tags')
        self._validate_int_option(normalized, 'rate_limit', minimum=1)
        self._validate_int_option(normalized, 'timeout', minimum=1)
        self._validate_string_option(normalized, 'proxy_url')
        self._validate_bool_option(normalized, 'force_http2')
        if 'severity' in normalized:
            normalized['severity'] = [str(level).lower() for level in normalized['severity']]
        self._normalize_extra_args(
            normalized,
            forbidden_flags={
                '-duc',
                '-fh2',
                '-json',
                '-jsonl',
                '-l',
                '-list',
                '-o',
                '-proxy',
                '-proxy-internal',
                '-rate-limit',
                '-severity',
                '-silent',
                '-t',
                '-tags',
                '-u',
                '--output',
            },
        )
        return normalized

    def scan(self, target: str, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Run nuclei scan against target.

        Args:
            target: URL or hostname to scan
            options: Optional dict with:
                - templates: List[str] - specific templates to use
                - severity: List[str] - filter by severity
                - tags: List[str] - filter by tags
                - rate_limit: int - requests per second
                - args: List[str] - additional nuclei arguments

        Returns:
            Dict with raw scan results
        """
        options = options or {}
        defaults = self.get_default_options()
        target = normalize_web_target(target)
        origin_target = normalize_web_target(options.get('origin_target', target))

        cmd = ['nuclei', '-u', target, '-jsonl', '-duc']

        if options.get('force_http2'):
            cmd.append('-fh2')

        if 'templates' in options:
            for tmpl in options['templates']:
                cmd.extend(['-t', tmpl])

        if 'severity' in options:
            cmd.extend(['-severity', ','.join(options['severity'])])

        if 'tags' in options:
            cmd.extend(['-tags', ','.join(options['tags'])])

        if 'rate_limit' in options:
            cmd.extend(['-rate-limit', str(options['rate_limit'])])

        if 'proxy_url' in options:
            # Compatibility route for a locally controlled translation proxy.
            # This is not a claim of native direct HTTP/2 support.
            cmd.extend(['-proxy', options['proxy_url'], '-proxy-internal'])

        cmd.append('-silent')

        if 'args' in options:
            cmd.extend(options['args'])

        timestamp = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=options.get('timeout', defaults.get('timeout', 600))
            )

            self.last_scan_time = datetime.now(timezone.utc)

            findings = self._parse_jsonl_output(result.stdout)

            return {
                'scanner': self.name,
                'target': target,
                'origin_target': origin_target,
                'timestamp': timestamp,
                'command': ' '.join(cmd),
                'raw_output': result.stdout,
                'stderr': result.stderr,
                'exit_code': result.returncode,
                'findings': findings
            }

        except subprocess.TimeoutExpired as exc:
            stdout = self._coerce_timeout_stream(exc.stdout)
            stderr = self._coerce_timeout_stream(exc.stderr)
            return {
                'scanner': self.name,
                'target': target,
                'origin_target': origin_target,
                'timestamp': timestamp,
                'command': ' '.join(cmd),
                'error': 'Scan timeout',
                'raw_output': stdout,
                'stderr': stderr,
                'exit_code': None,
                'findings': []
            }
        except Exception as e:
            return {
                'scanner': self.name,
                'target': target,
                'origin_target': origin_target,
                'timestamp': timestamp,
                'command': ' '.join(cmd),
                'error': str(e),
                'findings': []
            }

    @staticmethod
    def _coerce_timeout_stream(value: Any) -> str:
        """Normalize TimeoutExpired stdout/stderr into a safe text value."""
        if value is None:
            return ''
        if isinstance(value, bytes):
            return value.decode('utf-8', errors='replace')
        return str(value)

    def _parse_jsonl_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse nuclei JSONL output (one JSON per line)."""
        findings = []

        for line in output.split('\n'):
            line = line.strip()
            if not line:
                continue

            try:
                finding = json.loads(line)
                findings.append(finding)
            except json.JSONDecodeError:
                continue

        return findings

    def normalize(self, raw_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Convert nuclei results to unified schema format.

        Args:
            raw_results: Raw results from scan()

        Returns:
            List of normalized findings
        """
        normalized = []
        timestamp = raw_results.get('timestamp', datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'))
        scanned_target = raw_results.get('target', '')
        origin_target = raw_results.get('origin_target') or scanned_target
        if scanned_target:
            scanned_target = normalize_web_target(scanned_target)
        if origin_target:
            origin_target = normalize_web_target(origin_target)

        for finding in raw_results.get('findings', []):
            info = finding.get('info', {})
            template_id = finding.get('template-id', finding.get('templateID', 'unknown'))

            severity = self._normalize_severity(info.get('severity', 'info'))

            matched_at = self._remap_asset_to_origin(
                finding.get('matched-at', finding.get('matched', '')),
                scanned_target,
                origin_target,
            )
            host = self._remap_asset_to_origin(
                finding.get('host', scanned_target or 'unknown'),
                scanned_target,
                origin_target,
            )
            asset_id = matched_at if matched_at else host

            # Parse the asset_id URL into structured components once,
            # so fingerprinting doesn't need to re-parse later.
            parsed = parse_target(asset_id)

            vuln_name = info.get('name', template_id)

            matcher_name = finding.get('matcher-name', finding.get('matcher_name', ''))
            extracted = finding.get('extracted-results', [])
            description = str(info.get('description') or '').strip()
            remediation = str(info.get('remediation') or '').strip()

            references = info.get('reference', [])
            if isinstance(references, str):
                references = [references]

            cve_ids = self._extract_cves(info, references)
            cve_id = cve_ids[0] if cve_ids else ''

            # query_keys: sorted list of query param names for fingerprinting
            query_keys = sorted(parsed.get('query', {}).keys())

            normalized.append({
                'vulnerability_name': vuln_name,
                'severity': severity,
                'asset_id': asset_id,
                'description': description,
                'remediation': remediation,
                'meta': {
                    'scanner': self.name,
                    'timestamp': timestamp,
                    # Structured location fields (v2.0 contract)
                    'host': parsed['host'] or host,
                    'scheme': parsed['scheme'],
                    'path': parsed['path'],
                    'port': parsed['port'],
                    'query_keys': query_keys,
                    # CVE / template identity
                    'raw_id': template_id,
                    'template_id': template_id,
                    'cve_id': cve_id,
                    'cve_ids': cve_ids,
                    # Scanner-specific fields
                    'tags': info.get('tags', []),
                    'references': references,
                    'matcher_name': matcher_name,
                    'extracted_results': extracted if isinstance(extracted, list) else [],
                    'curl_command': finding.get('curl-command', ''),
                    'origin_target': origin_target,
                }
            })

        return normalized

    def get_proxy_options(self, proxy_url: str) -> Dict[str, Any]:
        """Return proxy settings for compatibility routing."""
        return {
            'proxy_url': proxy_url,
        }

    def _base_target(self, target: str) -> str:
        """Return scheme://host[:port] for a normalized target."""
        parsed = urlparse(normalize_web_target(target))
        return urlunparse((parsed.scheme, parsed.netloc, '', '', '', ''))

    def _remap_asset_to_origin(self, value: str, scanned_target: str, origin_target: str) -> str:
        """
        Replace bridge-local identities with the original origin identity.

        This keeps bridge execution transparent in normalized findings even
        when Nuclei reports bridge-local URLs in `host` or `matched-at`.
        """
        if not value or not scanned_target or not origin_target:
            return value

        scanned_base = self._base_target(scanned_target)
        origin_base = self._base_target(origin_target)
        scanned = urlparse(scanned_base)
        origin = urlparse(origin_base)
        bridge_hosts = {
            scanned.netloc,
            scanned.hostname or '',
        }
        if scanned.hostname and scanned.port:
            bridge_hosts.add(f'{scanned.hostname}:{scanned.port}')

        if '://' in value:
            parsed = urlparse(value)
            if parsed.scheme == scanned.scheme and parsed.netloc == scanned.netloc:
                return urlunparse((
                    origin.scheme,
                    origin.netloc,
                    parsed.path,
                    parsed.params,
                    parsed.query,
                    parsed.fragment,
                ))
            return value

        if value.startswith('/'):
            return origin_base.rstrip('/') + value

        if value in bridge_hosts or value == scanned_base:
            return origin_base

        return value

    def _normalize_severity(self, severity: str) -> str:
        """Normalize severity to standard levels."""
        severity = str(severity).lower().strip()
        valid = {'critical', 'high', 'medium', 'low', 'info'}
        return severity if severity in valid else 'info'

    def _extract_cves(self, info: Dict, references: List[str]) -> List[str]:
        """Extract CVE IDs from info and references."""
        cves = []

        classification = info.get('classification', {})
        if 'cve-id' in classification:
            cve_val = classification['cve-id']
            if isinstance(cve_val, list):
                cves.extend(cve_val)
            elif cve_val:
                cves.append(cve_val)

        import re
        cve_pattern = re.compile(r'CVE-\d{4}-\d+', re.IGNORECASE)
        for ref in references:
            matches = cve_pattern.findall(str(ref))
            cves.extend(matches)

        seen = set()
        unique_cves = []
        for cve in cves:
            cve_upper = cve.upper()
            if cve_upper not in seen:
                seen.add(cve_upper)
                unique_cves.append(cve_upper)

        return unique_cves
