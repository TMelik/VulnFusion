"""
Nmap Scanner Integration

Runs nmap service and NSE script scans using subprocess and normalizes the
results to the unified schema. This integration is useful for host/service
exposure and CVE hints from NSE scripts such as ``vulners``; it is not a
full web-application vulnerability scanner.
"""

import re
import subprocess
import shutil
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .base import BaseScanner
from utils.normalizer import parse_target

class NmapScanner(BaseScanner):
    """Nmap scanner implementation for service-level findings and CVE hints."""

    _HTTPS_SERVICE_MARKERS = (
        'https',
        'ssl/http',
        'https-alt',
    )
    _HTTP_SERVICE_MARKERS = (
        'http',
        'http-alt',
        'http-proxy',
        'httpapi',
        'sun-answerbook',
    )

    def __init__(self):
        super().__init__('nmap')
        self.scanner_type = 'network'
        self.supports_http2_direct = False
        self.supports_proxy = False

    def is_available(self) -> bool:
        """Check if nmap is installed."""
        return shutil.which('nmap') is not None

    def get_version(self) -> Optional[str]:
        """Get nmap version."""
        try:
            result = subprocess.run(
                ['nmap', '--version'],
                capture_output=True,
                text=True,
                timeout=10
            )
            first_line = result.stdout.split('\n')[0]
            return first_line
        except Exception:
            return None

    def get_default_options(self) -> Dict[str, Any]:
        """Return documented nmap defaults exposed through scan config."""
        return {
            'scripts': ['vulners'],
            'timeout': 300,
        }

    def get_supported_options(self) -> set[str]:
        """Return supported user-facing nmap option keys."""
        return {'ports', 'scripts', 'timeout', 'args', 'extra_args'}

    def validate_options(self, options: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Validate and normalize user-supplied nmap options."""
        normalized = super().validate_options(options)
        self._validate_string_option(normalized, 'ports')
        self._validate_string_list_option(normalized, 'scripts', allow_empty=True)
        self._validate_int_option(normalized, 'timeout', minimum=1)
        self._normalize_extra_args(
            normalized,
            forbidden_flags={
                '-iL',
                '-iR',
                '-oA',
                '-oG',
                '-oN',
                '-oS',
                '-oX',
                '-p',
                '--resume',
                '--script',
                '--stylesheet',
            },
        )
        return normalized

    def scan(self, target: str, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Run nmap scan against target.

        Args:
            target: IP address, hostname, or CIDR range
            options: Optional dict with:
                - ports: str - port specification (default: common ports)
                - scripts: List[str] - NSE scripts to run
                - args: List[str] - additional nmap arguments

        Returns:
            Dict with raw scan results
        """
        options = options or {}

        defaults = self.get_default_options()
        cmd = ['nmap', '-sV']

        if 'ports' in options:
            cmd.extend(['-p', options['ports']])

        scripts = options.get('scripts', defaults.get('scripts', ['vulners']))
        if scripts:
            cmd.extend(['--script', ','.join(scripts)])

        cmd.extend(['-oX', '-'])

        if 'args' in options:
            cmd.extend(options['args'])

        cmd.append(target)

        timestamp = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=options.get('timeout', defaults.get('timeout', 300))
            )

            self.last_scan_time = datetime.now(timezone.utc)

            discovered_services = self._parse_service_inventory(result.stdout, target)
            findings = self._parse_xml_output(result.stdout, target)

            return {
                'scanner': self.name,
                'target': target,
                'timestamp': timestamp,
                'command': ' '.join(cmd),
                'raw_output': result.stdout,
                'stderr': result.stderr,
                'exit_code': result.returncode,
                'discovered_services': discovered_services,
                'findings': findings
            }

        except subprocess.TimeoutExpired:
            return {
                'scanner': self.name,
                'target': target,
                'timestamp': timestamp,
                'command': ' '.join(cmd),
                'error': 'Scan timeout',
                'discovered_services': [],
                'findings': []
            }
        except Exception as e:
            return {
                'scanner': self.name,
                'target': target,
                'timestamp': timestamp,
                'command': ' '.join(cmd),
                'error': str(e),
                'discovered_services': [],
                'findings': []
            }

    def _parse_service_inventory(self, xml_output: str, target: str) -> List[Dict[str, Any]]:
        """Parse nmap XML output into structured open-service discovery records."""
        services: List[Dict[str, Any]] = []

        try:
            root = ET.fromstring(xml_output)
        except ET.ParseError:
            return services

        for host in root.findall('.//host'):
            addr_elem = host.find('address')
            host_addr = addr_elem.get('addr', target) if addr_elem is not None else target

            for port in host.findall('.//port'):
                state_elem = port.find('state')
                state = state_elem.get('state', '') if state_elem is not None else ''
                if state != 'open':
                    continue

                port_id = port.get('portid', 'unknown')
                protocol = port.get('protocol', 'tcp')

                service = port.find('service')
                service_name = service.get('name', 'unknown') if service is not None else 'unknown'
                service_version = service.get('version', '') if service is not None else ''
                product = service.get('product', '') if service is not None else ''
                extrainfo = service.get('extrainfo', '') if service is not None else ''
                tunnel = service.get('tunnel', '') if service is not None else ''

                web_scheme = self._infer_web_scheme(
                    service_name=service_name,
                    tunnel=tunnel,
                    product=product,
                    extrainfo=extrainfo,
                )

                service_record: Dict[str, Any] = {
                    'host': host_addr,
                    'port': int(port_id) if str(port_id).isdigit() else None,
                    'port_text': port_id,
                    'protocol': protocol,
                    'state': state,
                    'service': service_name,
                    'service_product': product,
                    'service_version': service_version,
                    'service_extrainfo': extrainfo,
                    'tunnel': tunnel,
                    'is_web': bool(web_scheme),
                    'web_scheme': web_scheme,
                }
                service_record['service_display'] = self._build_service_display(service_record)
                services.append(service_record)

        return services

    def _infer_web_scheme(
        self,
        service_name: str,
        tunnel: str = '',
        product: str = '',
        extrainfo: str = '',
    ) -> str:
        """Infer whether nmap identified a service as HTTP or HTTPS."""
        service_name = (service_name or '').strip().lower()
        tunnel = (tunnel or '').strip().lower()
        fingerprint = ' '.join(
            part.strip().lower()
            for part in (service_name, product, extrainfo)
            if part and part.strip()
        )

        if tunnel == 'ssl':
            if 'http' in fingerprint or not fingerprint:
                return 'https'

        if any(marker in service_name for marker in self._HTTPS_SERVICE_MARKERS):
            return 'https'
        if any(marker in service_name for marker in self._HTTP_SERVICE_MARKERS):
            return 'http'

        tokens = {
            token
            for token in re.split(r'[^a-z0-9]+', fingerprint)
            if token
        }
        if 'https' in tokens:
            return 'https'
        if 'http' in tokens and tunnel == 'ssl':
            return 'https'
        if 'http' in tokens:
            return 'http'
        return ''

    @staticmethod
    def _build_service_display(service_record: Dict[str, Any]) -> str:
        """Return a short human-readable service description."""
        service = str(service_record.get('service') or 'unknown').strip()
        product = str(service_record.get('service_product') or '').strip()
        version = str(service_record.get('service_version') or '').strip()
        extrainfo = str(service_record.get('service_extrainfo') or '').strip()

        parts = [product, version, extrainfo]
        detail = ' '.join(part for part in parts if part).strip()
        return f"{service} {detail}".strip()

    def _parse_xml_output(self, xml_output: str, target: str) -> List[Dict[str, Any]]:
        """Parse nmap XML output for vulnerabilities."""
        findings = []

        try:
            root = ET.fromstring(xml_output)

            for host in root.findall('.//host'):
                addr_elem = host.find('address')
                host_addr = addr_elem.get('addr', target) if addr_elem is not None else target

                for port in host.findall('.//port'):
                    port_id = port.get('portid', 'unknown')
                    protocol = port.get('protocol', 'tcp')

                    service = port.find('service')
                    service_name = service.get('name', 'unknown') if service is not None else 'unknown'
                    service_version = service.get('version', '') if service is not None else ''

                    for script in port.findall('.//script'):
                        script_id = script.get('id', '')
                        script_output = script.get('output', '')

                        if script_id == 'vulners':
                            vulns = self._parse_vulners_output(script_output)
                            for vuln in vulns:
                                findings.append({
                                    'host': host_addr,
                                    'port': port_id,
                                    'protocol': protocol,
                                    'service': service_name,
                                    'service_version': service_version,
                                    'script': script_id,
                                    **vuln
                                })
                        else:
                            if script_output.strip():
                                findings.append({
                                    'host': host_addr,
                                    'port': port_id,
                                    'protocol': protocol,
                                    'service': service_name,
                                    'service_version': service_version,
                                    'script': script_id,
                                    'output': script_output,
                                    'cve_id': None,
                                    'cvss': None
                                })

        except ET.ParseError:
            pass

        return findings

    def _parse_vulners_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse vulners script output for CVE information."""
        vulns = []

        for line in output.split('\n'):
            line = line.strip()
            if not line:
                continue

            parts = line.split()
            if len(parts) >= 2 and parts[0].startswith('CVE-'):
                cve_id = parts[0]
                try:
                    cvss = float(parts[1])
                except (ValueError, IndexError):
                    cvss = None

                vulns.append({
                    'cve_id': cve_id,
                    'cvss': cvss,
                    'output': line
                })

        return vulns

    def normalize(self, raw_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Convert nmap results to unified schema format.

        Args:
            raw_results: Raw results from scan()

        Returns:
            List of normalized findings
        """
        normalized = []
        timestamp = raw_results.get('timestamp', datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'))

        for finding in raw_results.get('findings', []):
            cvss = finding.get('cvss')
            severity = self._cvss_to_severity(cvss)

            host_addr = finding.get('host', raw_results.get('target', 'unknown'))
            port = finding.get('port', '')
            asset_id = f"{host_addr}:{port}" if port else host_addr

            # Parse asset_id to extract structured location fields once,
            # so create_fingerprints() can use them without re-parsing.
            parsed = parse_target(asset_id)

            cve_id = finding.get('cve_id') or ''
            script = finding.get('script', '')
            if cve_id:
                vuln_name = cve_id
            else:
                vuln_name = f"{script} finding on {finding.get('service', 'unknown')}"

            service = finding.get('service', 'unknown')
            version = finding.get('service_version', '')
            description = str(finding.get('output') or '').strip()
            remediation = str(
                finding.get('remediation')
                or finding.get('solution')
                or ''
            ).strip()

            meta = {
                'scanner': self.name,
                'timestamp': timestamp,
                # Structured location fields (v2.0 contract)
                'host': parsed['host'] or host_addr,
                'scheme': parsed['scheme'],
                'path': parsed['path'],
                'port': parsed['port'] if parsed['port'] is not None else (int(port) if str(port).isdigit() else None),
                # CVE fields
                'raw_id': cve_id or None,
                'cve_id': cve_id or None,
                'cve_ids': [cve_id] if cve_id else [],
                # Service details
                'cvss': cvss,
                'protocol': finding.get('protocol'),
                'service': service,
                'service_version': version,
            }
            meta = {key: value for key, value in meta.items() if value is not None}

            normalized.append({
                'vulnerability_name': vuln_name,
                'severity': severity,
                'asset_id': asset_id,
                'description': description,
                'remediation': remediation,
                'meta': meta,
            })

        return normalized

    def _cvss_to_severity(self, cvss: Optional[float]) -> str:
        """Convert CVSS score to severity level."""
        if cvss is None:
            return 'info'
        if cvss >= 9.0:
            return 'critical'
        if cvss >= 7.0:
            return 'high'
        if cvss >= 4.0:
            return 'medium'
        if cvss >= 0.1:
            return 'low'
        return 'info'
