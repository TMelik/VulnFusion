"""
Scanner Orchestrator

Central coordinator for running multiple vulnerability scanners against targets.
Manages scanner registration, execution, and result collection.
"""

import contextlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse, urlunparse

from scanners.base import BaseScanner
from scanners.nmap_scanner import NmapScanner
from scanners.nuclei_scanner import NucleiScanner
from scanners.wapiti_scanner import WapitiScanner
from scanners.nikto_scanner import NiktoScanner
from scanners.zap_scanner import ZapScanner
from utils.http_transport_adapters import (
    HTTP2_ADAPTER_MODE_AUTO,
    HTTP2_ADAPTER_MODE_BRIDGE,
    LocalTransportAdapterError,
    SUPPORTED_HTTP2_ADAPTER_MODES,
    create_local_transport_adapter,
)
from utils.target_probe import HTTP_MODE_AUTO, HTTP_MODE_HTTP1, HTTP_MODE_HTTP2, probe_web_target
from utils.normalizer import (
    is_adapter_local_connectivity_artifact,
    is_adapter_transport_artifact,
    normalize_web_target,
    parse_target,
)
from utils.export_sanitizer import sanitize_results_for_export
from utils.schema import SCHEMA_VERSION, assert_valid_results, sort_by_severity
from utils.run_folder import create_run_folder, get_raw_dir, get_normalized_json_path, get_scan_results_json_path, update_latest_pointer
from utils.scan_config import SCAN_CONFIG_ENABLED_KEY
from utils.defectdojo_raw import build_raw_upload_manifest_entry, resolve_raw_scan_type
from utils.timing import WorkflowTimer
from utils.xml_artifacts import extract_native_xml_text, save_xml_artifact

probe_http_transport = probe_web_target

SCAN_MODE_AUTOMATIC = 'automatic'
SCAN_MODE_MANUAL = 'manual'
SUPPORTED_SCAN_MODES = {
    SCAN_MODE_AUTOMATIC,
    SCAN_MODE_MANUAL,
}
TRANSPORT_ROUTE_CONTROL_KEYS = frozenset({
    'http2_adapter_mode',
    'bridge_url',
})

class ScannerOrchestrator:
    """
    Orchestrates vulnerability scanning across multiple tools.

    Example usage:
        orchestrator = ScannerOrchestrator()
        orchestrator.register_scanner('nmap', NmapScanner())
        results = orchestrator.run_all('192.168.1.1')
    """

    def __init__(
        self,
        reports_dir: Optional[Path] = None,
        http2_proxy_url: Optional[str] = None,
        http2_bridge_url: Optional[str] = None,
        http2_adapter_mode: str = HTTP2_ADAPTER_MODE_AUTO,
        http_probe_timeout: int = 8,
    ):
        """
        Initialize the orchestrator.

        Args:
            reports_dir: Base directory for run folders (default: ./data)
        """
        self.scanners: Dict[str, BaseScanner] = {}
        self.reports_dir = reports_dir or Path('data')
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        self.current_run_folder: Optional[Path] = None
        self.http2_proxy_url = http2_proxy_url
        self.http2_bridge_url = http2_bridge_url
        self.http_probe_timeout = http_probe_timeout
        self.http_mode = HTTP_MODE_AUTO
        self.scan_mode: Optional[str] = None
        self.selected_ports_spec: Optional[str] = None
        self.selected_ports: Optional[List[int]] = None
        self.http2_adapter_mode = HTTP2_ADAPTER_MODE_AUTO
        self._transport_probe_cache: Dict[str, Dict[str, Any]] = {}
        self._auto_http2_adapters: Dict[tuple[str, str], Any] = {}
        self.timing = WorkflowTimer()
        self.set_http2_adapter_mode(http2_adapter_mode)

    def register_scanner(self, name: str, scanner: BaseScanner) -> None:
        """
        Register a scanner with the orchestrator.

        Args:
            name: Unique name for the scanner
            scanner: Scanner instance (must inherit from BaseScanner)
        """
        if not isinstance(scanner, BaseScanner):
            raise TypeError(f"Scanner must inherit from BaseScanner")
        self.scanners[name] = scanner

    def unregister_scanner(self, name: str) -> bool:
        """
        Remove a scanner from the orchestrator.

        Args:
            name: Name of the scanner to remove

        Returns:
            True if scanner was removed, False if not found
        """
        if name in self.scanners:
            del self.scanners[name]
            return True
        return False

    def list_scanners(self) -> List[Dict[str, Any]]:
        """
        List all registered scanners with their status.

        Returns:
            List of dicts with scanner name, availability, and version
        """
        result = []
        for name, scanner in self.scanners.items():
            result.append({
                'name': name,
                'available': scanner.is_available(),
                'version': scanner.get_version(),
                'capabilities': scanner.get_capabilities(),
            })
        return result

    def set_http_mode(self, http_mode: str) -> None:
        """Set the requested HTTP mode used for web scanner routing."""
        self.http_mode = http_mode

    def set_scan_mode(self, scan_mode: Optional[str]) -> None:
        """Set the discovery-driven orchestration mode used by run_all()."""
        if scan_mode is None:
            self.scan_mode = None
            return
        if scan_mode not in SUPPORTED_SCAN_MODES:
            supported = ", ".join(sorted(SUPPORTED_SCAN_MODES))
            raise ValueError(f"scan mode must be one of: {supported}")
        self.scan_mode = scan_mode

    def set_selected_ports(self, ports_spec: Optional[str]) -> None:
        """Store the user-selected port specification for manual orchestration."""
        self.selected_ports_spec = ports_spec.strip() if isinstance(ports_spec, str) and ports_spec.strip() else None
        if self.selected_ports_spec is None:
            self.selected_ports = None
            return
        self.selected_ports = self._parse_ports_spec(self.selected_ports_spec)

    def set_http2_adapter_mode(self, adapter_mode: str) -> None:
        """Set the preferred compatibility adapter for adapter-dependent web scans."""
        if adapter_mode not in SUPPORTED_HTTP2_ADAPTER_MODES:
            supported = ", ".join(sorted(SUPPORTED_HTTP2_ADAPTER_MODES))
            raise ValueError(f"http2 adapter mode must be one of: {supported}")
        self.http2_adapter_mode = adapter_mode

    @staticmethod
    def _append_transport_note(route: Dict[str, Any], note: str) -> None:
        """Append one transport note to a route without losing prior context."""
        if not note:
            return
        route['scanner_transport_notes'] = (
            f"{route.get('scanner_transport_notes', '')} {note}"
        ).strip()

    @staticmethod
    def _extract_transport_owned_options(
        scanner: BaseScanner,
        options: Optional[Dict[str, Any]],
    ) -> Tuple[Dict[str, Any], Dict[str, Any], Dict[str, Any]]:
        """Split execution options from routing controls and transport overrides."""
        execution_options = dict(options or {})
        route_controls: Dict[str, Any] = {}
        requested_transport: Dict[str, Any] = {}

        for key in TRANSPORT_ROUTE_CONTROL_KEYS:
            if key in execution_options:
                route_controls[key] = execution_options.pop(key)

        for key in scanner.get_transport_option_keys():
            if key in execution_options:
                requested_transport[key] = execution_options.pop(key)

        return execution_options, route_controls, requested_transport

    def _finalize_transport_owned_route(
        self,
        _scanner: BaseScanner,
        route: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Drop planning-only keys and surface ignored transport overrides clearly."""
        route.pop('_planning_options', None)
        route.pop('_route_controls', None)
        requested_transport = dict(route.pop('_requested_transport_options', {}) or {})

        final_options = dict(route.get('options') or {})
        for key in TRANSPORT_ROUTE_CONTROL_KEYS:
            final_options.pop(key, None)
        route['options'] = final_options

        ignored = [
            key
            for key, requested_value in requested_transport.items()
            if final_options.get(key) != requested_value
        ]
        if ignored:
            ignored_text = ", ".join(sorted(ignored))
            self._append_transport_note(
                route,
                (
                    f"Ignored user-supplied transport option(s): {ignored_text}. "
                    f"Transport routing is orchestrator-owned; execution followed the planned "
                    f"{route.get('scan_route', 'direct')}/{route.get('adapter_mode', 'direct')} path."
                ),
            )

        return route

    def probe_target(self, target: str) -> Dict[str, Any]:
        """Probe and cache scheme/transport support for a web target."""
        for cache_key in self._probe_cache_aliases(target):
            cached = self._transport_probe_cache.get(cache_key)
            if cached is not None:
                return cached

        probe = probe_http_transport(
            target,
            timeout=self.http_probe_timeout,
        )
        for cache_key in self._probe_cache_aliases(
            target,
            normalized_target=probe.get('normalized_target'),
        ):
            self._transport_probe_cache[cache_key] = probe
        return probe

    @staticmethod
    def _probe_cache_aliases(
        target: str,
        *,
        normalized_target: Optional[str] = None,
    ) -> tuple[str, ...]:
        """Return equivalent cache keys for one web target probe result."""
        aliases: set[str] = set()
        candidates = [str(target or '').strip()]
        normalized = str(normalized_target or '').strip()
        if normalized:
            candidates.append(normalized)

        for candidate in candidates:
            if not candidate:
                continue
            aliases.add(candidate)
            if '://' not in candidate:
                continue

            parsed = urlparse(candidate)
            if parsed.scheme not in {'http', 'https'} or not parsed.hostname:
                continue

            display_host = parsed.hostname
            if ':' in display_host and not display_host.startswith('['):
                display_host = f'[{display_host}]'

            default_port = 443 if parsed.scheme == 'https' else 80
            explicit_port = parsed.port
            if explicit_port is None:
                aliases.add(urlunparse((parsed.scheme, display_host, '', '', '', '')))
                aliases.add(urlunparse((parsed.scheme, f'{display_host}:{default_port}', '', '', '', '')))
                continue

            aliases.add(urlunparse((parsed.scheme, f'{display_host}:{explicit_port}', '', '', '', '')))
            if explicit_port == default_port:
                aliases.add(urlunparse((parsed.scheme, display_host, '', '', '', '')))

        return tuple(sorted(aliases))

    def ensure_run_folder(
        self,
        target: str,
        *,
        timestamp: Optional[datetime] = None,
    ) -> Path:
        """Create or reuse the active run folder for this orchestration run."""
        if self.current_run_folder is None:
            self.current_run_folder = create_run_folder(self.reports_dir, target, timestamp)
        else:
            self.current_run_folder.mkdir(parents=True, exist_ok=True)
            get_raw_dir(self.current_run_folder).mkdir(exist_ok=True)
        return self.current_run_folder

    @staticmethod
    def _parse_ports_spec(ports_spec: str) -> List[int]:
        """Parse a simple nmap-style port string into a sorted list of ints."""
        ports: set[int] = set()
        for raw_chunk in ports_spec.split(','):
            chunk = raw_chunk.strip()
            if not chunk:
                continue
            if '-' in chunk:
                start_text, end_text = chunk.split('-', 1)
                if not start_text.isdigit() or not end_text.isdigit():
                    raise ValueError(f"Invalid port range: {chunk}")
                start = int(start_text)
                end = int(end_text)
                if start < 1 or end > 65535 or start > end:
                    raise ValueError(f"Invalid port range: {chunk}")
                ports.update(range(start, end + 1))
                continue
            if not chunk.isdigit():
                raise ValueError(f"Invalid port value: {chunk}")
            port = int(chunk)
            if port < 1 or port > 65535:
                raise ValueError(f"Invalid port value: {chunk}")
            ports.add(port)
        if not ports:
            raise ValueError("Port selection cannot be empty")
        return sorted(ports)

    @staticmethod
    def _build_discovery_target(target: str) -> str:
        """Strip URL-only parts before handing a target to nmap."""
        stripped = target.strip()
        if '://' not in stripped:
            return stripped

        parsed = urlparse(stripped)
        host = parsed.hostname or stripped
        if parsed.port:
            return f"{host}:{parsed.port}"
        return host

    @staticmethod
    def _preferred_web_host(target: str, discovered_host: str) -> str:
        """Prefer the user-supplied host for single-host scans to preserve vhosts."""
        stripped = target.strip()
        if '://' in stripped:
            parsed = urlparse(stripped)
            if parsed.hostname:
                return parsed.hostname
            return discovered_host

        if '/' in stripped:
            return discovered_host

        parsed = parse_target(stripped)
        return parsed.get('host') or discovered_host

    def _build_web_target_from_service(self, original_target: str, service: Dict[str, Any]) -> Optional[str]:
        """Build a URL target for one discovered HTTP or HTTPS service."""
        explicit_target = str(service.get('web_target') or '').strip()
        if explicit_target:
            return explicit_target

        scheme = str(service.get('web_scheme') or '').strip().lower()
        port = service.get('port')
        discovered_host = str(service.get('host') or '').strip()
        if scheme not in {'http', 'https'} or not discovered_host or port is None:
            return None

        host = self._preferred_web_host(original_target, discovered_host)
        return f"{scheme}://{host}:{port}"

    @staticmethod
    def _default_web_port(scheme: str) -> Optional[int]:
        """Return the conventional port for one HTTP scheme."""
        normalized_scheme = str(scheme or '').strip().lower()
        if normalized_scheme == 'https':
            return 443
        if normalized_scheme == 'http':
            return 80
        return None

    @staticmethod
    def _replace_web_target_host(target: str, host: str) -> str:
        """Swap one URL host while preserving path/query and any explicit port."""
        if not target or not host:
            return target

        parsed = urlparse(target)
        if not parsed.scheme:
            return target

        auth = ''
        if parsed.username:
            auth = parsed.username
            if parsed.password:
                auth += f":{parsed.password}"
            auth += '@'

        display_host = host
        if ':' in display_host and not display_host.startswith('['):
            display_host = f'[{display_host}]'

        netloc = f"{auth}{display_host}"
        if parsed.port is not None:
            netloc = f"{netloc}:{parsed.port}"

        return urlunparse((
            parsed.scheme,
            netloc,
            parsed.path,
            parsed.params,
            parsed.query,
            '',
        ))

    def _build_probe_fallback_web_service(
        self,
        original_target: str,
        planned_services: List[Dict[str, Any]],
    ) -> Optional[Dict[str, Any]]:
        """Build one probe-derived fallback web service when nmap found no usable web target."""
        probe = self.probe_target(original_target)
        if not probe.get('reachable'):
            return None

        scheme = str(probe.get('selected_scheme') or '').strip().lower()
        normalized_target = str(probe.get('normalized_target') or '').strip()
        if scheme not in {'http', 'https'} or not normalized_target:
            return None
        if self.http_mode == HTTP_MODE_HTTP2 and scheme != 'https':
            return None

        parsed = urlparse(normalized_target)
        host = self._preferred_web_host(original_target, parsed.hostname or '')
        port = parsed.port or self._default_web_port(parsed.scheme or scheme)
        if not host or port is None:
            return None

        selected_ports = set(self.selected_ports or [])
        if selected_ports and port not in selected_ports:
            return None
        if self.scan_mode == SCAN_MODE_MANUAL and selected_ports:
            if not any(service.get('port') == port for service in planned_services):
                return None

        web_target = self._replace_web_target_host(normalized_target, host)
        return {
            'host': host,
            'port': port,
            'port_text': str(port),
            'protocol': 'tcp',
            'state': 'open',
            'service': 'target-probe',
            'service_product': '',
            'service_version': probe.get('detected_http_version') or '',
            'service_extrainfo': probe.get('reason') or '',
            'tunnel': 'ssl' if scheme == 'https' else '',
            'is_web': True,
            'web_scheme': scheme,
            'web_target': web_target,
            'planning_source': 'target_probe',
        }

    def _is_discovery_web_service_eligible(self, service: Dict[str, Any]) -> bool:
        """Return True when discovery should schedule follow-up web scans for one service."""
        if not service.get('is_web'):
            return False
        if self.http_mode != HTTP_MODE_HTTP2:
            return True
        return str(service.get('web_scheme') or '').strip().lower() == 'https'

    def _build_discovery_scan_plan(
        self,
        original_target: str,
        web_services: List[Dict[str, Any]],
        web_scanners: List[Tuple[str, BaseScanner]],
    ) -> List[Dict[str, Any]]:
        """Build the follow-up web scan plan from discovery or probe-derived services."""
        eligible_web_services = [
            service for service in web_services
            if self._is_discovery_web_service_eligible(service)
        ]
        scanner_target_counts = {
            name: len(eligible_web_services)
            for name, _scanner in web_scanners
        }

        scan_plan: List[Dict[str, Any]] = []
        for service in eligible_web_services:
            web_target = self._build_web_target_from_service(original_target, service)
            if not web_target:
                continue
            for scanner_name, _scanner in web_scanners:
                execution_key = self._execution_key(scanner_name, service, scanner_target_counts)
                scan_plan.append({
                    'execution_key': execution_key,
                    'scanner': scanner_name,
                    'target': web_target,
                    'host': service.get('host'),
                    'port': service.get('port'),
                    'protocol': service.get('protocol'),
                    'service': service.get('service'),
                    'service_version': service.get('service_version'),
                    'web_scheme': service.get('web_scheme'),
                    'planning_source': service.get('planning_source', 'nmap_discovery'),
                })
        return scan_plan

    @staticmethod
    def _is_web_scanner(name: str, scanner: BaseScanner) -> bool:
        """Return True when the registered scanner is a follow-up web scanner."""
        return name != 'nmap' and scanner.get_capabilities().get('scanner_type') == 'web'

    @staticmethod
    def _execution_key(scanner_name: str, service: Dict[str, Any], counts: Dict[str, int]) -> str:
        """Return a stable result key for one scanner invocation."""
        if counts.get(scanner_name, 0) <= 1:
            return scanner_name

        host = str(service.get('host') or 'unknown')
        port = service.get('port')
        port_text = port if port is not None else service.get('port_text', 'unknown')
        return f"{scanner_name}@{host}:{port_text}"

    def _build_adapter_target(self, origin_target: str, adapter_url: str) -> str:
        """Map an origin URL onto a local adapter listener while preserving path/query."""
        origin = urlparse(normalize_web_target(origin_target))
        bridge = urlparse(normalize_web_target(adapter_url))
        path = origin.path or '/'
        return urlunparse((bridge.scheme, bridge.netloc, path, '', origin.query, ''))

    def _origin_base_target(self, origin_target: str) -> str:
        """Return scheme://host[:port] for normalization after bridged scans."""
        parsed = urlparse(normalize_web_target(origin_target))
        return urlunparse((parsed.scheme, parsed.netloc, '', '', '', ''))

    def _start_auto_http2_adapter(self, origin_target: str, adapter_mode: str) -> str:
        """Start or reuse one local compatibility adapter for one origin."""
        origin = self._origin_base_target(origin_target)
        adapter_key = (adapter_mode, origin)
        adapter = self._auto_http2_adapters.get(adapter_key)
        created = False
        if adapter is None:
            adapter = create_local_transport_adapter(adapter_mode, origin)
            created = True
        try:
            adapter_url = adapter.start()
        except Exception:
            with contextlib.suppress(Exception):
                adapter.stop()
            self._auto_http2_adapters.pop(adapter_key, None)
            raise

        if created:
            self._auto_http2_adapters[adapter_key] = adapter
            print(f"[*] Started local HTTP/2 bridge automatically: {adapter_url} -> {origin}")
        return adapter_url

    @staticmethod
    def _adapter_runtime_label(adapter_mode: str) -> Optional[str]:
        if adapter_mode == HTTP2_ADAPTER_MODE_BRIDGE:
            return 'python-bridge'
        return None

    @staticmethod
    def _adapter_translation_chain(adapter_mode: str) -> Optional[str]:
        if adapter_mode == HTTP2_ADAPTER_MODE_BRIDGE:
            return 'python HTTP/2 bridge -> origin'
        return None

    def _auto_http2_adapter_details(
        self,
        origin_target: str,
        adapter_mode: str,
        adapter_url: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Return structured details for one started or planned local adapter."""
        origin = self._origin_base_target(origin_target)
        adapter = self._auto_http2_adapters.get((adapter_mode, origin))
        if adapter is not None:
            details = dict(adapter.details())
        else:
            details = {
                'adapter_mode': adapter_mode,
                'adapter_url': adapter_url,
                'origin_target': origin,
                'adapter_upstream_url': origin,
                'adapter_runtime': self._adapter_runtime_label(adapter_mode),
                'adapter_translation_chain': self._adapter_translation_chain(adapter_mode),
                'adapter_status': 'ready' if adapter_url else None,
                'adapter_runtime_state': 'running' if adapter_url else None,
                'transport_confidence': 'normal' if adapter_url else None,
            }
        if adapter_url:
            details.setdefault('adapter_url', adapter_url)
        details.setdefault('adapter_mode', adapter_mode)
        details.setdefault('origin_target', origin)
        details.setdefault('adapter_upstream_url', origin)
        details.setdefault('adapter_runtime', self._adapter_runtime_label(adapter_mode))
        details.setdefault('adapter_translation_chain', self._adapter_translation_chain(adapter_mode))
        return details

    def _adapter_failure_details(
        self,
        origin_target: str,
        adapter_mode: str,
        exc: BaseException,
    ) -> Dict[str, Any]:
        """Normalize one adapter startup failure into structured route metadata."""
        details: Dict[str, Any]
        if isinstance(exc, LocalTransportAdapterError) and getattr(exc, 'details', None):
            details = dict(exc.details)
        else:
            details = {}
        origin = self._origin_base_target(origin_target) if origin_target else origin_target
        details.setdefault('adapter_mode', adapter_mode)
        details.setdefault('origin_target', origin)
        details.setdefault('adapter_upstream_url', origin)
        details.setdefault('adapter_runtime', self._adapter_runtime_label(adapter_mode))
        details.setdefault('adapter_translation_chain', self._adapter_translation_chain(adapter_mode))
        details.setdefault('adapter_status', 'startup_failed')
        details.setdefault('adapter_runtime_state', 'failed')
        details.setdefault('adapter_failure_reason', str(exc))
        details.setdefault('transport_confidence', 'failed')
        return details

    def _start_auto_http2_bridge(self, origin_target: str) -> str:
        """Backward-compatible wrapper for the built-in Python bridge."""
        return self._start_auto_http2_adapter(origin_target, HTTP2_ADAPTER_MODE_BRIDGE)

    def shutdown_background_services(self) -> None:
        """Stop any automatically started helper services."""
        for adapter in self._auto_http2_adapters.values():
            adapter.stop()
        self._auto_http2_adapters.clear()

    def _plan_scan_route(
        self,
        scanner: BaseScanner,
        target: str,
        options: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Decide whether the scanner should run direct, proxied, or be skipped.
        """
        capabilities = scanner.get_capabilities()
        scanner_type = capabilities.get('scanner_type', 'generic')
        execution_options, route_controls, requested_transport = self._extract_transport_owned_options(
            scanner,
            options,
        )
        planning_options = dict(execution_options)
        planning_options.update(route_controls)

        route = {
            'scanner_type': scanner_type,
            'scan_route': 'direct',
            'adapter_mode': 'direct',
            'adapter_details': None,
            'transport_detected': 'not_applicable',
            'skip_reason': None,
            'scanner_transport_notes': '',
            'target': target,
            'options': execution_options,
            'transport_probe': None,
            'requested_http_mode': self.http_mode,
            '_planning_options': planning_options,
            '_route_controls': route_controls,
            '_requested_transport_options': requested_transport,
        }

        if scanner_type != 'web':
            route['scanner_transport_notes'] = 'HTTP transport probing is not applied to non-web scanners.'
            return self._finalize_transport_owned_route(scanner, route)

        probe = self.probe_target(target)
        route['transport_probe'] = probe
        route['transport_detected'] = probe.get('transport_detected', 'unknown')
        route['target'] = probe.get('normalized_target', target)
        route['scanner_transport_notes'] = probe.get('reason', '')
        route['options'] = dict(execution_options)
        route['options']['target_probe'] = probe
        route['options']['requested_http_mode'] = self.http_mode

        if probe.get('probe_method') == 'unsupported_scheme':
            return self._finalize_transport_owned_route(
                scanner,
                self._skip_route(route, probe.get('reason') or 'Unsupported web target scheme.'),
            )

        if self.http_mode == HTTP_MODE_AUTO:
            return self._finalize_transport_owned_route(
                scanner,
                self._plan_auto_web_route(scanner, target, route, capabilities, probe),
            )
        if self.http_mode == HTTP_MODE_HTTP2:
            return self._finalize_transport_owned_route(
                scanner,
                self._plan_forced_http2_route(scanner, route, capabilities, probe),
            )
        if self.http_mode == HTTP_MODE_HTTP1:
            return self._finalize_transport_owned_route(
                scanner,
                self._plan_forced_http1_route(scanner, route, capabilities, probe),
            )

        return self._finalize_transport_owned_route(
            scanner,
            self._skip_route(route, f"Unsupported http mode '{self.http_mode}'."),
        )

    def _plan_offline_input_route(
        self,
        scanner: BaseScanner,
        target: str,
        options: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Build a no-network route for a scanner consuming an existing artifact."""
        return {
            'scanner_type': scanner.scanner_type,
            'scan_route': 'imported_report',
            'adapter_mode': 'not_applicable',
            'adapter_details': None,
            'transport_detected': 'not_contacted',
            'skip_reason': None,
            'scanner_transport_notes': (
                'Loaded an existing scanner report; this scanner invocation did not contact the target.'
            ),
            'target': target,
            'options': dict(options),
            'transport_probe': None,
            'requested_http_mode': self.http_mode,
        }

    def _skip_route(
        self,
        route: Dict[str, Any],
        reason: str,
        note_suffix: Optional[str] = None,
        adapter_mode: Optional[str] = None,
        adapter_details: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Mark a route as skipped with a clear reason."""
        route['scan_route'] = 'skipped'
        route['adapter_mode'] = adapter_mode or 'skipped'
        if adapter_details:
            route['adapter_details'] = dict(adapter_details)
            route['options'] = dict(route.get('options') or {})
            route['options']['adapter_details'] = dict(adapter_details)
            if adapter_mode:
                route['options']['adapter_mode'] = adapter_mode
        route['skip_reason'] = reason
        if note_suffix:
            route['scanner_transport_notes'] = (
                f"{route.get('scanner_transport_notes', '')} {note_suffix}"
            ).strip()
        return route

    def _local_adapter_route(
        self,
        route: Dict[str, Any],
        planned_options: Dict[str, Any],
        probe: Dict[str, Any],
        adapter_mode: str,
        adapter_url: str,
        adapter_details: Optional[Dict[str, Any]],
        notes: str,
    ) -> Dict[str, Any]:
        """Route a web scan through one local compatibility adapter."""
        original_target = probe.get('normalized_target', route['target'])
        route['scan_route'] = 'proxied'
        route['adapter_mode'] = adapter_mode
        route['adapter_details'] = dict(adapter_details or {})
        route['options'] = dict(planned_options)
        route['options']['origin_target'] = self._origin_base_target(original_target)
        route['options']['original_target'] = original_target
        route['options']['adapter_mode'] = adapter_mode
        if adapter_details:
            route['options']['adapter_details'] = dict(adapter_details)
        route['target'] = self._build_adapter_target(original_target, adapter_url)
        route['options']['effective_target'] = route['target']
        route['scanner_transport_notes'] = (
            f"{route.get('scanner_transport_notes', '')} {notes}"
        ).strip()
        return route

    def _bridge_route(
        self,
        route: Dict[str, Any],
        planned_options: Dict[str, Any],
        probe: Dict[str, Any],
        bridge_url: str,
        adapter_details: Optional[Dict[str, Any]],
        notes: str,
    ) -> Dict[str, Any]:
        """Route a web scan through the existing local Python bridge."""
        return self._local_adapter_route(
            route,
            planned_options,
            probe,
            HTTP2_ADAPTER_MODE_BRIDGE,
            bridge_url,
            adapter_details,
            notes,
        )

    def _proxy_route(
        self,
        scanner: BaseScanner,
        route: Dict[str, Any],
        planned_options: Dict[str, Any],
        proxy_url: str,
        notes: str,
    ) -> Dict[str, Any]:
        """Route a web scan through a user-supplied proxy."""
        route['scan_route'] = 'proxied'
        route['adapter_mode'] = 'proxy'
        merged_options = dict(planned_options)
        merged_options.update(scanner.get_proxy_options(proxy_url))
        route['options'] = merged_options
        route['scanner_transport_notes'] = (
            f"{route.get('scanner_transport_notes', '')} {notes}"
        ).strip()
        return route

    def _plan_auto_web_route(
        self,
        scanner: BaseScanner,
        target: str,
        route: Dict[str, Any],
        capabilities: Dict[str, Any],
        probe: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Choose the best supported route for automatic web scanning."""
        planned_options = dict(route.get('options') or {})
        planning_options = dict(route.get('_planning_options') or planned_options)
        requested_transport = dict(route.get('_requested_transport_options') or {})
        adapter_preference = planning_options.get('http2_adapter_mode') or self.http2_adapter_mode

        if probe.get('probe_method') == 'unavailable':
            return route

        if not probe.get('reachable'):
            return self._skip_route(
                route,
                "Web target probe could not confirm a reachable HTTP endpoint for this target.",
            )

        if probe.get('selected_scheme') == 'http':
            return route

        if probe.get('supports_http2') and probe.get('supports_http1_1'):
            self._append_transport_note(
                route,
                "Automatic routing prefers HTTP/1.1 because the target accepts both HTTP/2 and HTTP/1.1.",
            )
            return route

        if not probe.get('http2_only'):
            return route

        if capabilities.get('supports_http2_direct'):
            route['options'] = dict(planned_options)
            route['options']['force_http2'] = True
            route['scanner_transport_notes'] = (
                f"{route.get('scanner_transport_notes', '')} "
                "Scanner supports HTTP/2 directly, so the target was scanned without a proxy or bridge."
            ).strip()
            return route

        manual_bridge_url = planning_options.get('bridge_url') or self.http2_bridge_url
        if manual_bridge_url and capabilities.get('supports_http2_bridge'):
            bridge_details = self._auto_http2_adapter_details(
                probe.get('normalized_target', target),
                HTTP2_ADAPTER_MODE_BRIDGE,
                manual_bridge_url,
            )
            return self._bridge_route(
                route,
                planned_options,
                probe,
                manual_bridge_url,
                bridge_details,
                f"Scanner was routed through local HTTP/2 bridge {manual_bridge_url} because the target appears HTTP/2-only.",
            )

        proxy_url = requested_transport.get('proxy_url') or self.http2_proxy_url
        if (
            adapter_preference == HTTP2_ADAPTER_MODE_AUTO
            and proxy_url
            and capabilities.get('supports_proxy')
        ):
            return self._proxy_route(
                scanner,
                route,
                planned_options,
                proxy_url,
                (
                    f"Scanner was routed through proxy {proxy_url} because the target appears HTTP/2-only. "
                    "The tool does not independently verify the proxy's upstream HTTP version."
                ),
            )

        if capabilities.get('supports_http2_bridge'):
            normalized_target = probe.get('normalized_target', target)
            try:
                bridge_url = self._start_auto_http2_bridge(normalized_target)
                bridge_details = self._auto_http2_adapter_details(
                    normalized_target,
                    HTTP2_ADAPTER_MODE_BRIDGE,
                    bridge_url,
                )
            except Exception as exc:
                return self._skip_route(
                    route,
                    (
                        "Target appears HTTP/2-only, but the automatic local HTTP/2 bridge "
                        f"could not be started: {exc}"
                    ),
                    adapter_mode=HTTP2_ADAPTER_MODE_BRIDGE,
                    adapter_details=self._adapter_failure_details(
                        normalized_target,
                        HTTP2_ADAPTER_MODE_BRIDGE,
                        exc,
                    ),
                )
            return self._bridge_route(
                route,
                planned_options,
                probe,
                bridge_url,
                bridge_details,
                (
                    f"Started local HTTP/2 bridge {bridge_url} automatically. "
                    f"Scanner was routed through the bridge because the target appears HTTP/2-only."
                ),
            )

        return self._skip_route(
            route,
            "Target appears HTTP/2-only, but this scanner has no confirmed direct HTTP/2 support and no compatible bridge or proxy route was configured.",
            note_suffix="Scanner was skipped to avoid a misleading empty result.",
        )

    def _plan_forced_http2_route(
        self,
        scanner: BaseScanner,
        route: Dict[str, Any],
        capabilities: Dict[str, Any],
        probe: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Plan a route when the user explicitly requested HTTP/2."""
        planned_options = dict(route.get('options') or {})
        planning_options = dict(route.get('_planning_options') or planned_options)

        if probe.get('probe_method') == 'unavailable':
            return self._skip_route(
                route,
                "HTTP/2 was requested, but transport probing is unavailable on this system.",
            )

        if not probe.get('reachable'):
            return self._skip_route(
                route,
                "HTTP/2 was requested, but the target probe could not confirm a reachable HTTPS endpoint.",
            )

        if probe.get('selected_scheme') != 'https':
            return self._skip_route(
                route,
                "HTTP/2 was requested, but the selected target scheme is not HTTPS.",
            )

        if not probe.get('supports_http2'):
            return self._skip_route(
                route,
                "HTTP/2 was requested, but the target did not negotiate HTTP/2 during probing.",
            )

        if capabilities.get('supports_http2_direct'):
            route['options'] = dict(planned_options)
            route['options']['force_http2'] = True
            route['scanner_transport_notes'] = (
                f"{route.get('scanner_transport_notes', '')} "
                "HTTP/2 was requested and will use the scanner's direct HTTP/2 execution path."
            ).strip()
            return route

        bridge_url = planning_options.get('bridge_url') or self.http2_bridge_url
        auto_started = False
        if bridge_url is None and capabilities.get('supports_http2_bridge'):
            normalized_target = probe.get('normalized_target', route.get('target', ''))
            try:
                bridge_url = self._start_auto_http2_bridge(normalized_target)
                auto_started = True
                bridge_details = self._auto_http2_adapter_details(
                    normalized_target,
                    HTTP2_ADAPTER_MODE_BRIDGE,
                    bridge_url,
                )
            except Exception as exc:
                return self._skip_route(
                    route,
                    (
                        f"HTTP/2 was requested, but the automatic local HTTP/2 bridge could not be started: {exc}"
                    ),
                    adapter_mode=HTTP2_ADAPTER_MODE_BRIDGE,
                    adapter_details=self._adapter_failure_details(
                        normalized_target,
                        HTTP2_ADAPTER_MODE_BRIDGE,
                        exc,
                    ),
                )
        else:
            bridge_details = self._auto_http2_adapter_details(
                probe.get('normalized_target', route.get('target', '')),
                HTTP2_ADAPTER_MODE_BRIDGE,
                bridge_url,
            ) if bridge_url else None
        if bridge_url and capabilities.get('supports_http2_bridge'):
            return self._bridge_route(
                route,
                planned_options,
                probe,
                bridge_url,
                bridge_details,
                (
                    f"Started local HTTP/2 bridge {bridge_url} automatically. "
                    "HTTP/2 was requested and will be satisfied through the bridge."
                ) if auto_started else f"HTTP/2 was requested and will be satisfied through local bridge {bridge_url}.",
            )

        return self._skip_route(
            route,
            f"HTTP/2 was requested, but the current {scanner.name} execution path cannot force HTTP/2 for this target.",
        )

    def _plan_forced_http1_route(
        self,
        scanner: BaseScanner,
        route: Dict[str, Any],
        capabilities: Dict[str, Any],
        probe: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Plan a route when the user explicitly requested HTTP/1.1."""
        if probe.get('probe_method') == 'unavailable':
            return self._skip_route(
                route,
                "HTTP/1.1 was requested, but transport probing is unavailable on this system.",
            )

        if not probe.get('reachable'):
            return self._skip_route(
                route,
                "HTTP/1.1 was requested, but the target probe could not confirm a reachable web endpoint.",
            )

        if probe.get('selected_scheme') == 'http':
            route['scanner_transport_notes'] = (
                f"{route.get('scanner_transport_notes', '')} "
                "HTTP/1.1 was requested and the selected target uses http://."
            ).strip()
            return route

        if probe.get('selected_scheme') != 'https':
            return self._skip_route(
                route,
                "HTTP/1.1 was requested, but the selected target scheme is not supported for forcing.",
            )

        if not probe.get('supports_http1_1'):
            return self._skip_route(
                route,
                "HTTP/1.1 was requested, but the target did not accept HTTP/1.1 during probing.",
            )

        if probe.get('transport_detected') == 'http1_only':
            route['scanner_transport_notes'] = (
                f"{route.get('scanner_transport_notes', '')} "
                "HTTP/1.1 was requested and the HTTPS probe confirmed that the target only accepts HTTP/1.1."
            ).strip()
            return route

        if capabilities.get('supports_http1_force'):
            route['scanner_transport_notes'] = (
                f"{route.get('scanner_transport_notes', '')} "
                "HTTP/1.1 was requested and will use the scanner's explicit HTTP/1.1 execution path."
            ).strip()
            return route

        return self._skip_route(
            route,
            f"HTTP/1.1 was requested, but the current {scanner.name} execution path cannot force HTTP/1.1 for this target.",
        )

    def _execution_metadata(
        self,
        scanner: BaseScanner,
        route: Dict[str, Any],
        raw_results: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Build stable execution metadata for reports and saved results."""
        capabilities = scanner.get_capabilities()
        probe = route.get('transport_probe') or {}
        route_options = route.get('options') or {}
        execution_target = (
            raw_results.get('effective_target')
            if raw_results and raw_results.get('effective_target')
            else route.get('target')
        )
        origin_target = route_options.get('origin_target')
        if raw_results and raw_results.get('origin_target'):
            origin_target = raw_results.get('origin_target')
        original_target = route_options.get('original_target') or probe.get('normalized_target')
        if raw_results and raw_results.get('original_target'):
            original_target = raw_results.get('original_target')
        partial_results = bool(raw_results.get('partial_results')) if raw_results else False
        degraded_execution = bool(raw_results.get('degraded_execution')) if raw_results else False
        scanner_error = None
        if raw_results:
            scanner_error = raw_results.get('scanner_error') or raw_results.get('error')
        adapter_details: Dict[str, Any] = {}
        route_adapter_details = route.get('adapter_details')
        if isinstance(route_adapter_details, dict):
            adapter_details.update(route_adapter_details)
        option_adapter_details = route_options.get('adapter_details')
        if isinstance(option_adapter_details, dict):
            adapter_details.update(option_adapter_details)
        if raw_results:
            for field in (
                'adapter_status',
                'adapter_runtime_state',
                'adapter_failure_reason',
                'adapter_diagnostics',
                'adapter_runtime',
                'adapter_upstream_url',
                'adapter_translation_chain',
                'transport_confidence',
                'adapter_shutdown_reason',
                'adapter_shutdown_clean',
            ):
                if field in raw_results and raw_results.get(field) is not None:
                    adapter_details[field] = raw_results.get(field)
        transport_confidence = adapter_details.get('transport_confidence')
        if transport_confidence is None:
            if route.get('scan_route') == 'skipped':
                transport_confidence = (
                    'failed'
                    if adapter_details.get('adapter_status') == 'startup_failed'
                    else 'skipped'
                )
            elif degraded_execution or partial_results:
                transport_confidence = 'degraded'
            elif scanner_error and not partial_results:
                transport_confidence = 'failed'
            else:
                transport_confidence = 'normal'
        return {
            'scanner_type': capabilities.get('scanner_type', 'generic'),
            'supports_http2_direct': capabilities.get('supports_http2_direct', False),
            'supports_http1_force': capabilities.get('supports_http1_force', False),
            'supports_proxy': capabilities.get('supports_proxy', False),
            'supports_http2_bridge': capabilities.get('supports_http2_bridge', False),
            'execution_target': execution_target,
            'effective_target': execution_target,
            'origin_target': origin_target,
            'original_target': original_target,
            'transport_detected': route.get('transport_detected', 'unknown'),
            'scan_route': route.get('scan_route', 'direct'),
            'adapter_mode': route.get('adapter_mode', 'direct'),
            'skip_reason': route.get('skip_reason'),
            'scanner_error': scanner_error,
            'partial_results': partial_results,
            'degraded_execution': degraded_execution,
            'imported_report': bool(raw_results.get('imported_report')) if raw_results else False,
            'imported_report_path': raw_results.get('imported_report_path') if raw_results else None,
            'report_format': raw_results.get('report_format') if raw_results else None,
            'scanner_transport_notes': route.get('scanner_transport_notes', ''),
            'requested_http_mode': route.get('requested_http_mode', self.http_mode),
            'selected_scheme': probe.get('selected_scheme'),
            'detected_http_version': probe.get('detected_http_version'),
            'supports_http2': probe.get('supports_http2'),
            'supports_http1_1': probe.get('supports_http1_1'),
            'http2_only': probe.get('http2_only'),
            'probe_method': probe.get('probe_method'),
            'adapter_status': adapter_details.get('adapter_status'),
            'adapter_runtime_state': adapter_details.get('adapter_runtime_state'),
            'adapter_failure_reason': adapter_details.get('adapter_failure_reason'),
            'adapter_diagnostics': adapter_details.get('adapter_diagnostics'),
            'adapter_runtime': adapter_details.get('adapter_runtime'),
            'adapter_upstream_url': adapter_details.get('adapter_upstream_url'),
            'adapter_translation_chain': adapter_details.get('adapter_translation_chain'),
            'transport_confidence': transport_confidence,
            'adapter_shutdown_reason': adapter_details.get('adapter_shutdown_reason'),
            'adapter_shutdown_clean': adapter_details.get('adapter_shutdown_clean'),
        }

    def _decorate_raw_results(
        self,
        route: Dict[str, Any],
        raw_results: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Attach stable transport metadata to raw scanner results."""
        route_options = dict(route.get('options') or {})
        raw_results.setdefault('adapter_mode', route.get('adapter_mode', 'direct'))
        raw_results.setdefault('effective_target', route.get('target'))
        original_target = route_options.get('original_target')
        if original_target:
            raw_results.setdefault('original_target', original_target)
        origin_target = route_options.get('origin_target')
        if origin_target:
            raw_results.setdefault('origin_target', origin_target)
        adapter_details = route.get('adapter_details')
        if isinstance(adapter_details, dict):
            for field in (
                'adapter_status',
                'adapter_runtime_state',
                'adapter_failure_reason',
                'adapter_diagnostics',
                'adapter_runtime',
                'adapter_upstream_url',
                'adapter_translation_chain',
                'transport_confidence',
                'adapter_shutdown_reason',
                'adapter_shutdown_clean',
            ):
                if adapter_details.get(field) is not None:
                    raw_results.setdefault(field, adapter_details.get(field))
        return raw_results

    def _apply_execution_assessment(
        self,
        scanner: BaseScanner,
        raw_results: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Merge scanner-specific degraded-execution signals into raw results."""
        try:
            assessment = scanner.assess_execution(raw_results) or {}
        except Exception as exc:
            assessment = {
                'degraded_execution': True,
                'scanner_error': f"Execution assessment failed for scanner '{scanner.name}': {exc}",
            }

        for key, value in assessment.items():
            if key == 'partial_results':
                raw_results['partial_results'] = bool(raw_results.get('partial_results')) or bool(value)
            else:
                raw_results[key] = value

        if raw_results.get('partial_results'):
            raw_results['degraded_execution'] = True

        if raw_results.get('degraded_execution') and not raw_results.get('scanner_error'):
            raw_results['scanner_error'] = raw_results.get('error') or 'Scanner execution was degraded.'

        if (
            raw_results.get('degraded_execution')
            and raw_results.get('scanner_error')
            and 'error' not in raw_results
            and not raw_results.get('findings')
            and not raw_results.get('partial_results')
        ):
            raw_results['error'] = raw_results['scanner_error']

        return raw_results

    @staticmethod
    def _scanner_timing_status(results: Dict[str, Any]) -> str:
        """Map one scanner result to a compact timing status."""
        if results.get('skip_reason') or results.get('scan_route') == 'skipped':
            return 'skipped'
        if results.get('error') and not results.get('partial_results'):
            return 'failed'
        if results.get('warning') or results.get('scanner_error') or results.get('partial_results'):
            return 'warning'
        return 'success'

    @staticmethod
    def _scanner_timing_note(scanner_name: str, target: str, results: Dict[str, Any]) -> str:
        """Return a readable timing note for one scanner result."""
        notes = [f"scanner={scanner_name}", f"target={target}"]
        if results.get('skip_reason'):
            notes.append(f"skip_reason={results['skip_reason']}")
        if results.get('error'):
            notes.append(f"error={results['error']}")
        elif results.get('warning'):
            notes.append(f"warning={results['warning']}")
        elif results.get('scanner_error'):
            notes.append(f"scanner_error={results['scanner_error']}")
        if results.get('raw_findings_count') is not None:
            notes.append(f"raw_findings={results.get('raw_findings_count')}")
        if results.get('normalized_findings_count') is not None:
            notes.append(f"normalized_findings={results.get('normalized_findings_count')}")
        return "; ".join(notes)

    def _build_scan_options(self, route: Dict[str, Any]) -> Dict[str, Any]:
        """Return scanner options for one planned route."""
        options = dict(route.get('options') or {})
        if self.current_run_folder is not None and 'output_dir' not in options:
            options['output_dir'] = str(get_raw_dir(self.current_run_folder))
        return options

    def _execute_planned_scan(
        self,
        scanner: BaseScanner,
        target: str,
        route: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Run one scanner against one already-planned route."""
        options = self._build_scan_options(route)
        print(f"[*] Running {scanner.name} scan against {route.get('target', target)}...")
        raw_results = scanner.scan(route.get('target', target), options)
        raw_results = self._decorate_raw_results(route, raw_results)
        return self._apply_execution_assessment(scanner, raw_results)

    def _result_warning(self, raw_results: Dict[str, Any]) -> Optional[str]:
        """Return a non-fatal execution warning that should surface in reports."""
        warning = raw_results.get('scanner_error') or raw_results.get('error')
        if not warning:
            return None
        if (
            raw_results.get('findings')
            or raw_results.get('partial_results')
            or raw_results.get('execution_warnings')
            or raw_results.get('raw_output') is not None
            or raw_results.get('raw_output_path') is not None
        ):
            return warning
        return None

    def _append_execution_warning(self, raw_results: Dict[str, Any], warning: str) -> None:
        """Attach a scanner execution warning without promoting it to a finding."""
        warnings = raw_results.setdefault('execution_warnings', [])
        if warning not in warnings:
            warnings.append(warning)

        existing = raw_results.get('scanner_error')
        if existing:
            if warning not in existing:
                raw_results['scanner_error'] = f"{existing} {warning}"
        else:
            raw_results['scanner_error'] = warning
        raw_results['degraded_execution'] = True

    def _suppress_adapter_local_connectivity_findings(
        self,
        scanner: BaseScanner,
        route: Dict[str, Any],
        raw_results: Dict[str, Any],
        normalized_findings: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """Drop adapter-local transport artifacts from normalized findings."""
        if not normalized_findings:
            return normalized_findings

        route_options = route.get('options') or {}
        adapter_mode = raw_results.get('adapter_mode') or route.get('adapter_mode')
        effective_target = raw_results.get('effective_target') or route.get('target')
        original_target = (
            raw_results.get('original_target')
            or route_options.get('original_target')
            or raw_results.get('origin_target')
            or route_options.get('origin_target')
        )

        kept: List[Dict[str, Any]] = []
        suppressed_connectivity: List[Dict[str, Any]] = []
        suppressed_transport: List[Dict[str, Any]] = []
        for finding in normalized_findings:
            if is_adapter_local_connectivity_artifact(
                finding,
                effective_target=effective_target,
                original_target=original_target,
                adapter_mode=adapter_mode,
            ):
                suppressed_connectivity.append(finding)
            elif is_adapter_transport_artifact(
                finding,
                effective_target=effective_target,
                original_target=original_target,
                adapter_mode=adapter_mode,
            ):
                suppressed_transport.append(finding)
            else:
                kept.append(finding)

        suppressed = suppressed_connectivity + suppressed_transport
        if not suppressed:
            return normalized_findings

        raw_results['suppressed_adapter_findings_count'] = (
            int(raw_results.get('suppressed_adapter_findings_count') or 0)
            + len(suppressed)
        )
        artifact_label = (
            'adapter-local connectivity artifact'
            if suppressed_connectivity and not suppressed_transport
            else 'adapter-local transport artifact'
        )
        sample = suppressed[0].get('vulnerability_name') or suppressed[0].get('description') or artifact_label
        warning = (
            f"Suppressed {len(suppressed)} {artifact_label}"
            f"{'' if len(suppressed) == 1 else 's'} from {scanner.name}; "
            f"kept as scanner execution metadata instead of vulnerability findings. "
            f"Sample: {sample}"
        )
        self._append_execution_warning(raw_results, warning)
        return kept

    def run_scanner(
        self,
        name: str,
        target: str,
        options: Optional[Dict[str, Any]] = None,
        normalize: bool = True,
        save_raw: bool = True
    ) -> Dict[str, Any]:
        """
        Run a specific scanner against a target.

        Args:
            name: Name of the registered scanner
            target: Target to scan
            options: Scanner-specific options
            normalize: If True, normalize results to unified schema
            save_raw: If True, save raw output to data directory

        Returns:
            Dict with scan results
        """
        if name not in self.scanners:
            result = {
                'scanner': name,
                'target': target,
                'error': f"Scanner '{name}' not registered",
                'findings': []
            }
            handle = self.timing.start(name, note=f"scanner={name}; target={target}")
            self.timing.finish(
                handle,
                status='failed',
                note=self._scanner_timing_note(name, target, result),
            )
            return result

        # BUG-01 fix: check enabled BEFORE stripping internal markers so that
        # direct run_scanner(options={'enabled': False}) calls are not bypassed.
        if not self._scanner_enabled(options):
            result = {
                'scanner': name,
                'target': target,
                'timestamp': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
                'findings': [],
                'warning': f"Scanner '{name}' was disabled by the effective scan config",
            }
            handle = self.timing.start(name, note=f"scanner={name}; target={target}")
            self.timing.finish(
                handle,
                status='skipped',
                note=self._scanner_timing_note(name, target, result),
            )
            return result

        scanner = self.scanners[name]

        # Existing-report imports do not require a locally installed scanner and
        # must not be routed through target transport probing.
        requested_options = self._strip_internal_option_markers(options)
        offline_input = scanner.uses_offline_input(requested_options)

        if not offline_input and not scanner.is_available():
            result = {
                'scanner': name,
                'target': target,
                'error': f"Scanner '{name}' is not available on this system",
                'findings': []
            }
            handle = self.timing.start(name, note=f"scanner={name}; target={target}")
            self.timing.finish(
                handle,
                status='failed',
                note=self._scanner_timing_note(name, target, result),
            )
            return result

        # Validate after availability unless the invocation is an offline import,
        # which remains usable even when the scanner executable is absent.
        requested_options = scanner.validate_options(requested_options)
        offline_input = scanner.uses_offline_input(requested_options)
        route = (
            self._plan_offline_input_route(scanner, target, requested_options)
            if offline_input
            else self._plan_scan_route(scanner, target, requested_options)
        )
        execution_meta = self._execution_metadata(scanner, route)

        if route.get('scan_route') == 'skipped':
            timestamp = datetime.now(timezone.utc)
            result = {
                'scanner': name,
                'target': route.get('target', target),
                'timestamp': timestamp.isoformat().replace('+00:00', 'Z'),
                'error': execution_meta['skip_reason'],
                'findings': [],
                'scan_route': execution_meta['scan_route'],
                'transport_detected': execution_meta['transport_detected'],
                'skip_reason': execution_meta['skip_reason'],
                'scanner_transport_notes': execution_meta['scanner_transport_notes'],
                'scanner_execution': execution_meta,
                'target_probe': route.get('transport_probe'),
            }
            if options and options.get('discovered_services') is not None:
                result['discovered_services'] = options.get('discovered_services')
            if save_raw:
                if self.current_run_folder is None:
                    run_folder = self.ensure_run_folder(target, timestamp=timestamp)
                    print(f"[*] Created run folder: {run_folder}")
                self._persist_raw_artifacts(name, target, result)
            handle = self.timing.start(name, note=f"scanner={name}; target={route.get('target', target)}")
            self.timing.finish(
                handle,
                status='skipped',
                note=self._scanner_timing_note(name, route.get('target', target), result),
            )
            return result

        if self.current_run_folder is None:
            run_folder = self.ensure_run_folder(target, timestamp=datetime.now(timezone.utc))
            print(f"[*] Created run folder: {run_folder}")

        scan_target = route.get('target', target)
        scan_timing = self.timing.start(name, note=f"scanner={name}; target={scan_target}")
        try:
            raw_results = self._execute_planned_scan(scanner, target, route)
        except Exception as exc:
            self.timing.finish(
                scan_timing,
                status='failed',
                note=f"scanner={name}; target={scan_target}; error={exc}",
            )
            raise
        self.timing.finish(
            scan_timing,
            status=self._scanner_timing_status(raw_results),
            note=self._scanner_timing_note(name, scan_target, raw_results),
        )
        execution_meta = self._execution_metadata(scanner, route, raw_results)
        partial_warning = self._result_warning(raw_results)
        has_report_artifact = (
            raw_results.get('raw_output') is not None
            or raw_results.get('raw_output_path') is not None
        )

        if save_raw:
            self._persist_raw_artifacts(name, target, raw_results)

        if (
            'error' in raw_results
            and not raw_results.get('findings')
            and not raw_results.get('partial_results')
            and not has_report_artifact
        ):
            result = {
                'scanner': name,
                'target': route.get('target', target),
                'timestamp': raw_results.get('timestamp'),
                'error': raw_results['error'],
                'findings': [],
                'scan_route': execution_meta['scan_route'],
                'transport_detected': execution_meta['transport_detected'],
                'skip_reason': execution_meta['skip_reason'],
                'scanner_transport_notes': execution_meta['scanner_transport_notes'],
                'scanner_execution': execution_meta,
                'target_probe': route.get('transport_probe'),
            }
            if raw_results.get('discovered_services') is not None:
                result['discovered_services'] = raw_results.get('discovered_services')
            self._copy_raw_artifact_fields(raw_results, result)
            return result

        exit_code = raw_results.get('exit_code')
        if (
            exit_code not in (None, 0)
            and not raw_results.get('findings')
            and not raw_results.get('partial_results')
            and not has_report_artifact
        ):
            stderr = (raw_results.get('stderr') or '').strip()
            error = f"Scanner '{name}' exited with code {exit_code}"
            if stderr:
                error = f"{error}: {stderr}"
            raw_results.setdefault('scanner_error', error)
            execution_meta = self._execution_metadata(scanner, route, raw_results)
            result = {
                'scanner': name,
                'target': route.get('target', target),
                'timestamp': raw_results.get('timestamp'),
                'error': error,
                'findings': [],
                'scan_route': execution_meta['scan_route'],
                'transport_detected': execution_meta['transport_detected'],
                'skip_reason': execution_meta['skip_reason'],
                'scanner_transport_notes': execution_meta['scanner_transport_notes'],
                'scanner_execution': execution_meta,
                'target_probe': route.get('transport_probe'),
            }
            if raw_results.get('discovered_services') is not None:
                result['discovered_services'] = raw_results.get('discovered_services')
            self._copy_raw_artifact_fields(raw_results, result)
            return result

        if normalize:
            normalize_timing = self.timing.start(
                'normalization',
                note=f"scanner={name}; target={route.get('target', target)}",
            )
            try:
                normalized_findings = scanner.normalize(raw_results)
                normalized_findings = self._suppress_adapter_local_connectivity_findings(
                    scanner,
                    route,
                    raw_results,
                    normalized_findings,
                )
                execution_meta = self._execution_metadata(scanner, route, raw_results)
                partial_warning = self._result_warning(raw_results)

                # Stage A: post_normalize validation — fail fast before aggregation
                _temp = {
                    'schema_version': SCHEMA_VERSION,
                    'target': target,
                    'all_findings': normalized_findings,
                }
                assert_valid_results(_temp, stage='post_normalize')
            except Exception as exc:
                self.timing.finish(
                    normalize_timing,
                    status='failed',
                    note=f"scanner={name}; target={route.get('target', target)}; error={exc}",
                )
                raise
            self.timing.finish(
                normalize_timing,
                status='success',
                note=(
                    f"scanner={name}; target={route.get('target', target)}; "
                    f"raw_findings={len(raw_results.get('findings', []))}; "
                    f"normalized_findings={len(normalized_findings)}"
                ),
            )

            result = {
                'scanner': name,
                'target': route.get('target', target),
                'timestamp': raw_results.get('timestamp'),
                'findings': normalized_findings,
                'raw_findings_count': len(raw_results.get('findings', [])),
                'normalized_findings_count': len(normalized_findings),
                'scan_route': execution_meta['scan_route'],
                'transport_detected': execution_meta['transport_detected'],
                'skip_reason': execution_meta['skip_reason'],
                'scanner_transport_notes': execution_meta['scanner_transport_notes'],
                'scanner_execution': execution_meta,
                'target_probe': route.get('transport_probe'),
            }
            if partial_warning:
                result['warning'] = partial_warning
            if raw_results.get('partial_results') is not None:
                result['partial_results'] = raw_results.get('partial_results')
            if raw_results.get('discovered_services') is not None:
                result['discovered_services'] = raw_results.get('discovered_services')
            self._copy_raw_artifact_fields(raw_results, result)
            return result

        result = dict(raw_results)
        if partial_warning:
            result.pop('error', None)
            result['warning'] = partial_warning
        result['scanner_execution'] = execution_meta
        result['scan_route'] = execution_meta['scan_route']
        result['transport_detected'] = execution_meta['transport_detected']
        result['skip_reason'] = execution_meta['skip_reason']
        result['scanner_transport_notes'] = execution_meta['scanner_transport_notes']
        result['target_probe'] = route.get('transport_probe')
        return result

    def _initialize_aggregate_results(
        self,
        target: str,
        run_folder: Path,
        timestamp_iso: str,
    ) -> Dict[str, Any]:
        """Create the stable top-level aggregate result shell."""
        return {
            'schema_version': SCHEMA_VERSION,
            'target': target,
            'timestamp': timestamp_iso,
            'run_folder': str(run_folder),
            'scanners_run': [],
            'all_findings': [],
            'findings_by_scanner': {},
            'errors': [],
            'scanner_execution': {},
            'scanner_instances': {},
            'defectdojo_raw_uploads': [],
        }

    def _record_aggregate_result(
        self,
        aggregate: Dict[str, Any],
        execution_key: str,
        scanner_name: str,
        result: Dict[str, Any],
        service: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Merge one scanner invocation result into the aggregate payload."""
        findings = result.get('findings', [])
        if execution_key != scanner_name:
            for finding in findings:
                meta = finding.setdefault('meta', {})
                meta.setdefault('scanner_instance', execution_key)

        aggregate['scanners_run'].append(execution_key)
        aggregate['scanner_execution'][execution_key] = result.get('scanner_execution', {})
        aggregate['findings_by_scanner'][execution_key] = findings
        aggregate['all_findings'].extend(findings)

        instance_meta: Dict[str, Any] = {
            'scanner': scanner_name,
            'target': result.get('target'),
        }
        if service:
            instance_meta.update({
                'host': service.get('host'),
                'port': service.get('port'),
                'protocol': service.get('protocol'),
                'service': service.get('service'),
                'service_version': service.get('service_version'),
                'web_scheme': service.get('web_scheme'),
            })
        aggregate['scanner_instances'][execution_key] = instance_meta

        if result.get('imported_report'):
            aggregate.setdefault('imported_reports', []).append({
                'scanner': scanner_name,
                'execution_key': execution_key,
                'path': result.get('imported_report_path'),
                'format': result.get('report_format'),
            })

        if 'error' in result:
            aggregate['errors'].append({
                'scanner': execution_key,
                'error': result['error'],
            })
        if result.get('warning'):
            aggregate.setdefault('warnings', []).append({
                'scanner': execution_key,
                'warning': result['warning'],
            })
        if result.get('target_probe'):
            aggregate.setdefault('target_probes', {})[execution_key] = result['target_probe']

        aggregate.setdefault('defectdojo_raw_uploads', []).append(
            self._build_defectdojo_raw_upload_manifest_entry(
                execution_key=execution_key,
                scanner_name=scanner_name,
                result=result,
            )
        )

    def _build_defectdojo_raw_upload_manifest_entry(
        self,
        *,
        execution_key: str,
        scanner_name: str,
        result: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Build the DefectDojo raw-upload manifest entry for one execution."""
        execution_meta = result.get('scanner_execution') if isinstance(result.get('scanner_execution'), dict) else {}
        target = (
            execution_meta.get('original_target')
            or execution_meta.get('origin_target')
            or result.get('origin_target')
            or result.get('target')
            or execution_meta.get('execution_target')
            or ''
        )
        return build_raw_upload_manifest_entry(
            scanner_name=scanner_name,
            execution_key=execution_key,
            target=str(target or ''),
            artifact=result.get('defectdojo_raw_artifact'),
            scan_type=resolve_raw_scan_type(scanner_name),
            raw_artifacts=result.get('raw_artifacts'),
        )

    def _finalize_aggregate_results(
        self,
        aggregate: Dict[str, Any],
        normalize: bool,
        run_folder: Path,
    ) -> Dict[str, Any]:
        """Sort, summarize, version-stamp, and persist one aggregate result."""
        if normalize:
            aggregate['all_findings'] = sort_by_severity(aggregate['all_findings'])

        aggregate['summary'] = {
            'total_findings': len(aggregate['all_findings']),
            'by_severity': self._count_by_severity(aggregate['all_findings']),
            'by_scanner': {
                name: len(findings)
                for name, findings in aggregate['findings_by_scanner'].items()
            },
        }

        aggregate['schema_version'] = SCHEMA_VERSION
        # BUG-06 fix: stamp generated_at exactly once here and preserve it so that
        # main.py can reuse the same value instead of creating a second timestamp.
        # Both scan_results.json (written below) and normalized.json (written by
        # save_results() via main.py) will therefore carry identical timestamps.
        aggregate.setdefault(
            'generated_at',
            datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
        )

        tool_versions: Dict[str, Optional[str]] = {}
        for execution_key in aggregate['scanners_run']:
            instance = aggregate.get('scanner_instances', {}).get(execution_key, {})
            scanner_name = instance.get('scanner') or execution_key
            scanner = self.scanners.get(scanner_name)
            if scanner is not None:
                try:
                    tool_versions[execution_key] = scanner.get_version()
                except Exception:
                    tool_versions[execution_key] = None
        aggregate['tool_versions'] = tool_versions

        target_probes = aggregate.get('target_probes') or {}
        if len(target_probes) == 1:
            only_probe = next(iter(target_probes.values()))
            aggregate['target_probe'] = only_probe
            aggregate['transport_detected'] = only_probe

        scan_results_path = get_scan_results_json_path(run_folder)
        export_aggregate = sanitize_results_for_export(aggregate)
        with open(scan_results_path, 'w') as f:
            json.dump(export_aggregate, f, indent=2, default=str)
        print(f"[+] Raw scan results saved to: {scan_results_path}")

        return aggregate

    def _run_all_legacy(
        self,
        target: str,
        options: Optional[Dict[str, Dict[str, Any]]] = None,
        normalize: bool = True,
        save_raw: bool = True,
    ) -> Dict[str, Any]:
        """Run the original one-target-per-scanner orchestration flow."""
        options = options or {}
        timestamp = datetime.now(timezone.utc)
        timestamp_iso = timestamp.isoformat().replace('+00:00', 'Z')

        run_folder = self.ensure_run_folder(target, timestamp=timestamp)

        all_results = self._initialize_aggregate_results(target, run_folder, timestamp_iso)

        for name, scanner in self.scanners.items():
            scanner_options = dict(options.get(name, {}))
            if not self._scanner_enabled(scanner_options):
                continue
            scanner_options = self._strip_internal_option_markers(scanner_options)
            result = self.run_scanner(
                name, target, scanner_options, normalize, save_raw
            )
            self._record_aggregate_result(all_results, name, name, result)

            # Top-level transport_detected keeps the full shared probe payload.
            # Per-scanner scanner_execution[*].transport_detected stores the
            # summarized classification string used by routing/reporting.
            if result.get('target_probe') and 'target_probe' not in all_results:
                all_results['target_probe'] = result['target_probe']
                all_results['transport_detected'] = result['target_probe']

        return self._finalize_aggregate_results(all_results, normalize, run_folder)

    def _run_all_discovery_mode(
        self,
        target: str,
        options: Optional[Dict[str, Dict[str, Any]]] = None,
        normalize: bool = True,
        save_raw: bool = True,
    ) -> Dict[str, Any]:
        """Run discovery-first multi-stage orchestration for automatic/manual mode."""
        options = options or {}
        timestamp = datetime.now(timezone.utc)
        timestamp_iso = timestamp.isoformat().replace('+00:00', 'Z')

        run_folder = self.ensure_run_folder(target, timestamp=timestamp)

        all_results = self._initialize_aggregate_results(target, run_folder, timestamp_iso)
        all_results['scan_mode'] = self.scan_mode

        nmap_options = dict(options.get('nmap', {}))
        if not self._scanner_enabled(nmap_options):
            raise ValueError("nmap is required for discovery-mode --scanner all runs")
        nmap_options = self._strip_internal_option_markers(nmap_options)
        discovery_target = self._build_discovery_target(target)
        if self.selected_ports_spec and 'ports' not in nmap_options:
            nmap_options['ports'] = self.selected_ports_spec

        nmap_result = self.run_scanner('nmap', discovery_target, nmap_options, normalize, save_raw)
        self._record_aggregate_result(all_results, 'nmap', 'nmap', nmap_result)

        discovered_services = nmap_result.get('discovered_services') or []
        selected_ports = list(self.selected_ports or [])
        if self.scan_mode == SCAN_MODE_MANUAL and selected_ports:
            planned_services = [
                service for service in discovered_services
                if service.get('port') in set(selected_ports)
            ]
        else:
            planned_services = list(discovered_services)

        web_services = [
            service for service in planned_services
            if self._is_discovery_web_service_eligible(service)
        ]

        if self.scan_mode == SCAN_MODE_MANUAL and selected_ports:
            discovered_open_ports = {
                int(service['port'])
                for service in discovered_services
                if isinstance(service.get('port'), int)
            }
            missing_ports = [port for port in selected_ports if port not in discovered_open_ports]
            if missing_ports:
                all_results.setdefault('warnings', []).append({
                    'scanner': 'planner',
                    'warning': (
                        "Manual mode selected port(s) that nmap did not report as open: "
                        + ', '.join(str(port) for port in missing_ports)
                    ),
                })

        enabled_web_scanners: List[Tuple[str, BaseScanner]] = [
            (name, scanner)
            for name, scanner in self.scanners.items()
            if self._is_web_scanner(name, scanner) and self._scanner_enabled(options.get(name, {}))
        ]
        offline_web_scanners: List[Tuple[str, BaseScanner]] = []
        web_scanners: List[Tuple[str, BaseScanner]] = []
        for name, scanner in enabled_web_scanners:
            candidate_options = self._strip_internal_option_markers(options.get(name, {}))
            if scanner.uses_offline_input(candidate_options):
                offline_web_scanners.append((name, scanner))
            else:
                web_scanners.append((name, scanner))
        scan_plan = self._build_discovery_scan_plan(target, web_services, web_scanners)
        probe_fallback_service = None
        if web_scanners and not scan_plan:
            probe_fallback_service = self._build_probe_fallback_web_service(target, planned_services)
            if probe_fallback_service is not None:
                scan_plan = self._build_discovery_scan_plan(
                    target,
                    [probe_fallback_service],
                    web_scanners,
                )

        all_results['discovery'] = {
            'scanner': 'nmap',
            'input_target': target,
            'discovery_target': discovery_target,
            'ports_requested': nmap_options.get('ports'),
            'selected_ports': selected_ports or None,
            'services': discovered_services,
            'web_services': web_services,
            'probe_fallback_service': probe_fallback_service,
        }

        # Imported reports are target evidence, not live scan-plan entries. Load
        # each one exactly once even when discovery found several web services.
        for scanner_name, _scanner in offline_web_scanners:
            scanner_options = dict(options.get(scanner_name, {}))
            scanner_options = self._strip_internal_option_markers(scanner_options)
            result = self.run_scanner(
                scanner_name,
                target,
                scanner_options,
                normalize,
                save_raw,
            )
            self._record_aggregate_result(
                all_results,
                scanner_name,
                scanner_name,
                result,
            )
        # BUG-08 fix: evaluate the early-return condition AFTER scan_plan has been
        # fully built (including the probe-derived fallback).  The original code
        # used 'not scan_plan' before scan_plan was assigned, so the probe fallback
        # was never attempted when nmap raised a partial error.
        if 'error' in nmap_result and not discovered_services and not scan_plan:
            return self._finalize_aggregate_results(all_results, normalize, run_folder)

        all_results['scan_plan'] = scan_plan

        if self.scan_mode == SCAN_MODE_MANUAL and selected_ports and not web_services and probe_fallback_service is None:
            all_results.setdefault('warnings', []).append({
                'scanner': 'planner',
                'warning': (
                    "Manual mode did not schedule web scanners because none of the selected open ports "
                    "were identified by nmap as HTTP or HTTPS services."
                ),
            })

        for plan_entry in scan_plan:
            scanner_name = plan_entry['scanner']
            scanner_options = dict(options.get(scanner_name, {}))
            scanner_options = self._strip_internal_option_markers(scanner_options)
            if scanner_name == 'nikto':
                # BUG-12 fix: only inject the port option when the target URL does
                # not already embed it.  When _build_web_target_from_service builds
                # 'scheme://host:port', passing an additional port=N is redundant
                # and will break if Nikto CLI changes how it handles the clash.
                plan_web_target = plan_entry.get('target', '')
                parsed_plan_target = urlparse(plan_web_target)
                if parsed_plan_target.port is None:
                    scanner_options.setdefault('port', plan_entry.get('port'))

            result = self.run_scanner(
                scanner_name,
                plan_entry['target'],
                scanner_options,
                normalize,
                save_raw,
            )
            service_meta = {
                'host': plan_entry.get('host'),
                'port': plan_entry.get('port'),
                'protocol': plan_entry.get('protocol'),
                'service': plan_entry.get('service'),
                'service_version': plan_entry.get('service_version'),
                'web_scheme': plan_entry.get('web_scheme'),
                'planning_source': plan_entry.get('planning_source'),
            }
            self._record_aggregate_result(
                all_results,
                plan_entry['execution_key'],
                scanner_name,
                result,
                service=service_meta,
            )

        return self._finalize_aggregate_results(all_results, normalize, run_folder)

    def run_all(
        self,
        target: str,
        options: Optional[Dict[str, Dict[str, Any]]] = None,
        normalize: bool = True,
        save_raw: bool = True
    ) -> Dict[str, Any]:
        """
        Run all registered scanners against a target.

        Args:
            target: Target to scan
            options: Dict of scanner_name -> options
            normalize: If True, normalize all results
            save_raw: If True, save all raw output

        Returns:
            Dict with aggregated results from all scanners
        """
        if self.scan_mode in SUPPORTED_SCAN_MODES:
            return self._run_all_discovery_mode(target, options, normalize, save_raw)
        return self._run_all_legacy(target, options, normalize, save_raw)

    def _save_raw_output(self, scanner_name: str, target: str, results: Dict[str, Any]) -> Path:
        """Save raw scanner output to run folder's raw/ directory."""
        timestamp = datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')
        safe_target = target.replace('://', '_').replace('/', '_').replace(':', '_')
        filename = f"{scanner_name}_{safe_target}_{timestamp}.json"

        if self.current_run_folder:
            raw_dir = get_raw_dir(self.current_run_folder)
            output_path = raw_dir / filename
        else:
            data_dir = self.reports_dir.parent / 'data' if self.reports_dir.parent else Path('data')
            data_dir.mkdir(parents=True, exist_ok=True)
            output_path = data_dir / filename

        with open(output_path, 'w') as f:
            json.dump(results, f, indent=2, default=str)

        print(f"[+] Raw output saved to: {output_path}")
        return output_path

    def _persist_raw_artifacts(
        self,
        scanner_name: str,
        target: str,
        results: Dict[str, Any],
    ) -> tuple[Optional[Path], Path]:
        """Persist the existing raw artifact plus a matching XML artifact."""
        artifacts: List[Dict[str, Any]] = []
        json_path: Optional[Path] = None
        raw_output_path = results.get('raw_output_path')
        if raw_output_path is None:
            json_path = self._save_raw_output(scanner_name, target, results)
            artifacts.append({
                'path': str(json_path),
                'artifact_format': 'json',
                'native': False,
                'role': 'project-wrapper-json',
                'source': 'orchestrator-wrapper',
            })
        else:
            path = Path(str(raw_output_path))
            artifacts.append({
                'path': str(path),
                'artifact_format': path.suffix.lower().lstrip('.') or None,
                'native': True,
                'role': 'scanner-native-report',
                'source': 'raw_output_path',
            })

        xml_is_native = self._result_has_native_xml(results)
        xml_path = self._save_raw_xml_output(results, json_path=json_path)
        artifacts.append({
            'path': str(xml_path),
            'artifact_format': 'xml',
            'native': xml_is_native,
            'role': 'scanner-native-xml' if xml_is_native else 'project-generated-xml-wrapper',
            'source': 'raw_output' if xml_is_native else 'xml_artifacts-renderer',
        })

        native_artifact = self._ensure_defectdojo_native_artifact(
            scanner_name,
            target,
            results,
            xml_path=xml_path,
            xml_is_native=xml_is_native,
        )
        if native_artifact:
            self._append_unique_artifact(artifacts, native_artifact)
            results['defectdojo_raw_artifact'] = native_artifact
        else:
            results.pop('defectdojo_raw_artifact', None)
        results['raw_artifacts'] = artifacts
        return json_path, xml_path

    @staticmethod
    def _append_unique_artifact(artifacts: List[Dict[str, Any]], artifact: Dict[str, Any]) -> None:
        artifact_path = str(artifact.get('path') or '')
        for existing in artifacts:
            if str(existing.get('path') or '') == artifact_path:
                existing.update(artifact)
                return
        artifacts.append(artifact)

    @staticmethod
    def _result_has_native_xml(results: Dict[str, Any]) -> bool:
        raw_output_path = results.get('raw_output_path')
        if raw_output_path:
            path = Path(str(raw_output_path))
            if path.suffix.lower() == '.xml' and path.exists():
                return True
        return extract_native_xml_text(results) is not None

    def _ensure_defectdojo_native_artifact(
        self,
        scanner_name: str,
        target: str,
        results: Dict[str, Any],
        *,
        xml_path: Path,
        xml_is_native: bool,
    ) -> Optional[Dict[str, Any]]:
        """Return or create the scanner-native artifact safe for raw DefectDojo upload."""
        scanner_key = str(scanner_name or '').strip().lower()
        existing_artifact = results.get('defectdojo_raw_artifact')
        if isinstance(existing_artifact, dict):
            artifact_path = existing_artifact.get('path') or existing_artifact.get('raw_artifact_path')
            if artifact_path:
                path = Path(str(artifact_path))
                if path.exists() and existing_artifact.get('native'):
                    return {
                        'path': str(path),
                        'artifact_format': (
                            existing_artifact.get('artifact_format')
                            or path.suffix.lower().lstrip('.')
                            or self._native_artifact_format(scanner_key)
                        ),
                        'native': True,
                        'role': existing_artifact.get('role') or 'defectdojo-native-parser-input',
                        'source': existing_artifact.get('source') or 'scanner-provided-defectdojo-artifact',
                    }

        raw_output_path = results.get('raw_output_path')
        if raw_output_path:
            path = Path(str(raw_output_path))
            if path.exists() and (scanner_key != 'wapiti' or path.suffix.lower() == '.xml'):
                return {
                    'path': str(path),
                    'artifact_format': path.suffix.lower().lstrip('.') or self._native_artifact_format(scanner_key),
                    'native': True,
                    'role': 'defectdojo-native-parser-input',
                    'source': 'raw_output_path',
                }

        if scanner_key == 'nmap' and xml_is_native:
            return {
                'path': str(xml_path),
                'artifact_format': 'xml',
                'native': True,
                'role': 'defectdojo-native-parser-input',
                'source': 'raw_output',
            }

        if scanner_key == 'nuclei' and isinstance(results.get('raw_output'), str):
            path = self._write_native_raw_text(scanner_name, target, results['raw_output'], suffix='jsonl')
            return {
                'path': str(path),
                'artifact_format': 'jsonl',
                'native': True,
                'role': 'defectdojo-native-parser-input',
                'source': 'raw_output',
            }

        if scanner_key == 'wapiti':
            return None

        if scanner_key == 'nikto' and isinstance(results.get('raw_output'), (dict, list)):
            path = self._write_native_raw_json(scanner_name, target, results['raw_output'])
            return {
                'path': str(path),
                'artifact_format': 'json',
                'native': True,
                'role': 'defectdojo-native-parser-input',
                'source': 'raw_output',
            }

        return None

    @staticmethod
    def _native_artifact_format(scanner_name: str) -> Optional[str]:
        return {
            'nmap': 'xml',
            'nuclei': 'jsonl',
            'wapiti': 'xml',
            'nikto': 'json',
            'zap': 'json',
        }.get(scanner_name)

    def _native_artifact_path(self, scanner_name: str, target: str, suffix: str) -> Path:
        timestamp = datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')
        safe_target = target.replace('://', '_').replace('/', '_').replace(':', '_')
        filename = f"{scanner_name}_{safe_target}_{timestamp}.native.{suffix}"
        if self.current_run_folder:
            raw_dir = get_raw_dir(self.current_run_folder)
        else:
            raw_dir = self.reports_dir.parent / 'data' if self.reports_dir.parent else Path('data')
            raw_dir.mkdir(parents=True, exist_ok=True)
        return raw_dir / filename

    def _write_native_raw_text(self, scanner_name: str, target: str, value: str, *, suffix: str) -> Path:
        output_path = self._native_artifact_path(scanner_name, target, suffix)
        output_path.write_text(value, encoding='utf-8')
        print(f"[+] Native raw output saved to: {output_path}")
        return output_path

    def _write_native_raw_json(self, scanner_name: str, target: str, value: Any) -> Path:
        output_path = self._native_artifact_path(scanner_name, target, 'json')
        with open(output_path, 'w') as f:
            json.dump(value, f, indent=2, default=str)
        print(f"[+] Native raw output saved to: {output_path}")
        return output_path

    @staticmethod
    def _copy_raw_artifact_fields(source: Dict[str, Any], destination: Dict[str, Any]) -> Dict[str, Any]:
        """Copy raw artifact metadata from a raw result onto the public result."""
        for field in (
            'raw_artifacts',
            'defectdojo_raw_artifact',
            'imported_report',
            'imported_report_path',
            'report_format',
        ):
            if source.get(field) is not None:
                destination[field] = source[field]
        return destination

    def _save_raw_xml_output(
        self,
        results: Dict[str, Any],
        json_path: Optional[Path] = None,
    ) -> Path:
        """Save one XML artifact next to the existing raw scanner artifact."""
        output_path = self._raw_xml_artifact_path(results, json_path=json_path)
        existing_artifact = results.get('defectdojo_raw_artifact')
        if isinstance(existing_artifact, dict):
            artifact_path = existing_artifact.get('path') or existing_artifact.get('raw_artifact_path')
            if artifact_path:
                try:
                    if Path(str(artifact_path)).resolve() == output_path.resolve() and output_path.exists():
                        print(f"[+] Raw XML output saved to: {output_path}")
                        return output_path
                except OSError:
                    pass
        save_xml_artifact(results, output_path)
        print(f"[+] Raw XML output saved to: {output_path}")
        return output_path

    @staticmethod
    def _raw_xml_artifact_path(
        results: Dict[str, Any],
        json_path: Optional[Path] = None,
    ) -> Path:
        """Return the XML path that matches the existing raw artifact naming."""
        raw_output_path = results.get('raw_output_path')
        if raw_output_path:
            return Path(str(raw_output_path)).with_suffix('.xml')
        if json_path is None:
            raise ValueError('json_path is required when raw_output_path is not set')
        return json_path.with_suffix('.xml')

    def _count_by_severity(self, findings: List[Dict[str, Any]]) -> Dict[str, int]:
        """Count findings by severity level.

        BUG-07 fix: findings with an unrecognised severity label are folded into
        'info' so that sum(by_severity.values()) always equals total_findings.
        """
        counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for finding in findings:
            sev = finding.get('severity', 'info')
            if sev not in counts:
                sev = 'info'
            counts[sev] += 1
        return counts

    @staticmethod
    def _scanner_enabled(options: Optional[Dict[str, Any]]) -> bool:
        """Return True when the scan config did not disable this scanner."""
        if not isinstance(options, dict):
            return True
        return bool(options.get(SCAN_CONFIG_ENABLED_KEY, True))

    @staticmethod
    def _strip_internal_option_markers(options: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Remove config-only markers before validation/execution."""
        cleaned = dict(options or {})
        cleaned.pop(SCAN_CONFIG_ENABLED_KEY, None)
        return cleaned

    def save_results(self, results: Dict[str, Any], filename: Optional[str] = None) -> Path:
        """
        Save aggregated results to normalized.json in run folder.

        The caller is responsible for setting schema_version and generated_at
        before calling this method. save_results() does NOT auto-fill any field —
        doing so would hide upstream bugs.

        Args:
            results: Fully prepared results dict (must pass 'final' stage validation)
            filename: Optional custom filename (ignored if run_folder exists)

        Returns:
            Path to saved file

        Raises:
            ValueError: If results fail final-stage validation
        """
        export_results = sanitize_results_for_export(results)

        # Defensive final-stage gate — callers should validate before this,
        # but this ensures normalized.json is NEVER written from invalid data.
        assert_valid_results(export_results, stage='final')

        if self.current_run_folder:
            output_path = get_normalized_json_path(self.current_run_folder)
        else:
            if not filename:
                timestamp = datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')
                target = export_results.get('target', 'unknown')
                safe_target = target.replace('://', '_').replace('/', '_').replace(':', '_')
                # Use normalized_* prefix (not scan_results_*) to reflect
                # that this file is final-validated output, not raw aggregation.
                filename = f"normalized_{safe_target}_{timestamp}.json"

            data_dir = self.reports_dir.parent / 'data' if self.reports_dir.parent else Path('data')
            data_dir.mkdir(parents=True, exist_ok=True)
            output_path = data_dir / filename

        with open(output_path, 'w') as f:
            json.dump(export_results, f, indent=2, default=str)

        if self.current_run_folder:
            update_latest_pointer(self.current_run_folder)

        print(f"[+] Results saved to: {output_path}")
        return output_path

def create_default_orchestrator(
    reports_dir: Optional[Path] = None,
    http2_proxy_url: Optional[str] = None,
    http2_bridge_url: Optional[str] = None,
    http2_adapter_mode: str = HTTP2_ADAPTER_MODE_AUTO,
    http_probe_timeout: int = 8,
) -> ScannerOrchestrator:
    """
    Create an orchestrator with default scanners registered.

    Args:
        reports_dir: Optional custom reports directory

    Returns:
        Configured ScannerOrchestrator instance
    """
    orchestrator = ScannerOrchestrator(
        reports_dir,
        http2_proxy_url=http2_proxy_url,
        http2_bridge_url=http2_bridge_url,
        http2_adapter_mode=http2_adapter_mode,
        http_probe_timeout=http_probe_timeout,
    )

    orchestrator.register_scanner('nmap', NmapScanner())
    orchestrator.register_scanner('nuclei', NucleiScanner())
    orchestrator.register_scanner('wapiti', WapitiScanner())
    orchestrator.register_scanner('nikto', NiktoScanner())
    orchestrator.register_scanner('zap', ZapScanner())

    return orchestrator
