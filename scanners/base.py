"""
Base Scanner Interface

Defines the abstract base class that all scanner implementations must inherit from.
This ensures a consistent interface across nmap, nuclei, and future scanner integrations.
"""

from abc import ABC, abstractmethod
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

class BaseScanner(ABC):
    """Abstract base class for all vulnerability scanners."""

    def __init__(self, name: str):
        """
        Initialize the scanner.

        Args:
            name: Unique identifier for this scanner (e.g., 'nmap', 'nuclei')
        """
        self.name = name
        self.last_scan_time: Optional[datetime] = None
        self.scanner_type = 'generic'
        self.supports_http2_direct = False
        self.supports_http1_force = False
        self.supports_proxy = False
        self.supports_http2_bridge = False

    @abstractmethod
    def scan(self, target: str, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Execute a scan against the target.

        Args:
            target: The target to scan (IP, hostname, or URL)
            options: Optional scanner-specific options

        Returns:
            Dict containing raw scan results with at least:
                - 'scanner': str - name of the scanner
                - 'target': str - target that was scanned
                - 'timestamp': str - ISO8601 timestamp
                - 'raw_output': Any - raw scanner output
                - 'findings': List[Dict] - list of raw findings
        """
        pass

    @abstractmethod
    def normalize(self, raw_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Convert raw scan results to the unified schema format.

        Args:
            raw_results: Raw results from the scan() method

        Returns:
            List of findings in unified schema format:
                - vulnerability_name: str
                - severity: str (critical|high|medium|low|info)
                - asset_id: str
                - description: str
                - remediation: str
                - meta: Dict with scanner info
        """
        pass

    def is_available(self) -> bool:
        """
        Check if the scanner tool is available on the system.

        Returns:
            True if the scanner is installed and accessible
        """
        return True

    def get_version(self) -> Optional[str]:
        """
        Get the version of the scanner tool.

        Returns:
            Version string or None if not available
        """
        return None

    def get_capabilities(self) -> Dict[str, Any]:
        """
        Return scanner execution capabilities used by the orchestrator.
        """
        return {
            'scanner_type': self.scanner_type,
            'supports_http2_direct': self.supports_http2_direct,
            'supports_http1_force': self.supports_http1_force,
            'supports_proxy': self.supports_proxy,
            'supports_http2_bridge': self.supports_http2_bridge,
        }

    def get_proxy_options(self, proxy_url: str) -> Dict[str, Any]:
        """
        Return scanner-specific options for an upstream proxy.
        """
        return {}

    def get_transport_option_keys(self) -> set[str]:
        """
        Return transport-affecting option keys reserved for the orchestrator.

        These options can influence whether a scan runs direct or through a
        compatibility layer, so the orchestrator strips user-supplied values
        before execution and only reinjects the route it selected.
        """
        keys: set[str] = set()
        if self.supports_proxy:
            keys.add('proxy_url')
        return keys

    def get_default_options(self) -> Dict[str, Any]:
        """
        Return scanner defaults used for config resolution and reporting.

        Scanners may also read these defaults at runtime. Execution can still
        adjust values later, and the saved effective config reflects only
        defaults + config + CLI.
        """
        return {}

    def get_supported_options(self) -> set[str]:
        """
        Return the scanner-specific user option keys accepted by validate_options().
        """
        return set(self.get_default_options().keys())

    def get_path_option_keys(self) -> set[str]:
        """
        Return option keys that should resolve relative paths against the config file.
        """
        return set()

    def uses_offline_input(self, options: Optional[Dict[str, Any]] = None) -> bool:
        """Return True when this invocation consumes an artifact without contacting the target."""
        return False

    def validate_options(self, options: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Validate and normalize user-supplied scanner options.

        Scanners should override this when they expose structured options or
        passthrough args. The default implementation only rejects unknown keys.
        """
        normalized = dict(options or {})
        supported = set(self.get_supported_options())
        if not supported:
            return normalized

        unknown = sorted(key for key in normalized if key not in supported)
        if unknown:
            supported_text = ", ".join(sorted(supported))
            unknown_text = ", ".join(unknown)
            raise ValueError(
                f"{self.name} does not support option(s): {unknown_text}. "
                f"Supported options: {supported_text}"
            )
        return normalized

    def assess_execution(self, raw_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Inspect raw scanner output for degraded/partial execution signals.

        Scanners can override this to flag soft-failure cases where the tool
        technically exits but the run is not trustworthy enough to present as a
        clean zero-finding success.
        """
        return {}

    def _validate_bool_option(self, options: Dict[str, Any], key: str) -> None:
        """Validate one boolean option in-place."""
        if key not in options:
            return
        value = options[key]
        if not isinstance(value, bool):
            raise ValueError(f"{self.name} option '{key}' must be a boolean")

    def _validate_string_option(self, options: Dict[str, Any], key: str) -> None:
        """Validate one non-empty string option in-place."""
        if key not in options:
            return
        value = options[key]
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{self.name} option '{key}' must be a non-empty string")
        options[key] = value.strip()

    def _validate_int_option(
        self,
        options: Dict[str, Any],
        key: str,
        *,
        minimum: Optional[int] = None,
        maximum: Optional[int] = None,
    ) -> None:
        """Validate one integer option in-place."""
        if key not in options:
            return
        value = options[key]
        if not isinstance(value, int) or isinstance(value, bool):
            raise ValueError(f"{self.name} option '{key}' must be an integer")
        if minimum is not None and value < minimum:
            raise ValueError(f"{self.name} option '{key}' must be >= {minimum}")
        if maximum is not None and value > maximum:
            raise ValueError(f"{self.name} option '{key}' must be <= {maximum}")

    def _validate_string_list_option(
        self,
        options: Dict[str, Any],
        key: str,
        *,
        allow_empty: bool = False,
    ) -> None:
        """Validate one list[str] option in-place."""
        if key not in options:
            return
        value = options[key]
        if not isinstance(value, list):
            raise ValueError(f"{self.name} option '{key}' must be a list of strings")

        normalized: List[str] = []
        for item in value:
            if not isinstance(item, str) or not item.strip():
                raise ValueError(f"{self.name} option '{key}' must contain only non-empty strings")
            normalized.append(item.strip())

        if not normalized and not allow_empty:
            raise ValueError(f"{self.name} option '{key}' cannot be empty")
        options[key] = normalized

    def _normalize_path_option(self, options: Dict[str, Any], key: str) -> None:
        """Expand, validate, and normalize one file path option in-place."""
        if key not in options:
            return
        value = options[key]
        if not isinstance(value, (str, Path)):
            raise ValueError(f"{self.name} option '{key}' must be a file path")
        path = Path(str(value)).expanduser()
        if not path.exists():
            raise ValueError(f"{self.name} option '{key}' does not exist: {path}")
        if not path.is_file():
            raise ValueError(f"{self.name} option '{key}' must point to a regular file: {path}")
        options[key] = str(path.resolve())

    def _normalize_extra_args(
        self,
        options: Dict[str, Any],
        *,
        aliases: Iterable[str] = ("extra_args", "args"),
        forbidden_flags: Iterable[str] = (),
    ) -> None:
        """
        Normalize safe passthrough args onto the internal ``args`` option key.

        Raw shell strings are rejected on purpose. The caller must provide a
        list so downstream code never needs to parse arbitrary command text.
        """
        present = [key for key in aliases if key in options]
        if not present:
            return
        if len(present) > 1:
            joined = ", ".join(present)
            raise ValueError(f"{self.name} options cannot define both {joined}; use one passthrough list")

        source_key = present[0]
        value = options.pop(source_key)
        if isinstance(value, str):
            raise ValueError(
                f"{self.name} option '{source_key}' must be a list of args, not a raw command string"
            )
        if not isinstance(value, list):
            raise ValueError(f"{self.name} option '{source_key}' must be a list of strings")

        forbidden = set(forbidden_flags)
        normalized: List[str] = []
        for item in value:
            if not isinstance(item, str) or not item.strip():
                raise ValueError(f"{self.name} option '{source_key}' must contain only non-empty strings")
            token = item.strip()
            if "\n" in token or "\r" in token:
                raise ValueError(f"{self.name} option '{source_key}' cannot contain newline characters")
            flag = token.split("=", 1)[0]
            if flag in forbidden:
                raise ValueError(
                    f"{self.name} passthrough args cannot override reserved/internal flag '{flag}'"
                )
            normalized.append(token)

        options["args"] = normalized
