"""
Vulnerability Normalizer Module

Single source of truth for vulnerability name normalization, URL canonicalization,
and layered fingerprinting for accurate deduplication and comparison.
"""

import re
from typing import Any, Dict, Optional
from urllib.parse import urlparse, parse_qs, urlunparse

ABBREVIATION_MAP = {
    'xss': 'cross site scripting',
    'sqli': 'sql injection',
    'csrf': 'cross site request forgery',
    'ssrf': 'server side request forgery',
    'ssti': 'server side template injection',
    'rce': 'remote code execution',
    'lfi': 'local file inclusion',
    'rfi': 'remote file inclusion',
    'xxe': 'xml external entity',
    'idor': 'insecure direct object reference',
    'dos': 'denial of service',
    'ddos': 'distributed denial of service',
    'mitm': 'man in the middle',
    'csp': 'content security policy',
    'cors': 'cross origin resource sharing',
    'hsts': 'http strict transport security',
    'jwt': 'json web token',
    'otp': 'one time password',
    'mfa': 'multi factor authentication',
    '2fa': 'two factor authentication',
    'tls': 'transport layer security',
    'ssl': 'secure sockets layer',
    'cve': 'common vulnerabilities and exposures',
    'cwe': 'common weakness enumeration',
    'api': 'application programming interface',
}

STOP_WORDS = {
    'vulnerability', 'issue', 'bug', 'detected', 'in', 'on', 'at', 'of',
    'for', 'and', 'or', 'the', 'a', 'an', 'is', 'are', 'was', 'were',
    'be', 'been', 'being', 'have', 'has', 'had', 'do', 'does',
    'did', 'to', 'from', 'by', 'with', 'found', 'possible',
    'potential', 'may', 'might', 'could', 'should', 'via', 'using'
}

ADAPTER_LOCAL_MODES = {'bridge', 'proxy'}

_LOCAL_CONNECTIVITY_PATTERNS = (
    re.compile(
        r"\b(?:unable|failed|could not|cannot|can't)\s+to\s+connect\s+to\s+"
        r"(?:https?://)?(?:localhost|127\.0\.0\.1|\[?::1\]?)(?::\d+)?\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\bconnection\s+(?:refused|failed|reset|timed out)\b[^.]{0,120}"
        r"(?:localhost|127\.0\.0\.1|\[?::1\]?)(?::\d+)?\b",
        re.IGNORECASE,
    ),
)

_ADAPTER_IDENTITY_PATTERNS = (
    re.compile(
        r"\bserver\s+banner\s+changed\b.{0,160}\buvicorn\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\buvicorn\b.{0,160}\bserver\s+banner\s+changed\b",
        re.IGNORECASE,
    ),
)

_HEADER_CANONICALIZATION_DISQUALIFIERS = (
    "deprecated",
    "deprecation",
    "obsolete",
    "superseded",
    "replaced",
    "replacement",
    "instead",
)


def _canonical_security_header_name(name: str) -> Optional[str]:
    """Map common scanner phrasings for the same missing header issue."""
    text = name.lower().strip()
    words = re.sub(r'[^a-z0-9\s]', ' ', text.replace('-', ' ').replace('_', ' '))
    words = re.sub(r'\s+', ' ', words).strip()
    if any(marker in words for marker in _HEADER_CANONICALIZATION_DISQUALIFIERS):
        # Preserve the original wording for guidance/deprecation notices so
        # related headers do not collapse into the same "missing header" issue.
        return None
    trigger = any(
        phrase in words
        for phrase in (
            'header',
            'configuration',
            'not set',
            'missing',
            'protection',
            'suggested security',
        )
    )

    if 'frame ancestors' in words and trigger:
        return 'missing frame ancestors directive'

    if ('content security policy' in words or re.search(r'\bcsp\b', words)) and trigger:
        return 'missing content security policy header'

    if 'x content type options' in words and trigger:
        return 'missing x content type options header'

    if (
        'clickjacking' in words
        or 'x frame options' in words
    ) and trigger:
        return 'missing clickjacking protection header'

    return None

def normalize_vulnerability_name(name: str) -> str:
    """
    Normalize a vulnerability name for matching.

    Process:
    1. Lowercase and strip
    2. Remove punctuation
    3. Collapse whitespace
    4. Expand abbreviations
    5. Remove stopwords

    Args:
        name: Raw vulnerability name

    Returns:
        Normalized vulnerability name
    """
    if not name:
        return ''

    canonical_header = _canonical_security_header_name(name)
    if canonical_header:
        return canonical_header

    normalized = name.lower().strip()

    normalized = normalized.replace('-', ' ').replace('_', ' ')

    normalized = re.sub(r'[^a-z0-9\s]', ' ', normalized)

    normalized = re.sub(r'\s+', ' ', normalized)

    words = normalized.split()

    expanded_words = []
    for word in words:
        if word in ABBREVIATION_MAP:
            expanded = ABBREVIATION_MAP[word].split()
            expanded_words.extend(expanded)
        else:
            expanded_words.append(word)
    words = expanded_words

    words = [w for w in words if w not in STOP_WORDS]

    seen = set()
    unique_words = []
    for w in words:
        if w and w not in seen:
            seen.add(w)
            unique_words.append(w)

    return ' '.join(unique_words)

def parse_target(asset_id: str) -> Dict[str, Any]:
    """
    Parse asset_id (URL, IP, or hostname) into structured components.

    Args:
        asset_id: Asset identifier (URL, IP address, or hostname)

    Returns:
        Dict with: host, port, scheme, path, parameter, query
    """
    if not asset_id:
        return {
            'host': '',
            'port': None,
            'scheme': '',
            'path': '',
            'parameter': '',
            'query': {}
        }

    if '://' in asset_id:
        return _build_parsed_target(urlparse(asset_id))

    if asset_id.startswith('['):
        parsed = urlparse(f'//{asset_id}')
        if parsed.hostname:
            return _build_parsed_target(parsed)

    if ':' in asset_id and not asset_id.count(':') > 1:
        parts = asset_id.split(':')
        try:
            port = int(parts[1])
            return {
                'host': parts[0],
                'port': port,
                'scheme': '',
                'path': '',
                'parameter': '',
                'query': {}
            }
        except (ValueError, IndexError):
            pass

    return {
        'host': asset_id,
        'port': None,
        'scheme': '',
        'path': '',
        'parameter': '',
        'query': {}
    }

def normalize_web_target(target: str, default_scheme: str = 'https') -> str:
    """
    Normalize web scanner targets to a stable URL form.

    Web scanners should treat a bare hostname consistently so the same asset
    does not end up with mixed http/https identities across scanners.

    Args:
        target: URL or bare hostname/IP.
        default_scheme: Scheme to prepend when the target has none.

    Returns:
        URL string with a scheme when possible.
    """
    if not target:
        return target

    target = target.strip()
    if '://' in target:
        return target

    return f'{default_scheme}://{target}'


def _safe_parsed_port(parsed) -> Optional[int]:
    """Return a parsed URL port without raising on malformed values."""
    try:
        return parsed.port
    except ValueError:
        return None


def _build_parsed_target(parsed) -> Dict[str, Any]:
    """Convert a parsed URL object into the standard target component dict."""
    query_dict = parse_qs(parsed.query)
    parameter = list(query_dict.keys())[0] if query_dict else ''

    host = parsed.hostname or ''
    if not host and parsed.netloc and parsed.netloc.count(':') == 1:
        host = parsed.netloc.split(':')[0]

    return {
        'host': host,
        'port': _safe_parsed_port(parsed),
        'scheme': parsed.scheme,
        'path': parsed.path,
        'parameter': parameter,
        'query': query_dict
    }


def _base_target(target: str) -> str:
    """Return scheme://host[:port] for a normalized target URL."""
    parsed = urlparse(normalize_web_target(target))
    return urlunparse((parsed.scheme, parsed.netloc, '', '', '', ''))


def _default_port(scheme: str) -> Optional[int]:
    if scheme == 'https':
        return 443
    if scheme == 'http':
        return 80
    return None


def _is_loopback_host(hostname: Optional[str]) -> bool:
    if not hostname:
        return False
    host = hostname.lower()
    return host in {'localhost', '127.0.0.1', '::1'}


def is_loopback_target(target: Optional[str]) -> bool:
    """Return True when a URL/host/host:port points at a loopback host."""
    if not target:
        return False
    parsed = parse_target(str(target).strip())
    return _is_loopback_host(parsed.get('host'))


def _finding_text(finding: Dict[str, Any]) -> str:
    """Collect user-visible finding text used for execution-noise filtering."""
    meta = finding.get('meta') if isinstance(finding.get('meta'), dict) else {}
    fields = [
        finding.get('vulnerability_name'),
        finding.get('asset_id'),
        finding.get('description'),
        meta.get('uri'),
        meta.get('scanner_error'),
        meta.get('effective_target'),
    ]
    return ' '.join(str(value) for value in fields if value)


def is_adapter_local_connectivity_artifact(
    finding: Dict[str, Any],
    *,
    effective_target: Optional[str] = None,
    original_target: Optional[str] = None,
    adapter_mode: Optional[str] = None,
) -> bool:
    """
    Identify scanner-execution noise from local HTTP transport adapters.

    Local adapter endpoints are implementation detail. When a scanner reports
    "Unable to connect to 127.0.0.1:<port>" while scanning a public/original
    target through a bridge/proxy, that belongs in scanner execution metadata,
    not in the normalized vulnerability list.
    """
    meta = finding.get('meta') if isinstance(finding.get('meta'), dict) else {}
    mode = adapter_mode or meta.get('adapter_mode')
    if mode not in ADAPTER_LOCAL_MODES:
        return False

    effective = effective_target or meta.get('effective_target')
    original = original_target or meta.get('original_target') or meta.get('origin_target')

    if original and is_loopback_target(original):
        return False
    if not effective or not is_loopback_target(effective):
        return False

    text = _finding_text(finding)
    return any(pattern.search(text) for pattern in _LOCAL_CONNECTIVITY_PATTERNS)


def is_adapter_transport_artifact(
    finding: Dict[str, Any],
    *,
    effective_target: Optional[str] = None,
    original_target: Optional[str] = None,
    adapter_mode: Optional[str] = None,
) -> bool:
    """
    Identify local adapter transport artifacts that should not be final findings.

    Raw scanner evidence is still preserved by the caller. This helper only
    classifies normalized findings whose effective scan target was a loopback
    adapter for a non-loopback original target.
    """
    if is_adapter_local_connectivity_artifact(
        finding,
        effective_target=effective_target,
        original_target=original_target,
        adapter_mode=adapter_mode,
    ):
        return True

    meta = finding.get('meta') if isinstance(finding.get('meta'), dict) else {}
    mode = adapter_mode or meta.get('adapter_mode')
    if mode not in ADAPTER_LOCAL_MODES:
        return False

    effective = effective_target or meta.get('effective_target')
    original = original_target or meta.get('original_target') or meta.get('origin_target')

    if original and is_loopback_target(original):
        return False
    if not effective or not is_loopback_target(effective):
        return False

    text = _finding_text(finding)
    return any(pattern.search(text) for pattern in _ADAPTER_IDENTITY_PATTERNS)


def remap_absolute_asset_to_origin(value: str, scanned_target: str, origin_target: str) -> str:
    """
    Replace bridge-local absolute URLs with the original target identity.

    Relative paths are intentionally left untouched so each scanner can keep
    its existing target-joining behavior.
    """
    if not value or '://' not in value or not scanned_target or not origin_target:
        return value

    scanned_base = urlparse(_base_target(scanned_target))
    origin_base = urlparse(_base_target(origin_target))
    parsed_value = urlparse(value)

    value_port = _safe_parsed_port(parsed_value) or _default_port(parsed_value.scheme)
    scanned_port = _safe_parsed_port(scanned_base) or _default_port(scanned_base.scheme)
    same_scheme = parsed_value.scheme == scanned_base.scheme
    same_netloc = parsed_value.netloc == scanned_base.netloc
    same_loopback = (
        _is_loopback_host(parsed_value.hostname)
        and _is_loopback_host(scanned_base.hostname)
        and value_port == scanned_port
    )

    if not same_scheme or not (same_netloc or same_loopback):
        return value

    replaced = parsed_value._replace(
        scheme=origin_base.scheme,
        netloc=origin_base.netloc,
    )
    return urlunparse(replaced)

def canonical_path(path: str) -> str:
    """
    Normalize URL path for fingerprinting.

    - Remove trailing slashes
    - Lowercase
    - Remove duplicate slashes

    Args:
        path: URL path component

    Returns:
        Canonicalized path
    """
    if not path:
        return ''

    if len(path) > 1 and path.endswith('/'):
        path = path.rstrip('/')

    path = re.sub(r'/+', '/', path)

    path = path.lower()

    return path

def canonical_query(params) -> str:
    """
    Normalize query parameters into a sorted, stable key-only string.

    Accepts either:
    - a list of key names  (e.g. ['b', 'a'])
    - a dict keyed by param name (value is ignored)

    Args:
        params: Query param keys as list or dict

    Returns:
        Sorted, ampersand-joined param names (e.g. "a&b&page")
    """
    if not params:
        return ''

    if isinstance(params, dict):
        keys = list(params.keys())
    else:
        keys = list(params)

    return '&'.join(sorted(keys))


def _fingerprint_path(path: str) -> str:
    """
    Normalize path for fingerprint identity.

    Treat an explicit root path the same as an omitted path so
    "https://example.com" and "https://example.com/" do not split.
    """
    normalized = canonical_path(path) if path else ''
    return '' if normalized == '/' else normalized


def _fingerprint_port(port: Optional[int], scheme: str) -> Optional[int]:
    """
    Normalize port for fingerprint identity.

    For web findings with a known scheme, an explicit default port is
    equivalent to an omitted port for the same scheme. Non-default ports
    remain distinct.
    """
    if port is None:
        return None

    if scheme and port == _default_port(scheme):
        return None

    return port

def _coerce_port(value: Any) -> Optional[int]:
    """Return an integer port for fingerprinting, or None when unavailable."""
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return None


def _asset_id_has_host_port(asset_id: str) -> bool:
    """Return True when asset_id explicitly encodes a host:port target."""
    if not asset_id:
        return False
    if asset_id.startswith('['):
        return bool(parse_target(asset_id).get('port'))
    if asset_id.count(':') == 1:
        host, port = asset_id.rsplit(':', 1)
        return bool(host) and port.isdigit()
    return False


def _extract_query_keys(meta: Dict[str, Any], asset_id: str, *, prefer_asset_query: bool = False) -> str:
    """
    Derive the canonical query-key string for fp_strict.

    Precedence (first non-None wins):
    1. meta['query_keys']  — set explicitly by scanners during normalization
    2. query string parsed from asset_id
    3. empty string

    Args:
        meta:     The finding's meta dict.
        asset_id: The raw asset_id string.

    Returns:
        Sorted, ampersand-joined query key names, e.g. "a&b&page".
    """
    if prefer_asset_query and asset_id and '?' in asset_id:
        parsed = parse_target(asset_id)
        if parsed.get('query'):
            return canonical_query(parsed['query'])

    raw = meta.get('query_keys')
    if raw is not None:
        return canonical_query(raw)

    # Fall back to parsing the asset_id for a query string.
    if asset_id and '?' in asset_id:
        parsed = parse_target(asset_id)
        if parsed.get('query'):
            return canonical_query(parsed['query'])

    return ''


def create_fingerprints(finding: Dict[str, Any]) -> Dict[str, str]:
    """
    Create layered fingerprints for a finding.

    Three fingerprint levels with different precision/recall tradeoffs:

    fp_strict  — Most precise. Includes query_keys so that findings at the
                 same path but different query parameters are kept separate.
                 Use for: deduplication within a single scanner run.
                 Parts: norm_name + host + port + path + query_keys + parameter + method

    fp_general — Medium precision. Matches same vulnerability at the same
                 path regardless of query parameters or HTTP method.
                 Use for: cross-scanner deduplication (wapiti + nuclei on same path).
                 Parts: norm_name + host + path [+ port when non-default]
                        or norm_name + host + port for pathless service findings

    fp_host_only — Least precise. Matches same vulnerability on the same host
                   regardless of path or parameters.
                   Use for: comparison across scans where URL structure may shift.
                   Parts: norm_name + host

    Backward compatibility: if meta.query_keys is absent and asset_id has no
    query string, fp_strict is identical to the pre-v2.0 format.

    Args:
        finding: Vulnerability finding dict with:
            - vulnerability_name (str)
            - asset_id (str)
            - meta.host (str, optional)
            - meta.port (int|None, optional)
            - meta.path (str, optional)
            - meta.query_keys (list[str], optional) — preferred over re-parsing
            - meta.parameter (str, optional)
            - meta.method (str, optional)

    Returns:
        Dict with fp_strict, fp_general, fp_host_only
    """
    vuln_name = finding.get('vulnerability_name', '')
    norm_name = normalize_vulnerability_name(vuln_name)

    meta = finding.get('meta', {})
    if not isinstance(meta, dict):
        meta = {}
    asset_id = str(finding.get('asset_id', '') or '')
    parsed_asset = parse_target(asset_id)
    asset_has_scheme = '://' in asset_id
    asset_has_host_port = _asset_id_has_host_port(asset_id)
    asset_has_authority = asset_has_scheme or asset_has_host_port
    asset_has_path = asset_has_scheme and bool(parsed_asset.get('path'))
    asset_has_query = asset_has_scheme and bool(parsed_asset.get('query'))

    # Fingerprints use one deterministic source of truth per structural
    # component: canonical asset_id values win when they are encoded there;
    # scanner metadata is a fallback and remains preserved separately in meta.
    host      = parsed_asset['host'] if asset_has_authority and parsed_asset.get('host') else meta.get('host', '')
    scheme    = parsed_asset['scheme'] if asset_has_scheme else meta.get('scheme', '')
    if asset_has_scheme:
        port = parsed_asset['port']
        if port is None:
            port = _default_port(scheme)
    elif asset_has_host_port:
        port = parsed_asset['port']
    else:
        port = _coerce_port(meta.get('port'))
    path      = parsed_asset['path'] if asset_has_path else meta.get('path', '')
    # Only use parameter when explicitly set by the scanner in meta.
    # Never auto-derive it from URL parsing: the first query key in a URL is
    # order-dependent, which would produce different fp_strict values for
    # "?b=1&a=2" vs "?a=3&b=9" even though the canonical query key set is
    # identical. URL query keys are already captured stably via query_keys_str.
    parameter = meta.get('parameter', '')
    method    = meta.get('method', '')

    # If structural fields are missing, fall back to parsing asset_id.
    # This preserves backward compatibility with old findings that lack meta fields.
    if not host:
        parsed = parsed_asset
        host      = parsed['host']
        port      = port if port is not None else parsed['port']
        path      = path or parsed['path']
        scheme    = scheme or parsed['scheme']
        # NOTE: deliberately *not* falling back to parsed['parameter'] here;
        # see comment above on why auto-deriving parameter is unsafe.
    elif not scheme and '://' in asset_id:
        scheme = parse_target(asset_id)['scheme']

    # Normalize all components to stable, case-insensitive strings.
    host      = host.lower()   if host      else ''
    scheme    = scheme.lower() if scheme    else ''
    path      = _fingerprint_path(path)
    port      = _fingerprint_port(port, scheme)
    parameter = parameter.lower()           if parameter else ''
    method    = method.upper()              if method    else ''
    port_str  = str(port) if port is not None else ''

    # query_keys: sorted param names, independent of value or declaration order.
    # e.g. "?b=1&a=2" and "?a=3&b=9" both produce "a&b"
    query_keys_str = _extract_query_keys(meta, asset_id, prefer_asset_query=asset_has_query)

    # fp_strict: maximum specificity.
    fp_strict_parts = [norm_name, host, port_str, path, query_keys_str, parameter, method]
    fp_strict = '::'.join(p for p in fp_strict_parts if p)

    # fp_general: path-level match for web findings, preserving a normalized
    # non-default port so distinct service instances do not collapse together.
    fp_general_parts = [norm_name, host]
    if path:
        fp_general_parts.append(path)
        if port_str:
            fp_general_parts.append(port_str)
    elif port_str:
        fp_general_parts.append(port_str)
    fp_general = '::'.join(p for p in fp_general_parts if p)

    # fp_host_only: host-level match — used by comparator for change tracking.
    fp_host_only_parts = [norm_name, host]
    fp_host_only = '::'.join(p for p in fp_host_only_parts if p)

    return {
        'fp_strict':    fp_strict,
        'fp_general':   fp_general,
        'fp_host_only': fp_host_only,
    }

def upgrade_schema(scan_results: Dict[str, Any]) -> Dict[str, Any]:
    """
    Upgrade old scan results to current schema version.

    Best-effort parsing of asset_id into structured fields for old reports
    that don't have meta.host, meta.port, etc.

    Deliberately does NOT backfill meta.parameter.  The parameter field
    represents the specific request parameter that was flagged by the scanner,
    which cannot be reliably inferred from a URL.  parse_target() would return
    the first query-key it encounters, which may not be the tested parameter
    and would corrupt fp_strict fingerprints for legacy findings.

    Args:
        scan_results: Scan results dict (may be old version)

    Returns:
        Upgraded scan results with schema_version field
    """
    current_version = "2.0"

    if scan_results.get('schema_version') == current_version:
        return scan_results

    scan_results['schema_version'] = current_version

    findings = scan_results.get('all_findings', [])
    for finding in findings:
        asset_id = finding.get('asset_id', '')
        if not asset_id:
            continue

        meta = finding.get('meta', {})
        parsed = parse_target(asset_id)

        # Fill each missing structured field independently.
        # Never overwrite an existing explicit value set by the scanner.
        # The old code skipped the whole finding when meta.host was present,
        # leaving scheme/port/path/query_keys unfilled for partially-enriched findings.
        if not meta.get('host'):
            meta['host'] = parsed['host']
        if not meta.get('scheme'):
            meta['scheme'] = parsed['scheme']
        if meta.get('port') is None and parsed['port'] is not None:
            meta['port'] = parsed['port']
        if not meta.get('path'):
            meta['path'] = parsed['path']
        if 'query_keys' not in meta:
            query = parsed.get('query', {})
            meta['query_keys'] = sorted(query.keys()) if query else []
        # NOTE: meta.parameter is intentionally NOT backfilled from parsed URL.
        # See docstring for rationale.

        finding['meta'] = meta

    return scan_results
