"""
Target probing helpers for web scans.

The probe logic here focuses on two separate concerns:

1. Reachable scheme selection for bare targets:
   - try ``https://`` first
   - fall back to ``http://`` only when HTTPS could not be confirmed
2. Honest HTTPS transport detection:
   - probe whether the server accepts HTTP/2
   - probe whether the server accepts HTTP/1.1

The result is structured so the orchestrator can make scanner-specific routing
decisions without conflating URL scheme with HTTP protocol version.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

try:
    import httpx
except ImportError:  # pragma: no cover - requirements install httpx[http2]
    httpx = None  # type: ignore[assignment]

from utils.normalizer import normalize_web_target


HTTP_MODE_AUTO = "auto"
HTTP_MODE_HTTP1 = "http1"
HTTP_MODE_HTTP2 = "http2"
PROBE_METHOD_PYTHON_HTTPX = "python-httpx"
REQUESTED_MODE_HTTP2 = "http2"
REQUESTED_MODE_HTTP1_1 = "http1_1"

SUPPORTED_HTTP_MODES = {
    HTTP_MODE_AUTO,
    HTTP_MODE_HTTP1,
    HTTP_MODE_HTTP2,
}


def _empty_probe(target: str, normalized_target: Optional[str] = None) -> Dict[str, Any]:
    """Return a stable empty/default probe payload."""
    normalized = normalized_target if normalized_target is not None else target.strip()
    return {
        "input_target": target,
        "normalized_target": normalized,
        "selected_scheme": "",
        "reachable": None,
        "supports_http2": None,
        "supports_http1_1": None,
        "http2_only": None,
        "transport_detected": "unknown",
        "detected_http_version": "unknown",
        "probe_method": "unavailable",
        "reason": "",
        "attempts": [],
    }


def _target_has_explicit_scheme(target: str) -> bool:
    return "://" in target.strip()


def _format_probe_exception(exc: Exception) -> str:
    """Return a short exception summary suitable for probe diagnostics."""
    message = str(exc).strip()
    if message:
        return f"{type(exc).__name__}: {message}"
    return type(exc).__name__


def _python_probe_http_mode(url: str, *, http2: bool, timeout: int) -> Dict[str, Any]:
    """
    Probe a URL using Python/httpx and return the negotiated HTTP version.

    Any HTTP response counts as reachable. Supported transport modes are
    determined later by checking the negotiated version exactly.
    """
    if httpx is None:
        return {
            "reachable": False,
            "negotiated_http_version": "",
            "status_code": None,
            "error": "ImportError: httpx is not installed",
        }

    try:
        with httpx.Client(
            http2=http2,
            verify=False,
            timeout=timeout,
            follow_redirects=False,
        ) as client:
            response = client.get(url)
    except Exception as exc:
        return {
            "reachable": False,
            "negotiated_http_version": "",
            "status_code": None,
            "error": _format_probe_exception(exc),
        }

    return {
        "reachable": True,
        "negotiated_http_version": str(response.http_version or ""),
        "status_code": response.status_code,
        "error": "",
    }


def _requested_http_version(requested_mode: str) -> str:
    if requested_mode == REQUESTED_MODE_HTTP2:
        return "HTTP/2"
    return "HTTP/1.1"


def _probe_supports_requested_mode(probe: Dict[str, Any], requested_mode: str) -> bool:
    """Return True only when a probe negotiated the exact requested version."""
    if not probe.get("reachable"):
        return False

    negotiated = str(probe.get("negotiated_http_version") or "").strip().upper()
    return negotiated == _requested_http_version(requested_mode).upper()


def _build_probe_attempt(
    *,
    url: str,
    scheme: str,
    requested_mode: str,
    probe: Dict[str, Any],
) -> Dict[str, Any]:
    """Convert one low-level probe result into a stable diagnostics payload."""
    return {
        "url": url,
        "scheme": scheme,
        "requested_mode": requested_mode,
        "requested_http_version": _requested_http_version(requested_mode),
        "reachable": bool(probe.get("reachable")),
        "negotiated_http_version": str(probe.get("negotiated_http_version") or ""),
        "status_code": probe.get("status_code"),
        "error": str(probe.get("error") or ""),
    }


def _compose_probe_failure_reason(base_reason: str, probe_attempts: List[Dict[str, Any]]) -> str:
    """Append concise python-httpx diagnostics to a generic probe failure reason."""
    details: List[str] = []
    for attempt in probe_attempts:
        requested_mode = str(attempt.get("requested_mode") or "")
        wants_http2 = requested_mode == REQUESTED_MODE_HTTP2
        requested_version = str(attempt.get("requested_http_version") or "").strip()
        error = str(attempt.get("error") or "").strip()
        if error:
            details.append(f"python-httpx http2={wants_http2} failed: {error}")
            continue

        negotiated = str(attempt.get("negotiated_http_version") or "").strip()
        if attempt.get("reachable") and negotiated and negotiated != requested_version:
            status_code = attempt.get("status_code")
            status_text = f" (status {status_code})" if status_code is not None else ""
            details.append(
                "python-httpx http2="
                f"{wants_http2} negotiated {negotiated} instead of {requested_version}{status_text}"
            )

    if not details:
        return base_reason
    return f"{base_reason} {'; '.join(details)}"


def _probe_candidate_url(url: str, timeout: int) -> Dict[str, Any]:
    """Probe one candidate URL and summarize its reachable transport options."""
    parsed = urlparse(url)
    scheme = parsed.scheme

    attempt: Dict[str, Any] = {
        "url": url,
        "scheme": scheme,
        "reachable": False,
        "supports_http2": False,
        "supports_http1_1": False,
        "http2_only": False,
        "transport_detected": "unknown",
        "detected_http_version": "unknown",
        "reason": "",
        "attempts": [],
    }

    if scheme == "https":
        http2_probe = _python_probe_http_mode(url, http2=True, timeout=timeout)
        http1_probe = _python_probe_http_mode(url, http2=False, timeout=timeout)
        probe_attempts = [
            _build_probe_attempt(
                url=url,
                scheme=scheme,
                requested_mode=REQUESTED_MODE_HTTP2,
                probe=http2_probe,
            ),
            _build_probe_attempt(
                url=url,
                scheme=scheme,
                requested_mode=REQUESTED_MODE_HTTP1_1,
                probe=http1_probe,
            ),
        ]
        supports_http2 = _probe_supports_requested_mode(http2_probe, REQUESTED_MODE_HTTP2)
        supports_http1_1 = _probe_supports_requested_mode(http1_probe, REQUESTED_MODE_HTTP1_1)
        attempt["supports_http2"] = supports_http2
        attempt["supports_http1_1"] = supports_http1_1
        attempt["http2_only"] = supports_http2 and not supports_http1_1
        attempt["reachable"] = bool(http2_probe.get("reachable") or http1_probe.get("reachable"))
        attempt["attempts"] = probe_attempts

        if supports_http2 and supports_http1_1:
            attempt["transport_detected"] = "http2_and_http1"
            attempt["detected_http_version"] = "HTTP/1.1"
            attempt["reason"] = (
                "HTTPS probe confirmed both HTTP/2 and HTTP/1.1. "
                "Automatic routing prefers HTTP/1.1 when both are available."
            )
        elif supports_http2:
            attempt["transport_detected"] = "http2_only"
            attempt["detected_http_version"] = "HTTP/2"
            attempt["reason"] = "HTTPS probe confirmed HTTP/2, but not HTTP/1.1."
        elif supports_http1_1:
            attempt["transport_detected"] = "http1_only"
            attempt["detected_http_version"] = "HTTP/1.1"
            attempt["reason"] = "HTTPS probe confirmed HTTP/1.1, but not HTTP/2."
        elif attempt["reachable"]:
            attempt["reason"] = _compose_probe_failure_reason(
                "HTTPS probe reached the target, but separate python-httpx requests did not confirm either HTTP/2 or HTTP/1.1.",
                probe_attempts,
            )
        else:
            attempt["reason"] = _compose_probe_failure_reason(
                "HTTPS probe did not confirm reachability.",
                probe_attempts,
            )

        return attempt

    if scheme == "http":
        http1_probe = _python_probe_http_mode(url, http2=False, timeout=timeout)
        probe_attempts = [
            _build_probe_attempt(
                url=url,
                scheme=scheme,
                requested_mode=REQUESTED_MODE_HTTP1_1,
                probe=http1_probe,
            )
        ]
        supports_http1_1 = _probe_supports_requested_mode(http1_probe, REQUESTED_MODE_HTTP1_1)
        attempt["supports_http1_1"] = supports_http1_1
        attempt["reachable"] = bool(http1_probe.get("reachable"))
        attempt["attempts"] = probe_attempts

        if supports_http1_1:
            attempt["transport_detected"] = "http1_only"
            attempt["detected_http_version"] = "HTTP/1.1"
            attempt["reason"] = "HTTP probe confirmed HTTP/1.1."
        elif attempt["reachable"]:
            attempt["reason"] = _compose_probe_failure_reason(
                "HTTP probe reached the target, but the python-httpx request did not confirm HTTP/1.1.",
                probe_attempts,
            )
        else:
            attempt["reason"] = _compose_probe_failure_reason(
                "HTTP probe did not confirm reachability.",
                probe_attempts,
            )

        return attempt

    attempt["reason"] = f"Scheme '{scheme}' is not supported by the web target probe."
    return attempt


def probe_web_target(target: str, timeout: int = 8) -> Dict[str, Any]:
    """
    Probe a web target and return structured scheme/transport metadata.

    Bare targets are tried as HTTPS first and then HTTP. Explicit ``http://``
    and ``https://`` inputs are respected.
    """
    stripped_target = target.strip()
    explicit_scheme = _target_has_explicit_scheme(stripped_target)
    candidates: List[str]

    if explicit_scheme:
        parsed = urlparse(stripped_target)
        if parsed.scheme not in ("http", "https"):
            probe = _empty_probe(target, normalized_target=stripped_target)
            probe["selected_scheme"] = parsed.scheme
            probe["probe_method"] = "unsupported_scheme"
            probe["reachable"] = False
            probe["reason"] = f"Unsupported scheme '{parsed.scheme}'. Only http:// and https:// can be probed."
            return probe
        candidates = [stripped_target]
    else:
        candidates = [
            normalize_web_target(stripped_target, default_scheme="https"),
            normalize_web_target(stripped_target, default_scheme="http"),
        ]

    if httpx is None:
        fallback_target = candidates[0]
        parsed = urlparse(fallback_target)
        probe = _empty_probe(target, normalized_target=fallback_target)
        probe["selected_scheme"] = parsed.scheme
        probe["probe_method"] = "unavailable"
        probe["reachable"] = False
        probe["supports_http2"] = False
        probe["supports_http1_1"] = False
        probe["http2_only"] = False
        probe["reason"] = (
            "python-httpx is not available, so scheme and HTTP version probing was skipped. "
            f"Falling back to {fallback_target}."
        )
        return probe

    candidate_attempts: List[Dict[str, Any]] = []
    attempts: List[Dict[str, Any]] = []
    selected_attempt: Optional[Dict[str, Any]] = None

    for candidate in candidates:
        attempt = _probe_candidate_url(candidate, timeout)
        candidate_attempts.append(attempt)
        attempts.extend(attempt.get("attempts") or [])
        if attempt["reachable"]:
            selected_attempt = attempt
            break

    if selected_attempt is None:
        fallback_target = candidates[0]
        parsed = urlparse(fallback_target)
        probe = _empty_probe(target, normalized_target=fallback_target)
        probe["selected_scheme"] = parsed.scheme
        probe["probe_method"] = PROBE_METHOD_PYTHON_HTTPX
        probe["reachable"] = False
        probe["supports_http2"] = False
        probe["supports_http1_1"] = False
        probe["http2_only"] = False
        probe["attempts"] = attempts
        reasons = [str(attempt.get("reason") or "").strip() for attempt in candidate_attempts if attempt.get("reason")]
        probe["reason"] = " ".join(reasons) if reasons else "No probe attempts were executed."
        return probe

    selected_parsed = urlparse(selected_attempt["url"])
    probe = {
        "input_target": target,
        "normalized_target": selected_attempt["url"],
        "selected_scheme": selected_parsed.scheme,
        "reachable": selected_attempt["reachable"],
        "supports_http2": selected_attempt["supports_http2"],
        "supports_http1_1": selected_attempt["supports_http1_1"],
        "http2_only": selected_attempt["http2_only"],
        "transport_detected": selected_attempt["transport_detected"],
        "detected_http_version": selected_attempt["detected_http_version"],
        "probe_method": PROBE_METHOD_PYTHON_HTTPX,
        "reason": selected_attempt["reason"],
        "attempts": attempts,
    }

    if not explicit_scheme and selected_parsed.scheme == "http" and len(candidate_attempts) > 1:
        probe["reason"] = (
            "HTTPS probe failed, so the target fell back to HTTP. "
            f"{selected_attempt['reason']}"
        )

    return probe
