"""Secret redaction for LLM payloads and externally visible results.

The sanitizer is deliberately dependency-free and conservative.  It redacts
values only when their surrounding key/header identifies them as sensitive, or
when the value has a strong token signature (for example a JWT or known API-key
prefix).  The input is never mutated.
"""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any, Callable, Dict, Match


_PLACEHOLDER_PREFIX = "[REDACTED:"

_SENSITIVE_KEY_TYPES = {
    "authorization": "AUTHORIZATION",
    "proxyauthorization": "AUTHORIZATION",
    "cookie": "COOKIE",
    "setcookie": "COOKIE",
    "jwt": "JWT",
    "idtoken": "JWT",
    "apikey": "API_KEY",
    "xapikey": "API_KEY",
    "subscriptionkey": "API_KEY",
    "clientsecret": "API_KEY",
    "password": "PASSWORD",
    "passwd": "PASSWORD",
    "pwd": "PASSWORD",
    "accesstoken": "TOKEN",
    "refreshtoken": "TOKEN",
    "authtoken": "TOKEN",
    "bearertoken": "TOKEN",
    "session": "SESSION",
    "sessionid": "SESSION",
    "phpsessid": "SESSION",
    "jsessionid": "SESSION",
}

_HEADER_PATTERNS = (
    (
        re.compile(r"(?im)^(?P<prefix>\s*(?:proxy-)?authorization\s*:\s*)(?!\[REDACTED:)[^\r\n]+"),
        "AUTHORIZATION",
    ),
    (
        re.compile(r"(?im)^(?P<prefix>\s*(?:set-)?cookie\s*:\s*)(?!\[REDACTED:)[^\r\n]+"),
        "COOKIE",
    ),
    (
        re.compile(r"(?im)^(?P<prefix>\s*x-api-key\s*:\s*)(?!\[REDACTED:)[^\r\n]+"),
        "API_KEY",
    ),
)

_JWT_PATTERN = re.compile(
    r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}(?![A-Za-z0-9_-])"
)
_BEARER_PATTERN = re.compile(
    r"(?i)\bBearer\s+(?!\[REDACTED:)[A-Za-z0-9._~+/=-]{8,}"
)
_API_KEY_PATTERN = re.compile(
    r"(?<![A-Za-z0-9])(?:sk-[A-Za-z0-9_-]{12,}|gsk_[A-Za-z0-9_-]{12,}|ghp_[A-Za-z0-9]{12,}|github_pat_[A-Za-z0-9_]{12,}|hf_[A-Za-z0-9]{12,}|xox[bp]-[A-Za-z0-9-]{12,}|ya29\.[A-Za-z0-9_-]{12,})(?![A-Za-z0-9])",
    re.IGNORECASE,
)
_URL_CREDENTIAL_PATTERN = re.compile(
    r"(?P<scheme>https?://)(?P<username>[^\s/:@]+):(?P<password>(?!\[REDACTED:)[^\s/@]+)@",
    re.IGNORECASE,
)
_SENSITIVE_NAME_PATTERN = (
    r"api[_-]?key|x-api-key|client[_-]?secret|password|passwd|pwd|"
    r"access[_-]?token|refresh[_-]?token|auth[_-]?token|session[_-]?id|"
    r"sessionid|phpsessid|jsessionid"
)
_NAMED_QUOTED_VALUE_PATTERN = re.compile(
    rf"(?i)(?P<prefix>[\"']?(?P<name>{_SENSITIVE_NAME_PATTERN})[\"']?\s*[:=]\s*)"
    rf"(?P<quote>[\"'])(?!\[REDACTED:)(?P<value>.*?)(?P=quote)"
)
_NAMED_UNQUOTED_VALUE_PATTERN = re.compile(
    rf"(?i)(?P<prefix>[\"']?(?P<name>{_SENSITIVE_NAME_PATTERN})[\"']?\s*[:=]\s*)"
    rf"(?![\"']|\[REDACTED:)(?P<value>[^\s&,;\"'}}\]]+)"
)


@dataclass(frozen=True)
class SecretSanitizationResult:
    """A sanitized copy plus non-sensitive redaction diagnostics."""

    value: Any
    redactions_by_type: Dict[str, int]

    @property
    def total_redactions(self) -> int:
        """Return the total number of replacements."""
        return sum(self.redactions_by_type.values())


class _RedactionCounter:
    def __init__(self) -> None:
        self.values: Dict[str, int] = {}

    def add(self, secret_type: str, count: int = 1) -> None:
        if count > 0:
            self.values[secret_type] = self.values.get(secret_type, 0) + count


def _placeholder(secret_type: str) -> str:
    return f"[REDACTED:{secret_type}]"


def _normalized_key(value: Any) -> str:
    return re.sub(r"[^a-z0-9]", "", str(value or "").lower())


def _replace_pattern(
    text: str,
    pattern: re.Pattern[str],
    secret_type: str,
    counter: _RedactionCounter,
    replacement: str | Callable[[Match[str]], str] | None = None,
) -> str:
    def replace(match: Match[str]) -> str:
        counter.add(secret_type)
        if callable(replacement):
            return replacement(match)
        return replacement if isinstance(replacement, str) else _placeholder(secret_type)

    return pattern.sub(replace, text)


def _sanitize_text(text: str, counter: _RedactionCounter) -> str:
    if not text or _PLACEHOLDER_PREFIX in text and text.startswith(_PLACEHOLDER_PREFIX) and text.endswith("]"):
        return text

    cleaned = text
    for pattern, secret_type in _HEADER_PATTERNS:
        cleaned = _replace_pattern(
            cleaned,
            pattern,
            secret_type,
            counter,
            lambda match, kind=secret_type: f"{match.group('prefix')}{_placeholder(kind)}",
        )

    cleaned = _replace_pattern(
        cleaned,
        _URL_CREDENTIAL_PATTERN,
        "PASSWORD",
        counter,
        lambda match: (
            f"{match.group('scheme')}{match.group('username')}:"
            f"{_placeholder('PASSWORD')}@"
        ),
    )
    cleaned = _replace_pattern(cleaned, _JWT_PATTERN, "JWT", counter)
    cleaned = _replace_pattern(
        cleaned,
        _BEARER_PATTERN,
        "AUTHORIZATION",
        counter,
        f"Bearer {_placeholder('AUTHORIZATION')}",
    )
    cleaned = _replace_pattern(cleaned, _API_KEY_PATTERN, "API_KEY", counter)

    def replace_quoted_named(match: Match[str]) -> str:
        secret_type = _SENSITIVE_KEY_TYPES.get(_normalized_key(match.group("name")), "TOKEN")
        counter.add(secret_type)
        quote = match.group("quote")
        return f"{match.group('prefix')}{quote}{_placeholder(secret_type)}{quote}"

    cleaned = _NAMED_QUOTED_VALUE_PATTERN.sub(replace_quoted_named, cleaned)

    def replace_unquoted_named(match: Match[str]) -> str:
        secret_type = _SENSITIVE_KEY_TYPES.get(_normalized_key(match.group("name")), "TOKEN")
        counter.add(secret_type)
        return f"{match.group('prefix')}{_placeholder(secret_type)}"

    return _NAMED_UNQUOTED_VALUE_PATTERN.sub(replace_unquoted_named, cleaned)


def _sanitize_value(value: Any, counter: _RedactionCounter, *, key_hint: Any = None) -> Any:
    secret_type = _SENSITIVE_KEY_TYPES.get(_normalized_key(key_hint))
    if secret_type and value is not None:
        if isinstance(value, str) and value.startswith(_PLACEHOLDER_PREFIX) and value.endswith("]"):
            return value
        counter.add(secret_type)
        return _placeholder(secret_type)

    if isinstance(value, str):
        return _sanitize_text(value, counter)
    if isinstance(value, dict):
        return {
            key: _sanitize_value(item, counter, key_hint=key)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_sanitize_value(item, counter) for item in value]
    if isinstance(value, tuple):
        return tuple(_sanitize_value(item, counter) for item in value)
    if isinstance(value, set):
        return {_sanitize_value(item, counter) for item in value}
    return value


def sanitize_secrets(value: Any) -> SecretSanitizationResult:
    """Return a recursively sanitized copy of ``value`` and safe counters."""
    counter = _RedactionCounter()
    cleaned = _sanitize_value(value, counter)
    return SecretSanitizationResult(
        value=cleaned,
        redactions_by_type=dict(sorted(counter.values.items())),
    )
