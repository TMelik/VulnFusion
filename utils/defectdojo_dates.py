"""
Date helpers for DefectDojo import metadata.
"""

from __future__ import annotations

import re
from datetime import date, datetime
from typing import Any


_DATE_RE = re.compile(r"\d{4}-\d{2}-\d{2}")


def normalize_defectdojo_scan_date(value: Any) -> str | None:
    """Return a DefectDojo-compatible scan_date, or raise on invalid input."""
    if value is None:
        return None

    if isinstance(value, datetime):
        return value.date().isoformat()

    if isinstance(value, date):
        return value.isoformat()

    text = str(value).strip()
    if not text:
        return None

    if _DATE_RE.fullmatch(text):
        try:
            return date.fromisoformat(text).isoformat()
        except ValueError as exc:
            raise ValueError(_scan_date_error(text)) from exc

    iso_text = text[:-1] + "+00:00" if text.endswith("Z") else text
    try:
        return datetime.fromisoformat(iso_text).date().isoformat()
    except ValueError as exc:
        raise ValueError(_scan_date_error(text)) from exc


def _scan_date_error(value: str) -> str:
    return (
        "DefectDojo scan_date must be YYYY-MM-DD or a valid ISO datetime; "
        f"got {value!r}."
    )
