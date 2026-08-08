"""
XML artifact helpers for raw scanner result persistence.

These helpers preserve native XML when a scanner already exposes it and fall
back to a structured XML rendering of the raw result payload otherwise.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from io import BytesIO
from pathlib import Path
from typing import Any, Dict

_NATIVE_XML_FIELDS = ("raw_output", "xml_output", "raw_xml", "xml")
_INVALID_XML_NAME_CHARS = re.compile(r"[^A-Za-z0-9_.-]+")


def save_xml_artifact(result: Dict[str, Any], output_path: Path) -> Path:
    """
    Persist one XML artifact for a scanner result.

    Preference order:
    1. Reuse an existing native XML report file when ``raw_output_path`` points
       to one.
    2. Preserve native XML text already present in the result payload.
    3. Generate a structured XML rendering of the full result object.
    """
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    raw_output_path = result.get("raw_output_path")
    if raw_output_path:
        source_path = Path(str(raw_output_path))
        if source_path.suffix.lower() == ".xml" and source_path.exists():
            try:
                if source_path.resolve() != output_path.resolve():
                    output_path.write_bytes(source_path.read_bytes())
                return output_path
            except OSError:
                pass

    native_xml = extract_native_xml_text(result)
    if native_xml is not None:
        output_path.write_text(native_xml, encoding="utf-8")
        return output_path

    output_path.write_text(render_xml_document(result), encoding="utf-8")
    return output_path


def extract_native_xml_text(result: Dict[str, Any]) -> str | None:
    """Return native XML text from a scanner result when available."""
    for field in _NATIVE_XML_FIELDS:
        xml_text = _coerce_native_xml_text(result.get(field))
        if xml_text is not None:
            return xml_text
    return None


def render_xml_document(value: Any, root_tag: str = "scanner_result") -> str:
    """Render *value* into a valid UTF-8 XML document."""
    root = ET.Element(_sanitize_xml_tag(root_tag, default="scanner_result"))
    _append_xml_value(root, value)

    tree = ET.ElementTree(root)
    ET.indent(tree, space="  ")
    buffer = BytesIO()
    tree.write(buffer, encoding="utf-8", xml_declaration=True)
    return buffer.getvalue().decode("utf-8")


def _append_xml_value(element: ET.Element, value: Any) -> None:
    """Populate *element* with XML content representing *value*."""
    if isinstance(value, dict):
        for key, child_value in value.items():
            raw_name = str(key)
            tag_name = _sanitize_xml_tag(raw_name)
            child = ET.SubElement(element, tag_name)
            if tag_name != raw_name:
                child.set("name", raw_name)
            _append_xml_value(child, child_value)
        return

    if isinstance(value, (list, tuple)):
        element.set("type", "array")
        for item in value:
            child = ET.SubElement(element, "item")
            _append_xml_value(child, item)
        return

    if value is None:
        element.set("type", "null")
        return

    if isinstance(value, bool):
        element.set("type", "boolean")
        element.text = "true" if value else "false"
        return

    if isinstance(value, (int, float)) and not isinstance(value, bool):
        element.set("type", "number")
        element.text = str(value)
        return

    element.text = str(value)


def _coerce_native_xml_text(value: Any) -> str | None:
    """Return XML text when *value* is already valid XML."""
    if isinstance(value, bytes):
        text = value.decode("utf-8", errors="replace")
    elif isinstance(value, str):
        text = value
    else:
        return None

    stripped = text.lstrip("\ufeff\r\n\t ")
    if not stripped.startswith("<"):
        return None

    try:
        ET.fromstring(stripped)
    except ET.ParseError:
        return None
    return text


def _sanitize_xml_tag(name: str, default: str = "field") -> str:
    """Convert arbitrary keys into stable XML-safe tag names."""
    cleaned = _INVALID_XML_NAME_CHARS.sub("_", str(name).strip())
    if not cleaned:
        return default
    if not re.match(r"^[A-Za-z_]", cleaned):
        cleaned = f"{default}_{cleaned}"
    if cleaned.lower().startswith("xml"):
        cleaned = f"{default}_{cleaned}"
    return cleaned
