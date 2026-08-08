"""
Helpers for loading local configuration from a project-root .env file.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from dotenv import load_dotenv


PROJECT_ROOT = Path(__file__).resolve().parent.parent
_LOADED_DOTENV_PATHS: set[tuple[str, bool]] = set()


def load_project_dotenv(
    project_root: Optional[Path] = None,
    *,
    override: bool = False,
    force: bool = False,
) -> Optional[Path]:
    """Load ``<project_root>/.env`` into ``os.environ`` when the file exists."""
    root = Path(project_root or PROJECT_ROOT).resolve()
    dotenv_path = root / ".env"
    if not dotenv_path.is_file():
        return None

    cache_key = (str(dotenv_path), bool(override))
    if force or cache_key not in _LOADED_DOTENV_PATHS:
        load_dotenv(dotenv_path=dotenv_path, override=override)
        _LOADED_DOTENV_PATHS.add(cache_key)

    return dotenv_path
