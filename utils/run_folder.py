"""
Run Folder Management

Utilities for creating and managing organized scan run folders.
Structure: reports/<target_slug>/<timestamp>/
"""

import re
from datetime import datetime
from pathlib import Path
from typing import Optional, List

def create_target_slug(target: str) -> str:
    """
    Convert target (URL, IP, hostname) to filesystem-safe slug.

    Examples:
        https://example.com:8080/path -> example_com_8080
        192.168.1.1 -> 192_168_1_1
        example.com -> example_com

    Args:
        target: Target URL, IP, or hostname

    Returns:
        Filesystem-safe slug
    """
    slug = re.sub(r'^https?://', '', target)

    slug = slug.split('/')[0].split('?')[0]

    slug = re.sub(r'[.:\-\[\]]', '_', slug)

    slug = re.sub(r'[^a-zA-Z0-9_]', '', slug)

    slug = re.sub(r'_+', '_', slug)

    slug = slug.strip('_')

    slug = slug.lower()

    if not slug:
        slug = 'unknown_target'

    return slug

def format_timestamp(dt: datetime) -> str:
    """
    Format datetime as filesystem-safe timestamp.

    Format: YYYYMMDD_HHMMSS

    Args:
        dt: Datetime object

    Returns:
        Formatted timestamp string
    """
    return dt.strftime('%Y%m%d_%H%M%S')

def parse_timestamp(timestamp_str: str) -> Optional[datetime]:
    """
    Parse timestamp string back to datetime.

    Args:
        timestamp_str: Timestamp in YYYYMMDD_HHMMSS format

    Returns:
        Datetime object or None if parsing fails
    """
    try:
        return datetime.strptime(timestamp_str, '%Y%m%d_%H%M%S')
    except ValueError:
        return None

def create_run_folder(base_dir: Path, target: str, timestamp: Optional[datetime] = None) -> Path:
    """
    Create run folder structure for a scan.

    Structure:
        base_dir/
        └── <target_slug>/
            └── <timestamp>/
                └── raw/

    Args:
        base_dir: Base reports directory
        target: Target being scanned
        timestamp: Scan timestamp (default: now)

    Returns:
        Path to the created run folder
    """
    if timestamp is None:
        from datetime import datetime, timezone
        timestamp = datetime.now(timezone.utc)

    target_slug = create_target_slug(target)

    timestamp_str = format_timestamp(timestamp)

    run_folder = base_dir / target_slug / timestamp_str

    run_folder.mkdir(parents=True, exist_ok=True)
    (run_folder / 'raw').mkdir(exist_ok=True)

    return run_folder

def list_target_runs(base_dir: Path, target: str) -> List[Path]:
    """
    List all run folders for a target, sorted by timestamp (newest first).

    Args:
        base_dir: Base reports directory
        target: Target

    Returns:
        List of run folder paths, sorted newest first
    """
    target_slug = create_target_slug(target)
    target_dir = base_dir / target_slug

    if not target_dir.exists():
        return []

    runs = []
    for item in target_dir.iterdir():
        if item.is_dir():
            timestamp = parse_timestamp(item.name)
            if timestamp:
                runs.append((timestamp, item))

    runs.sort(key=lambda x: x[0], reverse=True)

    return [path for _, path in runs]

def get_latest_run(base_dir: Path, target: str, exclude_current: Optional[str] = None) -> Optional[Path]:
    """
    Get the most recent run folder for a target.

    Args:
        base_dir: Base reports directory
        target: Target
        exclude_current: Timestamp string to exclude (current run)

    Returns:
        Path to latest run folder, or None if no previous runs
    """
    runs = list_target_runs(base_dir, target)

    if exclude_current:
        runs = [r for r in runs if r.name != exclude_current]

    if runs:
        return runs[0]

    return None

def get_raw_dir(run_folder: Path) -> Path:
    """Get path to raw/ subdirectory in a run folder."""
    return run_folder / 'raw'

def get_scan_results_json_path(run_folder: Path) -> Path:
    """Get path to scan_results.json (raw aggregation) in a run folder."""
    return run_folder / 'scan_results.json'

def get_normalized_json_path(run_folder: Path) -> Path:
    """Get path to normalized.json in a run folder."""
    return run_folder / 'normalized.json'

def update_latest_pointer(run_folder: Path) -> None:
    """
    Create or update 'latest' pointer to most recent run folder.

    Uses symlink on Unix/Linux/Mac, falls back to folder copy on Windows
    or systems without symlink support.

    Args:
        run_folder: Path to the current run folder
    """
    import shutil

    target_dir = run_folder.parent
    latest_path = target_dir / 'latest'

    try:
        if latest_path.is_symlink():
            latest_path.unlink()
        elif latest_path.exists():
            if latest_path.is_dir():
                shutil.rmtree(latest_path)
            else:
                latest_path.unlink()

        latest_path.symlink_to(run_folder.name, target_is_directory=True)

    except (OSError, NotImplementedError,AttributeError):
        try:
            if latest_path.exists():
                shutil.rmtree(latest_path)
            shutil.copytree(run_folder, latest_path)
        except Exception as e:
            pass
