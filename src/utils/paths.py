"""Path resolution helper for NMD.

Provides unified resolution for project root, data files, assets, presets,
and icons, working seamlessly in standard Python development mode and
when packaged as a frozen PyInstaller binary (sys._MEIPASS).
"""

from __future__ import annotations

import os
import sys
from pathlib import Path


def get_base_dir() -> Path:
    """Return the base directory of the application.

    When running from a PyInstaller bundle, returns sys._MEIPASS.
    Otherwise, returns the project root directory.
    """
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        return Path(sys._MEIPASS)
    # src/utils/paths.py -> root is 2 levels up
    return Path(__file__).resolve().parent.parent.parent


def get_resource_path(relative_path: str) -> str:
    """Resolve a relative resource path to an absolute path.

    Args:
        relative_path: Path relative to project root (e.g. 'src/presets' or 'resources/icon.ico').

    Returns:
        Absolute filesystem path as a string.
    """
    base = get_base_dir()
    resolved = base / relative_path
    return str(resolved)


def get_app_data_dir() -> Path:
    """Return persistent user application data directory.

    In frozen/production mode, returns %APPDATA%/NMD (Windows) or ~/.nmd (Linux/macOS).
    In development mode, returns the project's 'data' directory.
    """
    if getattr(sys, "frozen", False):
        if sys.platform == "win32":
            appdata = os.environ.get("APPDATA")
            base = Path(appdata) if appdata else Path.home() / "AppData" / "Roaming"
            path = base / "NMD"
        else:
            path = Path.home() / ".nmd"
        path.mkdir(parents=True, exist_ok=True)
        return path

    path = get_base_dir() / "data"
    path.mkdir(parents=True, exist_ok=True)
    return path


def get_db_path() -> str:
    """Return absolute path to the SQLite database file."""
    return str(get_app_data_dir() / "nmd.db")


def get_logs_dir() -> str:
    """Return absolute path to the log files directory."""
    logs_path = get_app_data_dir() / "logs"
    logs_path.mkdir(parents=True, exist_ok=True)
    return str(logs_path)


def get_reports_dir() -> str:
    """Return absolute path to the reports/exports directory."""
    exports_path = get_app_data_dir() / "exports"
    exports_path.mkdir(parents=True, exist_ok=True)
    return str(exports_path)
