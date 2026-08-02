"""GUI resources package (Developer 3).

Centralized access to the dark theme defined in
``resources/styles/dark_theme.json``. Every Developer 3 widget reads its
colors, fonts and layout metrics from here instead of hard-coding values,
so Developer 4 can restyle the whole GUI from a single JSON file.
"""
import json
from pathlib import Path
from typing import Any

from utils.logger import log_event

RESOURCES_DIR = Path(__file__).resolve().parent
STYLES_DIR = RESOURCES_DIR / "styles"
ICONS_DIR = RESOURCES_DIR / "icons"
DARK_THEME_PATH = STYLES_DIR / "dark_theme.json"

# Minimal fallback used only if the JSON file is missing or corrupted,
# so the GUI degrades gracefully instead of crashing at startup.
_FALLBACK_THEME: dict[str, Any] = {
    "name": "nmd_dark_fallback",
    "appearance_mode": "dark",
    "colors": {
        "bg_primary": "#16181D",
        "bg_secondary": "#1E2128",
        "bg_tertiary": "#262A33",
        "border": "#2E333D",
        "text_primary": "#E6E8EC",
        "text_secondary": "#9BA1AC",
        "text_muted": "#71787F",
        "accent": "#3B82F6",
        "accent_hover": "#2563EB",
        "accent_text": "#BFDBFE",
        "card_bg": "#1E2128",
        "card_bg_hover": "#262A33",
        "card_border": "#2E333D",
        "button_bg": "#262A33",
        "button_hover": "#313745",
        "button_text": "#E6E8EC",
    },
    "status": {
        "online": "#22C55E",
        "offline": "#EF4444",
        "new": "#F59E0B",
        "unknown": "#71787F",
    },
    "font": {
        "family": "Segoe UI",
        "mono": "Consolas",
        "size_title": 18,
        "size_heading": 15,
        "size_body": 13,
        "size_small": 11,
        "size_metric": 26,
    },
    "layout": {
        "radius": 10,
        "card_padding": 12,
        "gap": 10,
        "sidebar_width": 190,
        "window_min_width": 1000,
        "window_min_height": 640,
        "refresh_interval_ms": 5000,
    },
}

_theme_cache: dict[str, Any] | None = None


def load_theme(path: str | Path | None = None, reload: bool = False) -> dict[str, Any]:
    """Load the dark theme JSON once and cache it."""
    global _theme_cache

    if _theme_cache is not None and not reload and path is None:
        return _theme_cache

    target = Path(path) if path else DARK_THEME_PATH
    try:
        with open(target, "r", encoding="utf-8") as handle:
            theme = json.load(handle)
    except FileNotFoundError:
        log_event(f"Theme file not found at {target}. Using fallback theme.", "warning")
        theme = _FALLBACK_THEME
    except json.JSONDecodeError as exc:
        log_event(f"Invalid JSON in theme file {target}: {exc}. Using fallback theme.", "error")
        theme = _FALLBACK_THEME

    if path is None:
        _theme_cache = theme
    return theme


def color(key: str, default: str = "#FFFFFF") -> str:
    """Return a color from the theme's ``colors`` section."""
    return load_theme().get("colors", {}).get(key, default)


def status_color(status: str | None) -> str:
    """Map a Device.status value to its theme color.

    Only 'online', 'offline' and 'new' are written by core.analyzer;
    anything else falls back to the neutral 'unknown' color.
    """
    statuses = load_theme().get("status", {})
    key = (status or "unknown").strip().lower()
    return statuses.get(key, statuses.get("unknown", "#71787F"))


def font(size_key: str = "size_body", weight: str = "normal", mono: bool = False) -> tuple:
    """Return a Tk font tuple built from the theme font section."""
    cfg = load_theme().get("font", {})
    family = cfg.get("mono" if mono else "family", "Segoe UI")
    size = cfg.get(size_key, 13)
    return (family, size, weight)


def layout(key: str, default: Any = 0) -> Any:
    """Return a value from the theme's ``layout`` section."""
    return load_theme().get("layout", {}).get(key, default)


__all__ = [
    "load_theme",
    "color",
    "status_color",
    "font",
    "layout",
    "RESOURCES_DIR",
    "STYLES_DIR",
    "ICONS_DIR",
    "DARK_THEME_PATH",
]