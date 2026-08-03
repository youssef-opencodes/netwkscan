"""Resources package for GUI (Developer 3/4).

Exports theme colors, fonts, layout constants, and status colors.
"""

import json
import os
from typing import Any, Dict, Tuple

# Path to dark theme JSON
THEME_PATH = os.path.join(os.path.dirname(__file__), "styles", "dark_theme.json")

# Cache for theme data
_theme_cache: Dict[str, Any] = {}


def load_theme() -> Dict[str, Any]:
    """Load and cache the dark theme configuration."""
    if _theme_cache:
        return _theme_cache

    try:
        with open(THEME_PATH, "r", encoding="utf-8") as f:
            theme = json.load(f)
        _theme_cache.update(theme)
        return _theme_cache
    except (FileNotFoundError, json.JSONDecodeError):
        # Fallback defaults if theme file is missing
        _theme_cache.update({
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
                "button_text": "#E6E8EC"
            },
            "status": {
                "online": "#22C55E",
                "offline": "#EF4444",
                "new": "#F59E0B",
                "unknown": "#71787F"
            },
            "font": {
                "family": "Segoe UI",
                "mono": "Consolas",
                "size_title": 18,
                "size_heading": 15,
                "size_body": 13,
                "size_small": 11,
                "size_metric": 26
            },
            "layout": {
                "radius": 10,
                "card_padding": 12,
                "gap": 10,
                "sidebar_width": 190,
                "window_min_width": 1000,
                "window_min_height": 640,
                "refresh_interval_ms": 5000
            }
        })
        return _theme_cache


def color(key: str) -> str:
    """Get a color hex value from the theme."""
    theme = load_theme()
    colors = theme.get("colors", {})
    return colors.get(key, "#FFFFFF")


def status_color(status: str) -> str:
    """Get the hex color for a device status."""
    theme = load_theme()
    statuses = theme.get("status", {})
    return statuses.get(status.lower(), statuses.get("unknown", "#71787F"))


def font(
    size_key: str,
    weight: str = "normal",
    mono: bool = False
) -> Tuple[str, int, str]:
    """Get a font tuple (family, size, weight) for CustomTkinter."""
    theme = load_theme()
    fonts = theme.get("font", {})
    family = fonts.get("mono" if mono else "family", "Segoe UI")
    size = fonts.get(size_key, 13)

    # Map weight to CustomTkinter format
    if weight == "bold":
        weight_str = "bold"
    else:
        weight_str = "normal"

    return (family, size, weight_str)


def layout(key: str, default: Any = None) -> Any:
    """Get a layout value from the theme."""
    theme = load_theme()
    layouts = theme.get("layout", {})
    return layouts.get(key, default)


def get_theme() -> Dict[str, Any]:
    """Return the complete theme dictionary."""
    return load_theme()