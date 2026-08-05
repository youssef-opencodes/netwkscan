"""Scan preset management: load, save, and delete Nmap presets. NEW (plan2)."""
import json
import os

PRESETS_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_PATH = os.path.join(PRESETS_DIR, "default.json")
CUSTOM_PATH = os.path.join(PRESETS_DIR, "custom_presets.json")


def _load_json(path: str) -> dict:
    if not os.path.exists(path):
        return {}
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _save_json(path: str, data: dict) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def load_presets() -> dict:
    """Return all presets: built-in defaults merged with user-defined custom presets."""
    presets = _load_json(DEFAULT_PATH)
    presets.update(_load_json(CUSTOM_PATH))
    return presets


def get_preset(name: str) -> dict | None:
    """Fetch a single preset by name (default or custom)."""
    return load_presets().get(name)


def save_preset(name: str, args: str, ports: str = "", description: str = "") -> dict:
    """Save (or overwrite) a user-defined preset in custom_presets.json."""
    custom = _load_json(CUSTOM_PATH)
    custom[name] = {"args": args, "ports": ports, "description": description}
    _save_json(CUSTOM_PATH, custom)
    return custom[name]


def delete_preset(name: str) -> bool:
    """Delete a user-defined preset. Built-in defaults cannot be deleted."""
    custom = _load_json(CUSTOM_PATH)
    if name not in custom:
        return False
    del custom[name]
    _save_json(CUSTOM_PATH, custom)
    return True
