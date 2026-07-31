"""Configuration management for NMD.

Handles loading, saving, updating, and validating application configuration.
Configuration is stored in JSON format at data/config.json using pathlib.
"""
import json
from pathlib import Path
from typing import Any

from utils.logger import log_event

# Resolve project root relative to this file: src/utils/config.py -> project_root
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
DEFAULT_CONFIG_PATH = PROJECT_ROOT / "data" / "config.json"

DEFAULT_CONFIG: dict[str, Any] = {
    "subnet": "192.168.1.0/24",
    "scan_interval": 60,
    "scan_type": "quick",
    "port_range": "1-1024",
    "theme": "dark",
}

VALID_SCAN_TYPES = {"quick", "full", "custom"}


def get_default_config() -> dict[str, Any]:
    """Return a fresh copy of the default configuration dictionary."""
    return DEFAULT_CONFIG.copy()


def validate_config(config: dict[str, Any]) -> tuple[bool, str]:
    """Validate configuration keys and values.

    Args:
        config: Configuration dictionary to validate.

    Returns:
        (is_valid, error_message)
    """
    if not isinstance(config, dict):
        return False, "Configuration must be a dictionary."

    # Validate subnet
    subnet = config.get("subnet")
    if not isinstance(subnet, str) or not subnet.strip():
        return False, "Subnet must be a non-empty string."

    # Validate scan_interval
    interval = config.get("scan_interval")
    if not isinstance(interval, (int, float)) or isinstance(interval, bool) or interval <= 0:
        return False, "scan_interval must be a positive number."

    # Validate scan_type
    scan_type = config.get("scan_type")
    if scan_type not in VALID_SCAN_TYPES:
        return False, f"scan_type must be one of {sorted(VALID_SCAN_TYPES)}."

    # Validate port_range
    port_range = config.get("port_range")
    if not isinstance(port_range, str) or not port_range.strip():
        return False, "port_range must be a non-empty string."

    return True, ""


def load_config(path: str | Path | None = None) -> dict[str, Any]:
    """Load configuration from file.

    If file does not exist, creates it with defaults.
    If file contains invalid JSON or fails validation, logs an error and
    falls back to default configuration.
    """
    target_path = Path(path) if path else DEFAULT_CONFIG_PATH

    if not target_path.exists():
        log_event(f"Config file not found at {target_path}. Creating default configuration.", "info")
        default_cfg = get_default_config()
        save_config(default_cfg, target_path)
        return default_cfg

    try:
        with open(target_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as exc:
        log_event(f"Invalid JSON in config file {target_path}: {exc}. Falling back to default configuration.", "error")
        return get_default_config()
    except Exception as exc:
        log_event(f"Error reading config file {target_path}: {exc}. Falling back to default configuration.", "error")
        return get_default_config()

    is_valid, err_msg = validate_config(data)
    if not is_valid:
        log_event(f"Invalid configuration in {target_path}: {err_msg}. Falling back to default configuration.", "error")
        return get_default_config()

    return data


def save_config(config: dict[str, Any], path: str | Path | None = None) -> bool:
    """Save configuration dictionary to JSON file after validation."""
    target_path = Path(path) if path else DEFAULT_CONFIG_PATH

    is_valid, err_msg = validate_config(config)
    if not is_valid:
        log_event(f"Cannot save invalid configuration: {err_msg}", "error")
        return False

    try:
        target_path.parent.mkdir(parents=True, exist_ok=True)
        with open(target_path, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=4)
        log_event(f"Configuration successfully saved to {target_path}.", "info")
        return True
    except Exception as exc:
        log_event(f"Failed to save configuration to {target_path}: {exc}", "error")
        return False


def update_config(path: str | Path | None = None, **kwargs: Any) -> dict[str, Any]:
    """Update specific configuration fields and save the result."""
    current_config = load_config(path)
    current_config.update(kwargs)

    is_valid, err_msg = validate_config(current_config)
    if not is_valid:
        log_event(f"Configuration update rejected: {err_msg}", "error")
        return load_config(path)

    save_config(current_config, path)
    return current_config
