"""Configuration management for NMD.

Handles loading, saving, updating, and validating application configuration.
Configuration is stored in JSON format at data/config.json using pathlib.
"""
import json
from pathlib import Path
from typing import Any

from utils.logger import log_event

import socket
import subprocess
import re
from pathlib import Path
import json


def detect_router_ip() -> str:
    """Auto-detect the router/gateway IP and return as subnet."""
    try:
        # Method 1: Get default gateway via ip route
        result = subprocess.run(['ip', 'route', 'show', 'default'], 
                              capture_output=True, text=True)
        # Look for: "default via 192.168.0.1 dev wlan0"
        match = re.search(r'default via (\d+\.\d+\.\d+\.\d+)', result.stdout)
        if match:
            ip = match.group(1)
            return ip.rsplit('.', 1)[0] + '.0/24'
    except:
        pass
    
    try:
        # Method 2: Get route to 8.8.8.8 (Google DNS)
        result = subprocess.run(['ip', 'route', 'get', '8.8.8.8'], 
                              capture_output=True, text=True)
        # Look for: "8.8.8.8 via 192.168.0.1 dev wlan0"
        match = re.search(r'via (\d+\.\d+\.\d+\.\d+)', result.stdout)
        if match:
            ip = match.group(1)
            return ip.rsplit('.', 1)[0] + '.0/24'
    except:
        pass
    
    try:
        # Method 3: Use /proc/net/route (Linux)
        with open('/proc/net/route', 'r') as f:
            lines = f.readlines()
            for line in lines[1:]:  # Skip header
                parts = line.strip().split()
                if parts[1] == '00000000':  # Default route
                    # Convert hex to IP: 0101A8C0 -> 192.168.1.1
                    hex_ip = parts[2]
                    ip_parts = [str(int(hex_ip[i:i+2][::-1], 16)) for i in range(0, 8, 2)]
                    ip = '.'.join(ip_parts)
                    return ip.rsplit('.', 1)[0] + '.0/24'
    except:
        pass
    
    try:
        # Method 4: Use socket to get local IP and assume /24
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
        s.close()
        if ip and ip != '127.0.0.1':
            return ip.rsplit('.', 1)[0] + '.0/24'
    except:
        pass
    
    # Fallback: Check common subnets
    common_subnets = [
        '192.168.0.0/24',
        '192.168.1.0/24',
        '192.168.2.0/24',
        '10.0.0.0/24',
        '172.16.0.0/24'
    ]
    
    # Try to find which subnet has active devices
    for subnet in common_subnets:
        try:
            result = subprocess.run(['ping', '-c', '1', '-W', '1', subnet.replace('.0/24', '.1')], 
                                  capture_output=True, timeout=2)
            if result.returncode == 0:
                return subnet
        except:
            pass
    
    return '192.168.0.0/24'

# Resolve project root relative to this file: src/utils/config.py -> project_root
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
DEFAULT_CONFIG_PATH = PROJECT_ROOT / "data" / "config.json"

DEFAULT_CONFIG: dict[str, Any] = {
    "subnet": "192.168.1.0/24",
    "scan_interval": 60,
    "scan_type": "quick",
    "port_range": "1-1024",
    "theme": "dark",
    # Developer 2 fields
    "selected_preset": "Quick",
    "last_used_preset": "Quick",
    "custom_scan_settings": {
        "timing": "-T4",
        "verbosity": "-v",
        "min_hostgroup": 32,
        "max_hostgroup": 64,
        "host_timeout": "5m",
        "arguments": "-sV -O",
    },
    "default_scan_target": "192.168.1.0/24",
    "last_timing_template": "-T4",
    "last_port_configuration": "1-1024",
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
    if not isinstance(scan_type, str) or not scan_type.strip():
        return False, "scan_type must be a non-empty string."
    known_types = {"quick", "full", "custom", "ping", "version", "os", "intense"}
    if scan_type.lower() not in known_types and scan_type not in VALID_SCAN_TYPES:
        return False, f"scan_type must be one of standard types or valid presets, got '{scan_type}'."


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
