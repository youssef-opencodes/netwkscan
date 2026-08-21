"""Configuration management for NMD.

Handles loading, saving, updating, and validating application configuration.
Configuration is stored in JSON format at data/config.json using pathlib.
"""
from __future__ import annotations

import ipaddress
import json
import platform
import re
import socket
import subprocess
from pathlib import Path
from typing import Any

from utils.logger import log_event



import subprocess
import re
import socket

def detect_gateway() -> str:
    """Auto-detect the default gateway IP and return as subnet.

    Delegates to detect_router_ip(), which correctly checks the Windows
    'ipconfig' Default Gateway first (avoiding false positives from VPNs
    or virtual adapters like VirtualBox/Hyper-V that can hijack the
    socket-based route-to-8.8.8.8 trick).
    """
    return detect_router_ip()

def detect_router_ip() -> str:
    """Auto-detect the router/gateway IP and return as /24 subnet string."""
    system_name = platform.system()

    # Method 1: Windows ipconfig / route print parsing
    if system_name == "Windows":
        try:
            output = subprocess.check_output("ipconfig", text=True, errors="ignore")
            gateways = re.findall(r"Default Gateway[.\s]*:\s*(\d+\.\d+\.\d+\.\d+)", output)
            for gw in gateways:
                if gw and gw != "0.0.0.0":
                    parts = gw.split(".")
                    return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        except Exception:
            pass

    # Method 2: Linux ip route show default
    else:
        try:
            result = subprocess.run(['ip', 'route', 'show', 'default'], capture_output=True, text=True)
            match = re.search(r'default via (\d+\.\d+\.\d+\.\d+)', result.stdout)
            if match:
                ip = match.group(1)
                parts = ip.split(".")
                return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        except Exception:
            pass

    # Method 3: Cross-platform UDP socket connection to 8.8.8.8
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        local_ip = s.getsockname()[0]
        s.close()
        if local_ip and local_ip != '127.0.0.1':
            parts = local_ip.split(".")
            return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    except Exception:
        pass

    return '192.168.1.0/24'


# Resolve project root relative to this file: src/utils/config.py -> project_root
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
DEFAULT_CONFIG_PATH = PROJECT_ROOT / "data" / "config.json"

DEFAULT_CONFIG: dict[str, Any] = {
    "subnet": "192.168.1.0/24",
    "scan_interval": 60,
    "scan_type": "quick",
    "port_range": "1-1024",
    "theme": "dark",
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
    "vulnerability_scan_enabled": True,
    "vulnerability_scripts": "vuln",
    "vulnerability_timeout": 300,
    "vulnerability_report_directory": "data/reports",
    "last_vulnerability_target": "192.168.1.0/24",
}

VALID_SCAN_TYPES = {"quick", "full", "custom", "vulnerability"}


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

    # Validate CIDR/IP syntax if subnet provided
    try:
        ipaddress.ip_network(subnet.strip(), strict=False)
    except ValueError:
        try:
            ipaddress.ip_address(subnet.strip())
        except ValueError:
            return False, f"Subnet '{subnet}' is not a valid IP or CIDR network."

    # Validate scan_interval
    interval = config.get("scan_interval")
    if not isinstance(interval, (int, float)) or isinstance(interval, bool) or interval <= 0:
        return False, "scan_interval must be a positive number."

    # Validate scan_type
    scan_type = config.get("scan_type")
    if not isinstance(scan_type, str) or not scan_type.strip():
        return False, "scan_type must be a non-empty string."

    known_types = {"quick", "full", "custom", "ping", "version", "os", "intense", "vulnerability"}
    if scan_type.lower() not in known_types and scan_type not in VALID_SCAN_TYPES:
        return False, f"scan_type must be one of standard types or valid presets, got '{scan_type}'."


    # Validate port_range
    port_range = config.get("port_range")
    if not isinstance(port_range, str) or not port_range.strip():
        return False, "port_range must be a non-empty string."

    return True, ""


def load_config(path: str | Path | None = None) -> dict[str, Any]:
    """Load configuration, auto-detecting subnet if needed."""
    target_path = Path(path) if path else DEFAULT_CONFIG_PATH
    
    # Ensure directory exists
    target_path.parent.mkdir(parents=True, exist_ok=True)
    
    # If config doesn't exist, create with auto-detected subnet
    if not target_path.exists():
        detected = detect_gateway()
        log_event(f"Auto-detected subnet: {detected}", "info")
        config = get_default_config()
        config["subnet"] = detected
        save_config(config, target_path)
        return config
    
    # Load existing config
    try:
        with open(target_path, 'r') as f:
            config = json.load(f)
    except:
        config = get_default_config()
    
    # Auto-detect and update if subnet is default or old
    detected = detect_gateway()
    current_subnet = config.get("subnet", "")
    
    # If subnet doesn't match detected, update it
    if current_subnet != detected and detected != "192.168.1.0/24":
        log_event(f"Subnet changed from {current_subnet} to {detected}", "info")
        config["subnet"] = detected
        save_config(config, target_path)
    
    return config


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
