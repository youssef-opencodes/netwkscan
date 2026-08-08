"""Device comparison logic: detects new, returned and disconnected devices
between a fresh scan result and what's already stored in the database.
"""
from datetime import datetime
from typing import Any

from core.database import (
    get_all_devices,
    get_device_by_ip,
    add_device,
    update_device_status,
)
from utils.logger import log_event


def analyze_scan(scan_results: list[dict[str, Any]], scan_failed: bool = False) -> dict[str, Any]:
    """Compare a scan's results against the database and update device states.

    Args:
        scan_results: list of dicts, each with at least an "ip" key, and
            optionally hostname, mac, vendor, os.
        scan_failed: If True, indicates scan execution failed. Skip marking
            devices as offline to prevent false disconnection alerts.

    Returns:
        dict with keys "new", "returned", "disconnected" -> lists of IPs,
        and "seen_ips" -> set of IPs present in this scan.
    """
    seen_ips = {entry["ip"] for entry in (scan_results or []) if isinstance(entry, dict) and "ip" in entry}
    known_devices = get_all_devices()
    known_ips = {device.ip for device in known_devices}

    new_ips: list[str] = []
    returned_ips: list[str] = []
    disconnected_ips: list[str] = []

    # If the scan failed, do NOT mark existing devices offline!
    if scan_failed:
        log_event("Scan failed flag is True; skipping disconnection processing.", "warning")
        return {
            "new": [],
            "returned": [],
            "disconnected": [],
            "seen_ips": set(),
            "scan_results": [],
            "timestamp": datetime.utcnow().isoformat(),
            "scan_failed": True,
        }

    # Devices found in this scan: either brand new, or returning/still online.
    for entry in scan_results or []:
        if not isinstance(entry, dict) or "ip" not in entry:
            continue
        ip = entry["ip"]
        existing = get_device_by_ip(ip)

        if existing is None:
            add_device(
                {
                    "ip": ip,
                    "hostname": entry.get("hostname"),
                    "mac": entry.get("mac"),
                    "vendor": entry.get("vendor"),
                    "os": entry.get("os"),
                    "device_type": entry.get("device_type") or "Unknown",
                    "ports": entry.get("ports") or {},
                    "status": "new",
                    "appearance_count": 1,
                }
            )
            new_ips.append(ip)
        else:
            was_offline = existing.status == "offline"
            update_device_status(
                ip,
                status="online",
                hostname=entry.get("hostname") or existing.hostname,
                mac=entry.get("mac") or existing.mac,
                vendor=entry.get("vendor") or existing.vendor,
                os=entry.get("os") or existing.os,
                device_type=entry.get("device_type") or existing.device_type or "Unknown",
                ports=entry.get("ports") if entry.get("ports") is not None else existing.ports,
                appearance_count=existing.appearance_count + 1,
            )
            if was_offline:
                returned_ips.append(ip)

    # Devices known before but absent from this scan -> mark offline.
    for ip in known_ips - seen_ips:
        device = get_device_by_ip(ip)
        if device is not None and device.status != "offline":
            update_device_status(ip, status="offline")
            disconnected_ips.append(ip)

    return {
        "new": new_ips,
        "returned": returned_ips,
        "disconnected": disconnected_ips,
        "seen_ips": seen_ips,
        "scan_results": scan_results,
        "timestamp": datetime.utcnow().isoformat(),
        "scan_failed": False,
    }
