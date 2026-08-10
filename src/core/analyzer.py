"""Device comparison logic: detects new, returned and disconnected devices
between a fresh scan result and what's already stored in the database.
"""
import json
import os
from datetime import datetime
from typing import Any

from core.database import (
    get_all_devices,
    get_device_by_ip,
    add_device,
    update_device_status,
)
from utils.logger import log_event

# JSON output written after every analyzed scan (overwritten each time).
_SRC_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
JSON_OUTPUT_DIR = os.path.join(_SRC_DIR, "data", "json")
JSON_OUTPUT_PATH = os.path.join(JSON_OUTPUT_DIR, "output.json")


def _build_json_report(analysis: dict[str, Any]) -> dict[str, Any]:
    """Assemble the full analysis report, enriching IP lists with the
    devices' current full DB records (ports, os, vendor, status, etc.).
    """
    seen_ips = analysis.get("seen_ips") or set()
    all_ips = set(analysis.get("new", [])) | set(analysis.get("returned", [])) \
        | set(analysis.get("disconnected", [])) | set(seen_ips)

    devices: list[dict[str, Any]] = []
    for ip in sorted(all_ips):
        device = get_device_by_ip(ip)
        if device is not None:
            devices.append(device.to_dict())

    return {
        "timestamp": analysis.get("timestamp"),
        "scan_failed": analysis.get("scan_failed", False),
        "summary": {
            "new_count": len(analysis.get("new", [])),
            "returned_count": len(analysis.get("returned", [])),
            "disconnected_count": len(analysis.get("disconnected", [])),
            "total_seen": len(seen_ips),
            "total_known_devices": len(get_all_devices()),
        },
        "new_devices": analysis.get("new", []),
        "returned_devices": analysis.get("returned", []),
        "disconnected_devices": analysis.get("disconnected", []),
        "seen_ips": sorted(seen_ips),
        "raw_scan_results": analysis.get("scan_results", []),
        "devices": devices,
    }


def export_analysis_json(analysis: dict[str, Any], path: str | None = None) -> str | None:
    """Write the full scan-analysis result to src/data/json/output.json.

    Overwrites the file on every call so it always reflects the latest scan.
    Never raises: a JSON-write failure must not break the scan/analysis flow.
    """
    output_path = path or JSON_OUTPUT_PATH
    try:
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        report = _build_json_report(analysis)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False, default=str)
        log_event(f"Analysis JSON written to {output_path}", "info")
        return output_path
    except OSError as exc:
        log_event(f"Failed to write analysis JSON: {exc}", "error")
        return None

def analyze_scan(scan_results: list[dict[str, Any]], scan_failed: bool = False) -> dict[str, Any]:
    """Compare a scan's results against the database and update device states.

    Args:
        scan_results: list of dicts, each with at least an "ip" key
        scan_failed: If True, skip marking devices offline

    Returns:
        dict with new, returned, disconnected lists
    """
    seen_ips = {entry["ip"] for entry in (scan_results or []) if isinstance(entry, dict) and "ip" in entry}
    known_devices = get_all_devices()
    known_ips = {device.ip for device in known_devices}

    new_ips: list[str] = []
    returned_ips: list[str] = []
    disconnected_ips: list[str] = []

    if scan_failed or not seen_ips:
        log_event("Scan failed or empty. Skipping database updates.", "warning")
        return {
            "new": [],
            "returned": [],
            "disconnected": [],
            "seen_ips": set(),
            "scan_results": scan_results or [],
            "timestamp": datetime.utcnow().isoformat(),
            "scan_failed": True,
        }

    # DETECT if this is a single‑IP scan
    is_single_ip_scan = all("/" not in ip for ip in seen_ips) and len(seen_ips) == 1

    # Process found devices
    for entry in scan_results or []:
        if not isinstance(entry, dict) or "ip" not in entry:
            continue
        ip = entry["ip"]
        existing = get_device_by_ip(ip)

        if existing is None:
            add_device({
                "ip": ip,
                "hostname": entry.get("hostname"),
                "mac": entry.get("mac"),
                "vendor": entry.get("vendor"),
                "os": entry.get("os"),
                "device_type": entry.get("device_type") or "Unknown",
                "ports": entry.get("ports") or {},
                "status": "online",
                "appearance_count": 1,
            })
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

    #  IMPORTANT: Only mark offline if this was a FULL SUBNET scan
    if not is_single_ip_scan:
        for ip in known_ips - seen_ips:
            device = get_device_by_ip(ip)
            if device is not None and device.status != "offline":
                update_device_status(ip, status="offline")
                disconnected_ips.append(ip)
    else:
        log_event("Single‑IP scan detected. Skipping disconnection of other devices.", "info")

    result = {
        "new": new_ips,
        "returned": returned_ips,
        "disconnected": disconnected_ips,
        "seen_ips": seen_ips,
        "scan_results": scan_results,
        "timestamp": datetime.utcnow().isoformat(),
        "scan_failed": False,
    }
    export_analysis_json(result)
    return result