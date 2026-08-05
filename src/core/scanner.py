"""Nmap results parsing (Dev 1 scope, plan2).

NOTE: This file historically belongs to Dev 2 (custom_scan(), run_scan(), the
actual subprocess/python-nmap execution). I don't have your current
scanner.py content, so only the two functions below are provided as a
drop-in addition — merge them into your existing file rather than
overwriting it.
"""
from __future__ import annotations


def parse_nmap_results(nm, host: str) -> dict:
    """Extract open ports/services for one host from a python-nmap PortScanner result.

    Args:
        nm: an nmap.PortScanner instance after nm.scan(...) has run.
        host: the IP address to extract results for.

    Returns:
        dict mapping port (str) -> service name, e.g. {"22": "ssh", "80": "http"}.
        Only ports in the "open" state are included.
    """
    ports: dict[str, str] = {}
    if host not in nm.all_hosts():
        return ports

    for proto in nm[host].all_protocols():
        for port in sorted(nm[host][proto].keys()):
            port_info = nm[host][proto][port]
            if port_info.get("state") == "open":
                ports[str(port)] = port_info.get("name") or "unknown"
    return ports


def guess_device_type(ports: dict, os_name: str | None = None) -> str:
    """Rough heuristic to classify a device from its open ports / OS fingerprint.

    Returns one of: "Router", "Phone", "PC", "Server", "Unknown".
    """
    os_name = (os_name or "").lower()
    port_set = set(ports.keys())

    if "router" in os_name or "gateway" in os_name or ({"53", "67"} & port_set and "80" in port_set):
        return "Router"
    if "android" in os_name or "ios" in os_name or "iphone" in os_name:
        return "Phone"
    if port_set & {"3389", "445", "139"} or "windows" in os_name:
        return "PC"
    if (port_set & {"22", "3306", "5432", "8080"}) and ("linux" in os_name or "server" in os_name):
        return "Server"
    return "Unknown"
