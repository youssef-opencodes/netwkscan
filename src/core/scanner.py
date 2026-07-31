"""Nmap network scanner module for NMD.

Provides the Scanner class to execute network scans (quick, full, custom)
using python-nmap and normalizes host discovery results.
Does NOT write directly to the database.
"""
import time
from typing import Any

import nmap

from utils.logger import log_event


class Scanner:
    """Nmap PortScanner wrapper for network device discovery."""

    def __init__(self) -> None:
        self.last_duration: float = 0.0

    def _is_nmap_available(self) -> bool:
        """Check if Nmap binary is accessible on the system."""
        try:
            nmap.PortScanner()
            return True
        except (nmap.PortScannerError, FileNotFoundError):
            return False
        except Exception:
            return False

    def parse_nmap_results(self, nm: nmap.PortScanner) -> list[dict[str, Any]]:
        """Parse raw nmap.PortScanner output into normalized dict format.

        Returns list of dicts:
            [
                {
                    "ip": "...",
                    "hostname": "...",
                    "mac": "...",
                    "vendor": "...",
                    "os": "..."
                }
            ]
        """
        results: list[dict[str, Any]] = []

        if not hasattr(nm, "all_hosts"):
            return results

        try:
            hosts = nm.all_hosts()
        except Exception as exc:
            log_event(f"Error fetching hosts from Nmap output: {exc}", "error")
            return results

        for host in hosts:
            try:
                host_data = nm[host]
            except Exception:
                continue

            # Parse IP
            ip = host
            addresses = host_data.get("addresses", {})
            if isinstance(addresses, dict) and "ipv4" in addresses:
                ip = addresses["ipv4"]

            # Parse Hostname
            hostname = ""
            hostnames = host_data.get("hostnames", [])
            if isinstance(hostnames, list) and len(hostnames) > 0 and isinstance(hostnames[0], dict):
                hostname = hostnames[0].get("name", "")
            if not hostname and hasattr(nm[host], "hostname"):
                try:
                    hostname = nm[host].hostname() or ""
                except Exception:
                    hostname = ""

            # Parse MAC and Vendor
            mac = ""
            if isinstance(addresses, dict):
                mac = addresses.get("mac", "") or ""

            vendor = ""
            vendor_dict = host_data.get("vendor", {})
            if isinstance(vendor_dict, dict) and mac:
                vendor = vendor_dict.get(mac, "") or ""
            elif isinstance(vendor_dict, dict) and vendor_dict:
                # Fallback to first vendor entry if any
                vendor = next(iter(vendor_dict.values()), "") or ""

            # Parse OS details
            os_name = ""
            osmatch = host_data.get("osmatch", [])
            if isinstance(osmatch, list) and len(osmatch) > 0 and isinstance(osmatch[0], dict):
                os_name = osmatch[0].get("name", "") or ""

            results.append(
                {
                    "ip": ip,
                    "hostname": hostname,
                    "mac": mac,
                    "vendor": vendor,
                    "os": os_name,
                }
            )

        return results

    def custom_scan(
        self,
        target: str,
        ports: str | None = None,
        arguments: str = "-sn",
    ) -> tuple[list[dict[str, Any]], float]:
        """Execute a custom Nmap scan with configurable arguments and ports.

        Args:
            target: IP or CIDR range (e.g. '192.168.1.0/24').
            ports: Port specification string (e.g. '1-1024', '80,443', or None).
            arguments: Nmap flag string (e.g. '-sn', '-sV', '-O', '-A').

        Returns:
            Tuple of (normalized results list, scan duration in seconds).
        """
        if not target or not isinstance(target, str) or not target.strip():
            log_event("Scanner received invalid empty target.", "error")
            self.last_duration = 0.0
            return [], 0.0

        start_time = time.time()
        log_event(f"Starting custom scan on target '{target}' (args: '{arguments}', ports: '{ports}')", "info")

        try:
            nm = nmap.PortScanner()
            nm.scan(hosts=target.strip(), ports=ports, arguments=arguments)
            results = self.parse_nmap_results(nm)
        except nmap.PortScannerError as exc:
            log_event(f"Nmap execution error during scan: {exc}", "error")
            results = []
        except FileNotFoundError as exc:
            log_event(f"Nmap binary not found on system: {exc}", "error")
            results = []
        except Exception as exc:
            log_event(f"Unexpected error during Nmap scan: {exc}", "error")
            results = []

        duration = round(time.time() - start_time, 2)
        self.last_duration = duration
        log_event(f"Scan on '{target}' completed in {duration}s. Found {len(results)} host(s).", "info")

        return results, duration

    def quick_scan(self, target: str) -> tuple[list[dict[str, Any]], float]:
        """Execute a quick host discovery ping scan (-sn)."""
        return self.custom_scan(target=target, ports=None, arguments="-sn")

    def full_scan(self, target: str, port_range: str = "1-1024") -> tuple[list[dict[str, Any]], float]:
        """Execute a full scan with service version and OS detection (-sV -O)."""
        return self.custom_scan(target=target, ports=port_range, arguments="-sV -O")
