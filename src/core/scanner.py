"""Nmap results parsing and scanning engine (Dev 1 & Dev 2).

Provides custom scan configuration, dynamic Nmap command generation,
device classification, open port parsing, and exception handling.
"""
from __future__ import annotations

from typing import Any, Tuple
import time

import nmap

from utils.logger import log_event


def parse_nmap_results(nm: nmap.PortScanner, host: str) -> dict[str, str]:
    """Extract open ports/services for one host from a python-nmap PortScanner result.

    Args:
        nm: an nmap.PortScanner instance after nm.scan(...) has run.
        host: the IP address to extract results for.

    Returns:
        dict mapping port (str) -> service name, e.g. {"22": "ssh", "80": "http"}.
        Only ports in the "open" state are included.
    """
    ports: dict[str, str] = {}
    if not hasattr(nm, "all_hosts") or host not in nm.all_hosts():
        return ports

    try:
        host_obj = nm[host]
        if hasattr(host_obj, "all_protocols"):
            protocols = host_obj.all_protocols()
        elif isinstance(host_obj, dict):
            protocols = [p for p in host_obj.keys() if p in ("tcp", "udp", "sctp", "ip")]
        else:
            protocols = []

        for proto in protocols:
            proto_ports = host_obj.get(proto, {}) if isinstance(host_obj, dict) else host_obj[proto]
            if isinstance(proto_ports, dict):
                for port in sorted(proto_ports.keys()):
                    port_info = proto_ports[port]
                    if isinstance(port_info, dict) and port_info.get("state") == "open":
                        ports[str(port)] = port_info.get("name") or "unknown"
    except Exception:
        pass

    return ports



def guess_device_type(ports: dict[str, str], os_name: str | None = None) -> str:
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


class Scanner:
    """Nmap scanning engine supporting customizable scans, timing, verbosity, and ports."""

    def __init__(self) -> None:
        self.last_duration: float = 0.0
        self._last_command: str = ""

    @property
    def last_command(self) -> str:
        """Return the exact string of the last constructed Nmap command."""
        return self._last_command

    def build_nmap_command(
        self,
        target: str,
        ports: str | None = None,
        arguments: str | None = None,
        timing: str | int | None = None,
        host_timeout: str | None = None,
        verbosity: str | int | None = None,
        min_hostgroup: int | str | None = None,
        max_hostgroup: int | str | None = None,
    ) -> str:
        """Dynamically build the final Nmap CLI command string according to parameters."""
        cmd_parts = ["nmap"]

        # 1. Base custom arguments or flags
        if arguments and arguments.strip():
            cmd_parts.append(arguments.strip())

        # 2. Timing template (-T0..-T5)
        if timing is not None:
            t_str = str(timing).strip()
            if not t_str.startswith("-T"):
                if t_str.isdigit():
                    t_str = f"-T{t_str}"
                elif t_str.startswith("T"):
                    t_str = f"-{t_str}"
            if t_str in {"-T0", "-T1", "-T2", "-T3", "-T4", "-T5"}:
                if not any(f in cmd_parts for f in ["-T0", "-T1", "-T2", "-T3", "-T4", "-T5"]):
                    cmd_parts.append(t_str)

        # 3. Verbosity (-v, -vv)
        if verbosity is not None:
            v_str = str(verbosity).strip()
            if v_str == "1" or v_str == "-v":
                if "-v" not in cmd_parts:
                    cmd_parts.append("-v")
            elif v_str == "2" or v_str == "-vv":
                if "-vv" not in cmd_parts:
                    cmd_parts.append("-vv")

        # 4. Host timeout (--host-timeout)
        if host_timeout and str(host_timeout).strip():
            ht = str(host_timeout).strip()
            cmd_parts.extend(["--host-timeout", ht])

        # 5. Parallelism (--min-hostgroup, --max-hostgroup)
        if min_hostgroup is not None:
            cmd_parts.extend(["--min-hostgroup", str(min_hostgroup)])
        if max_hostgroup is not None:
            cmd_parts.extend(["--max-hostgroup", str(max_hostgroup)])

        # 6. Ports specification (-p)
        if ports and str(ports).strip():
            p_str = str(ports).strip()
            if not p_str.startswith("-p"):
                cmd_parts.extend(["-p", p_str])
            else:
                cmd_parts.append(p_str)

        # 7. Target IP/CIDR
        cmd_parts.append(target.strip())
        return " ".join(cmd_parts)

    def parse_nmap_results(self, nm: nmap.PortScanner) -> list[dict[str, Any]]:
        """Parse all hosts from a python-nmap PortScanner object into structured device dicts.

        Args:
            nm: Active nmap.PortScanner object after scan execution.

        Returns:
            List of device dictionaries containing ip, hostname, mac, vendor, os, ports, device_type.
        """
        results: list[dict[str, Any]] = []
        if not hasattr(nm, "all_hosts"):
            return results

        for host in nm.all_hosts():
            try:
                host_data = nm[host]
                addresses = host_data.get("addresses", {})
                ip = addresses.get("ipv4", host)
                mac = addresses.get("mac", "")

                # Hostname extraction
                hostnames = host_data.get("hostnames", [])
                hostname = ""
                if hostnames and isinstance(hostnames, list):
                    hostname = hostnames[0].get("name", "") if isinstance(hostnames[0], dict) else ""

                # Vendor extraction
                vendor_map = host_data.get("vendor", {})
                vendor = vendor_map.get(mac, "") if mac and isinstance(vendor_map, dict) else ""

                # OS match extraction
                osmatch = host_data.get("osmatch", [])
                os_info = ""
                if osmatch and isinstance(osmatch, list):
                    os_info = osmatch[0].get("name", "") if isinstance(osmatch[0], dict) else ""

                # Extract ports & classify device type using Dev 1 functions
                discovered_ports = parse_nmap_results(nm, host)
                classified_type = guess_device_type(discovered_ports, os_info)

                device_dict = {
                    "ip": ip,
                    "hostname": hostname,
                    "mac": mac,
                    "vendor": vendor,
                    "os": os_info,
                    "device_type": classified_type,
                    "ports": discovered_ports,
                }
                results.append(device_dict)

            except Exception as exc:
                log_event(f"Error parsing scan result for host {host}: {exc}", "error")

        return results

    def custom_scan(
        self,
        target: str,
        ports: str | None = None,
        arguments: str | None = None,
        timing: str | int | None = None,
        host_timeout: str | None = None,
        verbosity: str | int | None = None,
        min_hostgroup: int | str | None = None,
        max_hostgroup: int | str | None = None,
        **kwargs: Any,
    ) -> tuple[list[dict[str, Any]], float]:
        """Perform a custom Nmap scan dynamically configured by parameters.

        Args:
            target: Subnet CIDR or IP address.
            ports: Custom port range (e.g. "1-1024", "22,80,443").
            arguments: Custom Nmap options string (e.g. "-sV -O").
            timing: Timing template (-T0..-T5).
            host_timeout: Max timeout per host (e.g. "5m").
            verbosity: Verbosity level (-v, -vv).
            min_hostgroup: Minimum parallel host group size.
            max_hostgroup: Maximum parallel host group size.

        Returns:
            Tuple of (list of device dicts, duration in seconds).
        """
        start_time = time.time()

        if not target or not target.strip():
            log_event("Custom scan target is empty.", "warning")
            self.last_duration = 0.0
            return [], 0.0

        # Construct full command string for audit / logging
        full_command = self.build_nmap_command(
            target=target,
            ports=ports,
            arguments=arguments,
            timing=timing,
            host_timeout=host_timeout,
            verbosity=verbosity,
            min_hostgroup=min_hostgroup,
            max_hostgroup=max_hostgroup,
        )
        self._last_command = full_command
        log_event(f"Executing dynamic scan: {full_command}", "info")

        # Build python-nmap arguments string (excluding target & ports which are passed separately)
        arg_list = []
        if arguments and arguments.strip():
            arg_list.append(arguments.strip())
        else:
            # Default to host discovery plus a lightweight port scan so local-network devices
            # that are up but not exposing common ports still appear in results.
            arg_list.append("-sn")
        if timing is not None:
            t_str = str(timing).strip()
            if not t_str.startswith("-T") and t_str.isdigit():
                t_str = f"-T{t_str}"
            if t_str in {"-T0", "-T1", "-T2", "-T3", "-T4", "-T5"}:
                arg_list.append(t_str)
        if verbosity is not None:
            v_str = str(verbosity).strip()
            if v_str in ("1", "-v"):
                arg_list.append("-v")
            elif v_str in ("2", "-vv"):
                arg_list.append("-vv")
        if host_timeout and str(host_timeout).strip():
            arg_list.append(f"--host-timeout {host_timeout.strip()}")
        if min_hostgroup is not None:
            arg_list.append(f"--min-hostgroup {min_hostgroup}")
        if max_hostgroup is not None:
            arg_list.append(f"--max-hostgroup {max_hostgroup}")

        nmap_args = " ".join(arg_list).strip() if arg_list else None

        results: list[dict[str, Any]] = []

        try:
            nm = nmap.PortScanner()
            nm.scan(hosts=target.strip(), ports=ports if ports else None, arguments=nmap_args or "")
            results = self.parse_nmap_results(nm)

            if not results and arguments and "-sn" in arguments:
                # Fallback to a standard TCP scan for the same target if host discovery returned none.
                nm = nmap.PortScanner()
                nm.scan(hosts=target.strip(), ports=ports or "1-1024", arguments="-sS -T4")
                results = self.parse_nmap_results(nm)
        except nmap.PortScannerError as nmap_err:
            log_event(f"Nmap execution failed: {nmap_err}", "error")
        except Exception as exc:
            log_event(f"Unexpected error during scan: {exc}", "error")

        duration = round(time.time() - start_time, 2)
        self.last_duration = duration
        log_event(f"Scan finished in {duration}s. Devices found: {len(results)}", "info")
        return results, duration

    def quick_scan(self, target: str) -> tuple[list[dict[str, Any]], float]:
        """Perform a fast host discovery ping scan (-sn)."""
        return self.custom_scan(target=target, arguments="-sn")

    def full_scan(self, target: str, ports: str | None = "1-65535") -> tuple[list[dict[str, Any]], float]:
        """Perform an in-depth scan with OS and service detection (-sV -O -A)."""
        return self.custom_scan(target=target, ports=ports, arguments="-sV -O -A")

    def run_scan(
        self, target: str, preset_name: str | None = None, **kwargs: Any
    ) -> tuple[list[dict[str, Any]], float, str]:
        """Run scan with optional preset support, returning (results, duration, command)."""
        ports = kwargs.get("ports")
        arguments = kwargs.get("arguments")

        if preset_name:
            try:
                from presets import get_preset
                preset = get_preset(preset_name)
                if preset:
                    arguments = preset.get("args", arguments)
                    ports = preset.get("ports", ports)
            except Exception as exc:
                log_event(f"Failed to load preset '{preset_name}': {exc}", "warning")

        results, duration = self.custom_scan(target=target, ports=ports, arguments=arguments, **kwargs)
        return results, duration, self.last_command

