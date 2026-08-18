"""Nmap scanning engine and XML parser for NMD (Network Monitoring Dashboard).

Provides dynamic Nmap command generation, cross-platform executable resolution,
privileged/unprivileged scan handling, subprocess execution with XML parsing,
timeout control, and detailed error classification.
"""
from __future__ import annotations

import ctypes
import ipaddress
import os
import platform
import re
import shutil
import subprocess
import time
import xml.etree.ElementTree as ET
from typing import Any

from utils.logger import log_event


def find_nmap_binary() -> str | None:
    """Detect nmap executable across Windows and Linux system paths.

    Returns:
        Absolute path string to nmap executable, or None if not installed.
    """
    # 1. Standard PATH resolution using shutil.which
    found = shutil.which("nmap") or shutil.which("nmap.exe")
    if found and os.path.isfile(found):
        return found

    system_name = platform.system()

    # 2. Windows specific standard installation paths
    if system_name == "Windows":
        candidate_paths = [
            os.path.join(os.environ.get("ProgramFiles", r"C:\Program Files"), "Nmap", "nmap.exe"),
            os.path.join(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"), "Nmap", "nmap.exe"),
            r"C:\Program Files\Nmap\nmap.exe",
            r"C:\Program Files (x86)\Nmap\nmap.exe",
        ]
        for path in candidate_paths:
            if os.path.isfile(path):
                return path

    # 3. Linux/POSIX specific standard binary paths
    else:
        candidate_paths = [
            "/usr/bin/nmap",
            "/usr/local/bin/nmap",
            "/bin/nmap",
        ]
        for path in candidate_paths:
            if os.path.isfile(path):
                return path

    return None


def is_admin() -> bool:
    """Check if the current process has Administrator (Windows) or root (Linux) privileges."""
    try:
        if platform.system() == "Windows":
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            return os.geteuid() == 0
    except Exception:
        return False


def validate_target(target: str) -> tuple[bool, str]:
    """Validate target IP, CIDR subnet, or hostname.

    Returns:
        (is_valid: bool, error_message: str)
    """
    if not target or not target.strip():
        return False, "Target address is empty."

    target_str = target.strip()

    # 1. Try IP network / CIDR (e.g. 10.222.83.0/24)
    try:
        ipaddress.ip_network(target_str, strict=False)
        return True, ""
    except ValueError:
        pass

    # 2. Try single IP (e.g. 192.168.1.1)
    try:
        ipaddress.ip_address(target_str)
        return True, ""
    except ValueError:
        pass

    # 3. Try domain name / hostname (e.g. localhost or scanme.nmap.org)
    hostname_regex = re.compile(
        r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$|^localhost$"
    )
    if hostname_regex.match(target_str):
        return True, ""

    return False, f"Invalid target format: '{target_str}'. Expected CIDR (e.g. 10.222.83.0/24) or IP."


def parse_nmap_results(nm: Any, host: str) -> dict[str, str]:
    """Legacy helper function kept for backwards compatibility."""
    if hasattr(nm, "all_hosts") and callable(nm.all_hosts):
        ports: dict[str, str] = {}
        try:
            if host in nm.all_hosts():
                host_obj = nm[host]
                for proto in ("tcp", "udp"):
                    if proto in host_obj:
                        for p, info in host_obj[proto].items():
                            if info.get("state") == "open":
                                ports[str(p)] = info.get("name", "unknown")
        except Exception:
            pass
        return ports
    return {}


def guess_device_type(ports: dict[str, str], os_name: str | None = None) -> str:
    """Classify device type based on open ports and OS fingerprint."""
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


def parse_nmap_xml(xml_content: str) -> list[dict[str, Any]]:
    """Parse Nmap XML output (-oX -) into structured device objects.

    Args:
        xml_content: String containing complete Nmap XML output.

    Returns:
        List of device dicts with ip, hostname, mac, vendor, os, device_type, ports.
    """
    devices: list[dict[str, Any]] = []
    if not xml_content or not xml_content.strip():
        return devices

    try:
        root = ET.fromstring(xml_content)
    except ET.ParseError as err:
        log_event(f"XML parse error: {err}", "error")
        return devices

    for host_node in root.findall("host"):
        # Check host status (only process hosts that are 'up')
        status_node = host_node.find("status")
        if status_node is not None and status_node.get("state") != "up":
            continue

        ip = ""
        mac = ""
        vendor = ""

        # Addresses (IPv4, IPv6, MAC)
        for addr_node in host_node.findall("address"):
            addr_type = addr_node.get("addrtype", "")
            addr_val = addr_node.get("addr", "")
            if addr_type in ("ipv4", "ipv6") and not ip:
                ip = addr_val
            elif addr_type == "mac":
                mac = addr_val
                vendor = addr_node.get("vendor", "")

        if not ip:
            continue

        # Hostname
        hostname = ""
        hostnames_node = host_node.find("hostnames")
        if hostnames_node is not None:
            hn_node = hostnames_node.find("hostname")
            if hn_node is not None:
                hostname = hn_node.get("name", "")

        # OS Detection
        os_info = ""
        os_node = host_node.find("os")
        if os_node is not None:
            osmatch_node = os_node.find("osmatch")
            if osmatch_node is not None:
                os_info = osmatch_node.get("name", "")

        # Open Ports & Service Parsing
        open_ports: dict[str, str] = {}
        port_details: list[dict[str, Any]] = []

        ports_node = host_node.find("ports")
        if ports_node is not None:
            for port_node in ports_node.findall("port"):
                state_node = port_node.find("state")
                if state_node is not None and state_node.get("state") == "open":
                    port_id = port_node.get("portid", "")
                    protocol = port_node.get("protocol", "tcp")
                    
                    service_node = port_node.find("service")
                    service_name = "unknown"
                    product = ""
                    version = ""

                    if service_node is not None:
                        service_name = service_node.get("name", "unknown")
                        product = service_node.get("product", "")
                        version = service_node.get("version", "")

                    version_full = f"{product} {version}".strip()
                    open_ports[port_id] = service_name

                    port_details.append(
                        {
                            "port": int(port_id) if port_id.isdigit() else port_id,
                            "protocol": protocol,
                            "state": "open",
                            "service": service_name,
                            "version": version_full,
                        }
                    )

        device_type = guess_device_type(open_ports, os_info)

        devices.append(
            {
                "ip": ip,
                "hostname": hostname,
                "mac": mac,
                "vendor": vendor,
                "os": os_info,
                "device_type": device_type,
                "ports": open_ports,
                "port_details": port_details,
                "status": "online",
            }
        )

    return devices


class ScanResult:
    """Structured container for scan execution results and status."""

    def __init__(
        self,
        success: bool,
        status_code: str,
        devices: list[dict[str, Any]],
        duration: float,
        command: str,
        error_message: str = "",
        raw_xml: str = "",
    ) -> None:
        self.success = success
        self.status_code = status_code  # SUCCESS, NO_HOSTS_FOUND, NMAP_NOT_FOUND, PERMISSION_ERROR, INVALID_TARGET, TIMEOUT, EXECUTION_ERROR
        self.devices = devices
        self.duration = duration
        self.command = command
        self.error_message = error_message
        self.raw_xml = raw_xml

    def to_tuple(self) -> tuple[list[dict[str, Any]], float]:
        """Backwards compatibility tuple representation."""
        return self.devices, self.duration


class Scanner:
    """Cross-platform Nmap scanning engine."""

    def __init__(self, nmap_path: str | None = None) -> None:
        self.nmap_path = nmap_path or find_nmap_binary()
        self.last_duration: float = 0.0
        self._last_command: str = ""
        self._active_process: subprocess.Popen | None = None

    @property
    def last_command(self) -> str:
        """Return the string representation of the last built Nmap command."""
        return self._last_command

    def is_nmap_available(self) -> bool:
        """Check if a valid Nmap binary is available."""
        self.nmap_path = find_nmap_binary()
        return self.nmap_path is not None

    def cancel_scan(self) -> None:
        """Cancel an actively executing Nmap subprocess."""
        if self._active_process and self._active_process.poll() is None:
            try:
                self._active_process.terminate()
                log_event("Active scan process termination requested.", "info")
            except Exception as err:
                log_event(f"Failed to terminate scan process: {err}", "error")

    def build_nmap_command_args(
        self,
        target: str,
        ports: str | None = None,
        arguments: str | None = None,
        timing: str | int | None = None,
        host_timeout: str | None = None,
        verbosity: str | int | None = None,
        min_hostgroup: int | str | None = None,
        max_hostgroup: int | str | None = None,
    ) -> list[str]:
        """Construct the argument list for Nmap subprocess execution."""
        nmap_bin = self.nmap_path or "nmap"
        cmd: list[str] = [nmap_bin]

        # Always add XML output flag
        cmd.extend(["-oX", "-"])

        # Check privileges for SYN scan fallback
        user_is_admin = is_admin()

        # Parse and process arguments
        args_str = (arguments or "").strip()

        # 🔥 NEW: AUTO-ADD --script-timeout 30s FOR VULNERABILITY SCANS
        if "--script" in args_str or "vuln" in args_str:
            if "--script-timeout" not in args_str:
                args_str += " --script-timeout 30s"
                log_event("🔒 Added --script-timeout 30s to vulnerability scan to prevent hangs.", "info")

        # Privileged flags handling: SYN stealth (-sS) requires Admin/root.
        # Fallback to TCP Connect scan (-sT) if non-admin.
        if "-sS" in args_str and not user_is_admin:
            log_event("SYN Stealth scan (-sS) requires Administrator/root privileges. Downgrading to TCP Connect scan (-sT).", "warning")
            args_str = args_str.replace("-sS", "-sT")

        if args_str:
            # Split custom arguments safely while retaining flags
            for arg_part in args_str.split():
                if arg_part not in cmd:
                    cmd.append(arg_part)

        # Timing template (-T0 to -T5)
        if timing is not None:
            t_str = str(timing).strip()
            if not t_str.startswith("-T"):
                if t_str.isdigit():
                    t_str = f"-T{t_str}"
                elif t_str.startswith("T"):
                    t_str = f"-{t_str}"
            if t_str in {"-T0", "-T1", "-T2", "-T3", "-T4", "-T5"}:
                if not any(t in cmd for t in ["-T0", "-T1", "-T2", "-T3", "-T4", "-T5"]):
                    cmd.append(t_str)

        # Verbosity
        if verbosity is not None:
            v_str = str(verbosity).strip()
            if v_str in ("1", "-v") and "-v" not in cmd:
                cmd.append("-v")
            elif v_str in ("2", "-vv") and "-vv" not in cmd:
                cmd.append("-vv")

        # Host timeout
        if host_timeout and str(host_timeout).strip():
            ht = str(host_timeout).strip()
            if "--host-timeout" not in cmd:
                cmd.extend(["--host-timeout", ht])

        # Parallelism
        if min_hostgroup is not None and "--min-hostgroup" not in cmd:
            cmd.extend(["--min-hostgroup", str(min_hostgroup)])
        if max_hostgroup is not None and "--max-hostgroup" not in cmd:
            cmd.extend(["--max-hostgroup", str(max_hostgroup)])

        # Ports
        if ports and str(ports).strip():
            p_str = str(ports).strip()
            if "-p" not in cmd:
                cmd.extend(["-p", p_str])

        # Target IP / Subnet
        cmd.append(target.strip())
        return cmd

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
        """Return human-readable command string representation for preview and logs."""
        args = self.build_nmap_command_args(
            target=target,
            ports=ports,
            arguments=arguments,
            timing=timing,
            host_timeout=host_timeout,
            verbosity=verbosity,
            min_hostgroup=min_hostgroup,
            max_hostgroup=max_hostgroup,
        )
        # Omit '-oX -' from the display command for cleaner preview
        display_args = [a for a in args if a not in ("-oX", "-")]
        return " ".join(display_args)

    def execute_scan(
        self,
        target: str,
        ports: str | None = None,
        arguments: str | None = None,
        timing: str | int | None = None,
        host_timeout: str | None = None,
        verbosity: str | int | None = None,
        min_hostgroup: int | str | None = None,
        max_hostgroup: int | str | None = None,
        timeout: float = 300.0,
    ) -> ScanResult:
        """Execute Nmap scan synchronously using subprocess and parse XML output.

        Returns:
            ScanResult object with success flag, status_code, hosts list, and detailed error messages.
        """
        start_time = time.time()

        # 1. Target Validation
        is_valid_tgt, tgt_err = validate_target(target)
        if not is_valid_tgt:
            log_event(f"Target validation failed: {tgt_err}", "error")
            return ScanResult(
                success=False,
                status_code="INVALID_TARGET",
                devices=[],
                duration=0.0,
                command=f"nmap {target}",
                error_message=tgt_err,
            )

        # 2. Binary Validation
        nmap_bin = find_nmap_binary()
        if not nmap_bin:
            err_msg = "Nmap executable not found. Please install Nmap or add it to PATH."
            log_event(err_msg, "error")
            return ScanResult(
                success=False,
                status_code="NMAP_NOT_FOUND",
                devices=[],
                duration=0.0,
                command=f"nmap {target}",
                error_message=err_msg,
            )
        self.nmap_path = nmap_bin

        # Build execution command
        cmd_args = self.build_nmap_command_args(
            target=target,
            ports=ports,
            arguments=arguments,
            timing=timing,
            host_timeout=host_timeout,
            verbosity=verbosity,
            min_hostgroup=min_hostgroup,
            max_hostgroup=max_hostgroup,
        )
        full_cmd_str = self.build_nmap_command(
            target=target,
            ports=ports,
            arguments=arguments,
            timing=timing,
            host_timeout=host_timeout,
            verbosity=verbosity,
            min_hostgroup=min_hostgroup,
            max_hostgroup=max_hostgroup,
        )
        self._last_command = full_cmd_str

        log_event(f"[INFO] Nmap path: {nmap_bin}", "info")
        log_event(f"[INFO] Target: {target}", "info")
        log_event(f"[INFO] Executing command: {full_cmd_str}", "info")

        stdout_data = ""
        stderr_data = ""
        returncode = -1

        try:
            # Execute subprocess safely
            self._active_process = subprocess.Popen(
                cmd_args,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
            )

            stdout_data, stderr_data = self._active_process.communicate(timeout=timeout)
            returncode = self._active_process.returncode

        except subprocess.TimeoutExpired:
            self.cancel_scan()
            duration = round(time.time() - start_time, 2)
            err_msg = f"Nmap scan timed out after {timeout} seconds."
            log_event(f"[ERROR] {err_msg}", "error")
            return ScanResult(
                success=False,
                status_code="TIMEOUT",
                devices=[],
                duration=duration,
                command=full_cmd_str,
                error_message=err_msg,
            )

        except Exception as exc:
            duration = round(time.time() - start_time, 2)
            err_msg = f"Failed to launch Nmap process: {exc}"
            log_event(f"[ERROR] {err_msg}", "error")
            return ScanResult(
                success=False,
                status_code="EXECUTION_ERROR",
                devices=[],
                duration=duration,
                command=full_cmd_str,
                error_message=err_msg,
            )

        finally:
            self._active_process = None

        duration = round(time.time() - start_time, 2)
        self.last_duration = duration

        # Check Nmap execution exit status and stderr
        stderr_clean = (stderr_data or "").strip()

        # Permission error detection
        if returncode != 0 and ("requires root privileges" in stderr_clean.lower() or "dnet: failed" in stderr_clean.lower() or "administrator" in stderr_clean.lower()):
            err_msg = "This scan option requires Administrator (Windows) or root (Linux) privileges."
            log_event(f"[ERROR] Permission error: {stderr_clean}", "error")
            return ScanResult(
                success=False,
                status_code="PERMISSION_ERROR",
                devices=[],
                duration=duration,
                command=full_cmd_str,
                error_message=err_msg,
            )

        if returncode != 0:
            err_msg = stderr_clean or f"Nmap exited with error code {returncode}."
            log_event(f"[ERROR] Nmap execution failed (return code {returncode}): {err_msg}", "error")
            return ScanResult(
                success=False,
                status_code="EXECUTION_ERROR",
                devices=[],
                duration=duration,
                command=full_cmd_str,
                error_message=err_msg,
            )

        # Parse XML results
        devices = parse_nmap_xml(stdout_data)
        log_event(f"[INFO] Scan completed in {duration}s. Devices found: {len(devices)}", "info")

        status_code = "SUCCESS" if devices else "NO_HOSTS_FOUND"
        return ScanResult(
            success=True,
            status_code=status_code,
            devices=devices,
            duration=duration,
            command=full_cmd_str,
            error_message="" if devices else "0 hosts found.",
            raw_xml=stdout_data,
        )


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
        """Perform scan and return tuple of (devices, duration) for backwards compatibility."""
        res = self.execute_scan(
            target=target,
            ports=ports,
            arguments=arguments,
            timing=timing,
            host_timeout=host_timeout,
            verbosity=verbosity,
            min_hostgroup=min_hostgroup,
            max_hostgroup=max_hostgroup,
        )
        return res.devices, res.duration

    def quick_scan(self, target: str) -> tuple[list[dict[str, Any]], float]:
        """Perform a host discovery ping scan (-sn)."""
        return self.custom_scan(target=target, arguments="-sn")

    def full_scan(self, target: str, ports: str | None = "1-1024") -> tuple[list[dict[str, Any]], float]:
        """Perform a standard full scan with version & OS detection."""
        return self.custom_scan(target=target, ports=ports, arguments="-sV -O")

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

        res = self.execute_scan(target=target, ports=ports, arguments=arguments, **kwargs)
        return res.devices, res.duration, res.command
