"""NMD - Network Monitoring Dashboard
Application entry point supporting Desktop GUI (PySide6) and CLI modes.
"""

from __future__ import annotations

import argparse
import os
import sys

# Make `src/` importable for core, gui, models, utils, etc.
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "src"))

from core.database import init_db
from core.scanner import Scanner, find_nmap_binary, is_admin
from core.vulnerability_scanner import VulnerabilityScanner
from utils.exporter import export_to_csv, export_to_pdf
from utils.logger import get_logger, log_event
from utils.paths import get_db_path

logger = get_logger()


def run_cli_mode(args: argparse.Namespace) -> None:
    """Execute NMD in Command Line Interface (CLI) mode without GUI."""
    print("=" * 60)
    print("      NMD — Network Monitoring Dashboard (CLI Mode)")
    print("=" * 60)

    init_db()

    target = args.target or "192.168.1.0/24"
    scan_type = args.scan_type or "quick"
    ports = args.ports or "1-1024"

    nmap_path = find_nmap_binary()
    print(f"[*] Target       : {target}")
    print(f"[*] Scan Type    : {scan_type}")
    print(f"[*] Nmap Binary  : {nmap_path or 'NOT FOUND'}")
    print(f"[*] Admin Status : {'Elevated' if is_admin() else 'Standard User'}")
    print("-" * 60)

    if not nmap_path:
        print("[!] Error: Nmap executable not found. Please install Nmap or add it to PATH.")
        sys.exit(1)

    if scan_type == "vulnerability":
        print("[*] Executing NSE vulnerability assessment...")
        vuln_scanner = VulnerabilityScanner()
        success, status_code, vulns, duration, command, err_msg = vuln_scanner.execute_vulnerability_scan(
            target=target, ports=ports
        )
        print(f"[+] Scan completed in {duration:.2f}s. Status: {status_code}")
        print(f"[+] Vulnerabilities detected: {len(vulns)}")
        for idx, v in enumerate(vulns, 1):
            print(f"    [{idx}] [{v.get('severity')}] {v.get('title')} ({v.get('cve') or 'N/A'})")

        if args.export:
            from reports.vulnerability_report import generate_vulnerability_txt_report
            report_text = generate_vulnerability_txt_report(vulns, target)
            out_file = "vulnerability_report.txt"
            with open(out_file, "w", encoding="utf-8") as f:
                f.write(report_text)
            print(f"[+] Report exported to: {out_file}")

    else:
        print("[*] Executing network discovery scan...")
        scanner = Scanner()
        p_args = "-sn" if scan_type == "quick" else "-sV -O"
        res = scanner.execute_scan(target=target, ports=ports if scan_type != "quick" else None, arguments=p_args)

        print(f"[+] Scan completed in {res.duration:.2f}s. Hosts found: {len(res.devices)}")
        for d in res.devices:
            print(f"    - {d.get('ip'):<16} {d.get('hostname') or 'N/A':<20} {d.get('device_type'):<10} {d.get('os') or ''}")

        if args.export:
            csv_path = export_to_csv(res.devices)
            print(f"[+] Devices exported to CSV: {csv_path}")

    print("=" * 60)


def main() -> None:
    # Check if CLI mode was requested or arguments provided
    cli_flags = {"--cli", "--target", "--scan-type", "-t", "-s", "--export", "-e"}
    is_cli = any(arg in cli_flags for arg in sys.argv[1:])

    if is_cli or len(sys.argv) > 1:
        parser = argparse.ArgumentParser(description="NMD — Network Monitoring Dashboard (CLI / GUI launcher)")
        parser.add_argument("--cli", action="store_true", help="Force CLI execution mode without GUI")
        parser.add_argument("-t", "--target", type=str, help="Target IP or CIDR subnet (e.g. 192.168.1.0/24)")
        parser.add_argument("-s", "--scan-type", type=str, choices=["quick", "full", "vulnerability"], default="quick", help="Scan mode")
        parser.add_argument("-p", "--ports", type=str, default="1-1024", help="Port range (e.g. 1-1024)")
        parser.add_argument("-e", "--export", action="store_true", help="Automatically export scan report")

        args = parser.parse_args()
        run_cli_mode(args)
    else:
        # Launch PySide6 Desktop GUI Application
        from desktop_app import run_desktop_app
        sys.exit(run_desktop_app())


if __name__ == "__main__":
    main()
