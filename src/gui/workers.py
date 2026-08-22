"""PySide6 Worker threads for non-blocking execution of backend engines.

Includes:
- ScanWorker: Executes network discovery and custom scans.
- VulnerabilityScanWorker: Executes Nmap NSE vulnerability assessment scans.
- ExportWorker: Generates PDF/CSV/TXT/JSON reports asynchronously.
"""

from __future__ import annotations

from typing import Any
from PySide6.QtCore import QObject, QThread, Signal

from core import analyzer, database
from core.scanner import Scanner, ScanResult
from core.vulnerability_scanner import VulnerabilityScanner
from utils.logger import log_event


class ScanWorker(QThread):
    """Background worker for network discovery and custom scans."""

    progress = Signal(int, str)  # (percent, message)
    log_line = Signal(str)       # (log text line)
    scan_finished = Signal(dict) # (analysis dict result)
    scan_error = Signal(str)    # (error message)

    def __init__(
        self,
        target: str,
        ports: str | None = None,
        arguments: str | None = None,
        timing: str | int | None = "-T4",
        parent: Any = None,
    ) -> None:
        super().__init__(parent)
        self.target = target
        self.ports = ports
        self.arguments = arguments
        self.timing = timing
        self.scanner = Scanner()

    def cancel(self) -> None:
        """Cancel active scanning process."""
        self.scanner.cancel_scan()
        self.log_line.emit("Cancellation requested for active scan process...")

    def run(self) -> None:
        self.progress.emit(10, f"Initializing scan against target {self.target}...")
        self.log_line.emit(f"[START] Launching scan on {self.target}...")

        try:
            self.progress.emit(30, "Executing Nmap scan engine...")
            res: ScanResult = self.scanner.execute_scan(
                target=self.target,
                ports=self.ports,
                arguments=self.arguments,
                timing=self.timing,
            )

            if not res.success:
                err_msg = res.error_message or "Scan execution failed."
                self.log_line.emit(f"[ERROR] Scan failed: {err_msg}")
                self.scan_error.emit(err_msg)
                return

            self.progress.emit(70, "Analyzing scan findings & updating database...")
            self.log_line.emit(f"[INFO] Scan completed in {res.duration:.2f}s. Hosts found: {len(res.devices)}")

            analysis = analyzer.analyze_scan(res.devices, scan_failed=False)

            # Record scan in database
            scan_record_data = {
                "scan_date": database.datetime.utcnow(),
                "duration": res.duration,
                "total_devices": len(res.devices),
                "new_devices": len(analysis.get("new", [])),
                "disconnected_devices": len(analysis.get("disconnected", [])),
                "scan_command": res.command,
            }
            database.add_scan(scan_record_data)

            analysis["raw_devices"] = res.devices
            analysis["duration"] = res.duration
            analysis["command"] = res.command

            self.progress.emit(100, "Scan completed successfully.")
            self.scan_finished.emit(analysis)

        except Exception as exc:
            log_event(f"Unhandled exception in ScanWorker: {exc}", "error", exc_info=True)
            self.log_line.emit(f"[CRITICAL] Scan worker exception: {exc}")
            self.scan_error.emit(str(exc))


class VulnerabilityScanWorker(QThread):
    """Background worker for authorized Nmap NSE vulnerability assessment scans."""

    progress = Signal(int, str)             # (percent, status)
    log_line = Signal(str)                  # (log string)
    vuln_finished = Signal(list, float, str)# (vulnerabilities list, duration, command)
    vuln_error = Signal(str)               # (error message)

    def __init__(
        self,
        target: str,
        ports: str | None = "1-1024",
        scripts: str = "vuln",
        timeout: float = 300.0,
        parent: Any = None,
    ) -> None:
        super().__init__(parent)
        self.target = target
        self.ports = ports
        self.scripts = scripts
        self.timeout = timeout
        self.vuln_scanner = VulnerabilityScanner()

    def cancel(self) -> None:
        """Cancel active vulnerability scan."""
        self.vuln_scanner.scanner.cancel_scan()
        self.log_line.emit("Cancellation requested for active vulnerability scan...")

    def run(self) -> None:
        self.progress.emit(10, f"Initializing NSE vulnerability assessment on {self.target}...")
        self.log_line.emit(f"[START] Launching NSE vulnerability assessment (-sV --script {self.scripts})...")

        try:
            self.progress.emit(40, "Executing Nmap service detection & NSE scripts...")
            success, status_code, vulns, duration, command, err_msg = (
                self.vuln_scanner.execute_vulnerability_scan(
                    target=self.target,
                    ports=self.ports,
                    scripts=self.scripts,
                    timeout=self.timeout,
                )
            )

            if not success:
                err = err_msg or f"Vulnerability scan failed with status code: {status_code}"
                self.log_line.emit(f"[ERROR] Vulnerability scan error: {err}")
                self.vuln_error.emit(err)
                return

            self.progress.emit(85, "Persisting vulnerability findings to database...")
            self.log_line.emit(f"[INFO] Assessment complete in {duration:.2f}s. Vulnerabilities detected: {len(vulns)}")

            # Store findings in SQLite database
            for v in vulns:
                try:
                    database.add_vulnerability(v)
                except Exception as db_err:
                    log_event(f"Failed to persist vulnerability record to database: {db_err}", "warning")

            self.progress.emit(100, "Vulnerability scan completed.")
            self.vuln_finished.emit(vulns, duration, command)

        except Exception as exc:
            log_event(f"Unhandled exception in VulnerabilityScanWorker: {exc}", "error", exc_info=True)
            self.log_line.emit(f"[CRITICAL] Vulnerability worker exception: {exc}")
            self.vuln_error.emit(str(exc))


class ExportWorker(QThread):
    """Worker for non-blocking report generation."""

    export_finished = Signal(str) # (output file path)
    export_error = Signal(str)    # (error message)

    def __init__(self, export_fn: Any, *args: Any, parent: Any = None) -> None:
        if parent is None and args and isinstance(args[-1], QObject):
            parent = args[-1]
            args = args[:-1]
        super().__init__(parent)
        self.export_fn = export_fn
        self.args = args

    def run(self) -> None:
        try:
            result_path = self.export_fn(*self.args)
            self.export_finished.emit(str(result_path) if result_path is not None else "")
        except Exception as exc:
            log_event(f"Export error: {exc}", "error", exc_info=True)
            self.export_error.emit(str(exc))

