"""Background automated network scan scheduler for NMD.

Orchestrates periodic background scans, analysis, database updates,
and alert generation without blocking the main/GUI thread.
"""
from datetime import datetime
import threading
from typing import Any

from core import analyzer, database
from core.alert_engine import AlertEngine
from core.scanner import Scanner
from utils.config import load_config
from utils.logger import log_event


class NetworkScheduler:
    """Automated background scheduler for network discovery scans."""

    def __init__(
        self,
        scanner: Scanner | None = None,
        alert_engine: AlertEngine | None = None,
        interval: float | None = None,
    ) -> None:
        self.scanner = scanner or Scanner()
        self.alert_engine = alert_engine or AlertEngine()

        cfg = load_config()
        self._interval = float(interval if interval is not None else cfg.get("scan_interval", 60))

        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._scan_lock = threading.Lock()
        self._is_scanning: bool = False

    def is_running(self) -> bool:
        """Return True if background scheduler thread is running."""
        return self._thread is not None and self._thread.is_alive()

    def set_interval(self, seconds: float) -> None:
        """Update the scan interval in seconds."""
        if seconds <= 0:
            log_event(f"Invalid interval {seconds}s provided to scheduler.", "error")
            return
        self._interval = float(seconds)
        log_event(f"Scheduler scan interval updated to {self._interval}s.", "info")

    def get_interval(self) -> float:
        """Get the current scan interval in seconds."""
        return self._interval

    def _execute_scan(self) -> dict[str, Any] | None:
        """Perform a single scan execution pipeline.

        Prevents overlapping scans if a scan is already running.
        Pipeline: Scanner -> Analyzer -> Database -> AlertEngine.
        """
        if not self._scan_lock.acquire(blocking=False):
            log_event("Scan already in progress. Skipping duplicate scan run.", "warning")
            return None

        self._is_scanning = True
        try:
            cfg = load_config()
            target = cfg.get("subnet", "192.168.1.0/24")
            scan_type = cfg.get("scan_type", "quick")
            port_range = cfg.get("port_range", "1-1024")

            log_event(f"Scheduler starting '{scan_type}' scan on target '{target}'.", "info")

            # 1. Run Nmap scan
            if scan_type == "full":
                scan_results, duration = self.scanner.full_scan(target, port_range)
            elif scan_type == "custom":
                scan_results, duration = self.scanner.custom_scan(target, port_range)
            else:
                scan_results, duration = self.scanner.quick_scan(target)

            # 2. Compare scan results with DB using Dev 1's analyzer
            analysis = analyzer.analyze_scan(scan_results)

            # 3. Add scan record using Dev 1's database API
            scan_record_data = {
                "scan_date": datetime.utcnow(),
                "duration": duration,
                "total_devices": len(scan_results),
                "new_devices": len(analysis.get("new", [])),
                "disconnected_devices": len(analysis.get("disconnected", [])),
            }
            database.add_scan(scan_record_data)

            # 4. Generate alerts using Dev 2's AlertEngine
            self.alert_engine.process_scan_result(analysis)

            log_event(
                f"Scheduler scan completed successfully: {len(scan_results)} total devices, "
                f"{len(analysis.get('new', []))} new, {len(analysis.get('disconnected', []))} disconnected.",
                "info",
            )
            return analysis

        except Exception as exc:
            log_event(f"Error during scheduler scan execution: {exc}", "error")
            return None
        finally:
            self._is_scanning = False
            self._scan_lock.release()

    def _worker_loop(self) -> None:
        """Background thread loop executing periodic scans."""
        log_event("Scheduler background worker thread started.", "info")
        while not self._stop_event.is_set():
            self._execute_scan()

            # Wait for interval seconds or until stop signal
            # Interrupted immediately when stop() is called
            if self._stop_event.wait(self._interval):
                break
        log_event("Scheduler background worker thread exiting.", "info")

    def start(self) -> bool:
        """Start the background scheduler thread."""
        if self.is_running():
            log_event("Scheduler is already running.", "warning")
            return False

        self._stop_event.clear()
        self._thread = threading.Thread(target=self._worker_loop, daemon=True, name="NMDSchedulerThread")
        self._thread.start()
        log_event(f"Scheduler started with interval of {self._interval}s.", "info")
        return True

    def stop(self) -> bool:
        """Stop the background scheduler thread cleanly."""
        if not self.is_running():
            log_event("Scheduler is not running.", "warning")
            return False

        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3.0)
        self._thread = None
        log_event("Scheduler stopped.", "info")
        return True

    def run_now(self) -> None:
        """Trigger an immediate scan in a separate background thread."""
        log_event("Manual scan requested via scheduler run_now().", "info")
        trigger_thread = threading.Thread(target=self._execute_scan, daemon=True, name="NMDManualScanThread")
        trigger_thread.start()
