"""Background automated network scan scheduler for NMD.

Orchestrates periodic background scans, analysis, database updates,
and alert generation without blocking the main/GUI thread.
"""

from datetime import datetime
import threading
from typing import Any

from core import analyzer, database
from core.alert_engine import AlertEngine
from core.scanner import Scanner, ScanResult
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
        self._interval = float(
            interval if interval is not None else cfg.get("scan_interval", 60)
        )
        self._preset_name: str | None = None

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
            log_event(
                f"Invalid interval {seconds}s provided to scheduler.",
                "error",
            )
            return

        self._interval = float(seconds)
        log_event(
            f"Scheduler scan interval updated to {self._interval}s.",
            "info",
        )

    def get_interval(self) -> float:
        """Get the current scan interval."""
        return self._interval

    def set_preset(self, preset_name: str) -> None:
        """Set active scan preset name for the scheduler."""
        self._preset_name = preset_name
        log_event(
            f"Scheduler preset updated to '{preset_name}'.",
            "info",
        )

    def get_preset(self) -> str | None:
        """Get active preset name."""
        return self._preset_name

    def _execute_scan(self) -> dict[str, Any] | None:
        """Perform a single scan execution pipeline.

        Prevents overlapping scans if a scan is already running.
        """

        if not self._scan_lock.acquire(blocking=False):
            log_event(
                "Scan already in progress. Skipping duplicate scan run.",
                "warning",
            )
            return None

        self._is_scanning = True

        try:
            # ---------------------------------------------------------
            # 1. Load configuration
            # ---------------------------------------------------------
            cfg = load_config()

            target = cfg.get("subnet")

            # Auto-detect subnet only when configuration is missing
            # or still contains the old default.
            if not target or target == "192.168.1.0/24":
                try:
                    from utils.config import detect_gateway

                    detected = detect_gateway()

                    if detected and detected != "192.168.1.0/24":
                        target = detected

                        cfg["subnet"] = detected

                        from utils.config import save_config

                        save_config(cfg)

                        log_event(
                            f"Auto-detected and updated subnet to: {detected}",
                            "info",
                        )
                    else:
                        target = "192.168.1.0/24"
                        log_event(
                            "Using fallback subnet: 192.168.1.0/24",
                            "warning",
                        )

                except Exception as exc:
                    target = "192.168.1.0/24"
                    log_event(
                        f"Failed to auto-detect subnet, using fallback: {exc}",
                        "warning",
                    )

            scan_type = cfg.get("scan_type", "quick")
            port_range = cfg.get("port_range", "1-1024")

            log_event(
                f"Scheduler scan started with target: {target}, "
                f"type: {scan_type}",
                "info",
            )

            # ---------------------------------------------------------
            # 2. Determine preset
            # ---------------------------------------------------------
            preset_name = self._preset_name

            if not preset_name and scan_type not in (
                "quick",
                "full",
                "custom",
            ):
                preset_name = scan_type

            preset_data = None

            if preset_name:
                try:
                    from presets import get_preset

                    preset_data = get_preset(preset_name)

                    log_event(
                        f"Loaded preset: {preset_name}",
                        "debug",
                    )

                except Exception as exc:
                    log_event(
                        f"Failed to fetch preset '{preset_name}': {exc}",
                        "warning",
                    )

            # ---------------------------------------------------------
            # 3. Build scan arguments
            # ---------------------------------------------------------
            p_args = None
            p_ports = None

            if preset_data:
                p_args = preset_data.get("args")
                p_ports = preset_data.get("ports")

            elif scan_type == "full":
                p_args = "-sV -O"
                p_ports = port_range

            elif scan_type == "custom":
                custom_settings = cfg.get(
                    "custom_scan_settings",
                    {},
                )

                p_args = custom_settings.get(
                    "arguments",
                    "-sV",
                )

                p_ports = port_range

            elif scan_type == "vulnerability":
                p_args = "-sV --script vuln"
                p_ports = port_range

            else:
                # Quick scan / discovery scan
                p_args = "-sn"
                p_ports = None


            log_event(
                f"Scheduler starting scan (type: '{scan_type}') "
                f"on target '{target}'.",
                "info",
            )

            # ---------------------------------------------------------
            # 4. Execute Nmap scan
            # ---------------------------------------------------------
            scan_res: ScanResult = self.scanner.execute_scan(
                target=target,
                ports=p_ports,
                arguments=p_args,
            )

            log_event(
                f"Scheduler scan finished. "
                f"Status: {scan_res.status_code}, "
                f"Duration: {scan_res.duration:.2f}s, "
                f"Devices: {len(scan_res.devices)}",
                "info",
            )

            # ---------------------------------------------------------
            # 5. Handle scan failure
            # ---------------------------------------------------------
            if not scan_res.success:
                log_event(
                    f"Scheduler scan error: {scan_res.error_message}",
                    "error",
                )

                # IMPORTANT:
                # Do not treat a failed scan as a valid empty scan.
                analysis = analyzer.analyze_scan(
                    scan_res.devices,
                    scan_failed=True,
                )

                return analysis

            # ---------------------------------------------------------
            # 6. Analyze successful scan
            # ---------------------------------------------------------
            analysis = analyzer.analyze_scan(
                scan_res.devices,
                scan_failed=False,
            )

            log_event(
                f"Analysis result: "
                f"{len(analysis.get('new', []))} new, "
                f"{len(analysis.get('returned', []))} returned, "
                f"{len(analysis.get('disconnected', []))} disconnected",
                "debug",
            )

            # ---------------------------------------------------------
            # 7. Save scan information to database
            # ---------------------------------------------------------
            scan_record_data = {
                "scan_date": datetime.utcnow(),
                "duration": scan_res.duration,
                "total_devices": len(scan_res.devices),
                "new_devices": len(analysis.get("new", [])),
                "disconnected_devices": len(
                    analysis.get("disconnected", [])
                ),
                "scan_command": scan_res.command,
            }

            database.add_scan(scan_record_data)

            log_event(
                f"Scan record saved to database: "
                f"{len(scan_res.devices)} devices",
                "debug",
            )

            # ---------------------------------------------------------
            # 8. Generate alerts
            # ---------------------------------------------------------
            alerts = self.alert_engine.process_scan_result(
                analysis
            )

            if alerts:
                log_event(
                    f"Generated {len(alerts)} alerts from scan",
                    "info",
                )

            return analysis

        except Exception as exc:
            log_event(
                f"Error during scheduler scan execution: {exc}",
                "error",
                exc_info=True,
            )
            return None

        finally:
            self._is_scanning = False

            try:
                self._scan_lock.release()
            except RuntimeError:
                # Lock wasn't acquired; ignore.
                pass

    def _worker_loop(self) -> None:
        """Background thread loop executing periodic scans."""

        log_event(
            "Scheduler background worker thread started.",
            "info",
        )

        while not self._stop_event.is_set():
            self._execute_scan()

            if self._stop_event.wait(self._interval):
                break

        log_event(
            "Scheduler background worker thread exiting.",
            "info",
        )

    def start(self) -> bool:
        """Start the background scheduler thread."""

        if self.is_running():
            log_event(
                "Scheduler is already running.",
                "warning",
            )
            return False

        self._stop_event.clear()

        self._thread = threading.Thread(
            target=self._worker_loop,
            daemon=True,
            name="NMDSchedulerThread",
        )

        self._thread.start()

        log_event(
            f"Scheduler started with interval of "
            f"{self._interval}s.",
            "info",
        )

        return True

    def stop(self) -> bool:
        """Stop the background scheduler thread cleanly."""

        if not self.is_running():
            log_event(
                "Scheduler is not running.",
                "warning",
            )
            return False

        self._stop_event.set()

        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3.0)

        self._thread = None

        log_event(
            "Scheduler stopped.",
            "info",
        )

        return True

    def run_now(self) -> None:
        """Trigger an immediate scan in a separate background thread."""

        log_event(
            "Manual scan requested via scheduler run_now().",
            "info",
        )

        trigger_thread = threading.Thread(
            target=self._execute_scan,
            daemon=True,
            name="NMDManualScanThread",
        )

        trigger_thread.start()