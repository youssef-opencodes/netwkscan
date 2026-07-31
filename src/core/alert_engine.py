"""Alert engine module for NMD.

Processes device scan analysis results and generates backend alerts
for new devices, disconnected devices, and returned devices.
"""
from datetime import datetime
import threading
from typing import Any

from utils.logger import log_event


class AlertEngine:
    """Backend alert engine to track and generate device status alerts."""

    def __init__(self) -> None:
        self._alerts: list[dict[str, Any]] = []
        self._lock = threading.Lock()

    def process_scan_result(self, analysis_result: dict[str, Any]) -> list[dict[str, Any]]:
        """Process scan results returned by core.analyzer.analyze_scan().

        Generates alert objects for new, disconnected, and returned devices.

        Args:
            analysis_result: Dict containing 'new', 'returned', 'disconnected',
                'timestamp' keys.

        Returns:
            List of newly generated alert dictionaries for this scan.
        """
        if not isinstance(analysis_result, dict):
            log_event("AlertEngine received invalid scan result format.", "error")
            return []

        timestamp = analysis_result.get("timestamp") or datetime.utcnow().isoformat()
        new_ips = analysis_result.get("new", [])
        returned_ips = analysis_result.get("returned", [])
        disconnected_ips = analysis_result.get("disconnected", [])

        generated_alerts: list[dict[str, Any]] = []

        # Process NEW devices
        for ip in new_ips:
            alert = {
                "type": "NEW_DEVICE",
                "message": f"New device detected: {ip}",
                "ip": ip,
                "timestamp": timestamp,
            }
            generated_alerts.append(alert)
            log_event(alert["message"], "info")

        # Process RETURNED devices
        for ip in returned_ips:
            alert = {
                "type": "RETURNED",
                "message": f"Device returned online: {ip}",
                "ip": ip,
                "timestamp": timestamp,
            }
            generated_alerts.append(alert)
            log_event(alert["message"], "info")

        # Process DISCONNECTED devices
        for ip in disconnected_ips:
            alert = {
                "type": "DISCONNECTED",
                "message": f"Device disconnected: {ip}",
                "ip": ip,
                "timestamp": timestamp,
            }
            generated_alerts.append(alert)
            log_event(alert["message"], "warning")

        with self._lock:
            self._alerts.extend(generated_alerts)

        return generated_alerts

    def get_alerts(self, limit: int | None = None) -> list[dict[str, Any]]:
        """Return generated alerts, newest first.

        Args:
            limit: Maximum number of alerts to return (None for all).
        """
        with self._lock:
            # Return reversed list (newest first)
            alerts_copy = list(reversed(self._alerts))

        if limit is not None and limit > 0:
            return alerts_copy[:limit]
        return alerts_copy

    def clear_alerts(self) -> None:
        """Clear all stored alerts."""
        with self._lock:
            self._alerts.clear()
        log_event("Alert memory cleared.", "info")
