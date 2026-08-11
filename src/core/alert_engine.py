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
        self._previous_ports: dict[str, dict[str, str]] = {}
        self._lock = threading.Lock()

    def process_scan_result(self, analysis_result: dict[str, Any]) -> list[dict[str, Any]]:
        """Process scan results returned by core.analyzer.analyze_scan().

        Generates alert objects for new, disconnected, and returned devices,
        as well as new open ports, closed ports, and service changes.

        Args:
            analysis_result: Dict containing 'new', 'returned', 'disconnected',
                'timestamp', and optional 'scan_results' or 'devices' keys.

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

        # Process PORT and SERVICE changes
        scan_devices = analysis_result.get("scan_results") or analysis_result.get("devices") or []
        for dev in scan_devices:
            if not isinstance(dev, dict):
                continue
            ip = dev.get("ip")
            if not ip or "ports" not in dev:
                continue

            current_ports = dev.get("ports") or {}
            if not isinstance(current_ports, dict):
                continue

            port_alerts = self._analyze_port_changes(ip, current_ports, timestamp)
            generated_alerts.extend(port_alerts)

        # Process VULNERABILITIES if present in analysis
        vulnerabilities = analysis_result.get("vulnerabilities", [])
        if vulnerabilities:
            vuln_alerts = self.process_vulnerability_results(vulnerabilities, timestamp)
            generated_alerts.extend(vuln_alerts)

        with self._lock:
            self._alerts.extend(generated_alerts)

        return generated_alerts

    def process_vulnerability_results(
        self, vulnerabilities: list[dict[str, Any]], timestamp: str | None = None
    ) -> list[dict[str, Any]]:
        """Generate NEW_VULNERABILITY_DETECTED alert dictionaries."""
        ts = timestamp or datetime.utcnow().isoformat()
        alerts: list[dict[str, Any]] = []

        for v in vulnerabilities:
            if not isinstance(v, dict):
                continue
            host = v.get("host")
            port = v.get("port")
            cve = v.get("cve") or "N/A"
            title = v.get("title", "Vulnerability Finding")
            severity = (v.get("severity") or "UNKNOWN").upper()

            alert = {
                "type": "NEW_VULNERABILITY_DETECTED",
                "message": f"New vulnerability detected on {host}:{port or 'host'} - [{severity}] {title} ({cve})",
                "ip": host,
                "port": port,
                "cve": cve,
                "title": title,
                "severity": severity,
                "timestamp": ts,
            }
            alerts.append(alert)
            log_event(alert["message"], "warning")

        with self._lock:
            self._alerts.extend(alerts)

        return alerts


    def _analyze_port_changes(
        self, ip: str, current_ports: dict[str, str], timestamp: str
    ) -> list[dict[str, Any]]:
        """Compare previous and current open ports for a device and return port alert dicts."""
        alerts: list[dict[str, Any]] = []

        with self._lock:
            if ip not in self._previous_ports:
                self._previous_ports[ip] = current_ports.copy()
                return alerts
            prev_ports = self._previous_ports[ip]

        # 1. Detect New Open Ports ("New Open Port Detected")
        added_ports = set(current_ports.keys()) - set(prev_ports.keys())
        for port in sorted(added_ports, key=lambda x: int(x) if x.isdigit() else x):
            svc = current_ports[port]
            alert = {
                "type": "NEW_OPEN_PORT",
                "message": f"New Open Port Detected on {ip}: {port} ({svc})",
                "ip": ip,
                "port": port,
                "service": svc,
                "timestamp": timestamp,
            }
            alerts.append(alert)
            log_event(alert["message"], "warning")

        # 2. Detect Closed Ports ("Port Closed")
        closed_ports = set(prev_ports.keys()) - set(current_ports.keys())
        for port in sorted(closed_ports, key=lambda x: int(x) if x.isdigit() else x):
            old_svc = prev_ports[port]
            alert = {
                "type": "PORT_CLOSED",
                "message": f"Port Closed on {ip}: {port} ({old_svc})",
                "ip": ip,
                "port": port,
                "service": old_svc,
                "timestamp": timestamp,
            }
            alerts.append(alert)
            log_event(alert["message"], "info")

        # 3. Detect Service Changes
        common_ports = set(current_ports.keys()) & set(prev_ports.keys())
        for port in sorted(common_ports, key=lambda x: int(x) if x.isdigit() else x):
            if prev_ports[port] != current_ports[port]:
                alert = {
                    "type": "SERVICE_CHANGED",
                    "message": f"Service changed on {ip} port {port}: {prev_ports[port]} -> {current_ports[port]}",
                    "ip": ip,
                    "port": port,
                    "old_service": prev_ports[port],
                    "new_service": current_ports[port],
                    "timestamp": timestamp,
                }
                alerts.append(alert)
                log_event(alert["message"], "warning")

        # Update historical cache
        with self._lock:
            self._previous_ports[ip] = current_ports.copy()

        return alerts


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
