"""Results Page (PySide6) for NMD.

Provides tabular data exploration for discovered devices and vulnerability findings,
with search, severity/status filtering, column sorting, and technical details popup dialogs.
"""

from __future__ import annotations

from typing import Any
from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QComboBox,
    QPushButton, QTableWidget, QTableWidgetItem, QHeaderView, QTabWidget,
    QDialog, QTextEdit, QFrame, QSplitter
)

from core.database import get_all_devices, get_vulnerabilities, get_vulnerabilities_by_host


class ResultsPage(QWidget):
    """Scan results exploration page with search, filters, and detailed view."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._init_ui()

    def _init_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        # Header
        title = QLabel("Scan Results & Asset Findings")
        title.setObjectName("TitleLabel")
        subtitle = QLabel("Browse discovered network devices, open ports, OS fingerprints, and detected vulnerabilities.")
        subtitle.setObjectName("SubtitleLabel")

        layout.addWidget(title)
        layout.addWidget(subtitle)

        # Filter & Search Bar Layout
        filter_layout = QHBoxLayout()
        filter_layout.setSpacing(12)

        self.txt_search = QLineEdit()
        self.txt_search.setPlaceholderText("🔍 Search by IP, hostname, OS, CVE, or title...")
        self.txt_search.textChanged.connect(self.apply_filters)
        filter_layout.addWidget(self.txt_search, 1)

        self.cbo_filter = QComboBox()
        self.cbo_filter.addItems(["All Items", "Online Devices Only", "Offline Devices Only", "CRITICAL / HIGH Vulns", "MEDIUM / LOW Vulns"])
        self.cbo_filter.currentIndexChanged.connect(self.apply_filters)
        filter_layout.addWidget(self.cbo_filter)

        btn_refresh = QPushButton("🔄 Refresh Data")
        btn_refresh.setObjectName("SecondaryButton")
        btn_refresh.clicked.connect(self.load_data)
        filter_layout.addWidget(btn_refresh)

        layout.addLayout(filter_layout)

        # Tab Widget (Tab 1: Discovered Devices, Tab 2: Vulnerabilities)
        self.tabs = QTabWidget()
        self.tabs.setStyleSheet("""
            QTabWidget::pane {
                border: 1px solid #334155;
                background-color: #1E293B;
                border-radius: 8px;
            }
            QTabBar::tab {
                background-color: #0F172A;
                color: #94A3B8;
                padding: 8px 16px;
                border-top-left-radius: 6px;
                border-top-right-radius: 6px;
                font-weight: 600;
            }
            QTabBar::tab:selected {
                background-color: #1E293B;
                color: #3B82F6;
                border-bottom: 2px solid #3B82F6;
            }
        """)

        # Devices Tab
        tab_devices_widget = QWidget()
        dev_layout = QVBoxLayout(tab_devices_widget)
        dev_layout.setContentsMargins(12, 12, 12, 12)

        self.tbl_devices = QTableWidget(0, 7)
        self.tbl_devices.setHorizontalHeaderLabels(["IP Address", "Hostname", "MAC Address", "Vendor", "OS Fingerprint", "Type", "Status"])
        self.tbl_devices.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.tbl_devices.setSelectionBehavior(QTableWidget.SelectRows)
        self.tbl_devices.setEditTriggers(QTableWidget.NoEditTriggers)
        self.tbl_devices.setSortingEnabled(True)
        self.tbl_devices.itemDoubleClicked.connect(self._on_device_double_clicked)
        dev_layout.addWidget(self.tbl_devices)

        self.tabs.addTab(tab_devices_widget, "🖥️ Discovered Devices")

        # Vulnerabilities Tab
        tab_vulns_widget = QWidget()
        vuln_layout = QVBoxLayout(tab_vulns_widget)
        vuln_layout.setContentsMargins(12, 12, 12, 12)

        self.tbl_vulns = QTableWidget(0, 7)
        self.tbl_vulns.setHorizontalHeaderLabels(["Severity", "CVE ID", "Title / Finding", "Target Host", "Port / Protocol", "CVSS", "Detection Script"])
        self.tbl_vulns.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.tbl_vulns.setSelectionBehavior(QTableWidget.SelectRows)
        self.tbl_vulns.setEditTriggers(QTableWidget.NoEditTriggers)
        self.tbl_vulns.setSortingEnabled(True)
        self.tbl_vulns.itemDoubleClicked.connect(self._on_vuln_double_clicked)
        vuln_layout.addWidget(self.tbl_vulns)

        self.tabs.addTab(tab_vulns_widget, "🛡️ Vulnerability Findings")

        layout.addWidget(self.tabs, 1)

        self._all_devices: list[dict] = []
        self._all_vulns: list[dict] = []
        self.load_data()

    def load_data(self) -> None:
        """Fetch fresh data from SQLite database."""
        db_devs = get_all_devices()
        self._all_devices = [d.to_dict() for d in db_devs]

        db_vulns = get_vulnerabilities(limit=1000)
        self._all_vulns = [v.to_dict() for v in db_vulns]

        self.apply_filters()

    def apply_filters(self) -> None:
        query = self.txt_search.text().strip().lower()
        filter_idx = self.cbo_filter.currentIndex()

        # Populate Devices Table
        self.tbl_devices.setSortingEnabled(False)
        self.tbl_devices.setRowCount(0)

        for dev in self._all_devices:
            ip = (dev.get("ip") or "").lower()
            hostname = (dev.get("hostname") or "").lower()
            os_info = (dev.get("os") or "").lower()
            status = dev.get("status") or "offline"

            if query and not (query in ip or query in hostname or query in os_info):
                continue

            if filter_idx == 1 and status != "online":
                continue
            if filter_idx == 2 and status != "offline":
                continue

            row = self.tbl_devices.rowCount()
            self.tbl_devices.insertRow(row)

            self.tbl_devices.setItem(row, 0, QTableWidgetItem(dev.get("ip") or "—"))
            self.tbl_devices.setItem(row, 1, QTableWidgetItem(dev.get("hostname") or "—"))
            self.tbl_devices.setItem(row, 2, QTableWidgetItem(dev.get("mac") or "—"))
            self.tbl_devices.setItem(row, 3, QTableWidgetItem(dev.get("vendor") or "—"))
            self.tbl_devices.setItem(row, 4, QTableWidgetItem(dev.get("os") or "—"))
            self.tbl_devices.setItem(row, 5, QTableWidgetItem(dev.get("device_type") or "Unknown"))

            item_status = QTableWidgetItem(status)
            item_status.setForeground(Qt.green if status == "online" else Qt.gray)
            self.tbl_devices.setItem(row, 6, item_status)

        self.tbl_devices.setSortingEnabled(True)

        # Populate Vulnerabilities Table
        self.tbl_vulns.setSortingEnabled(False)
        self.tbl_vulns.setRowCount(0)

        for v in self._all_vulns:
            sev = (v.get("severity") or "UNKNOWN").upper()
            cve = (v.get("cve") or "").lower()
            title = (v.get("title") or "").lower()
            host = (v.get("host") or "").lower()

            if query and not (query in cve or query in title or query in host or query in sev.lower()):
                continue

            if filter_idx == 3 and sev not in ("CRITICAL", "HIGH"):
                continue
            if filter_idx == 4 and sev not in ("MEDIUM", "LOW"):
                continue

            row = self.tbl_vulns.rowCount()
            self.tbl_vulns.insertRow(row)

            item_sev = QTableWidgetItem(sev)
            if sev == "CRITICAL":
                item_sev.setForeground(Qt.red)
            elif sev == "HIGH":
                item_sev.setForeground(Qt.darkRed)
            elif sev == "MEDIUM":
                item_sev.setForeground(Qt.darkYellow)
            elif sev == "LOW":
                item_sev.setForeground(Qt.blue)
            else:
                item_sev.setForeground(Qt.gray)

            port_str = f"{v.get('port')}/{v.get('protocol', 'tcp')}" if v.get("port") else "Host"
            cvss_val = v.get("cvss")
            cvss_str = f"{cvss_val:.1f}" if isinstance(cvss_val, (int, float)) else "N/A"

            self.tbl_vulns.setItem(row, 0, item_sev)
            self.tbl_vulns.setItem(row, 1, QTableWidgetItem(v.get("cve") or "N/A"))
            self.tbl_vulns.setItem(row, 2, QTableWidgetItem(v.get("title") or "—"))
            self.tbl_vulns.setItem(row, 3, QTableWidgetItem(v.get("host") or "—"))
            self.tbl_vulns.setItem(row, 4, QTableWidgetItem(port_str))
            self.tbl_vulns.setItem(row, 5, QTableWidgetItem(cvss_str))
            self.tbl_vulns.setItem(row, 6, QTableWidgetItem(v.get("script_name") or "Nmap NSE"))

        self.tbl_vulns.setSortingEnabled(True)

    def _on_device_double_clicked(self, item: QTableWidgetItem) -> None:
        row = item.row()
        ip = self.tbl_devices.item(row, 0).text()
        dev_data = next((d for d in self._all_devices if d.get("ip") == ip), None)
        if not dev_data:
            return

        dialog = QDialog(self)
        dialog.setWindowTitle(f"Device Technical Details — {ip}")
        dialog.resize(600, 450)

        box = QVBoxLayout(dialog)
        txt = QTextEdit()
        txt.setReadOnly(True)
        txt.setObjectName("LogConsole")

        ports_dict = dev_data.get("ports") or {}
        ports_str = "\n".join([f"  Port {p}: {svc}" for p, svc in ports_dict.items()]) if ports_dict else "  No open ports recorded"

        details_text = f"""==================================================
           DEVICE TECHNICAL SUMMARY
==================================================
IP Address       : {dev_data.get('ip')}
Hostname         : {dev_data.get('hostname') or 'N/A'}
MAC Address      : {dev_data.get('mac') or 'N/A'}
Vendor / NIC     : {dev_data.get('vendor') or 'N/A'}
OS Fingerprint   : {dev_data.get('os') or 'N/A'}
Device Type      : {dev_data.get('device_type') or 'Unknown'}
Status           : {dev_data.get('status')}
Appearance Count : {dev_data.get('appearance_count', 1)}
Last Seen        : {dev_data.get('last_seen')}

--------------------------------------------------
OPEN PORTS & SERVICES:
--------------------------------------------------
{ports_str}
==================================================
"""
        txt.setText(details_text)
        box.addWidget(txt)

        btn_close = QPushButton("Close")
        btn_close.clicked.connect(dialog.accept)
        box.addWidget(btn_close)

        dialog.exec()

    def _on_vuln_double_clicked(self, item: QTableWidgetItem) -> None:
        row = item.row()
        host = self.tbl_vulns.item(row, 3).text()
        cve = self.tbl_vulns.item(row, 1).text()
        title = self.tbl_vulns.item(row, 2).text()

        vuln_data = next((v for v in self._all_vulns if v.get("host") == host and (v.get("cve") == cve or v.get("title") == title)), None)
        if not vuln_data:
            return

        dialog = QDialog(self)
        dialog.setWindowTitle(f"Vulnerability Finding — {vuln_data.get('title')}")
        dialog.resize(650, 500)

        box = QVBoxLayout(dialog)
        txt = QTextEdit()
        txt.setReadOnly(True)
        txt.setObjectName("LogConsole")

        details_text = f"""==================================================
        VULNERABILITY FINDING DETAILS
==================================================
Title       : {vuln_data.get('title')}
Severity    : [{vuln_data.get('severity')}]
CVSS Score  : {vuln_data.get('cvss') or 'N/A'}
CVE ID      : {vuln_data.get('cve') or 'N/A'}
Target Host : {vuln_data.get('host')}:{vuln_data.get('port') or 'host'}
Script Name : {vuln_data.get('script_name')}
Detected At : {vuln_data.get('detected_at')}

--------------------------------------------------
DESCRIPTION:
--------------------------------------------------
{vuln_data.get('description') or 'No description available'}

--------------------------------------------------
NSE SCRIPT EVIDENCE OUTPUT:
--------------------------------------------------
{vuln_data.get('evidence') or 'No raw evidence captured'}
==================================================
"""
        txt.setText(details_text)
        box.addWidget(txt)

        btn_close = QPushButton("Close")
        btn_close.clicked.connect(dialog.accept)
        box.addWidget(btn_close)

        dialog.exec()
