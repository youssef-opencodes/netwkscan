"""Dashboard Page (PySide6) for NMD.

Displays application status, real-time metrics (active devices, total scans,
vulnerability counts, alert summary), recent scan history table, and quick scan trigger.
"""

from __future__ import annotations

from typing import Callable, Any
from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QFrame, QTableWidget, QTableWidgetItem, QHeaderView, QGridLayout
)

from core.database import get_all_devices, get_scan_history, get_vulnerabilities
from core.scanner import find_nmap_binary, is_admin
from utils.config import load_config


class DashboardPage(QWidget):
    """Main application dashboard with real-time statistics and scan history."""

    def __init__(self, on_quick_scan_clicked: Callable[[], None] | None = None, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.on_quick_scan_clicked = on_quick_scan_clicked
        self._init_ui()

        # Auto-refresh timer every 5 seconds
        self._timer = QTimer(self)
        self._timer.timeout.connect(self.refresh_data)
        self._timer.start(5000)

    def _init_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(20)

        # Header Section
        header_layout = QHBoxLayout()
        header_text_layout = QVBoxLayout()

        title = QLabel("Dashboard")
        title.setObjectName("TitleLabel")
        subtitle = QLabel("Overview of network monitoring, active assets, and security assessment statistics.")
        subtitle.setObjectName("SubtitleLabel")

        header_text_layout.addWidget(title)
        header_text_layout.addWidget(subtitle)
        header_layout.addLayout(header_text_layout)
        header_layout.addStretch()

        self.btn_quick_scan = QPushButton("⚡ Launch Quick Scan")
        self.btn_quick_scan.setObjectName("PrimaryButton")
        if self.on_quick_scan_clicked:
            self.btn_quick_scan.clicked.connect(self.on_quick_scan_clicked)
        header_layout.addWidget(self.btn_quick_scan)

        layout.addLayout(header_layout)

        # Stat Cards Grid (4 Cards)
        grid_layout = QGridLayout()
        grid_layout.setSpacing(16)

        self.card_active_devices = self._create_stat_card("Active Devices", "0", "Online hosts detected", "#3B82F6")
        self.card_vulnerabilities = self._create_stat_card("Vulnerabilities", "0", "Detected CVEs / Security Risks", "#EF4444")
        self.card_total_scans = self._create_stat_card("Total Scans", "0", "Completed discovery scans", "#10B981")
        self.card_nmap_status = self._create_stat_card("Nmap Engine", "Checking...", "Subprocess engine", "#8B5CF6")

        grid_layout.addWidget(self.card_active_devices, 0, 0)
        grid_layout.addWidget(self.card_vulnerabilities, 0, 1)
        grid_layout.addWidget(self.card_total_scans, 0, 2)
        grid_layout.addWidget(self.card_nmap_status, 0, 3)

        layout.addLayout(grid_layout)

        # Content Split: Left Table (Recent Devices), Right Table (Recent Scans)
        tables_layout = QHBoxLayout()
        tables_layout.setSpacing(16)

        # Left Card: Recent Devices
        left_card = QFrame()
        left_card.setObjectName("CardFrame")
        left_box = QVBoxLayout(left_card)
        left_box.setContentsMargins(16, 16, 16, 16)

        left_title = QLabel("Discovered Assets (Devices)")
        left_title.setStyleSheet("font-size: 15px; font-weight: bold; color: #F8FAFC;")
        left_box.addWidget(left_title)

        self.tbl_devices = QTableWidget(0, 4)
        self.tbl_devices.setHorizontalHeaderLabels(["IP Address", "Hostname", "Type", "Status"])
        self.tbl_devices.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.tbl_devices.setSelectionBehavior(QTableWidget.SelectRows)
        self.tbl_devices.setEditTriggers(QTableWidget.NoEditTriggers)
        left_box.addWidget(self.tbl_devices)

        # Right Card: Recent Scans History
        right_card = QFrame()
        right_card.setObjectName("CardFrame")
        right_box = QVBoxLayout(right_card)
        right_box.setContentsMargins(16, 16, 16, 16)

        right_title = QLabel("Recent Scan History")
        right_title.setStyleSheet("font-size: 15px; font-weight: bold; color: #F8FAFC;")
        right_box.addWidget(right_title)

        self.tbl_scans = QTableWidget(0, 4)
        self.tbl_scans.setHorizontalHeaderLabels(["Date", "Duration", "Hosts Found", "Command"])
        self.tbl_scans.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.tbl_scans.setSelectionBehavior(QTableWidget.SelectRows)
        self.tbl_scans.setEditTriggers(QTableWidget.NoEditTriggers)
        right_box.addWidget(self.tbl_scans)

        tables_layout.addWidget(left_card, 1)
        tables_layout.addWidget(right_card, 1)

        layout.addLayout(tables_layout, 1)

        self.refresh_data()

    def _create_stat_card(self, title_text: str, value_text: str, subtitle_text: str, accent_color: str) -> QFrame:
        card = QFrame()
        card.setObjectName("CardFrame")
        box = QVBoxLayout(card)
        box.setContentsMargins(16, 16, 16, 16)

        lbl_title = QLabel(title_text)
        lbl_title.setObjectName("StatLabel")

        lbl_value = QLabel(value_text)
        lbl_value.setObjectName("StatValue")
        lbl_value.setStyleSheet(f"font-size: 26px; font-weight: bold; color: {accent_color};")

        lbl_subtitle = QLabel(subtitle_text)
        lbl_subtitle.setObjectName("SubtitleLabel")
        lbl_subtitle.setStyleSheet("font-size: 11px; color: #94A3B8;")

        box.addWidget(lbl_title)
        box.addWidget(lbl_value)
        box.addWidget(lbl_subtitle)

        # Store value label reference dynamically
        setattr(card, "lbl_value", lbl_value)
        setattr(card, "lbl_subtitle", lbl_subtitle)
        return card

    def refresh_data(self) -> None:
        """Fetch real data from SQLite database and update cards & tables."""
        # 1. Fetch devices
        devices = get_all_devices()
        online_count = sum(1 for d in devices if d.status == "online")
        self.card_active_devices.lbl_value.setText(str(online_count))
        self.card_active_devices.lbl_subtitle.setText(f"{len(devices)} total registered")

        # 2. Fetch vulnerabilities
        vulns = get_vulnerabilities(limit=500)
        self.card_vulnerabilities.lbl_value.setText(str(len(vulns)))
        critical_high = sum(1 for v in vulns if (v.severity or "").upper() in ("CRITICAL", "HIGH"))
        self.card_vulnerabilities.lbl_subtitle.setText(f"{critical_high} Critical/High severity")

        # 3. Fetch scans history
        scans = get_scan_history(limit=50)
        self.card_total_scans.lbl_value.setText(str(len(scans)))
        last_date = scans[0].scan_date.strftime("%Y-%m-%d %H:%M") if scans else "None"
        self.card_total_scans.lbl_subtitle.setText(f"Last: {last_date}")

        # 4. Engine Nmap status
        nmap_path = find_nmap_binary()
        user_admin = is_admin()
        if nmap_path:
            self.card_nmap_status.lbl_value.setText("Available")
            self.card_nmap_status.lbl_value.setStyleSheet("font-size: 24px; font-weight: bold; color: #10B981;")
            self.card_nmap_status.lbl_subtitle.setText("Privileges: " + ("Admin" if user_admin else "Standard User"))
        else:
            self.card_nmap_status.lbl_value.setText("Not Installed")
            self.card_nmap_status.lbl_value.setStyleSheet("font-size: 24px; font-weight: bold; color: #EF4444;")
            self.card_nmap_status.lbl_subtitle.setText("Please install Nmap")

        # Populate Recent Devices Table
        self.tbl_devices.setRowCount(0)
        for dev in devices[:15]:
            row = self.tbl_devices.rowCount()
            self.tbl_devices.insertRow(row)

            self.tbl_devices.setItem(row, 0, QTableWidgetItem(dev.ip or "—"))
            self.tbl_devices.setItem(row, 1, QTableWidgetItem(dev.hostname or "—"))
            self.tbl_devices.setItem(row, 2, QTableWidgetItem(dev.device_type or "Unknown"))

            item_status = QTableWidgetItem(dev.status or "offline")
            if dev.status == "online":
                item_status.setForeground(Qt.green)
            else:
                item_status.setForeground(Qt.gray)
            self.tbl_devices.setItem(row, 3, item_status)

        # Populate Recent Scans Table
        self.tbl_scans.setRowCount(0)
        for scan in scans[:15]:
            row = self.tbl_scans.rowCount()
            self.tbl_scans.insertRow(row)

            dt_str = scan.scan_date.strftime("%Y-%m-%d %H:%M:%S") if scan.scan_date else "—"
            dur_str = f"{scan.duration:.2f}s" if scan.duration is not None else "—"

            self.tbl_scans.setItem(row, 0, QTableWidgetItem(dt_str))
            self.tbl_scans.setItem(row, 1, QTableWidgetItem(dur_str))
            self.tbl_scans.setItem(row, 2, QTableWidgetItem(str(scan.total_devices or 0)))
            self.tbl_scans.setItem(row, 3, QTableWidgetItem(scan.scan_command or "nmap scan"))
