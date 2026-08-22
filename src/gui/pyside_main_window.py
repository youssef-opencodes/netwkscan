"""Main Window (PySide6) for NMD.

Provides top-level window container, dark cybersecurity sidebar navigation,
QStackedWidget page swapping, status bar diagnostics, and scheduler controls.
"""

from __future__ import annotations

import os
from typing import Any
from PySide6.QtCore import Qt, QSize
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QStackedWidget, QFrame, QStatusBar, QMessageBox
)

from core.scanner import find_nmap_binary, is_admin
from core.scheduler import NetworkScheduler
from gui.pages.pyside_about import AboutPage
from gui.pages.pyside_dashboard import DashboardPage
from gui.pages.pyside_reports import ReportsPage
from gui.pages.pyside_results import ResultsPage
from gui.pages.pyside_scan import ScanPage
from gui.pages.pyside_settings import SettingsPage
from gui.theme import MODERN_QSS
from utils.logger import log_event
from utils.paths import get_resource_path


class PySideMainWindow(QMainWindow):
    """NMD Main Desktop Window with PySide6 GUI."""

    def __init__(self) -> None:
        super().__init__()

        self.setWindowTitle("NMD — Network Monitoring Dashboard")
        self.resize(1240, 780)
        self.setMinimumSize(1024, 680)

        # Set Window Icon
        icon_path = get_resource_path("resources/icon.ico")
        if not os.path.exists(icon_path):
            icon_path = get_resource_path("resources/icon.png")
        if os.path.exists(icon_path):
            self.setWindowIcon(QIcon(icon_path))

        self.setStyleSheet(MODERN_QSS)

        self._scheduler: NetworkScheduler | None = None
        self._nav_buttons: dict[str, QPushButton] = {}

        self._init_ui()
        self._init_statusBar()

    def _init_ui(self) -> None:
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        main_layout = QHBoxLayout(central_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # Sidebar Frame
        sidebar = QFrame()
        sidebar.setObjectName("SidebarFrame")
        sidebar.setFixedWidth(220)

        sidebar_layout = QVBoxLayout(sidebar)
        sidebar_layout.setContentsMargins(12, 16, 12, 16)
        sidebar_layout.setSpacing(8)

        # App Brand Header
        brand_layout = QHBoxLayout()
        lbl_logo = QLabel("🛡️")
        lbl_logo.setStyleSheet("font-size: 22px;")
        lbl_title = QLabel("NMD")
        lbl_title.setStyleSheet("font-size: 22px; font-weight: bold; color: #3B82F6;")

        brand_layout.addWidget(lbl_logo)
        brand_layout.addWidget(lbl_title)
        brand_layout.addStretch()
        sidebar_layout.addLayout(brand_layout)

        sidebar_layout.addSpacing(16)

        # Navigation Buttons
        nav_items = [
            ("dashboard", "📊 Dashboard"),
            ("scan", "🔍 Scan Target"),
            ("results", "📑 Scan Results"),
            ("reports", "📄 Reports"),
            ("settings", "⚙️ Settings"),
            ("about", "ℹ️ About"),
        ]

        for key, label in nav_items:
            btn = QPushButton(label)
            btn.setObjectName("NavButton")
            btn.setCheckable(True)
            btn.clicked.connect(lambda checked, k=key: self.show_page(k))
            sidebar_layout.addWidget(btn)
            self._nav_buttons[key] = btn

        sidebar_layout.addStretch()

        # Scheduler Footer Widget
        footer_frame = QFrame()
        footer_frame.setObjectName("CardFrame")
        footer_box = QVBoxLayout(footer_frame)
        footer_box.setContentsMargins(10, 10, 10, 10)

        self.lbl_scheduler = QLabel("Scheduler: Stopped")
        self.lbl_scheduler.setStyleSheet("font-size: 11px; color: #94A3B8;")
        footer_box.addWidget(self.lbl_scheduler)

        self.btn_scheduler = QPushButton("Start Scheduler")
        self.btn_scheduler.setObjectName("SecondaryButton")
        self.btn_scheduler.setStyleSheet("font-size: 11px; padding: 4px;")
        self.btn_scheduler.clicked.connect(self.toggle_scheduler)
        footer_box.addWidget(self.btn_scheduler)

        sidebar_layout.addWidget(footer_frame)
        main_layout.addWidget(sidebar)

        # Stacked Pages Widget
        self.page_stack = QStackedWidget()

        # Instanciate Pages
        self.page_dashboard = DashboardPage(on_quick_scan_clicked=lambda: self.show_page("scan"))
        self.page_scan = ScanPage()
        self.page_results = ResultsPage()
        self.page_reports = ReportsPage()
        self.page_settings = SettingsPage()
        self.page_about = AboutPage()

        self.page_stack.addWidget(self.page_dashboard)  # 0
        self.page_stack.addWidget(self.page_scan)       # 1
        self.page_stack.addWidget(self.page_results)    # 2
        self.page_stack.addWidget(self.page_reports)    # 3
        self.page_stack.addWidget(self.page_settings)   # 4
        self.page_stack.addWidget(self.page_about)      # 5

        self.page_map = {
            "dashboard": 0,
            "scan": 1,
            "results": 2,
            "reports": 3,
            "settings": 4,
            "about": 5,
        }

        main_layout.addWidget(self.page_stack, 1)

        # Show Dashboard initially
        self.show_page("dashboard")

    def _init_statusBar(self) -> None:
        status_bar = QStatusBar()
        self.setStatusBar(status_bar)

        nmap_path = find_nmap_binary()
        nmap_str = f"Nmap: {nmap_path}" if nmap_path else "Nmap: NOT FOUND (Please install Nmap)"
        admin_str = "Privileges: Admin" if is_admin() else "Privileges: Standard User"

        status_bar.showMessage(f"Ready | {nmap_str} | {admin_str}")

    def show_page(self, key: str) -> None:
        idx = self.page_map.get(key, 0)
        self.page_stack.setCurrentIndex(idx)

        # Refresh page data if applicable
        if key == "dashboard":
            self.page_dashboard.refresh_data()
        elif key == "results":
            self.page_results.load_data()

        # Update button check states
        for k, btn in self._nav_buttons.items():
            btn.setChecked(k == key)

    def toggle_scheduler(self) -> None:
        if self._scheduler is None:
            self._scheduler = NetworkScheduler()

        if self._scheduler.is_running():
            self._scheduler.stop()
            self.lbl_scheduler.setText("Scheduler: Stopped")
            self.btn_scheduler.setText("Start Scheduler")
            log_event("Network scheduler stopped.", "info")
        else:
            self._scheduler.start()
            self.lbl_scheduler.setText("Scheduler: Running")
            self.btn_scheduler.setText("Stop Scheduler")
            log_event("Network scheduler started.", "info")

    def closeEvent(self, event: Any) -> None:
        if self._scheduler and self._scheduler.is_running():
            self._scheduler.stop()
        log_event("PySide6 Desktop Application closed cleanly.", "info")
        event.accept()
