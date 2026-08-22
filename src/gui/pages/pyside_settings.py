"""Settings Page (PySide6) for NMD.

Manages application parameters, network configuration, log level,
scan intervals, and database paths. Respects .env configuration overrides.
"""

from __future__ import annotations

from typing import Any
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QComboBox,
    QSpinBox, QPushButton, QFrame, QMessageBox, QGridLayout
)

from utils.config import load_config, save_config
from utils.paths import get_db_path, get_logs_dir


class SettingsPage(QWidget):
    """Application configuration and environment settings page."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._init_ui()

    def _init_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(20)

        # Header
        title = QLabel("Settings & Configuration")
        title.setObjectName("TitleLabel")
        subtitle = QLabel("Configure network monitoring defaults, scan intervals, audit log levels, and database options.")
        subtitle.setObjectName("SubtitleLabel")

        layout.addWidget(title)
        layout.addWidget(subtitle)

        # Settings Card
        card = QFrame()
        card.setObjectName("CardFrame")
        grid = QGridLayout(card)
        grid.setContentsMargins(20, 20, 20, 20)
        grid.setSpacing(16)

        # Subnet
        grid.addWidget(QLabel("Default Subnet / CIDR Target:"), 0, 0)
        self.txt_subnet = QLineEdit()
        grid.addWidget(self.txt_subnet, 0, 1)

        # Scan Interval (Seconds)
        grid.addWidget(QLabel("Scheduler Scan Interval (seconds):"), 1, 0)
        self.spin_interval = QSpinBox()
        self.spin_interval.setRange(10, 86400)
        grid.addWidget(self.spin_interval, 1, 1)

        # Default Scan Type
        grid.addWidget(QLabel("Default Scan Type:"), 2, 0)
        self.cbo_scan_type = QComboBox()
        self.cbo_scan_type.addItems(["quick", "full", "custom", "vulnerability"])
        grid.addWidget(self.cbo_scan_type, 2, 1)

        # Port Range
        grid.addWidget(QLabel("Default Port Range:"), 3, 0)
        self.txt_ports = QLineEdit()
        grid.addWidget(self.txt_ports, 3, 1)

        # Log Level
        grid.addWidget(QLabel("Audit Log Level (NMD_LOG_LEVEL):"), 4, 0)
        self.cbo_log_level = QComboBox()
        self.cbo_log_level.addItems(["INFO", "DEBUG", "WARNING", "ERROR"])
        grid.addWidget(self.cbo_log_level, 4, 1)

        # Read-only Database Path
        grid.addWidget(QLabel("Active SQLite Database Path:"), 5, 0)
        self.lbl_db_path = QLineEdit(get_db_path())
        self.lbl_db_path.setReadOnly(True)
        grid.addWidget(self.lbl_db_path, 5, 1)

        # Read-only Log Path
        grid.addWidget(QLabel("Audit Logs Directory:"), 6, 0)
        self.lbl_log_path = QLineEdit(get_logs_dir())
        self.lbl_log_path.setReadOnly(True)
        grid.addWidget(self.lbl_log_path, 6, 1)

        layout.addWidget(card)

        # Actions Layout
        btn_layout = QHBoxLayout()
        btn_save = QPushButton("💾 Save Configuration")
        btn_save.setObjectName("PrimaryButton")
        btn_save.clicked.connect(self.save_settings)

        btn_reload = QPushButton("🔄 Reload Defaults")
        btn_reload.setObjectName("SecondaryButton")
        btn_reload.clicked.connect(self.load_settings)

        btn_layout.addWidget(btn_save)
        btn_layout.addWidget(btn_reload)
        btn_layout.addStretch()

        layout.addLayout(btn_layout)
        layout.addStretch()

        self.load_settings()

    def load_settings(self) -> None:
        cfg = load_config()
        self.txt_subnet.setText(cfg.get("subnet", "192.168.1.0/24"))
        self.spin_interval.setValue(int(cfg.get("scan_interval", 60)))

        st = cfg.get("scan_type", "quick")
        idx = self.cbo_scan_type.findText(st)
        if idx >= 0:
            self.cbo_scan_type.setCurrentIndex(idx)

        self.txt_ports.setText(cfg.get("port_range", "1-1024"))

    def save_settings(self) -> None:
        cfg = load_config()
        cfg["subnet"] = self.txt_subnet.text().strip()
        cfg["scan_interval"] = self.spin_interval.value()
        cfg["scan_type"] = self.cbo_scan_type.currentText()
        cfg["port_range"] = self.txt_ports.text().strip()

        success = save_config(cfg)
        if success:
            QMessageBox.information(self, "Settings Saved", "Configuration parameters successfully saved to data/config.json.")
        else:
            QMessageBox.critical(self, "Save Error", "Failed to save configuration due to validation errors.")
