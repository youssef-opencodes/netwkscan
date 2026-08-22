"""About Page (PySide6) for NMD.

Displays application metadata, version information, runtime environment details,
Nmap detection status, and legal/security disclaimers.
"""

from __future__ import annotations

import platform
import sys
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QWidget, QVBoxLayout, QLabel, QFrame, QTextEdit

from core.scanner import find_nmap_binary, is_admin


class AboutPage(QWidget):
    """Application metadata, system diagnostics, and credits page."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._init_ui()

    def _init_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(18)

        # Header
        title = QLabel("About NMD")
        title.setObjectName("TitleLabel")
        subtitle = QLabel("Network Monitoring Dashboard — Professional Cyber Security Assessment Tool")
        subtitle.setObjectName("SubtitleLabel")

        layout.addWidget(title)
        layout.addWidget(subtitle)

        # Info Card Frame
        card = QFrame()
        card.setObjectName("CardFrame")
        box = QVBoxLayout(card)
        box.setContentsMargins(20, 20, 20, 20)
        box.setSpacing(12)

        nmap_path = find_nmap_binary() or "Not Installed / Not Found"
        admin_str = "Administrator (Elevated)" if is_admin() else "Standard User (Non-Elevated)"

        info_text = f"""================================================================================
  NMD — NETWORK MONITORING DASHBOARD (v1.0.0)
================================================================================

Description:
  An industrial-grade desktop application for network discovery, active host tracking,
  open port mapping, service version fingerprinting, and authorized vulnerability assessments.

Runtime Environment Diagnostics:
  - Python Version   : {platform.python_version()} ({platform.architecture()[0]})
  - Operating System : {platform.system()} {platform.release()} ({platform.version()})
  - Host Architecture: {platform.machine()}
  - Nmap Executable  : {nmap_path}
  - Process Privileges: {admin_str}

Key Capabilities:
  - Non-blocking PySide6 Qt GUI with multi-threaded QThread workers.
  - Integration with native Nmap binary for XML output parsing (-oX -).
  - Safe authorized NSE vulnerability detection (--script vuln).
  - SQLite persistence for devices, scan history, and vulnerabilities.
  - Multi-format report generation (ReportLab PDF, ASCII TXT, CSV, JSON).

================================================================================
  AUTHORIZATION & LEGAL DISCLAIMER
================================================================================
  IMPORTANT: Only run scanning procedures against hosts, networks, and subnets
  that you own or have explicit written authorization to assess.
  Unauthorized port scanning or security testing may violate local and international
  computer mis-use laws.

  Nmap® is a registered trademark of Insecure.Com LLC.
  Copyright © 2026 NMD Development Team. All rights reserved.
================================================================================
"""

        txt_info = QTextEdit()
        txt_info.setObjectName("LogConsole")
        txt_info.setReadOnly(True)
        txt_info.setText(info_text)

        box.addWidget(txt_info)
        layout.addWidget(card, 1)
