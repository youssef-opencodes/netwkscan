"""Scan Page (PySide6) for NMD.

Provides target configuration, scan type selection (Quick, Full, Vulnerability, Custom),
timing and port settings, Start/Stop controls, non-blocking execution via workers,
progress bar, and real-time log streaming terminal.
"""

from __future__ import annotations

from typing import Any
from PySide6.QtCore import Qt, QTime
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QComboBox,
    QPushButton, QProgressBar, QTextEdit, QFrame, QMessageBox, QGridLayout
)

from gui.workers import ScanWorker, VulnerabilityScanWorker
from utils.config import detect_gateway, load_config
from utils.logger import log_event


class ScanPage(QWidget):
    """Network scan execution page with real-time logging and non-blocking workers."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._active_worker: ScanWorker | VulnerabilityScanWorker | None = None
        self._active_workers: set[ScanWorker | VulnerabilityScanWorker] = set()
        self._init_ui()

    def _cleanup_worker(self, worker: ScanWorker | VulnerabilityScanWorker) -> None:
        """Clean up the worker safely after thread execution finishes."""
        try:
            if worker.isRunning():
                worker.quit()
                worker.wait()
        except Exception as err:
            log_event(f"Error during scan worker cleanup: {err}", "warning")
        if worker in self._active_workers:
            self._active_workers.remove(worker)
        if self._active_worker == worker:
            self._active_worker = None
        worker.deleteLater()

    def closeEvent(self, event: Any) -> None:
        """Clean up active scan workers when widget is closed/destroyed."""
        for worker in list(self._active_workers):
            try:
                if worker.isRunning():
                    worker.cancel()
                    worker.quit()
                    worker.wait()
            except Exception:
                pass
            worker.deleteLater()
        self._active_workers.clear()
        super().closeEvent(event)

    def _init_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(18)

        # Header
        title = QLabel("Network Scan Engine")
        title.setObjectName("TitleLabel")
        subtitle = QLabel("Configure and execute authorized network discovery and vulnerability assessment scans.")
        subtitle.setObjectName("SubtitleLabel")

        layout.addWidget(title)
        layout.addWidget(subtitle)

        # Config Card Frame
        config_card = QFrame()
        config_card.setObjectName("CardFrame")
        grid = QGridLayout(config_card)
        grid.setContentsMargins(20, 20, 20, 20)
        grid.setSpacing(14)

        # Target IP / Subnet
        grid.addWidget(QLabel("Target IP / Subnet CIDR:"), 0, 0)

        target_box = QHBoxLayout()
        self.txt_target = QLineEdit()
        self.txt_target.setPlaceholderText("e.g. 192.168.1.0/24 or 192.168.1.10")

        cfg = load_config()
        self.txt_target.setText(cfg.get("subnet", "192.168.1.0/24"))

        btn_auto_detect = QPushButton("Auto-Detect Gateway")
        btn_auto_detect.setObjectName("SecondaryButton")
        btn_auto_detect.clicked.connect(self._on_auto_detect)

        target_box.addWidget(self.txt_target, 1)
        target_box.addWidget(btn_auto_detect)

        grid.addLayout(target_box, 0, 1)

        # Scan Type Combo
        grid.addWidget(QLabel("Scan Mode:"), 1, 0)
        self.cbo_type = QComboBox()
        self.cbo_type.addItems([
            "Quick Host Discovery (-sn)",
            "Full Service & OS Detection (-sV -O)",
            "Vulnerability Assessment (-sV --script vuln)",
            "Custom Scan Parameters",
        ])
        self.cbo_type.currentIndexChanged.connect(self._on_type_changed)
        grid.addWidget(self.cbo_type, 1, 1)

        # Ports Range
        grid.addWidget(QLabel("Port Range:"), 2, 0)
        self.txt_ports = QLineEdit("1-1024")
        self.txt_ports.setPlaceholderText("e.g. 1-1024, 80,443,22,3389")
        grid.addWidget(self.txt_ports, 2, 1)

        # Timing Template
        grid.addWidget(QLabel("Timing Template:"), 3, 0)
        self.cbo_timing = QComboBox()
        self.cbo_timing.addItems(["-T4 (Aggressive)", "-T3 (Normal)", "-T2 (Polite)", "-T5 (Insane)", "-T1 (Sneaky)"])
        grid.addWidget(self.cbo_timing, 3, 1)

        # Extra Nmap Arguments
        grid.addWidget(QLabel("Extra Nmap Arguments:"), 4, 0)
        self.txt_arguments = QLineEdit("-sV")
        self.txt_arguments.setPlaceholderText("e.g. --script-timeout 30s -v")
        grid.addWidget(self.txt_arguments, 4, 1)

        layout.addWidget(config_card)

        # Actions & Controls Layout
        controls_layout = QHBoxLayout()

        self.btn_start = QPushButton("▶ Start Scan")
        self.btn_start.setObjectName("PrimaryButton")
        self.btn_start.setStyleSheet("padding: 10px 24px; font-size: 14px;")
        self.btn_start.clicked.connect(self.start_scan)

        self.btn_stop = QPushButton("⏹ Stop / Cancel")
        self.btn_stop.setObjectName("DangerButton")
        self.btn_stop.setStyleSheet("padding: 10px 24px; font-size: 14px;")
        self.btn_stop.setEnabled(False)
        self.btn_stop.clicked.connect(self.stop_scan)

        controls_layout.addWidget(self.btn_start)
        controls_layout.addWidget(self.btn_stop)
        controls_layout.addStretch()

        layout.addLayout(controls_layout)

        # Progress Bar & Status
        self.lbl_status = QLabel("Status: Idle")
        self.lbl_status.setStyleSheet("font-size: 13px; font-weight: bold; color: #94A3B8;")
        layout.addWidget(self.lbl_status)

        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                background-color: #1E293B;
                border: 1px solid #334155;
                border-radius: 6px;
                text-align: center;
                color: #F8FAFC;
            }
            QProgressBar::chunk {
                background-color: #3B82F6;
                border-radius: 5px;
            }
        """)
        layout.addWidget(self.progress_bar)

        # Real-time Log Console Widget
        log_card = QFrame()
        log_card.setObjectName("CardFrame")
        log_box = QVBoxLayout(log_card)
        log_box.setContentsMargins(12, 12, 12, 12)

        log_header = QLabel("Real-Time Execution Log")
        log_header.setStyleSheet("font-size: 13px; font-weight: bold; color: #94A3B8;")
        log_box.addWidget(log_header)

        self.txt_console = QTextEdit()
        self.txt_console.setObjectName("LogConsole")
        self.txt_console.setReadOnly(True)
        log_box.addWidget(self.txt_console)

        layout.addWidget(log_card, 1)

    def _on_auto_detect(self) -> None:
        detected = detect_gateway()
        self.txt_target.setText(detected)
        self.append_log(f"[INFO] Auto-detected default gateway subnet: {detected}")

    def _on_type_changed(self, idx: int) -> None:
        if idx == 0:  # Quick
            self.txt_ports.setEnabled(False)
            self.txt_arguments.setText("-sn")
            self.txt_arguments.setEnabled(False)
        elif idx == 1:  # Full
            self.txt_ports.setEnabled(True)
            self.txt_arguments.setText("-sV -O")
            self.txt_arguments.setEnabled(True)
        elif idx == 2:  # Vulnerability
            self.txt_ports.setEnabled(True)
            self.txt_arguments.setText("-sV --script vuln")
            self.txt_arguments.setEnabled(True)
        else:  # Custom
            self.txt_ports.setEnabled(True)
            self.txt_arguments.setEnabled(True)

    def append_log(self, text: str) -> None:
        ts = QTime.currentTime().toString("hh:mm:ss")
        self.txt_console.append(f"[{ts}] {text}")
        # Auto scroll to bottom
        scrollbar = self.txt_console.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())

    def start_scan(self) -> None:
        target = self.txt_target.text().strip()
        if not target:
            QMessageBox.warning(self, "Validation Error", "Please specify a target IP address or CIDR subnet.")
            return

        mode_idx = self.cbo_type.currentIndex()
        ports = self.txt_ports.text().strip() if self.txt_ports.isEnabled() else None
        args = self.txt_arguments.text().strip() if self.txt_arguments.isEnabled() else None
        timing_str = self.cbo_timing.currentText().split()[0]  # e.g. -T4

        self.btn_start.setEnabled(False)
        self.btn_stop.setEnabled(True)
        self.progress_bar.setValue(5)
        self.lbl_status.setText("Status: Scanning in progress...")
        self.append_log(f"[START] Initiating scan sequence on target: {target}")

        if mode_idx == 2:  # Vulnerability Scan Mode
            worker = VulnerabilityScanWorker(
                target=target,
                ports=ports or "1-1024",
                scripts="vuln",
                timeout=300.0,
                parent=self,
            )
            self._active_worker = worker
            self._active_workers.add(worker)
            worker.progress.connect(self._on_worker_progress)
            worker.log_line.connect(self.append_log)
            worker.vuln_finished.connect(self._on_vuln_finished)
            worker.vuln_error.connect(self._on_worker_error)
            worker.finished.connect(lambda w=worker: self._cleanup_worker(w))
            worker.start()
        else:  # Quick, Full, or Custom Scan Mode
            worker = ScanWorker(
                target=target,
                ports=ports,
                arguments=args,
                timing=timing_str,
                parent=self,
            )
            self._active_worker = worker
            self._active_workers.add(worker)
            worker.progress.connect(self._on_worker_progress)
            worker.log_line.connect(self.append_log)
            worker.scan_finished.connect(self._on_scan_finished)
            worker.scan_error.connect(self._on_worker_error)
            worker.finished.connect(lambda w=worker: self._cleanup_worker(w))
            worker.start()

    def stop_scan(self) -> None:
        if self._active_worker and self._active_worker.isRunning():
            self._active_worker.cancel()
            self.append_log("[WARNING] Termination signal sent to Nmap worker.")

    def _on_worker_progress(self, percent: int, msg: str) -> None:
        self.progress_bar.setValue(percent)
        self.lbl_status.setText(f"Status: {msg}")

    def _on_scan_finished(self, analysis: dict) -> None:
        self.progress_bar.setValue(100)
        new_cnt = len(analysis.get("new", []))
        total_cnt = len(analysis.get("seen_ips", []))
        self.lbl_status.setText(f"Status: Finished. Discovered {total_cnt} hosts ({new_cnt} new).")
        self.append_log(f"[SUCCESS] Scan completed. Total active hosts: {total_cnt}")
        self._reset_buttons()

    def _on_vuln_finished(self, vulns: list, duration: float, command: str) -> None:
        self.progress_bar.setValue(100)
        self.lbl_status.setText(f"Status: Vulnerability assessment completed. Findings: {len(vulns)}")
        self.append_log(f"[SUCCESS] Assessment finished in {duration:.2f}s. Vulnerabilities detected: {len(vulns)}")
        self._reset_buttons()

    def _on_worker_error(self, err_msg: str) -> None:
        self.progress_bar.setValue(0)
        self.lbl_status.setText(f"Status: Error - {err_msg}")
        self.append_log(f"[ERROR] Scan execution error: {err_msg}")
        QMessageBox.critical(self, "Scan Error", f"Scan failed: {err_msg}")
        self._reset_buttons()

    def _reset_buttons(self) -> None:
        self.btn_start.setEnabled(True)
        self.btn_stop.setEnabled(False)
