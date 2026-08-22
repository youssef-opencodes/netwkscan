"""Reports & Export Page (PySide6) for NMD.

Integrates ReportLab PDF generators, ASCII TXT assessment reports, CSV device exports,
and JSON data exports with QFileDialog save dialogs and non-blocking ExportWorkers.
"""

from __future__ import annotations

import csv
import json
import os
from typing import Any
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QFrame, QFileDialog, QMessageBox, QGridLayout
)

from core.database import get_all_devices, get_vulnerabilities
from gui.workers import ExportWorker
from reports.vulnerability_report import generate_vulnerability_pdf_report, generate_vulnerability_txt_report
from utils.exporter import export_to_csv, export_to_pdf
from utils.logger import log_event
from utils.paths import get_reports_dir


class ReportsPage(QWidget):
    """Report generation and data export management page."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._active_workers: set[ExportWorker] = set()
        self._init_ui()

    def _cleanup_worker(self, worker: ExportWorker) -> None:
        """Clean up the worker after execution to free resources properly."""
        try:
            if worker.isRunning():
                worker.quit()
                worker.wait()
        except Exception as err:
            log_event(f"Error during export worker cleanup: {err}", "warning")
        if worker in self._active_workers:
            self._active_workers.remove(worker)
        worker.deleteLater()

    def closeEvent(self, event: Any) -> None:
        """Clean up active export workers when widget is closed/destroyed."""
        for worker in list(self._active_workers):
            try:
                if worker.isRunning():
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
        layout.setSpacing(20)

        # Header
        title = QLabel("Reports & Data Export Center")
        title.setObjectName("TitleLabel")
        subtitle = QLabel("Generate executive vulnerability reports, technical audit files, and export asset inventories.")
        subtitle.setObjectName("SubtitleLabel")

        layout.addWidget(title)
        layout.addWidget(subtitle)

        # Grid of Export Cards
        grid = QGridLayout()
        grid.setSpacing(16)

        # Card 1: Vulnerability PDF Executive Assessment Report
        card_vuln_pdf = self._create_report_card(
            "Vulnerability PDF Assessment Report",
            "Professional ReportLab PDF report containing executive summaries, severity breakdown matrices, and remediation recommendations.",
            "📄 Export PDF Report",
            self._export_vuln_pdf
        )
        grid.addWidget(card_vuln_pdf, 0, 0)

        # Card 2: Vulnerability ASCII TXT Assessment Report
        card_vuln_txt = self._create_report_card(
            "Vulnerability TXT Technical Report",
            "Clean formatted ASCII text assessment report suitable for technical documentation and offline review.",
            "📝 Export TXT Report",
            self._export_vuln_txt
        )
        grid.addWidget(card_vuln_txt, 0, 1)

        # Card 3: Vulnerability JSON Export
        card_vuln_json = self._create_report_card(
            "Vulnerability Findings JSON Export",
            "Complete raw JSON data dump of all vulnerability scan findings, CVE scores, and evidence.",
            "💾 Export JSON Data",
            self._export_vuln_json
        )
        grid.addWidget(card_vuln_json, 1, 0)

        # Card 4: Vulnerability CSV Export
        card_vuln_csv = self._create_report_card(
            "Vulnerability Findings CSV Export",
            "Tabular CSV export of detected vulnerabilities formatted for spreadsheet software (Excel, LibreOffice).",
            "📊 Export CSV File",
            self._export_vuln_csv
        )
        grid.addWidget(card_vuln_csv, 1, 1)

        # Card 5: Discovered Assets PDF Report
        card_dev_pdf = self._create_report_card(
            "Discovered Assets PDF Report",
            "Landscape PDF report listing all discovered network devices, IP addresses, MACs, OS types, and status.",
            "📄 Export Devices PDF",
            self._export_devices_pdf
        )
        grid.addWidget(card_dev_pdf, 2, 0)

        # Card 6: Discovered Assets CSV Inventory
        card_dev_csv = self._create_report_card(
            "Discovered Assets CSV Inventory",
            "Complete device inventory list exported in standard CSV format for asset management systems.",
            "📊 Export Devices CSV",
            self._export_devices_csv
        )
        grid.addWidget(card_dev_csv, 2, 1)

        layout.addLayout(grid)
        layout.addStretch()

    def _create_report_card(self, title: str, description: str, button_label: str, handler: Any) -> QFrame:
        card = QFrame()
        card.setObjectName("CardFrame")
        box = QVBoxLayout(card)
        box.setContentsMargins(18, 18, 18, 18)
        box.setSpacing(10)

        lbl_title = QLabel(title)
        lbl_title.setStyleSheet("font-size: 15px; font-weight: bold; color: #F8FAFC;")

        lbl_desc = QLabel(description)
        lbl_desc.setWordWrap(True)
        lbl_desc.setStyleSheet("font-size: 12px; color: #94A3B8;")

        btn = QPushButton(button_label)
        btn.setObjectName("PrimaryButton")
        btn.clicked.connect(handler)

        box.addWidget(lbl_title)
        box.addWidget(lbl_desc)
        box.addWidget(btn)
        box.addStretch()
        return card

    # Handlers
    def _export_vuln_pdf(self) -> None:
        default_dir = get_reports_dir()
        path, _ = QFileDialog.getSaveFileName(self, "Save Vulnerability PDF Report", os.path.join(default_dir, "vulnerability_report.pdf"), "PDF Files (*.pdf)")
        if not path:
            return

        db_vulns = get_vulnerabilities(limit=1000)
        vuln_dicts = [v.to_dict() for v in db_vulns]
        target = vuln_dicts[0].get("host", "All Scanned Targets") if vuln_dicts else "192.168.1.0/24"

        worker = ExportWorker(generate_vulnerability_pdf_report, vuln_dicts, target, path, parent=self)
        self._active_workers.add(worker)
        worker.export_finished.connect(lambda p: QMessageBox.information(self, "Export Success", f"Vulnerability PDF report saved to:\n{p}"))
        worker.export_error.connect(lambda e: QMessageBox.critical(self, "Export Error", f"Failed to generate PDF: {e}"))
        worker.finished.connect(lambda w=worker: self._cleanup_worker(w))
        worker.start()

    def _export_vuln_txt(self) -> None:
        default_dir = get_reports_dir()
        path, _ = QFileDialog.getSaveFileName(self, "Save Vulnerability TXT Report", os.path.join(default_dir, "vulnerability_report.txt"), "Text Files (*.txt)")
        if not path:
            return

        db_vulns = get_vulnerabilities(limit=1000)
        vuln_dicts = [v.to_dict() for v in db_vulns]
        target = vuln_dicts[0].get("host", "All Scanned Targets") if vuln_dicts else "192.168.1.0/24"

        def _write_txt():
            content = generate_vulnerability_txt_report(vuln_dicts, target)
            with open(path, "w", encoding="utf-8") as f:
                f.write(content)
            return path

        worker = ExportWorker(_write_txt, parent=self)
        self._active_workers.add(worker)
        worker.export_finished.connect(lambda p: QMessageBox.information(self, "Export Success", f"Vulnerability TXT report saved to:\n{p}"))
        worker.export_error.connect(lambda e: QMessageBox.critical(self, "Export Error", f"Failed to generate TXT: {e}"))
        worker.finished.connect(lambda w=worker: self._cleanup_worker(w))
        worker.start()

    def _export_vuln_json(self) -> None:
        default_dir = get_reports_dir()
        path, _ = QFileDialog.getSaveFileName(self, "Save Vulnerabilities JSON Data", os.path.join(default_dir, "vulnerabilities.json"), "JSON Files (*.json)")
        if not path:
            return

        db_vulns = get_vulnerabilities(limit=1000)
        vuln_dicts = [v.to_dict() for v in db_vulns]

        def _write_json():
            with open(path, "w", encoding="utf-8") as f:
                json.dump(vuln_dicts, f, indent=2, ensure_ascii=False, default=str)
            return path

        worker = ExportWorker(_write_json, parent=self)
        self._active_workers.add(worker)
        worker.export_finished.connect(lambda p: QMessageBox.information(self, "Export Success", f"Vulnerabilities JSON saved to:\n{p}"))
        worker.export_error.connect(lambda e: QMessageBox.critical(self, "Export Error", f"Failed to export JSON: {e}"))
        worker.finished.connect(lambda w=worker: self._cleanup_worker(w))
        worker.start()

    def _export_vuln_csv(self) -> None:
        default_dir = get_reports_dir()
        path, _ = QFileDialog.getSaveFileName(self, "Save Vulnerabilities CSV File", os.path.join(default_dir, "vulnerabilities.csv"), "CSV Files (*.csv)")
        if not path:
            return

        db_vulns = get_vulnerabilities(limit=1000)
        vuln_dicts = [v.to_dict() for v in db_vulns]

        def _write_csv():
            fields = ["cve", "severity", "cvss", "title", "host", "port", "protocol", "service", "script_name", "detected_at"]
            with open(path, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
                writer.writeheader()
                writer.writerows(vuln_dicts)
            return path

        worker = ExportWorker(_write_csv, parent=self)
        self._active_workers.add(worker)
        worker.export_finished.connect(lambda p: QMessageBox.information(self, "Export Success", f"Vulnerabilities CSV saved to:\n{p}"))
        worker.export_error.connect(lambda e: QMessageBox.critical(self, "Export Error", f"Failed to export CSV: {e}"))
        worker.finished.connect(lambda w=worker: self._cleanup_worker(w))
        worker.start()

    def _export_devices_pdf(self) -> None:
        default_dir = get_reports_dir()
        path, _ = QFileDialog.getSaveFileName(self, "Save Devices PDF Report", os.path.join(default_dir, "devices_report.pdf"), "PDF Files (*.pdf)")
        if not path:
            return

        devices = [d.to_dict() for d in get_all_devices()]

        worker = ExportWorker(export_to_pdf, devices, path, parent=self)
        self._active_workers.add(worker)
        worker.export_finished.connect(lambda p: QMessageBox.information(self, "Export Success", f"Devices PDF report saved to:\n{p}"))
        worker.export_error.connect(lambda e: QMessageBox.critical(self, "Export Error", f"Failed to generate PDF: {e}"))
        worker.finished.connect(lambda w=worker: self._cleanup_worker(w))
        worker.start()

    def _export_devices_csv(self) -> None:
        default_dir = get_reports_dir()
        path, _ = QFileDialog.getSaveFileName(self, "Save Devices CSV Inventory", os.path.join(default_dir, "devices_inventory.csv"), "CSV Files (*.csv)")
        if not path:
            return

        devices = [d.to_dict() for d in get_all_devices()]

        worker = ExportWorker(export_to_csv, devices, path, parent=self)
        self._active_workers.add(worker)
        worker.export_finished.connect(lambda p: QMessageBox.information(self, "Export Success", f"Devices CSV inventory saved to:\n{p}"))
        worker.export_error.connect(lambda e: QMessageBox.critical(self, "Export Error", f"Failed to generate CSV: {e}"))
        worker.finished.connect(lambda w=worker: self._cleanup_worker(w))
        worker.start()
