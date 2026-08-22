"""NMD - Network Monitoring Dashboard
Desktop Application Launcher (PySide6).
"""

from __future__ import annotations

import os
import sys

# Ensure `src/` is in Python path for package resolution
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "src"))

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication

from core.database import init_db
from gui.pyside_main_window import PySideMainWindow
from utils.logger import get_logger, log_event

logger = get_logger()


def run_desktop_app() -> int:
    """Initialize database, configure high-DPI scaling, and launch PySide6 GUI."""
    logger.info("Initializing NMD SQLite Database...")
    init_db()
    logger.info("Database initialized successfully.")

    # Configure High DPI scaling for crisp modern rendering on Windows
    QApplication.setHighDpiScaleFactorRoundingPolicy(
        Qt.HighDpiScaleFactorRoundingPolicy.PassThrough
    )

    app = QApplication(sys.argv)
    app.setApplicationName("NMD Security Tool")
    app.setOrganizationName("NMD Development Team")

    logger.info("Launching PySide6 Main Application Window...")
    window = PySideMainWindow()
    window.show()

    return app.exec()


if __name__ == "__main__":
    sys.exit(run_desktop_app())
