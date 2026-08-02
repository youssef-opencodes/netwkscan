"""NMD - Network Monitoring Dashboard
Application entry point: initializes the database and launches the GUI.
"""
import os
import sys

# Integration fix (Dev 3): make `src/` importable so `core.*`, `gui.*`,
# `models.*` and `utils.*` resolve when running `python main.py` from root.
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "src"))

from core.database import init_db
from utils.logger import get_logger

logger = get_logger()


def main() -> None:
    logger.info("Starting NMD application...")

    init_db()
    logger.info("Database initialized (data/nmd.db).")

    try:
        from gui.main_window import MainWindow  # provided by Developer 3
    except ImportError:
        logger.error(
            "GUI module not found (gui/main_window.py). "
            "Backend is ready; waiting on frontend integration."
        )
        sys.exit(1)

    app = MainWindow()
    logger.info("Launching GUI main window.")
    app.mainloop()


if __name__ == "__main__":
    main()
