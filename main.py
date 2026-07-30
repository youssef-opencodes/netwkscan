"""NMD - Network Monitoring Dashboard
Application entry point: initializes the database and launches the GUI.
"""
import sys

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
