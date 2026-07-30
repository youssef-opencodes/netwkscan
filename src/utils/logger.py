"""Audit logging setup for NMD: rotating file log + console output."""
import logging
import os
from logging.handlers import RotatingFileHandler

LOG_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "logs"
)
LOG_FILE = os.path.join(LOG_DIR, "audit.log")

_logger: logging.Logger | None = None


def get_logger(name: str = "nmd") -> logging.Logger:
    """Return the shared NMD logger, configuring it on first call."""
    global _logger
    if _logger is not None:
        return _logger

    os.makedirs(LOG_DIR, exist_ok=True)

    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    logger.propagate = False

    formatter = logging.Formatter(
        fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    file_handler = RotatingFileHandler(
        LOG_FILE, maxBytes=1_000_000, backupCount=5, encoding="utf-8"
    )
    file_handler.setFormatter(formatter)

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    _logger = logger
    return logger


def log_event(message: str, level: str = "info") -> None:
    """Convenience shortcut to log an audit event at a given level."""
    logger = get_logger()
    getattr(logger, level.lower(), logger.info)(message)
