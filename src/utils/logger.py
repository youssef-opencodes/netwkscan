"""Audit logging setup for NMD: rotating file log + console output with detailed context."""

import logging
import os
import sys
import traceback
from datetime import datetime
from logging.handlers import RotatingFileHandler
from pathlib import Path

LOG_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "logs"
)
LOG_FILE = os.path.join(LOG_DIR, "audit.log")

_logger: logging.Logger | None = None


class DetailedLogger:
    """Wrapper class for detailed logging with context and tracking."""

    def __init__(self):
        self._session_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        self._call_count = 0

    def _get_caller_info(self) -> str:
        """Get caller file, function, and line number."""
        frame = None
        try:
            frame = sys._getframe(3)
        except ValueError:
            try:
                frame = sys._getframe(2)
            except ValueError:
                frame = None

        if frame is not None:
            filename = os.path.basename(frame.f_code.co_filename)
            funcname = frame.f_code.co_name
            lineno = frame.f_lineno
            return f"{filename}:{funcname}():{lineno}"
        return "unknown"

    def _format_message(self, message: str, context: dict = None) -> str:
        """Format message with context and tracking info."""
        self._call_count += 1
        caller = self._get_caller_info()
        
        # Base message with session and call count
        formatted = f"[SID:{self._session_id}] [CALL:{self._call_count}] {caller} | {message}"
        
        # Add context if provided
        if context:
            context_str = " | ".join(f"{k}={v}" for k, v in context.items())
            formatted += f" | {context_str}"
        
        return formatted

    def log(self, level: str, message: str, context: dict = None, exc_info: bool = False):
        """Log a message with full context and optional exception info."""
        logger = get_logger()
        formatted = self._format_message(message, context)
        
        log_method = getattr(logger, level.lower(), logger.info)
        
        if exc_info:
            # Add exception details
            exc_details = traceback.format_exc()
            if exc_details and exc_details != "NoneType: None\n":
                formatted += f"\n--- EXCEPTION DETAILS ---\n{exc_details}--- END EXCEPTION ---"
        
        log_method(formatted)


# Global instance
_detailed_logger: DetailedLogger | None = None


def get_detailed_logger() -> DetailedLogger:
    """Return the shared detailed logger instance."""
    global _detailed_logger
    if _detailed_logger is None:
        _detailed_logger = DetailedLogger()
    return _detailed_logger


def get_logger(name: str = "nmd") -> logging.Logger:
    """Return the shared NMD logger, configuring it on first call."""
    global _logger
    if _logger is not None:
        return _logger

    os.makedirs(LOG_DIR, exist_ok=True)

    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)  # Set to DEBUG for maximum detail
    logger.propagate = False

    # Detailed formatter
    formatter = logging.Formatter(
        fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # File handler - detailed logs
    file_handler = RotatingFileHandler(
        LOG_FILE, maxBytes=5_000_000, backupCount=10, encoding="utf-8"
    )
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)

    # Console handler - INFO and above
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(formatter)

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    # Log startup info
    logger.info("=" * 60)
    logger.info(f"LOGGER INITIALIZED - Session: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    logger.info(f"Log file: {LOG_FILE}")
    logger.info(f"Python version: {sys.version}")
    logger.info("=" * 60)

    _logger = logger
    return logger


def log_event(message: str, level: str = "info", context: dict = None, exc_info: bool = False) -> None:
    """
    Log an event with detailed context.
    
    Args:
        message: Log message
        level: Log level (debug, info, warning, error, critical)
        context: Dictionary of key-value pairs for context
        exc_info: Include exception traceback if True
    """
    logger = get_logger()
    detailed = get_detailed_logger()
    
    # Use detailed logger for context
    detailed.log(level, message, context, exc_info)


def log_step(step_name: str, status: str, details: dict = None) -> None:
    """
    Log a specific step in the application workflow.
    
    Args:
        step_name: Name of the step (e.g., "GUI_START", "SCAN_EXECUTE")
        status: "START", "SUCCESS", "FAILED", "SKIPPED"
        details: Additional details about the step
    """
    context = {"step": step_name, "status": status}
    if details:
        context.update(details)
    
    if status == "START":
        log_event(f"Step started: {step_name}", "info", context)
    elif status == "SUCCESS":
        log_event(f"Step completed: {step_name}", "info", context)
    elif status == "FAILED":
        log_event(f"Step failed: {step_name}", "error", context, exc_info=True)
    elif status == "SKIPPED":
        log_event(f"Step skipped: {step_name}", "warning", context)


def log_function_call(func_name: str, args: dict = None, result: dict = None) -> None:
    """
    Log a function call with arguments and result.
    
    Args:
        func_name: Name of the function
        args: Function arguments
        result: Function result
    """
    context = {"function": func_name}
    if args:
        # Limit args length for readability
        args_str = {k: str(v)[:100] + "..." if len(str(v)) > 100 else str(v) 
                   for k, v in args.items()}
        context["args"] = args_str
    if result:
        # Limit result length for readability
        result_str = {k: str(v)[:100] + "..." if len(str(v)) > 100 else str(v) 
                     for k, v in result.items()}
        context["result"] = result_str
    
    log_event(f"Function call: {func_name}", "debug", context)


def log_ui_action(action: str, target: str = None, status: str = "triggered") -> None:
    """
    Log a UI action.
    
    Args:
        action: UI action name (e.g., "CLICK", "REFRESH", "NAVIGATE")
        target: Target element (e.g., "scan_button", "dashboard_page")
        status: Status of the action
    """
    context = {"ui_action": action, "target": target or "unknown", "status": status}
    log_event(f"UI Action: {action} -> {target or 'unknown'}", "debug", context)


def log_db_operation(operation: str, table: str, affected_rows: int = 0, query: str = None) -> None:
    """
    Log a database operation.
    
    Args:
        operation: DB operation (SELECT, INSERT, UPDATE, DELETE)
        table: Table name
        affected_rows: Number of affected rows
        query: SQL query (truncated if too long)
    """
    context = {"db_op": operation, "table": table, "rows": affected_rows}
    if query:
        context["query"] = query[:200] + "..." if len(query) > 200 else query
    
    level = "debug" if operation in ["SELECT"] else "info"
    log_event(f"DB Operation: {operation} on {table}", level, context)


def log_scan_result(device_count: int, new_count: int, offline_count: int, duration: float) -> None:
    """
    Log scan results in a structured way.
    
    Args:
        device_count: Total devices found
        new_count: New devices
        offline_count: Offline devices
        duration: Scan duration in seconds
    """
    context = {
        "total_devices": device_count,
        "new_devices": new_count,
        "offline_devices": offline_count,
        "duration": f"{duration:.2f}s"
    }
    log_event(f"Scan completed with {device_count} devices", "info", context)


def log_device_action(action: str, ip: str, details: dict = None) -> None:
    """
    Log a device-specific action.
    
    Args:
        action: Action performed (ADDED, UPDATED, REMOVED, OFFLINE, ONLINE)
        ip: Device IP address
        details: Additional device details
    """
    context = {"device_ip": ip, "action": action}
    if details:
        context.update(details)
    
    log_event(f"Device {action}: {ip}", "info", context)


def log_performance(operation: str, duration: float, unit: str = "s") -> None:
    """
    Log performance metrics.
    
    Args:
        operation: Operation name
        duration: Duration value
        unit: Unit (s, ms, etc.)
    """
    context = {"operation": operation, "duration": f"{duration}{unit}"}
    log_event(f"Performance: {operation} took {duration}{unit}", "debug", context)


# Convenience functions for different log levels
def log_debug(message: str, context: dict = None) -> None:
    log_event(message, "debug", context)


def log_info(message: str, context: dict = None) -> None:
    log_event(message, "info", context)


def log_warning(message: str, context: dict = None) -> None:
    log_event(message, "warning", context)


def log_error(message: str, context: dict = None, exc_info: bool = True) -> None:
    log_event(message, "error", context, exc_info)


def log_critical(message: str, context: dict = None, exc_info: bool = True) -> None:
    log_event(message, "critical", context, exc_info)


# Module-level exports
__all__ = [
    "get_logger",
    "log_event",
    "log_step",
    "log_function_call",
    "log_ui_action",
    "log_db_operation",
    "log_scan_result",
    "log_device_action",
    "log_performance",
    "log_debug",
    "log_info",
    "log_warning",
    "log_error",
    "log_critical",
    "get_detailed_logger",
]