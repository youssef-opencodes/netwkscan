"""Unit tests for core/scheduler.py NetworkScheduler module."""
import time
from unittest.mock import MagicMock, patch
import pytest

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from core.alert_engine import AlertEngine
from core.scanner import Scanner
from core.scheduler import NetworkScheduler


def test_scheduler_lifecycle():
    mock_scanner = MagicMock(spec=Scanner)
    mock_scanner.quick_scan.return_value = ([], 0.1)

    mock_alert_engine = MagicMock(spec=AlertEngine)

    scheduler = NetworkScheduler(scanner=mock_scanner, alert_engine=mock_alert_engine, interval=0.2)
    assert scheduler.is_running() is False
    assert scheduler.get_interval() == 0.2

    scheduler.set_interval(0.5)
    assert scheduler.get_interval() == 0.5
    scheduler.set_interval(0.1)

    # Start scheduler
    start_res = scheduler.start()
    assert start_res is True
    assert scheduler.is_running() is True

    # Duplicate start should return False
    assert scheduler.start() is False

    time.sleep(0.35)

    # Stop scheduler
    stop_res = scheduler.stop()
    assert stop_res is True
    assert scheduler.is_running() is False


@patch("core.database.add_scan")
@patch("core.analyzer.analyze_scan")
def test_scheduler_manual_run_now(mock_analyze_scan, mock_add_scan):
    mock_analyze_scan.return_value = {
        "new": ["192.168.1.1"],
        "returned": [],
        "disconnected": [],
        "timestamp": "2026-07-31T12:00:00.000000",
    }

    mock_scanner = MagicMock(spec=Scanner)
    mock_scanner.quick_scan.return_value = (
        [{"ip": "192.168.1.1", "hostname": "host1", "mac": "", "vendor": "", "os": ""}],
        0.05,
    )

    mock_alert_engine = MagicMock(spec=AlertEngine)

    scheduler = NetworkScheduler(scanner=mock_scanner, alert_engine=mock_alert_engine, interval=60.0)
    scheduler._execute_scan()

    mock_scanner.quick_scan.assert_called_once()
    mock_analyze_scan.assert_called_once()
    mock_add_scan.assert_called_once()
    mock_alert_engine.process_scan_result.assert_called_once()
