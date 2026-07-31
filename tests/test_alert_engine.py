"""Unit tests for core/alert_engine.py AlertEngine module."""
import pytest

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from core.alert_engine import AlertEngine


def test_alert_engine_process_scan_result():
    engine = AlertEngine()

    analysis = {
        "new": ["192.168.1.100"],
        "returned": ["192.168.1.101"],
        "disconnected": ["192.168.1.102"],
        "timestamp": "2026-07-31T12:00:00.000000",
    }

    alerts = engine.process_scan_result(analysis)
    assert len(alerts) == 3

    # Check NEW_DEVICE
    new_alert = next(a for a in alerts if a["type"] == "NEW_DEVICE")
    assert new_alert["ip"] == "192.168.1.100"
    assert "New device detected" in new_alert["message"]

    # Check RETURNED
    ret_alert = next(a for a in alerts if a["type"] == "RETURNED")
    assert ret_alert["ip"] == "192.168.1.101"
    assert "returned online" in ret_alert["message"]

    # Check DISCONNECTED
    disc_alert = next(a for a in alerts if a["type"] == "DISCONNECTED")
    assert disc_alert["ip"] == "192.168.1.102"
    assert "disconnected" in disc_alert["message"]


def test_alert_engine_get_and_clear_alerts():
    engine = AlertEngine()

    analysis1 = {"new": ["10.0.0.1"], "returned": [], "disconnected": [], "timestamp": "t1"}
    analysis2 = {"new": [], "returned": [], "disconnected": ["10.0.0.2"], "timestamp": "t2"}

    engine.process_scan_result(analysis1)
    engine.process_scan_result(analysis2)

    all_alerts = engine.get_alerts()
    assert len(all_alerts) == 2
    # Newest first
    assert all_alerts[0]["type"] == "DISCONNECTED"
    assert all_alerts[1]["type"] == "NEW_DEVICE"

    limited_alerts = engine.get_alerts(limit=1)
    assert len(limited_alerts) == 1
    assert limited_alerts[0]["type"] == "DISCONNECTED"

    engine.clear_alerts()
    assert len(engine.get_alerts()) == 0
