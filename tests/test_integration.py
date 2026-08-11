"""Integration tests for Developer 2 backend modules with Developer 1 database and analyzer."""
import os
import pytest
from unittest.mock import MagicMock
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from core import database, analyzer
from core.alert_engine import AlertEngine
from core.scanner import Scanner
from core.scheduler import NetworkScheduler


@pytest.fixture(autouse=True)
def setup_isolated_test_db(tmp_path: Path, monkeypatch):
    """Isolate database for integration tests to ensure deterministic results."""
    test_db_file = tmp_path / "test_nmd.db"
    test_engine = create_engine(f"sqlite:///{test_db_file}", echo=False, future=True)
    test_sessionmaker = sessionmaker(bind=test_engine, expire_on_commit=False, future=True)

    monkeypatch.setattr(database, "engine", test_engine)
    monkeypatch.setattr(database, "SessionLocal", test_sessionmaker)

    database.Base.metadata.create_all(test_engine)
    yield
    database.Base.metadata.drop_all(test_engine)


def test_end_to_end_backend_flow():
    # 1. Instantiate Scanner and AlertEngine
    alert_engine = AlertEngine()

    # 2. Simulate raw Nmap scan results
    scan_results = [
        {
            "ip": "192.168.1.100",
            "hostname": "test-device-1",
            "mac": "00:11:22:33:44:55",
            "vendor": "Test Vendor",
            "os": "Linux",
        },
        {
            "ip": "192.168.1.101",
            "hostname": "test-device-2",
            "mac": "AA:BB:CC:DD:EE:FF",
            "vendor": "Another Vendor",
            "os": "Windows",
        },
    ]

    # 3. Analyze scan results with Developer 1's analyzer
    analysis = analyzer.analyze_scan(scan_results)

    assert "192.168.1.100" in analysis["new"]
    assert "192.168.1.101" in analysis["new"]

    # 4. Save scan summary to database using Developer 1's database API
    scan_data = {
        "duration": 1.25,
        "total_devices": len(scan_results),
        "new_devices": len(analysis["new"]),
        "disconnected_devices": len(analysis["disconnected"]),
    }
    scan_record = database.add_scan(scan_data)
    assert scan_record.id is not None
    assert scan_record.total_devices == 2

    # 5. Process alerts with Developer 2's AlertEngine
    alerts = alert_engine.process_scan_result(analysis)
    assert len(alerts) == 2
    assert any(a["ip"] == "192.168.1.100" and a["type"] == "NEW_DEVICE" for a in alerts)

    # 6. Verify devices exist in database via get_all_devices
    devices = database.get_all_devices()
    device_ips = {d.ip for d in devices}
    assert "192.168.1.100" in device_ips
    assert "192.168.1.101" in device_ips

    # 7. Simulate subsequent scan where 192.168.1.101 disconnects
    second_scan_results = [
        {
            "ip": "192.168.1.100",
            "hostname": "test-device-1",
            "mac": "00:11:22:33:44:55",
            "vendor": "Test Vendor",
            "os": "Linux",
        }
    ]
    second_analysis = analyzer.analyze_scan(second_scan_results, is_single_ip=False)
    assert "192.168.1.101" in second_analysis["disconnected"]


    second_alerts = alert_engine.process_scan_result(second_analysis)
    disc_alert = next(a for a in second_alerts if a["type"] == "DISCONNECTED")
    assert disc_alert["ip"] == "192.168.1.101"

    # Verify device status in DB updated to offline
    device_101 = database.get_device_by_ip("192.168.1.101")
    assert device_101 is not None
    assert device_101.status == "offline"
