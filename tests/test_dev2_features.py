"""Unit tests specifically covering Developer 2 new features."""
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from core.alert_engine import AlertEngine
from core.scanner import ScanResult, Scanner
from core.scheduler import NetworkScheduler
from presets import delete_preset, get_preset, load_presets, save_preset


def test_scanner_dynamic_command_building():
    scanner = Scanner()
    cmd = scanner.build_nmap_command(
        target="192.168.1.0/24",
        ports="22,80,443",
        arguments="-sV -O -A",
        timing="-T4",
        verbosity="-v",
        host_timeout="5m",
        min_hostgroup=32,
        max_hostgroup=64,
    )
    assert "nmap" in cmd
    assert "-sV -O -A" in cmd
    assert "-T4" in cmd
    assert "-v" in cmd
    assert "--host-timeout 5m" in cmd
    assert "--min-hostgroup 32" in cmd
    assert "--max-hostgroup 64" in cmd
    assert "-p 22,80,443" in cmd
    assert "192.168.1.0/24" in cmd


def test_alert_engine_port_change_alerts():
    engine = AlertEngine()

    # First scan for host 192.168.1.50 with port 22 open
    analysis1 = {
        "new": ["192.168.1.50"],
        "returned": [],
        "disconnected": [],
        "timestamp": "2026-08-06T10:00:00",
        "scan_results": [
            {
                "ip": "192.168.1.50",
                "ports": {"22": "ssh"},
            }
        ],
    }
    alerts1 = engine.process_scan_result(analysis1)
    assert any(a["type"] == "NEW_DEVICE" for a in alerts1)

    # Second scan: port 80 opens (NEW_OPEN_PORT)
    analysis2 = {
        "new": [],
        "returned": [],
        "disconnected": [],
        "timestamp": "2026-08-06T10:05:00",
        "scan_results": [
            {
                "ip": "192.168.1.50",
                "ports": {"22": "ssh", "80": "http"},
            }
        ],
    }
    alerts2 = engine.process_scan_result(analysis2)
    port_alert = next(a for a in alerts2 if a["type"] == "NEW_OPEN_PORT")
    assert port_alert["port"] == "80"
    assert port_alert["service"] == "http"
    assert "New Open Port Detected" in port_alert["message"]

    # Third scan: port 22 closes (PORT_CLOSED)
    analysis3 = {
        "new": [],
        "returned": [],
        "disconnected": [],
        "timestamp": "2026-08-06T10:10:00",
        "scan_results": [
            {
                "ip": "192.168.1.50",
                "ports": {"80": "http"},
            }
        ],
    }
    alerts3 = engine.process_scan_result(analysis3)
    closed_alert = next(a for a in alerts3 if a["type"] == "PORT_CLOSED")
    assert closed_alert["port"] == "22"
    assert "Port Closed" in closed_alert["message"]


def test_presets_manager_lifecycle():
    all_presets = load_presets()
    assert "Ping" in all_presets
    assert "Quick" in all_presets

    # Save custom preset
    custom_name = "Dev2_Test_Preset"
    save_preset(custom_name, "-T4 -sV", "80,443", "Test preset description")

    loaded = get_preset(custom_name)
    assert loaded is not None
    assert loaded["args"] == "-T4 -sV"
    assert loaded["ports"] == "80,443"

    # Delete custom preset
    deleted = delete_preset(custom_name)
    assert deleted is True
    assert get_preset(custom_name) is None


@patch("core.database.add_scan")
@patch("core.analyzer.analyze_scan")
def test_scheduler_preset_execution(mock_analyze, mock_add_scan):
    mock_analyze.return_value = {"new": [], "returned": [], "disconnected": [], "timestamp": "t"}
    mock_scanner = MagicMock(spec=Scanner)
    mock_scanner.execute_scan.return_value = ScanResult(
        success=True,
        status_code="SUCCESS",
        devices=[],
        duration=0.5,
        command="nmap -T4 -F 192.168.1.0/24",
    )
    mock_scanner.last_command = "nmap -T4 -F 192.168.1.0/24"

    scheduler = NetworkScheduler(scanner=mock_scanner)
    scheduler.set_preset("Quick")
    assert scheduler.get_preset() == "Quick"

    scheduler._execute_scan()
    mock_scanner.execute_scan.assert_called_once()
    mock_add_scan.assert_called_once()
