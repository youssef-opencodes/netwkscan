"""Unit tests for core/scanner.py Nmap scanner module."""
from unittest.mock import MagicMock, patch
import pytest

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import nmap
from core.scanner import Scanner


def test_scanner_init():
    scanner = Scanner()
    assert scanner.last_duration == 0.0


def test_parse_nmap_results_complete():
    scanner = Scanner()

    mock_nm = MagicMock()
    mock_nm.all_hosts.return_value = ["192.168.1.10"]
    mock_nm.__getitem__.return_value = {
        "addresses": {"ipv4": "192.168.1.10", "mac": "AA:BB:CC:DD:EE:FF"},
        "hostnames": [{"name": "router.local", "type": "PTR"}],
        "vendor": {"AA:BB:CC:DD:EE:FF": "Cisco Systems"},
        "osmatch": [{"name": "Linux 5.x", "accuracy": "95"}],
    }

    parsed = scanner.parse_nmap_results(mock_nm)
    assert len(parsed) == 1
    assert parsed[0]["ip"] == "192.168.1.10"
    assert parsed[0]["hostname"] == "router.local"
    assert parsed[0]["mac"] == "AA:BB:CC:DD:EE:FF"
    assert parsed[0]["vendor"] == "Cisco Systems"
    assert parsed[0]["os"] == "Linux 5.x"


def test_parse_nmap_results_missing_fields():
    scanner = Scanner()

    mock_nm = MagicMock()
    mock_nm.all_hosts.return_value = ["192.168.1.20"]
    mock_nm.__getitem__.return_value = {
        "addresses": {"ipv4": "192.168.1.20"},  # No MAC address
        "hostnames": [],
        "vendor": {},
        "osmatch": [],
    }

    parsed = scanner.parse_nmap_results(mock_nm)
    assert len(parsed) == 1
    assert parsed[0]["ip"] == "192.168.1.20"
    assert parsed[0]["hostname"] == ""
    assert parsed[0]["mac"] == ""
    assert parsed[0]["vendor"] == ""
    assert parsed[0]["os"] == ""


def test_scanner_invalid_target():
    scanner = Scanner()
    results, duration = scanner.quick_scan("")
    assert results == []
    assert duration == 0.0


@patch("nmap.PortScanner")
def test_scanner_quick_scan_mocked(mock_port_scanner_cls):
    mock_instance = MagicMock()
    mock_port_scanner_cls.return_value = mock_instance
    mock_instance.all_hosts.return_value = ["192.168.1.50"]
    mock_instance.__getitem__.return_value = {
        "addresses": {"ipv4": "192.168.1.50"},
        "hostnames": [{"name": "desktop", "type": "user"}],
        "vendor": {},
        "osmatch": [],
    }

    scanner = Scanner()
    results, duration = scanner.quick_scan("192.168.1.0/24")

    assert len(results) == 1
    assert results[0]["ip"] == "192.168.1.50"
    assert duration >= 0.0
    mock_instance.scan.assert_called_once_with(hosts="192.168.1.0/24", ports=None, arguments="-sn")


@patch("nmap.PortScanner")
def test_scanner_nmap_error_handling(mock_port_scanner_cls):
    mock_instance = MagicMock()
    mock_port_scanner_cls.return_value = mock_instance
    mock_instance.scan.side_effect = nmap.PortScannerError("Nmap error simulation")

    scanner = Scanner()
    results, duration = scanner.quick_scan("192.168.1.1")
    assert results == []
    assert duration >= 0.0
