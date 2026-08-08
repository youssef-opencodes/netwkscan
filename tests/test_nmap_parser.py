"""Comprehensive unit tests for Nmap parser, binary discovery, privilege fallback, and error handling."""
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from core.scanner import (
    ScanResult,
    Scanner,
    find_nmap_binary,
    is_admin,
    parse_nmap_xml,
    validate_target,
)


def test_find_nmap_binary():
    path = find_nmap_binary()
    # Path should either be None or a valid non-empty string path
    if path is not None:
        assert isinstance(path, str)
        assert len(path) > 0


def test_is_admin():
    res = is_admin()
    assert isinstance(res, bool)


def test_non_admin_syn_downgrade():
    scanner = Scanner(nmap_path="/usr/bin/nmap")
    with patch("core.scanner.is_admin", return_value=False):
        cmd_args = scanner.build_nmap_command_args(
            target="10.222.83.0/24",
            arguments="-sS -sV",
        )
        cmd_str = " ".join(cmd_args)
        assert "-sS" not in cmd_str
        assert "-sT" in cmd_str


def test_admin_syn_retained():
    scanner = Scanner(nmap_path="/usr/bin/nmap")
    with patch("core.scanner.is_admin", return_value=True):
        cmd_args = scanner.build_nmap_command_args(
            target="10.222.83.0/24",
            arguments="-sS -sV",
        )
        cmd_str = " ".join(cmd_args)
        assert "-sS" in cmd_str


def test_nmap_not_found_handling():
    with patch("core.scanner.find_nmap_binary", return_value=None):
        scanner = Scanner(nmap_path=None)
        res = scanner.execute_scan("10.222.83.0/24")
        assert res.success is False
        assert res.status_code == "NMAP_NOT_FOUND"
        assert "not found" in res.error_message.lower()


def test_xml_host_discovery_up_no_ports():
    xml_data = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun format="xml" version="7.94">
<host>
    <status state="up" reason="echo-reply"/>
    <address addr="10.222.83.1" addrtype="ipv4"/>
    <address addr="AA:BB:CC:DD:EE:11" addrtype="mac" vendor="Router Vendor"/>
    <hostnames><hostname name="gateway.home" type="PTR"/></hostnames>
</host>
</nmaprun>
"""
    devices = parse_nmap_xml(xml_data)
    assert len(devices) == 1
    assert devices[0]["ip"] == "10.222.83.1"
    assert devices[0]["mac"] == "AA:BB:CC:DD:EE:11"
    assert devices[0]["vendor"] == "Router Vendor"
    assert devices[0]["ports"] == {}


def test_xml_multiple_hosts():
    xml_data = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun format="xml" version="7.94">
<host>
    <status state="up"/>
    <address addr="10.222.83.2" addrtype="ipv4"/>
</host>
<host>
    <status state="up"/>
    <address addr="10.222.83.3" addrtype="ipv4"/>
</host>
</nmaprun>
"""
    devices = parse_nmap_xml(xml_data)
    assert len(devices) == 2
    assert devices[0]["ip"] == "10.222.83.2"
    assert devices[1]["ip"] == "10.222.83.3"
