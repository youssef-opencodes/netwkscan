"""Unit tests for core/scanner.py Nmap scanner module."""
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from core.scanner import (
    ScanResult,
    Scanner,
    find_nmap_binary,
    guess_device_type,
    is_admin,
    parse_nmap_xml,
    validate_target,
)


def test_scanner_init():
    scanner = Scanner()
    assert scanner.last_duration == 0.0


def test_validate_target():
    is_valid, _ = validate_target("10.222.83.0/24")
    assert is_valid is True

    is_valid, _ = validate_target("192.168.1.1")
    assert is_valid is True

    is_valid, _ = validate_target("")
    assert is_valid is False

    is_valid, _ = validate_target("invalid_target_123$$$")
    assert is_valid is False


def test_guess_device_type():
    dev_type = guess_device_type({"80": "http", "53": "domain"}, "Router OS")
    assert dev_type == "Router"

    dev_type = guess_device_type({"3389": "ms-wbt-server"}, "Windows 11")
    assert dev_type == "PC"

    dev_type = guess_device_type({"22": "ssh", "3306": "mysql"}, "Linux Ubuntu")
    assert dev_type == "Server"


def test_build_nmap_command():
    scanner = Scanner()
    cmd = scanner.build_nmap_command(
        target="10.222.83.0/24",
        ports="1-1024",
        arguments="-sV -O",
        timing="-T4",
    )
    assert "10.222.83.0/24" in cmd
    assert "-p 1-1024" in cmd
    assert "-sV" in cmd
    assert "-T4" in cmd


def test_parse_nmap_xml_sample():
    sample_xml = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun format="xml" version="7.94">
<host>
    <status state="up" reason="arp-response"/>
    <address addr="10.222.83.15" addrtype="ipv4"/>
    <address addr="00:11:22:33:44:55" addrtype="mac" vendor="Dell Inc"/>
    <hostnames><hostname name="test-host.local" type="PTR"/></hostnames>
    <ports>
        <port protocol="tcp" portid="22">
            <state state="open"/>
            <service name="ssh" product="OpenSSH" version="8.2p1"/>
        </port>
        <port protocol="tcp" portid="80">
            <state state="open"/>
            <service name="http" product="Apache" version="2.4.41"/>
        </port>
    </ports>
    <os><osmatch name="Linux 5.4"/></os>
</host>
</nmaprun>
"""
    devices = parse_nmap_xml(sample_xml)
    assert len(devices) == 1
    dev = devices[0]
    assert dev["ip"] == "10.222.83.15"
    assert dev["mac"] == "00:11:22:33:44:55"
    assert dev["vendor"] == "Dell Inc"
    assert dev["hostname"] == "test-host.local"
    assert dev["os"] == "Linux 5.4"
    assert dev["ports"] == {"22": "ssh", "80": "http"}


def test_scanner_execute_invalid_target():
    scanner = Scanner()
    res = scanner.execute_scan("invalid@@target")
    assert res.success is False
    assert res.status_code == "INVALID_TARGET"
    assert res.devices == []
