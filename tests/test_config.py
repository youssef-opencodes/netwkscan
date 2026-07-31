"""Unit tests for utils/config.py configuration management."""
import json
import pytest
from pathlib import Path

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from utils.config import (
    load_config,
    save_config,
    update_config,
    get_default_config,
    validate_config,
)


def test_get_default_config():
    cfg = get_default_config()
    assert isinstance(cfg, dict)
    assert cfg["subnet"] == "192.168.1.0/24"
    assert cfg["scan_interval"] == 60
    assert cfg["scan_type"] == "quick"
    assert cfg["port_range"] == "1-1024"
    assert cfg["theme"] == "dark"


def test_validate_config():
    valid_cfg = get_default_config()
    is_valid, err = validate_config(valid_cfg)
    assert is_valid is True
    assert err == ""

    # Invalid interval
    invalid_cfg = valid_cfg.copy()
    invalid_cfg["scan_interval"] = -10
    is_valid, err = validate_config(invalid_cfg)
    assert is_valid is False

    # Invalid scan type
    invalid_cfg = valid_cfg.copy()
    invalid_cfg["scan_type"] = "invalid_type"
    is_valid, err = validate_config(invalid_cfg)
    assert is_valid is False

    # Empty subnet
    invalid_cfg = valid_cfg.copy()
    invalid_cfg["subnet"] = "   "
    is_valid, err = validate_config(invalid_cfg)
    assert is_valid is False


def test_load_save_config_tempfile(tmp_path: Path):
    config_file = tmp_path / "test_config.json"

    # Should create default config file if missing
    loaded = load_config(config_file)
    assert loaded["subnet"] == "192.168.1.0/24"
    assert config_file.exists()

    # Save modified config
    loaded["scan_interval"] = 120
    save_res = save_config(loaded, config_file)
    assert save_res is True

    # Reload and verify
    reloaded = load_config(config_file)
    assert reloaded["scan_interval"] == 120


def test_load_invalid_json_fallback(tmp_path: Path):
    config_file = tmp_path / "corrupt.json"
    config_file.write_text("{ invalid json content ...", encoding="utf-8")

    # Should gracefully log and return defaults
    loaded = load_config(config_file)
    assert loaded["scan_interval"] == 60


def test_update_config(tmp_path: Path):
    config_file = tmp_path / "update_test.json"
    updated = update_config(config_file, scan_interval=300, scan_type="full")
    assert updated["scan_interval"] == 300
    assert updated["scan_type"] == "full"

    reloaded = load_config(config_file)
    assert reloaded["scan_interval"] == 300
    assert reloaded["scan_type"] == "full"
