"""Unit tests for PySide6 GUI integration, CLI mode, and path resolution."""

import os
import sys
import pytest

from utils.paths import get_base_dir, get_resource_path, get_db_path, get_logs_dir, get_reports_dir


def test_path_resolution_helpers():
    """Verify path resolution helpers in dev and frozen modes."""
    base_dir = get_base_dir()
    assert os.path.exists(base_dir)

    icon_path = get_resource_path("resources/icon.ico")
    assert icon_path.endswith("icon.ico")

    db_path = get_db_path()
    assert db_path.endswith("nmd.db")

    logs_dir = get_logs_dir()
    assert os.path.exists(logs_dir)

    reports_dir = get_reports_dir()
    assert os.path.exists(reports_dir)


def test_cli_argument_parsing(monkeypatch, capsys):
    """Verify main.py CLI mode execution."""
    from main import main

    monkeypatch.setattr(sys, "argv", ["main.py", "--cli", "--target", "127.0.0.1", "--scan-type", "quick"])

    # CLI mode runs cleanly to completion
    main()
    captured = capsys.readouterr()
    assert "NMD" in captured.out or "Target" in captured.out


def test_pyside6_imports():
    """Verify PySide6 core modules can be imported."""
    try:
        from PySide6.QtCore import QThread, Signal
        from PySide6.QtWidgets import QApplication
        assert QThread is not None
        assert Signal is not None
        assert QApplication is not None
    except ImportError:
        pytest.skip("PySide6 not yet installed in virtualenv")


def test_export_worker_lifecycle():
    """Verify ExportWorker thread lifecycle, persistent storage, and clean finish."""
    try:
        from PySide6.QtCore import QObject
        from PySide6.QtWidgets import QApplication
        from gui.workers import ExportWorker
    except ImportError:
        pytest.skip("PySide6 environment not available")

    app = QApplication.instance() or QApplication([])

    class Parent(QObject):
        def __init__(self):
            super().__init__()
            self._active_workers = set()

    parent = Parent()

    def dummy_export(val: str) -> str:
        return f"result_{val}"

    # Verify positional parent extraction
    worker1 = ExportWorker(dummy_export, "test1", parent)
    assert worker1.parent() == parent
    assert worker1.args == ("test1",)

    # Verify keyword parent
    worker2 = ExportWorker(dummy_export, "test2", parent=parent)
    assert worker2.parent() == parent
    assert worker2.args == ("test2",)

    # Test thread execution and persistent reference retention
    parent._active_workers.add(worker1)
    results = []

    worker1.export_finished.connect(lambda r: results.append(r))
    worker1.start()
    worker1.wait()
    app.processEvents()

    assert results == ["result_test1"]
    assert not worker1.isRunning()

    # Clean up
    parent._active_workers.remove(worker1)
    worker1.deleteLater()


def test_export_worker_exception_handling():
    """Verify exceptions inside ExportWorker do not crash the application."""
    try:
        from PySide6.QtWidgets import QApplication
        from gui.workers import ExportWorker
    except ImportError:
        pytest.skip("PySide6 environment not available")

    app = QApplication.instance() or QApplication([])

    def failing_export():
        raise ValueError("Simulated export failure")

    worker = ExportWorker(failing_export)
    errors = []

    worker.export_error.connect(lambda err: errors.append(err))
    worker.start()
    worker.wait()
    app.processEvents()

    assert len(errors) == 1
    assert "Simulated export failure" in errors[0]
    assert not worker.isRunning()
    worker.deleteLater()

