# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec configuration for NMD Windows Standalone Executable."""

from PyInstaller.utils.hooks import collect_all

block_cipher = None


# ============================================================
# PySide6
# ============================================================
# Collect all PySide6 modules, DLLs, Qt plugins and data files.
pyside6_datas, pyside6_binaries, pyside6_hiddenimports = collect_all("PySide6")


# ============================================================
# Hidden imports
# ============================================================
hidden_imports = [
    # PySide6
    "PySide6",
    "PySide6.QtCore",
    "PySide6.QtGui",
    "PySide6.QtWidgets",

    # SQLAlchemy
    "sqlalchemy",
    "sqlalchemy.dialects.sqlite",

    # ReportLab
    "reportlab",
    "reportlab.lib",
    "reportlab.platypus",

    # OpenPyXL
    "openpyxl",

    # Pillow
    "PIL",

    # Python standard libraries
    "sqlite3",
    "json",
    "xml.etree.ElementTree",
]

# Add all PySide6 modules discovered automatically.
hidden_imports += pyside6_hiddenimports


# ============================================================
# Data files
# ============================================================
datas = [
    # Project resources
    ("resources", "resources"),

    # Application presets
    ("src/presets", "src/presets"),

    # Application data
    ("data", "data"),
]

# Add PySide6 data files and Qt plugins.
datas += pyside6_datas


# ============================================================
# Analysis
# ============================================================
a = Analysis(
    ["main.py"],

    # Allow imports from src/
    pathex=["src"],

    # PySide6 DLLs and binaries
    binaries=pyside6_binaries,

    # Project + PySide6 data
    datas=datas,

    # Hidden imports
    hiddenimports=hidden_imports,

    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],

    excludes=[],

    win_no_prefer_redirects=False,
    win_private_assemblies=False,

    cipher=block_cipher,
    noarchive=False,
)


# ============================================================
# PYZ
# ============================================================
pyz = PYZ(
    a.pure,
    a.zipped_data,
    cipher=block_cipher,
)


# ============================================================
# EXE
# ============================================================
exe = EXE(
    pyz,
    a.scripts,
    [],

    # Binaries/data are collected separately by COLLECT.
    exclude_binaries=True,

    name="NMD-Security-Dashboard",

    debug=False,

    bootloader_ignore_signals=False,

    strip=False,

    # UPX can sometimes cause problems with Qt DLLs.
    # Disable it for better PySide6 compatibility.
    upx=False,

    # GUI application: no console window.
    console=False,

    disable_windowed_traceback=False,

    argv_emulation=False,

    target_arch=None,

    codesign_identity=None,

    entitlements_file=None,

    # Application icon
    icon="resources/icon.ico",
)


# ============================================================
# COLLECT
# ============================================================
coll = COLLECT(
    exe,

    # Application binaries
    a.binaries,

    # Python zip files
    a.zipfiles,

    # Application + PySide6 data
    a.datas,

    strip=False,

    # Disable UPX for Qt/PySide6 compatibility.
    upx=False,

    upx_exclude=[],

    # Final directory name
    name="NMD",
)