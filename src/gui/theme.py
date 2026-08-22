"""Dark Theme & Styling Engine for PySide6 (NMD).

Provides cybersecurity color palette, font definitions, and QSS stylesheets.
"""

from __future__ import annotations

COLOR_PALETTE = {
    "bg_dark": "#0F172A",       # Slate 900
    "bg_card": "#1E293B",       # Slate 800
    "bg_hover": "#334155",      # Slate 700
    "border": "#334155",        # Slate 700
    "text_bright": "#F8FAFC",   # Slate 50
    "text_dim": "#94A3B8",      # Slate 400
    "accent_blue": "#3B82F6",   # Blue 500
    "accent_cyan": "#06B6D4",   # Cyan 500
    "accent_hover": "#2563EB",  # Blue 600
    "success": "#10B981",       # Emerald 500
    "warning": "#F59E0B",       # Amber 500
    "danger": "#EF4444",        # Red 500
    "purple": "#8B5CF6",       # Purple 500
}

MODERN_QSS = """
QMainWindow {
    background-color: #0F172A;
}

QWidget {
    font-family: 'Segoe UI', Arial, sans-serif;
    color: #F8FAFC;
}

/* Sidebar Styling */
QFrame#SidebarFrame {
    background-color: #1E293B;
    border-right: 1px solid #334155;
}

QPushButton#NavButton {
    background-color: transparent;
    color: #94A3B8;
    border: none;
    border-radius: 8px;
    padding: 10px 16px;
    font-size: 14px;
    font-weight: 600;
    text-align: left;
}

QPushButton#NavButton:hover {
    background-color: #334155;
    color: #F8FAFC;
}

QPushButton#NavButton:checked {
    background-color: #3B82F6;
    color: #FFFFFF;
}

/* Card Frames */
QFrame#CardFrame {
    background-color: #1E293B;
    border: 1px solid #334155;
    border-radius: 12px;
}

QFrame#CardHeader {
    background-color: rgba(59, 130, 246, 0.1);
    border-bottom: 1px solid #334155;
    border-top-left-radius: 12px;
    border-top-right-radius: 12px;
}

/* Labels */
QLabel#TitleLabel {
    font-size: 20px;
    font-weight: bold;
    color: #F8FAFC;
}

QLabel#SubtitleLabel {
    font-size: 13px;
    color: #94A3B8;
}

QLabel#StatValue {
    font-size: 28px;
    font-weight: bold;
    color: #3B82F6;
}

QLabel#StatLabel {
    font-size: 12px;
    font-weight: 600;
    color: #94A3B8;
    text-transform: uppercase;
}

/* Standard Buttons */
QPushButton#PrimaryButton {
    background-color: #3B82F6;
    color: #FFFFFF;
    border: none;
    border-radius: 8px;
    padding: 8px 18px;
    font-size: 13px;
    font-weight: 600;
}

QPushButton#PrimaryButton:hover {
    background-color: #2563EB;
}

QPushButton#PrimaryButton:disabled {
    background-color: #475569;
    color: #94A3B8;
}

QPushButton#DangerButton {
    background-color: #EF4444;
    color: #FFFFFF;
    border: none;
    border-radius: 8px;
    padding: 8px 18px;
    font-size: 13px;
    font-weight: 600;
}

QPushButton#DangerButton:hover {
    background-color: #DC2626;
}

QPushButton#SecondaryButton {
    background-color: #334155;
    color: #F8FAFC;
    border: 1px solid #475569;
    border-radius: 8px;
    padding: 8px 18px;
    font-size: 13px;
}

QPushButton#SecondaryButton:hover {
    background-color: #475569;
}

/* Input Fields */
QLineEdit, QComboBox, QSpinBox {
    background-color: #0F172A;
    border: 1px solid #334155;
    border-radius: 6px;
    padding: 8px 12px;
    color: #F8FAFC;
    font-size: 13px;
}

QLineEdit:focus, QComboBox:focus, QSpinBox:focus {
    border: 1px solid #3B82F6;
}

QComboBox::drop-down {
    border: none;
}

/* Tables */
QTableWidget {
    background-color: #0F172A;
    border: 1px solid #334155;
    border-radius: 8px;
    gridline-color: #1E293B;
    font-size: 13px;
}

QTableWidget::item {
    padding: 6px 10px;
}

QTableWidget::item:selected {
    background-color: rgba(59, 130, 246, 0.25);
    color: #F8FAFC;
}

QHeaderView::section {
    background-color: #1E293B;
    color: #94A3B8;
    font-weight: 600;
    font-size: 12px;
    border: none;
    border-bottom: 1px solid #334155;
    padding: 8px;
}

/* Log Console Text Area */
QTextEdit#LogConsole {
    background-color: #0B0F19;
    border: 1px solid #334155;
    border-radius: 8px;
    font-family: 'Consolas', 'Courier New', monospace;
    font-size: 12px;
    color: #38BDF8;
    padding: 8px;
}

/* Scrollbars */
QScrollBar:vertical {
    background-color: #0F172A;
    width: 8px;
    margin: 0px;
}

QScrollBar::handle:vertical {
    background-color: #334155;
    border-radius: 4px;
    min-height: 20px;
}

QScrollBar::handle:vertical:hover {
    background-color: #475569;
}

QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0px;
}

/* Status Bar */
QStatusBar {
    background-color: #1E293B;
    border-top: 1px solid #334155;
    color: #94A3B8;
    font-size: 12px;
}
"""
