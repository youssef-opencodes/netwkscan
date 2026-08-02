"""GUI pages package (Developer 3).

Exports the main dashboard page. Developer 4 pages (custom_scan, logs_page)
register themselves through MainWindow.register_page() and are not imported
here, so this package stays importable while those files are empty.
"""
from gui.pages.main_page import MainPage

__all__ = ["MainPage"]