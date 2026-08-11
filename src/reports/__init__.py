"""Reports package for NMD."""
from .vulnerability_report import generate_vulnerability_txt_report, generate_vulnerability_pdf_report

__all__ = [
    "generate_vulnerability_txt_report",
    "generate_vulnerability_pdf_report",
]
