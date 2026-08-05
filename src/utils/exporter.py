"""Export device data to CSV and PDF reports (data/exports/). NEW (plan2)."""
import csv
import os
from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.pagesizes import landscape, A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
EXPORT_DIR = os.path.join(PROJECT_ROOT, "data", "exports")

FIELDS = [
    "ip", "hostname", "mac", "vendor", "os",
    "device_type", "open_ports", "status", "custom_label", "last_seen",
]


def _ensure_dir() -> None:
    os.makedirs(EXPORT_DIR, exist_ok=True)


def _timestamped_path(ext: str) -> str:
    _ensure_dir()
    date_str = datetime.now().strftime("%Y-%m-%d")
    path = os.path.join(EXPORT_DIR, f"devices_{date_str}.{ext}")
    counter = 1
    while os.path.exists(path):
        path = os.path.join(EXPORT_DIR, f"devices_{date_str}_{counter}.{ext}")
        counter += 1
    return path


def _prepare_rows(devices: list[dict]) -> list[dict]:
    """Flatten each device dict for tabular display (ports dict -> count)."""
    rows = []
    for device in devices:
        row = dict(device)
        row["open_ports"] = len(device.get("ports") or {})
        rows.append(row)
    return rows


def export_to_csv(devices: list[dict], path: str | None = None) -> str:
    """Export a list of device dicts (e.g. Device.to_dict()) to CSV. Returns the file path."""
    path = path or _timestamped_path("csv")
    rows = _prepare_rows(devices)
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    return path


def export_to_pdf(devices: list[dict], path: str | None = None) -> str:
    """Export a list of device dicts to a PDF report (reportlab). Returns the file path."""
    path = path or _timestamped_path("pdf")
    rows = _prepare_rows(devices)
    styles = getSampleStyleSheet()

    header = [f.replace("_", " ").title() for f in FIELDS]
    table_data = [header] + [[str(row.get(f, "") or "") for f in FIELDS] for row in rows]

    table = Table(table_data, repeatRows=1)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2563eb")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f4f7fc")]),
    ]))

    doc = SimpleDocTemplate(path, pagesize=landscape(A4))
    doc.build([
        Paragraph("NMD - Device Report", styles["Title"]),
        Paragraph(
            f"Generated on {datetime.now().strftime('%Y-%m-%d %H:%M')} — {len(rows)} device(s)",
            styles["Normal"],
        ),
        Spacer(1, 12),
        table,
    ])
    return path
