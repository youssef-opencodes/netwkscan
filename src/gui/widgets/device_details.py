"""Device details popup (Developer 3, task 4).

Opens a modal Toplevel describing a single device. Data is re-read from
Developer 1's database API (``get_device_by_ip``) so the popup always shows
the current persisted state, and falls back to the object it was handed if
the device is no longer in the database.
"""
from datetime import datetime
from typing import Any

import customtkinter as ctk

from core.database import get_device_by_ip
from gui.resources import color, font, layout, status_color
from gui.widgets.device_card import PLACEHOLDER, device_value

# The current schema (Developer 1) has no PORTS table, so open ports are not
# persisted yet. We display a graceful placeholder instead of inventing fields.
OPEN_PORTS_PLACEHOLDER = "Not available"


def format_datetime(value: Any) -> str:
    """Render a datetime (or ISO string) in a readable form."""
    if value in (None, "", PLACEHOLDER):
        return PLACEHOLDER
    if isinstance(value, datetime):
        return value.strftime("%Y-%m-%d %H:%M:%S")
    try:
        return datetime.fromisoformat(str(value)).strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        return str(value)


class DeviceDetails(ctk.CTkToplevel):
    """Modal popup showing every stored attribute of one device."""

    def __init__(self, master: Any, device: Any, **kwargs: Any) -> None:
        super().__init__(master, fg_color=color("bg_primary"), **kwargs)

        ip = str(device_value(device, "ip"))
        # Prefer fresh data from the database; keep the given object as fallback.
        try:
            refreshed = get_device_by_ip(ip)
        except Exception:
            refreshed = None
        self.device = refreshed or device

        self.title(f"Device — {ip}")
        self.geometry("460x520")
        self.minsize(420, 460)
        self.resizable(False, True)
        self.transient(master)

        self._build_header(ip)
        self._build_body()

        self.after(120, self._focus_popup)

    def _focus_popup(self) -> None:
        """Grab focus after the window is mapped (avoids Tk grab errors)."""
        try:
            self.grab_set()
            self.lift()
            self.focus_force()
        except Exception:
            pass

    def _build_header(self, ip: str) -> None:
        status = str(device_value(self.device, "status", "unknown")).lower()
        hostname = device_value(self.device, "hostname")

        header = ctk.CTkFrame(self, fg_color=color("bg_tertiary"), corner_radius=0)
        header.pack(fill="x")
        header.grid_columnconfigure(0, weight=1)

        titles = ctk.CTkFrame(header, fg_color="transparent")
        titles.grid(row=0, column=0, sticky="w", padx=16, pady=12)

        ctk.CTkLabel(
            titles,
            text=ip,
            font=font("size_title", mono=True),
            text_color=color("text_primary"),
            anchor="w",
        ).pack(anchor="w")
        ctk.CTkLabel(
            titles,
            text=str(hostname),
            font=font("size_small"),
            text_color=color("text_secondary"),
            anchor="w",
        ).pack(anchor="w")

        ctk.CTkLabel(
            header,
            text=f"  {status}  ",
            font=font("size_small"),
            text_color=status_color(status),
            fg_color=color("bg_secondary"),
            corner_radius=12,
        ).grid(row=0, column=1, padx=16)

    def _build_body(self) -> None:
        device = self.device
        rows = [
            ("ip", device_value(device, "ip")),
            ("mac", device_value(device, "mac")),
            ("hostname", device_value(device, "hostname")),
            ("vendor", device_value(device, "vendor")),
            ("os", device_value(device, "os")),
            ("status", device_value(device, "status")),
            ("custom label", device_value(device, "custom_label")),
            ("first seen", format_datetime(device_value(device, "first_seen"))),
            ("last seen", format_datetime(device_value(device, "last_seen"))),
            ("appearance count", device_value(device, "appearance_count", 0)),
            ("open ports", OPEN_PORTS_PLACEHOLDER),
        ]

        body = ctk.CTkScrollableFrame(self, fg_color=color("bg_primary"))
        body.pack(fill="both", expand=True, padx=12, pady=12)
        body.grid_columnconfigure(1, weight=1)

        for index, (key, value) in enumerate(rows):
            is_placeholder = value == OPEN_PORTS_PLACEHOLDER
            ctk.CTkLabel(
                body,
                text=key,
                font=font("size_body"),
                text_color=color("text_secondary"),
                anchor="w",
            ).grid(row=index, column=0, sticky="w", padx=(8, 12), pady=5)
            ctk.CTkLabel(
                body,
                text=str(value),
                font=font("size_body", mono=key in ("ip", "mac")),
                text_color=color("text_muted") if is_placeholder else color("text_primary"),
                anchor="e",
                wraplength=240,
                justify="right",
            ).grid(row=index, column=1, sticky="e", padx=(0, 8), pady=5)

        ctk.CTkButton(
            self,
            text="Close",
            width=110,
            font=font("size_body"),
            fg_color=color("button_bg"),
            hover_color=color("button_hover"),
            text_color=color("button_text"),
            corner_radius=layout("radius", 10),
            command=self.destroy,
        ).pack(pady=(0, 14))


def show_device_details(master: Any, device: Any) -> DeviceDetails | None:
    """Open the details popup for a device. Returns the popup instance."""
    if device is None:
        return None
    return DeviceDetails(master, device)