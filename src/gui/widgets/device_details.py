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

# Open ports will be displayed dynamically


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
            ("device type", device_value(device, "device_type", "Unknown")),
            ("vendor", device_value(device, "vendor")),
            ("os", device_value(device, "os")),
            ("status", device_value(device, "status")),
            ("first seen", format_datetime(device_value(device, "first_seen"))),
            ("last seen", format_datetime(device_value(device, "last_seen"))),
            ("appearance count", device_value(device, "appearance_count", 0)),
        ]

        body = ctk.CTkScrollableFrame(self, fg_color=color("bg_primary"))
        body.pack(fill="both", expand=True, padx=12, pady=12)
        body.grid_columnconfigure(1, weight=1)

        for index, (key, value) in enumerate(rows):
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
                text_color=color("text_primary"),
                anchor="e",
                wraplength=240,
                justify="right",
            ).grid(row=index, column=1, sticky="e", padx=(0, 8), pady=5)

        cur_row = len(rows)

        # Custom Label
        ctk.CTkLabel(
            body,
            text="custom label",
            font=font("size_body"),
            text_color=color("text_secondary"),
            anchor="w",
        ).grid(row=cur_row, column=0, sticky="w", padx=(8, 12), pady=5)

        label_frame = ctk.CTkFrame(body, fg_color="transparent")
        label_frame.grid(row=cur_row, column=1, sticky="e", padx=(0, 8), pady=5)

        self._label_entry = ctk.CTkEntry(
            label_frame,
            width=160,
            font=font("size_body"),
            fg_color=color("bg_secondary"),
            text_color=color("text_primary"),
            border_color=color("border")
        )
        self._label_entry.pack(side="left", padx=(0, 4))
        
        current_label = str(device_value(device, "custom_label", ""))
        if current_label != PLACEHOLDER:
            self._label_entry.insert(0, current_label)

        ctk.CTkButton(
            label_frame,
            text="Save",
            width=50,
            font=font("size_small"),
            fg_color=color("accent"),
            hover_color=color("accent_hover"),
            command=self._save_label
        ).pack(side="left")

        cur_row += 1

        # Open Ports
        ctk.CTkLabel(
            body,
            text="open ports",
            font=font("size_body"),
            text_color=color("text_secondary"),
            anchor="nw",
        ).grid(row=cur_row, column=0, sticky="nw", padx=(8, 12), pady=5)

        ports = device_value(device, "ports", {})
        if not ports or ports == PLACEHOLDER:
            ports_text = "No open ports found"
        else:
            ports_text = "\n".join([f"{p} → {s}" for p, s in ports.items()])

        ctk.CTkLabel(
            body,
            text=ports_text,
            font=font("size_body", mono=True),
            text_color=color("text_primary"),
            anchor="e",
            justify="right",
        ).grid(row=cur_row, column=1, sticky="e", padx=(0, 8), pady=5)

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

    def _save_label(self) -> None:
        from core.database import update_device_label
        ip = str(device_value(self.device, "ip"))
        new_label = self._label_entry.get().strip()
        update_device_label(ip, new_label)
        self.title(f"Device — {ip} (Saved)")


def show_device_details(master: Any, device: Any) -> DeviceDetails | None:
    """Open the details popup for a device. Returns the popup instance."""
    if device is None:
        return None
    return DeviceDetails(master, device)