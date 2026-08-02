"""Reusable clickable device card widget (Developer 3, task 3).

The card renders a single device coming from Developer 1's ``Device`` model
(or its ``to_dict()`` output). It never queries the database itself and never
invents data: it only displays what it is given.
"""
from typing import Any, Callable

import customtkinter as ctk

from gui.resources import color, font, layout, status_color

PLACEHOLDER = "—"


def device_value(device: Any, field: str, default: str = PLACEHOLDER) -> Any:
    """Read a field from a Device ORM object or from a plain dict.

    Keeps every widget compatible with both ``get_all_devices()`` (ORM objects)
    and ``get_device_history()`` (dict), without duplicating the model.
    """
    if device is None:
        return default
    if isinstance(device, dict):
        value = device.get(field)
    else:
        value = getattr(device, field, None)
    if value is None or value == "":
        return default
    return value


class DeviceCard(ctk.CTkFrame):
    """Compact clickable card showing IP address, status and vendor."""

    def __init__(
        self,
        master: Any,
        device: Any,
        on_click: Callable[[Any], None] | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(
            master,
            fg_color=color("card_bg"),
            border_color=color("card_border"),
            border_width=1,
            corner_radius=layout("radius", 10),
            **kwargs,
        )
        self.device = device
        self._on_click = on_click

        self._ip = str(device_value(device, "ip"))
        self._status = str(device_value(device, "status", "unknown")).lower()
        self._vendor = str(device_value(device, "vendor"))
        self._label = device_value(device, "custom_label", "")

        pad = layout("card_padding", 12)
        self.grid_columnconfigure(1, weight=1)

        self._ip_label = ctk.CTkLabel(
            self,
            text=self._ip,
            font=font("size_heading", mono=True),
            text_color=color("text_primary"),
            anchor="w",
        )
        self._ip_label.grid(row=0, column=0, columnspan=2, sticky="ew", padx=pad, pady=(pad, 0))

        status_row = ctk.CTkFrame(self, fg_color="transparent")
        status_row.grid(row=1, column=0, columnspan=2, sticky="ew", padx=pad, pady=(4, 0))

        self._dot = ctk.CTkFrame(
            status_row,
            width=9,
            height=9,
            corner_radius=5,
            fg_color=status_color(self._status),
        )
        self._dot.pack(side="left", pady=2)
        self._dot.pack_propagate(False)

        self._status_label = ctk.CTkLabel(
            status_row,
            text=self._status,
            font=font("size_small"),
            text_color=status_color(self._status),
            anchor="w",
        )
        self._status_label.pack(side="left", padx=(6, 0))

        subtitle = self._vendor
        if self._label:
            subtitle = f"{self._label} · {self._vendor}"

        self._vendor_label = ctk.CTkLabel(
            self,
            text=subtitle,
            font=font("size_small"),
            text_color=color("text_muted"),
            anchor="w",
            wraplength=190,
            justify="left",
        )
        self._vendor_label.grid(row=2, column=0, columnspan=2, sticky="ew", padx=pad, pady=(2, pad))

        self._bind_recursive(self)

    def _bind_recursive(self, widget: Any) -> None:
        """Make the whole card clickable, not only its background frame."""
        widget.bind("<Button-1>", self._handle_click)
        widget.bind("<Enter>", self._handle_enter)
        widget.bind("<Leave>", self._handle_leave)
        for child in widget.winfo_children():
            self._bind_recursive(child)

    def _handle_click(self, _event: Any = None) -> None:
        if callable(self._on_click):
            self._on_click(self.device)

    def _handle_enter(self, _event: Any = None) -> None:
        self.configure(fg_color=color("card_bg_hover"), border_color=color("accent"))

    def _handle_leave(self, _event: Any = None) -> None:
        self.configure(fg_color=color("card_bg"), border_color=color("card_border"))