"""Main dashboard page (Developer 3, task 2).

Displays network visualization, device counters, last-scan information and
the clickable device grid. Every value is read from Developer 1's database
API — this page never scans, never analyzes and never fabricates records.
"""
from datetime import datetime
from typing import Any, Callable

import customtkinter as ctk

from core.database import get_all_devices, get_scan_history
from gui.resources import color, font, layout, status_color
from gui.widgets.device_card import DeviceCard, device_value
from gui.widgets.device_details import show_device_details
from utils.logger import log_event

CARD_COLUMNS = 3
MAX_MAP_NODES = 8


class MainPage(ctk.CTkFrame):
    """Dashboard page: counters, network map, scan info and device cards."""

    def __init__(
        self,
        master: Any,
        on_scan_request: Callable[[], None] | None = None,
        scan_enabled: bool = True,
        **kwargs: Any,
    ) -> None:
        super().__init__(master, fg_color=color("bg_primary"), **kwargs)

        self._on_scan_request = on_scan_request
        self._scan_enabled = scan_enabled
        self._refresh_job: str | None = None
        self._devices: list[Any] = []
        self._card_widgets: list[ctk.CTkBaseClass] = []

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(3, weight=1)

        self._build_header()
        self._build_counters()
        self._build_middle_row()
        self._build_device_area()

        self.refresh()
        self._schedule_auto_refresh()

    # ------------------------------------------------------------------
    # Layout construction
    # ------------------------------------------------------------------
    def _build_header(self) -> None:
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", padx=16, pady=(14, 8))
        header.grid_columnconfigure(2, weight=1)

        ctk.CTkLabel(
            header,
            text="Dashboard",
            font=font("size_title", weight="bold"),
            text_color=color("text_primary"),
        ).grid(row=0, column=0, sticky="w")

        self._updated_label = ctk.CTkLabel(
            header,
            text="",
            font=font("size_small"),
            text_color=color("text_muted"),
        )
        self._updated_label.grid(row=0, column=1, sticky="w", padx=10)

        ctk.CTkButton(
            header,
            text="Refresh",
            width=92,
            font=font("size_body"),
            fg_color=color("button_bg"),
            hover_color=color("button_hover"),
            text_color=color("button_text"),
            corner_radius=layout("radius", 10),
            command=self.refresh,
        ).grid(row=0, column=3, padx=(0, 8))

        self._scan_button = ctk.CTkButton(
            header,
            text="Scan now",
            width=104,
            font=font("size_body"),
            fg_color=color("accent") if self._scan_enabled else color("button_bg"),
            hover_color=color("accent_hover"),
            text_color=color("text_primary"),
            corner_radius=layout("radius", 10),
            state="normal" if self._scan_enabled else "disabled",
            command=self._handle_scan_request,
        )
        self._scan_button.grid(row=0, column=4)

    def _build_counters(self) -> None:
        row = ctk.CTkFrame(self, fg_color="transparent")
        row.grid(row=1, column=0, sticky="ew", padx=16)
        for index in range(4):
            row.grid_columnconfigure(index, weight=1, uniform="counters")

        self._counter_values: dict[str, ctk.CTkLabel] = {}
        definitions = [
            ("total", "Total devices", color("text_primary")),
            ("online", "Online", status_color("online")),
            ("offline", "Offline", status_color("offline")),
            ("new", "New", status_color("new")),
        ]

        for index, (key, label, value_color) in enumerate(definitions):
            card = ctk.CTkFrame(
                row,
                fg_color=color("card_bg"),
                border_color=color("card_border"),
                border_width=1,
                corner_radius=layout("radius", 10),
            )
            card.grid(row=0, column=index, sticky="ew", padx=(0 if index == 0 else 5, 5))
            ctk.CTkLabel(
                card,
                text=label,
                font=font("size_small"),
                text_color=color("text_secondary"),
                anchor="w",
            ).pack(anchor="w", padx=14, pady=(10, 0))
            value = ctk.CTkLabel(
                card,
                text="0",
                font=font("size_metric", weight="bold"),
                text_color=value_color,
                anchor="w",
            )
            value.pack(anchor="w", padx=14, pady=(0, 10))
            self._counter_values[key] = value

    def _build_middle_row(self) -> None:
        row = ctk.CTkFrame(self, fg_color="transparent")
        row.grid(row=2, column=0, sticky="ew", padx=16, pady=10)
        row.grid_columnconfigure(0, weight=3)
        row.grid_columnconfigure(1, weight=2)

        map_card = ctk.CTkFrame(
            row,
            fg_color=color("card_bg"),
            border_color=color("card_border"),
            border_width=1,
            corner_radius=layout("radius", 10),
        )
        map_card.grid(row=0, column=0, sticky="nsew", padx=(0, 5))
        ctk.CTkLabel(
            map_card,
            text="Network map",
            font=font("size_small"),
            text_color=color("text_secondary"),
            anchor="w",
        ).pack(anchor="w", padx=14, pady=(10, 0))

        self._canvas = ctk.CTkCanvas(
            map_card,
            height=170,
            bg=color("card_bg"),
            highlightthickness=0,
            bd=0,
        )
        self._canvas.pack(fill="both", expand=True, padx=10, pady=(4, 10))
        self._canvas.bind("<Configure>", lambda _e: self._draw_network_map())

        scan_card = ctk.CTkFrame(
            row,
            fg_color=color("card_bg"),
            border_color=color("card_border"),
            border_width=1,
            corner_radius=layout("radius", 10),
        )
        scan_card.grid(row=0, column=1, sticky="nsew", padx=(5, 0))
        scan_card.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(
            scan_card,
            text="Last scan",
            font=font("size_small"),
            text_color=color("text_secondary"),
            anchor="w",
        ).grid(row=0, column=0, columnspan=2, sticky="w", padx=14, pady=(10, 6))

        self._scan_values: dict[str, ctk.CTkLabel] = {}
        fields = [
            ("scan_date", "date"),
            ("duration", "duration"),
            ("total_devices", "devices found"),
            ("new_devices", "new"),
            ("disconnected_devices", "disconnected"),
        ]
        colors = {
            "new_devices": status_color("new"),
            "disconnected_devices": status_color("offline"),
        }
        for index, (key, label) in enumerate(fields, start=1):
            ctk.CTkLabel(
                scan_card,
                text=label,
                font=font("size_body"),
                text_color=color("text_secondary"),
                anchor="w",
            ).grid(row=index, column=0, sticky="w", padx=(14, 8), pady=3)
            value = ctk.CTkLabel(
                scan_card,
                text="—",
                font=font("size_body"),
                text_color=colors.get(key, color("text_primary")),
                anchor="e",
            )
            value.grid(row=index, column=1, sticky="e", padx=(0, 14), pady=3)
            self._scan_values[key] = value

    def _build_device_area(self) -> None:
        wrapper = ctk.CTkFrame(self, fg_color="transparent")
        wrapper.grid(row=3, column=0, sticky="nsew", padx=16, pady=(0, 14))
        wrapper.grid_columnconfigure(0, weight=1)
        wrapper.grid_rowconfigure(1, weight=1)

        ctk.CTkLabel(
            wrapper,
            text="Devices",
            font=font("size_small"),
            text_color=color("text_secondary"),
            anchor="w",
        ).grid(row=0, column=0, sticky="w", pady=(0, 6))

        self._device_container = ctk.CTkScrollableFrame(
            wrapper,
            fg_color=color("bg_secondary"),
            corner_radius=layout("radius", 10),
        )
        self._device_container.grid(row=1, column=0, sticky="nsew")
        for column in range(CARD_COLUMNS):
            self._device_container.grid_columnconfigure(column, weight=1, uniform="cards")

    # ------------------------------------------------------------------
    # Data refresh (always runs on the Tk main thread)
    # ------------------------------------------------------------------
    def refresh(self) -> None:
        """Reload devices and scan history from the database and repaint."""
        try:
            self._devices = get_all_devices() or []
        except Exception as exc:
            log_event(f"Dashboard could not load devices: {exc}", "error")
            self._devices = []

        self._update_counters()
        self._update_scan_info()
        self._render_device_cards()
        self._draw_network_map()
        self._updated_label.configure(text=f"updated {datetime.now().strftime('%H:%M:%S')}")

    def _update_counters(self) -> None:
        statuses = [str(device_value(d, "status", "unknown")).lower() for d in self._devices]
        self._counter_values["total"].configure(text=str(len(self._devices)))
        self._counter_values["online"].configure(text=str(statuses.count("online")))
        self._counter_values["offline"].configure(text=str(statuses.count("offline")))
        self._counter_values["new"].configure(text=str(statuses.count("new")))

    def _update_scan_info(self) -> None:
        try:
            history = get_scan_history(limit=1) or []
        except Exception as exc:
            log_event(f"Dashboard could not load scan history: {exc}", "error")
            history = []

        if not history:
            for label in self._scan_values.values():
                label.configure(text="—")
            return

        scan = history[0]
        scan_date = device_value(scan, "scan_date", None)
        if isinstance(scan_date, datetime):
            scan_date = scan_date.strftime("%Y-%m-%d %H:%M:%S")
        duration = device_value(scan, "duration", 0) or 0

        self._scan_values["scan_date"].configure(text=str(scan_date or "—"))
        self._scan_values["duration"].configure(text=f"{float(duration):.2f} s")
        self._scan_values["total_devices"].configure(text=str(device_value(scan, "total_devices", 0)))
        self._scan_values["new_devices"].configure(text=str(device_value(scan, "new_devices", 0)))
        self._scan_values["disconnected_devices"].configure(
            text=str(device_value(scan, "disconnected_devices", 0))
        )

    def _render_device_cards(self) -> None:
        for widget in self._card_widgets:
            widget.destroy()
        self._card_widgets = []

        if not self._devices:
            self._render_empty_state()
            return

        for index, device in enumerate(self._devices):
            card = DeviceCard(self._device_container, device, on_click=self._open_details)
            card.grid(
                row=index // CARD_COLUMNS,
                column=index % CARD_COLUMNS,
                sticky="ew",
                padx=6,
                pady=6,
            )
            self._card_widgets.append(card)

    def _render_empty_state(self) -> None:
        """Shown when the database holds no device. No fake records, ever."""
        empty = ctk.CTkFrame(self._device_container, fg_color="transparent")
        empty.grid(row=0, column=0, columnspan=CARD_COLUMNS, sticky="nsew", pady=48)
        ctk.CTkLabel(
            empty,
            text="No devices discovered yet",
            font=font("size_heading"),
            text_color=color("text_primary"),
        ).pack()
        ctk.CTkLabel(
            empty,
            text="Run a scan to populate the dashboard.",
            font=font("size_body"),
            text_color=color("text_secondary"),
        ).pack(pady=(4, 0))
        self._card_widgets.append(empty)

    # ------------------------------------------------------------------
    # Network visualization
    # ------------------------------------------------------------------
    def _draw_network_map(self) -> None:
        canvas = self._canvas
        canvas.delete("all")

        width = max(canvas.winfo_width(), 320)
        height = max(canvas.winfo_height(), 150)
        line_color = color("border")
        router_x, router_y = width // 2, 30

        if not self._devices:
            canvas.create_text(
                width // 2,
                height // 2,
                text="No devices to display",
                fill=color("text_muted"),
                font=font("size_body"),
            )
            return

        canvas.create_rectangle(
            router_x - 46, router_y - 16, router_x + 46, router_y + 16,
            outline=color("accent"), fill=color("bg_tertiary"), width=1,
        )
        canvas.create_text(
            router_x, router_y, text="ROUTER", fill=color("accent_text"), font=font("size_small")
        )

        shown = self._devices[:MAX_MAP_NODES]
        node_y = height - 46
        slot = width / (len(shown) + 1)

        for index, device in enumerate(shown, start=1):
            node_x = slot * index
            status = str(device_value(device, "status", "unknown")).lower()
            ip = str(device_value(device, "ip"))
            short_ip = ip.split(".")[-1] if "." in ip else ip

            canvas.create_line(router_x, router_y + 16, node_x, node_y - 16, fill=line_color)
            canvas.create_rectangle(
                node_x - 34, node_y - 16, node_x + 34, node_y + 16,
                outline=status_color(status), fill=color("bg_secondary"), width=1,
            )
            canvas.create_oval(
                node_x - 26, node_y - 4, node_x - 18, node_y + 4,
                fill=status_color(status), outline="",
            )
            canvas.create_text(
                node_x + 6, node_y, text=f".{short_ip}",
                fill=color("text_primary"), font=font("size_small"),
            )

        hidden = len(self._devices) - len(shown)
        if hidden > 0:
            canvas.create_text(
                width - 60, 16, text=f"+{hidden} more",
                fill=color("text_muted"), font=font("size_small"),
            )

    # ------------------------------------------------------------------
    # Interactions
    # ------------------------------------------------------------------
    def _open_details(self, device: Any) -> None:
        show_device_details(self.winfo_toplevel(), device)

    def _handle_scan_request(self) -> None:
        if callable(self._on_scan_request):
            self._on_scan_request()

    def set_scan_enabled(self, enabled: bool) -> None:
        """Enable/disable the 'Scan now' button (e.g. when Nmap is missing)."""
        self._scan_enabled = enabled
        self._scan_button.configure(
            state="normal" if enabled else "disabled",
            fg_color=color("accent") if enabled else color("button_bg"),
        )

    # ------------------------------------------------------------------
    # Auto refresh
    # ------------------------------------------------------------------
    def _schedule_auto_refresh(self) -> None:
        interval = int(layout("refresh_interval_ms", 5000))
        self._refresh_job = self.after(interval, self._auto_refresh_tick)

    def _auto_refresh_tick(self) -> None:
        if not self.winfo_exists():
            return
        self.refresh()
        self._schedule_auto_refresh()

    def stop_auto_refresh(self) -> None:
        """Cancel the pending after() job (called before the window closes)."""
        if self._refresh_job is not None:
            try:
                self.after_cancel(self._refresh_job)
            except Exception:
                pass
            self._refresh_job = None

    def destroy(self) -> None:
        self.stop_auto_refresh()
        super().destroy()