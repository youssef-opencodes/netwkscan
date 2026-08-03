"""Custom scan page - Manual scan with Nmap options (Developer 4, task 1).

Provides interface for custom scans with configurable options:
- Target IP/CIDR input
- Scan type selection (-sn, -sV, -O, -A)
- Port range input
- Results display with device cards
"""

import customtkinter as ctk

from core.database import get_all_devices, get_device_by_ip
from core.scanner import Scanner
from gui.resources import color, font, layout, status_color
from gui.widgets.device_card import DeviceCard
from gui.widgets.status_badge import StatusBadge
from utils.config import load_config, update_config
from utils.logger import log_event


class CustomScanPage(ctk.CTkFrame):
    """Custom scan page with input controls and results display."""

    def __init__(self, master, **kwargs) -> None:
        super().__init__(master, fg_color=color("bg_primary"), **kwargs)

        self._scanner = Scanner()
        self._scan_results = []
        self._result_widgets = []

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)

        self._build_input_section()
        self._build_options_section()
        self._build_results_section()

        # Load default values from config
        self._load_defaults()

    def _build_input_section(self) -> None:
        """Build target input and scan button."""
        input_frame = ctk.CTkFrame(self, fg_color="transparent")
        input_frame.grid(row=0, column=0, sticky="ew", padx=16, pady=(14, 8))
        input_frame.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(
            input_frame,
            text="Custom Scan",
            font=font("size_title", weight="bold"),
            text_color=color("text_primary"),
        ).grid(row=0, column=0, sticky="w", padx=(0, 16))

        # Target input
        self._target_entry = ctk.CTkEntry(
            input_frame,
            placeholder_text="Target (e.g. 192.168.1.0/24 or 192.168.1.1)",
            font=font("size_body"),
            fg_color=color("bg_secondary"),
            text_color=color("text_primary"),
            border_color=color("border"),
            border_width=1,
            corner_radius=layout("radius", 10),
            height=38,
            width=300,
        )
        self._target_entry.grid(row=0, column=1, sticky="w", padx=(0, 10))

        # Scan button
        self._scan_button = ctk.CTkButton(
            input_frame,
            text="▶ Start Scan",
            width=120,
            height=38,
            font=font("size_body", weight="bold"),
            fg_color=color("accent"),
            hover_color=color("accent_hover"),
            text_color=color("text_primary"),
            corner_radius=layout("radius", 10),
            command=self._start_scan,
        )
        self._scan_button.grid(row=0, column=2, sticky="w")

        # Status indicator
        self._status_label = ctk.CTkLabel(
            input_frame,
            text="",
            font=font("size_small"),
            text_color=color("text_muted"),
        )
        self._status_label.grid(row=0, column=3, sticky="w", padx=(12, 0))

    def _build_options_section(self) -> None:
        """Build scan options checkboxes and port input."""
        options_frame = ctk.CTkFrame(
            self,
            fg_color=color("bg_secondary"),
            corner_radius=layout("radius", 10),
        )
        options_frame.grid(row=1, column=0, sticky="ew", padx=16, pady=(0, 10))
        options_frame.grid_columnconfigure(4, weight=1)

        # Label
        ctk.CTkLabel(
            options_frame,
            text="Scan Options",
            font=font("size_small", weight="bold"),
            text_color=color("text_secondary"),
        ).grid(row=0, column=0, sticky="w", padx=12, pady=(8, 0))

        # Scan type checkboxes
        self._scan_vars = {}
        scan_options = [
            ("-sn", "Ping scan"),
            ("-sV", "Version detection"),
            ("-O", "OS detection"),
            ("-A", "Aggressive scan"),
        ]

        for idx, (flag, label) in enumerate(scan_options):
            var = ctk.StringVar(value="off")
            self._scan_vars[flag] = var

            cb = ctk.CTkCheckBox(
                options_frame,
                text=label,
                variable=var,
                onvalue="on",
                offvalue="off",
                font=font("size_body"),
                fg_color=color("accent"),
                hover_color=color("accent_hover"),
                text_color=color("text_primary"),
                checkmark_color=color("text_primary"),
                corner_radius=4,
            )
            cb.grid(row=0, column=idx + 1, sticky="w", padx=(4 if idx > 0 else 12, 8), pady=(6, 8))

        # Port range
        ctk.CTkLabel(
            options_frame,
            text="Ports:",
            font=font("size_body"),
            text_color=color("text_secondary"),
        ).grid(row=0, column=5, sticky="w", padx=(16, 4), pady=(6, 8))

        self._ports_entry = ctk.CTkEntry(
            options_frame,
            placeholder_text="e.g. 1-1024, 80,443",
            font=font("size_body"),
            fg_color=color("bg_primary"),
            text_color=color("text_primary"),
            border_color=color("border"),
            border_width=1,
            corner_radius=layout("radius", 10),
            height=32,
            width=160,
        )
        self._ports_entry.grid(row=0, column=6, sticky="w", padx=(0, 12), pady=(6, 8))

    def _build_results_section(self) -> None:
        """Build scrollable results area."""
        # Header with count
        results_header = ctk.CTkFrame(self, fg_color="transparent")
        results_header.grid(row=2, column=0, sticky="ew", padx=16, pady=(0, 6))
        results_header.grid_columnconfigure(0, weight=1)

        self._results_label = ctk.CTkLabel(
            results_header,
            text="Results: 0 devices found",
            font=font("size_small"),
            text_color=color("text_secondary"),
        )
        self._results_label.grid(row=0, column=0, sticky="w")

        # Container for results
        self._results_container = ctk.CTkScrollableFrame(
            self,
            fg_color=color("bg_secondary"),
            corner_radius=layout("radius", 10),
        )
        self._results_container.grid(row=3, column=0, sticky="nsew", padx=16, pady=(0, 14))
        self._results_container.grid_columnconfigure(0, weight=1)

    def _load_defaults(self) -> None:
        """Load default values from config."""
        try:
            config = load_config()
            self._target_entry.insert(0, config.get("subnet", "192.168.1.0/24"))
            self._ports_entry.insert(0, config.get("port_range", "1-1024"))
        except Exception:
            pass

    def _get_scan_arguments(self) -> str:
        """Build Nmap arguments from selected checkboxes."""
        args = []
        for flag, var in self._scan_vars.items():
            if var.get() == "on":
                args.append(flag)

        # Default to ping scan if nothing selected
        if not args:
            args.append("-sn")

        return " ".join(args)

    def _start_scan(self) -> None:
        """Execute the custom scan."""
        target = self._target_entry.get().strip()
        if not target:
            self._show_status("Please enter a target", "error")
            return

        ports = self._ports_entry.get().strip() or None
        arguments = self._get_scan_arguments()

        # Disable button during scan
        self._scan_button.configure(state="disabled", text="⏳ Scanning...")
        self._show_status(f"Scanning {target}...", "info")

        try:
            # Execute scan
            results, duration = self._scanner.custom_scan(
                target=target,
                ports=ports,
                arguments=arguments,
            )

            self._scan_results = results
            self._display_results(results, duration)

            # Update config with last used values
            update_config(
                subnet=target,
                port_range=ports or "1-1024",
                scan_type="custom",
            )

            self._show_status(f"Completed in {duration}s - {len(results)} devices found", "success")

        except Exception as e:
            self._show_status(f"Error: {str(e)}", "error")
            log_event(f"Custom scan failed: {e}", "error")

        finally:
            self._scan_button.configure(state="normal", text="▶ Start Scan")

    def _display_results(self, results: list, duration: float) -> None:
        """Display scan results as device cards."""
        # Clear previous results
        for widget in self._result_widgets:
            widget.destroy()
        self._result_widgets = []

        # Update count
        self._results_label.configure(text=f"Results: {len(results)} devices found in {duration:.2f}s")

        if not results:
            empty = ctk.CTkFrame(self._results_container, fg_color="transparent")
            empty.grid(row=0, column=0, sticky="nsew", pady=48)

            ctk.CTkLabel(
                empty,
                text="No devices found",
                font=font("size_heading"),
                text_color=color("text_primary"),
            ).pack()

            ctk.CTkLabel(
                empty,
                text="Try changing the target or scan options.",
                font=font("size_body"),
                text_color=color("text_secondary"),
            ).pack(pady=(4, 0))

            self._result_widgets.append(empty)
            return

        # Display as cards (2 columns)
        cols = 2
        for idx, device_data in enumerate(results):
            row = idx // cols
            col = idx % cols

            # Create card
            card = self._create_result_card(device_data)
            card.grid(
                row=row,
                column=col,
                sticky="nsew",
                padx=6,
                pady=6,
            )
            self._result_widgets.append(card)

        # Configure column weights
        for col in range(cols):
            self._results_container.grid_columnconfigure(col, weight=1, uniform="cards")

    def _create_result_card(self, device_data: dict) -> ctk.CTkFrame:
        """Create a card for a single device result."""
        card = ctk.CTkFrame(
            self._results_container,
            fg_color=color("card_bg"),
            border_color=color("card_border"),
            border_width=1,
            corner_radius=layout("radius", 10),
        )

        ip = device_data.get("ip", "Unknown")
        hostname = device_data.get("hostname", "")
        mac = device_data.get("mac", "")
        vendor = device_data.get("vendor", "")
        os_info = device_data.get("os", "")

        # Check if device exists in database for status
        existing = get_device_by_ip(ip)
        if existing:
            status = getattr(existing, "status", "online")
        else:
            status = "new"

        pad = layout("card_padding", 12)

        # IP with status badge
        ip_frame = ctk.CTkFrame(card, fg_color="transparent")
        ip_frame.pack(fill="x", padx=pad, pady=(pad, 0))

        ctk.CTkLabel(
            ip_frame,
            text=ip,
            font=font("size_heading", mono=True),
            text_color=color("text_primary"),
            anchor="w",
        ).pack(side="left")

        # Status badge
        StatusBadge(
            ip_frame,
            status=status,
            text="",
            dot_size=8,
        ).pack(side="left", padx=(8, 0))

        # Hostname
        if hostname:
            ctk.CTkLabel(
                card,
                text=f"🏷 {hostname}",
                font=font("size_body"),
                text_color=color("text_secondary"),
                anchor="w",
            ).pack(fill="x", padx=pad, pady=(2, 0))

        # MAC & Vendor
        details = []
        if mac:
            details.append(mac)
        if vendor:
            details.append(vendor)
        if os_info:
            details.append(os_info)

        if details:
            ctk.CTkLabel(
                card,
                text=" · ".join(details),
                font=font("size_small"),
                text_color=color("text_muted"),
                anchor="w",
                wraplength=180,
                justify="left",
            ).pack(fill="x", padx=pad, pady=(2, pad))

        return card

    def _show_status(self, message: str, level: str = "info") -> None:
        """Update status label with color."""
        colors = {
            "info": color("text_muted"),
            "success": status_color("online"),
            "error": status_color("offline"),
        }
        self._status_label.configure(text=message, text_color=colors.get(level, color("text_muted")))

    def refresh(self) -> None:
        """Refresh results (re-fetch device status from DB)."""
        if self._scan_results:
            self._display_results(self._scan_results, 0)