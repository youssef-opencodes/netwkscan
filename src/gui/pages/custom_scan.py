"""Custom scan page - Full Nmap GUI with presets, options, and results (Developer 4).

Complete rewrite with:
- Target input
- Presets dropdown (default + custom)
- Scan options checkboxes (-sV, -O, -A, -sC, -v, --traceroute, -sU, -sS)
- Port specification (Common/All/Custom)
- Performance settings (Timing T0-T5)
- Save/Load/Delete Preset buttons
- Nmap command preview
- Start scan with results display
"""

import json
import re
from pathlib import Path

import customtkinter as ctk

from core import analyzer, database
from core.database import get_device_by_ip
from core.scanner import Scanner
from gui.resources import color, font, layout, status_color
from gui.widgets.port_badge import PortBadge
from gui.widgets.status_badge import StatusBadge
from utils.config import load_config, update_config
from utils.logger import log_event

# Removed DEFAULT_PRESETS in favor of src/presets/default.json


class CustomScanPage(ctk.CTkFrame):
    """Full Nmap GUI with presets, options, performance, and results."""

    def __init__(self, master, **kwargs):
        super().__init__(master, fg_color=color("bg_primary"), **kwargs)

        self._scanner = Scanner()
        self._scan_results = []
        self._result_widgets = []
        self._custom_presets = {}

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(9, weight=1)

        # Load presets (handled dynamically now)
        pass

        # Build UI sections
        self._build_target_section()
        self._build_preset_section()
        self._build_options_section()
        self._build_port_section()
        self._build_performance_section()
        self._build_preset_management()
        self._build_command_preview()
        self._build_scan_button()
        self._build_results_section()

        # Load defaults from config
        self._load_defaults()

    # ------------------------------------------------------------------
    # Preset Management
    # ------------------------------------------------------------------

    def _load_presets(self):
        pass

    def _save_presets(self):
        pass

    def _get_all_presets(self):
        """Return combined default + custom presets."""
        from presets import load_presets
        all_presets = load_presets()
        for name, p in all_presets.items():
            if "name" not in p:
                p["name"] = name
            if "args" in p:
                p["arguments"] = p["args"]
        return all_presets

    # ------------------------------------------------------------------
    # UI Construction
    # ------------------------------------------------------------------

    def _build_target_section(self):
        """Build target input section."""
        frame = ctk.CTkFrame(self, fg_color="transparent")
        frame.grid(row=0, column=0, sticky="ew", padx=16, pady=(14, 6))
        frame.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(
            frame,
            text="Target:",
            font=font("size_body", weight="bold"),
            text_color=color("text_secondary"),
        ).grid(row=0, column=0, sticky="w", padx=(0, 8))

        self._target_entry = ctk.CTkEntry(
            frame,
            placeholder_text="e.g. 192.168.0.0/24 or 192.168.0.105",
            font=font("size_body"),
            fg_color=color("bg_secondary"),
            text_color=color("text_primary"),
            border_color=color("border"),
            border_width=1,
            corner_radius=layout("radius", 10),
            height=38,
        )
        self._target_entry.grid(row=0, column=1, sticky="ew")

    def _build_preset_section(self):
        """Build presets dropdown."""
        frame = ctk.CTkFrame(self, fg_color="transparent")
        frame.grid(row=1, column=0, sticky="ew", padx=16, pady=(0, 6))
        frame.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(
            frame,
            text="Preset:",
            font=font("size_body", weight="bold"),
            text_color=color("text_secondary"),
        ).grid(row=0, column=0, sticky="w", padx=(0, 8))

        self._preset_var = ctk.StringVar(value="Select a preset...")
        self._preset_dropdown = ctk.CTkOptionMenu(
            frame,
            values=["Select a preset..."] + list(self._get_all_presets().keys()),
            command=self._on_preset_selected,
            font=font("size_body"),
            fg_color=color("bg_secondary"),
            text_color=color("text_primary"),
            button_color=color("bg_tertiary"),
            button_hover_color=color("border"),
            dropdown_fg_color=color("bg_secondary"),
            dropdown_text_color=color("text_primary"),
            dropdown_hover_color=color("bg_tertiary"),
            width=200,
        )
        self._preset_dropdown.grid(row=0, column=1, sticky="w")

        self._preset_description = ctk.CTkLabel(
            frame,
            text="",
            font=font("size_small"),
            text_color=color("text_muted"),
        )
        self._preset_description.grid(row=0, column=2, sticky="w", padx=(12, 0))

    def _build_options_section(self):
        """Build scan options checkboxes."""
        frame = ctk.CTkFrame(
            self,
            fg_color=color("bg_secondary"),
            corner_radius=layout("radius", 10),
        )
        frame.grid(row=2, column=0, sticky="ew", padx=16, pady=(0, 6))
        frame.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            frame,
            text="Scan Options",
            font=font("size_small", weight="bold"),
            text_color=color("text_secondary"),
        ).grid(row=0, column=0, columnspan=4, sticky="w", padx=12, pady=(8, 4))

        options = [
            ("-sV", "Version Detection"),
            ("-O", "OS Detection"),
            ("-A", "Aggressive Scan"),
            ("-sC", "Script Scan"),
            ("--traceroute", "Traceroute"),
            ("-v", "Verbose"),
            ("-sU", "UDP Scan"),
            ("-sS", "SYN Stealth"),
        ]

        self._option_vars = {}
        for idx, (flag, label) in enumerate(options):
            row = 1 + (idx // 4)
            col = idx % 4
            var = ctk.StringVar(value="off")
            self._option_vars[flag] = var

            cb = ctk.CTkCheckBox(
                frame,
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
                command=self._update_command_preview,
            )
            cb.grid(
                row=row,
                column=col,
                sticky="w",
                padx=(12 if col == 0 else 4, 8),
                pady=4,
            )

    def _build_port_section(self):
        """Build port specification."""
        frame = ctk.CTkFrame(
            self,
            fg_color=color("bg_secondary"),
            corner_radius=layout("radius", 10),
        )
        frame.grid(row=3, column=0, sticky="ew", padx=16, pady=(0, 6))
        frame.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            frame,
            text="Ports",
            font=font("size_small", weight="bold"),
            text_color=color("text_secondary"),
        ).grid(row=0, column=0, columnspan=3, sticky="w", padx=12, pady=(8, 4))

        self._port_var = ctk.StringVar(value="common")

        port_options = [
            ("common", "Common (1-1024)"),
            ("all", "All (1-65535)"),
            ("custom", "Custom:"),
        ]

        for idx, (value, label) in enumerate(port_options):
            rb = ctk.CTkRadioButton(
                frame,
                text=label,
                variable=self._port_var,
                value=value,
                font=font("size_body"),
                fg_color=color("accent"),
                hover_color=color("accent_hover"),
                text_color=color("text_primary"),
                command=self._update_command_preview,
            )
            rb.grid(row=1, column=idx, sticky="w", padx=(12 if idx == 0 else 8, 4), pady=4)

        self._custom_ports_entry = ctk.CTkEntry(
            frame,
            placeholder_text="e.g. 22,80,443 or 1-1000",
            font=font("size_body"),
            fg_color=color("bg_primary"),
            text_color=color("text_primary"),
            border_color=color("border"),
            border_width=1,
            corner_radius=layout("radius", 10),
            height=32,
            width=200,
        )
        self._custom_ports_entry.grid(row=1, column=3, sticky="w", padx=(0, 12), pady=4)
        self._custom_ports_entry.bind("<KeyRelease>", lambda e: self._update_command_preview())

    def _build_performance_section(self):
        """Build performance settings."""
        frame = ctk.CTkFrame(
            self,
            fg_color=color("bg_secondary"),
            corner_radius=layout("radius", 10),
        )
        frame.grid(row=4, column=0, sticky="ew", padx=16, pady=(0, 6))
        frame.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            frame,
            text="Performance",
            font=font("size_small", weight="bold"),
            text_color=color("text_secondary"),
        ).grid(row=0, column=0, columnspan=4, sticky="w", padx=12, pady=(8, 4))

        ctk.CTkLabel(
            frame,
            text="Timing:",
            font=font("size_body"),
            text_color=color("text_secondary"),
        ).grid(row=1, column=0, sticky="w", padx=(12, 4), pady=4)

        self._timing_var = ctk.StringVar(value="-T3")
        timing_dropdown = ctk.CTkOptionMenu(
            frame,
            values=["-T0", "-T1", "-T2", "-T3", "-T4", "-T5"],
            variable=self._timing_var,
            font=font("size_body"),
            fg_color=color("bg_primary"),
            text_color=color("text_primary"),
            button_color=color("bg_tertiary"),
            button_hover_color=color("border"),
            dropdown_fg_color=color("bg_primary"),
            dropdown_text_color=color("text_primary"),
            width=80,
            command=self._update_command_preview,
        )
        timing_dropdown.grid(row=1, column=1, sticky="w", padx=(0, 12), pady=4)

        ctk.CTkLabel(
            frame,
            text="Parallelism:",
            font=font("size_body"),
            text_color=color("text_secondary"),
        ).grid(row=1, column=2, sticky="w", padx=(12, 4), pady=4)

        self._parallelism_var = ctk.StringVar(value="")
        parallel_entry = ctk.CTkEntry(
            frame,
            textvariable=self._parallelism_var,
            placeholder_text="Hosts",
            font=font("size_body"),
            fg_color=color("bg_primary"),
            text_color=color("text_primary"),
            border_color=color("border"),
            border_width=1,
            corner_radius=layout("radius", 10),
            height=32,
            width=80,
        )
        parallel_entry.grid(row=1, column=3, sticky="w", padx=(0, 12), pady=4)
        parallel_entry.bind("<KeyRelease>", lambda e: self._update_command_preview())

        ctk.CTkLabel(
            frame,
            text="Host timeout:",
            font=font("size_body"),
            text_color=color("text_secondary"),
        ).grid(row=2, column=0, sticky="w", padx=(12, 4), pady=4)

        self._host_timeout_var = ctk.StringVar(value="")
        timeout_entry = ctk.CTkEntry(
            frame,
            textvariable=self._host_timeout_var,
            placeholder_text="e.g. 5m",
            font=font("size_body"),
            fg_color=color("bg_primary"),
            text_color=color("text_primary"),
            border_color=color("border"),
            border_width=1,
            corner_radius=layout("radius", 10),
            height=32,
            width=120,
        )
        timeout_entry.grid(row=2, column=1, sticky="w", padx=(0, 12), pady=4)
        timeout_entry.bind("<KeyRelease>", lambda e: self._update_command_preview())

        ctk.CTkLabel(
            frame,
            text="(Optional)",
            font=font("size_small"),
            text_color=color("text_muted"),
        ).grid(row=2, column=2, columnspan=2, sticky="w", padx=(12, 0), pady=4)

    def _build_preset_management(self):
        """Build Save/Load/Delete preset buttons."""
        frame = ctk.CTkFrame(
            self,
            fg_color=color("bg_secondary"),
            corner_radius=layout("radius", 10),
        )
        frame.grid(row=5, column=0, sticky="ew", padx=16, pady=(0, 6))
        frame.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            frame,
            text="Preset Management",
            font=font("size_small", weight="bold"),
            text_color=color("text_secondary"),
        ).grid(row=0, column=0, columnspan=4, sticky="w", padx=12, pady=(8, 4))

        self._preset_name_entry = ctk.CTkEntry(
            frame,
            placeholder_text="Preset name...",
            font=font("size_body"),
            fg_color=color("bg_primary"),
            text_color=color("text_primary"),
            border_color=color("border"),
            border_width=1,
            corner_radius=layout("radius", 10),
            height=32,
            width=180,
        )
        self._preset_name_entry.grid(row=1, column=0, sticky="w", padx=(12, 4), pady=4)

        save_btn = ctk.CTkButton(
            frame,
            text="💾 Save Preset",
            font=font("size_body"),
            fg_color=color("accent"),
            hover_color=color("accent_hover"),
            text_color=color("text_primary"),
            corner_radius=layout("radius", 10),
            height=32,
            command=self._save_custom_preset,
        )
        save_btn.grid(row=1, column=1, sticky="w", padx=(0, 8), pady=4)

        load_btn = ctk.CTkButton(
            frame,
            text="📁 Load Preset",
            font=font("size_body"),
            fg_color=color("button_bg"),
            hover_color=color("button_hover"),
            text_color=color("button_text"),
            corner_radius=layout("radius", 10),
            height=32,
            command=self._load_custom_preset,
        )
        load_btn.grid(row=1, column=2, sticky="w", padx=(0, 8), pady=4)

        delete_btn = ctk.CTkButton(
            frame,
            text="🗑 Delete Preset",
            font=font("size_body"),
            fg_color="#EF4444",
            hover_color="#DC2626",
            text_color=color("text_primary"),
            corner_radius=layout("radius", 10),
            height=32,
            command=self._delete_custom_preset,
        )
        delete_btn.grid(row=1, column=3, sticky="w", padx=(0, 12), pady=4)

    def _build_command_preview(self):
        """Build Nmap command preview."""
        frame = ctk.CTkFrame(
            self,
            fg_color=color("bg_secondary"),
            corner_radius=layout("radius", 10),
        )
        frame.grid(row=6, column=0, sticky="ew", padx=16, pady=(0, 6))
        frame.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            frame,
            text="Nmap Command",
            font=font("size_small", weight="bold"),
            text_color=color("text_secondary"),
        ).grid(row=0, column=0, sticky="w", padx=12, pady=(8, 4))

        self._command_preview = ctk.CTkTextbox(
            frame,
            height=40,
            font=font("size_body", mono=True),
            fg_color=color("bg_primary"),
            text_color=color("text_primary"),
            border_color=color("border"),
            border_width=1,
            corner_radius=layout("radius", 10),
            wrap="none",
        )
        self._command_preview.grid(row=1, column=0, sticky="ew", padx=12, pady=(0, 10))
        self._command_preview.insert("1.0", "nmap <target>")
        self._command_preview.configure(state="disabled")

    def _build_scan_button(self):
        """Build Start Scan button."""
        self._scan_button = ctk.CTkButton(
            self,
            text="▶ Start Scan",
            font=font("size_body", weight="bold"),
            fg_color=color("accent"),
            hover_color=color("accent_hover"),
            text_color=color("text_primary"),
            corner_radius=layout("radius", 10),
            height=44,
            command=self._start_scan,
        )
        self._scan_button.grid(row=7, column=0, sticky="ew", padx=16, pady=(0, 6))

        self._status_label = ctk.CTkLabel(
            self,
            text="",
            font=font("size_small"),
            text_color=color("text_muted"),
        )
        self._status_label.grid(row=7, column=0, sticky="w", padx=16, pady=(0, 6))

    def _build_results_section(self):
        """Build results display area."""
        results_header = ctk.CTkFrame(self, fg_color="transparent")
        results_header.grid(row=8, column=0, sticky="ew", padx=16, pady=(0, 6))
        results_header.grid_columnconfigure(0, weight=1)

        self._results_label = ctk.CTkLabel(
            results_header,
            text="Results: 0 devices found",
            font=font("size_small"),
            text_color=color("text_secondary"),
        )
        self._results_label.grid(row=0, column=0, sticky="w")

        self._results_container = ctk.CTkScrollableFrame(
            self,
            fg_color=color("bg_secondary"),
            corner_radius=layout("radius", 10),
        )
        self._results_container.grid(row=9, column=0, sticky="nsew", padx=16, pady=(0, 14))
        self._results_container.grid_columnconfigure(0, weight=1)

    # ------------------------------------------------------------------
    # Logic
    # ------------------------------------------------------------------

    def _load_defaults(self):
        """Load default target from config."""
        try:
            config = load_config()
            self._target_entry.insert(0, config.get("subnet", "192.168.0.0/24"))
        except:
            pass

    def _on_preset_selected(self, preset_key: str):
        """Apply selected preset."""
        if preset_key == "Select a preset...":
            return

        presets = self._get_all_presets()
        preset = presets.get(preset_key)
        if not preset:
            return

        self._preset_description.configure(text=preset.get("description", ""))

        args = preset.get("arguments", "")
        self._clear_options()

        for flag in self._option_vars.keys():
            if flag in args:
                self._option_vars[flag].set("on")

        ports = preset.get("ports")
        if ports is None or ports == "":
            self._port_var.set("common")
        elif ports == "1-65535" or ports == "all":
            self._port_var.set("all")
        else:
            self._port_var.set("custom")
            self._custom_ports_entry.delete(0, "end")
            self._custom_ports_entry.insert(0, ports)

        timing_match = re.search(r'-T[0-5]', args)
        if timing_match:
            self._timing_var.set(timing_match.group(0))
        elif preset.get("timing"):
            self._timing_var.set(str(preset.get("timing")))

        timeout_match = re.search(r'--host-timeout\s+(\S+)', args)
        if timeout_match:
            self._host_timeout_var.set(timeout_match.group(1))
        else:
            self._host_timeout_var.set(str(preset.get("host_timeout") or ""))

        hostgroup_match = re.search(r'--(?:min|max)-hostgroup\s+(\d+)', args)
        if hostgroup_match:
            self._parallelism_var.set(hostgroup_match.group(1))
        else:
            parallelism = preset.get("parallelism")
            self._parallelism_var.set(str(parallelism) if parallelism is not None else "")

        self._update_command_preview()

    def _clear_options(self):
        """Clear all option checkboxes."""
        for var in self._option_vars.values():
            var.set("off")

    def _get_selected_options(self) -> str:
        """Get selected scan options as Nmap arguments."""
        args = []
        for flag, var in self._option_vars.items():
            if var.get() == "on":
                args.append(flag)
        return " ".join(args)

    def _get_host_timeout(self) -> str | None:
        """Get the host timeout string for Nmap."""
        timeout = self._host_timeout_var.get().strip()
        return timeout if timeout else None

    def _get_parallelism(self) -> int | None:
        """Get the configured parallelism value."""
        value = self._parallelism_var.get().strip()
        if not value:
            return None
        try:
            return max(1, int(value))
        except ValueError:
            return None

    def _get_ports(self) -> str | None:
        """Get port specification."""
        port_type = self._port_var.get()
        if port_type == "common":
            return "1-1024"
        elif port_type == "all":
            return "1-65535"
        else:
            ports = self._custom_ports_entry.get().strip()
            return ports if ports else None

    def _build_nmap_command(self) -> str:
        """Build full Nmap command from UI selections."""
        target = self._target_entry.get().strip() or "<target>"
        options = self._get_selected_options()
        ports = self._get_ports()
        host_timeout = self._get_host_timeout()
        parallelism = self._get_parallelism()

        cmd = ["nmap", target]
        if options:
            cmd.extend(options.split())
        timing = self._timing_var.get()
        if timing:
            cmd.append(timing)
        if host_timeout:
            cmd.extend(["--host-timeout", host_timeout])
        if parallelism is not None:
            cmd.extend(["--min-hostgroup", str(parallelism), "--max-hostgroup", str(parallelism)])
        if ports:
            cmd.extend(["-p", ports])
        return " ".join(cmd)

    def _update_command_preview(self, _value: str | None = None):
        """Update the command preview text box."""
        cmd = self._build_nmap_command()
        self._command_preview.configure(state="normal")
        self._command_preview.delete("1.0", "end")
        self._command_preview.insert("1.0", cmd)
        self._command_preview.configure(state="disabled")

    def _save_custom_preset(self):
        """Save current settings as a custom preset."""
        name = self._preset_name_entry.get().strip()
        if not name:
            self._show_status("Enter a preset name", "error")
            return

        from presets import _load_json, DEFAULT_PATH, save_preset
        defaults = _load_json(DEFAULT_PATH)
        if name in defaults:
            self._show_status(f"'{name}' is a default preset. Choose another name.", "error")
            return

        save_preset(
            name=name,
            args=self._get_selected_options(),
            ports=self._get_ports() or "",
            description=f"Custom: {name}"
        )

        self._refresh_presets_dropdown()
        self._show_status(f"Preset '{name}' saved!", "success")

    def _load_custom_preset(self):
        """Load a custom preset."""
        name = self._preset_name_entry.get().strip()
        if not name or name not in self._get_all_presets():
            self._show_status("Enter a valid preset name", "error")
            return

        self._on_preset_selected(name)
        self._show_status(f"Preset '{name}' loaded", "success")

    def _delete_custom_preset(self):
        """Delete a custom preset."""
        name = self._preset_name_entry.get().strip()
        from presets import delete_preset
        if not name or not delete_preset(name):
            self._show_status("Enter a valid custom preset name", "error")
            return

        self._refresh_presets_dropdown()
        self._show_status(f"Preset '{name}' deleted", "success")

    def _refresh_presets_dropdown(self):
        """Refresh the presets dropdown."""
        keys = ["Select a preset..."] + list(self._get_all_presets().keys())
        self._preset_dropdown.configure(values=keys)
        if hasattr(self._preset_dropdown, "set"):
            self._preset_dropdown.set("Select a preset...")

    def _start_scan(self):
        """Execute the scan with selected options."""
        target = self._target_entry.get().strip()
        if not target:
            self._show_status("Please enter a target", "error")
            return

        options = self._get_selected_options()
        ports = self._get_ports()
        timing = self._timing_var.get()
        host_timeout = self._get_host_timeout()
        parallelism = self._get_parallelism()

        self._scan_button.configure(state="disabled", text="⏳ Scanning...")
        self._show_status(f"Scanning {target}...", "info")

        import threading
        def _scan_thread():
            try:
                results, duration = self._scanner.custom_scan(
                    target=target,
                    ports=ports,
                    arguments=options,
                    timing=timing,
                    host_timeout=host_timeout,
                    min_hostgroup=parallelism,
                    max_hostgroup=parallelism,
                )
                self.after(0, self._on_scan_complete, results, duration)
            except Exception as e:
                self.after(0, self._on_scan_error, str(e))
                
        threading.Thread(target=_scan_thread, daemon=True).start()

    def _on_scan_error(self, err_msg: str):
        """Handle scan error on main thread."""
        self._show_status(f"Error: {err_msg}", "error")
        log_event(f"Custom scan failed: {err_msg}", "error")
        self._scan_button.configure(state="normal", text="▶ Start Scan")

    def _on_scan_complete(self, results, duration):
        """Handle scan completion on main thread."""
        try:
            self._scan_results = results
            self._display_results(results, duration)

            try:
                analysis = analyzer.analyze_scan(results)
                scan_command = getattr(self._scanner, "last_command", "")
                database.add_scan(
                    {
                        "scan_date": __import__("datetime").datetime.utcnow(),
                        "duration": duration,
                        "total_devices": len(results),
                        "new_devices": len(analysis.get("new", [])),
                        "disconnected_devices": len(analysis.get("disconnected", [])),
                        "scan_command": scan_command,
                    }
                )
            except Exception as save_exc:
                log_event(f"Failed to save manual scan to database: {save_exc}", "error")

            self._show_status(f"Completed in {duration}s - {len(results)} devices found", "success")

        except Exception as e:
            self._show_status(f"Error: {str(e)}", "error")
            log_event(f"Custom scan UI update failed: {e}", "error")

        finally:
            self._scan_button.configure(state="normal", text="▶ Start Scan")

    def _display_results(self, results: list, duration: float):
        """Display scan results as device cards."""
        for widget in self._result_widgets:
            widget.destroy()
        self._result_widgets = []

        self._results_label.configure(
            text=f"Results: {len(results)} devices found in {duration:.2f}s"
        )

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

        cols = 2
        for idx, device_data in enumerate(results):
            row = idx // cols
            col = idx % cols

            card = self._create_result_card(device_data)
            card.grid(row=row, column=col, sticky="nsew", padx=6, pady=6)
            self._result_widgets.append(card)

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
        ports = device_data.get("ports", {})

        existing = get_device_by_ip(ip)
        status = getattr(existing, "status", "online") if existing else "new"

        pad = layout("card_padding", 12)

        ip_frame = ctk.CTkFrame(card, fg_color="transparent")
        ip_frame.pack(fill="x", padx=pad, pady=(pad, 0))

        ctk.CTkLabel(
            ip_frame,
            text=ip,
            font=font("size_heading", mono=True),
            text_color=color("text_primary"),
            anchor="w",
        ).pack(side="left")

        StatusBadge(ip_frame, status=status, text="", dot_size=8).pack(side="left", padx=(8, 0))

        if ports:
            PortBadge(ip_frame, port_count=len(ports), port_list=list(ports.keys())).pack(side="left", padx=(8, 0))

        if hostname:
            ctk.CTkLabel(
                card,
                text=f"🏷 {hostname}",
                font=font("size_body"),
                text_color=color("text_secondary"),
                anchor="w",
            ).pack(fill="x", padx=pad, pady=(2, 0))

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

        if ports:
            port_str = ", ".join(list(ports.keys())[:5])
            if len(ports) > 5:
                port_str += f" +{len(ports) - 5} more"

            ctk.CTkLabel(
                card,
                text=f"🖧 {port_str}",
                font=font("size_small", mono=True),
                text_color=color("accent"),
                anchor="w",
            ).pack(fill="x", padx=pad, pady=(0, pad))

        return card

    def _show_status(self, message: str, level: str = "info"):
        """Update status label with color."""
        colors = {
            "info": color("text_muted"),
            "success": status_color("online"),
            "error": status_color("offline"),
        }
        self._status_label.configure(text=message, text_color=colors.get(level, color("text_muted")))

    def refresh(self):
        """Refresh results (re-fetch device status from DB)."""
        if self._scan_results:
            self._display_results(self._scan_results, 0)