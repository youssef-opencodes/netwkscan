"""Custom scan page - Full Nmap GUI with presets, options, live preview, and results.

Features:
- Target input with CIDR validation
- Presets dropdown (default + custom)
- Dynamic scan options (-sV, -O, -A, -sC, -v, --traceroute, -sU, -sS)
- Port specification (Common 1-1024, All 1-65535, Custom)
- Performance settings (Timing T0-T5, Parallelism, Host Timeout)
- Live Nmap command preview built central via Scanner.build_nmap_command
- Real-time status indication: Preparing, Scanning, Parsing, Completed, Failed
- Cancel Scan button for terminating background processes
- Detailed error messages on Nmap missing, permission denied, invalid target, or execution errors
"""
from __future__ import annotations

import json
import re
import threading
from pathlib import Path
from typing import Any

import customtkinter as ctk

from core import analyzer, database
from core.database import get_device_by_ip
from core.scanner import Scanner, ScanResult, validate_target
from gui.resources import color, font, layout, status_color
from gui.widgets.port_badge import PortBadge
from gui.widgets.status_badge import StatusBadge
from utils.config import load_config, update_config
from utils.logger import log_event


class CustomScanPage(ctk.CTkFrame):
    """Full Nmap GUI with presets, options, performance, live command preview, and results."""

    def __init__(self, master: Any, **kwargs: Any) -> None:
        super().__init__(master, fg_color=color("bg_primary"), **kwargs)

        self._scanner = Scanner()
        self._scan_results: list[dict[str, Any]] = []
        self._result_widgets: list[ctk.CTkBaseClass] = []
        self._custom_presets: dict[str, Any] = {}
        self._is_scanning: bool = False

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(9, weight=1)

        # Build UI sections
        self._build_target_section()
        self._build_preset_section()
        self._build_options_section()
        self._build_port_section()
        self._build_performance_section()
        self._build_preset_management()
        self._build_command_preview()
        self._build_scan_controls()
        self._build_results_section()

        # Load defaults from config
        self._load_defaults()

    # ------------------------------------------------------------------
    # Preset Management
    # ------------------------------------------------------------------

    def _get_all_presets(self) -> dict[str, Any]:
        """Return combined default + custom presets."""
        try:
            from presets import load_presets
            all_presets = load_presets()
            for name, p in all_presets.items():
                if "name" not in p:
                    p["name"] = name
                if "args" in p:
                    p["arguments"] = p["args"]
            return all_presets
        except Exception:
            return {}

    # ------------------------------------------------------------------
    # UI Construction
    # ------------------------------------------------------------------

    def _build_target_section(self) -> None:
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
            placeholder_text="e.g. 10.222.83.0/24 or 192.168.1.1",
            font=font("size_body"),
            fg_color=color("bg_secondary"),
            text_color=color("text_primary"),
            border_color=color("border"),
            border_width=1,
            corner_radius=layout("radius", 10),
            height=38,
        )
        self._target_entry.grid(row=0, column=1, sticky="ew")
        self._target_entry.bind("<KeyRelease>", lambda e: self._update_command_preview())

    def _build_preset_section(self) -> None:
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

    def _build_options_section(self) -> None:
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

        self._option_vars: dict[str, ctk.StringVar] = {}
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

    def _build_port_section(self) -> None:
        """Build port specification options."""
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

    def _build_performance_section(self) -> None:
        """Build timing and performance controls."""
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

    def _build_preset_management(self) -> None:
        """Build Save/Load/Delete preset controls."""
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

    def _build_command_preview(self) -> None:
        """Build live Nmap command preview box."""
        frame = ctk.CTkFrame(
            self,
            fg_color=color("bg_secondary"),
            corner_radius=layout("radius", 10),
        )
        frame.grid(row=6, column=0, sticky="ew", padx=16, pady=(0, 6))
        frame.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            frame,
            text="Generated Nmap Command",
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
        self._command_preview.insert("1.0", "nmap 10.222.83.0/24")
        self._command_preview.configure(state="disabled")

    def _build_scan_controls(self) -> None:
        """Build Start Scan, Cancel Scan, and status indicator controls."""
        btn_frame = ctk.CTkFrame(self, fg_color="transparent")
        btn_frame.grid(row=7, column=0, sticky="ew", padx=16, pady=(0, 6))
        btn_frame.grid_columnconfigure(0, weight=3)
        btn_frame.grid_columnconfigure(1, weight=1)

        self._scan_button = ctk.CTkButton(
            btn_frame,
            text="▶ Start Scan",
            font=font("size_body", weight="bold"),
            fg_color=color("accent"),
            hover_color=color("accent_hover"),
            text_color=color("text_primary"),
            corner_radius=layout("radius", 10),
            height=44,
            command=self._start_scan,
        )
        self._scan_button.grid(row=0, column=0, sticky="ew", padx=(0, 8))

        self._cancel_button = ctk.CTkButton(
            btn_frame,
            text="⏹ Cancel Scan",
            font=font("size_body", weight="bold"),
            fg_color="#DC2626",
            hover_color="#B91C1C",
            text_color="#FFFFFF",
            corner_radius=layout("radius", 10),
            height=44,
            state="disabled",
            command=self._cancel_scan,
        )
        self._cancel_button.grid(row=0, column=1, sticky="ew")

        # Status text & badge
        status_box = ctk.CTkFrame(self, fg_color="transparent")
        status_box.grid(row=8, column=0, sticky="ew", padx=16, pady=(0, 4))
        status_box.grid_columnconfigure(1, weight=1)

        self._state_badge = ctk.CTkLabel(
            status_box,
            text="READY",
            font=font("size_small", weight="bold"),
            fg_color=color("bg_tertiary"),
            text_color=color("text_primary"),
            corner_radius=6,
            padx=10,
            pady=4,
        )
        self._state_badge.grid(row=0, column=0, sticky="w", padx=(0, 8))

        self._status_label = ctk.CTkLabel(
            status_box,
            text="Ready to scan.",
            font=font("size_small"),
            text_color=color("text_muted"),
            anchor="w",
        )
        self._status_label.grid(row=0, column=1, sticky="w")

    def _build_results_section(self) -> None:
        """Build results scrollable container."""
        results_header = ctk.CTkFrame(self, fg_color="transparent")
        results_header.grid(row=9, column=0, sticky="ew", padx=16, pady=(0, 6))
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
        self._results_container.grid(row=10, column=0, sticky="nsew", padx=16, pady=(0, 14))
        self._results_container.grid_columnconfigure(0, weight=1)

    # ------------------------------------------------------------------
    # Logic & State Updates
    # ------------------------------------------------------------------

    def _load_defaults(self) -> None:
        """Load default target from configuration."""
        try:
            config = load_config()
            target_val = config.get("subnet", "10.222.83.0/24")
            self._target_entry.delete(0, "end")
            self._target_entry.insert(0, target_val)
        except Exception:
            pass
        self._update_command_preview()

    def _update_state(self, state_name: str, message: str, is_error: bool = False) -> None:
        """Update UI scan lifecycle state badge and status label."""
        badge_colors = {
            "READY": (color("bg_tertiary"), color("text_primary")),
            "PREPARING": ("#3B82F6", "#FFFFFF"),
            "SCANNING": ("#F59E0B", "#FFFFFF"),
            "PARSING": ("#8B5CF6", "#FFFFFF"),
            "COMPLETED": ("#10B981", "#FFFFFF"),
            "FAILED": ("#EF4444", "#FFFFFF"),
        }
        bg, fg = badge_colors.get(state_name, (color("bg_tertiary"), color("text_primary")))
        self._state_badge.configure(text=state_name, fg_color=bg, text_color=fg)
        self._status_label.configure(
            text=message,
            text_color="#EF4444" if is_error else color("text_primary"),
        )

    def _on_preset_selected(self, preset_key: str) -> None:
        """Apply selected preset options to UI widgets."""
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

        self._update_command_preview()

    def _clear_options(self) -> None:
        """Clear all option checkboxes."""
        for var in self._option_vars.values():
            var.set("off")

    def _get_selected_options(self) -> str:
        """Combine selected scan option checkboxes into argument string."""
        args = []
        for flag, var in self._option_vars.items():
            if var.get() == "on":
                args.append(flag)
        return " ".join(args)

    def _get_host_timeout(self) -> str | None:
        timeout = self._host_timeout_var.get().strip()
        return timeout if timeout else None

    def _get_parallelism(self) -> int | None:
        val = self._parallelism_var.get().strip()
        if not val:
            return None
        try:
            return max(1, int(val))
        except ValueError:
            return None

    def _get_ports(self) -> str | None:
        port_type = self._port_var.get()
        if port_type == "common":
            return "1-1024"
        elif port_type == "all":
            return "1-65535"
        else:
            ports = self._custom_ports_entry.get().strip()
            return ports if ports else None

    def _update_command_preview(self, _value: str | None = None) -> None:
        """Update live command preview text using central build_nmap_command."""
        target = self._target_entry.get().strip() or "10.222.83.0/24"
        options = self._get_selected_options()
        ports = self._get_ports()
        timing = self._timing_var.get()
        host_timeout = self._get_host_timeout()
        parallelism = self._get_parallelism()

        cmd = self._scanner.build_nmap_command(
            target=target,
            ports=ports,
            arguments=options,
            timing=timing,
            host_timeout=host_timeout,
            min_hostgroup=parallelism,
            max_hostgroup=parallelism,
        )

        self._command_preview.configure(state="normal")
        self._command_preview.delete("1.0", "end")
        self._command_preview.insert("1.0", cmd)
        self._command_preview.configure(state="disabled")

    def _save_custom_preset(self) -> None:
        """Save current selections to custom presets."""
        name = self._preset_name_entry.get().strip()
        if not name:
            self._update_state("FAILED", "Please enter a preset name", is_error=True)
            return

        try:
            from presets import save_preset
            save_preset(
                name=name,
                args=self._get_selected_options(),
                ports=self._get_ports() or "",
                description=f"Custom: {name}"
            )
            self._refresh_presets_dropdown()
            self._update_state("READY", f"Preset '{name}' saved successfully!")
        except Exception as err:
            self._update_state("FAILED", f"Failed to save preset: {err}", is_error=True)

    def _load_custom_preset(self) -> None:
        name = self._preset_name_entry.get().strip()
        if not name or name not in self._get_all_presets():
            self._update_state("FAILED", "Enter a valid preset name", is_error=True)
            return
        self._on_preset_selected(name)
        self._update_state("READY", f"Preset '{name}' loaded")

    def _delete_custom_preset(self) -> None:
        name = self._preset_name_entry.get().strip()
        try:
            from presets import delete_preset
            if not name or not delete_preset(name):
                self._update_state("FAILED", "Enter a valid custom preset name", is_error=True)
                return
            self._refresh_presets_dropdown()
            self._update_state("READY", f"Preset '{name}' deleted")
        except Exception as err:
            self._update_state("FAILED", f"Failed to delete preset: {err}", is_error=True)

    def _refresh_presets_dropdown(self) -> None:
        keys = ["Select a preset..."] + list(self._get_all_presets().keys())
        self._preset_dropdown.configure(values=keys)
        self._preset_dropdown.set("Select a preset...")

    def _cancel_scan(self) -> None:
        """Cancel active scan subprocess."""
        if self._is_scanning:
            self._scanner.cancel_scan()
            self._update_state("FAILED", "Scan cancelled by user.", is_error=True)
            self._scan_button.configure(state="normal", text="▶ Start Scan")
            self._cancel_button.configure(state="disabled")
            self._is_scanning = False

    def _start_scan(self) -> None:
        """Execute scan workflow in background thread."""
        target = self._target_entry.get().strip()

        # 1. Target Validation
        is_valid_tgt, tgt_err = validate_target(target)
        if not is_valid_tgt:
            self._update_state("FAILED", tgt_err, is_error=True)
            return

        # 2. Binary Check
        if not self._scanner.is_nmap_available():
            self._update_state("FAILED", "Nmap is not installed or not found in system PATH.", is_error=True)
            return

        options = self._get_selected_options()
        ports = self._get_ports()
        timing = self._timing_var.get()
        host_timeout = self._get_host_timeout()
        parallelism = self._get_parallelism()

        self._is_scanning = True
        self._scan_button.configure(state="disabled", text="⏳ Scanning...")
        self._cancel_button.configure(state="normal")
        self._update_state("SCANNING", f"Executing Nmap scan on {target}...")

        def _worker() -> None:
            self.after(0, lambda: self._update_state("SCANNING", f"Running Nmap subprocess on {target}..."))
            scan_res: ScanResult = self._scanner.execute_scan(
                target=target,
                ports=ports,
                arguments=options,
                timing=timing,
                host_timeout=host_timeout,
                min_hostgroup=parallelism,
                max_hostgroup=parallelism,
            )
            self.after(0, lambda: self._update_state("PARSING", "Parsing Nmap XML output..."))
            self.after(0, self._on_scan_finished, scan_res)

        threading.Thread(target=_worker, daemon=True).start()

    def _on_scan_finished(self, scan_res: ScanResult) -> None:
        """Process scan completion or failure on Tk main thread."""
        self._is_scanning = False
        self._scan_button.configure(state="normal", text="▶ Start Scan")
        self._cancel_button.configure(state="disabled")

        if not scan_res.success:
            err_msg = scan_res.error_message or "Nmap scan failed."
            self._update_state("FAILED", f"Error: {err_msg}", is_error=True)
            log_event(f"Custom scan execution failed: {err_msg}", "error")
            self._display_results([], scan_res.duration, error_message=err_msg)
            return

        # Success path
        self._scan_results = scan_res.devices
        self._display_results(scan_res.devices, scan_res.duration)

        try:
            analysis = analyzer.analyze_scan(scan_res.devices, scan_failed=False)
            database.add_scan(
                {
                    "scan_date": __import__("datetime").datetime.utcnow(),
                    "duration": scan_res.duration,
                    "total_devices": len(scan_res.devices),
                    "new_devices": len(analysis.get("new", [])),
                    "disconnected_devices": len(analysis.get("disconnected", [])),
                    "scan_command": scan_res.command,
                }
            )
        except Exception as save_exc:
            log_event(f"Failed to record scan in database: {save_exc}", "error")

        msg = f"Completed in {scan_res.duration}s — {len(scan_res.devices)} hosts found."
        self._update_state("COMPLETED", msg)

    def _display_results(self, results: list[dict[str, Any]], duration: float, error_message: str = "") -> None:
        """Display scan result cards or clear error banner."""
        for widget in self._result_widgets:
            widget.destroy()
        self._result_widgets = []

        if error_message:
            self._results_label.configure(
                text=f"Scan Failed ({error_message})",
                text_color="#EF4444",
            )
            empty = ctk.CTkFrame(self._results_container, fg_color="transparent")
            empty.grid(row=0, column=0, sticky="nsew", pady=32)

            ctk.CTkLabel(
                empty,
                text="⚠️ Scan Execution Error",
                font=font("size_heading"),
                text_color="#EF4444",
            ).pack()

            ctk.CTkLabel(
                empty,
                text=error_message,
                font=font("size_body"),
                text_color=color("text_primary"),
                wraplength=600,
            ).pack(pady=(6, 0))

            self._result_widgets.append(empty)
            return

        self._results_label.configure(
            text=f"Results: {len(results)} devices found in {duration:.2f}s",
            text_color=color("text_secondary"),
        )

        if not results:
            empty = ctk.CTkFrame(self._results_container, fg_color="transparent")
            empty.grid(row=0, column=0, sticky="nsew", pady=48)

            ctk.CTkLabel(
                empty,
                text="No active hosts found",
                font=font("size_heading"),
                text_color=color("text_primary"),
            ).pack()

            ctk.CTkLabel(
                empty,
                text="No responding devices were detected on this target.",
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

    def _create_result_card(self, device: dict[str, Any]) -> ctk.CTkFrame:
        """Create structured result card for host."""
        card = ctk.CTkFrame(
            self._results_container,
            fg_color=color("card_bg"),
            border_color=color("card_border"),
            border_width=1,
            corner_radius=layout("radius", 10),
        )
        card.grid_columnconfigure(1, weight=1)

        # Header: IP & Device Type
        ip = device.get("ip", "Unknown")
        dev_type = device.get("device_type", "Unknown")
        hostname = device.get("hostname", "")

        ctk.CTkLabel(
            card,
            text=ip,
            font=font("size_body", weight="bold"),
            text_color=color("accent"),
        ).grid(row=0, column=0, sticky="w", padx=12, pady=(10, 2))

        ctk.CTkLabel(
            card,
            text=dev_type,
            font=font("size_small", weight="bold"),
            fg_color=color("bg_tertiary"),
            text_color=color("text_primary"),
            corner_radius=4,
            padx=6,
            pady=2,
        ).grid(row=0, column=1, sticky="e", padx=12, pady=(10, 2))

        if hostname:
            ctk.CTkLabel(
                card,
                text=f"Host: {hostname}",
                font=font("size_small"),
                text_color=color("text_secondary"),
            ).grid(row=1, column=0, columnspan=2, sticky="w", padx=12, pady=(0, 4))

        # MAC & Vendor
        mac = device.get("mac", "")
        vendor = device.get("vendor", "")
        if mac:
            mac_str = f"MAC: {mac}" + (f" ({vendor})" if vendor else "")
            ctk.CTkLabel(
                card,
                text=mac_str,
                font=font("size_small", mono=True),
                text_color=color("text_muted"),
            ).grid(row=2, column=0, columnspan=2, sticky="w", padx=12, pady=(0, 4))

        # Open Ports
        ports = device.get("ports", {})
        if ports:
            ports_str = ", ".join([f"{p}/{svc}" for p, svc in list(ports.items())[:6]])
            if len(ports) > 6:
                ports_str += f" (+{len(ports)-6} more)"
            ctk.CTkLabel(
                card,
                text=f"Ports: {ports_str}",
                font=font("size_small"),
                text_color=color("text_primary"),
            ).grid(row=3, column=0, columnspan=2, sticky="w", padx=12, pady=(0, 10))
        else:
            ctk.CTkLabel(
                card,
                text="Host active (no open ports detected)",
                font=font("size_small"),
                text_color=color("text_muted"),
            ).grid(row=3, column=0, columnspan=2, sticky="w", padx=12, pady=(0, 10))

        return card