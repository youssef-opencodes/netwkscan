"""Port badge widget - shows number of open ports with color coding."""

import customtkinter as ctk
from typing import Optional

from gui.resources import color, font, layout


class PortBadge(ctk.CTkFrame):
    """Small badge showing number of open ports with color coding."""

    def __init__(
        self,
        master,
        port_count: int = 0,
        port_list: Optional[list] = None,
        **kwargs
    ):
        super().__init__(
            master,
            fg_color="transparent",
            **kwargs
        )

        self.port_count = port_count
        self.port_list = port_list or []

        # Determine color based on port count
        if port_count == 0:
            badge_color = color("text_muted")
            text_color = color("text_muted")
        elif port_count <= 3:
            badge_color = "#22C55E"  # green
            text_color = "#22C55E"
        elif port_count <= 10:
            badge_color = "#F59E0B"  # yellow
            text_color = "#F59E0B"
        else:
            badge_color = "#EF4444"  # red
            text_color = "#EF4444"

        # Icon
        self.icon_label = ctk.CTkLabel(
            self,
            text="🖧",
            font=font("size_body"),
            text_color=badge_color,
        )
        self.icon_label.pack(side="left", padx=(0, 2))

        # Count label
        self.count_label = ctk.CTkLabel(
            self,
            text=str(port_count),
            font=font("size_body", weight="bold"),
            text_color=text_color,
        )
        self.count_label.pack(side="left")

        # Tooltip on hover (optional)
        if port_count > 0 and port_list:
            self.bind("<Enter>", self._show_tooltip)
            self.bind("<Leave>", self._hide_tooltip)

        self._tooltip = None

    def _show_tooltip(self, event):
        """Show tooltip with port list."""
        if self._tooltip:
            return

        port_str = ", ".join(str(p) for p in self.port_list[:10])
        if len(self.port_list) > 10:
            port_str += f" +{len(self.port_list) - 10} more"

        self._tooltip = ctk.CTkToplevel(self)
        self._tooltip.wm_overrideredirect(True)
        self._tooltip.wm_geometry(f"+{event.x_root + 10}+{event.y_root - 10}")
        self._tooltip.configure(fg_color=color("bg_tertiary"))

        label = ctk.CTkLabel(
            self._tooltip,
            text=f"Ports: {port_str}",
            font=font("size_small"),
            text_color=color("text_primary"),
            corner_radius=8,
        )
        label.pack(padx=10, pady=6)

    def _hide_tooltip(self, event):
        """Hide tooltip."""
        if self._tooltip:
            self._tooltip.destroy()
            self._tooltip = None

    def update_count(self, port_count: int, port_list: Optional[list] = None):
        """Update the badge with new port data."""
        self.port_count = port_count
        self.port_list = port_list or []
        self.count_label.configure(text=str(port_count))