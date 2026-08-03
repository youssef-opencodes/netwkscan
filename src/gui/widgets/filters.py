"""Filter buttons widget - All, Online, Offline, Unknown (Developer 4, task 4).

Provides filter buttons for device status filtering with visual feedback
for the active filter.
"""

import customtkinter as ctk

from gui.resources import color, font, layout, status_color


class FilterButtons(ctk.CTkFrame):
    """Filter buttons: All, Online, Offline, New."""

    FILTERS = [
        {"key": "all", "label": "All", "color": "text_secondary"},
        {"key": "online", "label": "Online", "color": "online"},
        {"key": "offline", "label": "Offline", "color": "offline"},
        {"key": "new", "label": "New", "color": "new"},
    ]

    def __init__(
        self,
        master,
        on_filter_change=None,
        initial_filter: str = "all",
        **kwargs,
    ) -> None:
        """
        Args:
            master: Parent widget
            on_filter_change: Callback when filter changes, receives (filter_key)
            initial_filter: Initial active filter
        """
        super().__init__(master, fg_color="transparent", **kwargs)

        self._on_filter_change = on_filter_change
        self._active_filter = initial_filter.lower()
        self._buttons = {}

        # Build filter buttons
        for index, filter_info in enumerate(self.FILTERS):
            key = filter_info["key"]
            label = filter_info["label"]
            color_key = filter_info["color"]

            btn = ctk.CTkButton(
                self,
                text=label,
                font=font("size_body"),
                height=32,
                width=70,
                fg_color=color("bg_secondary"),
                hover_color=color("bg_tertiary"),
                text_color=color("text_secondary"),
                corner_radius=layout("radius", 10),
                command=lambda k=key: self.set_active_filter(k),
            )
            btn.grid(row=0, column=index, padx=(0 if index == 0 else 6, 6))
            self._buttons[key] = {"button": btn, "color_key": color_key}

        # Set initial active state
        self.set_active_filter(initial_filter)

    def set_active_filter(self, filter_key: str) -> None:
        """Set the active filter and update button styles."""
        filter_key = filter_key.lower()

        # Validate filter exists
        if filter_key not in self._buttons:
            return

        # Reset all buttons
        for key, data in self._buttons.items():
            btn = data["button"]
            if key == filter_key:
                # Active state
                color_key = data["color_key"]
                if color_key == "text_secondary":
                    # All button uses accent color
                    btn.configure(
                        fg_color=color("accent"),
                        text_color=color("text_primary"),
                        hover_color=color("accent_hover"),
                    )
                else:
                    # Status buttons use status color
                    status_hex = status_color(color_key)
                    btn.configure(
                        fg_color=status_hex,
                        text_color=color("text_primary"),
                        hover_color=status_hex,
                    )
            else:
                # Inactive state
                btn.configure(
                    fg_color=color("bg_secondary"),
                    text_color=color("text_secondary"),
                    hover_color=color("bg_tertiary"),
                )

        self._active_filter = filter_key

        # Trigger callback
        if callable(self._on_filter_change):
            self._on_filter_change(filter_key)

    def get_active_filter(self) -> str:
        """Return the currently active filter key."""
        return self._active_filter

    def filter_devices(self, devices: list) -> list:
        """Filter a list of devices by the active filter."""
        if self._active_filter == "all":
            return devices

        filtered = []
        for device in devices:
            # Handle both ORM object and dict
            if isinstance(device, dict):
                status = device.get("status", "unknown")
            else:
                status = getattr(device, "status", "unknown")

            if status.lower() == self._active_filter:
                filtered.append(device)

        return filtered

    def reset(self) -> None:
        """Reset to 'All' filter."""
        self.set_active_filter("all")