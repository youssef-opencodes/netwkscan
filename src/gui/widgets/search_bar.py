"""Search bar widget - Search devices by IP, Hostname, or MAC (Developer 4, task 3).

Provides a search input field with clear button that emits search events.
"""

import customtkinter as ctk

from core.database import get_all_devices
from gui.resources import color, font, layout


class SearchBar(ctk.CTkFrame):
    """Search input with real-time filtering and clear button."""

    def __init__(self, master, on_search=None, placeholder: str = "Search by IP, Hostname, or MAC...", **kwargs):
        """
        Args:
            master: Parent widget
            on_search: Callback function when search changes, receives (query, filtered_devices)
            placeholder: Placeholder text for input
        """
        super().__init__(master, fg_color="transparent", **kwargs)

        self._on_search = on_search
        self._all_devices = []
        self._query = ""

        # Configure grid
        self.grid_columnconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=0)

        # Search input
        self._entry = ctk.CTkEntry(
            self,
            placeholder_text=placeholder,
            font=font("size_body"),
            fg_color=color("bg_secondary"),
            text_color=color("text_primary"),
            border_color=color("border"),
            border_width=1,
            corner_radius=layout("radius", 10),
            height=38,
        )
        self._entry.grid(row=0, column=0, sticky="ew")
        self._entry.bind("<KeyRelease>", self._on_entry_change)
        self._entry.bind("<Return>", self._on_entry_change)

        # Clear button
        self._clear_btn = ctk.CTkButton(
            self,
            text="✕",
            width=30,
            height=30,
            font=font("size_small"),
            fg_color="transparent",
            hover_color=color("bg_tertiary"),
            text_color=color("text_muted"),
            corner_radius=layout("radius", 10),
            command=self.clear,
        )
        self._clear_btn.grid(row=0, column=1, padx=(6, 0))
        self._clear_btn.grid_remove()  # Hidden initially

        # Load initial data
        self._load_devices()

    def _load_devices(self) -> None:
        """Load all devices from database."""
        try:
            self._all_devices = get_all_devices() or []
        except Exception:
            self._all_devices = []

    def _on_entry_change(self, event=None) -> None:
        """Handle input change, filter devices, and trigger callback."""
        self._query = self._entry.get().strip()

        # Show/hide clear button
        if self._query:
            self._clear_btn.grid()
        else:
            self._clear_btn.grid_remove()

        # Filter devices
        filtered = self._filter_devices(self._query)

        # Trigger callback
        if callable(self._on_search):
            self._on_search(self._query, filtered)

    def _filter_devices(self, query: str) -> list:
        """Filter devices by IP, Hostname, or MAC."""
        if not query:
            return self._all_devices

        query_lower = query.lower()
        filtered = []

        for device in self._all_devices:
            # Handle both ORM object and dict
            ip = self._get_field(device, "ip", "")
            hostname = self._get_field(device, "hostname", "")
            mac = self._get_field(device, "mac", "")

            # Check if query matches any field
            if (query_lower in str(ip).lower() or
                query_lower in str(hostname).lower() or
                query_lower in str(mac).lower()):
                filtered.append(device)

        return filtered

    def _get_field(self, device, field: str, default: str = ""):
        """Helper to get field from ORM object or dict."""
        if device is None:
            return default
        if isinstance(device, dict):
            return device.get(field, default)
        return getattr(device, field, default)

    def search(self, query: str) -> list:
        """Manually trigger search with given query."""
        self._entry.delete(0, "end")
        self._entry.insert(0, query)
        self._on_entry_change()
        return self._filter_devices(query)

    def clear(self) -> None:
        """Clear search input and reset."""
        self._entry.delete(0, "end")
        self._query = ""
        self._clear_btn.grid_remove()
        if callable(self._on_search):
            self._on_search("", self._all_devices)
        self._entry.focus()

    def get_query(self) -> str:
        """Return current search query."""
        return self._query

    def get_all_devices(self) -> list:
        """Return unfiltered device list."""
        return self._all_devices

    def refresh(self) -> None:
        """Reload devices from database and reapply filter."""
        self._load_devices()
        self._on_entry_change()

    def set_placeholder(self, text: str) -> None:
        """Update placeholder text."""
        self._entry.configure(placeholder_text=text)