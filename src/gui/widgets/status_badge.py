"""Status badge widget - LED indicator for device status (Developer 4, task 5).

Provides a visual LED indicator with label for device status.
Supports online, offline, and new statuses with appropriate colors.
"""

import customtkinter as ctk

from gui.resources import color, font, layout, status_color


class StatusBadge(ctk.CTkFrame):
    """LED indicator with label showing device status."""

    def __init__(
        self,
        master,
        status: str = "unknown",
        text: str = "",
        show_label: bool = True,
        dot_size: int = 10,
        **kwargs,
    ) -> None:
        """
        Args:
            master: Parent widget
            status: Device status (online, offline, new, unknown)
            text: Optional custom text (defaults to status if empty)
            show_label: Show text label next to dot
            dot_size: Size of LED dot in pixels
        """
        super().__init__(master, fg_color="transparent", **kwargs)

        self._status = status.lower()
        self._text = text if text else self._status.capitalize()
        self._dot_size = dot_size

        # Configure grid
        self.grid_columnconfigure(1, weight=1)

        # LED dot
        self._dot = ctk.CTkFrame(
            self,
            width=dot_size,
            height=dot_size,
            corner_radius=dot_size // 2,
            fg_color=status_color(self._status),
        )
        self._dot.grid(row=0, column=0, sticky="w", padx=(0, 6))
        self._dot.grid_propagate(False)

        # Label
        if show_label:
            self._label = ctk.CTkLabel(
                self,
                text=self._text,
                font=font("size_body"),
                text_color=status_color(self._status),
                anchor="w",
            )
            self._label.grid(row=0, column=1, sticky="w")

    def set_status(self, status: str) -> None:
        """Update the status and refresh colors."""
        self._status = status.lower()
        color_hex = status_color(self._status)
        self._dot.configure(fg_color=color_hex)
        if hasattr(self, "_label"):
            self._label.configure(text_color=color_hex)

    def set_text(self, text: str) -> None:
        """Update the label text."""
        self._text = text
        if hasattr(self, "_label"):
            self._label.configure(text=text)

    def get_status(self) -> str:
        """Return current status."""
        return self._status

    def get_text(self) -> str:
        """Return current label text."""
        return self._text

    def toggle_pulse(self, enabled: bool = True) -> None:
        """Enable/disable pulsing animation for attention."""
        if enabled:
            self._dot.configure(
                fg_color=status_color(self._status),
                border_color=status_color(self._status),
                border_width=2,
            )
        else:
            self._dot.configure(border_width=0)