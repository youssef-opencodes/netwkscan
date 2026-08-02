"""Main application window (Developer 3, task 1).

Owns the CustomTkinter root window, the sidebar navigation and the content
area. Pages are registered through ``register_page()`` so Developer 4 can plug
custom_scan.py and logs_page.py in without editing this file.
"""
import shutil
from typing import Any, Callable

import customtkinter as ctk

from core.scheduler import NetworkScheduler
from gui.pages.main_page import MainPage
from gui.resources import color, font, layout, load_theme
from utils.config import load_config
from utils.logger import log_event


class MainWindow(ctk.CTk):
    """NMD root window: sidebar navigation + swappable content pages."""

    def __init__(self) -> None:
        super().__init__(fg_color=color("bg_primary"))

        theme = load_theme()
        ctk.set_appearance_mode(theme.get("appearance_mode", "dark"))

        self.title("NMD — Network Monitoring Dashboard")
        self.geometry("1180x740")
        self.minsize(layout("window_min_width", 1000), layout("window_min_height", 640))

        self._config = load_config()
        self._nmap_available = shutil.which("nmap") is not None
        self._scheduler: NetworkScheduler | None = None

        self._pages: dict[str, dict[str, Any]] = {}
        self._nav_buttons: dict[str, ctk.CTkButton] = {}
        self._current_page: str | None = None

        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self._build_sidebar()
        self._build_content_area()

        self.register_page("dashboard", "Dashboard", self._create_main_page)
        self._register_developer4_pages()
        self.show_page("dashboard")

        if not self._nmap_available:
            log_event("Nmap binary not found: scanning controls are disabled.", "warning")

        self.protocol("WM_DELETE_WINDOW", self._on_close)

    # ------------------------------------------------------------------
    # Sidebar
    # ------------------------------------------------------------------
    def _build_sidebar(self) -> None:
        sidebar = ctk.CTkFrame(
            self,
            width=layout("sidebar_width", 190),
            fg_color=color("bg_secondary"),
            corner_radius=0,
        )
        sidebar.grid(row=0, column=0, sticky="nsw")
        sidebar.grid_propagate(False)
        sidebar.grid_rowconfigure(1, weight=1)

        ctk.CTkLabel(
            sidebar,
            text="NMD",
            font=font("size_title", weight="bold"),
            text_color=color("accent"),
        ).grid(row=0, column=0, sticky="w", padx=20, pady=(20, 16))

        self._nav_container = ctk.CTkFrame(sidebar, fg_color="transparent")
        self._nav_container.grid(row=1, column=0, sticky="new", padx=10)
        self._nav_container.grid_columnconfigure(0, weight=1)

        footer = ctk.CTkFrame(sidebar, fg_color="transparent")
        footer.grid(row=2, column=0, sticky="sew", padx=16, pady=14)

        self._scheduler_label = ctk.CTkLabel(
            footer,
            text="scheduler stopped",
            font=font("size_small"),
            text_color=color("text_muted"),
            anchor="w",
        )
        self._scheduler_label.pack(anchor="w", pady=(0, 6))

        self._scheduler_button = ctk.CTkButton(
            footer,
            text="Start scheduler",
            font=font("size_small"),
            height=30,
            fg_color=color("button_bg"),
            hover_color=color("button_hover"),
            text_color=color("button_text"),
            corner_radius=layout("radius", 10),
            state="normal" if self._nmap_available else "disabled",
            command=self.toggle_scheduler,
        )
        self._scheduler_button.pack(fill="x")

        details = (
            f"subnet  {self._config.get('subnet', '—')}\n"
            f"type    {self._config.get('scan_type', '—')} · {self._config.get('port_range', '—')}\n"
            f"every   {self._config.get('scan_interval', '—')} s"
        )
        if not self._nmap_available:
            details += "\nnmap    not found"

        ctk.CTkLabel(
            footer,
            text=details,
            font=font("size_small", mono=True),
            text_color=color("text_muted"),
            justify="left",
            anchor="w",
        ).pack(anchor="w", pady=(10, 0))

    def _build_content_area(self) -> None:
        self._content = ctk.CTkFrame(self, fg_color=color("bg_primary"), corner_radius=0)
        self._content.grid(row=0, column=1, sticky="nsew")
        self._content.grid_columnconfigure(0, weight=1)
        self._content.grid_rowconfigure(0, weight=1)

    # ------------------------------------------------------------------
    # Page registry — Developer 4 integration point
    # ------------------------------------------------------------------
    def register_page(
        self,
        key: str,
        label: str,
        factory: Callable[[Any], ctk.CTkFrame],
    ) -> None:
        """Register a navigable page.

        Args:
            key: unique identifier, e.g. "logs".
            label: sidebar text.
            factory: callable receiving the content frame and returning a frame.
                It is called lazily, the first time the page is shown.
        """
        if key in self._pages:
            log_event(f"Page '{key}' is already registered; ignoring duplicate.", "warning")
            return

        self._pages[key] = {"label": label, "factory": factory, "instance": None}

        button = ctk.CTkButton(
            self._nav_container,
            text=label,
            anchor="w",
            height=36,
            font=font("size_body"),
            fg_color="transparent",
            hover_color=color("bg_tertiary"),
            text_color=color("text_secondary"),
            corner_radius=layout("radius", 10),
            command=lambda k=key: self.show_page(k),
        )
        button.grid(row=len(self._nav_buttons), column=0, sticky="ew", pady=2)
        self._nav_buttons[key] = button

    def _register_developer4_pages(self) -> None:
        """Auto-register Developer 4 pages if their modules already exist.

        Guarded: while custom_scan.py and logs_page.py are still empty, the
        imports fail silently and the GUI keeps working.
        """
        candidates = [
            ("custom_scan", "Custom scan", "gui.pages.custom_scan", ("CustomScanPage", "CustomScan")),
            ("logs", "Logs", "gui.pages.logs_page", ("LogsPage", "LogsFrame")),
        ]
        for key, label, module_path, class_names in candidates:
            try:
                module = __import__(module_path, fromlist=list(class_names))
            except Exception:
                continue
            for class_name in class_names:
                page_class = getattr(module, class_name, None)
                if page_class is not None:
                    self.register_page(key, label, lambda master, c=page_class: c(master))
                    log_event(f"Developer 4 page '{key}' registered automatically.", "info")
                    break

    def show_page(self, key: str) -> None:
        """Display a registered page, instantiating it on first use."""
        page = self._pages.get(key)
        if page is None:
            log_event(f"Requested unknown page '{key}'.", "error")
            return

        if page["instance"] is None:
            try:
                page["instance"] = page["factory"](self._content)
            except Exception as exc:
                log_event(f"Failed to build page '{key}': {exc}", "error")
                return

        for other_key, other in self._pages.items():
            if other["instance"] is not None and other_key != key:
                other["instance"].grid_forget()

        page["instance"].grid(row=0, column=0, sticky="nsew")
        self._current_page = key
        self._highlight_nav(key)

    def _highlight_nav(self, key: str) -> None:
        for nav_key, button in self._nav_buttons.items():
            active = nav_key == key
            button.configure(
                fg_color=color("bg_tertiary") if active else "transparent",
                text_color=color("text_primary") if active else color("text_secondary"),
            )

    def _create_main_page(self, master: Any) -> ctk.CTkFrame:
        self._main_page = MainPage(
            master,
            on_scan_request=self.run_scan_now,
            scan_enabled=self._nmap_available,
        )
        return self._main_page

    # ------------------------------------------------------------------
    # Scheduler control (Developer 2 backend)
    # ------------------------------------------------------------------
    def _get_scheduler(self) -> NetworkScheduler | None:
        if self._scheduler is None:
            try:
                self._scheduler = NetworkScheduler()
            except Exception as exc:
                log_event(f"Could not create scheduler: {exc}", "error")
                return None
        return self._scheduler

    def run_scan_now(self) -> None:
        """Trigger one immediate scan in Developer 2's background thread."""
        scheduler = self._get_scheduler()
        if scheduler is None:
            return
        scheduler.run_now()
        log_event("Manual scan triggered from dashboard.", "info")
        self._update_scheduler_label()

    def toggle_scheduler(self) -> None:
        """Start or stop periodic background scanning."""
        scheduler = self._get_scheduler()
        if scheduler is None:
            return
        if scheduler.is_running():
            scheduler.stop()
        else:
            scheduler.start()
        self._update_scheduler_label()

    def _update_scheduler_label(self) -> None:
        scheduler = self._scheduler
        running = bool(scheduler and scheduler.is_running())
        interval = int(scheduler.get_interval()) if scheduler else 0
        self._scheduler_label.configure(
            text=f"scheduler running · {interval}s" if running else "scheduler stopped",
            text_color=color("accent") if running else color("text_muted"),
        )
        self._scheduler_button.configure(text="Stop scheduler" if running else "Start scheduler")

    # ------------------------------------------------------------------
    # Shutdown
    # ------------------------------------------------------------------
    def _on_close(self) -> None:
        main_page = getattr(self, "_main_page", None)
        if main_page is not None:
            main_page.stop_auto_refresh()
        if self._scheduler is not None and self._scheduler.is_running():
            self._scheduler.stop()
        log_event("GUI closed by user.", "info")
        self.destroy()