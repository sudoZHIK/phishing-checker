"""Tkinter GUI for Phishing Checker."""

from __future__ import annotations

import json
import logging
import os
import queue
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from . import __version__
from .analyzer import analyze
from .gui_logic import (
    DEFAULT_NETWORK,
    NETWORK_FIELDS,
    NetworkSettings,
    flow_place,
    grid_columns,
    parse_network_settings,
    shortcut_action,
)
from .models import AnalysisReport
from .report_text import (
    COVERAGE_TITLES,
    RISK_TITLES,
    build_readable_report,
    mask_url,
)

LOGGER = logging.getLogger(__name__)

HISTORY_LIMIT = 20
PROJECT_URL = "https://github.com/sudoZHIK/phishing-checker"
FONT = "DejaVu Sans"
METRIC_MIN_WIDTH = 320

API_KEYS = (
    ("VIRUSTOTAL_API_KEY", "VirusTotal"),
    ("GOOGLE_SAFE_BROWSING_API_KEY", "Google Safe Browsing"),
)

DARK = {
    "BG": "#101114",
    "PANEL": "#181a1f",
    "PANEL2": "#20232a",
    "BORDER": "#2d3038",
    "TEXT": "#f2f3f5",
    "MUTED": "#9298a3",
    "ACCENT": "#6ea8fe",
    "ACCENT_TEXT": "#0d1117",
    "INPUT": "#111318",
    "SELECT": "#3c5f91",
    "BTN_ACTIVE": "#292d36",
    "BTN_OFF_BG": "#17191d",
    "BTN_OFF_FG": "#666b75",
    "GREEN": "#55d187",
    "YELLOW": "#e5b95c",
    "RED": "#ef6b73",
}

LIGHT = {
    "BG": "#f4f5f7",
    "PANEL": "#ffffff",
    "PANEL2": "#e9ecf1",
    "BORDER": "#c9cdd6",
    "TEXT": "#1b1e24",
    "MUTED": "#5b6270",
    "ACCENT": "#1f6feb",
    "ACCENT_TEXT": "#ffffff",
    "INPUT": "#ffffff",
    "SELECT": "#b6d4fe",
    "BTN_ACTIVE": "#d9dde5",
    "BTN_OFF_BG": "#eceef2",
    "BTN_OFF_FG": "#9aa1ad",
    "GREEN": "#1a7f4b",
    "YELLOW": "#9a6700",
    "RED": "#c62828",
}

PALETTES = {"dark": DARK, "light": LIGHT}

# Семантические цвета тёмной темы (по умолчанию).
GREEN = DARK["GREEN"]
YELLOW = DARK["YELLOW"]
RED = DARK["RED"]


def _risk_role(score: int) -> str:
    if score >= 70:
        return "RED"
    if score >= 20:
        return "YELLOW"
    return "GREEN"


def _risk_color(score: int) -> str:
    return DARK[_risk_role(score)]


def _risk_title(level: str) -> str:
    return RISK_TITLES.get(level, "НЕ ОПРЕДЕЛЁН")


def _coverage_status(status: str) -> str:
    return COVERAGE_TITLES.get(status, status)


_mask_url = mask_url


def _evidence_text(report: AnalysisReport) -> str:
    """Краткая текстовая сводка (оставлена для совместимости с тестами)."""
    lines: list[str] = []

    if report.evidence:
        lines.append("ОБНАРУЖЕННЫЕ ПРИЗНАКИ")
        lines.append("")

        for item in report.evidence:
            marker = {
                "high": "✕",
                "medium": "⚠",
                "low": "⚠",
                "info": "•",
            }.get(item.severity, "•")

            weight = f"  [+{item.weight}]" if item.weight else ""
            lines.append(f"{marker} {item.message}{weight}")

            if item.details:
                for key, value in item.details.items():
                    lines.append(f"    {key}: {value}")

        lines.append("")
    else:
        lines.append("ПРИЗНАКИ РИСКА")
        lines.append("")
        lines.append("✓ Подозрительных признаков не обнаружено.")
        lines.append("")

    if report.errors:
        lines.append("ОШИБКИ / НЕПОЛНЫЕ ПРОВЕРКИ")
        lines.append("")

        for error in report.errors:
            lines.append(f"⚠ {error}")

        lines.append("")

    lines.append("РЕКОМЕНДАЦИЯ")
    lines.append("")

    if report.risk_score >= 70:
        lines.append(
            "Не вводите пароль, данные карты или коды "
            "подтверждения на этом сайте."
        )
    elif report.risk_score >= 40:
        lines.append(
            "Будьте осторожны. Перед вводом важных данных "
            "внимательно проверьте домен и адрес страницы."
        )
    elif report.risk_score >= 20:
        lines.append(
            "Обнаружены отдельные подозрительные признаки. "
            "Проверьте адрес сайта перед вводом важных данных."
        )
    else:
        lines.append(
            "Явных признаков фишинга не обнаружено. "
            "Это не гарантирует абсолютную безопасность сайта."
        )

    if report.coverage.status != "COMPLETE":
        lines.append("")
        lines.append(
            "Проверка выполнена не полностью. "
            "Низкая риск-оценка не означает, что сайт безопасен."
        )

    lines.append("")
    lines.append(
        "Результат является автоматической оценкой и "
        "не гарантирует безопасность сайта."
    )

    return "\n".join(lines)


def _technical_text(report: AnalysisReport, url: str) -> str:
    document = {
        "tool": "Phishing Checker",
        "version": __version__,
        "input_url": url,
        "report": report.to_dict(),
    }
    return json.dumps(document, ensure_ascii=False, indent=2)


def _json_text(report: AnalysisReport) -> str:
    return json.dumps(report.to_dict(), ensure_ascii=False, indent=2)


def _fmt_number(value: float) -> str:
    return f"{value:g}"


class _App:
    """Главное окно. Tk трогает только основной поток."""

    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.theme = "dark"
        self.windowing = str(root.tk.call("tk", "windowingsystem"))

        self.registry: dict[tk.Misc, dict[str, str]] = {}
        self.layouts: dict[tk.Misc, object] = {}
        self.secret_widgets: set[tk.Misc] = set()

        self.network: NetworkSettings = DEFAULT_NETWORK
        self.results: queue.Queue = queue.Queue()
        self.running = False

        self.last_report: AnalysisReport | None = None
        self.last_url = ""
        self.view_mode = "readable"
        self.history: list[tuple[str, str, AnalysisReport]] = []

        self.settings_window: tk.Toplevel | None = None
        self.original_keys = {name: os.environ.get(name) for name, _ in API_KEYS}
        self.session_keys: set[str] = set()

        self.url_var = tk.StringVar()
        self.status_var = tk.StringVar()
        self.score_var = tk.StringVar()
        self.verdict_var = tk.StringVar()
        self.coverage_var = tk.StringVar()
        self.coverage_state_var = tk.StringVar()
        self.theme_var = tk.StringVar(value=self.theme)

        root.title("Phishing Checker")
        root.geometry("980x760")

        self._build_ui()
        self.apply_theme()
        self.reset_view()
        self._set_result_buttons(False)

        root.update_idletasks()
        root.minsize(560, 600)
        root.protocol("WM_DELETE_WINDOW", root.destroy)
        self.url_entry.focus_set()

    # ------------------------------------------------------------------ тема

    def _pal(self) -> dict[str, str]:
        return PALETTES[self.theme]

    def _apply(self, widget: tk.Misc, roles: dict[str, str]) -> None:
        pal = self._pal()
        widget.configure(**{option: pal[role] for option, role in roles.items()})

    def themed(self, widget, **roles: str):
        """Запомнить роли цветов виджета, чтобы перекрасить при смене темы."""
        self.registry[widget] = dict(roles)
        self._apply(widget, roles)
        return widget

    def recolor(self, widget, **roles: str) -> None:
        self.registry.setdefault(widget, {}).update(roles)
        self._apply(widget, roles)

    def _configure_styles(self) -> None:
        pal = self._pal()
        style = ttk.Style(self.root)
        style.theme_use("clam")

        style.configure(
            "Main.TButton",
            font=(FONT, 10, "bold"),
            padding=(16, 9),
            background=pal["PANEL2"],
            foreground=pal["TEXT"],
            borderwidth=0,
        )
        style.map(
            "Main.TButton",
            background=[("active", pal["BTN_ACTIVE"]), ("disabled", pal["BTN_OFF_BG"])],
            foreground=[("disabled", pal["BTN_OFF_FG"])],
        )

        style.configure(
            "Accent.TButton",
            font=(FONT, 10, "bold"),
            padding=(20, 9),
            background=pal["ACCENT"],
            foreground=pal["ACCENT_TEXT"],
            borderwidth=0,
        )
        style.map(
            "Accent.TButton",
            background=[("active", pal["ACCENT"]), ("disabled", pal["BTN_OFF_BG"])],
            foreground=[("disabled", pal["BTN_OFF_FG"])],
        )

        for name, role in (
            ("Risk", "GREEN"),
            ("RiskYellow", "YELLOW"),
            ("RiskRed", "RED"),
        ):
            color = pal[role]
            style.configure(
                f"{name}.Horizontal.TProgressbar",
                troughcolor=pal["PANEL2"],
                background=color,
                bordercolor=pal["PANEL2"],
                lightcolor=color,
                darkcolor=color,
            )

        style.configure(
            "Vertical.TScrollbar",
            background=pal["PANEL2"],
            troughcolor=pal["PANEL"],
            bordercolor=pal["PANEL"],
            arrowcolor=pal["TEXT"],
        )
        style.configure("TNotebook", background=pal["BG"], borderwidth=0)
        style.configure(
            "TNotebook.Tab",
            background=pal["PANEL2"],
            foreground=pal["TEXT"],
            padding=(14, 6),
        )
        style.map(
            "TNotebook.Tab",
            background=[("selected", pal["ACCENT"])],
            foreground=[("selected", pal["ACCENT_TEXT"])],
        )

    def _configure_tags(self) -> None:
        pal = self._pal()
        text = self.text

        text.tag_configure(
            "title", foreground=pal["ACCENT"], font=(FONT, 14, "bold"), spacing3=2
        )
        text.tag_configure(
            "section",
            foreground=pal["ACCENT"],
            font=(FONT, 10, "bold"),
            spacing1=8,
            spacing3=3,
        )
        text.tag_configure("body", foreground=pal["TEXT"])
        text.tag_configure("body_b", foreground=pal["TEXT"], font=(FONT, 10, "bold"))
        for tag, role in (
            ("ok", "GREEN"),
            ("warn", "YELLOW"),
            ("bad", "RED"),
            ("muted", "MUTED"),
        ):
            text.tag_configure(tag, foreground=pal[role])
            text.tag_configure(
                f"{tag}_b", foreground=pal[role], font=(FONT, 10, "bold")
            )
        text.tag_configure("desc", foreground=pal["MUTED"], lmargin1=24, lmargin2=24)
        text.tag_configure("res", foreground=pal["TEXT"], lmargin1=24, lmargin2=24)
        text.tag_configure("mono", foreground=pal["TEXT"], font="TkFixedFont")

    def apply_theme(self) -> None:
        self._configure_styles()
        self.root.configure(bg=self._pal()["BG"])

        for widget, roles in list(self.registry.items()):
            try:
                self._apply(widget, roles)
            except tk.TclError:
                self.registry.pop(widget, None)

        self._configure_tags()

    def set_theme(self, name: str) -> None:
        if name not in PALETTES:
            return
        self.theme = name
        self.theme_var.set(name)
        self.theme_button.configure(
            text="Тёмная тема" if name == "light" else "Светлая тема"
        )
        self.apply_theme()

    def toggle_theme(self) -> None:
        self.set_theme("light" if self.theme == "dark" else "dark")

    # --------------------------------------------------------- фабрики виджетов

    def _frame(self, parent, bg: str = "PANEL", border: bool = False) -> tk.Frame:
        frame = tk.Frame(parent)
        roles = {"bg": bg}
        if border:
            frame.configure(highlightthickness=1)
            roles["highlightbackground"] = "BORDER"
        return self.themed(frame, **roles)

    def _label(
        self,
        parent,
        text: str = "",
        *,
        textvariable: tk.StringVar | None = None,
        fg: str = "TEXT",
        bg: str = "PANEL",
        font: tuple | None = None,
        **options,
    ) -> tk.Label:
        label = tk.Label(parent, text=text, font=font or (FONT, 10), **options)
        if textvariable is not None:
            label.configure(textvariable=textvariable)
        return self.themed(label, fg=fg, bg=bg)

    def _button(self, parent, text: str, command, style: str = "Main.TButton"):
        return ttk.Button(parent, text=text, style=style, command=command)

    def _entry(
        self,
        parent,
        textvariable: tk.StringVar,
        *,
        secret: bool = False,
        width: int | None = None,
    ) -> tk.Entry:
        entry = tk.Entry(
            parent,
            textvariable=textvariable,
            relief="flat",
            bd=0,
            font=(FONT, 11),
            highlightthickness=1,
            insertwidth=2,
        )
        if width is not None:
            entry.configure(width=width)
        if secret:
            entry.configure(show="•")
            self.secret_widgets.add(entry)
        self.themed(
            entry,
            bg="INPUT",
            fg="TEXT",
            insertbackground="TEXT",
            selectbackground="SELECT",
            selectforeground="TEXT",
            highlightbackground="BORDER",
            highlightcolor="ACCENT",
            disabledbackground="INPUT",
            disabledforeground="MUTED",
        )
        self._edit_support(entry, "secret" if secret else "entry")
        return entry

    # ---------------------------------------------- правка текста: меню, Ctrl+...

    def _selection(self, widget) -> str:
        if isinstance(widget, tk.Text):
            ranges = widget.tag_ranges("sel")
            if ranges:
                return str(widget.get(ranges[0], ranges[1]))
            return ""
        if widget.selection_present():
            return str(widget.selection_get())
        return ""

    def _edit_action(self, widget, action: str) -> None:
        is_text = isinstance(widget, tk.Text)
        editable = (not is_text) and str(widget.cget("state")) == "normal"

        if action == "select_all":
            if is_text:
                widget.tag_add("sel", "1.0", "end-1c")
            else:
                widget.selection_range(0, "end")
                widget.icursor("end")
            return

        if action in ("copy", "cut"):
            if widget in self.secret_widgets:
                return
            selected = self._selection(widget)
            if not selected:
                return
            self.root.clipboard_clear()
            self.root.clipboard_append(selected)
            if action == "cut" and editable:
                widget.delete("sel.first", "sel.last")
            return

        if action == "paste" and editable:
            try:
                text = self.root.clipboard_get()
            except tk.TclError:
                return
            text = text.replace("\r", "").replace("\n", "")
            if widget.selection_present():
                widget.delete("sel.first", "sel.last")
            widget.insert("insert", text)

    def _on_ctrl_key(self, event) -> str | None:
        action = shortcut_action(event.keysym, event.keycode, self.windowing)
        if action is None:
            return None
        self._edit_action(event.widget, action)
        return "break"

    def _edit_support(self, widget, kind: str) -> None:
        """Контекстное меню (ПКМ) и Ctrl+C/V/X/A для любой раскладки."""
        menu = tk.Menu(widget, tearoff=0)
        self.themed(
            menu,
            bg="PANEL2",
            fg="TEXT",
            activebackground="ACCENT",
            activeforeground="ACCENT_TEXT",
        )

        if kind == "entry":
            menu.add_command(
                label="Вырезать", command=lambda: self._edit_action(widget, "cut")
            )
        if kind in ("entry", "text"):
            menu.add_command(
                label="Копировать", command=lambda: self._edit_action(widget, "copy")
            )
        if kind in ("entry", "secret"):
            menu.add_command(
                label="Вставить", command=lambda: self._edit_action(widget, "paste")
            )
        menu.add_separator()
        menu.add_command(
            label="Выделить всё",
            command=lambda: self._edit_action(widget, "select_all"),
        )

        def popup(event) -> str:
            widget.focus_set()
            try:
                menu.tk_popup(event.x_root, event.y_root)
            finally:
                menu.grab_release()
            return "break"

        widget.bind("<Button-3>", popup)
        if self.windowing == "aqua":
            widget.bind("<Button-2>", popup)
            widget.bind("<Control-Button-1>", popup)
        widget.bind("<Control-KeyPress>", self._on_ctrl_key)

    # --------------------------------------------------------------- раскладка

    def _build_ui(self) -> None:
        main = self._frame(self.root, bg="BG")
        main.pack(fill="both", expand=True, padx=20, pady=16)
        main.columnconfigure(0, weight=1)
        main.rowconfigure(6, weight=1)
        self.main = main

        self._build_header(main)
        self._build_url_row(main)
        self._build_metrics(main)
        self._build_buttons(main)
        self._build_history(main)

        self.progress = ttk.Progressbar(
            main, mode="indeterminate", style="Risk.Horizontal.TProgressbar"
        )

        self._build_result(main)

        self.status_label = self._label(
            main,
            textvariable=self.status_var,
            fg="MUTED",
            bg="BG",
            anchor="w",
            justify="left",
        )
        self.status_label.grid(row=7, column=0, sticky="ew", pady=(8, 0))
        main.bind(
            "<Configure>",
            lambda event: self.status_label.configure(
                wraplength=max(200, event.width - 20)
            ),
        )

    def _build_header(self, main: tk.Frame) -> None:
        header = self._frame(main, bg="BG")
        header.grid(row=0, column=0, sticky="ew")
        header.columnconfigure(0, weight=1)

        self._label(
            header,
            "PHISHING CHECKER",
            bg="BG",
            font=(FONT, 20, "bold"),
        ).grid(row=0, column=0, sticky="w")

        self.subtitle = self._label(
            header,
            "Локальная защитная проверка URL. "
            "Результат не является гарантией безопасности.",
            fg="MUTED",
            bg="BG",
            font=(FONT, 9),
            justify="left",
            anchor="w",
        )
        self.subtitle.grid(row=1, column=0, sticky="w", pady=(2, 12))

        self.theme_button = self._button(
            header, "Светлая тема", self.toggle_theme
        )
        self.theme_button.grid(row=0, column=1, rowspan=2, sticky="e", padx=(12, 0))

        header.bind(
            "<Configure>",
            lambda event: self.subtitle.configure(
                wraplength=max(200, event.width - 180)
            ),
        )

    def _build_url_row(self, main: tk.Frame) -> None:
        frame = self._frame(main, "PANEL", border=True)
        frame.grid(row=1, column=0, sticky="ew", pady=(0, 12))
        frame.columnconfigure(0, weight=1)

        self.url_entry = self._entry(frame, self.url_var)
        self.url_entry.grid(row=0, column=0, sticky="ew", padx=(12, 8), pady=12, ipady=5)
        self.url_entry.bind("<Return>", self.start_check)

        self.paste_button = self._button(frame, "Вставить", self.paste_url)
        self.paste_button.grid(row=0, column=1, padx=(0, 8), pady=8)

    def _metric_panel(self, parent: tk.Frame, caption: str) -> tk.Frame:
        panel = self._frame(parent, "PANEL", border=True)
        self._label(
            panel,
            caption,
            fg="MUTED",
            font=(FONT, 9, "bold"),
        ).pack(anchor="w", padx=18, pady=(14, 0))
        return panel

    def _build_metrics(self, main: tk.Frame) -> None:
        self.metrics = self._frame(main, bg="BG")
        self.metrics.grid(row=2, column=0, sticky="ew", pady=(0, 12))

        self.risk_panel = self._metric_panel(self.metrics, "РИСК-ОЦЕНКА")
        self.score_value = self._label(
            self.risk_panel,
            textvariable=self.score_var,
            fg="MUTED",
            font=(FONT, 30, "bold"),
            anchor="w",
        )
        self.score_value.pack(anchor="w", padx=18)
        self.verdict_label = self._label(
            self.risk_panel,
            textvariable=self.verdict_var,
            fg="MUTED",
            font=(FONT, 11, "bold"),
            justify="left",
            anchor="w",
        )
        self.verdict_label.pack(anchor="w", padx=18, pady=(0, 10))
        self.risk_bar = ttk.Progressbar(
            self.risk_panel,
            maximum=100,
            mode="determinate",
            style="Risk.Horizontal.TProgressbar",
        )
        self.risk_bar.pack(fill="x", padx=18, pady=(0, 14))

        self.coverage_panel = self._metric_panel(self.metrics, "ПОЛНОТА ПРОВЕРКИ")
        self.coverage_value = self._label(
            self.coverage_panel,
            textvariable=self.coverage_var,
            fg="MUTED",
            font=(FONT, 23, "bold"),
            anchor="w",
            justify="left",
        )
        self.coverage_value.pack(anchor="w", padx=18, pady=(3, 0))
        self.coverage_state = self._label(
            self.coverage_panel,
            textvariable=self.coverage_state_var,
            fg="MUTED",
            font=(FONT, 13, "bold"),
            anchor="w",
            justify="left",
        )
        self.coverage_state.pack(anchor="w", padx=18)
        self._label(
            self.coverage_panel,
            "Количество успешно завершённых проверок",
            fg="MUTED",
            font=(FONT, 9),
            anchor="w",
            justify="left",
        ).pack(anchor="w", padx=18, pady=(2, 14))

        self.risk_panel.grid(row=0, column=0, sticky="nsew", padx=(0, 7))
        self.coverage_panel.grid(row=0, column=1, sticky="nsew", padx=(7, 0))
        self.metrics.columnconfigure(0, weight=1, uniform="metrics")
        self.metrics.columnconfigure(1, weight=1, uniform="metrics")

        self.metrics.bind("<Configure>", lambda _event: self._reflow_metrics())
        self.risk_panel.bind(
            "<Configure>",
            lambda event: self.verdict_label.configure(
                wraplength=max(120, event.width - 40)
            ),
        )
        self.coverage_panel.bind(
            "<Configure>",
            lambda event: self.coverage_state.configure(
                wraplength=max(120, event.width - 40)
            ),
        )

    def _reflow_metrics(self) -> None:
        width = self.metrics.winfo_width()
        if width <= 1:
            return

        columns = grid_columns(width, METRIC_MIN_WIDTH, 2)
        if self.layouts.get(self.metrics) == columns:
            return
        self.layouts[self.metrics] = columns

        for index, panel in enumerate((self.risk_panel, self.coverage_panel)):
            if columns == 2:
                padx = (0, 7) if index == 0 else (7, 0)
                pady = 0
            else:
                padx = 0
                pady = (0, 8) if index == 0 else 0
            panel.grid(
                row=index // columns,
                column=index % columns,
                sticky="nsew",
                padx=padx,
                pady=pady,
            )

        for column in range(2):
            self.metrics.columnconfigure(
                column,
                weight=1 if column < columns else 0,
                uniform="metrics" if column < columns else "",
            )

    def _build_buttons(self, main: tk.Frame) -> None:
        self.bar = self._frame(main, bg="BG")
        self.bar.grid(row=3, column=0, sticky="ew", pady=(0, 6))
        self.bar.configure(height=40)

        self.check_button = self._button(
            self.bar, "ПРОВЕРИТЬ", self.start_check, "Accent.TButton"
        )
        self.clear_button = self._button(self.bar, "Очистить", self.clear)
        self.view_button = self._button(
            self.bar, "ТЕХНИЧЕСКИЙ ОТЧЁТ", self.toggle_view
        )
        self.history_button = self._button(self.bar, "История", self.toggle_history)
        self.settings_button = self._button(
            self.bar, "Настройки", self.open_settings
        )
        self.copy_button = self._button(self.bar, "Копировать", self.copy_report)
        self.export_button = self._button(self.bar, "Экспорт JSON", self.export_json)

        self.bar_items = [
            self.check_button,
            self.clear_button,
            self.view_button,
            self.history_button,
            self.settings_button,
            self.copy_button,
            self.export_button,
        ]
        for item in self.bar_items:
            item.place(x=0, y=0)

        self.bar.bind("<Configure>", lambda _event: self._reflow_bar())

    def _reflow_bar(self) -> None:
        width = self.bar.winfo_width()
        if width <= 1:
            return

        sizes = [(item.winfo_reqwidth(), item.winfo_reqheight()) for item in self.bar_items]
        positions, height = flow_place(sizes, width)

        key = (tuple(positions), height)
        if self.layouts.get(self.bar) == key:
            return
        self.layouts[self.bar] = key

        for item, (x_pos, y_pos) in zip(self.bar_items, positions, strict=True):
            item.place(x=x_pos, y=y_pos)
        self.bar.configure(height=height)

    def _relayout_bar(self) -> None:
        """Подпись кнопки изменилась: пересчитать перенос кнопок."""
        self.layouts.pop(self.bar, None)
        self.root.update_idletasks()
        self._reflow_bar()

    def _build_history(self, main: tk.Frame) -> None:
        self.history_frame = self._frame(main, "PANEL", border=True)
        self.history_visible = False

        self._label(
            self.history_frame,
            "ИСТОРИЯ ПРОВЕРОК (хранится, пока открыто окно)",
            fg="ACCENT",
            font=(FONT, 9, "bold"),
        ).pack(anchor="w", padx=14, pady=(10, 4))

        self.history_list = tk.Listbox(
            self.history_frame,
            height=6,
            relief="flat",
            bd=0,
            highlightthickness=0,
            activestyle="none",
            exportselection=False,
            font="TkFixedFont",
        )
        self.themed(
            self.history_list,
            bg="PANEL2",
            fg="TEXT",
            selectbackground="SELECT",
            selectforeground="TEXT",
        )
        self.history_list.pack(fill="x", padx=14, pady=(0, 6))
        self.history_list.bind("<<ListboxSelect>>", self.show_history_item)

        self._button(
            self.history_frame, "Очистить историю", self.clear_history
        ).pack(anchor="e", padx=14, pady=(0, 10))

    def _build_result(self, main: tk.Frame) -> None:
        panel = self._frame(main, "PANEL", border=True)
        panel.grid(row=6, column=0, sticky="nsew")
        panel.rowconfigure(0, weight=1)
        panel.columnconfigure(0, weight=1)

        self.text = tk.Text(
            panel,
            wrap="word",
            relief="flat",
            bd=0,
            highlightthickness=0,
            font=(FONT, 10),
            padx=16,
            pady=14,
            width=10,
            height=5,
            state="disabled",
        )
        self.themed(
            self.text,
            bg="INPUT",
            fg="TEXT",
            insertbackground="TEXT",
            selectbackground="SELECT",
            selectforeground="TEXT",
        )
        self.text.grid(row=0, column=0, sticky="nsew", padx=(12, 0), pady=12)
        self.text.bind("<Button-1>", lambda _event: self.text.focus_set())
        self._edit_support(self.text, "text")

        scrollbar = ttk.Scrollbar(panel, orient="vertical", command=self.text.yview)
        scrollbar.grid(row=0, column=1, sticky="ns", padx=(0, 12), pady=12)
        self.text.configure(yscrollcommand=scrollbar.set)

    # --------------------------------------------------------------- состояния

    def show_lines(self, lines: list[tuple[str, str]]) -> None:
        text = self.text
        text.configure(state="normal")
        text.delete("1.0", "end")
        for tag, content in lines:
            if tag in ("blank", ""):
                text.insert("end", "\n")
            else:
                text.insert("end", content + "\n", (tag,))
        text.configure(state="disabled")
        text.yview_moveto(0)

    def reset_view(self) -> None:
        self.status_var.set("Введите ссылку и нажмите «ПРОВЕРИТЬ»")
        self.score_var.set("—")
        self.verdict_var.set("ГОТОВ К ПРОВЕРКЕ")
        self.coverage_var.set("—")
        self.coverage_state_var.set("НЕ ПРОВЕРЕНО")

        for widget in (
            self.score_value,
            self.verdict_label,
            self.coverage_value,
            self.coverage_state,
        ):
            self.recolor(widget, fg="MUTED")

        self.risk_bar.configure(value=0, style="Risk.Horizontal.TProgressbar")
        self.show_lines(
            [
                ("title", "РЕЗУЛЬТАТ ПРОВЕРКИ ПОЯВИТСЯ ЗДЕСЬ"),
                ("blank", ""),
                ("body", "Вставьте ссылку на сайт в поле выше и нажмите «ПРОВЕРИТЬ»."),
                ("blank", ""),
                ("section", "ЧТО ПРОВЕРЯЕТСЯ"),
                (
                    "body",
                    ("Адрес и признаки маскировки, сходство с известными брендами, "
                    "DNS, данные о регистрации домена, сертификат HTTPS, ответ "
                    "сайта, содержимое страницы и (по желанию) репутационные "
                    "сервисы."),
                ),
                ("blank", ""),
                (
                    "muted",
                    ("Низкая риск-оценка означает лишь, что признаков риска не "
                    "обнаружено. Это не гарантия безопасности сайта."),
                ),
            ]
        )

    def set_verdict(self, report: AnalysisReport) -> None:
        score = int(report.risk_score)
        role = _risk_role(score)
        coverage = report.coverage

        self.score_var.set(f"{score}/100")
        self.verdict_var.set(_risk_title(report.risk_level))
        self.coverage_var.set(f"{coverage.passed}/{coverage.total} — {coverage.percent:.0f}%")
        self.coverage_state_var.set(_coverage_status(coverage.status))

        coverage_role = {"COMPLETE": "GREEN", "PARTIAL": "YELLOW"}.get(
            coverage.status, "MUTED"
        )
        self.recolor(self.score_value, fg=role)
        self.recolor(self.verdict_label, fg=role)
        self.recolor(self.coverage_value, fg=coverage_role)
        self.recolor(self.coverage_state, fg=coverage_role)

        style = {
            "RED": "RiskRed.Horizontal.TProgressbar",
            "YELLOW": "RiskYellow.Horizontal.TProgressbar",
            "GREEN": "Risk.Horizontal.TProgressbar",
        }[role]
        self.risk_bar.configure(value=max(0, min(100, score)), style=style)

    def render(self) -> None:
        report = self.last_report
        if report is None:
            return

        if self.view_mode == "technical":
            body = _technical_text(report, self.last_url)
            lines = [("section", "ТЕХНИЧЕСКИЙ ОТЧЁТ"), ("blank", "")]
            lines.extend(("mono", row) for row in body.splitlines())
            self.show_lines(lines)
            self.view_button.configure(text="ПОНЯТНЫЙ ОТЧЁТ")
        else:
            self.show_lines(build_readable_report(report, self.last_url))
            self.view_button.configure(text="ТЕХНИЧЕСКИЙ ОТЧЁТ")

        self._relayout_bar()

    def _set_result_buttons(self, enabled: bool) -> None:
        state = "normal" if enabled else "disabled"
        for button in (self.view_button, self.copy_button, self.export_button):
            button.configure(state=state)

    def _set_busy(self, busy: bool) -> None:
        state = "disabled" if busy else "normal"
        for button in (self.check_button, self.clear_button, self.paste_button):
            button.configure(state=state)
        self.url_entry.configure(state=state)

        if busy:
            self._set_result_buttons(False)
        else:
            self._set_result_buttons(self.last_report is not None)

    # ------------------------------------------------------------------ проверка

    def paste_url(self) -> None:
        try:
            text = self.root.clipboard_get()
        except tk.TclError:
            return
        self.url_var.set(text.strip())
        self.url_entry.focus_set()
        self.url_entry.icursor("end")

    def start_check(self, _event=None) -> str:
        if self.running:
            return "break"

        url = self.url_var.get().strip()
        if not url:
            self.status_var.set("Введите ссылку")
            self.url_entry.focus_set()
            return "break"

        self.running = True
        self._set_busy(True)

        self.status_var.set("Выполняется проверка…")
        self.score_var.set("—")
        self.verdict_var.set("ИДЁТ ПРОВЕРКА")
        self.coverage_var.set("—")
        self.coverage_state_var.set("ПРОВЕРКА…")
        for widget in (self.score_value, self.verdict_label):
            self.recolor(widget, fg="ACCENT")
        self.recolor(self.coverage_value, fg="MUTED")
        self.recolor(self.coverage_state, fg="MUTED")
        self.risk_bar.configure(value=0, style="Risk.Horizontal.TProgressbar")

        self.show_lines(
            [
                ("title", "ВЫПОЛНЯЕТСЯ ПРОВЕРКА"),
                ("blank", ""),
                (
                    "body",
                    ("Анализируется структура ссылки и выполняются доступные "
                    "сетевые проверки. Окно не зависло: анализ идёт в отдельном "
                    "потоке."),
                ),
            ]
        )

        self.progress.grid(row=5, column=0, sticky="ew", pady=(0, 10))
        self.progress.start(12)

        threading.Thread(
            target=self._worker,
            args=(url, self.network),
            daemon=True,
        ).start()
        self.root.after(100, self._poll)
        return "break"

    def _worker(self, url: str, net: NetworkSettings) -> None:
        """Рабочий поток: Tk не трогает, результат отдаёт через очередь."""
        try:
            report = analyze(
                url,
                fetch_dns=True,
                dns_timeout=net.dns_timeout,
                rdap_timeout=net.rdap_timeout,
                fetch_http=True,
                http_connect_timeout=net.http_connect_timeout,
                http_read_timeout=net.http_read_timeout,
                http_overall_timeout=net.http_overall_timeout,
                http_max_redirects=net.http_max_redirects,
                allow_private=False,
            )
        except Exception as exc:
            LOGGER.error("GUI analysis failed: %s", type(exc).__name__)
            LOGGER.debug("GUI analysis traceback", exc_info=True)
            self.results.put(("error", url, exc))
            return

        self.results.put(("ok", url, report))

    def _poll(self) -> None:
        try:
            kind, url, payload = self.results.get_nowait()
        except queue.Empty:
            self.root.after(100, self._poll)
            return

        if kind == "ok":
            self._finish(url, report=payload)
        else:
            self._finish(url, error=payload)

    def _finish(
        self,
        url: str,
        report: AnalysisReport | None = None,
        error: Exception | None = None,
    ) -> None:
        self.running = False
        self.progress.stop()
        self.progress.grid_remove()

        if error is not None or report is None:
            self.last_report = None
            self._set_busy(False)
            self.status_var.set("Ошибка проверки")
            self.score_var.set("—")
            self.verdict_var.set("ОШИБКА")
            self.coverage_var.set("—")
            self.coverage_state_var.set("НЕ ПРОВЕРЕНО")
            self.recolor(self.score_value, fg="RED")
            self.recolor(self.verdict_label, fg="RED")
            self.recolor(self.coverage_value, fg="MUTED")
            self.recolor(self.coverage_state, fg="MUTED")
            self.show_lines(
                [
                    ("bad_b", "Не удалось выполнить проверку."),
                    ("blank", ""),
                    ("body", str(error) if error else "Неизвестная ошибка."),
                ]
            )
            self.url_entry.focus_set()
            return

        self.last_report = report
        self.last_url = url
        self.view_mode = "readable"
        self._set_busy(False)
        self._add_history(url, report)
        self.set_verdict(report)
        self.render()
        self.status_var.set("Проверка завершена")
        self.url_entry.focus_set()
        self.url_entry.icursor("end")

    def clear(self) -> None:
        self.last_report = None
        self.last_url = ""
        self.view_mode = "readable"
        self.url_var.set("")
        self._set_result_buttons(False)
        self.view_button.configure(text="ТЕХНИЧЕСКИЙ ОТЧЁТ")
        self._relayout_bar()
        self.reset_view()
        self.url_entry.focus_set()

    # ------------------------------------------------------------ отчёт и экспорт

    def toggle_view(self) -> None:
        if self.last_report is None:
            return
        self.view_mode = "technical" if self.view_mode == "readable" else "readable"
        self.render()

    def copy_report(self) -> None:
        if self.last_report is None:
            return
        content = self.text.get("1.0", "end-1c")
        self.root.clipboard_clear()
        self.root.clipboard_append(content)
        self.root.update_idletasks()
        self.status_var.set("Отчёт скопирован в буфер обмена")

    def export_json(self) -> None:
        if self.last_report is None:
            return

        path = filedialog.asksaveasfilename(
            title="Сохранить JSON-отчёт",
            defaultextension=".json",
            filetypes=[("JSON", "*.json"), ("Все файлы", "*.*")],
        )
        if not path:
            return

        try:
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(_json_text(self.last_report))
        except OSError as exc:
            messagebox.showerror("Ошибка экспорта", str(exc))
            return

        self.status_var.set(f"JSON сохранён: {path}")

    # ------------------------------------------------------------------- история

    def toggle_history(self) -> None:
        if self.history_visible:
            self.history_frame.grid_remove()
            self.history_visible = False
        else:
            self.history_frame.grid(row=4, column=0, sticky="ew", pady=(0, 10))
            self.history_visible = True

    def _refresh_history(self) -> None:
        self.history_list.delete(0, "end")
        for label, _url, report in self.history:
            self.history_list.insert(
                "end",
                f"{report.risk_score:>3}  {report.risk_level:<10} {label}",
            )

    def _add_history(self, url: str, report: AnalysisReport) -> None:
        if not url:
            return
        self.history.insert(0, (_mask_url(url), url, report))
        del self.history[HISTORY_LIMIT:]
        self._refresh_history()

    def show_history_item(self, _event=None) -> None:
        if self.running:
            return
        selection = self.history_list.curselection()
        if not selection:
            return

        _label, url, report = self.history[selection[0]]
        self.last_report = report
        self.last_url = url
        self.view_mode = "readable"
        self.url_var.set(url)
        self.set_verdict(report)
        self._set_result_buttons(True)
        self.render()
        self.status_var.set("Показан результат из истории")
        self.url_entry.focus_set()
        self.url_entry.icursor("end")

    def clear_history(self) -> None:
        self.history.clear()
        self._refresh_history()
        self.status_var.set("История очищена")

    # ------------------------------------------------------------------ настройки

    def open_settings(self, tab: int = 0) -> None:
        window = self.settings_window
        if window is not None and window.winfo_exists():
            window.lift()
            window.focus_set()
            return

        window = tk.Toplevel(self.root)
        self.settings_window = window
        window.title("Настройки")
        window.geometry("620x560")
        window.minsize(540, 480)
        window.transient(self.root)
        self.themed(window, bg="BG")

        body = self._frame(window, bg="BG")
        body.pack(fill="both", expand=True, padx=14, pady=14)

        notebook = ttk.Notebook(body)
        notebook.pack(fill="both", expand=True)

        for title, builder in (
            ("Сеть", self._tab_network),
            ("API-ключи", self._tab_keys),
            ("Оформление", self._tab_theme),
            ("О программе", self._tab_about),
        ):
            page = self._frame(notebook, "PANEL")
            notebook.add(page, text=title)
            builder(page)

        self._button(body, "Закрыть", window.destroy).pack(anchor="e", pady=(10, 0))
        notebook.select(tab)

    def _heading(self, page: tk.Frame, title: str, hint: str) -> None:
        self._label(page, title, fg="ACCENT", font=(FONT, 11, "bold")).pack(
            anchor="w", padx=18, pady=(16, 2)
        )
        self._label(
            page,
            hint,
            fg="MUTED",
            font=(FONT, 9),
            justify="left",
            wraplength=520,
            anchor="w",
        ).pack(anchor="w", padx=18, pady=(0, 10))

    def _tab_network(self, page: tk.Frame) -> None:
        self._heading(
            page,
            "Сетевые ограничения",
            "Значения применяются к следующей проверке. По умолчанию стоят "
            "значения из спецификации проекта.",
        )

        self.net_vars: dict[str, tk.StringVar] = {}
        grid = self._frame(page, "PANEL")
        grid.pack(anchor="w", padx=18)

        for row, (name, label) in enumerate(NETWORK_FIELDS):
            variable = tk.StringVar(value=_fmt_number(getattr(self.network, name)))
            self.net_vars[name] = variable
            self._label(grid, label).grid(row=row, column=0, sticky="w", pady=4)
            self._entry(grid, variable, width=10).grid(
                row=row, column=1, sticky="w", padx=(16, 0), pady=4, ipady=3
            )

        self.net_message_var = tk.StringVar()
        self.net_message = self._label(
            page,
            textvariable=self.net_message_var,
            fg="MUTED",
            font=(FONT, 9),
            justify="left",
            wraplength=520,
            anchor="w",
        )
        self.net_message.pack(anchor="w", padx=18, pady=(10, 0))

        buttons = self._frame(page, "PANEL")
        buttons.pack(anchor="w", padx=18, pady=10)
        self._button(buttons, "Применить", self.apply_network).pack(side="left")
        self._button(buttons, "По умолчанию", self.reset_network).pack(
            side="left", padx=(8, 0)
        )

    def apply_network(self) -> None:
        raw = {name: variable.get() for name, variable in self.net_vars.items()}
        try:
            self.network = parse_network_settings(raw)
        except ValueError as exc:
            self.net_message_var.set(str(exc))
            self.recolor(self.net_message, fg="RED")
            return

        self.net_message_var.set("Настройки применены.")
        self.recolor(self.net_message, fg="GREEN")

    def reset_network(self) -> None:
        for name, variable in self.net_vars.items():
            variable.set(_fmt_number(getattr(DEFAULT_NETWORK, name)))
        self.apply_network()

    def _key_status(self, env_name: str) -> str:
        return "Ключ задан" if os.environ.get(env_name) else "Ключ не задан"

    def _tab_keys(self, page: tk.Frame) -> None:
        self._heading(
            page,
            "Ключи репутационных сервисов",
            "Необязательно: программа полноценно работает и без ключей. Ключ "
            "хранится только в памяти, пока открыто окно, и нигде не "
            "записывается. Для постоянного хранения задайте переменную "
            "окружения с тем же именем.",
        )

        self.key_vars: dict[str, tk.StringVar] = {}
        self.key_status_vars: dict[str, tk.StringVar] = {}

        for env_name, title in API_KEYS:
            box = self._frame(page, "PANEL")
            box.pack(fill="x", padx=18, pady=(0, 10))
            box.columnconfigure(0, weight=1)

            self._label(box, title, font=(FONT, 10, "bold")).grid(
                row=0, column=0, sticky="w"
            )

            status = tk.StringVar(value=self._key_status(env_name))
            self.key_status_vars[env_name] = status
            self._label(box, textvariable=status, fg="MUTED", font=(FONT, 9)).grid(
                row=0, column=1, sticky="e"
            )

            variable = tk.StringVar()
            self.key_vars[env_name] = variable
            self._entry(box, variable, secret=True).grid(
                row=1, column=0, columnspan=2, sticky="ew", pady=(4, 0), ipady=4
            )
            self._label(box, env_name, fg="MUTED", font=(FONT, 8)).grid(
                row=2, column=0, columnspan=2, sticky="w"
            )

        self.key_message_var = tk.StringVar()
        self.key_message = self._label(
            page,
            textvariable=self.key_message_var,
            fg="MUTED",
            font=(FONT, 9),
            justify="left",
            wraplength=520,
            anchor="w",
        )
        self.key_message.pack(anchor="w", padx=18)

        buttons = self._frame(page, "PANEL")
        buttons.pack(anchor="w", padx=18, pady=10)
        self._button(buttons, "Применить на время сеанса", self.apply_keys).pack(
            side="left"
        )
        self._button(buttons, "Забыть ключи сеанса", self.forget_keys).pack(
            side="left", padx=(8, 0)
        )

    def apply_keys(self) -> None:
        applied = 0
        for env_name, variable in self.key_vars.items():
            value = variable.get().strip()
            if not value:
                continue
            os.environ[env_name] = value
            self.session_keys.add(env_name)
            variable.set("")
            applied += 1

        for env_name, status in self.key_status_vars.items():
            status.set(self._key_status(env_name))

        if applied:
            self.key_message_var.set("Ключ принят и действует до закрытия программы.")
            self.recolor(self.key_message, fg="GREEN")
        else:
            self.key_message_var.set("Введите ключ в одно из полей.")
            self.recolor(self.key_message, fg="MUTED")

    def forget_keys(self) -> None:
        for env_name in list(self.session_keys):
            original = self.original_keys.get(env_name)
            if original is None:
                os.environ.pop(env_name, None)
            else:
                os.environ[env_name] = original
        self.session_keys.clear()

        for env_name, status in self.key_status_vars.items():
            status.set(self._key_status(env_name))

        self.key_message_var.set("Ключи, введённые в этом сеансе, забыты.")
        self.recolor(self.key_message, fg="MUTED")

    def _tab_theme(self, page: tk.Frame) -> None:
        self._heading(
            page,
            "Оформление",
            "Тёмная тема включена по умолчанию. Выбор действует до закрытия "
            "программы.",
        )
        for value, title in (("dark", "Тёмная (по умолчанию)"), ("light", "Светлая")):
            radio = tk.Radiobutton(
                page,
                text=title,
                value=value,
                variable=self.theme_var,
                command=lambda name=value: self.set_theme(name),
                anchor="w",
                font=(FONT, 10),
                relief="flat",
                bd=0,
                highlightthickness=0,
            )
            self.themed(
                radio,
                bg="PANEL",
                fg="TEXT",
                selectcolor="PANEL2",
                activebackground="PANEL",
                activeforeground="TEXT",
            )
            radio.pack(anchor="w", padx=18, pady=3)

    def _tab_about(self, page: tk.Frame) -> None:
        self._heading(
            page,
            f"Phishing Checker {__version__}",
            "Бесплатный open-source инструмент для первичной проверки "
            "подозрительных ссылок. Лицензия: MIT.",
        )

        points = (
            ("Что делает: разбирает адрес, проверяет DNS, данные регистрации, "
            "сертификат, ответ сайта и содержимое страницы."),
            ("Чего не делает: не выполняет JavaScript, не вводит и не "
            "отправляет пароли, cookies и токены, делает один запрос GET."),
            ("Важно: низкая риск-оценка не гарантирует безопасность сайта. "
            "Сбои сети и лимиты API не считаются признаком фишинга."),
        )
        for point in points:
            self._label(
                page,
                point,
                justify="left",
                wraplength=520,
                anchor="w",
            ).pack(anchor="w", padx=18, pady=(0, 8))

        self._label(page, PROJECT_URL, fg="ACCENT", font=(FONT, 9)).pack(
            anchor="w", padx=18, pady=(6, 0)
        )
        self._button(page, "Скопировать ссылку на проект", self.copy_project_url).pack(
            anchor="w", padx=18, pady=10
        )

    def copy_project_url(self) -> None:
        self.root.clipboard_clear()
        self.root.clipboard_append(PROJECT_URL)
        self.status_var.set("Ссылка на проект скопирована")


def run_gui() -> None:
    """Start the graphical interface."""
    root = tk.Tk()
    _App(root)
    root.mainloop()


if __name__ == "__main__":
    run_gui()
