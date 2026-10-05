"""Tkinter GUI for Phishing Checker."""

from __future__ import annotations

import json
import logging
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from . import __version__
from .analyzer import analyze
from .models import AnalysisReport

LOGGER = logging.getLogger(__name__)


BG = "#101114"
PANEL = "#181a1f"
PANEL2 = "#20232a"
BORDER = "#2d3038"
TEXT = "#f2f3f5"
MUTED = "#9298a3"
ACCENT = "#6ea8fe"
GREEN = "#55d187"
YELLOW = "#e5b95c"
RED = "#ef6b73"


def _risk_color(score: int) -> str:
    if score >= 70:
        return RED
    if score >= 20:
        return YELLOW
    return GREEN


def _risk_title(level: str) -> str:
    return {
        "LOW": "НИЗКИЙ РИСК",
        "CAUTION": "ОСТОРОЖНО",
        "SUSPICIOUS": "ПОДОЗРИТЕЛЬНО",
        "HIGH": "ВЫСОКИЙ РИСК",
    }.get(level, "НЕ ОПРЕДЕЛЁН")


def _coverage_status(status: str) -> str:
    return {
        "COMPLETE": "ПОЛНАЯ",
        "PARTIAL": "ПРОВЕРКА НЕПОЛНАЯ",
        "NOT_CHECKED": "НЕ ПРОВЕРЕНО",
    }.get(status, status)


def _evidence_text(report: AnalysisReport) -> str:
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
    payload = report.to_dict()

    document = {
        "tool": "Phishing Checker",
        "version": __version__,
        "input_url": url,
        "report": payload,
    }

    return json.dumps(
        document,
        ensure_ascii=False,
        indent=2,
    )


def _json_text(report: AnalysisReport) -> str:
    return json.dumps(
        report.to_dict(),
        ensure_ascii=False,
        indent=2,
    )


def run_gui() -> None:
    """Start the graphical interface."""

    root = tk.Tk()
    root.title("Phishing Checker")
    root.geometry("980x760")
    root.minsize(780, 620)
    root.configure(bg=BG)

    style = ttk.Style(root)
    style.theme_use("clam")

    style.configure(
        "Main.TButton",
        font=("DejaVu Sans", 10, "bold"),
        padding=(18, 10),
        background=PANEL2,
        foreground=TEXT,
        borderwidth=0,
    )
    style.map(
        "Main.TButton",
        background=[
            ("active", "#292d36"),
            ("disabled", "#17191d"),
        ],
        foreground=[
            ("disabled", "#666b75"),
        ],
    )

    style.configure(
        "Accent.TButton",
        font=("DejaVu Sans", 10, "bold"),
        padding=(22, 10),
        background=ACCENT,
        foreground="#0d1117",
        borderwidth=0,
    )
    style.map(
        "Accent.TButton",
        background=[
            ("active", "#8abaff"),
            ("disabled", "#39485e"),
        ],
    )

    style.configure(
        "Risk.Horizontal.TProgressbar",
        troughcolor=PANEL2,
        background=GREEN,
        bordercolor=PANEL2,
        lightcolor=GREEN,
        darkcolor=GREEN,
    )

    style.configure(
        "RiskYellow.Horizontal.TProgressbar",
        troughcolor=PANEL2,
        background=YELLOW,
        bordercolor=PANEL2,
        lightcolor=YELLOW,
        darkcolor=YELLOW,
    )

    style.configure(
        "RiskRed.Horizontal.TProgressbar",
        troughcolor=PANEL2,
        background=RED,
        bordercolor=PANEL2,
        lightcolor=RED,
        darkcolor=RED,
    )

    main = tk.Frame(root, bg=BG)
    main.pack(fill="both", expand=True, padx=24, pady=22)

    title = tk.Label(
        main,
        text="PHISHING CHECKER",
        bg=BG,
        fg=TEXT,
        font=("DejaVu Sans", 20, "bold"),
    )
    title.pack(anchor="w")

    subtitle = tk.Label(
        main,
        text=(
            "Локальная защитная проверка URL. "
            "Результат не является гарантией безопасности."
        ),
        bg=BG,
        fg=MUTED,
        font=("DejaVu Sans", 9),
    )
    subtitle.pack(anchor="w", pady=(2, 18))

    url_frame = tk.Frame(
        main,
        bg=PANEL,
        highlightbackground=BORDER,
        highlightthickness=1,
    )
    url_frame.pack(fill="x", pady=(0, 14))

    url_var = tk.StringVar()

    url_entry = tk.Entry(
        url_frame,
        textvariable=url_var,
        bg="#111318",
        fg=TEXT,
        insertbackground=TEXT,
        relief="flat",
        bd=0,
        font=("DejaVu Sans", 11),
    )
    url_entry.pack(
        side="left",
        fill="x",
        expand=True,
        padx=(14, 8),
        pady=13,
    )

    last_report: dict[str, AnalysisReport | None] = {"value": None}

    def paste_url() -> None:
        try:
            url_var.set(root.clipboard_get().strip())
        except tk.TclError:
            pass
        url_entry.focus_set()

    paste_button = ttk.Button(
        url_frame,
        text="Вставить",
        style="Main.TButton",
        command=paste_url,
    )
    paste_button.pack(side="right", padx=(0, 8), pady=8)

    status_var = tk.StringVar(
        value="Введите ссылку и нажмите «ПРОВЕРИТЬ»"
    )
    verdict_var = tk.StringVar(value="ГОТОВ К ПРОВЕРКЕ")
    score_var = tk.StringVar(value="—")
    coverage_var = tk.StringVar(value="—")

    metrics = tk.Frame(main, bg=BG)
    metrics.pack(fill="x", pady=(0, 14))

    risk_panel = tk.Frame(
        metrics,
        bg=PANEL,
        highlightbackground=BORDER,
        highlightthickness=1,
    )
    risk_panel.pack(
        side="left",
        fill="both",
        expand=True,
        padx=(0, 7),
    )

    coverage_panel = tk.Frame(
        metrics,
        bg=PANEL,
        highlightbackground=BORDER,
        highlightthickness=1,
    )
    coverage_panel.pack(
        side="left",
        fill="both",
        expand=True,
        padx=(7, 0),
    )

    tk.Label(
        risk_panel,
        text="РИСК-ОЦЕНКА",
        bg=PANEL,
        fg=MUTED,
        font=("DejaVu Sans", 9, "bold"),
    ).pack(anchor="w", padx=18, pady=(14, 0))

    score_value = tk.Label(
        risk_panel,
        textvariable=score_var,
        bg=PANEL,
        fg=MUTED,
        font=("DejaVu Sans", 30, "bold"),
    )
    score_value.pack(anchor="w", padx=18)

    verdict_label = tk.Label(
        risk_panel,
        textvariable=verdict_var,
        bg=PANEL,
        fg=MUTED,
        font=("DejaVu Sans", 11, "bold"),
    )
    verdict_label.pack(anchor="w", padx=18, pady=(0, 14))

    risk_progress = ttk.Progressbar(
        risk_panel,
        maximum=100,
        mode="determinate",
        style="Risk.Horizontal.TProgressbar",
    )
    risk_progress.pack(fill="x", padx=18, pady=(0, 14))

    tk.Label(
        coverage_panel,
        text="ПОЛНОТА ПРОВЕРКИ",
        bg=PANEL,
        fg=MUTED,
        font=("DejaVu Sans", 9, "bold"),
    ).pack(anchor="w", padx=18, pady=(14, 0))

    coverage_value = tk.Label(
        coverage_panel,
        textvariable=coverage_var,
        bg=PANEL,
        fg=MUTED,
        font=("DejaVu Sans", 23, "bold"),
    )
    coverage_value.pack(anchor="w", padx=18, pady=(3, 0))

    tk.Label(
        coverage_panel,
        text="Количество успешно завершённых проверок",
        bg=PANEL,
        fg=MUTED,
        font=("DejaVu Sans", 9),
    ).pack(anchor="w", padx=18, pady=(0, 14))

    button_frame = tk.Frame(main, bg=BG)
    button_frame.pack(fill="x", pady=(0, 12))

    check_button = ttk.Button(
        button_frame,
        text="ПРОВЕРИТЬ",
        style="Accent.TButton",
    )
    check_button.pack(side="left")

    clear_button = ttk.Button(
        button_frame,
        text="Очистить",
        style="Main.TButton",
    )
    clear_button.pack(side="left", padx=(8, 0))

    details_button = ttk.Button(
        button_frame,
        text="ТЕХНИЧЕСКИЙ ОТЧЁТ",
        style="Main.TButton",
        state="disabled",
    )
    details_button.pack(side="left", padx=(8, 0))

    settings_button = ttk.Button(
        button_frame,
        text="Настройки",
        style="Main.TButton",
    )
    settings_button.pack(side="left", padx=(8, 0))

    copy_button = ttk.Button(
        button_frame,
        text="Копировать",
        style="Main.TButton",
        state="disabled",
    )
    copy_button.pack(side="right")

    export_button = ttk.Button(
        button_frame,
        text="Экспорт JSON",
        style="Main.TButton",
        state="disabled",
    )
    export_button.pack(side="right", padx=(0, 8))

    # --- Панель настроек (скрыта по умолчанию) ---
    settings_frame = tk.Frame(
        main,
        bg=PANEL,
        highlightbackground=BORDER,
        highlightthickness=1,
    )

    dns_timeout_var = tk.StringVar(value="3.0")
    rdap_timeout_var = tk.StringVar(value="5.0")
    connect_timeout_var = tk.StringVar(value="5.0")
    read_timeout_var = tk.StringVar(value="10.0")
    overall_timeout_var = tk.StringVar(value="30.0")
    max_redirects_var = tk.StringVar(value="10")

    def _make_setting_row(parent, label, var):
        row = tk.Frame(parent, bg=PANEL)
        row.pack(fill="x", padx=14, pady=3)
        tk.Label(
            row, text=label, bg=PANEL, fg=MUTED,
            font=("DejaVu Sans", 9), width=28, anchor="w",
        ).pack(side="left")
        tk.Entry(
            row, textvariable=var, bg=PANEL2, fg=TEXT,
            insertbackground=TEXT, relief="flat", bd=1,
            font=("DejaVu Sans", 9), width=8,
        ).pack(side="left")

    tk.Label(
        settings_frame, text="НАСТРОЙКИ СЕТИ",
        bg=PANEL, fg=ACCENT,
        font=("DejaVu Sans", 9, "bold"),
    ).pack(anchor="w", padx=14, pady=(10, 4))

    _make_setting_row(settings_frame, "DNS timeout (сек)", dns_timeout_var)
    _make_setting_row(settings_frame, "RDAP timeout (сек)", rdap_timeout_var)
    _make_setting_row(settings_frame, "HTTP connect timeout (сек)", connect_timeout_var)
    _make_setting_row(settings_frame, "HTTP read timeout (сек)", read_timeout_var)
    _make_setting_row(settings_frame, "HTTP overall timeout (сек)", overall_timeout_var)
    _make_setting_row(settings_frame, "HTTP max redirects", max_redirects_var)

    tk.Frame(settings_frame, bg=PANEL, height=8).pack()

    settings_visible = {"value": False}

    def toggle_settings():
        if settings_visible["value"]:
            settings_frame.pack_forget()
            settings_visible["value"] = False
            settings_button.configure(text="Настройки")
        else:
            settings_frame.pack(fill="x", pady=(0, 10))
            settings_visible["value"] = True
            settings_button.configure(text="Скрыть настройки")

    settings_button.configure(command=toggle_settings)
    # --- конец панели настроек ---

    progress = ttk.Progressbar(
        main,
        mode="indeterminate",
        style="Risk.Horizontal.TProgressbar",
    )

    result_panel = tk.Frame(
        main,
        bg=PANEL,
        highlightbackground=BORDER,
        highlightthickness=1,
    )
    result_panel.pack(fill="both", expand=True)

    result_text = tk.Text(
        result_panel,
        bg="#111318",
        fg=TEXT,
        insertbackground=TEXT,
        selectbackground="#3c5f91",
        selectforeground=TEXT,
        relief="flat",
        bd=0,
        wrap="word",
        font=("DejaVu Sans", 9),
        padx=16,
        pady=14,
    )
    result_text.pack(
        side="left",
        fill="both",
        expand=True,
        padx=(12, 0),
        pady=12,
    )

    scrollbar = ttk.Scrollbar(
        result_panel,
        orient="vertical",
        command=result_text.yview,
    )
    scrollbar.pack(
        side="right",
        fill="y",
        padx=(0, 12),
        pady=12,
    )
    result_text.configure(yscrollcommand=scrollbar.set)

    result_text.tag_configure(
        "heading",
        foreground=ACCENT,
        font=("DejaVu Sans", 10, "bold"),
    )
    result_text.tag_configure(
        "green",
        foreground=GREEN,
    )
    result_text.tag_configure(
        "yellow",
        foreground=YELLOW,
    )
    result_text.tag_configure(
        "red",
        foreground=RED,
    )
    result_text.tag_configure(
        "muted",
        foreground=MUTED,
    )

    def set_text(text: str) -> None:
        result_text.configure(state="normal")
        result_text.delete("1.0", "end")

        for line in text.splitlines():
            stripped = line.strip()

            if stripped in (
                "ОБНАРУЖЕННЫЕ ПРИЗНАКИ",
                "ОШИБКИ / НЕПОЛНЫЕ ПРОВЕРКИ",
                "РЕКОМЕНДАЦИЯ",
            ):
                tag = "heading"
            elif stripped.startswith("✓"):
                tag = "green"
            elif stripped.startswith("⚠"):
                tag = "yellow"
            elif stripped.startswith("✕"):
                tag = "red"
            else:
                tag = None

            result_text.insert(
                "end",
                line + "\n",
                tag or "",
            )

        result_text.configure(state="disabled")

    def set_verdict(report: AnalysisReport) -> None:
        score = int(report.risk_score)
        color = _risk_color(score)

        score_var.set(f"{score}/100")
        verdict_var.set(_risk_title(report.risk_level))

        coverage = report.coverage
        coverage_var.set(
            f"{coverage.passed}/{coverage.total} — "
            f"{coverage.percent:.0f}%\n"
            f"{_coverage_status(coverage.status)}"
        )

        score_value.configure(foreground=color)
        verdict_label.configure(foreground=color)
        coverage_value.configure(
            foreground=GREEN
            if coverage.status == "COMPLETE"
            else YELLOW
            if coverage.status == "PARTIAL"
            else MUTED
        )

        risk_progress["value"] = max(
            0,
            min(100, score),
        )

        if score >= 70:
            risk_progress.configure(
                style="RiskRed.Horizontal.TProgressbar"
            )
        elif score >= 20:
            risk_progress.configure(
                style="RiskYellow.Horizontal.TProgressbar"
            )
        else:
            risk_progress.configure(
                style="Risk.Horizontal.TProgressbar"
            )

    def check_done(
        report: AnalysisReport | None = None,
        error: Exception | None = None,
    ) -> None:
        progress.stop()
        progress.pack_forget()

        check_button.configure(state="normal")
        clear_button.configure(state="normal")
        paste_button.configure(state="normal")
        url_entry.configure(state="normal")

        if error is not None:
            status_var.set("Ошибка проверки")
            verdict_var.set("ОШИБКА")
            score_var.set("—")
            coverage_var.set("—")
            score_value.configure(foreground=RED)
            verdict_label.configure(foreground=RED)
            set_text(
                "Не удалось выполнить проверку.\n\n"
                f"{error}"
            )
            details_button.configure(state="disabled")
            copy_button.configure(state="disabled")
            export_button.configure(state="disabled")
            return

        if report is None:
            return

        last_report["value"] = report

        status_var.set("Проверка завершена")
        details_button.configure(state="normal")
        copy_button.configure(state="normal")
        export_button.configure(state="normal")

        set_verdict(report)
        set_text(_evidence_text(report))

    def worker(url: str) -> None:
        try:
            report = analyze(
                url,
                fetch_dns=True,
                dns_timeout=float(dns_timeout_var.get()),
                rdap_timeout=float(rdap_timeout_var.get()),
                fetch_http=True,
                http_connect_timeout=float(connect_timeout_var.get()),
                http_read_timeout=float(read_timeout_var.get()),
                http_overall_timeout=float(overall_timeout_var.get()),
                http_max_redirects=int(max_redirects_var.get()),
                allow_private=False,
            )
            root.after(
                0,
                lambda: check_done(report=report),
            )
        except Exception as exc:
            LOGGER.exception("GUI analysis failed")
            root.after(
                0,
                lambda error=exc: check_done(error=error),
            )

    def start_check(event=None) -> str:
        url = url_var.get().strip()

        if not url:
            status_var.set("Введите ссылку")
            url_entry.focus_set()
            return "break"

        check_button.configure(state="disabled")
        clear_button.configure(state="disabled")
        paste_button.configure(state="disabled")
        details_button.configure(state="disabled")
        copy_button.configure(state="disabled")
        export_button.configure(state="disabled")
        url_entry.configure(state="disabled")

        status_var.set("Выполняется проверка…")
        verdict_var.set("ИДЁТ ПРОВЕРКА")
        score_var.set("—")
        coverage_var.set("—")
        score_value.configure(foreground=ACCENT)
        verdict_label.configure(foreground=ACCENT)
        risk_progress["value"] = 0

        set_text(
            "Выполняется анализ ссылки.\n\n"
            "Проверяется локальная структура URL "
            "и доступные сетевые проверки.\n\n"
            "Окно не зависло — анализ выполняется "
            "в отдельном потоке."
        )

        progress.pack(
            fill="x",
            pady=(0, 10),
        )
        progress.start(12)

        threading.Thread(
            target=worker,
            args=(url,),
            daemon=True,
        ).start()

        return "break"

    def clear() -> None:
        last_report["value"] = None
        url_var.set("")
        status_var.set("Введите ссылку и нажмите «ПРОВЕРИТЬ»")
        verdict_var.set("ГОТОВ К ПРОВЕРКЕ")
        score_var.set("—")
        coverage_var.set("—")
        score_value.configure(foreground=MUTED)
        verdict_label.configure(foreground=MUTED)
        coverage_value.configure(foreground=MUTED)
        risk_progress["value"] = 0

        details_button.configure(state="disabled")
        copy_button.configure(state="disabled")
        export_button.configure(state="disabled")

        set_text(
            "Результат проверки появится здесь.\n\n"
            "Вставьте ссылку на сайт в поле выше."
        )

        url_entry.focus_set()

    def show_details() -> None:
        report = last_report["value"]
        if report is None:
            return

        set_text(
            "ТЕХНИЧЕСКИЙ ОТЧЁТ\n\n"
            + _technical_text(
                report,
                url_var.get().strip(),
            )
        )

    def copy_report() -> None:
        report = last_report["value"]
        if report is None:
            return

        root.clipboard_clear()
        root.clipboard_append(
            _technical_text(
                report,
                url_var.get().strip(),
            )
        )
        root.update()
        status_var.set("Технический отчёт скопирован")

    def export_json() -> None:
        report = last_report["value"]
        if report is None:
            return

        path = filedialog.asksaveasfilename(
            title="Сохранить JSON-отчёт",
            defaultextension=".json",
            filetypes=[
                ("JSON", "*.json"),
                ("Все файлы", "*.*"),
            ],
        )

        if not path:
            return

        try:
            with open(
                path,
                "w",
                encoding="utf-8",
            ) as handle:
                handle.write(_json_text(report))
        except OSError as exc:
            messagebox.showerror(
                "Ошибка экспорта",
                str(exc),
            )
            return

        status_var.set(f"JSON сохранён: {path}")

    check_button.configure(command=start_check)
    clear_button.configure(command=clear)
    details_button.configure(command=show_details)
    copy_button.configure(command=copy_report)
    export_button.configure(command=export_json)

    url_entry.bind("<Return>", start_check)

    status_label = tk.Label(
        main,
        textvariable=status_var,
        bg=BG,
        fg=MUTED,
        anchor="w",
        font=("DejaVu Sans", 9),
    )
    status_label.pack(
        fill="x",
        pady=(8, 0),
    )

    set_text(
        "Результат проверки появится здесь.\n\n"
        "Вставьте ссылку на сайт в поле выше."
    )

    url_entry.focus_set()
    root.protocol("WM_DELETE_WINDOW", root.destroy)
    root.mainloop()


if __name__ == "__main__":
    run_gui()
