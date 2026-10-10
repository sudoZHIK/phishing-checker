"""Tk-free helpers for the GUI: settings validation, layout math, shortcuts.

Kept separate from gui.py so that it can be unit-tested without a display.
"""

from __future__ import annotations

import math
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class NetworkSettings:
    """Network limits passed to analyze(). Defaults follow the specification."""

    dns_timeout: float = 3.0
    rdap_timeout: float = 5.0
    http_connect_timeout: float = 5.0
    http_read_timeout: float = 10.0
    http_overall_timeout: float = 30.0
    http_max_redirects: int = 10


DEFAULT_NETWORK = NetworkSettings()

MAX_TIMEOUT = 300.0
MAX_REDIRECTS = 20

# (field name, Russian label)
NETWORK_FIELDS: tuple[tuple[str, str], ...] = (
    ("dns_timeout", "DNS: таймаут, сек"),
    ("rdap_timeout", "RDAP: таймаут, сек"),
    ("http_connect_timeout", "HTTP: подключение, сек"),
    ("http_read_timeout", "HTTP: чтение, сек"),
    ("http_overall_timeout", "HTTP: общий таймаут, сек"),
    ("http_max_redirects", "HTTP: максимум редиректов"),
)


def parse_network_settings(raw: dict[str, str]) -> NetworkSettings:
    """Validate user input. Raises ValueError with a Russian message."""
    values: dict[str, float | int] = {}

    for name, label in NETWORK_FIELDS:
        text = str(raw.get(name, "")).strip().replace(",", ".")
        if not text:
            raise ValueError(f"Поле «{label}» не заполнено.")

        if name == "http_max_redirects":
            try:
                count = int(text)
            except ValueError:
                raise ValueError(f"Поле «{label}» должно быть целым числом.") from None
            if not 0 <= count <= MAX_REDIRECTS:
                raise ValueError(
                    f"Поле «{label}» должно быть от 0 до {MAX_REDIRECTS}."
                )
            values[name] = count
            continue

        try:
            number = float(text)
        except ValueError:
            raise ValueError(f"Поле «{label}» должно быть числом.") from None
        if not math.isfinite(number) or not 0 < number <= MAX_TIMEOUT:
            raise ValueError(
                f"Поле «{label}» должно быть больше 0 и не больше {MAX_TIMEOUT:g}."
            )
        values[name] = number

    return NetworkSettings(**values)


def flow_layout(widths: list[int], available: int, gap: int = 8) -> list[tuple[int, int]]:
    """(row, column) for each item of a left-aligned wrapping row.

    An item is never cut: if it does not fit, it moves to the next row.
    """
    positions: list[tuple[int, int]] = []
    row = 0
    column = 0
    used = 0

    for width in widths:
        need = width + (gap if column else 0)
        if column and used + need > available:
            row += 1
            column = 0
            used = 0
            need = width
        positions.append((row, column))
        column += 1
        used += need

    return positions


def flow_place(
    sizes: list[tuple[int, int]],
    available: int,
    gap_x: int = 8,
    gap_y: int = 6,
) -> tuple[list[tuple[int, int]], int]:
    """Absolute (x, y) of every item of a wrapping row, plus total height.

    ``sizes`` are (width, height) of the items. An item that does not fit is
    moved to the next row as a whole, so nothing is ever cut off.
    """
    cells = flow_layout([width for width, _height in sizes], available, gap_x)

    row_heights: dict[int, int] = {}
    for (row, _column), (_width, height) in zip(cells, sizes, strict=True):
        row_heights[row] = max(row_heights.get(row, 0), height)

    row_tops: dict[int, int] = {}
    top = 0
    for row in sorted(row_heights):
        row_tops[row] = top
        top += row_heights[row] + gap_y

    positions: list[tuple[int, int]] = []
    x = 0
    for index, (row, column) in enumerate(cells):
        if column == 0:
            x = 0
        positions.append((x, row_tops[row]))
        x += sizes[index][0] + gap_x

    total = max(top - gap_y, 0)
    return positions, total


def grid_columns(width: int, min_item: int, count: int, gap: int = 14) -> int:
    """How many equal columns of at least ``min_item`` fit into ``width``."""
    if count <= 0:
        return 1
    return max(1, min(count, (width + gap) // (min_item + gap)))


_X11_KEYCODES = {38: "select_all", 54: "copy", 55: "paste", 53: "cut"}
_WIN_KEYCODES = {65: "select_all", 67: "copy", 86: "paste", 88: "cut"}


def shortcut_action(keysym: str, keycode: int, windowing: str) -> str | None:
    """Map Ctrl+<key> to an edit action.

    Latin c/v/x are left to Tk (returns None). Ctrl+A is handled for every
    layout, because Tk on X11 maps it to "line start". For non-Latin layouts
    the physical key code is used, so Ctrl+С/В/Ч/Ф work in a Russian layout.
    """
    is_latin = len(keysym) == 1 and keysym.isascii() and keysym.isalpha()

    if is_latin:
        return "select_all" if keysym.lower() == "a" else None

    if windowing == "x11":
        return _X11_KEYCODES.get(keycode)
    if windowing == "win32":
        return _WIN_KEYCODES.get(keycode)
    return None
