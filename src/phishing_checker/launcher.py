"""Точка входа для бинарников: без аргументов окно, с аргументами CLI."""

from __future__ import annotations

import sys


def launch(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv

    if not args:
        from .gui import run_gui

        run_gui()
        return 0

    from .cli import main

    return main(args)
