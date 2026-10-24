"""Точка входа бинарников: без аргументов окно, с аргументами CLI."""

from __future__ import annotations

import json

import pytest

from phishing_checker.launcher import launch


def test_no_arguments_start_gui(monkeypatch):
    import phishing_checker.gui as gui

    calls = []
    monkeypatch.setattr(gui, "run_gui", lambda: calls.append("gui"))

    assert launch([]) == 0
    assert calls == ["gui"]


def test_arguments_go_to_cli(monkeypatch):
    import phishing_checker.cli as cli

    seen = {}

    def fake_main(argv=None):
        seen["argv"] = argv
        return 7

    monkeypatch.setattr(cli, "main", fake_main)

    assert launch(["https://example.com", "--json"]) == 7
    assert seen["argv"] == ["https://example.com", "--json"]


def test_help_exits_with_zero():
    with pytest.raises(SystemExit) as info:
        launch(["--help"])
    assert info.value.code == 0


def test_cli_json_without_network(capsys):
    assert launch(["https://example.com", "--no-fetch", "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["schema_version"] == "1.0"
