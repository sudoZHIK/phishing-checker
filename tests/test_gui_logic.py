"""Чистая логика GUI: настройки, перенос кнопок, горячие клавиши. Без Tk."""

from __future__ import annotations

import pytest

from phishing_checker.gui_logic import (
    DEFAULT_NETWORK,
    NETWORK_FIELDS,
    flow_layout,
    flow_place,
    grid_columns,
    parse_network_settings,
    shortcut_action,
)


def _defaults() -> dict[str, str]:
    return {
        name: f"{getattr(DEFAULT_NETWORK, name):g}" for name, _label in NETWORK_FIELDS
    }


def test_defaults_match_specification():
    assert DEFAULT_NETWORK.dns_timeout == 3.0
    assert DEFAULT_NETWORK.http_connect_timeout == 5.0
    assert DEFAULT_NETWORK.http_read_timeout == 10.0
    assert DEFAULT_NETWORK.http_overall_timeout == 30.0
    assert DEFAULT_NETWORK.http_max_redirects == 10


def test_parse_defaults_roundtrip():
    assert parse_network_settings(_defaults()) == DEFAULT_NETWORK


def test_parse_accepts_comma_decimal():
    raw = _defaults() | {"dns_timeout": "2,5"}
    assert parse_network_settings(raw).dns_timeout == 2.5


@pytest.mark.parametrize("bad", ["", "abc", "0", "-1", "nan", "inf", "999"])
def test_parse_rejects_bad_timeouts(bad):
    with pytest.raises(ValueError):
        parse_network_settings(_defaults() | {"http_read_timeout": bad})


@pytest.mark.parametrize("bad", ["", "x", "1.5", "-1", "21"])
def test_parse_rejects_bad_redirects(bad):
    with pytest.raises(ValueError):
        parse_network_settings(_defaults() | {"http_max_redirects": bad})


def test_parse_allows_zero_redirects():
    raw = _defaults() | {"http_max_redirects": "0"}
    assert parse_network_settings(raw).http_max_redirects == 0


def test_flow_layout_wraps_whole_items():
    positions = flow_layout([100, 100, 100], available=250, gap=10)
    assert positions == [(0, 0), (0, 1), (1, 0)]


def test_flow_layout_single_row_when_wide_enough():
    assert flow_layout([100, 100], available=500) == [(0, 0), (0, 1)]


def test_flow_layout_empty():
    assert flow_layout([], available=100) == []


def test_flow_place_never_exceeds_available_width():
    sizes = [(140, 36), (100, 36), (210, 36), (90, 36), (110, 36), (120, 36), (130, 36)]
    for available in (300, 450, 600, 800, 1200):
        positions, _height = flow_place(sizes, available)
        for (x_pos, _y), (width, _h) in zip(positions, sizes, strict=True):
            assert x_pos + width <= max(available, width)


def test_flow_place_height_grows_with_rows():
    sizes = [(100, 30)] * 4
    _positions, one_row = flow_place(sizes, available=1000)
    _positions, two_rows = flow_place(sizes, available=250)
    assert one_row == 30
    assert two_rows == 30 * 2 + 6


def test_grid_columns():
    assert grid_columns(900, 320, 2) == 2
    assert grid_columns(500, 320, 2) == 1
    assert grid_columns(10, 320, 2) == 1
    assert grid_columns(900, 320, 0) == 1


def test_shortcut_latin_copy_paste_cut_left_to_tk():
    for key in ("c", "v", "x", "C", "V", "X"):
        assert shortcut_action(key, 54, "x11") is None


def test_shortcut_select_all_for_latin_and_cyrillic():
    assert shortcut_action("a", 38, "x11") == "select_all"
    assert shortcut_action("Cyrillic_ef", 38, "x11") == "select_all"


def test_shortcut_cyrillic_layout_x11():
    assert shortcut_action("Cyrillic_es", 54, "x11") == "copy"
    assert shortcut_action("Cyrillic_em", 55, "x11") == "paste"
    assert shortcut_action("Cyrillic_che", 53, "x11") == "cut"


def test_shortcut_cyrillic_layout_windows():
    assert shortcut_action("Cyrillic_es", 67, "win32") == "copy"
    assert shortcut_action("Cyrillic_em", 86, "win32") == "paste"


def test_shortcut_unknown_platform_or_key():
    assert shortcut_action("Cyrillic_es", 54, "aqua") is None
    assert shortcut_action("Cyrillic_es", 99, "x11") is None
