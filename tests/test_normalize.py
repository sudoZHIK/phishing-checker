"""Focused normalization tests required by the project specification."""

import pytest

from phishing_checker.analyzer import normalize_url


def test_normalize_is_deterministic() -> None:
    first = normalize_url("Example.COM/path")
    second = normalize_url("Example.COM/path")
    assert first.normalized == second.normalized
    assert first.hostname_ascii == "example.com"


def test_normalize_exposes_idn_forms() -> None:
    result = normalize_url("пример.рф")
    assert result.hostname_unicode == "пример.рф"
    assert result.hostname_ascii == "xn--e1afmkfd.xn--p1ai"


def test_normalize_does_not_preserve_userinfo() -> None:
    result = normalize_url("https://user:secret@example.com/login")
    assert result.has_userinfo is True
    assert "secret" not in result.normalized


def test_normalize_rejects_unsupported_scheme() -> None:
    with pytest.raises(ValueError):
        normalize_url("ftp://example.com")
