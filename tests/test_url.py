"""Unit tests for deterministic URL normalization and local analysis."""

import pytest

from phishing_checker.analyzer import analyze_url, normalize_url


def test_https_url_is_normalized_deterministically() -> None:
    result = normalize_url("HTTPS://Example.COM/path?q=1")

    assert result.scheme == "https"
    assert result.hostname_unicode == "example.com"
    assert result.hostname_ascii == "example.com"
    assert result.port is None
    assert result.normalized == "https://example.com/path?q=1"

    again = normalize_url("HTTPS://Example.COM/path?q=1")
    assert result == again


def test_missing_scheme_defaults_to_https() -> None:
    result = normalize_url("example.com/login")

    assert result.scheme == "https"
    assert result.hostname_unicode == "example.com"
    assert result.hostname_ascii == "example.com"
    assert result.normalized == "https://example.com/login"


def test_standard_ports_are_preserved() -> None:
    http = normalize_url("http://example.com:80/")
    https = normalize_url("https://example.com:443/")

    assert http.port == 80
    assert https.port == 443
    assert http.normalized == "http://example.com:80/"
    assert https.normalized == "https://example.com:443/"


def test_non_standard_port_is_detected() -> None:
    result, evidence = analyze_url("https://example.com:8443/")

    assert result.port == 8443
    assert any(item.code == "NON_STANDARD_PORT" for item in evidence)


def test_userinfo_is_detected_without_leaking_credentials() -> None:
    result, evidence = analyze_url(
        "https://user:secret@example.com/login"
    )

    assert result.has_userinfo is True
    assert result.has_username is True
    assert result.has_password is True

    assert "user" not in result.normalized
    assert "secret" not in result.normalized
    assert "user" not in result.hostname_ascii
    assert "secret" not in result.hostname_ascii

    codes = {item.code for item in evidence}
    assert "AT_SIGN" in codes
    assert "CREDENTIAL_PATH" in codes


def test_ipv4_hostname_is_detected() -> None:
    result, evidence = analyze_url("http://192.168.1.10/login")

    assert result.is_ip is True
    assert result.ip_version == 4
    assert result.hostname_ascii == "192.168.1.10"
    assert any(item.code == "IP_HOST" for item in evidence)


def test_ipv6_hostname_is_detected() -> None:
    result = normalize_url("http://[2001:db8::1]:8080/test")

    assert result.is_ip is True
    assert result.ip_version == 6
    assert result.hostname_ascii == "2001:db8::1"
    assert result.port == 8080
    assert result.normalized == "http://[2001:db8::1]:8080/test"


def test_idn_has_unicode_and_punycode_forms() -> None:
    result, evidence = analyze_url("https://пример.рф/")

    assert result.hostname_unicode == "пример.рф"
    assert result.hostname_ascii == "xn--e1afmkfd.xn--p1ai"
    assert result.is_punycode is True
    assert result.normalized == "https://xn--e1afmkfd.xn--p1ai/"

    idn_evidence = next(
        item for item in evidence if item.code == "IDN_PUNYCODE"
    )

    assert idn_evidence.details["unicode"] == "пример.рф"
    assert idn_evidence.details["punycode"] == "xn--e1afmkfd.xn--p1ai"


def test_existing_punycode_is_normalized() -> None:
    result = normalize_url("https://XN--E1AFMKFD.XN--P1AI/")

    assert result.hostname_unicode == "пример.рф"
    assert result.hostname_ascii == "xn--e1afmkfd.xn--p1ai"
    assert result.is_punycode is True


def test_punycode_structure_does_not_trigger_many_hyphens() -> None:
    _, evidence = analyze_url("https://пример.рф/")

    codes = {item.code for item in evidence}

    assert "IDN_PUNYCODE" in codes
    assert "MANY_HYPHENS" not in codes


def test_trailing_hostname_dot_is_removed() -> None:
    result = normalize_url("https://Example.COM./")

    assert result.hostname_unicode == "example.com"
    assert result.hostname_ascii == "example.com"
    assert result.normalized == "https://example.com/"


def test_deep_subdomain_and_hyphens_are_detected() -> None:
    url = (
        "https://a.b.c.d.example----test.com/"
    )

    _, evidence = analyze_url(url)
    codes = {item.code for item in evidence}

    assert "DEEP_SUBDOMAIN" in codes
    assert "MANY_HYPHENS" in codes


def test_long_url_is_detected() -> None:
    url = "https://example.com/" + ("a" * 200)

    _, evidence = analyze_url(url)

    assert any(item.code == "LONG_URL" for item in evidence)


def test_security_related_path_is_detected() -> None:
    _, evidence = analyze_url(
        "https://example.com/account/verify"
    )

    assert any(item.code == "CREDENTIAL_PATH" for item in evidence)


@pytest.mark.parametrize(
    "url",
    [
        "",
        "   ",
        "ftp://example.com/file",
        "https:///missing-host",
        "https://example.com:0/",
        "https://example.com:65536/",
        "https://example.com:not-a-port/",
        "https://",
    ],
)
def test_invalid_urls_are_rejected(url: str) -> None:
    with pytest.raises((TypeError, ValueError)):
        normalize_url(url)
