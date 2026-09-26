from __future__ import annotations

import socket
from typing import ClassVar

import pytest
import requests

from phishing_checker.http import (
    USER_AGENT,
    HTTPReport,
    HTTPSSRFBlocked,
    ResolvedAddress,
    _resolve_destination,
    fetch_url,
)


def test_private_ipv4_is_blocked_by_default():
    with pytest.raises(HTTPSSRFBlocked):
        _resolve_destination(
            "127.0.0.1",
            port=80,
            allow_private=False,
        )


def test_private_ipv4_allowed_explicitly():
    result = _resolve_destination(
        "127.0.0.1",
        port=80,
        allow_private=True,
    )

    assert result
    assert result[0].ip == "127.0.0.1"


def test_private_ipv6_is_blocked_by_default():
    with pytest.raises(HTTPSSRFBlocked):
        _resolve_destination(
            "::1",
            port=80,
            allow_private=False,
        )


def test_public_ip_is_allowed():
    result = _resolve_destination(
        "8.8.8.8",
        port=443,
        allow_private=False,
    )

    assert result[0].ip == "8.8.8.8"


def test_fetch_invalid_url_does_not_raise():
    report = fetch_url("not a valid url ://")

    assert isinstance(report, HTTPReport)
    assert report.checked is False
    assert report.error


def test_fetch_private_url_is_blocked_before_network():
    report = fetch_url("http://127.0.0.1:8080/")

    assert report.checked is False
    assert report.blocked is True
    assert "непубличный IP" in (report.error or "")


def test_fetch_private_url_allowed_does_not_fail_for_ssrf_reason(monkeypatch):
    calls = []

    def fake_get(self, url, **kwargs):
        calls.append((url, kwargs))
        raise requests.exceptions.ConnectionError("test connection")

    monkeypatch.setattr(requests.Session, "get", fake_get)

    report = fetch_url(
        "http://127.0.0.1:8080/",
        allow_private=True,
    )

    assert report.checked is False
    assert report.blocked is False
    assert "ConnectionError" in (report.error or "")
    assert calls


def test_user_agent_is_project_specific():
    assert USER_AGENT.startswith("PhishingChecker/0.1.0 ")
    assert "+https://" in USER_AGENT


def test_redirect_limit_validation():
    with pytest.raises(ValueError):
        fetch_url(
            "http://127.0.0.1:80/",
            max_redirects=-1,
        )


def test_timeout_validation():
    with pytest.raises(ValueError):
        fetch_url(
            "http://127.0.0.1:80/",
            connect_timeout=0,
        )

    with pytest.raises(ValueError):
        fetch_url(
            "http://127.0.0.1:80/",
            read_timeout=-1,
        )

    with pytest.raises(ValueError):
        fetch_url(
            "http://127.0.0.1:80/",
            overall_timeout=0,
        )


def test_resolution_error_is_reported(monkeypatch):
    def fake_getaddrinfo(*args, **kwargs):
        raise socket.gaierror("temporary failure")

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)

    report = fetch_url(
        "https://example.com/",
    )

    assert report.checked is False
    assert report.blocked is False
    assert "DNS" in (report.error or "")


def test_redirect_to_private_ip_is_blocked(monkeypatch):
    class FakeResponse:
        status_code = 302
        headers: ClassVar[dict[str, str]] = {
            "Location": "http://127.0.0.1:8080/private"
        }
        is_redirect = True

        def close(self):
            pass

    def fake_get(self, url, **kwargs):
        return FakeResponse()

    monkeypatch.setattr(requests.Session, "get", fake_get)

    report = fetch_url(
        "https://example.com/",
    )

    assert report.checked is False
    assert report.blocked is True
    assert "непубличный IP" in (report.error or "")


def test_redirect_is_resolved_again(monkeypatch):
    calls = []

    def fake_resolve(hostname, *, port, allow_private):
        calls.append(hostname)

        if len(calls) == 1:
            return [
                ResolvedAddress(
                    hostname=hostname,
                    ip="93.184.216.34",
                    family=socket.AF_INET,
                )
            ]

        return [
            ResolvedAddress(
                hostname=hostname,
                ip="93.184.216.35",
                family=socket.AF_INET,
            )
        ]

    class FakeRaw:
        decode_content = False

        def __init__(self):
            self._done = False

        def read(self, size):
            if self._done:
                return b""
            self._done = True
            return b"OK"

    class FakeResponse:
        def __init__(self, status_code, location=None):
            self.status_code = status_code
            self.headers = {}
            self.is_redirect = location is not None
            self.raw = FakeRaw()

            if location:
                self.headers["Location"] = location

        def close(self):
            pass

    responses = [
        FakeResponse(302, "https://redirect.example/next"),
        FakeResponse(200),
    ]

    def fake_get(self, url, **kwargs):
        assert kwargs["allow_redirects"] is False
        return responses.pop(0)

    monkeypatch.setattr(
        "phishing_checker.http._resolve_destination",
        fake_resolve,
    )
    monkeypatch.setattr(requests.Session, "get", fake_get)

    report = fetch_url("https://example.com/")

    assert report.checked is True
    assert report.redirects == 1
    assert calls[0] == "example.com"
    assert calls.count("redirect.example") >= 2


def test_redirect_resolution_failure_blocks_chain(monkeypatch):
    calls = []

    def fake_resolve(hostname, *, port, allow_private):
        calls.append(hostname)

        if hostname == "example.com":
            return [
                ResolvedAddress(
                    hostname=hostname,
                    ip="93.184.216.34",
                    family=socket.AF_INET,
                )
            ]

        raise HTTPSSRFBlocked(
            "HTTP-запрос заблокирован: непубличный IP 127.0.0.1"
        )

    class FakeResponse:
        status_code = 302
        headers: ClassVar[dict[str, str]] = {
            "Location": "http://internal.example/"
        }
        is_redirect = True

        def close(self):
            pass

    def fake_get(self, url, **kwargs):
        return FakeResponse()

    monkeypatch.setattr(
        "phishing_checker.http._resolve_destination",
        fake_resolve,
    )
    monkeypatch.setattr(requests.Session, "get", fake_get)

    report = fetch_url("https://example.com/")

    assert report.checked is False
    assert report.blocked is True
    assert calls == ["example.com", "internal.example"]


def test_max_redirects_zero_does_not_follow_redirect(monkeypatch):
    class FakeResponse:
        status_code = 302
        headers: ClassVar[dict[str, str]] = {
            "Location": "https://redirect.example/"
        }
        is_redirect = True

        def close(self):
            pass

    calls = []

    def fake_get(self, url, **kwargs):
        calls.append(url)
        return FakeResponse()

    monkeypatch.setattr(requests.Session, "get", fake_get)

    report = fetch_url(
        "https://example.com/",
        max_redirects=0,
    )

    assert report.checked is False
    assert report.blocked is False
    assert report.redirects == 0
    assert "лимит редиректов" in (report.error or "")
    assert calls == ["https://example.com/"]


def test_body_size_limit_is_enforced(monkeypatch):
    class FakeRaw:
        decode_content = False

        def read(self, size):
            return b"x" * 101

    class FakeResponse:
        status_code = 200
        headers: ClassVar[dict[str, str]] = {}
        is_redirect = False
        raw = FakeRaw()

        def close(self):
            pass

    def fake_get(self, url, **kwargs):
        return FakeResponse()

    monkeypatch.setattr(requests.Session, "get", fake_get)

    report = fetch_url(
        "https://example.com/",
        max_body_bytes=100,
    )

    assert report.checked is False
    assert "превышает лимит" in (report.error or "")


def test_content_length_over_limit_is_rejected(monkeypatch):
    class FakeRaw:
        decode_content = False

        def read(self, size):
            raise AssertionError(
                "body не должен читаться при заведомо большом Content-Length"
            )

    class FakeResponse:
        status_code = 200
        headers: ClassVar[dict[str, str]] = {
            "Content-Length": "1001"
        }
        is_redirect = False
        raw = FakeRaw()

        def close(self):
            pass

    def fake_get(self, url, **kwargs):
        return FakeResponse()

    monkeypatch.setattr(requests.Session, "get", fake_get)

    report = fetch_url(
        "https://example.com/",
        max_body_bytes=1000,
    )

    assert report.checked is False
    assert "превышает лимит" in (report.error or "")


def test_session_does_not_use_environment_proxy(monkeypatch):
    captured = {}

    class FakeResponse:
        status_code = 200
        headers: ClassVar[dict[str, str]] = {}
        is_redirect = False

        class Raw:
            decode_content = False

            def __init__(self):
                self._done = False

            def read(self, size):
                if self._done:
                    return b""
                self._done = True
                return b"OK"

        raw = Raw()

        def close(self):
            pass

    def fake_get(self, url, **kwargs):
        captured["trust_env"] = self.trust_env
        return FakeResponse()

    monkeypatch.setattr(
        "phishing_checker.http._resolve_destination",
        lambda hostname, *, port, allow_private: [
            ResolvedAddress(
                hostname=hostname,
                ip="93.184.216.34",
                family=socket.AF_INET,
            )
        ],
    )
    monkeypatch.setattr(requests.Session, "get", fake_get)

    report = fetch_url("https://example.com/")

    assert report.checked is True
    assert captured["trust_env"] is False


def test_user_agent_is_sent_by_session(monkeypatch):
    captured = {}

    class FakeResponse:
        status_code = 200
        headers: ClassVar[dict[str, str]] = {}
        is_redirect = False

        class Raw:
            decode_content = False

            def __init__(self):
                self._done = False

            def read(self, size):
                if self._done:
                    return b""
                self._done = True
                return b"OK"

        raw = Raw()

        def close(self):
            pass

    def fake_get(self, url, **kwargs):
        captured["user_agent"] = self.headers["User-Agent"]
        return FakeResponse()

    monkeypatch.setattr(
        "phishing_checker.http._resolve_destination",
        lambda hostname, *, port, allow_private: [
            ResolvedAddress(
                hostname=hostname,
                ip="93.184.216.34",
                family=socket.AF_INET,
            )
        ],
    )
    monkeypatch.setattr(requests.Session, "get", fake_get)

    report = fetch_url("https://example.com/")

    assert report.checked is True
    assert captured["user_agent"] == USER_AGENT
