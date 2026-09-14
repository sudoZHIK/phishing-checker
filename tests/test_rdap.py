from unittest.mock import Mock, patch

import pytest
import requests

from phishing_checker.rdap import (
    lookup_rdap,
    lookup_url_rdap,
)


def make_response(status_code=200, data=None):
    response = Mock()
    response.status_code = status_code
    response.content = (
        b"{}"
        if data is None
        else __import__("json").dumps(data).encode("utf-8")
    )
    response.close = Mock()
    return response


def test_rdap_success():
    response = make_response(
        200,
        {
            "rdapConformance": ["rdap_level_0"],
            "events": [
                {
                    "eventAction": "registration",
                    "eventDate": "2020-01-01T00:00:00Z",
                }
            ],
            "nameservers": [
                {"ldhName": "ns1.example.com"},
                {"ldhName": "ns2.example.com"},
            ],
        },
    )

    with patch("phishing_checker.rdap.requests.get", return_value=response):
        report = lookup_rdap(
            "example.com",
            base_url="https://rdap.example.test/domain/",
        )

    assert report.checked is True
    assert report.status_code == 200
    assert report.hostname_ascii == "example.com"
    assert report.events == [
        {
            "action": "registration",
            "date": "2020-01-01T00:00:00Z",
        }
    ]
    assert report.nameservers == [
        "ns1.example.com",
        "ns2.example.com",
    ]


def test_rdap_404_is_checked_but_not_evidence():
    response = make_response(404)

    with patch("phishing_checker.rdap.requests.get", return_value=response):
        report = lookup_rdap(
            "missing.example",
            base_url="https://rdap.example.test/domain/",
        )

    assert report.checked is True
    assert report.status_code == 404
    assert report.error == "RDAP server reports domain not found"


def test_rdap_http_error_is_incomplete():
    response = make_response(500)

    with patch("phishing_checker.rdap.requests.get", return_value=response):
        report = lookup_rdap(
            "example.com",
            base_url="https://rdap.example.test/domain/",
        )

    assert report.checked is False
    assert report.status_code == 500
    assert report.error == "RDAP HTTP error: 500"


def test_rdap_network_error_is_incomplete():
    with patch(
        "phishing_checker.rdap.requests.get",
        side_effect=requests.RequestException("connection failed"),
    ):
        report = lookup_rdap(
            "example.com",
            base_url="https://rdap.example.test/domain/",
        )

    assert report.checked is False
    assert "RDAP network error" in report.error


def test_rdap_idn_is_converted_to_ascii():
    response = make_response(200, {})

    with patch(
        "phishing_checker.rdap.requests.get",
        return_value=response,
    ) as mock_get:
        report = lookup_rdap(
            "пример.рф",
            base_url="https://rdap.example.test/domain/",
        )

    assert report.checked is True
    assert report.hostname == "xn--e1afmkfd.xn--p1ai"
    assert report.hostname_ascii == "xn--e1afmkfd.xn--p1ai"

    requested_url = mock_get.call_args.args[0]
    assert requested_url.endswith(
        "/xn--e1afmkfd.xn--p1ai"
    )


def test_rdap_ip_is_not_checked():
    report = lookup_rdap("192.168.1.1")

    assert report.checked is False
    assert report.error == (
        "RDAP domain lookup is not applicable to IP addresses"
    )


def test_lookup_url_rdap_extracts_hostname():
    response = make_response(200, {})

    with patch(
        "phishing_checker.rdap.requests.get",
        return_value=response,
    ) as mock_get:
        report = lookup_url_rdap(
            "https://Example.COM/login",
            base_url="https://rdap.example.test/domain/",
        )

    assert report.checked is True
    assert report.hostname_ascii == "example.com"

    requested_url = mock_get.call_args.args[0]
    assert requested_url.endswith("/example.com")


def test_lookup_url_rdap_invalid_url():
    report = lookup_url_rdap("not a url")

    assert report.checked is False
    assert report.error is not None


def test_rdap_invalid_timeout():
    with pytest.raises(ValueError):
        lookup_rdap("example.com", timeout=0)


def test_rdap_empty_hostname():
    report = lookup_rdap("")

    assert report.checked is False
    assert report.error == "Hostname is empty"


def test_rdap_response_too_large():
    response = Mock()
    response.status_code = 200
    response.content = b"x" * 1_000_001
    response.close = Mock()

    with patch("phishing_checker.rdap.requests.get", return_value=response):
        report = lookup_rdap(
            "example.com",
            base_url="https://rdap.example.test/domain/",
        )

    assert report.checked is False
    assert report.error == "RDAP response is too large"


def test_rdap_serialization():
    response = make_response(
        200,
        {
            "events": [],
            "nameservers": [],
        },
    )

    with patch("phishing_checker.rdap.requests.get", return_value=response):
        report = lookup_rdap(
            "example.com",
            base_url="https://rdap.example.test/domain/",
        )

    data = report.to_dict()

    assert isinstance(data, dict)
    assert data["hostname_ascii"] == "example.com"
    assert data["checked"] is True
