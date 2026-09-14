"""Unit tests for DNS-over-HTTPS analysis."""

from unittest.mock import Mock, patch

import pytest

from phishing_checker.dns import DNSReport, DNSResult, lookup_dns, lookup_url_dns


def test_dns_result_is_serializable() -> None:
    result = DNSResult(
        record_type="A",
        answers=("192.0.2.1",),
        success=True,
        server="https://dns.example.test/resolve",
    )

    assert result.checked is True


def test_dns_report_tracks_coverage() -> None:
    report = DNSReport(
        hostname="example.com",
        hostname_ascii="example.com",
        results=(
            DNSResult("A", ("192.0.2.1",), True),
            DNSResult("AAAA", (), False, "timeout"),
        ),
    )

    assert report.checked == 1
    assert report.total == 2
    assert report.complete is False

    data = report.to_dict()
    assert data["checked"] == 1
    assert data["total"] == 2
    assert data["complete"] is False


@patch("phishing_checker.dns.requests.get")
def test_lookup_dns_parses_doh_json(mock_get: Mock) -> None:
    response = Mock()
    response.raise_for_status.return_value = None
    response.json.return_value = {
        "Status": 0,
        "Answer": [
            {"type": 1, "data": "192.0.2.10"},
            {"type": 1, "data": "192.0.2.20"},
        ],
    }
    mock_get.return_value = response

    report = lookup_dns(
        "example.com",
        record_types=("A",),
        servers=("https://dns.example.test/resolve",),
    )

    assert report.complete is True
    assert report.results[0].answers == ("192.0.2.10", "192.0.2.20")

    mock_get.assert_called_once()
    assert mock_get.call_args.kwargs["params"]["name"] == "example.com"
    assert mock_get.call_args.kwargs["params"]["type"] == "A"
    assert mock_get.call_args.kwargs["timeout"] == 3.0


@patch("phishing_checker.dns.requests.get")
def test_dns_transport_failure_is_incomplete_not_evidence(mock_get: Mock) -> None:
    import requests

    mock_get.side_effect = requests.Timeout("timed out")

    report = lookup_dns(
        "example.com",
        record_types=("A",),
        servers=("https://dns.example.test/resolve",),
    )

    assert report.complete is False
    assert report.checked == 0
    assert report.total == 1
    assert report.results[0].answers == ()
    assert report.results[0].success is False
    assert "failed" in report.results[0].error.lower()


@patch("phishing_checker.dns.requests.get")
def test_dns_falls_back_to_second_server(mock_get: Mock) -> None:
    import requests

    first = Mock()
    first.side_effect = requests.ConnectionError("connection failed")

    second = Mock()
    second.raise_for_status.return_value = None
    second.json.return_value = {
        "Status": 0,
        "Answer": [{"type": 1, "data": "192.0.2.55"}],
    }

    mock_get.side_effect = [first, second]

    report = lookup_dns(
        "example.com",
        record_types=("A",),
        servers=(
            "https://first.example.test/resolve",
            "https://second.example.test/resolve",
        ),
    )

    assert report.complete is True
    assert report.results[0].answers == ("192.0.2.55",)
    assert report.results[0].server == "https://second.example.test/resolve"


@patch("phishing_checker.dns.requests.get")
def test_idn_is_sent_to_doh_as_punycode(mock_get: Mock) -> None:
    response = Mock()
    response.raise_for_status.return_value = None
    response.json.return_value = {
        "Status": 0,
        "Answer": [{"type": 1, "data": "192.0.2.77"}],
    }
    mock_get.return_value = response

    report = lookup_url_dns(
        "https://пример.рф/login",
        record_types=("A",),
        servers=("https://dns.example.test/resolve",),
    )

    assert report.hostname == "пример.рф"
    assert report.hostname_ascii == "xn--e1afmkfd.xn--p1ai"

    assert (
        mock_get.call_args.kwargs["params"]["name"]
        == "xn--e1afmkfd.xn--p1ai"
    )


@pytest.mark.parametrize(
    "hostname",
    ["", "   ", None],
)
def test_invalid_hostname_is_rejected(hostname: str | None) -> None:
    with pytest.raises((TypeError, ValueError)):
        lookup_dns(hostname)  # type: ignore[arg-type]


def test_invalid_record_type_is_rejected() -> None:
    with pytest.raises(ValueError):
        lookup_dns(
            "example.com",
            record_types=("TXT",),
            servers=("https://dns.example.test/resolve",),
        )


def test_invalid_timeout_is_rejected() -> None:
    with pytest.raises(ValueError):
        lookup_dns("example.com", timeout=0)


def test_empty_servers_produces_incomplete_checks() -> None:
    report = lookup_dns(
        "example.com",
        record_types=("A",),
        servers=(),
    )

    assert report.complete is False
    assert report.checked == 0
    assert report.total == 1
