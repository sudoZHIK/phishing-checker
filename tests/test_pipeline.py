"""Integration tests for the URL analysis pipeline."""

from unittest.mock import patch

from phishing_checker.analyzer import analyze
from phishing_checker.dns import DNSReport, DNSResult
from phishing_checker.rdap import RDAPReport


def test_no_fetch_runs_local_analysis_only() -> None:
    report = analyze(
        "https://example.com",
        fetch_dns=False,
    )

    assert report.risk_score == 0
    assert report.risk_level == "LOW"

    assert report.coverage.passed == 1
    assert report.coverage.total == 8
    assert report.coverage.status == "PARTIAL"

    assert report.evidence == []
    assert report.errors == []


@patch("phishing_checker.rdap.lookup_url_rdap")
@patch("phishing_checker.dns.lookup_url_dns")
def test_dns_success_contributes_to_coverage(mock_dns, mock_rdap) -> None:
    mock_rdap.return_value = RDAPReport(
        hostname="example.com",
        hostname_ascii="example.com",
        checked=False,
    )

    mock_dns.return_value = DNSReport(
        hostname="example.com",
        hostname_ascii="example.com",
        results=(
            DNSResult(
                record_type="A",
                answers=("192.0.2.1",),
                success=True,
            ),
            DNSResult(
                record_type="AAAA",
                answers=("2001:db8::1",),
                success=True,
            ),
        ),
    )

    report = analyze("https://example.com")

    assert report.coverage.passed == 2
    assert report.coverage.total == 8
    assert report.coverage.status == "PARTIAL"
    assert report.errors == []


@patch("phishing_checker.rdap.lookup_url_rdap")
@patch("phishing_checker.dns.lookup_url_dns")
def test_dns_failure_reduces_coverage_without_increasing_risk(mock_dns, mock_rdap) -> None:
    mock_rdap.return_value = RDAPReport(
        hostname="example.com",
        hostname_ascii="example.com",
        checked=False,
    )

    mock_dns.return_value = DNSReport(
        hostname="example.com",
        hostname_ascii="example.com",
        results=(
            DNSResult(
                record_type="A",
                answers=(),
                success=False,
                error="DNS-over-HTTPS request failed: timeout",
            ),
            DNSResult(
                record_type="AAAA",
                answers=(),
                success=False,
                error="DNS-over-HTTPS request failed: timeout",
            ),
        ),
    )

    report = analyze("https://example.com")

    assert report.coverage.passed == 1
    assert report.coverage.total == 8
    assert report.coverage.status == "PARTIAL"

    assert report.risk_score == 0
    assert report.risk_level == "LOW"

    assert len(report.errors) == 2
    assert "DNS A:" in report.errors[0]
    assert "DNS AAAA:" in report.errors[1]


@patch("phishing_checker.rdap.lookup_url_rdap")
@patch("phishing_checker.dns.lookup_url_dns")
def test_local_high_confidence_signal_survives_low_coverage(mock_dns, mock_rdap) -> None:
    mock_rdap.return_value = RDAPReport(
        hostname="192.0.2.10",
        hostname_ascii="192.0.2.10",
        checked=False,
        error="RDAP intentionally disabled in local signal test",
    )

    mock_dns.return_value = DNSReport(
        hostname="192.0.2.10",
        hostname_ascii="192.0.2.10",
        results=(
            DNSResult(
                record_type="A",
                answers=(),
                success=False,
                error="timeout",
            ),
            DNSResult(
                record_type="AAAA",
                answers=(),
                success=False,
                error="timeout",
            ),
        ),
    )

    report = analyze("https://192.0.2.10/login")

    assert report.coverage.passed == 1
    assert report.coverage.total == 8
    assert report.coverage.status == "PARTIAL"

    assert any(item.code == "IP_HOST" for item in report.evidence)
    assert any(item.code == "CREDENTIAL_PATH" for item in report.evidence)

    # IP_HOST is an explicit high-confidence local signal.
    assert report.risk_score == 43
    assert report.risk_level == "SUSPICIOUS"


@patch("phishing_checker.rdap.lookup_url_rdap")
@patch("phishing_checker.dns.lookup_url_dns")
def test_dns_is_called_with_normalized_url(mock_dns, mock_rdap) -> None:
    mock_rdap.return_value = RDAPReport(
        hostname="пример.рф",
        hostname_ascii="xn--e1afmkfd.xn--p1ai",
        checked=False,
    )

    mock_dns.return_value = DNSReport(
        hostname="пример.рф",
        hostname_ascii="xn--e1afmkfd.xn--p1ai",
        results=(
            DNSResult(
                record_type="A",
                answers=("192.0.2.20",),
                success=True,
            ),
        ),
    )

    report = analyze("пример.рф", fetch_dns=True)

    assert report.coverage.passed == 2
    assert report.coverage.total == 8

    mock_dns.assert_called_once()
    called_url = mock_dns.call_args.args[0]

    assert called_url == "https://xn--e1afmkfd.xn--p1ai/"


def test_invalid_url_is_reported_without_exception() -> None:
    report = analyze("not a valid URL with spaces")

    assert report.coverage.passed == 0
    assert report.coverage.total == 8
    assert report.coverage.status == "PARTIAL"
    assert report.risk_score == 0
    assert report.errors


def test_report_is_json_serializable() -> None:
    report = analyze(
        "https://example.com",
        fetch_dns=False,
    )

    data = report.to_dict()

    assert data["schema_version"] == "1.0"
    assert data["risk_score"] == 0
    assert data["risk_level"] == "LOW"
    assert data["coverage"]["status"] == "PARTIAL"
    assert isinstance(data["evidence"], list)
    assert isinstance(data["errors"], list)
