"""Результаты отдельных проверок. Без сети."""

from __future__ import annotations

from types import SimpleNamespace

from phishing_checker.analyzer import analyze
from phishing_checker.checks import (
    CHECK_ORDER,
    build_check_results,
    count_passed,
)

ALL_OK = {
    "dns": {"passed": True},
    "rdap": {"passed": True},
    "tls": {"passed": True},
    "http": {"passed": True, "message": "200"},
    "html": {"passed": True},
}


def _by_name(checks):
    return {check.name: check for check in checks}


def test_order_and_count():
    checks = build_check_results(log=ALL_OK, scheme="https")
    assert [check.name for check in checks] == list(CHECK_ORDER)
    assert len(checks) == 8


def test_all_passed_with_reputation():
    reputation = SimpleNamespace(checked=True, provider="virustotal", error=None)
    checks = build_check_results(log=ALL_OK, scheme="https", reputation_report=reputation)
    assert count_passed(checks) == 8


def test_reputation_not_configured_is_not_passed():
    reputation = SimpleNamespace(checked=False, provider=None, error="не настроен")
    checks = build_check_results(log=ALL_OK, scheme="https", reputation_report=reputation)
    result = _by_name(checks)["reputation"]
    assert result.status == "not_configured"
    assert not result.passed
    assert count_passed(checks) == 7


def test_reputation_rate_limit_is_failed_with_error():
    reputation = SimpleNamespace(
        checked=False, provider="virustotal", error="429 Too Many Requests"
    )
    checks = build_check_results(log=ALL_OK, scheme="https", reputation_report=reputation)
    result = _by_name(checks)["reputation"]
    assert result.status == "failed"
    assert "429" in (result.error or "")


def test_http_scheme_skips_tls_with_reason():
    log = {k: v for k, v in ALL_OK.items() if k != "tls"}
    checks = build_check_results(log=log, scheme="http")
    result = _by_name(checks)["tls"]
    assert result.status == "skipped"
    assert result.message == "not_https"


def test_no_network_skips_everything_except_local_checks():
    checks = build_check_results(log={}, scheme="https")
    result = _by_name(checks)
    assert result["url"].passed and result["brand"].passed
    for name in ("dns", "rdap", "tls", "http", "html", "reputation"):
        assert result[name].status == "skipped"
        assert result[name].message == "network_disabled"
    assert count_passed(checks) == 2


def test_failed_http_makes_html_skipped_with_no_response():
    log = {
        "dns": {"passed": True},
        "rdap": {"passed": True},
        "tls": {"passed": True},
        "http": {"passed": False, "error": "timeout"},
    }
    result = _by_name(build_check_results(log=log, scheme="https"))
    assert result["http"].status == "failed"
    assert result["http"].error == "timeout"
    assert result["html"].status == "skipped"
    assert result["html"].message == "no_response"


def test_http_ok_without_body_marks_html_no_content():
    log = {k: v for k, v in ALL_OK.items() if k != "html"}
    result = _by_name(build_check_results(log=log, scheme="https"))
    assert result["html"].message == "no_content"


def test_invalid_url_fails_url_and_skips_rest():
    checks = build_check_results(
        log={}, scheme="", url_valid=False, url_error="Некорректный URL"
    )
    assert checks[0].status == "failed"
    assert checks[0].error == "Некорректный URL"
    assert all(check.status == "skipped" for check in checks[1:])
    assert count_passed(checks) == 0


def test_analyze_offline_records_checks_and_matches_coverage():
    report = analyze("https://example.com/", fetch_dns=False)
    assert len(report.checks) == 8
    assert count_passed(report.checks) == report.coverage.passed == 2
    assert report.coverage.total == 8


def test_json_schema_is_unchanged_by_checks():
    report = analyze("https://example.com/", fetch_dns=False)
    assert set(report.to_dict()) == {
        "schema_version",
        "risk_score",
        "risk_level",
        "coverage",
        "evidence",
        "errors",
    }
    assert report.to_dict()["schema_version"] == "1.0"
