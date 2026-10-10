"""Понятный отчёт: тексты, статусы проверок, честные формулировки. Без сети и Tk."""

from __future__ import annotations

from phishing_checker.checks import build_check_results
from phishing_checker.models import AnalysisReport, CheckResult, Coverage, Evidence
from phishing_checker.report_text import (
    CHECK_INFO,
    build_readable_report,
    mask_url,
    readable_report_text,
)


def _full_checks() -> list[CheckResult]:
    log = {
        "dns": {"passed": True},
        "rdap": {"passed": True},
        "tls": {"passed": True},
        "http": {"passed": True, "message": "200"},
        "html": {"passed": True},
    }
    return build_check_results(log=log, scheme="https", reputation_report=None)


def _report(**overrides) -> AnalysisReport:
    report = AnalysisReport(
        risk_score=0,
        risk_level="LOW",
        coverage=Coverage(7, 8),
        checks=_full_checks(),
    )
    for key, value in overrides.items():
        setattr(report, key, value)
    return report


def test_mask_url_hides_query_userinfo_and_fragment():
    masked = mask_url("https://user:pw@example.com/a/b?token=1&x=2#frag")
    assert masked == "https://example.com/a/b?<redacted:2>"


def test_mask_url_plain_and_schemeless():
    assert mask_url("https://example.com/path") == "https://example.com/path"
    assert mask_url("example.com/p?x=1") == "example.com/p?<redacted:1>"


def test_report_shows_score_and_coverage_lines():
    text = readable_report_text(_report(), "https://example.com/")
    assert "Риск-оценка: 0/100 — НИЗКИЙ РИСК" in text
    assert "Полнота проверки: 7/8 — 88% — ПРОВЕРКА НЕПОЛНАЯ" in text


def test_report_lists_all_eight_checks():
    text = readable_report_text(_report())
    for title, _description in CHECK_INFO.values():
        assert title in text


def test_low_risk_never_claims_site_is_safe():
    lines = build_readable_report(_report(), "https://example.com/")
    for _tag, line in lines:
        if "безопас" in line.lower():
            assert " не " in f" {line.lower()} ", line


def test_partial_coverage_is_not_phishing_evidence():
    text = readable_report_text(_report())
    assert "не считаются признаком фишинга" in text


def test_failed_check_is_explained_without_raising_risk_wording():
    log = {
        "dns": {"passed": False, "error": "таймаут"},
        "rdap": {"passed": True},
    }
    checks = build_check_results(log=log, scheme="https", reputation_report=None)
    report = _report(checks=checks, coverage=Coverage(3, 8))
    text = readable_report_text(report)
    assert "не удалось выполнить" in text
    assert "таймаут" in text
    assert "Это не признак фишинга" in text


def test_reputation_not_configured_points_to_settings():
    reputation = type(
        "Rep", (), {"checked": False, "provider": None, "error": "не настроен"}
    )()
    checks = build_check_results(
        log={
            "dns": {"passed": True},
            "rdap": {"passed": True},
            "tls": {"passed": True},
            "http": {"passed": True, "message": "200"},
            "html": {"passed": True},
        },
        scheme="https",
        reputation_report=reputation,
    )
    text = readable_report_text(_report(checks=checks))
    assert "ключ API не задан" in text
    assert "API-ключи" in text


def test_skipped_checks_are_reported_with_reason():
    checks = build_check_results(log={}, scheme="https")
    text = readable_report_text(_report(checks=checks, coverage=Coverage(2, 8)))
    assert "пропущена" in text
    assert "Пропущено: сетевые проверки отключены." in text


def test_evidence_is_shown_with_weight_and_explanation():
    evidence = Evidence(
        code="AT_SIGN",
        message="URL содержит userinfo перед hostname (@).",
        weight=30,
        severity="high",
    )
    report = _report(evidence=[evidence], risk_score=30, risk_level="CAUTION")
    text = readable_report_text(report)
    assert "URL содержит userinfo" in text
    assert "+30 к риску" in text
    assert "Что это значит" in text


def test_no_evidence_message():
    text = readable_report_text(_report())
    assert "Подозрительных признаков в проверенных данных не обнаружено" in text


def test_zero_total_coverage_has_no_division_error():
    report = AnalysisReport(coverage=Coverage(0, 0))
    text = readable_report_text(report)
    assert "0/0" in text
    assert "НЕ ПРОВЕРЕНО" in text
    assert "Проверка не выполнялась" in text


def test_complete_coverage_has_no_partial_warning():
    checks = build_check_results(
        log={
            "dns": {"passed": True},
            "rdap": {"passed": True},
            "tls": {"passed": True},
            "http": {"passed": True, "message": "200"},
            "html": {"passed": True},
        },
        scheme="https",
        reputation_report=type(
            "Rep", (), {"checked": True, "provider": "virustotal", "error": None}
        )(),
    )
    report = AnalysisReport(coverage=Coverage(8, 8), checks=checks)
    text = readable_report_text(report)
    assert "ПОЛНАЯ" in text
    assert "не полностью" not in text
    assert "VirusTotal" in text


def test_query_values_are_not_printed_in_header():
    url = "https://example.com/login?token=SECRET123&sid=abc"
    text = readable_report_text(_report(), url)
    assert "SECRET123" not in text
    assert "<redacted:2>" in text


def test_duplicate_errors_are_not_repeated():
    checks = build_check_results(
        log={"dns": {"passed": False, "error": "таймаут"}, "rdap": {"passed": True}},
        scheme="https",
    )
    report = _report(
        checks=checks,
        errors=["DNS A: таймаут", "HTTP: сервер вернул 429 Too Many Requests"],
    )
    text = readable_report_text(report)
    assert "ДОПОЛНИТЕЛЬНЫЕ СООБЩЕНИЯ О СБОЯХ" in text
    assert "429 Too Many Requests" in text
    assert text.count("DNS A: таймаут") == 0


def test_report_without_checks_falls_back_to_counts():
    report = AnalysisReport(coverage=Coverage(2, 8))
    text = readable_report_text(report)
    assert "Выполнено проверок: 2 из 8" in text


def test_high_risk_advice():
    report = _report(risk_score=80, risk_level="HIGH")
    text = readable_report_text(report)
    assert "ВЫСОКИЙ РИСК" in text
    assert "Не вводите пароль" in text
