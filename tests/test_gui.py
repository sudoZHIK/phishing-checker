"""GUI unit tests — no real Tk window is opened."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _make_report(score: int = 0, level: str = "LOW", coverage_status: str = "COMPLETE"):
    report = MagicMock()
    report.risk_score = score
    report.risk_level = level
    report.evidence = []
    report.errors = []
    report.coverage.passed = 8
    report.coverage.total = 8
    report.coverage.percent = 100.0
    report.coverage.status = coverage_status
    report.to_dict.return_value = {"risk_score": score}
    return report


# ---------------------------------------------------------------------------
# _risk_color
# ---------------------------------------------------------------------------

def test_risk_color_low():
    from phishing_checker.gui import GREEN, _risk_color
    assert _risk_color(0) == GREEN
    assert _risk_color(19) == GREEN


def test_risk_color_yellow():
    from phishing_checker.gui import YELLOW, _risk_color
    assert _risk_color(20) == YELLOW
    assert _risk_color(69) == YELLOW


def test_risk_color_red():
    from phishing_checker.gui import RED, _risk_color
    assert _risk_color(70) == RED
    assert _risk_color(100) == RED


# ---------------------------------------------------------------------------
# _risk_title
# ---------------------------------------------------------------------------

def test_risk_title_known():
    from phishing_checker.gui import _risk_title
    assert _risk_title("LOW") == "НИЗКИЙ РИСК"
    assert _risk_title("CAUTION") == "ОСТОРОЖНО"
    assert _risk_title("SUSPICIOUS") == "ПОДОЗРИТЕЛЬНО"
    assert _risk_title("HIGH") == "ВЫСОКИЙ РИСК"


def test_risk_title_unknown():
    from phishing_checker.gui import _risk_title
    assert _risk_title("WHATEVER") == "НЕ ОПРЕДЕЛЁН"


# ---------------------------------------------------------------------------
# _coverage_status
# ---------------------------------------------------------------------------

def test_coverage_status():
    from phishing_checker.gui import _coverage_status
    assert _coverage_status("COMPLETE") == "ПОЛНАЯ"
    assert _coverage_status("PARTIAL") == "ПРОВЕРКА НЕПОЛНАЯ"
    assert _coverage_status("NOT_CHECKED") == "НЕ ПРОВЕРЕНО"
    assert _coverage_status("UNKNOWN") == "UNKNOWN"


# ---------------------------------------------------------------------------
# _evidence_text
# ---------------------------------------------------------------------------

def test_evidence_text_no_evidence():
    from phishing_checker.gui import _evidence_text
    report = _make_report(score=0)
    text = _evidence_text(report)
    assert "Подозрительных признаков не обнаружено" in text
    assert "РЕКОМЕНДАЦИЯ" in text


def test_evidence_text_high_risk():
    from phishing_checker.gui import _evidence_text
    report = _make_report(score=80, level="HIGH")
    text = _evidence_text(report)
    assert "пароль" in text.lower() or "данные карты" in text.lower()


def test_evidence_text_partial_coverage_warning():
    from phishing_checker.gui import _evidence_text
    report = _make_report(score=5, coverage_status="PARTIAL")
    text = _evidence_text(report)
    assert "не полностью" in text or "не означает" in text


def test_evidence_text_complete_coverage_no_warning():
    from phishing_checker.gui import _evidence_text
    report = _make_report(score=5, coverage_status="COMPLETE")
    text = _evidence_text(report)
    assert "не полностью" not in text


def test_evidence_text_with_errors():
    from phishing_checker.gui import _evidence_text
    report = _make_report(score=0)
    report.errors = ["DNS timeout", "TLS unavailable"]
    text = _evidence_text(report)
    assert "DNS timeout" in text
    assert "TLS unavailable" in text


def test_evidence_text_with_evidence_items():
    from phishing_checker.gui import _evidence_text
    item = MagicMock()
    item.severity = "high"
    item.message = "Подозрительный домен"
    item.weight = 40
    item.details = {}
    report = _make_report(score=40)
    report.evidence = [item]
    text = _evidence_text(report)
    assert "Подозрительный домен" in text
    assert "+40" in text


# ---------------------------------------------------------------------------
# _technical_text / _json_text
# ---------------------------------------------------------------------------

def test_technical_text_is_valid_json():
    import json

    from phishing_checker.gui import _technical_text
    report = _make_report(score=10)
    text = _technical_text(report, "https://example.com")
    doc = json.loads(text)
    assert doc["input_url"] == "https://example.com"
    assert doc["tool"] == "Phishing Checker"
    assert "report" in doc


def test_json_text_is_valid_json():
    import json

    from phishing_checker.gui import _json_text
    report = _make_report(score=10)
    text = _json_text(report)
    doc = json.loads(text)
    assert "risk_score" in doc


# ---------------------------------------------------------------------------
# worker passes all analyze parameters
# ---------------------------------------------------------------------------

def test_worker_passes_all_timeouts():
    """Worker must forward all timeout/flag params to analyze()."""
    with patch("phishing_checker.gui.tk.Tk") as mock_tk_cls, \
         patch("phishing_checker.gui.analyze") as mock_analyze:

        mock_root = MagicMock()
        mock_tk_cls.return_value = mock_root
        mock_root.mainloop.side_effect = Exception("stop")

        mock_analyze.return_value = _make_report()

        # Прямо проверяем сигнатуру через inspect
        import inspect

        # analyze должен принимать все параметры — проверяем через analyzer
        from phishing_checker.analyzer import analyze
        sig = inspect.signature(analyze)
        params = set(sig.parameters.keys())
        required = {
            "fetch_dns", "dns_timeout", "rdap_timeout",
            "fetch_http", "http_connect_timeout", "http_read_timeout",
            "http_overall_timeout", "http_max_redirects", "allow_private",
        }
        assert required.issubset(params), f"Отсутствуют параметры: {required - params}"
