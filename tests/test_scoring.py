"""Unit tests for deterministic scoring and coverage."""

from phishing_checker.models import Coverage, Evidence
from phishing_checker.scoring import (
    CAUTION_MAX,
    calculate_risk,
    calculate_score,
    risk_level,
)


def test_coverage_zero_zero() -> None:
    coverage = Coverage(0, 0)

    assert coverage.percent == 0.0
    assert coverage.status == "NOT_CHECKED"


def test_coverage_zero_one() -> None:
    coverage = Coverage(0, 1)

    assert coverage.percent == 0.0
    assert coverage.status == "PARTIAL"


def test_coverage_one_one() -> None:
    coverage = Coverage(1, 1)

    assert coverage.percent == 100.0
    assert coverage.status == "COMPLETE"


def test_coverage_eight_eight() -> None:
    coverage = Coverage(8, 8)

    assert coverage.percent == 100.0
    assert coverage.status == "COMPLETE"


def test_risk_boundaries() -> None:
    assert risk_level(0) == "LOW"
    assert risk_level(19) == "LOW"
    assert risk_level(20) == "CAUTION"
    assert risk_level(39) == "CAUTION"
    assert risk_level(40) == "SUSPICIOUS"
    assert risk_level(69) == "SUSPICIOUS"
    assert risk_level(70) == "HIGH"
    assert risk_level(100) == "HIGH"


def test_duplicate_signal_is_not_counted_twice() -> None:
    evidence = [
        Evidence("AT_SIGN", "Символ @ обнаружен", weight=30),
        Evidence("AT_SIGN", "Повторное описание того же сигнала", weight=30),
    ]

    assert calculate_score(evidence, Coverage(8, 8)) == 30


def test_deterministic_scoring() -> None:
    evidence = [
        Evidence("AT_SIGN", "Символ @ обнаружен", weight=30),
        Evidence("SUSPICIOUS_PATH", "Подозрительный путь", weight=10),
    ]
    coverage = Coverage(8, 8)

    first = calculate_risk(evidence, coverage)
    second = calculate_risk(evidence, coverage)

    assert first == second
    assert first == (40, "SUSPICIOUS")


def test_low_coverage_caps_score_without_explicit_local_signal() -> None:
    evidence = [
        Evidence("SUSPICIOUS_TLD", "Подозрительная зона", weight=20),
        Evidence("SUSPICIOUS_PATH", "Подозрительный путь", weight=10),
        Evidence("OTHER", "Другой сигнал", weight=30),
    ]

    score = calculate_score(evidence, Coverage(1, 8))

    assert score == CAUTION_MAX


def test_explicit_local_signal_can_exceed_low_coverage_cap() -> None:
    evidence = [
        Evidence("IP_HOST", "Хост задан IP-адресом", weight=35),
        Evidence("IDN_SPOOF", "Обнаружен IDN-спуфинг", weight=40),
    ]

    score = calculate_score(evidence, Coverage(1, 8))

    assert score == 75
