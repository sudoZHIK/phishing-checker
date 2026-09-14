"""Deterministic risk scoring for Phishing Checker."""

from __future__ import annotations

from collections.abc import Iterable

from .models import Coverage, Evidence

# Named weights. Each represents one underlying risk signal.
WEIGHT_IP_HOST = 35
WEIGHT_AT_SIGN = 30
WEIGHT_IDN_SPOOF = 40
WEIGHT_SUSPICIOUS_TLD = 20
WEIGHT_SUSPICIOUS_PATH = 10

MAX_SCORE = 100
LOW_MAX = 19
CAUTION_MAX = 39
SUSPICIOUS_MAX = 69


def risk_level(score: int) -> str:
    """Return the risk level for a score in the inclusive 0..100 range."""
    score = max(0, min(MAX_SCORE, score))

    if score <= LOW_MAX:
        return "LOW"
    if score <= CAUTION_MAX:
        return "CAUTION"
    if score <= SUSPICIOUS_MAX:
        return "SUSPICIOUS"
    return "HIGH"


def calculate_score(
    evidence: Iterable[Evidence],
    coverage: Coverage,
) -> int:
    """Calculate a deterministic score from unique evidence signals.

    Coverage below 50% limits the score to CAUTION unless an explicit
    local high-confidence signal is present.
    """
    evidence_list = list(evidence)

    # One code represents one underlying signal.
    unique_evidence: dict[str, Evidence] = {}
    for item in evidence_list:
        if item.weight <= 0:
            continue
        unique_evidence.setdefault(item.code, item)

    score = sum(item.weight for item in unique_evidence.values())
    score = max(0, min(MAX_SCORE, score))

    explicit_local_signals = {
        "IP_HOST",
        "AT_SIGN",
        "IDN_SPOOF",
    }

    if coverage.total == 0:
        coverage_percent = 0.0
    else:
        coverage_percent = coverage.percent

    if coverage_percent < 50.0:
        has_explicit_local_signal = any(
            item.code in explicit_local_signals
            for item in unique_evidence.values()
        )
        if not has_explicit_local_signal:
            score = min(score, CAUTION_MAX)

    return score


def calculate_risk(
    evidence: Iterable[Evidence],
    coverage: Coverage,
) -> tuple[int, str]:
    """Return deterministic (score, level)."""
    score = calculate_score(evidence, coverage)
    return score, risk_level(score)
