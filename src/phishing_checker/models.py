"""Core data models for Phishing Checker."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True, slots=True)
class Evidence:
    """A single piece of evidence supporting an analysis result."""

    code: str
    message: str
    weight: int = 0
    severity: str = "info"
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "message": self.message,
            "weight": self.weight,
            "severity": self.severity,
            "details": self.details,
        }


@dataclass(frozen=True, slots=True)
class CheckResult:
    """Result of one individual analysis check."""

    name: str
    passed: bool
    status: str = "passed"
    message: str = ""
    evidence: tuple[Evidence, ...] = ()
    error: str | None = None


@dataclass(frozen=True, slots=True)
class Coverage:
    """Coverage information for performed checks."""

    passed: int
    total: int

    def __post_init__(self) -> None:
        if self.passed < 0:
            raise ValueError("passed не может быть отрицательным")
        if self.total < 0:
            raise ValueError("total не может быть отрицательным")
        if self.passed > self.total:
            raise ValueError("passed не может быть больше total")

    @property
    def percent(self) -> float:
        if self.total == 0:
            return 0.0
        return (self.passed / self.total) * 100.0

    @property
    def status(self) -> str:
        if self.total == 0:
            return "NOT_CHECKED"
        if self.passed == self.total:
            return "COMPLETE"
        return "PARTIAL"

    def to_dict(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "total": self.total,
            "percent": round(self.percent, 2),
            "status": self.status,
        }


@dataclass(slots=True)
class AnalysisReport:
    """Serializable report produced by the analysis pipeline."""

    schema_version: str = "1.0"
    risk_score: int = 0
    risk_level: str = "LOW"
    coverage: Coverage = field(default_factory=lambda: Coverage(0, 0))
    evidence: list[Evidence] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    # Результаты отдельных проверок для GUI. В JSON (schema 1.0) не входят.
    checks: list[CheckResult] = field(
        default_factory=list,
        compare=False,
        repr=False,
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "coverage": self.coverage.to_dict(),
            "evidence": [item.to_dict() for item in self.evidence],
            "errors": list(self.errors),
        }
