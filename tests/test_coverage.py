"""Coverage model tests."""

from phishing_checker.models import Coverage


def test_coverage_zero_of_zero() -> None:
    coverage = Coverage(0, 0)

    assert coverage.percent == 0.0
    assert coverage.status == "NOT_CHECKED"
    assert coverage.to_dict() == {
        "passed": 0,
        "total": 0,
        "percent": 0.0,
        "status": "NOT_CHECKED",
    }


def test_coverage_zero_of_one() -> None:
    coverage = Coverage(0, 1)

    assert coverage.percent == 0.0
    assert coverage.status == "PARTIAL"


def test_coverage_one_of_one() -> None:
    coverage = Coverage(1, 1)

    assert coverage.percent == 100.0
    assert coverage.status == "COMPLETE"


def test_coverage_eight_of_eight() -> None:
    coverage = Coverage(8, 8)

    assert coverage.percent == 100.0
    assert coverage.status == "COMPLETE"
    assert coverage.to_dict()["percent"] == 100.0


def test_coverage_rejects_invalid_values() -> None:
    try:
        Coverage(9, 8)
    except ValueError:
        pass
    else:
        raise AssertionError("Coverage должна отклонять passed > total")
