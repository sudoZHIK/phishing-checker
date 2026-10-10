"""Per-check results of the analysis pipeline.

The pipeline counts passed checks for coverage. This module records which
individual check ended in which state, so the GUI can explain it to a user.
It is pure: no network, no Tk, deterministic.
"""

from __future__ import annotations

from typing import Any

from .models import CheckResult

CHECK_ORDER: tuple[str, ...] = (
    "url",
    "brand",
    "dns",
    "rdap",
    "tls",
    "http",
    "html",
    "reputation",
)

STATUS_PASSED = "passed"
STATUS_FAILED = "failed"
STATUS_SKIPPED = "skipped"
STATUS_NOT_CONFIGURED = "not_configured"

REASON_NETWORK_DISABLED = "network_disabled"
REASON_NOT_HTTPS = "not_https"
REASON_NO_RESPONSE = "no_response"
REASON_NO_CONTENT = "no_content"
REASON_INVALID_URL = "invalid_url"
REASON_NOT_CONFIGURED = "not_configured"


def _skipped(name: str, reason: str) -> CheckResult:
    return CheckResult(
        name=name,
        passed=False,
        status=STATUS_SKIPPED,
        message=reason,
    )


def _from_log(name: str, entry: dict[str, Any]) -> CheckResult:
    message = str(entry.get("message") or "")
    if entry.get("passed"):
        return CheckResult(
            name=name,
            passed=True,
            status=STATUS_PASSED,
            message=message,
        )

    error = entry.get("error")
    return CheckResult(
        name=name,
        passed=False,
        status=STATUS_FAILED,
        message=message,
        error=str(error) if error else None,
    )


def _reputation_result(reputation_report: Any) -> CheckResult:
    if reputation_report is None:
        return _skipped("reputation", REASON_NETWORK_DISABLED)

    provider = str(getattr(reputation_report, "provider", None) or "")

    if getattr(reputation_report, "checked", False):
        return CheckResult(
            name="reputation",
            passed=True,
            status=STATUS_PASSED,
            message=provider,
        )

    if not provider:
        return CheckResult(
            name="reputation",
            passed=False,
            status=STATUS_NOT_CONFIGURED,
            message=REASON_NOT_CONFIGURED,
        )

    error = getattr(reputation_report, "error", None)
    return CheckResult(
        name="reputation",
        passed=False,
        status=STATUS_FAILED,
        message=provider,
        error=str(error) if error else None,
    )


def build_check_results(
    *,
    log: dict[str, dict[str, Any]],
    scheme: str,
    reputation_report: Any = None,
    url_valid: bool = True,
    url_error: str | None = None,
) -> list[CheckResult]:
    """Return one CheckResult per pipeline check, in CHECK_ORDER.

    ``log`` holds only the checks that were actually attempted
    (keys: dns, rdap, tls, http, html). Each entry has ``passed`` and
    optionally ``error`` and ``message``. Everything else is reported as
    skipped with a reason code.
    """
    if not url_valid:
        results = [
            CheckResult(
                name="url",
                passed=False,
                status=STATUS_FAILED,
                error=url_error,
            )
        ]
        results.extend(_skipped(name, REASON_INVALID_URL) for name in CHECK_ORDER[1:])
        return results

    results = [
        CheckResult(name="url", passed=True, status=STATUS_PASSED),
        CheckResult(name="brand", passed=True, status=STATUS_PASSED),
    ]

    for name in ("dns", "rdap"):
        if name in log:
            results.append(_from_log(name, log[name]))
        else:
            results.append(_skipped(name, REASON_NETWORK_DISABLED))

    if "tls" in log:
        results.append(_from_log("tls", log["tls"]))
    elif scheme != "https":
        results.append(_skipped("tls", REASON_NOT_HTTPS))
    else:
        results.append(_skipped("tls", REASON_NETWORK_DISABLED))

    if "http" in log:
        results.append(_from_log("http", log["http"]))
    else:
        results.append(_skipped("http", REASON_NETWORK_DISABLED))

    if "html" in log:
        results.append(_from_log("html", log["html"]))
    elif "http" in log:
        reason = REASON_NO_CONTENT if log["http"].get("passed") else REASON_NO_RESPONSE
        results.append(_skipped("html", reason))
    else:
        results.append(_skipped("html", REASON_NETWORK_DISABLED))

    results.append(_reputation_result(reputation_report))
    return results


def count_passed(checks: list[CheckResult]) -> int:
    return sum(1 for check in checks if check.passed)
