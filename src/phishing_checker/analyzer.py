"""URL normalization and local static analysis.

This module performs deterministic, network-free URL analysis.
It does not fetch URLs, resolve DNS, execute JavaScript, or store
userinfo credentials.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import SplitResult, urlsplit, urlunsplit

import idna

from .models import Evidence

SUPPORTED_SCHEMES = frozenset({"http", "https"})

CREDENTIAL_PATH_RE = re.compile(
    r"(?:^|/)(?:login|signin|sign-in|verify|verification|"
    r"secure|account|wallet|recover|password|update|confirm|"
    r"support|billing)(?:/|$)",
    re.IGNORECASE,
)


@dataclass(frozen=True, slots=True)
class NormalizedURL:
    """Deterministic normalized representation of a URL."""

    original: str
    normalized: str
    scheme: str
    hostname_unicode: str
    hostname_ascii: str
    port: int | None
    has_userinfo: bool
    has_username: bool
    has_password: bool
    is_ip: bool
    ip_version: int | None
    is_punycode: bool

    @property
    def hostname(self) -> str:
        """Compatibility alias: Unicode hostname."""
        return self.hostname_unicode

    @property
    def host_ascii(self) -> str:
        """Compatibility alias: ASCII/Punycode hostname."""
        return self.hostname_ascii


def _validate_input(url: str) -> str:
    if not isinstance(url, str):
        raise TypeError("URL должен быть строкой")

    value = url.strip()

    if not value:
        raise ValueError("URL не может быть пустым")

    if any(ord(char) < 0x20 for char in value):
        raise ValueError("URL содержит управляющие символы")

    return value


def _split_url(value: str) -> SplitResult:
    """Parse a URL, accepting a missing scheme as https."""
    candidate = value

    if "://" not in candidate:
        candidate = f"https://{candidate}"

    parsed = urlsplit(candidate)

    if parsed.scheme.lower() not in SUPPORTED_SCHEMES:
        raise ValueError(
            f"Неподдерживаемая схема URL: {parsed.scheme!r}"
        )

    if not parsed.netloc:
        raise ValueError("URL не содержит hostname")

    return parsed


def _normalize_hostname(hostname: str) -> tuple[str, str, bool, bool]:
    """Return Unicode host, ASCII host, is_ip and is_punycode."""
    if not hostname:
        raise ValueError("Hostname не может быть пустым")

    # IPv6 literals are already ASCII and must not pass through IDNA.
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        address = None

    if address is not None:
        return (
            address.compressed.lower(),
            address.compressed.lower(),
            True,
            False,
        )

    host = hostname.rstrip(".").lower()

    try:
        ascii_host = idna.encode(
            host,
            uts46=True,
            std3_rules=True,
        ).decode("ascii").lower()

        unicode_host = idna.decode(
            ascii_host.encode("ascii"),
            uts46=True,
            std3_rules=True,
        ).lower()
    except idna.IDNAError as exc:
        raise ValueError(f"Некорректный IDN hostname: {exc}") from exc

    is_punycode = any(
        label.startswith("xn--")
        for label in ascii_host.split(".")
    )

    return unicode_host, ascii_host, False, is_punycode


def normalize_url(url: str) -> NormalizedURL:
    """Normalize a URL deterministically without performing network I/O."""
    original = _validate_input(url)
    parsed = _split_url(original)

    try:
        hostname = parsed.hostname
    except ValueError as exc:
        raise ValueError(f"Некорректный hostname: {exc}") from exc

    if hostname is None:
        raise ValueError("URL не содержит hostname")

    unicode_host, ascii_host, is_ip, is_punycode = _normalize_hostname(
        hostname
    )

    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError(f"Некорректный порт: {exc}") from exc

    if port is not None and not 1 <= port <= 65535:
        raise ValueError("Порт должен находиться в диапазоне 1..65535")

    scheme = parsed.scheme.lower()

    has_userinfo = bool(parsed.username is not None or parsed.password is not None)
    has_username = parsed.username is not None
    has_password = parsed.password is not None

    # Never preserve credentials in the normalized URL.
    if has_userinfo:
        safe_netloc = ascii_host
        if port is not None:
            safe_netloc = f"{safe_netloc}:{port}"
    else:
        safe_netloc = ascii_host
        if port is not None:
            safe_netloc = f"{safe_netloc}:{port}"

    # IPv6 literals need brackets when reconstructed.
    if is_ip and ":" in ascii_host:
        safe_netloc = f"[{ascii_host}]"
        if port is not None:
            safe_netloc = f"{safe_netloc}:{port}"

    normalized = urlunsplit(
        (
            scheme,
            safe_netloc,
            parsed.path or "/",
            parsed.query,
            "",
        )
    )

    try:
        ip_version = ipaddress.ip_address(ascii_host).version
    except ValueError:
        ip_version = None

    return NormalizedURL(
        original=original,
        normalized=normalized,
        scheme=scheme,
        hostname_unicode=unicode_host,
        hostname_ascii=ascii_host,
        port=port,
        has_userinfo=has_userinfo,
        has_username=has_username,
        has_password=has_password,
        is_ip=is_ip,
        ip_version=ip_version,
        is_punycode=is_punycode,
    )


def analyze_url(url: str) -> tuple[NormalizedURL, list[Evidence]]:
    """Normalize a URL and produce deterministic local evidence.

    No network access is performed.
    """
    result = normalize_url(url)
    evidence: list[Evidence] = []

    if result.has_userinfo:
        evidence.append(
            Evidence(
                code="AT_SIGN",
                message="URL содержит userinfo перед hostname (@).",
                weight=30,
                severity="high",
            )
        )

    if result.is_ip:
        evidence.append(
            Evidence(
                code="IP_HOST",
                message="В качестве hostname используется IP-адрес.",
                weight=35,
                severity="high",
                details={"ip_version": result.ip_version},
            )
        )

    if result.is_punycode:
        evidence.append(
            Evidence(
                code="IDN_PUNYCODE",
                message="Hostname содержит Punycode/IDN.",
                weight=12,
                severity="medium",
                details={
                    "unicode": result.hostname_unicode,
                    "punycode": result.hostname_ascii,
                },
            )
        )

    if result.port is not None and result.port not in (80, 443):
        evidence.append(
            Evidence(
                code="NON_STANDARD_PORT",
                message="Используется нестандартный TCP-порт.",
                weight=7,
                severity="low",
                details={"port": result.port},
            )
        )

    if len(result.normalized) > 180:
        evidence.append(
            Evidence(
                code="LONG_URL",
                message="URL имеет необычно большую длину.",
                weight=4,
                severity="low",
                details={"length": len(result.normalized)},
            )
        )

    labels = result.hostname_ascii.split(".")
    if len(labels) >= 5:
        evidence.append(
            Evidence(
                code="DEEP_SUBDOMAIN",
                message="Hostname содержит большое количество уровней поддоменов.",
                weight=5,
                severity="low",
                details={"label_count": len(labels)},
            )
        )

    # Do not count the structural "--" inside Punycode labels (xn--...).
    # Count hyphens in the Unicode representation instead, otherwise a
    # normal IDN can receive a false-positive MANY_HYPHENS signal.
    unicode_hyphen_count = result.hostname_unicode.count("-")

    if unicode_hyphen_count >= 4:
        evidence.append(
            Evidence(
                code="MANY_HYPHENS",
                message="Hostname содержит много дефисов.",
                weight=4,
                severity="low",
                details={"count": unicode_hyphen_count},
            )
        )

    parsed = urlsplit(result.normalized)

    if CREDENTIAL_PATH_RE.search(parsed.path):
        evidence.append(
            Evidence(
                code="CREDENTIAL_PATH",
                message="Путь URL содержит слова, связанные с входом или подтверждением аккаунта.",
                weight=8,
                severity="low",
            )
        )

    return result, evidence


def analyze(
    url: str,
    *,
    fetch_dns: bool = True,
    dns_timeout: float = 3.0,
    rdap_timeout: float = 5.0,
):
    """Run the currently available analysis pipeline.

    Coverage consists of eight top-level checks defined by the project
    architecture:

        URL, brand similarity, DNS, RDAP, TLS, HTTP, HTML, reputation

    Only checks that are actually implemented and successfully executed
    contribute to the completed count.
    """
    from .dns import lookup_url_dns
    from .models import AnalysisReport, Coverage
    from .rdap import lookup_url_rdap
    from .scoring import calculate_risk

    TOTAL_CHECKS = 8

    report = AnalysisReport()

    try:
        normalized, local_evidence = analyze_url(url)
    except (TypeError, ValueError) as exc:
        report.errors.append(str(exc))
        report.coverage = Coverage(0, TOTAL_CHECKS)
        report.risk_score, report.risk_level = calculate_risk(
            report.evidence,
            report.coverage,
        )
        return report

    report.evidence.extend(local_evidence)

    # URL/local analysis is one completed top-level check.
    passed_checks = 1

    if fetch_dns:
        dns_report = lookup_url_dns(
            normalized.normalized,
            timeout=dns_timeout,
        )

        # A/AAAA/etc. are details of ONE DNS check.
        # Transport failures never become phishing evidence.
        dns_success = bool(dns_report.results) and all(
            result.success for result in dns_report.results
        )

        if dns_success:
            passed_checks += 1
        else:
            for result in dns_report.results:
                if result.success:
                    continue

                if result.error:
                    report.errors.append(
                        f"DNS {result.record_type}: {result.error}"
                    )

        rdap_report = lookup_url_rdap(
            normalized.normalized,
            timeout=rdap_timeout,
        )

        if rdap_report.checked:
            passed_checks += 1
        elif rdap_report.error:
            report.errors.append(rdap_report.error)

    report.coverage = Coverage(
        passed=passed_checks,
        total=TOTAL_CHECKS,
    )

    report.risk_score, report.risk_level = calculate_risk(
        report.evidence,
        report.coverage,
    )

    return report

