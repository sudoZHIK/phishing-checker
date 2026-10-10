"""URL normalization and local static analysis.

This module performs deterministic, network-free URL analysis.
It does not fetch URLs, resolve DNS, execute JavaScript, or store
userinfo credentials.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from difflib import SequenceMatcher
from urllib.parse import SplitResult, urlsplit, urlunsplit

import idna

from .models import Evidence
from .scoring import WEIGHT_BRAND_SIMILARITY

SUPPORTED_SCHEMES = frozenset({"http", "https"})

CREDENTIAL_PATH_RE = re.compile(
    r"(?:^|/)(?:login|signin|sign-in|verify|verification|"
    r"secure|account|wallet|recover|password|update|confirm|"
    r"support|billing)(?:/|$)",
    re.IGNORECASE,
)

BRAND_DOMAINS = {
    "paypal": {"paypal.com"},
    "microsoft": {"microsoft.com", "live.com", "outlook.com"},
    "google": {"google.com"},
    "apple": {"apple.com"},
    "amazon": {"amazon.com"},
    "facebook": {"facebook.com", "fb.com"},
    "instagram": {"instagram.com"},
    "netflix": {"netflix.com"},
    "steam": {"steampowered.com", "steamcommunity.com"},
    "binance": {"binance.com"},
}

BRAND_SIMILARITY_THRESHOLD = 0.78


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

    brand_evidence = _brand_similarity(result.hostname_ascii)
    if brand_evidence is not None:
        evidence.append(brand_evidence)

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



def _brand_similarity(hostname: str) -> Evidence | None:
    """Detect hostnames that closely imitate known brands."""
    hostname = hostname.lower().rstrip(".")

    # Official domains and their subdomains are legitimate.
    for official_domains in BRAND_DOMAINS.values():
        for official_domain in official_domains:
            if (
                hostname == official_domain
                or hostname.endswith("." + official_domain)
            ):
                return None

    def normalize_label(value: str) -> str:
        """Normalize common ASCII leet substitutions."""
        table = str.maketrans({
            "0": "o",
            "1": "l",
            "3": "e",
            "4": "a",
            "5": "s",
            "7": "t",
        })
        return value.translate(table)

    # Compare each hostname label with the brand name.
    # The final TLD is intentionally ignored.
    for brand, official_domains in BRAND_DOMAINS.items():
        for label in hostname.split("."):
            label_clean = re.sub(r"[^a-z0-9]", "", label)
            if not label_clean:
                continue

            normalized_label = normalize_label(label_clean)

            similarity = SequenceMatcher(
                None,
                normalized_label,
                brand,
            ).ratio()

            # Exact canonical match is legitimate only when the hostname
            # belongs to one of the official domains, handled above.
            if similarity >= BRAND_SIMILARITY_THRESHOLD:
                return Evidence(
                    code="BRAND_SIMILARITY",
                    message=f"Hostname похож на бренд «{brand}».",
                    weight=WEIGHT_BRAND_SIMILARITY,
                    severity="high",
                    details={
                        "brand": brand,
                        "hostname": hostname,
                        "similarity": round(similarity, 3),
                    },
                )

    return None


def analyze(
    url: str,
    *,
    fetch_dns: bool = True,
    dns_timeout: float = 3.0,
    rdap_timeout: float = 5.0,
    fetch_http: bool = True,
    http_connect_timeout: float = 5.0,
    http_read_timeout: float = 10.0,
    http_overall_timeout: float = 30.0,
    http_max_redirects: int = 10,
    allow_private: bool = False,
):
    """Run the complete analysis pipeline."""

    from .checks import build_check_results
    from .dns import lookup_url_dns
    from .html import analyze_html
    from .http import fetch_url
    from .models import AnalysisReport, Coverage
    from .rdap import lookup_url_rdap
    from .reputation import check_reputation
    from .scoring import (
        WEIGHT_REPUTATION_MALICIOUS,
        WEIGHT_REPUTATION_SUSPICIOUS,
        calculate_risk,
    )
    from .tls import check_tls

    TOTAL_CHECKS = 8

    report = AnalysisReport()
    checks_log: dict[str, dict] = {}

    try:
        normalized, local_evidence = analyze_url(url)
    except (TypeError, ValueError) as exc:
        report.errors.append(str(exc))
        report.checks = build_check_results(
            log={},
            scheme="",
            url_valid=False,
            url_error=str(exc),
        )
        report.coverage = Coverage(0, TOTAL_CHECKS)
        report.risk_score, report.risk_level = calculate_risk(
            report.evidence,
            report.coverage,
        )
        return report

    report.evidence.extend(local_evidence)

    # 1. URL
    passed_checks = 1

    # 2. Brand similarity is already part of local_evidence from analyze_url().
    # Do not append it a second time: one underlying signal must have one
    # evidence item even though scoring also deduplicates by evidence code.
    passed_checks += 1

    # 3. DNS
    if fetch_dns:
        dns_report = lookup_url_dns(
            normalized.normalized,
            timeout=dns_timeout,
        )

        dns_success = bool(dns_report.results) and all(
            result.success for result in dns_report.results
        )

        checks_log["dns"] = {
            "passed": dns_success,
            "error": next(
                (
                    str(item.error)
                    for item in dns_report.results
                    if not item.success and item.error
                ),
                None,
            ),
        }
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

        # 4. RDAP
        rdap_report = lookup_url_rdap(
            normalized.normalized,
            timeout=rdap_timeout,
        )

        checks_log["rdap"] = {
            "passed": bool(rdap_report.checked),
            "error": rdap_report.error,
        }
        if rdap_report.checked:
            passed_checks += 1
        elif rdap_report.error:
            report.errors.append(rdap_report.error)

    # 5. TLS
    #
    # TLS is meaningful only for HTTPS. For HTTP there is no TLS endpoint
    # to inspect, so the check remains incomplete rather than becoming
    # artificial evidence.
    if normalized.scheme == "https" and fetch_dns and fetch_http:
        tls_report = check_tls(
            normalized.hostname_ascii,
            port=normalized.port or 443,
            timeout=5.0,
            allow_private=allow_private,
        )

        checks_log["tls"] = {
            "passed": bool(tls_report.checked),
            "error": tls_report.error,
        }
        if tls_report.checked:
            passed_checks += 1

        # TLS failures are transport/coverage information, not
        # phishing evidence.
        if tls_report.error:
            report.errors.append(
                f"TLS: {tls_report.error}"
            )

    # 6. HTTP
    http_report = None

    if fetch_dns and fetch_http:
        http_report = fetch_url(
            normalized.normalized,
            connect_timeout=http_connect_timeout,
            read_timeout=http_read_timeout,
            overall_timeout=http_overall_timeout,
            max_redirects=http_max_redirects,
            allow_private=allow_private,
        )

        checks_log["http"] = {
            "passed": bool(http_report.checked)
            and http_report.status_code != 429,
            "error": http_report.error,
            "message": str(http_report.status_code or ""),
        }
        if http_report.status_code == 429:
            report.errors.append(
                "HTTP: сервер вернул 429 Too Many Requests"
            )
        elif http_report.checked:
            passed_checks += 1
        elif http_report.error:
            if http_report.blocked:
                report.errors.append(
                    f"HTTP/SSRF: {http_report.error}"
                )
            else:
                report.errors.append(http_report.error)

    # 7. HTML
    #
    # HTML analysis is strictly static. It is performed only when HTTP
    # successfully returned a response body.
    if http_report is not None and http_report.checked:
        body = getattr(http_report, "body", None)

        if body is None:
            body = getattr(http_report, "content", None)

        if body:
            try:
                html_report = analyze_html(
                    body,
                    base_url=normalized.normalized,
                )

                checks_log["html"] = {"passed": True, "error": None}
                passed_checks += 1

                for evidence in getattr(
                    html_report,
                    "evidence",
                    (),
                ):
                    report.evidence.append(evidence)

                html_error = getattr(html_report, "error", None)
                if html_error:
                    report.errors.append(
                        f"HTML: {html_error}"
                    )

            except (TypeError, ValueError, UnicodeError) as exc:
                checks_log["html"] = {"passed": False, "error": str(exc)}
                report.errors.append(f"HTML: {exc}")

    # 8. Reputation
    #
    # The current reputation module is a provider placeholder. When no
    # real provider is configured, this is deliberately incomplete and
    # does not affect phishing risk.
    reputation_report = None
    if fetch_dns and fetch_http:
        reputation_report = check_reputation(
            normalized.normalized,
            timeout=min(http_read_timeout, 10.0),
        )

    if reputation_report is not None and reputation_report.checked:
        passed_checks += 1
        if reputation_report.malicious:
            report.evidence.append(
                Evidence(
                    code="REPUTATION_MALICIOUS",
                    message="Репутационный сервис сообщил о вредоносной активности для URL.",
                    weight=WEIGHT_REPUTATION_MALICIOUS,
                    severity="high",
                    details={"provider": reputation_report.provider},
                )
            )
        elif reputation_report.suspicious:
            report.evidence.append(
                Evidence(
                    code="REPUTATION_SUSPICIOUS",
                    message="Репутационный сервис сообщил о подозрительной активности для URL.",
                    weight=WEIGHT_REPUTATION_SUSPICIOUS,
                    severity="medium",
                    details={"provider": reputation_report.provider},
                )
            )

    if reputation_report is not None and reputation_report.error and reputation_report.provider:
        report.errors.append(
            f"Репутация: {reputation_report.error}"
        )

    report.coverage = Coverage(
        passed=min(passed_checks, TOTAL_CHECKS),
        total=TOTAL_CHECKS,
    )
    report.checks = build_check_results(
        log=checks_log,
        scheme=normalized.scheme,
        reputation_report=reputation_report,
    )

    report.risk_score, report.risk_level = calculate_risk(
        report.evidence,
        report.coverage,
    )

    return report

