"""Network DNS analysis via DNS-over-HTTPS.

This module performs DNS lookups through HTTPS and never treats a
transport failure as evidence of phishing. DNS failures are reported
as incomplete checks.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import requests

from .analyzer import normalize_url

DEFAULT_DOH_SERVERS = (
    "https://cloudflare-dns.com/dns-query",
    "https://dns.google/resolve",
)

SUPPORTED_RECORD_TYPES = frozenset({"A", "AAAA", "CNAME", "MX", "NS"})


@dataclass(frozen=True, slots=True)
class DNSResult:
    """Result of one DNS record lookup."""

    record_type: str
    answers: tuple[str, ...]
    success: bool
    error: str | None = None
    server: str | None = None

    @property
    def checked(self) -> bool:
        return self.success


@dataclass(frozen=True, slots=True)
class DNSReport:
    """Complete DNS analysis for one hostname."""

    hostname: str
    hostname_ascii: str
    results: tuple[DNSResult, ...]

    @property
    def checked(self) -> int:
        return sum(result.success for result in self.results)

    @property
    def total(self) -> int:
        return len(self.results)

    @property
    def complete(self) -> bool:
        return self.total > 0 and self.checked == self.total

    def to_dict(self) -> dict[str, Any]:
        return {
            "hostname": self.hostname,
            "hostname_ascii": self.hostname_ascii,
            "checked": self.checked,
            "total": self.total,
            "complete": self.complete,
            "results": [
                {
                    "record_type": result.record_type,
                    "answers": list(result.answers),
                    "success": result.success,
                    "error": result.error,
                    "server": result.server,
                }
                for result in self.results
            ],
        }


def _query_doh(
    hostname: str,
    record_type: str,
    server: str,
    timeout: float,
) -> DNSResult:
    """Perform one DNS-over-HTTPS JSON query."""
    try:
        response = requests.get(
            server,
            params={
                "name": hostname,
                "type": record_type,
            },
            headers={
                "Accept": "application/dns-json",
            },
            timeout=timeout,
            allow_redirects=False,
        )
        response.raise_for_status()
    except requests.RequestException as exc:
        return DNSResult(
            record_type=record_type,
            answers=(),
            success=False,
            error=f"DNS-over-HTTPS request failed: {exc}",
            server=server,
        )

    try:
        payload = response.json()
    except ValueError as exc:
        return DNSResult(
            record_type=record_type,
            answers=(),
            success=False,
            error=f"Некорректный JSON от DNS-over-HTTPS: {exc}",
            server=server,
        )

    status = payload.get("Status")
    if status != 0:
        return DNSResult(
            record_type=record_type,
            answers=(),
            success=False,
            error=f"DNS server returned status {status}",
            server=server,
        )

    answers = payload.get("Answer", [])
    values: list[str] = []

    for answer in answers:
        if not isinstance(answer, dict):
            continue

        data = answer.get("data")
        if isinstance(data, str) and data:
            values.append(data)

    # A valid NOERROR response with no Answer section is still a
    # successful DNS check. NXDOMAIN is represented by a non-zero
    # Status above.
    return DNSResult(
        record_type=record_type,
        answers=tuple(values),
        success=True,
        error=None,
        server=server,
    )


def lookup_dns(
    hostname: str,
    *,
    record_types: tuple[str, ...] = ("A", "AAAA", "CNAME", "MX", "NS"),
    timeout: float = 3.0,
    servers: tuple[str, ...] = DEFAULT_DOH_SERVERS,
) -> DNSReport:
    """Resolve a hostname through DNS-over-HTTPS.

    The hostname is normalized through the same IDNA rules used by the
    URL analyzer. Only ASCII/Punycode is sent to DNS providers.

    A request failure is an incomplete DNS check, not phishing evidence.
    """
    if not isinstance(hostname, str):
        raise TypeError("hostname должен быть строкой")

    value = hostname.strip()
    if not value:
        raise ValueError("hostname не может быть пустым")

    if timeout <= 0:
        raise ValueError("timeout должен быть больше нуля")

    normalized = normalize_url(f"https://{value}/")

    requested = tuple(record_types)

    if not requested:
        raise ValueError("record_types не может быть пустым")

    if any(record_type not in SUPPORTED_RECORD_TYPES for record_type in requested):
        raise ValueError(
            f"Поддерживаются только: {', '.join(sorted(SUPPORTED_RECORD_TYPES))}"
        )

    results: list[DNSResult] = []

    for record_type in requested:
        result: DNSResult | None = None

        for server in servers:
            result = _query_doh(
                normalized.hostname_ascii,
                record_type,
                server,
                timeout,
            )

            if result.success:
                break

        if result is None:
            result = DNSResult(
                record_type=record_type,
                answers=(),
                success=False,
                error="DNS-over-HTTPS серверы не заданы",
                server=None,
            )

        results.append(result)

    return DNSReport(
        hostname=normalized.hostname_unicode,
        hostname_ascii=normalized.hostname_ascii,
        results=tuple(results),
    )


def lookup_url_dns(
    url: str,
    *,
    record_types: tuple[str, ...] = ("A", "AAAA", "CNAME", "MX", "NS"),
    timeout: float = 3.0,
    servers: tuple[str, ...] = DEFAULT_DOH_SERVERS,
) -> DNSReport:
    """Resolve the hostname extracted from a URL."""
    normalized = normalize_url(url)

    return lookup_dns(
        normalized.hostname_ascii,
        record_types=record_types,
        timeout=timeout,
        servers=servers,
    )
