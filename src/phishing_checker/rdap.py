"""RDAP domain lookup for Phishing Checker.

RDAP is an informational network check. Network failures and HTTP errors
are returned as check errors and must not become phishing evidence.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

import requests

from . import __version__
from .analyzer import normalize_url

DEFAULT_RDAP_URL = "https://rdap.org/domain/"
DEFAULT_TIMEOUT = 5.0
MAX_RESPONSE_BYTES = 1_000_000


@dataclass(frozen=True, slots=True)
class RDAPReport:
    """Result of one RDAP domain lookup."""

    hostname: str
    hostname_ascii: str
    checked: bool
    status_code: int | None = None
    events: list[dict[str, str]] | None = None
    nameservers: list[str] | None = None
    error: str | None = None
    server: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "hostname": self.hostname,
            "hostname_ascii": self.hostname_ascii,
            "checked": self.checked,
            "status_code": self.status_code,
            "events": list(self.events or []),
            "nameservers": list(self.nameservers or []),
            "error": self.error,
            "server": self.server,
        }


def _empty_report(
    hostname: str = "",
    *,
    error: str,
    server: str | None = None,
) -> RDAPReport:
    """Create an incomplete report for invalid local input."""
    return RDAPReport(
        hostname=hostname,
        hostname_ascii=hostname,
        checked=False,
        error=error,
        server=server,
    )


def _extract_events(payload: dict[str, Any]) -> list[dict[str, str]]:
    events: list[dict[str, str]] = []

    raw_events = payload.get("events", [])
    if not isinstance(raw_events, list):
        return events

    for item in raw_events:
        if not isinstance(item, dict):
            continue

        action = item.get("eventAction")
        date = item.get("eventDate")

        if isinstance(action, str) and isinstance(date, str):
            events.append(
                {
                    "action": action,
                    "date": date,
                }
            )

    return events


def _extract_nameservers(payload: dict[str, Any]) -> list[str]:
    nameservers: list[str] = []

    raw_nameservers = payload.get("nameservers", [])
    if not isinstance(raw_nameservers, list):
        return nameservers

    for item in raw_nameservers:
        if not isinstance(item, dict):
            continue

        name = item.get("ldhName")

        if isinstance(name, str) and name:
            normalized = name.rstrip(".").lower()

            if normalized and normalized not in nameservers:
                nameservers.append(normalized)

    return nameservers


def _request_rdap(
    hostname_ascii: str,
    *,
    timeout: float,
    server: str,
) -> RDAPReport:
    url = f"{server.rstrip('/')}/{hostname_ascii}"

    headers = {
        "Accept": "application/rdap+json, application/json",
        "User-Agent": f"PhishingChecker/{__version__}",
    }

    try:
        response = requests.get(
            url,
            headers=headers,
            timeout=timeout,
            allow_redirects=True,
            stream=True,
        )
    except requests.RequestException as exc:
        return RDAPReport(
            hostname=hostname_ascii,
            hostname_ascii=hostname_ascii,
            checked=False,
            error=f"RDAP network error: {exc}",
            server=server,
        )

    try:
        status_code = response.status_code

        if status_code == 404:
            return RDAPReport(
                hostname=hostname_ascii,
                hostname_ascii=hostname_ascii,
                checked=True,
                status_code=status_code,
                error="RDAP server reports domain not found",
                server=server,
            )

        if not 200 <= status_code < 300:
            return RDAPReport(
                hostname=hostname_ascii,
                hostname_ascii=hostname_ascii,
                checked=False,
                status_code=status_code,
                error=f"RDAP HTTP error: {status_code}",
                server=server,
            )

        # The tests and normal requests responses expose the complete
        # response body through .content. Check that first so the size
        # limit is deterministic and works with mocked responses too.
        content = response.content

        if len(content) > MAX_RESPONSE_BYTES:
            return RDAPReport(
                hostname=hostname_ascii,
                hostname_ascii=hostname_ascii,
                checked=False,
                status_code=status_code,
                error="RDAP response is too large",
                server=server,
            )

        try:
            payload = json.loads(
                content.decode("utf-8", errors="replace")
            )
        except (ValueError, UnicodeDecodeError) as exc:
            return RDAPReport(
                hostname=hostname_ascii,
                hostname_ascii=hostname_ascii,
                checked=False,
                status_code=status_code,
                error=f"Invalid RDAP JSON: {exc}",
                server=server,
            )

        if not isinstance(payload, dict):
            return RDAPReport(
                hostname=hostname_ascii,
                hostname_ascii=hostname_ascii,
                checked=False,
                status_code=status_code,
                error="RDAP response is not a JSON object",
                server=server,
            )

        return RDAPReport(
            hostname=hostname_ascii,
            hostname_ascii=hostname_ascii,
            checked=True,
            status_code=status_code,
            events=_extract_events(payload),
            nameservers=_extract_nameservers(payload),
            server=server,
        )

    finally:
        response.close()


def lookup_rdap(
    hostname: str,
    *,
    timeout: float = DEFAULT_TIMEOUT,
    server: str = DEFAULT_RDAP_URL,
    base_url: str | None = None,
) -> RDAPReport:
    """Look up a domain through RDAP.

    ``base_url`` is retained as a compatibility alias for ``server``.
    The hostname is normalized with the same IDNA rules as URL analysis.
    """

    if base_url is not None:
        server = base_url

    if not isinstance(hostname, str):
        return _empty_report(
            error="Hostname must be a string",
            server=server,
        )

    value = hostname.strip()

    if not value:
        return _empty_report(
            error="Hostname is empty",
            server=server,
        )

    if timeout <= 0:
        raise ValueError("timeout должен быть больше нуля")

    try:
        normalized = normalize_url(f"https://{value}/")
    except (TypeError, ValueError) as exc:
        return _empty_report(
            hostname=value,
            error=f"Invalid hostname: {exc}",
            server=server,
        )

    if normalized.is_ip:
        return RDAPReport(
            hostname=normalized.hostname_ascii,
            hostname_ascii=normalized.hostname_ascii,
            checked=False,
            error="RDAP domain lookup is not applicable to IP addresses",
            server=server,
        )

    return _request_rdap(
        normalized.hostname_ascii,
        timeout=timeout,
        server=server,
    )


def lookup_url_rdap(
    url: str,
    *,
    timeout: float = DEFAULT_TIMEOUT,
    server: str = DEFAULT_RDAP_URL,
    base_url: str | None = None,
) -> RDAPReport:
    """Look up the domain extracted from a URL."""

    if base_url is not None:
        server = base_url

    try:
        normalized = normalize_url(url)
    except (TypeError, ValueError) as exc:
        return _empty_report(
            error=f"Invalid URL: {exc}",
            server=server,
        )

    return lookup_rdap(
        normalized.hostname_ascii,
        timeout=timeout,
        server=server,
    )
