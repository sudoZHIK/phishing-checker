"""Optional VirusTotal and Google Safe Browsing reputation checks."""
from __future__ import annotations

import base64
import os
from dataclasses import dataclass

import requests

from . import __version__
from .cache import get as cache_get
from .cache import put as cache_put
from .network_guard import respect_retry_after, wait_for_request

REPUTATION_CACHE_TTL = 900.0

DEFAULT_TIMEOUT = 10.0
USER_AGENT = f"PhishingChecker/{__version__} (+https://github.com/sudoZHIK/phishing-checker)"


@dataclass(frozen=True, slots=True)
class ReputationReport:
    checked: bool = False
    provider: str | None = None
    malicious: bool = False
    suspicious: bool = False
    error: str | None = None
    status_code: int | None = None
    details: dict | None = None

    @property
    def configured(self) -> bool:
        return bool(self.provider)


def _timeout(value: float) -> float:
    value = float(value)
    if value <= 0:
        raise ValueError("timeout должен быть больше нуля")
    return value


def _virustotal(url: str, key: str, timeout: float) -> ReputationReport:
    encoded = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    wait_for_request("www.virustotal.com")
    try:
        response = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{encoded}",
            headers={"x-apikey": key, "User-Agent": USER_AGENT},
            timeout=timeout,
        )
    except requests.RequestException as exc:
        return ReputationReport(provider="virustotal", error=f"network error: {exc}")

    if response.status_code == 429:
        respect_retry_after(response.headers.get("Retry-After"))
        return ReputationReport(provider="virustotal", error="429 Too Many Requests", status_code=429)
    if response.status_code != 200:
        return ReputationReport(provider="virustotal", error=f"HTTP {response.status_code}", status_code=response.status_code)

    try:
        stats = response.json()["data"]["attributes"].get("last_analysis_stats", {})
    except (ValueError, KeyError, TypeError) as exc:
        return ReputationReport(provider="virustotal", error=f"invalid response: {exc}", status_code=200)

    malicious = bool(stats.get("malicious", 0))
    suspicious = bool(stats.get("suspicious", 0))
    return ReputationReport(
        checked=True,
        provider="virustotal",
        malicious=malicious,
        suspicious=suspicious,
        status_code=200,
        details={"last_analysis_stats": stats},
    )


def _gsb(url: str, key: str, timeout: float) -> ReputationReport:
    endpoint = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
    payload = {
        "client": {"clientId": "local-phishing-checker", "clientVersion": __version__},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    wait_for_request("safebrowsing.googleapis.com")
    try:
        response = requests.post(
            endpoint,
            params={"key": key},
            json=payload,
            headers={"User-Agent": USER_AGENT},
            timeout=timeout,
        )
    except requests.RequestException as exc:
        return ReputationReport(provider="google_safe_browsing", error=f"network error: {exc}")

    if response.status_code == 429:
        respect_retry_after(response.headers.get("Retry-After"))
        return ReputationReport(provider="google_safe_browsing", error="429 Too Many Requests", status_code=429)
    if response.status_code != 200:
        return ReputationReport(provider="google_safe_browsing", error=f"HTTP {response.status_code}", status_code=response.status_code)

    try:
        matches = response.json().get("matches", [])
    except (ValueError, AttributeError) as exc:
        return ReputationReport(provider="google_safe_browsing", error=f"invalid response: {exc}", status_code=200)

    return ReputationReport(
        checked=True,
        provider="google_safe_browsing",
        malicious=bool(matches),
        suspicious=bool(matches),
        status_code=200,
        details={"matches": matches},
    )


def check_reputation(url: str, timeout: float = DEFAULT_TIMEOUT) -> ReputationReport:
    """Run the first configured reputation provider; no key is required."""
    if not isinstance(url, str) or not url.strip():
        return ReputationReport(error="URL для reputation-проверки не может быть пустым")
    timeout = _timeout(timeout)

    vt_key = os.getenv("VIRUSTOTAL_API_KEY")
    if vt_key:
        namespace = "reputation:virustotal"
        key = url
        cached = cache_get(namespace, key)
        if cached:
            return ReputationReport(**cached)
        result = _virustotal(url, vt_key, timeout)
        if result.checked:
            cache_put(namespace, key, {
                "checked": result.checked,
                "provider": result.provider,
                "malicious": result.malicious,
                "suspicious": result.suspicious,
                "error": result.error,
                "status_code": result.status_code,
                "details": result.details,
            }, REPUTATION_CACHE_TTL)
        return result

    gsb_key = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY")
    if gsb_key:
        namespace = "reputation:google_safe_browsing"
        key = url
        cached = cache_get(namespace, key)
        if cached:
            return ReputationReport(**cached)
        result = _gsb(url, gsb_key, timeout)
        if result.checked:
            cache_put(namespace, key, {
                "checked": result.checked,
                "provider": result.provider,
                "malicious": result.malicious,
                "suspicious": result.suspicious,
                "error": result.error,
                "status_code": result.status_code,
                "details": result.details,
            }, REPUTATION_CACHE_TTL)
        return result

    return ReputationReport(error="Репутационный провайдер не настроен")


__all__ = ["DEFAULT_TIMEOUT", "ReputationReport", "check_reputation"]
