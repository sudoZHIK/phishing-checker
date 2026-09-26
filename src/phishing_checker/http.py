"""Safe HTTP fetching with SSRF and DNS-rebinding protection."""

from __future__ import annotations

import ipaddress
import socket
import threading
import time
from dataclasses import dataclass, field
from urllib.parse import urljoin

import requests

from . import __version__
from .analyzer import normalize_url
from .network_guard import respect_retry_after, wait_for_request

DEFAULT_CONNECT_TIMEOUT = 5.0
DEFAULT_READ_TIMEOUT = 10.0
DEFAULT_OVERALL_TIMEOUT = 30.0
DEFAULT_MAX_REDIRECTS = 10
DEFAULT_MAX_BODY_BYTES = 2_000_000

USER_AGENT = (
    f"PhishingChecker/{__version__} "
    "(+https://github.com/sudoZHIK/phishing-checker)"
)

# Requests/urllib3 resolves hostnames through socket.getaddrinfo().
# We temporarily pin that resolution to the IPs we already validated.
# The lock prevents another checker request in the same process from
# observing the temporary resolver override.
_RESOLUTION_LOCK = threading.RLock()


class HTTPFetchError(Exception):
    """Base error for safe HTTP fetching."""


class HTTPSSRFBlocked(HTTPFetchError):
    """Raised when a destination resolves to a blocked address."""


class HTTPResolutionError(HTTPFetchError):
    """Raised when hostname resolution fails or returns no usable IPs."""


@dataclass(frozen=True, slots=True)
class ResolvedAddress:
    """Validated destination address."""

    hostname: str
    ip: str
    family: int


@dataclass(slots=True)
class HTTPReport:
    """Result of one safe target-page HTTP fetch."""

    url: str
    final_url: str | None = None
    status_code: int | None = None
    content_type: str | None = None
    content_length: int | None = None
    body: bytes = b""
    redirects: int = 0
    checked: bool = False
    error: str | None = None
    blocked: bool = False
    resolved_ips: list[str] = field(default_factory=list)

    @property
    def success(self) -> bool:
        return self.checked and self.status_code is not None

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "final_url": self.final_url,
            "status_code": self.status_code,
            "content_type": self.content_type,
            "content_length": self.content_length,
            "redirects": self.redirects,
            "checked": self.checked,
            "error": self.error,
            "blocked": self.blocked,
            "resolved_ips": list(self.resolved_ips),
        }


def _validate_timeout(name: str, value: float) -> float:
    try:
        result = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} должен быть числом") from exc

    if result <= 0:
        raise ValueError(f"{name} должен быть больше нуля")

    return result


def _is_blocked_ip(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Return True for non-public/special-use addresses.

    This intentionally blocks more than only RFC1918:
    loopback, link-local, multicast, unspecified, reserved and other
    non-global destinations are not valid default Internet targets.
    """

    return not address.is_global


def _resolve_hostname(
    hostname: str,
    *,
    port: int,
    allow_private: bool,
) -> list[ResolvedAddress]:
    """Resolve hostname and validate every returned address."""

    try:
        infos = socket.getaddrinfo(
            hostname,
            port,
            type=socket.SOCK_STREAM,
        )
    except socket.gaierror as exc:
        raise HTTPResolutionError(
            f"DNS не удалось разрешить hostname: {exc}"
        ) from exc
    except OSError as exc:
        raise HTTPResolutionError(
            f"Ошибка разрешения hostname: {exc}"
        ) from exc

    addresses: list[ResolvedAddress] = []
    seen: set[tuple[int, str]] = set()

    for family, _socktype, _proto, _canonname, sockaddr in infos:
        if family not in (socket.AF_INET, socket.AF_INET6):
            continue

        ip_text = sockaddr[0]

        try:
            address = ipaddress.ip_address(ip_text)
        except ValueError:
            continue

        key = (family, address.compressed)
        if key in seen:
            continue
        seen.add(key)

        if not allow_private and _is_blocked_ip(address):
            raise HTTPSSRFBlocked(
                f"HTTP-запрос заблокирован: {hostname} "
                f"разрешается в непубличный IP {address}"
            )

        addresses.append(
            ResolvedAddress(
                hostname=hostname,
                ip=address.compressed,
                family=family,
            )
        )

    if not addresses:
        raise HTTPResolutionError(
            f"Hostname {hostname!r} не имеет подходящих A/AAAA-адресов"
        )

    return addresses


def _resolve_destination(
    hostname: str,
    *,
    port: int,
    allow_private: bool,
) -> list[ResolvedAddress]:
    """Resolve an IP literal or hostname."""

    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        return _resolve_hostname(
            hostname,
            port=port,
            allow_private=allow_private,
        )

    if not allow_private and _is_blocked_ip(address):
        raise HTTPSSRFBlocked(
            f"HTTP-запрос заблокирован: непубличный IP {address}"
        )

    family = socket.AF_INET6 if address.version == 6 else socket.AF_INET

    return [
        ResolvedAddress(
            hostname=hostname,
            ip=address.compressed,
            family=family,
        )
    ]


def _patched_getaddrinfo(
    approved: list[ResolvedAddress],
    original_getaddrinfo,
):
    """Create a resolver returning only already-approved addresses."""

    def getaddrinfo(
        host,
        port,
        family=0,
        type=0,
        proto=0,
        flags=0,
    ):
        # Only pin the destination hostname. Other DNS lookups performed
        # internally by unrelated libraries are passed through unchanged.
        if isinstance(host, str) and host.lower().rstrip(".") == approved[0].hostname.lower().rstrip("."):
            result = []

            for item in approved:
                if family not in (0, item.family):
                    continue
                if type not in (0, socket.SOCK_STREAM):
                    continue

                if item.family == socket.AF_INET:
                    sockaddr = (item.ip, port)
                else:
                    sockaddr = (item.ip, port, 0, 0)

                result.append(
                    (
                        item.family,
                        socket.SOCK_STREAM,
                        socket.IPPROTO_TCP,
                        "",
                        sockaddr,
                    )
                )

            if result:
                return result

        return original_getaddrinfo(
            host,
            port,
            family,
            type,
            proto,
            flags,
        )

    return getaddrinfo


def _remaining(deadline: float) -> float:
    remaining = deadline - time.monotonic()

    if remaining <= 0:
        raise HTTPFetchError("Превышен общий таймаут HTTP-проверки")

    return remaining


def _request_once(
    session: requests.Session,
    url: str,
    *,
    hostname: str,
    port: int,
    approved: list[ResolvedAddress],
    connect_timeout: float,
    read_timeout: float,
    deadline: float,
) -> requests.Response:
    """Perform exactly one GET while pinning DNS resolution."""

    remaining = _remaining(deadline)

    timeout = (
        min(connect_timeout, remaining),
        min(read_timeout, remaining),
    )

    original_getaddrinfo = socket.getaddrinfo
    socket.getaddrinfo = _patched_getaddrinfo(
        approved,
        original_getaddrinfo,
    )

    wait_for_request(hostname)
    try:
        return session.get(
            url,
            allow_redirects=False,
            timeout=timeout,
            stream=True,
        )
    finally:
        socket.getaddrinfo = original_getaddrinfo


def _read_body(
    response: requests.Response,
    *,
    max_body_bytes: int,
    deadline: float,
) -> bytes:
    """Read at most max_body_bytes from a streaming response."""

    remaining = _remaining(deadline)

    # Content-Length is advisory; the stream is still capped below.
    header_length = response.headers.get("Content-Length")

    if header_length:
        try:
            if int(header_length) > max_body_bytes:
                raise HTTPFetchError(
                    f"Ответ превышает лимит {max_body_bytes} байт"
                )
        except ValueError:
            pass

    chunks: list[bytes] = []
    total = 0

    # The read timeout is controlled by requests/urllib3. The overall
    # deadline is checked between chunks.
    response.raw.decode_content = True

    while True:
        _remaining(deadline)

        chunk = response.raw.read(
            min(64 * 1024, max_body_bytes - total + 1)
        )

        if not chunk:
            break

        total += len(chunk)

        if total > max_body_bytes:
            raise HTTPFetchError(
                f"Ответ превышает лимит {max_body_bytes} байт"
            )

        chunks.append(chunk)

        # Avoid an unused local warning while documenting the deadline
        # intent explicitly.
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise HTTPFetchError(
                "Превышен общий таймаут чтения HTTP-ответа"
            )

    return b"".join(chunks)


def fetch_url(
    url: str,
    *,
    connect_timeout: float = DEFAULT_CONNECT_TIMEOUT,
    read_timeout: float = DEFAULT_READ_TIMEOUT,
    overall_timeout: float = DEFAULT_OVERALL_TIMEOUT,
    max_redirects: int = DEFAULT_MAX_REDIRECTS,
    max_body_bytes: int = DEFAULT_MAX_BODY_BYTES,
    allow_private: bool = False,
) -> HTTPReport:
    """Safely GET one target page with manual redirect validation.

    Security properties:
    - HTTP/HTTPS only through normalize_url().
    - private/loopback/link-local/special IPs blocked by default.
    - DNS resolution is validated before every request.
    - DNS resolution is pinned during the actual socket connection.
    - redirects are followed manually and revalidated.
    - maximum redirects are bounded.
    - response body is size-limited.
    - connect/read and overall wall-clock timeouts are enforced.
    - only one target-page request chain is performed; no crawling.
    """

    connect_timeout = _validate_timeout(
        "connect_timeout",
        connect_timeout,
    )
    read_timeout = _validate_timeout(
        "read_timeout",
        read_timeout,
    )
    overall_timeout = _validate_timeout(
        "overall_timeout",
        overall_timeout,
    )

    if not isinstance(max_redirects, int) or max_redirects < 0:
        raise ValueError("max_redirects должен быть целым числом >= 0")

    if not isinstance(max_body_bytes, int) or max_body_bytes <= 0:
        raise ValueError("max_body_bytes должен быть целым числом > 0")

    try:
        normalized = normalize_url(url)
    except (TypeError, ValueError) as exc:
        return HTTPReport(
            url=str(url),
            error=str(exc),
        )

    report = HTTPReport(url=normalized.normalized)
    deadline = time.monotonic() + overall_timeout

    current_url = normalized.normalized

    # Prevent concurrent requests from interfering with the temporary
    # getaddrinfo pinning.
    with _RESOLUTION_LOCK:
        session = requests.Session()
        session.trust_env = False
        session.headers.update({"User-Agent": USER_AGENT})

        try:
            for redirect_number in range(max_redirects + 1):
                _remaining(deadline)

                current = normalize_url(current_url)

                try:
                    approved = _resolve_destination(
                        current.hostname_ascii,
                        port=current.port
                        or (443 if current.scheme == "https" else 80),
                        allow_private=allow_private,
                    )
                except HTTPSSRFBlocked as exc:
                    report.blocked = True
                    report.error = str(exc)

                    if current.is_ip and current.hostname_ascii:
                        report.resolved_ips = [current.hostname_ascii]

                    return report

                except HTTPResolutionError as exc:
                    report.error = f"DNS resolution error: {exc}"
                    return report

                report.resolved_ips = [item.ip for item in approved]

                response = None

                try:
                    response = _request_once(
                        session,
                        current.normalized,
                        hostname=current.hostname_ascii,
                        port=current.port
                        or (443 if current.scheme == "https" else 80),
                        approved=approved,
                        connect_timeout=connect_timeout,
                        read_timeout=read_timeout,
                        deadline=deadline,
                    )

                    report.status_code = response.status_code
                    report.final_url = current.normalized
                    if response.status_code == 429:
                        respect_retry_after(response.headers.get("Retry-After"))
                        report.error = "HTTP 429 Too Many Requests"
                        return report
                    report.content_type = response.headers.get("Content-Type")

                    if response.is_redirect:
                        location = response.headers.get("Location")

                        if not location:
                            report.checked = True
                            report.error = (
                                "HTTP-редирект не содержит Location"
                            )
                            return report

                        if redirect_number >= max_redirects:
                            report.error = (
                                f"Превышен лимит редиректов: "
                                f"{max_redirects}"
                            )
                            return report

                        next_url = urljoin(current.normalized, location)

                        try:
                            next_normalized = normalize_url(next_url)
                        except (TypeError, ValueError) as exc:
                            report.error = (
                                f"Некорректный URL редиректа: {exc}"
                            )
                            return report

                        # Validate the redirect destination immediately,
                        # before issuing the next network request.
                        _resolve_destination(
                            next_normalized.hostname_ascii,
                            port=next_normalized.port
                            or (
                                443
                                if next_normalized.scheme == "https"
                                else 80
                            ),
                            allow_private=allow_private,
                        )

                        current_url = next_normalized.normalized
                        report.redirects += 1
                        continue

                    report.body = _read_body(
                        response,
                        max_body_bytes=max_body_bytes,
                        deadline=deadline,
                    )
                    report.content_length = len(report.body)
                    report.checked = True
                    return report

                except HTTPSSRFBlocked as exc:
                    report.blocked = True
                    report.error = str(exc)
                    return report

                except HTTPResolutionError as exc:
                    report.error = str(exc)
                    return report

                except requests.exceptions.Timeout as exc:
                    report.error = f"HTTP timeout: {exc}"
                    return report

                except requests.exceptions.ProxyError as exc:
                    report.error = f"HTTP proxy error: {exc}"
                    return report

                except requests.exceptions.RequestException as exc:
                    report.error = f"HTTP request error: {type(exc).__name__}: {exc}"
                    return report

                except HTTPFetchError as exc:
                    report.error = str(exc)
                    return report

                finally:
                    if response is not None:
                        response.close()

        finally:
            session.close()

    report.error = "HTTP-проверка завершилась без результата"
    return report


__all__ = [
    "DEFAULT_CONNECT_TIMEOUT",
    "DEFAULT_MAX_BODY_BYTES",
    "DEFAULT_MAX_REDIRECTS",
    "DEFAULT_OVERALL_TIMEOUT",
    "DEFAULT_READ_TIMEOUT",
    "USER_AGENT",
    "HTTPFetchError",
    "HTTPReport",
    "HTTPResolutionError",
    "HTTPSSRFBlocked",
    "ResolvedAddress",
    "fetch_url",
]
