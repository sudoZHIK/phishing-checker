"""Passive TLS certificate inspection for Phishing Checker."""

from __future__ import annotations

import ipaddress
import socket
import ssl
from dataclasses import dataclass

DEFAULT_TIMEOUT = 5.0


class TLSCheckError(Exception):
    """Base error for TLS inspection."""


class TLSBlockedError(TLSCheckError):
    """Raised when TLS destination is not publicly routable."""


@dataclass(frozen=True, slots=True)
class TLSReport:
    """Result of one TLS certificate check."""

    hostname: str
    port: int
    checked: bool = False
    verified: bool = False
    tls_version: str | None = None
    cipher: str | None = None
    subject: str | None = None
    issuer: str | None = None
    error: str | None = None

    @property
    def success(self) -> bool:
        return self.checked


def _is_blocked_ip(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Return True for non-public/special-use destinations."""
    return (
        address.is_loopback
        or address.is_private
        or address.is_link_local
        or address.is_reserved
        or address.is_multicast
        or address.is_unspecified
    )


def _resolve_public_addresses(
    hostname: str,
    port: int,
    *,
    allow_private: bool,
) -> list[tuple[int, str]]:
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        address = None

    if address is not None:
        if not allow_private and _is_blocked_ip(address):
            raise TLSBlockedError("TLS-запрос заблокирован: непубличный IP")
        family = socket.AF_INET6 if address.version == 6 else socket.AF_INET
        return [(family, address.compressed)]

    try:
        resolved = socket.getaddrinfo(
            hostname,
            port,
            type=socket.SOCK_STREAM,
        )
    except socket.gaierror as exc:
        raise TLSCheckError(f"TLS DNS error: {exc}") from exc

    result: list[tuple[int, str]] = []
    seen: set[tuple[int, str]] = set()

    for family, _, _, _, sockaddr in resolved:
        ip_text = sockaddr[0]

        try:
            address = ipaddress.ip_address(ip_text)
        except ValueError:
            continue

        if not allow_private and _is_blocked_ip(address):
            raise TLSBlockedError(
                f"TLS-запрос заблокирован: непубличный IP {address}"
            )

        item = (family, address.compressed)
        if item not in seen:
            seen.add(item)
            result.append(item)

    if not result:
        raise TLSCheckError("TLS DNS error: не найден публичный IP")

    return result


def check_tls(
    hostname: str,
    *,
    port: int = 443,
    timeout: float = DEFAULT_TIMEOUT,
    allow_private: bool = False,
) -> TLSReport:
    """Perform one bounded TLS handshake without following redirects."""
    if not isinstance(hostname, str) or not hostname.strip():
        return TLSReport(
            hostname=str(hostname),
            port=port,
            error="TLS hostname не может быть пустым",
        )

    if not isinstance(port, int) or not 1 <= port <= 65535:
        return TLSReport(
            hostname=hostname,
            port=port,
            error="TLS порт должен находиться в диапазоне 1..65535",
        )

    if not isinstance(timeout, (int, float)) or timeout <= 0:
        raise ValueError("timeout должен быть числом > 0")

    hostname = hostname.strip().rstrip(".").lower()

    try:
        addresses = _resolve_public_addresses(
            hostname,
            port,
            allow_private=allow_private,
        )
    except TLSCheckError as exc:
        return TLSReport(
            hostname=hostname,
            port=port,
            error=str(exc),
        )

    context = ssl.create_default_context()

    last_error: str | None = None

    for family, ip_text in addresses:
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.settimeout(float(timeout))

        try:
            target = (
                (ip_text, port, 0, 0)
                if family == socket.AF_INET6
                else (ip_text, port)
            )
            sock.connect(target)

            with context.wrap_socket(
                sock,
                server_hostname=hostname,
            ) as tls_socket:
                certificate = tls_socket.getpeercert()
                cipher_info = tls_socket.cipher()

                subject = None
                issuer = None

                if certificate:
                    subject = str(certificate.get("subject", ""))
                    issuer = str(certificate.get("issuer", ""))

                return TLSReport(
                    hostname=hostname,
                    port=port,
                    checked=True,
                    verified=True,
                    tls_version=tls_socket.version(),
                    cipher=cipher_info[0] if cipher_info else None,
                    subject=subject,
                    issuer=issuer,
                )

        except TLSBlockedError:
            raise
        except (OSError, ssl.SSLError) as exc:
            last_error = f"{type(exc).__name__}: {exc}"
        finally:
            try:
                sock.close()
            except OSError:
                pass

    return TLSReport(
        hostname=hostname,
        port=port,
        error=f"TLS handshake error: {last_error or 'неизвестная ошибка'}",
    )


__all__ = [
    "DEFAULT_TIMEOUT",
    "TLSBlockedError",
    "TLSCheckError",
    "TLSReport",
    "check_tls",
]
