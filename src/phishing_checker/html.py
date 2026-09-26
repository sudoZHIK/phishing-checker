"""Static HTML inspection for Phishing Checker."""

from __future__ import annotations

from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

from .models import Evidence

SUSPICIOUS_FORM_WORDS = (
    "login",
    "signin",
    "sign-in",
    "verify",
    "verification",
    "account",
    "password",
    "credential",
    "wallet",
    "billing",
    "recover",
    "confirm",
)


@dataclass(slots=True)
class HTMLReport:
    """Result of static HTML inspection."""

    checked: bool = False
    evidence: list[Evidence] = field(default_factory=list)
    error: str | None = None
    forms: int = 0
    password_inputs: int = 0
    external_links: int = 0

    def to_dict(self) -> dict:
        return {
            "checked": self.checked,
            "forms": self.forms,
            "password_inputs": self.password_inputs,
            "external_links": self.external_links,
            "error": self.error,
            "evidence": [item.to_dict() for item in self.evidence],
        }


class _StaticHTMLParser(HTMLParser):
    def __init__(self, target_url: str) -> None:
        super().__init__(convert_charrefs=True)
        self.target_url = target_url
        self.target_host = (urlsplit(target_url).hostname or "").lower()

        self.forms: list[dict[str, str]] = []
        self.password_inputs = 0
        self.links: list[str] = []
        self._current_form: dict[str, str] | None = None

    def handle_starttag(self, tag: str, attrs) -> None:
        values = {str(key).lower(): str(value or "") for key, value in attrs}

        if tag.lower() == "form":
            self._current_form = {
                "action": values.get("action", ""),
                "method": values.get("method", "get").lower(),
            }
            self.forms.append(self._current_form)

        elif tag.lower() == "input":
            input_type = values.get("type", "").lower()
            if input_type == "password":
                self.password_inputs += 1

        elif tag.lower() in {"a", "link"}:
            href = values.get("href", "")
            if href:
                self.links.append(href)

    def handle_startendtag(self, tag: str, attrs) -> None:
        self.handle_starttag(tag, attrs)


def analyze_html(
    body: bytes | str,
    *,
    base_url: str,
    max_bytes: int = 2_000_000,
) -> HTMLReport:
    """Analyze already-fetched HTML without executing active content."""
    if not isinstance(body, (bytes, str)):
        return HTMLReport(error="HTML body должен быть bytes или str")

    if max_bytes <= 0:
        raise ValueError("max_bytes должен быть > 0")

    if isinstance(body, bytes):
        if len(body) > max_bytes:
            return HTMLReport(
                error=f"HTML превышает лимит {max_bytes} байт"
            )
        text = body.decode("utf-8", errors="replace")
    else:
        encoded = body.encode("utf-8", errors="replace")
        if len(encoded) > max_bytes:
            return HTMLReport(
                error=f"HTML превышает лимит {max_bytes} байт"
            )
        text = body

    try:
        parser = _StaticHTMLParser(base_url)
        parser.feed(text)
        parser.close()
    except (ValueError, TypeError, UnicodeError) as exc:
        return HTMLReport(
            error=f"HTML parse error: {type(exc).__name__}: {exc}"
        )

    evidence: list[Evidence] = []

    if parser.password_inputs:
        evidence.append(
            Evidence(
                code="HTML_PASSWORD_INPUT",
                message="HTML содержит поле для ввода пароля.",
                weight=0,
                severity="info",
                details={"count": parser.password_inputs},
            )
        )

    suspicious_forms = 0

    for form in parser.forms:
        action = form["action"]

        if not action:
            continue

        absolute = urljoin(base_url, action)
        action_host = (urlsplit(absolute).hostname or "").lower()

        if action_host and action_host != parser.target_host:
            suspicious_forms += 1

    if suspicious_forms:
        evidence.append(
            Evidence(
                code="HTML_EXTERNAL_FORM",
                message="Форма отправляет данные на другой hostname.",
                weight=10,
                severity="medium",
                details={"count": suspicious_forms},
            )
        )

    external_links = 0

    for href in parser.links:
        absolute = urljoin(base_url, href)
        parsed = urlsplit(absolute)
        link_host = (parsed.hostname or "").lower()

        if (
            parsed.scheme in {"http", "https"}
            and link_host
            and link_host != parser.target_host
        ):
            external_links += 1

    return HTMLReport(
        checked=True,
        evidence=evidence,
        forms=len(parser.forms),
        password_inputs=parser.password_inputs,
        external_links=external_links,
    )


__all__ = [
    "HTMLReport",
    "analyze_html",
]
