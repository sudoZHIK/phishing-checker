"""Human-readable Russian report text for Phishing Checker.

Pure functions: no Tk, no network. The GUI renders the (tag, text) lines;
``readable_report_text`` returns the same content as plain text for copying.

Wording rule: LOW never means "safe", only "no risk signs were detected".
Network failures, timeouts and API limits are not phishing evidence.
"""

from __future__ import annotations

from urllib.parse import parse_qsl, urlsplit

from .checks import (
    REASON_INVALID_URL,
    REASON_NETWORK_DISABLED,
    REASON_NO_CONTENT,
    REASON_NO_RESPONSE,
    REASON_NOT_HTTPS,
    STATUS_FAILED,
    STATUS_NOT_CONFIGURED,
    STATUS_PASSED,
    STATUS_SKIPPED,
)
from .models import AnalysisReport, CheckResult

Line = tuple[str, str]

RISK_TITLES = {
    "LOW": "НИЗКИЙ РИСК",
    "CAUTION": "ОСТОРОЖНО",
    "SUSPICIOUS": "ПОДОЗРИТЕЛЬНО",
    "HIGH": "ВЫСОКИЙ РИСК",
}

COVERAGE_TITLES = {
    "COMPLETE": "ПОЛНАЯ",
    "PARTIAL": "ПРОВЕРКА НЕПОЛНАЯ",
    "NOT_CHECKED": "НЕ ПРОВЕРЕНО",
}

CHECK_INFO = {
    "url": (
        "Адрес (URL)",
        ("Разбор адреса и поиск приёмов маскировки: символ «@», IP-адрес вместо "
        "имени сайта, слишком длинный адрес, много дефисов или поддоменов, "
        "нестандартный порт, необычные символы в домене."),
    ),
    "brand": (
        "Сходство с известными брендами",
        ("Сравнение домена с названиями популярных сервисов: подделки часто "
        "отличаются от оригинала одной буквой."),
    ),
    "dns": (
        "DNS",
        "Проверка, что домен существует и находится в системе доменных имён.",
    ),
    "rdap": (
        "Данные о регистрации домена (RDAP)",
        "Запрос открытых данных о регистрации домена.",
    ),
    "tls": (
        "Сертификат HTTPS (TLS)",
        "Проверка защищённого соединения и сертификата сайта.",
    ),
    "http": (
        "Ответ сайта (HTTP)",
        ("Один запрос GET без выполнения JavaScript. Переадресации проверяются "
        "повторно, обращения к локальным и служебным адресам блокируются."),
    ),
    "html": (
        "Содержимое страницы (HTML)",
        ("Статический разбор страницы: поля ввода пароля и формы, которые "
        "отправляют данные на другой домен."),
    ),
    "reputation": (
        "Репутационные сервисы",
        ("Необязательная проверка в VirusTotal или Google Safe Browsing. "
        "Нужен собственный ключ API."),
    ),
}

URL_CODES = frozenset(
    {
        "AT_SIGN",
        "IP_HOST",
        "LONG_URL",
        "MANY_HYPHENS",
        "DEEP_SUBDOMAIN",
        "NON_STANDARD_PORT",
        "IDN_PUNYCODE",
        "CREDENTIAL_PATH",
    }
)

HTML_CODES = frozenset({"HTML_PASSWORD_INPUT", "HTML_EXTERNAL_FORM"})
REPUTATION_CODES = frozenset({"REPUTATION_MALICIOUS", "REPUTATION_SUSPICIOUS"})

EVIDENCE_HELP = {
    "AT_SIGN": (
        "Всё, что стоит до «@», браузер считает логином, а настоящий сайт указан "
        "после него. Так маскируют поддельные ссылки под знакомые адреса."
    ),
    "IP_HOST": (
        "Вместо имени сайта указан IP-адрес. Настоящие сервисы почти всегда "
        "используют понятные доменные имена."
    ),
    "IDN_PUNYCODE": (
        "Домен содержит символы не только латиницы. Некоторые буквы других "
        "алфавитов выглядят как латинские и используются для подмены."
    ),
    "BRAND_SIMILARITY": (
        "Домен похож на название известного сервиса, но может не быть его "
        "официальным адресом. Сравните адрес с тем, который вы знаете."
    ),
    "CREDENTIAL_PATH": (
        "В пути адреса есть слова, связанные со входом или подтверждением "
        "данных. Само по себе это не доказательство, но так часто оформляют "
        "поддельные страницы входа."
    ),
    "DEEP_SUBDOMAIN": (
        "В адресе много уровней поддоменов. Настоящий домен при этом может "
        "оказаться совсем не там, где вы его ждёте."
    ),
    "LONG_URL": (
        "Очень длинный адрес. В длинных адресах легко спрятать важную часть."
    ),
    "MANY_HYPHENS": (
        "Много дефисов в имени домена. Такие имена часто используют, когда "
        "подбирают адрес, похожий на настоящий."
    ),
    "NON_STANDARD_PORT": (
        "Сайт открывается на необычном порту. Для обычных сайтов это редкость."
    ),
    "HTML_PASSWORD_INPUT": (
        "На странице есть поле ввода пароля. Это нормально для настоящего входа, "
        "поэтому важно убедиться, что вы на нужном сайте."
    ),
    "HTML_EXTERNAL_FORM": (
        "Форма на странице отправляет данные на другой домен. Проверьте, "
        "доверяете ли вы получателю."
    ),
    "REPUTATION_MALICIOUS": (
        "Внешний репутационный сервис сообщил о вредоносной активности для этой "
        "ссылки."
    ),
    "REPUTATION_SUSPICIOUS": (
        "Внешний репутационный сервис сообщил о подозрительной активности для "
        "этой ссылки."
    ),
}

PROVIDER_NAMES = {
    "virustotal": "VirusTotal",
    "google_safe_browsing": "Google Safe Browsing",
}

STATUS_VIEW = {
    STATUS_PASSED: ("✓", "ok", "выполнена"),
    STATUS_FAILED: ("⚠", "warn", "не удалось выполнить"),
    STATUS_SKIPPED: ("–", "muted", "пропущена"),
    STATUS_NOT_CONFIGURED: ("–", "muted", "не настроена"),
}

SKIP_TEXTS = {
    REASON_NETWORK_DISABLED: "Пропущено: сетевые проверки отключены.",
    REASON_NOT_HTTPS: (
        "Адрес начинается с http://, соединение не шифруется, проверять "
        "сертификат нечего."
    ),
    REASON_NO_RESPONSE: "Пропущено: страница не была получена.",
    REASON_NO_CONTENT: "Пропущено: страница не вернула содержимого для разбора.",
    REASON_INVALID_URL: "Пропущено: адрес не удалось разобрать.",
}

VERDICTS = {
    "LOW": (
        "ok",
        ("Явных признаков фишинга в проверенных данных не обнаружено. Это не "
        "означает, что сайт безопасен: часть проверок могла не выполняться, а "
        "новые поддельные сайты не всегда заметны."),
    ),
    "CAUTION": (
        "warn",
        ("Обнаружены отдельные подозрительные признаки. Проверьте адрес сайта "
        "перед вводом важных данных."),
    ),
    "SUSPICIOUS": (
        "warn",
        ("Обнаружено несколько тревожных признаков. Не вводите пароли и данные "
        "карты, пока не убедитесь, что адрес настоящий."),
    ),
    "HIGH": (
        "bad",
        ("Обнаружены серьёзные признаки фишинга. Не вводите пароль, данные карты "
        "или коды подтверждения на этом сайте."),
    ),
}

ADVICE = {
    "LOW": (
        "Явных признаков фишинга не обнаружено. Это не гарантирует абсолютную "
        "безопасность сайта."
    ),
    "CAUTION": (
        "Обнаружены отдельные подозрительные признаки. Проверьте адрес сайта "
        "перед вводом важных данных."
    ),
    "SUSPICIOUS": (
        "Будьте осторожны. Перед вводом важных данных внимательно проверьте "
        "домен и адрес страницы."
    ),
    "HIGH": (
        "Не вводите пароль, данные карты или коды подтверждения на этом сайте. "
        "Если вы уже что-то ввели, смените пароль и свяжитесь с сервисом."
    ),
}

GENERAL_TIP = (
    "Если ссылка пришла в письме или сообщении, откройте нужный сайт вручную, "
    "набрав адрес сами или через закладку."
)


def mask_url(url: str) -> str:
    """scheme://host/path?<redacted:N>: без userinfo, query и fragment."""
    try:
        parts = urlsplit(url.strip())
    except ValueError:
        return "<некорректный URL>"

    host = parts.netloc.rsplit("@", 1)[-1]
    if parts.scheme:
        base = f"{parts.scheme}://{host}{parts.path}"
    else:
        base = f"{host}{parts.path}"

    if parts.query:
        count = len(parse_qsl(parts.query, keep_blank_values=True))
        base += f"?<redacted:{count}>"

    return base


def _passed_text(check: CheckResult, codes: set[str]) -> str:
    name = check.name

    if name == "url":
        if codes & URL_CODES:
            return "В самом адресе найдены признаки риска (см. ниже)."
        return "Подозрительных приёмов в самом адресе не найдено."
    if name == "brand":
        if "BRAND_SIMILARITY" in codes:
            return "Домен похож на известный бренд (см. ниже)."
        return "Явного сходства с известными брендами не найдено."
    if name == "dns":
        return "Запросы к DNS выполнены успешно."
    if name == "rdap":
        return "Данные о регистрации домена получены."
    if name == "tls":
        return "Защищённое соединение проверено."
    if name == "http":
        if check.message:
            return f"Страница ответила (код {check.message})."
        return "Страница ответила."
    if name == "html":
        if codes & HTML_CODES:
            return "На странице найдены элементы, требующие внимания (см. ниже)."
        return "Тревожных элементов на странице не найдено."
    if name == "reputation":
        provider = PROVIDER_NAMES.get(check.message, check.message or "сервис")
        if codes & REPUTATION_CODES:
            return f"{provider} сообщил об угрозе (см. ниже)."
        return f"{provider} не сообщил об угрозах для этой ссылки."
    return "Выполнено."


def _failed_text(check: CheckResult) -> str:
    if check.message == "429":
        text = "Сайт ограничил число запросов (код 429), проверка не завершена."
    elif check.name == "reputation" and check.error and "429" in check.error:
        text = "Сервис ограничил число запросов (429), проверка не завершена."
    elif check.error:
        text = f"Проверку выполнить не удалось: {check.error}."
    else:
        text = "Проверку выполнить не удалось."
    return text + " Это не признак фишинга: проверка просто осталась неполной."


def _result_text(check: CheckResult, codes: set[str]) -> str:
    if check.status == STATUS_PASSED:
        return _passed_text(check, codes)
    if check.status == STATUS_FAILED:
        return _failed_text(check)
    if check.status == STATUS_NOT_CONFIGURED:
        return (
            "Не проверялось: ключ API не задан. Это необязательно, программа "
            "работает и без ключей. Ключ можно указать в «Настройки → API-ключи»."
        )
    return SKIP_TEXTS.get(check.message, "Пропущено.")


def _evidence_lines(report: AnalysisReport) -> list[Line]:
    lines: list[Line] = [("section", "НАЙДЕННЫЕ ПРИЗНАКИ")]

    if not report.evidence:
        lines.append(
            ("ok", "✓ Подозрительных признаков в проверенных данных не обнаружено.")
        )
        return lines

    for item in report.evidence:
        marker, tag = {
            "high": ("✕", "bad"),
            "medium": ("⚠", "warn"),
            "low": ("⚠", "warn"),
        }.get(item.severity, ("•", "muted"))

        weight = f"  [+{item.weight} к риску]" if item.weight else ""
        lines.append((f"{tag}_b", f"{marker} {item.message}{weight}"))

        help_text = EVIDENCE_HELP.get(item.code)
        if help_text:
            lines.append(("res", f"Что это значит: {help_text}"))

        for key, value in item.details.items():
            lines.append(("desc", f"{key}: {value}"))

    return lines


def _remaining_errors(report: AnalysisReport) -> list[str]:
    shown = [check.error for check in report.checks if check.error]
    return [
        error
        for error in report.errors
        if not any(text in error for text in shown)
    ]


def build_readable_report(report: AnalysisReport, url: str = "") -> list[Line]:
    """Return (tag, text) lines of the human-readable report."""
    lines: list[Line] = []
    add = lines.append

    level = report.risk_level
    coverage = report.coverage
    verdict_tag, verdict_text = VERDICTS.get(
        level,
        ("muted", "Уровень риска не определён."),
    )

    add(("title", "РЕЗУЛЬТАТ ПРОВЕРКИ"))
    if url:
        add(("muted", f"Ссылка: {mask_url(url)}"))
    add(("blank", ""))

    add(
        (
            "body_b",
            (f"Риск-оценка: {report.risk_score}/100 — "
            f"{RISK_TITLES.get(level, 'НЕ ОПРЕДЕЛЁН')}"),
        )
    )
    add(
        (
            "body_b",
            (f"Полнота проверки: {coverage.passed}/{coverage.total} — "
            f"{coverage.percent:.0f}% — "
            f"{COVERAGE_TITLES.get(coverage.status, coverage.status)}"),
        )
    )
    add(("blank", ""))
    add((verdict_tag, verdict_text))

    if coverage.status == "NOT_CHECKED":
        add(("muted", "Проверка не выполнялась."))
    elif coverage.status == "PARTIAL":
        add(
            (
                "muted",
                (f"Проверка выполнена не полностью ({coverage.passed} из "
                f"{coverage.total}). Сетевые сбои, таймауты и лимиты API не "
                "считаются признаком фишинга: они только снижают полноту."),
            )
        )

    add(("blank", ""))
    add(("section", "ЧТО ПРОВЕРЯЛОСЬ"))

    codes = {item.code for item in report.evidence}

    if report.checks:
        for check in report.checks:
            title, what = CHECK_INFO.get(check.name, (check.name, ""))
            icon, tag, word = STATUS_VIEW.get(check.status, ("•", "muted", check.status))
            add((f"{tag}_b", f"{icon} {title} — {word}"))
            if what:
                add(("desc", what))
            add(("res", _result_text(check, codes)))
            add(("blank", ""))
    else:
        add(
            (
                "muted",
                (f"Выполнено проверок: {coverage.passed} из {coverage.total}. "
                "Подробности по каждой проверке недоступны."),
            )
        )
        add(("blank", ""))

    lines.extend(_evidence_lines(report))
    add(("blank", ""))

    extra_errors = _remaining_errors(report)
    if extra_errors:
        add(("section", "ДОПОЛНИТЕЛЬНЫЕ СООБЩЕНИЯ О СБОЯХ"))
        for error in extra_errors:
            add(("warn", f"⚠ {error}"))
        add(("blank", ""))

    add(("section", "ЧТО ДЕЛАТЬ"))
    add(("body", ADVICE.get(level, "Проверьте адрес сайта перед вводом данных.")))
    add(("body", GENERAL_TIP))
    add(("blank", ""))
    add(
        (
            "muted",
            "Результат — автоматическая оценка, а не гарантия безопасности сайта.",
        )
    )

    return lines


def readable_report_text(report: AnalysisReport, url: str = "") -> str:
    """Plain-text version of the readable report (for copying)."""
    return "\n".join(text for _tag, text in build_readable_report(report, url))
