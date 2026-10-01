"""Command-line interface for Phishing Checker."""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import logging
from pathlib import Path

from . import __version__
from .analyzer import analyze

LOGGER = logging.getLogger(__name__)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="phishing-checker",
        description="Локальная защитная проверка URL на признаки фишинга.",
    )

    parser.add_argument(
        "url",
        nargs="*",
        help="Один или несколько URL для проверки",
    )

    parser.add_argument(
        "--batch",
        metavar="FILE",
        help="Файл со списком URL, по одному URL на строку.",
    )

    parser.add_argument(
        "--fail-on-high",
        action="store_true",
        help="Вернуть код 10, если хотя бы один URL получил HIGH.",
    )

    parser.add_argument(
        "--no-fetch",
        action="store_true",
        help="Не выполнять сетевые запросы.",
    )

    parser.add_argument(
        "--json",
        action="store_true",
        help="Вывести результат в JSON.",
    )

    parser.add_argument(
        "--dns-timeout",
        type=float,
        default=3.0,
        help="Таймаут DNS-запроса в секундах (по умолчанию: 3).",
    )

    parser.add_argument(
        "--http-connect-timeout",
        type=float,
        default=5.0,
        help="Таймаут подключения HTTP в секундах (по умолчанию: 5).",
    )

    parser.add_argument(
        "--http-read-timeout",
        type=float,
        default=10.0,
        help="Таймаут чтения HTTP в секундах (по умолчанию: 10).",
    )

    parser.add_argument(
        "--http-overall-timeout",
        type=float,
        default=30.0,
        help="Общий таймаут HTTP в секундах (по умолчанию: 30).",
    )

    parser.add_argument(
        "--http-max-redirects",
        type=int,
        default=10,
        help="Максимальное число HTTP-редиректов (по умолчанию: 10).",
    )

    parser.add_argument(
        "--allow-private",
        action="store_true",
        help="Разрешить HTTP-запросы к локальным/непубличным адресам.",
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    parser.add_argument(
        "--gui",
        action="store_true",
        help="Запустить графический интерфейс.",
    )

    return parser


def _print_human(report) -> None:
    coverage = report.coverage

    print(f"Риск-оценка: {report.risk_score}/100")
    print(f"Уровень риска: {report.risk_level}")
    print(
        f"Полнота проверки: "
        f"{coverage.passed}/{coverage.total} — "
        f"{coverage.percent:.0f}% — {coverage.status}"
    )

    if report.evidence:
        print("\nПризнаки:")
        for item in report.evidence:
            print(
                f"  [{item.severity.upper()}] "
                f"{item.code}: {item.message}"
                f" (+{item.weight})"
            )
    else:
        print("\nПризнаки: не обнаружены")

    if report.errors:
        print("\nОшибки/неполные проверки:")
        for error in report.errors:
            print(f"  - {error}")


def _analyze_one(url: str, args):
    return analyze(
        url,
        fetch_dns=not args.no_fetch,
        dns_timeout=args.dns_timeout,
        fetch_http=not args.no_fetch,
        http_connect_timeout=args.http_connect_timeout,
        http_read_timeout=args.http_read_timeout,
        http_overall_timeout=args.http_overall_timeout,
        http_max_redirects=args.http_max_redirects,
        allow_private=args.allow_private,
    )


def _load_batch(path: str) -> list[str]:
    try:
        lines = Path(path).read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise ValueError(f"Не удалось прочитать batch-файл: {exc}") from exc

    return [line.strip() for line in lines if line.strip() and not line.lstrip().startswith("#")]


def _run_batch(urls: list[str], args):
    workers = min(8, len(urls))
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [executor.submit(_analyze_one, url, args) for url in urls]
        return [future.result() for future in futures]


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s: %(message)s")
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.gui:
        from .gui import run_gui
        run_gui()
        return 0

    if args.dns_timeout <= 0:
        parser.error("--dns-timeout должен быть больше нуля")
    if args.http_connect_timeout <= 0:
        parser.error("--http-connect-timeout должен быть больше нуля")
    if args.http_read_timeout <= 0:
        parser.error("--http-read-timeout должен быть больше нуля")
    if args.http_overall_timeout <= 0:
        parser.error("--http-overall-timeout должен быть больше нуля")
    if args.http_max_redirects < 0:
        parser.error("--http-max-redirects не может быть отрицательным")

    urls = list(args.url)
    if args.batch:
        if urls:
            parser.error("Нельзя одновременно использовать URL и --batch")
        urls = _load_batch(args.batch)

    if not urls:
        parser.print_help()
        return 0

    try:
        reports = _run_batch(urls, args) if len(urls) > 1 else [_analyze_one(urls[0], args)]
    except (OSError, ValueError) as exc:
        LOGGER.error("Ошибка выполнения: %s", exc)
        return 1
    except Exception:
        LOGGER.exception("Непредвиденная ошибка выполнения")
        return 1

    high_found = any(report.risk_level == "HIGH" for report in reports)

    if args.json:
        payload = reports[0].to_dict() if len(reports) == 1 else {
            "results": [report.to_dict() for report in reports]
        }
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        for index, (url, report) in enumerate(zip(urls, reports), start=1):
            if len(reports) > 1:
                print(f"\n=== Проверка {index}/{len(reports)}: {url} ===")
            else:
                print(f"Проверка URL: {url}")
            _print_human(report)

    return 10 if args.fail_on_high and high_found else 0


if __name__ == "__main__":
    raise SystemExit(main())
