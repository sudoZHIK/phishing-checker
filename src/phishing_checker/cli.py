"""Command-line interface for Phishing Checker."""

from __future__ import annotations

import argparse
import json

from . import __version__
from .analyzer import analyze


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="phishing-checker",
        description="Локальная защитная проверка URL на признаки фишинга.",
    )

    parser.add_argument(
        "url",
        nargs="?",
        help="URL для проверки",
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
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
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


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.url:
        parser.print_help()
        return 0

    if args.dns_timeout <= 0:
        parser.error("--dns-timeout должен быть больше нуля")

    report = analyze(
        args.url,
        fetch_dns=not args.no_fetch,
        dns_timeout=args.dns_timeout,
    )

    if args.json:
        print(json.dumps(
            report.to_dict(),
            ensure_ascii=False,
            indent=2,
        ))
    else:
        print(f"Проверка URL: {args.url}")
        _print_human(report)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
