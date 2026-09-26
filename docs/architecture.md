# Архитектура Phishing Checker

## Pipeline

`URL → normalization → URL/domain analysis → IDN/Punycode → brand similarity → DNS/DoH → RDAP → TLS → HTTP/redirects → HTML → reputation → scoring → report`

Внешние проверки выполняются только как defensive triage. JavaScript не исполняется, crawling отсутствует, credentials/cookies/session tokens не собираются.

## Network safety

`http.py` вручную обрабатывает redirects, перед каждым запросом разрешает hostname и проверяет IP. Loopback, private, link-local и другие non-global адреса блокируются по умолчанию. `--allow-private` отключает эту блокировку только для явного локального тестирования. Разрешённые адреса временно pin-ятся через `socket.getaddrinfo`, что снижает риск DNS rebinding.

`network_guard.py` ограничивает исходящие запросы: не более 1 request/host/sec и 5 requests/sec глобально внутри процесса. `Retry-After` обрабатывается для ответов 429.

## Cache

`cache.py` использует стандартный `sqlite3`, поэтому дополнительная runtime-зависимость не нужна.

- Linux: `~/.cache/phishing-checker/cache.sqlite3`
- Windows: `%LOCALAPPDATA%/PhishingChecker/cache/cache.sqlite3`
- DNS TTL: 5 минут
- RDAP TTL: 1 час
- Reputation TTL: 15 минут
- ошибки и 429 не кэшируются

## Coverage

Network failures, timeout, proxy/DNS errors, HTTP 429 и отсутствие optional API keys отражаются в `errors`/coverage и не становятся evidence сами по себе.

## Concurrency

Batch CLI использует `concurrent.futures.ThreadPoolExecutor`. GUI запускает анализ в worker thread и обновляет Tkinter только через main thread.

## Reports

`AnalysisReport` содержит `schema_version`, `risk_score`, `risk_level`, `coverage`, `evidence[]` и `errors[]`. Формат JSON фиксирован схемой `docs/report-schema.json`, текущая версия — `1.0`.
