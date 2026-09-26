# Phishing Checker

Defensive-инструмент для triage подозрительных URL. Низкий score означает только отсутствие обнаруженных признаков риска и не является гарантией безопасности сайта.

## Ограничения

Проект работает на Python 3.10+, Linux и Windows. GUI построен на Tkinter/ttk и полностью русскоязычный. JavaScript, crawling, credentials, cookies, session tokens и загруженные программы не выполняются и не отправляются.

Обязательные runtime-зависимости: `requests`, `idna`, `dnspython`. Optional reputation API не требуется.

## Linux: разработка

```bash
cd ~/phishing-checker
python3 -m venv .venv
source .venv/bin/activate
python -c "import sys; assert sys.prefix != sys.base_prefix, 'venv не активирован'; print(sys.executable)"
pip install -e .
```

## CLI

```bash
python -m phishing_checker --help
python -m phishing_checker https://example.com --no-fetch
python -m phishing_checker https://example.com --json
python -m phishing_checker --batch urls.txt --json
python -m phishing_checker --batch urls.txt --fail-on-high
```

Exit codes: `0` — успешно; `1` — ошибка выполнения; `2` — неверные аргументы; `10` — HIGH при `--fail-on-high`.

Настройки сети: DNS 3 s, connect 5 s, read 10 s, общий URL timeout 30 s, максимум 10 redirects. Есть `--allow-private` для явного тестирования локальных ресурсов.

Batch использует `ThreadPoolExecutor`. Rate limit: максимум 1 request/host/sec и 5 requests/sec глобально внутри процесса. `Retry-After` учитывается.

## Cache

DNS/RDAP/reputation кэшируются с TTL через стандартный `sqlite3` без новой runtime-зависимости.

Linux: `~/.cache/phishing-checker/cache.sqlite3`.

Windows: `%LOCALAPPDATA%/PhishingChecker/cache/cache.sqlite3`.

TTL: DNS 5 минут, RDAP 1 час, reputation 15 минут. Ошибки и 429 не кэшируются.

Для изоляции unit-тестов можно использовать `PHISHING_CHECKER_DISABLE_CACHE=1`.

## Reputation API

Поддерживаются optional VirusTotal и Google Safe Browsing. Ключи задаются только через environment:

```bash
export VIRUSTOTAL_API_KEY='...'
export GOOGLE_SAFE_BROWSING_API_KEY='...'
```

Ключи не хранятся в исходниках. Если API не настроен, программа продолжает работать; coverage остаётся неполной.

## GUI

```bash
python -c 'from phishing_checker.gui import run_gui; run_gui()'
```

GUI не блокирует интерфейс во время сетевого анализа: worker thread выполняет проверку, Tkinter обновляется через main thread. Есть риск-оценка, полнота проверки, evidence, технический отчёт, копирование и JSON export.

## Testing

```bash
source .venv/bin/activate
python -c "import sys; assert sys.prefix != sys.base_prefix, 'venv не активирован'; print(sys.executable)"
ruff check src tests
python -m compileall -q src
pytest -q
```

Перед релизом также проверяется standalone через PyInstaller.

## Packaging

Linux onedir:

```bash
pyinstaller --clean --noconfirm PhishingChecker.spec
pyinstaller --clean --noconfirm PhishingCheckerGUI.spec
```

Linux onefile:

```bash
pyinstaller --clean --noconfirm --onefile --name PhishingCheckerOnefile pyinstaller_entry.py
pyinstaller --clean --noconfirm --onefile --name PhishingCheckerGUIOnefile --windowed --hidden-import=tkinter pyinstaller_gui_entry.py
```

После сборки бинарники запускаются без `.venv` и Python проекта. Windows binary необходимо собирать непосредственно на Windows.

## Документация

- `docs/checklist.md` — checklist соответствия.
- `docs/report-schema.json` — JSON schema версии `1.0`.
- `docs/architecture.md` — архитектура и security/network model.

## License

MIT.
