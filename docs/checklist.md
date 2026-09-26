# Phishing Checker checklist

## Core
- [x] Python 3.10+
- [x] Tkinter/ttk GUI
- [x] CLI and JSON output
- [x] No mandatory cloud API
- [x] `schema_version` 1.0
- [x] Risk score 0–100 and four risk levels
- [x] Coverage passed/total/percent/status

## URL and static analysis
- [x] Deterministic URL normalization
- [x] Unicode + Punycode forms
- [x] userinfo / `@` detection
- [x] IP hostname detection
- [x] IDN/Punycode detection
- [x] Brand similarity
- [x] Suspicious path patterns
- [x] No JavaScript execution

## Network safety
- [x] DNS timeout 3 s default
- [x] HTTP connect/read/overall timeouts
- [x] Maximum 10 redirects by default
- [x] Private/loopback/link-local blocking by default
- [x] `--allow-private`
- [x] Redirect destination re-validation
- [x] DNS rebinding mitigation by address pinning
- [x] HTTP 429 treated as incomplete coverage

## CLI
- [x] Single URL
- [x] Batch file
- [x] ThreadPoolExecutor batch execution
- [x] `--no-fetch`
- [x] `--fail-on-high`
- [x] Configurable timeouts

## Testing
- [x] Coverage 0/0, 0/1, 1/1, 8/8
- [x] Deterministic scoring
- [x] URL normalization and IDN tests
- [x] HTML/static tests
- [x] HTTP/SSRF tests
- [x] RDAP tests
- [x] Ruff
- [x] compileall
- [x] pytest

## Known follow-up
- [x] Persistent DNS/RDAP/reputation cache with platform-specific TTL storage
- [x] Batch/global rate limiter with Retry-After handling
- [x] Offline HTML fixture tests
- [x] Linux PyInstaller onedir runtime test without venv
- [x] Linux PyInstaller onefile runtime test without venv
- [x] Tk/Tcl included in GUI standalone build
- [ ] Windows standalone build and runtime test (must be built on Windows)
