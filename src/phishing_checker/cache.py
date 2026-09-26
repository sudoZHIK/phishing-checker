"""Small persistent SQLite TTL cache using only the Python standard library."""
from __future__ import annotations

import json
import os
import sqlite3
import time
from pathlib import Path
from typing import Any


def cache_dir() -> Path:
    if os.name == "nt":
        root = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        path = Path(root) / "PhishingChecker" / "cache"
    else:
        path = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache")) / "phishing-checker"
    path.mkdir(parents=True, exist_ok=True)
    return path


_DB = cache_dir() / "cache.sqlite3"


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(_DB, timeout=5.0)
    conn.execute("CREATE TABLE IF NOT EXISTS cache (namespace TEXT NOT NULL, cache_key TEXT NOT NULL, expires REAL NOT NULL, payload TEXT NOT NULL, PRIMARY KEY(namespace, cache_key))")
    return conn


def get(namespace: str, key: str) -> dict[str, Any] | None:
    if os.getenv("PHISHING_CHECKER_DISABLE_CACHE") == "1":
        return None
    now = time.time()
    with _connect() as conn:
        row = conn.execute("SELECT expires, payload FROM cache WHERE namespace=? AND cache_key=?", (namespace, key)).fetchone()
        if not row:
            return None
        if row[0] <= now:
            conn.execute("DELETE FROM cache WHERE namespace=? AND cache_key=?", (namespace, key))
            return None
        try:
            value = json.loads(row[1])
        except (TypeError, ValueError):
            conn.execute("DELETE FROM cache WHERE namespace=? AND cache_key=?", (namespace, key))
            return None
        return value if isinstance(value, dict) else None


def put(namespace: str, key: str, payload: dict[str, Any], ttl: float) -> None:
    if os.getenv("PHISHING_CHECKER_DISABLE_CACHE") == "1" or ttl <= 0:
        return
    expires = time.time() + ttl
    data = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    with _connect() as conn:
        conn.execute("INSERT OR REPLACE INTO cache(namespace, cache_key, expires, payload) VALUES (?, ?, ?, ?)", (namespace, key, expires, data))
