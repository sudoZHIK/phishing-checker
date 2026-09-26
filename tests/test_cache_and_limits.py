
from phishing_checker import cache, network_guard


def test_cache_roundtrip_and_expiry(tmp_path, monkeypatch):
    monkeypatch.delenv("PHISHING_CHECKER_DISABLE_CACHE", raising=False)
    monkeypatch.setattr(cache, "_DB", tmp_path / "cache.sqlite3")
    cache.put("unit", "key", {"value": 1}, ttl=60)
    assert cache.get("unit", "key") == {"value": 1}
    monkeypatch.setattr(cache.time, "time", lambda: 10_000)
    cache.put("unit", "expired", {"value": 2}, ttl=1)
    monkeypatch.setattr(cache.time, "time", lambda: 10_002)
    assert cache.get("unit", "expired") is None


def test_cache_can_be_disabled(monkeypatch, tmp_path):
    monkeypatch.setenv("PHISHING_CHECKER_DISABLE_CACHE", "1")
    monkeypatch.setattr(cache, "_DB", tmp_path / "cache.sqlite3")
    cache.put("unit", "key", {"value": 1}, ttl=60)
    assert cache.get("unit", "key") is None


def test_retry_after_seconds_and_date(monkeypatch):
    assert network_guard.retry_after_seconds("2") == 2.0
    assert network_guard.retry_after_seconds("not-a-date") is None
