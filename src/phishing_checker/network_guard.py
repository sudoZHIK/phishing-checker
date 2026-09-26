"""Process-local rate limiting for outbound checker requests."""
from __future__ import annotations

import threading
import time
from collections import deque
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

_HOST_MIN_INTERVAL = 1.0
_GLOBAL_WINDOW = 1.0
_GLOBAL_MAX_REQUESTS = 5

_lock = threading.RLock()
_host_next: dict[str, float] = {}
_global_requests: deque[float] = deque()


def wait_for_request(host: str) -> None:
    """Enforce <=1 request/host/sec and <=5 requests/sec globally."""
    host = host.lower().rstrip(".")
    while True:
        with _lock:
            now = time.monotonic()
            while _global_requests and now - _global_requests[0] >= _GLOBAL_WINDOW:
                _global_requests.popleft()
            host_wait = max(0.0, _host_next.get(host, 0.0) - now)
            global_wait = 0.0
            if len(_global_requests) >= _GLOBAL_MAX_REQUESTS:
                global_wait = max(0.0, _GLOBAL_WINDOW - (now - _global_requests[0]))
            delay = max(host_wait, global_wait)
            if delay <= 0:
                _global_requests.append(now)
                _host_next[host] = now + _HOST_MIN_INTERVAL
                return
        time.sleep(delay)


def retry_after_seconds(value: str | None) -> float | None:
    """Parse Retry-After seconds or an HTTP-date into a delay."""
    if not value:
        return None
    try:
        delay = float(value.strip())
        return max(0.0, delay)
    except ValueError:
        pass
    try:
        target = parsedate_to_datetime(value)
        if target.tzinfo is None:
            target = target.replace(tzinfo=timezone.utc)
        return max(0.0, (target - datetime.now(timezone.utc)).total_seconds())
    except (TypeError, ValueError, OverflowError):
        return None


def respect_retry_after(value: str | None) -> None:
    """Sleep for a server-requested retry delay, when supplied."""
    delay = retry_after_seconds(value)
    if delay is not None:
        time.sleep(delay)
