from __future__ import annotations

import threading
import time
from email.utils import parsedate_to_datetime
from typing import Mapping


class RequestLimiter:
    """Small process-local request gate shared by integration providers.

    This is not a substitute for vendor quota accounting.  It prevents accidental
    request bursts and provides a common place for future per-provider policies.
    """

    def __init__(self) -> None:
        self._last: dict[str, float] = {}
        self._locks: dict[str, threading.Lock] = {}
        self._guard = threading.Lock()

    def _lock_for(self, key: str) -> threading.Lock:
        with self._guard:
            return self._locks.setdefault(key, threading.Lock())

    def wait(self, key: str, *, min_interval_seconds: float = 0.05) -> None:
        minimum = max(0.0, float(min_interval_seconds))
        with self._lock_for(key):
            now = time.monotonic()
            previous = self._last.get(key, 0.0)
            delay = minimum - (now - previous)
            if delay > 0:
                time.sleep(delay)
            self._last[key] = time.monotonic()


def retry_after_seconds(headers: Mapping[str, str] | None, *, maximum: float = 5.0) -> float | None:
    """Parse Retry-After without allowing an API response to stall NodeWatch for long."""

    if not headers:
        return None
    raw = str(headers.get("Retry-After") or headers.get("retry-after") or "").strip()
    if not raw:
        return None
    delay: float
    try:
        delay = float(raw)
    except ValueError:
        try:
            dt = parsedate_to_datetime(raw)
            delay = max(0.0, dt.timestamp() - time.time())
        except (TypeError, ValueError, OverflowError):
            return None
    if delay < 0:
        return 0.0
    if delay > float(maximum):
        return None
    return delay


REQUEST_LIMITER = RequestLimiter()
