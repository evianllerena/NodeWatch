from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Any

CACHE_TTLS = {"hot": 30.0, "warm": 300.0, "cold": 3600.0}


@dataclass
class CacheEntry:
    expires_at: float
    value: Any
    tier: str


class TieredCache:
    def __init__(self) -> None:
        self._items: dict[str, CacheEntry] = {}
        self._lock = threading.RLock()

    def get(self, key: str) -> Any | None:
        now = time.monotonic()
        with self._lock:
            item = self._items.get(key)
            if item is None:
                return None
            if item.expires_at <= now:
                self._items.pop(key, None)
                return None
            return item.value

    def put(self, key: str, value: Any, *, tier: str = "warm", ttl_seconds: float | None = None) -> None:
        if tier not in CACHE_TTLS:
            raise ValueError(f"Unknown cache tier: {tier}")
        ttl = CACHE_TTLS[tier] if ttl_seconds is None else max(0.0, float(ttl_seconds))
        with self._lock:
            self._items[key] = CacheEntry(time.monotonic() + ttl, value, tier)

    def invalidate(self, prefix: str = "") -> int:
        with self._lock:
            keys = [k for k in self._items if not prefix or k.startswith(prefix)]
            for key in keys:
                self._items.pop(key, None)
            return len(keys)

    def stats(self) -> dict[str, int]:
        now = time.monotonic()
        with self._lock:
            live = [v for v in self._items.values() if v.expires_at > now]
        return {tier: sum(1 for item in live if item.tier == tier) for tier in CACHE_TTLS}


CACHE = TieredCache()
