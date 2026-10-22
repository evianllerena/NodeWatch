from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Callable

from app.integrations.base import IntegrationError


@dataclass
class TokenEntry:
    token: str
    expires_at: float


class TokenManager:
    """Process-memory token cache with refresh margin and single-flight locking."""

    def __init__(self) -> None:
        self._tokens: dict[str, TokenEntry] = {}
        self._locks: dict[str, threading.Lock] = {}
        self._guard = threading.Lock()

    def _lock_for(self, key: str) -> threading.Lock:
        with self._guard:
            return self._locks.setdefault(key, threading.Lock())

    def get(self, key: str, fetcher: Callable[[], tuple[str, int]], *, refresh_margin_seconds: int = 90) -> str:
        now = time.time()
        cached = self._tokens.get(key)
        if cached and cached.token and cached.expires_at - now > refresh_margin_seconds:
            return cached.token

        with self._lock_for(key):
            now = time.time()
            cached = self._tokens.get(key)
            if cached and cached.token and cached.expires_at - now > refresh_margin_seconds:
                return cached.token
            token, expires_in = fetcher()
            if not token:
                raise IntegrationError(
                    "Authentication server returned an empty access token", code="AUTHENTICATION_FAILED"
                )
            ttl = max(1, int(expires_in or 0))
            self._tokens[key] = TokenEntry(token=token, expires_at=now + ttl)
            return token

    def invalidate(self, key: str) -> None:
        self._tokens.pop(key, None)

    def clear(self) -> None:
        self._tokens.clear()


TOKEN_MANAGER = TokenManager()
