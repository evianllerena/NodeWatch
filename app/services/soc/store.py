"""Bounded local store of security detections (v0.10.30).

The SOC needs a few days of history (trends, "first seen", incidents that span hours), which a single Log
Viewer / XML API query cannot give cheaply. Detections — not traffic logs — are kept: normalised
:class:`SecurityEvent` dictionaries only, never raw vendor rows, for at most ``RETENTION_S`` and at most
``MAX_EVENTS`` (oldest dropped first). The file lives in NodeWatch's private data folder
(``state/security/detections.json``, owner-only permissions) and is never part of a diagnostics export.
"""

from __future__ import annotations

import json
import logging
import threading
import time
from pathlib import Path
from typing import Any, Iterable

log = logging.getLogger("nodewatch.soc")

RETENTION_S = 7 * 24 * 3600.0
MAX_EVENTS = 30_000
SAVE_EVERY_S = 60.0
FILE_NAME = "detections.json"
SCHEMA = 1


class EventStore:
    def __init__(self, root: Path | None = None, *, persist: bool = True) -> None:
        self._root = root
        self._persist = persist
        self._lock = threading.RLock()
        self._events: dict[str, dict[str, Any]] = {}
        self._cursor: dict[str, float] = {}  # source → newest detection time read
        self._loaded = not persist
        self._dirty = False
        self._saved_at = 0.0
        self.version = 0  # bumped whenever detections are added (page caches key on it)

    # ---- persistence ------------------------------------------------------------------------------
    def _path(self) -> Path:
        if self._root is not None:
            return self._root / FILE_NAME
        from app.core.config import STATE_ROOT

        return STATE_ROOT / "security" / FILE_NAME

    def _load(self) -> None:
        if self._loaded:
            return
        self._loaded = True
        try:
            raw = json.loads(self._path().read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return
        if not isinstance(raw, dict) or raw.get("schema") != SCHEMA:
            return
        cutoff = time.time() - RETENTION_S
        for e in raw.get("events") or []:
            if isinstance(e, dict) and e.get("key") and float(e.get("timestamp") or 0) >= cutoff:
                self._events[str(e["key"])] = e
        self._cursor = {str(k): float(v) for k, v in (raw.get("cursor") or {}).items() if isinstance(v, (int, float))}

    def save(self, *, force: bool = False) -> None:
        if not self._persist:
            return
        with self._lock:
            if not self._dirty or (not force and time.time() - self._saved_at < SAVE_EVERY_S):
                return
            data = {"schema": SCHEMA, "cursor": dict(self._cursor), "events": list(self._events.values())}
            self._dirty = False
            self._saved_at = time.time()
        try:
            from app.core.file_utils import write_private_text

            write_private_text(self._path(), json.dumps(data, separators=(",", ":"), default=str))
        except OSError as exc:
            log.info("SOC detections not saved: %s", exc)

    # ---- writes -----------------------------------------------------------------------------------
    def add(self, source: str, events: Iterable[dict[str, Any]]) -> int:
        """Add detections of one source (dicts of :class:`SecurityEvent`); returns how many were new."""
        new = 0
        with self._lock:
            self._load()
            newest = self._cursor.get(source, 0.0)
            for e in events:
                key = str(e.get("key") or "")
                if not key:
                    continue
                if key not in self._events:
                    new += 1
                self._events[key] = e
                newest = max(newest, float(e.get("timestamp") or 0))
            if newest:
                self._cursor[source] = newest
            self._prune()
            self._dirty = self._dirty or bool(new)
            if new:
                self.version += 1
        return new

    def _prune(self) -> None:
        cutoff = time.time() - RETENTION_S
        stale = [k for k, e in self._events.items() if float(e.get("timestamp") or 0) < cutoff]
        for k in stale:
            del self._events[k]
        if len(self._events) > MAX_EVENTS:
            ordered = sorted(self._events.items(), key=lambda kv: float(kv[1].get("timestamp") or 0))
            for k, _ in ordered[: len(self._events) - MAX_EVENTS]:
                del self._events[k]

    def forget_source(self, source: str) -> None:
        with self._lock:
            self._load()
            for k in [k for k, e in self._events.items() if e.get("source") == source]:
                del self._events[k]
            self._cursor.pop(source, None)
            self._dirty = True

    # ---- reads ------------------------------------------------------------------------------------
    def cursor(self, source: str) -> float:
        with self._lock:
            self._load()
            return self._cursor.get(source, 0.0)

    def window(self, since: float, until: float | None = None) -> list[dict[str, Any]]:
        until = until or time.time() + 60
        with self._lock:
            self._load()
            return [e for e in self._events.values() if since <= float(e.get("timestamp") or 0) <= until]

    def stats(self) -> dict[str, Any]:
        with self._lock:
            self._load()
            per: dict[str, int] = {}
            oldest = None
            for e in self._events.values():
                per[e.get("source") or ""] = per.get(e.get("source") or "", 0) + 1
                t = float(e.get("timestamp") or 0)
                oldest = t if oldest is None else min(oldest, t)
            return {"events": len(self._events), "by_source": per, "oldest": oldest, "cursor": dict(self._cursor)}
