"""Rolling, incrementally refreshed buffer of Mist org device events (v0.10.18).

Before v0.10.18 every consumer (Command Center, the alerting monitor, the SIEM forwarder, the Mist
alerts connector, chassis views) searched ``/orgs/{org}/devices/events/search`` for its whole window on
every refresh: one day of events is up to ten 1000-row pages, re-read every 20-30 seconds.

This buffer loads the lookback window once, then asks Mist only for events newer than what it already
holds (``start``/``end`` epoch seconds, with a small overlap for late-indexed events) at most every
``poll_seconds``. Every consumer is answered from memory with its own window and limit.

* No duplicates: events are keyed by their content (Mist device events carry no ID).
* No gaps: each incremental read starts where the previous one ended, minus ``overlap_seconds``; if an
  incremental read hits its row limit (so older rows could be missing), coverage restarts at the oldest
  row of that read instead of leaving a hole.
* Bounded memory: events older than the lookback are dropped; beyond ``max_events`` the oldest go.
* Single flight: concurrent readers share one fetch (the second waits and then reads the result).
* Failures: a failed incremental read keeps serving the buffered events while they are younger than
  ``max_stale_seconds`` (the error is kept in :meth:`stats`); after that, or before the first successful
  load, the error is raised to the caller as before.
"""

from __future__ import annotations

import bisect
import hashlib
import json
import threading
import time
from typing import Any, Callable
from app.core.freshness import stale_allowed

Fetch = Callable[[float, float, int], list[dict]]


def event_epoch(event: dict) -> float | None:
    """Mist event timestamp in epoch seconds (accepts seconds or milliseconds)."""
    value = event.get("timestamp")
    try:
        ts = float(value)
    except (TypeError, ValueError):
        return None
    if ts > 1e12:  # milliseconds
        ts /= 1000.0
    return ts if ts > 0 else None


def event_identity(event: dict) -> str:
    """Stable identity for an event that has no ID: a digest of its full content."""
    try:
        raw = json.dumps(event, sort_keys=True, default=str, separators=(",", ":"))
    except (TypeError, ValueError):
        raw = repr(sorted(event.items(), key=lambda kv: str(kv[0])))
    return hashlib.blake2b(raw.encode("utf-8", "replace"), digest_size=16).hexdigest()


class RollingEventBuffer:
    def __init__(
        self,
        fetch: Fetch,
        *,
        lookback_seconds: float,
        poll_seconds: float = 30.0,
        overlap_seconds: float = 300.0,
        max_events: int = 50_000,
        initial_limit: int = 10_000,
        incremental_limit: int = 10_000,
        max_stale_seconds: float = 600.0,
        deep_every_seconds: float = 900.0,
        deep_lookback_seconds: float = 1800.0,
        clock: Callable[[], float] | None = None,
        poll_multiplier: Callable[[], float] | None = None,
        quick_seconds: float | None = None,
    ):
        self._fetch = fetch
        # Cold start (v0.10.23): when set, the first read covers only the last ``quick_seconds`` (one
        # small Mist page instead of up to ten sequential ones for a whole day), and the rest of the
        # lookback is back-filled by a background thread. Until it finishes, :attr:`backfilling` is True.
        self.quick_seconds = (
            float(quick_seconds) if quick_seconds and 0 < float(quick_seconds) < float(lookback_seconds) else None
        )
        self._backfilling = False
        self._coverage_epoch = 0  # bumped whenever coverage moves forward or resets (backfill guard)
        self.lookback = max(60.0, float(lookback_seconds))
        self.poll_seconds = max(1.0, float(poll_seconds))
        self.overlap = max(0.0, float(overlap_seconds))
        self.max_events = max(100, int(max_events))
        self.initial_limit = max(1, int(initial_limit))
        self.incremental_limit = max(1, int(incremental_limit))
        self.max_stale = max(self.poll_seconds, float(max_stale_seconds))
        # Every ``deep_every`` seconds an incremental read reaches back ``deep_lookback`` seconds, so
        # events Mist indexes later than the normal overlap are still picked up.
        self.deep_every = max(self.poll_seconds, float(deep_every_seconds))
        # A deep read covers the last ``deep_lookback`` seconds: with reads every ``deep_every`` seconds,
        # events indexed up to (deep_lookback - deep_every) late are caught (15 min by default).
        self.deep_lookback = max(self.deep_every + self.overlap, float(deep_lookback_seconds))
        self._deep_until = 0.0  # ``end`` of the last full or deep read
        self._clock = clock or time.time
        self._poll_multiplier = poll_multiplier or (lambda: 1.0)
        self._refresh_lock = threading.Lock()  # single flight: one fetch at a time, others wait for it
        self._data_lock = threading.Lock()
        self._by_id: dict[str, dict] = {}
        self._ts: list[float] = []  # ascending, parallel to _ids
        self._ids: list[str] = []
        self._loaded = False
        self._covered_from = 0.0  # oldest instant with complete coverage
        self._covered_until = 0.0  # ``end`` of the last successful read
        self._last_ok = 0.0  # clock time of the last successful read
        self._stale = False  # set by invalidate(): next read refreshes regardless of age
        self._retry_at = 0.0  # after a failed read: do not hammer Mist before this time
        self._last_exc: Exception | None = None
        self._generation = 0  # bumped by every fetch attempt (single-flight bookkeeping)
        self.fetches = 0
        self.full_loads = 0
        self.last_error = ""

    # ------------------------------------------------------------------ reading
    def window(self, seconds: float, *, limit: int = 10_000, max_age: float | None = None) -> list[dict]:
        """Events of the last ``seconds`` (newest first, at most ``limit``).

        ``max_age`` overrides the poll interval for this read (e.g. the alerting monitor wants events no
        older than a few seconds); ``0`` forces an incremental read now.
        """
        rows = self.window_if_covered(seconds, limit=limit, max_age=max_age, partial_ok=True)
        return rows or []

    def window_if_covered(
        self,
        seconds: float,
        *,
        limit: int = 10_000,
        max_age: float | None = None,
        partial_ok: bool = False,
        partial_while_backfilling: bool = False,
    ) -> list[dict] | None:
        """Like :meth:`window`, but None when the buffer cannot answer completely.

        Complete means the window starts inside the buffer's gap-free coverage, or the buffer holds at
        least ``limit`` events of the window (coverage is contiguous back from now, so the newest
        ``limit`` events are all there). After a truncated read or the size cap moved coverage forward,
        a longer window is therefore *not* answered silently shorter: the caller searches Mist itself.

        ``partial_while_backfilling``: during the back-fill after a quick first load, answer with what
        is buffered so far (newest events complete, older part still arriving) instead of None, so the
        caller does not start the very full-window search the quick load exists to avoid.
        """
        if float(seconds) > self.lookback and not partial_ok:
            return None
        self.refresh_if_needed(max_age)
        cutoff = self._clock() - max(0.0, float(seconds))
        limit = max(0, int(limit))
        with self._data_lock:
            start = bisect.bisect_left(self._ts, cutoff)
            ids = self._ids[start:]
            complete = cutoff >= self._covered_from - 1.0 or len(ids) >= limit
            if not complete and not partial_ok and not (partial_while_backfilling and self._backfilling):
                return None
            picked = ids[::-1][:limit]
            return [self._by_id[i] for i in picked]

    def invalidate(self) -> None:
        """Make the next read fetch new events (incrementally) whatever their age."""
        self._stale = True

    def reset(self) -> None:
        with self._refresh_lock, self._data_lock:
            self._by_id.clear()
            self._ts.clear()
            self._ids.clear()
            self._loaded = False
            self._covered_from = self._covered_until = self._last_ok = self._deep_until = 0.0
            self._stale = False
            self._coverage_epoch += 1  # a back-fill still running must not merge into the new buffer

    @property
    def backfilling(self) -> bool:
        """True while the background back-fill of a quick first load is still running."""
        return self._backfilling

    def covers(self, seconds: float) -> bool:
        """True when ``seconds`` fits in the lookback *and* in the current gap-free coverage."""
        if float(seconds) > self.lookback:
            return False
        if not self._loaded:
            return True  # the first read loads the whole lookback
        return self._clock() - float(seconds) >= self._covered_from - 1.0

    def stats(self) -> dict[str, Any]:
        now = self._clock()
        with self._data_lock:
            return {
                "events": len(self._ids),
                "loaded": self._loaded,
                "lookback_seconds": self.lookback,
                "poll_seconds": round(self.effective_poll(), 1),
                "covered_from": self._covered_from or None,
                "age_seconds": round(now - self._last_ok, 1) if self._last_ok else None,
                "fetches": self.fetches,
                "full_loads": self.full_loads,
                "backfilling": self._backfilling,
                "last_error": self.last_error,
            }

    def effective_poll(self) -> float:
        try:
            factor = max(1.0, float(self._poll_multiplier()))
        except Exception:  # noqa: BLE001 - a broken budget hook must never stop events
            factor = 1.0
        return self.poll_seconds * factor

    # ------------------------------------------------------------------ refresh
    def _due(self, max_age: float | None) -> bool:
        if not self._loaded:
            return True  # nothing to serve: always try (and raise to the caller on failure)
        now = self._clock()
        if now < self._retry_at:  # a read just failed: serve the buffer, unless it is too old
            return now - self._last_ok > self.max_stale
        if self._stale:
            return True
        limit = self.effective_poll() if max_age is None else max(0.0, float(max_age))
        return self._clock() - self._last_ok >= limit

    def refresh_if_needed(self, max_age: float | None = None) -> None:
        if not self._due(max_age):
            return
        # v0.10.40: an ordinary reader (no max_age) of a loaded, recently read buffer is answered from it
        # at once; the incremental read runs in the background (readers no longer wait ~0.6-1 s each time).
        if (
            max_age is None
            and stale_allowed()
            and self._loaded
            and not self._stale
            and self._clock() - self._last_ok < 3 * self.effective_poll()
        ):
            if not getattr(self, "_bg_pending", False) and not self._refresh_lock.locked():
                self._bg_pending = True
                threading.Thread(target=self._background_refresh, name="mist-events-refresh", daemon=True).start()
            return
        generation = self._generation
        with self._refresh_lock:
            # Another reader refreshed while we waited for the lock: share its result.
            if generation != self._generation:
                failed = self._last_exc
                if failed is not None and (not self._loaded or self._clock() - self._last_ok > self.max_stale):
                    raise failed  # the shared read failed and there is nothing usable to serve
                return
            if not self._due(max_age):
                return
            self._generation += 1
            try:
                self._refresh()
                self.last_error = ""
                self._last_exc = None
                self._retry_at = 0.0
            except Exception as exc:
                self.last_error = str(exc)[:300]
                self._last_exc = exc
                # Serve what we have; the next read tries again after half a poll interval.
                self._retry_at = self._clock() + self.effective_poll() / 2
                if not self._loaded or self._clock() - self._last_ok > self.max_stale:
                    raise

    def _background_refresh(self) -> None:
        try:
            self.refresh_if_needed(max_age=self.effective_poll())
        except Exception:  # noqa: BLE001 - recorded in last_error; the next reader retries
            pass
        finally:
            self._bg_pending = False

    def _refresh(self) -> None:
        now = self._clock()
        self._stale = False
        first = not self._loaded
        quick = first and self.quick_seconds is not None
        if first:
            start = now - (self.quick_seconds if quick else self.lookback)
            limit = self.initial_limit
        else:
            start = self._covered_until - self.overlap
            if now - self._deep_until >= self.deep_every:
                start = min(start, now - self.deep_lookback)
            start = max(now - self.lookback, start)
            limit = self.incremental_limit
        deep = not self._loaded or now - self._deep_until >= self.deep_every
        rows = self._fetch(start, now, limit)
        self.fetches += 1
        truncated = len(rows) >= limit
        with self._data_lock:
            if not self._loaded:
                self.full_loads += 1
                self._covered_from = start
            if truncated:
                oldest = min((t for t in (event_epoch(r) for r in rows) if t is not None), default=now)
                # The read stopped at its row limit: anything older than its oldest row may be missing.
                # Restart coverage there rather than keep a hole in the middle of the buffer.
                self._drop_before(oldest)
                self._covered_from = max(self._covered_from, oldest)
                self._coverage_epoch += 1
            self._merge(rows)
            self._drop_before(now - self.lookback)
            self._covered_from = max(self._covered_from, now - self.lookback)
            self._trim_overflow()
            self._covered_until = now
            if deep:
                self._deep_until = now
            self._last_ok = now
            self._loaded = True
            start_backfill = quick and self._covered_from > now - self.lookback + 1.0
            if start_backfill:
                self._backfilling = True
                self._backfill_token = getattr(self, "_backfill_token", 0) + 1
                token = self._backfill_token
                epoch = self._coverage_epoch
                backfill_end = self._covered_from
        if start_backfill:
            threading.Thread(
                target=self._backfill, args=(epoch, backfill_end, token), name="mist-event-backfill", daemon=True
            ).start()

    def _trim_overflow(self) -> None:
        """Beyond ``max_events`` drop the oldest; coverage then starts at the oldest kept event (caller locks)."""
        overflow = len(self._ids) - self.max_events
        if overflow > 0:
            for i in self._ids[:overflow]:
                self._by_id.pop(i, None)
            self._covered_from = max(self._covered_from, self._ts[overflow])
            self._coverage_epoch += 1
            del self._ids[:overflow]
            del self._ts[:overflow]

    def _backfill(self, epoch: int, end: float, token: int = 0) -> None:
        """Read the rest of the lookback (older than the quick first load) and extend coverage back.

        Coverage stays gap-free: the back-fill ends where coverage starts (plus the usual overlap; duplicates
        are dropped by identity). If it is truncated at its row limit, coverage extends only back to its
        oldest row. If coverage moved forward meanwhile (truncated incremental read, size cap, reset), the
        result is discarded rather than leave a hole."""
        try:
            start = self._clock() - self.lookback
            try:
                rows = self._fetch(start, end + self.overlap, self.initial_limit)
            except Exception as exc:  # noqa: BLE001 - the buffer keeps serving the quick window
                self.last_error = f"event back-fill failed: {exc}"[:300]
                return
            self.fetches += 1
            truncated = len(rows) >= self.initial_limit
            with self._data_lock:
                if epoch != self._coverage_epoch or not self._loaded:
                    return
                new_from = start
                if truncated:
                    new_from = min(
                        (t for t in (event_epoch(r) for r in rows) if t is not None), default=self._covered_from
                    )
                self._merge(rows)
                now = self._clock()
                self._drop_before(now - self.lookback)
                self._covered_from = max(min(self._covered_from, new_from), now - self.lookback)
                self._trim_overflow()
        finally:
            with self._data_lock:
                # Only the newest back-fill clears the flag (an older one may finish after a new one started).
                if token == getattr(self, "_backfill_token", 0):
                    self._backfilling = False

    def _merge(self, rows: list[dict]) -> None:
        fresh: list[tuple[float, str]] = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            ts = event_epoch(row)
            if ts is None:
                continue
            ident = event_identity(row)
            if ident in self._by_id:
                continue
            self._by_id[ident] = row
            fresh.append((ts, ident))
        if not fresh:
            return
        fresh.sort()
        if not self._ts or fresh[0][0] >= self._ts[-1]:
            self._ts.extend(t for t, _ in fresh)
            self._ids.extend(i for _, i in fresh)
            return
        merged = list(zip(self._ts, self._ids))
        merged.extend(fresh)
        merged.sort(key=lambda x: x[0])  # stable: equal timestamps keep arrival order
        self._ts = [t for t, _ in merged]
        self._ids = [i for _, i in merged]

    def _drop_before(self, cutoff: float) -> None:
        cut = bisect.bisect_left(self._ts, cutoff)
        if cut <= 0:
            return
        for i in self._ids[:cut]:
            self._by_id.pop(i, None)
        del self._ids[:cut]
        del self._ts[:cut]
