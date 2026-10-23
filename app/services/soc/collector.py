"""Background collection of security detections from every ``security.events`` source (v0.10.30).

Each connected source is read on its own moving window (``since`` = newest detection seen − overlap, at most
the last ``BACKFILL_S``), in parallel, off the request path. A failing source is reported in ``status`` and
never hides the others. While someone has the Security page open the cadence is ``ACTIVE_EVERY_S``; with
nobody looking it slows to ``IDLE_EVERY_S`` so the logging services are not asked for nothing.
"""

from __future__ import annotations

import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from app.core.security import redact_text
from app.integrations.contracts import SECURITY_EVENTS
from app.services.soc.store import EventStore

log = logging.getLogger("nodewatch.soc")

BACKFILL_S = 24 * 3600.0  # the first read of a source (and after a long pause) goes back this far
OVERLAP_S = 600.0  # logs arrive late at the logging service: re-read the last 10 minutes
FIRST_LIMIT = 5000
NEXT_LIMIT = 2000
ACTIVE_EVERY_S = 120.0
IDLE_EVERY_S = 900.0
ACTIVE_FOR_S = 900.0  # a page request keeps the fast cadence this long


class Collector:
    def __init__(self, store: EventStore) -> None:
        self.store = store
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._wake = threading.Event()
        self._stop = threading.Event()
        self.status: dict[str, dict[str, Any]] = {}
        self.last_run = 0.0
        self.running = False
        self._seen_at = 0.0

    # ---- control ------------------------------------------------------------------------------------
    def touch(self) -> None:
        """A page asked for data: keep the fast cadence, start the loop if needed."""
        self._seen_at = time.time()
        self.ensure_started()

    def ensure_started(self) -> None:
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return
            self._stop.clear()
            self._thread = threading.Thread(target=self._loop, name="soc-collector", daemon=True)
            self._thread.start()

    def kick(self) -> None:
        self._wake.set()
        self.ensure_started()

    def stop(self) -> None:
        self._stop.set()
        self._wake.set()

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.run_once()
            except Exception:  # noqa: BLE001 - the loop must survive anything a source does
                log.exception("SOC collection failed")
            active = time.time() - self._seen_at < ACTIVE_FOR_S
            self._wake.wait(ACTIVE_EVERY_S if active else IDLE_EVERY_S)
            self._wake.clear()

    # ---- one pass -----------------------------------------------------------------------------------
    def run_once(self) -> dict[str, Any]:
        from app.integrations.connectors import sdk

        sources = sdk.sources(SECURITY_EVENTS)
        if not sources:
            self.last_run = time.time()
            return {}
        self.running = True
        try:
            with ThreadPoolExecutor(max_workers=min(4, len(sources)), thread_name_prefix="soc-read") as pool:
                results = list(pool.map(self._read, sources))
        finally:
            self.running = False
        self.last_run = time.time()
        self.store.save()
        return {r["source"]: r for r in results}

    def _read(self, c: Any) -> dict[str, Any]:
        """Newest detections first; when a read is cut off at its limit, the part it could not reach is kept
        as a gap and read (oldest end first, newest of the gap first) on the following passes until closed."""
        now = time.time()
        cursor = self.store.cursor(c.provider_id)
        first = cursor <= 0 or now - cursor > BACKFILL_S
        since = now - BACKFILL_S if first else cursor - OVERLAP_S
        limit = FIRST_LIMIT if first else NEXT_LIMIT
        started = time.monotonic()
        prev = self.status.get(c.provider_id) or {}
        st: dict[str, Any] = {
            "source": c.provider_id,
            "product": c.manifest.product,
            "vendor": c.manifest.vendor,
            "read_at": now,
            "since": since,
        }
        gap = prev.get("gap")  # (since, until) still to read from an earlier truncated read
        try:
            rows = c.list_security_events(since=since, until=now, limit=limit)
            events = [r.to_dict() if hasattr(r, "to_dict") else dict(r) for r in rows]
            new = self.store.add(c.provider_id, events)
            truncated = len(events) >= limit
            if truncated and events:
                oldest = min(float(e.get("timestamp") or now) for e in events)
                gap = (since, oldest) if not gap else (min(gap[0], since), max(gap[1], oldest))
            if gap:
                g_rows = c.list_security_events(since=gap[0], until=gap[1], limit=NEXT_LIMIT)
                g_events = [r.to_dict() if hasattr(r, "to_dict") else dict(r) for r in g_rows]
                new += self.store.add(c.provider_id, g_events)
                if len(g_events) >= NEXT_LIMIT and g_events:
                    gap = (gap[0], min(float(e.get("timestamp") or gap[1]) for e in g_events))
                else:
                    gap = None
                if gap and gap[1] - gap[0] < 1:
                    gap = None
            st.update(ok=True, read=len(events), new=new, error="", truncated=truncated, gap=gap)
        except Exception as exc:  # noqa: BLE001 - IntegrationError text is already redacted by the connector
            st.update(ok=False, read=0, new=0, error=redact_text(exc)[:300], gap=gap)
            log.info("SOC read of %s failed: %s", c.provider_id, redact_text(exc)[:200])
        st["ms"] = round((time.monotonic() - started) * 1000)
        st["last_ok"] = now if st.get("ok") else prev.get("last_ok")
        self.status = {**self.status, c.provider_id: st}  # swapped, never mutated while others iterate
        return st
