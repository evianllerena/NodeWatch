"""Panorama → ``security.events`` (v0.10.30): threat and URL logs through the XML API's log query.

Panorama keeps the logs its firewalls forward (directly or through log collectors). One asynchronous,
read-only query per log type (``type=log&log-type=threat|url``, then ``action=get`` until FIN — see
:meth:`PanoramaClient.log_query`) returns at most 500 entries; they become vendor-neutral
:class:`SecurityEvent` records through the same PAN-OS vocabulary the Strata Cloud Manager connector uses
(:mod:`app.integrations.connectors.panos_logs`), so a detection counts the same way whichever Palo Alto
system delivered it. URL logs are asked only for blocked or warned requests.
"""

from __future__ import annotations

import logging
import re
import time
from datetime import datetime, timezone
from typing import Any

from app.integrations.connectors.panos_logs import to_event
from app.integrations.contracts import SECURITY_EVENTS
from app.integrations.domain import SecurityEvent

log = logging.getLogger("nodewatch.connectors.panorama")

MAX_PER_QUERY = 500  # the XML API's own ceiling for one log query
MAX_PAGES = 10  # ≤ 5,000 entries per call, paged with ``skip``
URL_FILTER = "(action eq block-url) or (action eq block-continue) or (action eq block-override)"
# Relative windows the XML API understands. Absolute receive_time filters would be read in Panorama's own
# time zone, which the API does not state, so NodeWatch asks for the smallest relative window that covers
# the range and keeps only the entries inside it.
_PERIODS = ((900, "last-15-minutes"), (3600, "last-hour"), (6 * 3600, "last-6-hrs"), (12 * 3600, "last-12-hrs"), (24 * 3600, "last-24-hrs"), (7 * 86400, "last-7-days"))
_CLOCK = re.compile(r"(\w{3})\s+(\w{3})\s+(\d{1,2})\s+(\d{1,2}):(\d{2}):(\d{2})\s+(?:\S+\s+)?(\d{4})")


def _period(seconds: float) -> str:
    for limit, name in _PERIODS:
        if seconds <= limit:
            return name
    return _PERIODS[-1][1]


def _entry_dict(entry: Any) -> dict[str, Any]:
    return {child.tag: (child.text or "").strip() for child in list(entry)}


def clock_offset(clock_text: str, now: float | None = None) -> float | None:
    """Seconds Panorama's wall clock is ahead of UTC, from ``show clock`` ('Fri Oct 16 14:11:27 EDT 2026'),
    rounded to 15 minutes; None when it cannot be read."""
    m = _CLOCK.search(str(clock_text or ""))
    if not m:
        return None
    try:
        local = datetime.strptime(f"{m.group(2)} {m.group(3)} {m.group(7)} {m.group(4)}:{m.group(5)}:{m.group(6)}", "%b %d %Y %H:%M:%S")
    except ValueError:
        return None
    naive = local.replace(tzinfo=timezone.utc).timestamp()
    return round((naive - (now or time.time())) / 900.0) * 900.0


class PanoramaThreats:
    CAPABILITIES: tuple[str, ...] = (SECURITY_EVENTS,)

    def _panorama_offset(self, pan: Any) -> float:
        cached = getattr(self, "_pan_offset", None)
        if cached is not None and time.time() - cached[1] < 6 * 3600:
            return cached[0]
        offset = 0.0
        try:
            root = pan.op("<show><clock></clock></show>", cache=False)
            text = "".join(root.itertext()) if root is not None else ""
            found = clock_offset(text)
            offset = found if found is not None else 0.0
        except Exception as exc:  # noqa: BLE001 - fall back to UTC; high_res_timestamp carries its own zone
            log.info("Panorama clock not read: %s", str(exc)[:160])
        self._pan_offset = (offset, time.time())
        return offset

    def _pages(self, pan: Any, log_type: str, query: str, limit: int, timeout_s: float) -> list[Any]:
        out: list[Any] = []
        for page in range(MAX_PAGES):
            want = min(MAX_PER_QUERY, limit - len(out))
            if want <= 0:
                break
            batch = pan.log_query(log_type, query, nlogs=want, skip=len(out), timeout_s=timeout_s)
            out += list(batch or [])
            if len(batch or []) < want:
                break
        return out

    def list_security_events(self, *, since: float, until: float | None = None, limit: int = 2000) -> list[SecurityEvent]:
        until = float(until or time.time())
        since = float(since)
        if since >= until:
            return []
        limit = max(1, min(int(limit or 2000), MAX_PER_QUERY * MAX_PAGES))
        span = f"(receive_time in {_period(time.time() - since)})"
        pan = self.pan()  # type: ignore[attr-defined]
        offset = self._panorama_offset(pan)
        threats = self.call(  # type: ignore[attr-defined]
            lambda: self._pages(pan, "threat", span, limit, 30.0), "read threat logs"
        )
        urls: list[Any] = []
        try:
            urls = self._pages(pan, "url", f"{span} and ({URL_FILTER})", min(limit, 1000), 20.0)
        except Exception as exc:  # noqa: BLE001 - blocked-web events are a bonus
            log.info("Panorama URL log read skipped: %s", str(exc)[:200])
        out: list[SecurityEvent] = []
        seen: set[str] = set()
        for entries, kind in ((threats, "threat"), (urls, "url")):
            for e in entries or []:
                ev = to_event(_entry_dict(e), self.provider_id, kind, naive_offset_s=offset)  # type: ignore[attr-defined]
                if ev is None or ev.key in seen or (kind == "url" and ev.outcome == "allowed"):
                    continue
                if not (since <= ev.timestamp <= until + 60):
                    continue
                seen.add(ev.key)
                out.append(ev)
        out.sort(key=lambda e: -e.timestamp)
        return out[:limit]
