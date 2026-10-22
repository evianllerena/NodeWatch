"""Per-connector HTTP timing for Support diagnostics (v0.10.21): ``integration_api_timing``.

Every real HTTP call a connector makes (Mist through ``MistClient``, every other vendor through the
SDK's ``HttpJsonClient``) is noted here in memory: connector, method, endpoint template (IDs and MACs
replaced), duration and success. Nothing else — no query values, bodies, headers or tokens.

``summary()`` answers, per connector over the last hour: calls, total and average milliseconds, errors,
the slowest single call and the endpoints that cost the most time. That is what tells a support
engineer "the map was slow because /stats/ports/search took 70 s in 21 pages".
"""

from __future__ import annotations

import re
import threading
import time
from collections import deque
from typing import Any

WINDOW_S = 3600.0
MAX_CALLS = 20_000  # per process; oldest dropped first
TOP_ENDPOINTS = 8

_lock = threading.Lock()
_calls: deque[tuple[float, str, str, float, bool]] = deque()  # (when, connector, endpoint, ms, ok)

_UUID = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
_MAC = re.compile(r"(?<=/)[0-9a-fA-F]{12}(?=/|$)")
_NUM = re.compile(r"(?<=/)\d{2,}(?=/|$)")


def endpoint(method: str, path: str) -> str:
    """``GET /api/v1/sites/<uuid>/stats`` → ``GET /api/v1/sites/{id}/stats`` (no IDs, MACs or query)."""
    p = str(path or "").split("?", 1)[0]
    p = _NUM.sub("{n}", _MAC.sub("{mac}", _UUID.sub("{id}", p)))
    return f"{str(method or 'GET').upper()} {p}"[:160]


def note(connector: str, method: str, path: str, duration_ms: float, ok: bool) -> None:
    """Record one real HTTP call. Never raises."""
    try:
        now = time.time()
        row = (now, str(connector or "unknown")[:60], endpoint(method, path), max(0.0, float(duration_ms)), bool(ok))
        with _lock:
            _calls.append(row)
            while len(_calls) > MAX_CALLS or (_calls and now - _calls[0][0] > WINDOW_S):
                _calls.popleft()
    except Exception:  # noqa: BLE001 - diagnostics must never break a call
        pass


def reset() -> None:
    with _lock:
        _calls.clear()


def summary(now: float | None = None) -> dict[str, Any]:
    """Per connector over the last hour: calls, total/avg ms, errors, slowest call, costliest endpoints."""
    now = time.time() if now is None else now
    with _lock:
        rows = [r for r in _calls if now - r[0] <= WINDOW_S]
    per: dict[str, dict[str, Any]] = {}
    for _when, conn, ep, ms, ok in rows:
        c = per.setdefault(conn, {"calls": 0, "total_ms": 0.0, "errors": 0, "slowest": None, "endpoints": {}})
        c["calls"] += 1
        c["total_ms"] += ms
        c["errors"] += 0 if ok else 1
        if c["slowest"] is None or ms > c["slowest"]["ms"]:
            c["slowest"] = {"endpoint": ep, "ms": round(ms)}
        e = c["endpoints"].setdefault(ep, {"endpoint": ep, "calls": 0, "total_ms": 0.0, "max_ms": 0.0})
        e["calls"] += 1
        e["total_ms"] += ms
        e["max_ms"] = max(e["max_ms"], ms)
    out: dict[str, Any] = {}
    for conn, c in sorted(per.items()):
        eps = sorted(c["endpoints"].values(), key=lambda e: -e["total_ms"])[:TOP_ENDPOINTS]
        out[conn] = {
            "calls": c["calls"],
            "total_ms": round(c["total_ms"]),
            "avg_ms": round(c["total_ms"] / c["calls"]) if c["calls"] else 0,
            "errors": c["errors"],
            "slowest": c["slowest"],
            "slowest_endpoint": eps[0]["endpoint"] if eps else "",
            "endpoints": [
                {
                    "endpoint": e["endpoint"],
                    "calls": e["calls"],
                    "total_ms": round(e["total_ms"]),
                    "avg_ms": round(e["total_ms"] / e["calls"]),
                    "max_ms": round(e["max_ms"]),
                }
                for e in eps
            ],
        }
    return {"window_s": int(WINDOW_S), "connectors": out}
