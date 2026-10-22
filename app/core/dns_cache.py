"""Process-wide DNS answer cache with last-good fallback (v0.10.23).

Field diagnostics (v0.10.22) showed about 5 % of name lookups on a customer PC timing out after
~12 s ("[Errno 11001] getaddrinfo failed") for every cloud API alike (Mist, Palo Alto,
Orchestrator). Python asks the resolver again for every new connection, so each of those
stalls cost a 12 s wait and a failed call, and the failure then showed up as a broken
connection in the UI.

``install()`` wraps :func:`socket.getaddrinfo` once for the whole backend:

* a successful answer is reused for ``FRESH_S`` seconds (the OS resolver cache would normally
  do this, but a misbehaving first DNS server defeats it);
* when a lookup fails, the last good answer for the same query is returned if it is younger
  than ``STALE_S`` - the address of a SaaS API endpoint does not change minute to minute, and
  TLS still verifies the certificate against the host name, so a stale address can never be
  used to impersonate the server;
* literal IP addresses and ``localhost`` are passed straight through (never cached).

v0.10.24: the last good answers are also kept in ``<data>/state/dns_cache.json`` (host names and
addresses only) and loaded at start-up as stale fallbacks, so the first calls after a launch survive
a resolver timeout too. They are never served as fresh answers.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import socket
import threading
import time
from typing import Any
from app.core.file_utils import write_private_text

log = logging.getLogger("nodewatch.dns")

FRESH_S = 300.0
STALE_S = 24 * 3600.0
MAX_ENTRIES = 512

_lock = threading.Lock()
_cache: dict[tuple, tuple[float, Any]] = {}
_installed = False
_original = socket.getaddrinfo
stats = {"hits": 0, "misses": 0, "stale_served": 0, "failures": 0}


def _is_literal(host: Any) -> bool:
    if host is None:
        return True
    text = host.decode() if isinstance(host, bytes) else str(host)
    if not text or text.lower() in ("localhost", "localhost.localdomain"):
        return True
    try:
        ipaddress.ip_address(text.split("%", 1)[0])
        return True
    except ValueError:
        return False


_DISK_EVERY_S = 300.0
_disk_saved_at = -1e18


def _disk_path():
    try:
        from app.core.config import DATA_ROOT

        return DATA_ROOT / "state" / "dns_cache.json"
    except Exception:  # noqa: BLE001
        return None


def _load_disk() -> None:
    path = _disk_path()
    if path is None:
        return
    try:
        rows = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return
    now = time.monotonic()
    age_cap = STALE_S - FRESH_S - 1  # loaded answers start stale (older than FRESH_S)
    with _lock:
        for row in rows if isinstance(rows, list) else []:
            try:
                key = tuple(row["key"])
                answer = [(a[0], a[1], a[2], a[3], tuple(a[4])) for a in row["answer"]]
                # Real age: age when saved + wall-clock time since (the app may have been closed for weeks).
                age = float(row.get("age", 0)) + max(0.0, time.time() - float(row.get("saved_at", time.time())))
                if age >= STALE_S:
                    continue
                age = min(max(age, FRESH_S + 1), age_cap)
            except (KeyError, TypeError, ValueError, IndexError):
                continue
            if key not in _cache:
                _cache[key] = (now - age, answer)


def _save_disk(force: bool = False) -> None:
    global _disk_saved_at
    now = time.monotonic()
    if not force and now - _disk_saved_at < _DISK_EVERY_S:
        return
    _disk_saved_at = now
    path = _disk_path()
    if path is None:
        return
    with _lock:
        rows = [
            {"key": list(k), "age": round(now - t, 1), "saved_at": round(time.time(), 1), "answer": [[int(a[0]), int(a[1]), a[2], a[3], list(a[4])] for a in ans]}
            for k, (t, ans) in _cache.items()
            if isinstance(k[0], str)
        ]
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        write_private_text(path, json.dumps(rows))  # atomic, owner-only (v0.10.40)
    except OSError:
        pass


_refreshing: set[tuple] = set()


def _refresh_later(key: tuple) -> None:
    with _lock:
        if key in _refreshing:
            return
        _refreshing.add(key)

    def run() -> None:
        try:
            answer = _original(*key)
        except (socket.gaierror, OSError) as exc:
            stats["failures"] += 1
            stats["stale_served"] += 1
            log.info("DNS lookup for %s failed (%s); using the last good address", key[0], exc)
            answer = None
        finally:
            with _lock:
                _refreshing.discard(key)
        if answer:
            with _lock:
                _cache[key] = (time.monotonic(), list(answer))
            _save_disk()

    threading.Thread(target=run, name="dns-refresh", daemon=True).start()


def _cached_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):  # noqa: A002 - socket API names
    if _is_literal(host):
        return _original(host, port, family, type, proto, flags)
    key = (host, port, family, type, proto, flags)
    now = time.monotonic()
    with _lock:
        hit = _cache.get(key)
    if hit and now - hit[0] < FRESH_S:
        stats["hits"] += 1
        return list(hit[1])
    if hit and now - hit[0] < STALE_S:
        # v0.10.35: stale-while-revalidate. A failing resolver on the customer PC takes ~12 s to give up
        # (Windows getaddrinfo), and every API call that needed a new connection waited for it - pages
        # took 12-18 s. The last good answer is served at once and the lookup runs in the background;
        # TLS still checks the certificate against the host name.
        stats["hits"] += 1
        _refresh_later(key)
        return list(hit[1])
    stats["misses"] += 1
    try:
        answer = _original(host, port, family, type, proto, flags)
    except (socket.gaierror, OSError) as exc:
        stats["failures"] += 1
        if hit and now - hit[0] < STALE_S:
            stats["stale_served"] += 1
            log.info("DNS lookup for %s failed (%s); using the last good address", host, exc)
            return list(hit[1])
        raise
    with _lock:
        if len(_cache) >= MAX_ENTRIES:
            oldest = min(_cache, key=lambda k: _cache[k][0])
            _cache.pop(oldest, None)
        _cache[key] = (now, list(answer))
    _save_disk()
    return answer


def install() -> None:
    """Idempotent; called once from app.main before any connector runs."""
    global _installed
    if _installed:
        return
    _load_disk()
    socket.getaddrinfo = _cached_getaddrinfo
    _installed = True


def snapshot() -> dict[str, Any]:
    with _lock:
        size = len(_cache)
    return {**stats, "entries": size, "installed": _installed}
