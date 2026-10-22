"""Stale-while-revalidate cache for topology graphs (v0.10.21).

Building a map can take seconds to a minute on a large organisation (vendor statistics are slow), so
the map never waits for it once it has been built before:

* the last built graph of every level/scope is kept in memory and persisted under the data folder
  (``state/topology/<kind>-<hash>.json``), so it survives a restart;
* a request answers instantly with what is there (``stale: true`` once it is older than the TTL) and
  starts a background rebuild — one per scope at a time (single-flight);
* a builder may publish a *partial* result first (devices before links) so a cold map can draw boxes
  while the cabling is still being read;
* the answer always carries ``built_at``, ``age_s``, ``stale``, ``refreshing``, ``partial`` and the
  last ``refresh_error`` so the UI can say "Updated 40 s ago · refreshing…" and poll until it swaps in.
"""

from __future__ import annotations

import hashlib
import json
import logging
import threading
import time
from pathlib import Path
from typing import Any, Callable

from app.core.config import STATE_ROOT
from app.core.file_utils import write_private_text

log = logging.getLogger("nodewatch.topology")

ROOT: Path = STATE_ROOT / "topology"
COLD_WAIT_S = 45.0  # a never-built scope waits this long for the first (partial) result
MAX_MEMORY_SCOPES = 48
KEEP_GOOD_S = 6 * 3600.0  # a degraded build (a source failed with no fallback) never replaces a
# complete result younger than this; the complete one keeps being served with ``refresh_error`` set

Builder = Callable[[str, Callable[[dict[str, Any]], None]], dict[str, Any]]


class SwrCache:
    def __init__(self, kind: str, ttl_s: float, build: Builder) -> None:
        self.kind = kind
        self.ttl_s = ttl_s
        self._build = build
        self._cond = threading.Condition()
        self._mem: dict[str, tuple[float, dict[str, Any]]] = {}
        self._partial: dict[str, tuple[float, dict[str, Any]]] = {}
        self._threads: dict[str, threading.Thread] = {}
        self._errors: dict[str, str] = {}
        self._dirty: set[str] = set()  # invalidated: serve as stale and rebuild on the next request
        self._invalidated_at = 0.0
        self.builds = 0  # completed background builds (tests, diagnostics)

    # ---------------------------------------------------------------- persistence
    def _path(self, scope: str) -> Path:
        digest = hashlib.sha256(f"{self.kind}|{scope}".encode()).hexdigest()[:24]
        return ROOT / f"{self.kind}-{digest}.json"

    def _load(self, scope: str) -> tuple[float, dict[str, Any]] | None:
        try:
            data = json.loads(self._path(scope).read_text(encoding="utf-8"))
        except FileNotFoundError:
            return None
        except (OSError, ValueError) as exc:
            log.info("topology: cached %s graph unreadable: %s", self.kind, exc)
            return None
        if not isinstance(data, dict) or not isinstance(data.get("result"), dict) or data.get("scope") != scope:
            return None
        try:
            return float(data.get("built_at") or 0), data["result"]
        except (TypeError, ValueError):
            return None

    def _save(self, scope: str, built_at: float, result: dict[str, Any]) -> None:
        path = self._path(scope)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            write_private_text(  # atomic, owner-only (v0.10.40)
                path,
                json.dumps({"scope": scope, "built_at": built_at, "result": result}, default=str, separators=(",", ":")),
            )
        except (OSError, TypeError, ValueError) as exc:
            log.info("topology: %s graph not persisted: %s", self.kind, exc)

    # ---------------------------------------------------------------- public
    def peek(self, scope: str) -> tuple[float, dict[str, Any]] | None:
        """Last full result (memory, else disk) without building anything."""
        with self._cond:
            hit = self._mem.get(scope)
        if hit:
            return hit
        disk = self._load(scope)
        if disk:
            with self._cond:
                self._mem.setdefault(scope, disk)
        return disk

    def refreshing(self, scope: str) -> bool:
        with self._cond:
            return scope in self._threads

    def refresh(self, scope: str) -> bool:
        """Start a background rebuild unless one is running. True when this call started it."""
        with self._cond:
            if scope in self._threads:
                return False
            t = threading.Thread(target=self._run, args=(scope,), name=f"topology-{self.kind}", daemon=True)
            self._threads[scope] = t
        t.start()
        return True

    def get(self, scope: str, *, fresh: bool = False, wait_s: float = COLD_WAIT_S) -> dict[str, Any]:
        """Instant answer for a scope (see the module docs). ``fresh`` starts a rebuild even when current."""
        now = time.time()
        have = self.peek(scope)
        with self._cond:
            dirty = scope in self._dirty or bool(have and have[0] < self._invalidated_at)
        if have and not fresh and not dirty and now - have[0] < self.ttl_s:
            return self._decorate(scope, have, stale=False)
        self.refresh(scope)
        if have:
            return self._decorate(scope, have, stale=dirty or now - have[0] >= self.ttl_s)
        # Never built: wait for the first partial or full result (or the build failing).
        with self._cond:
            self._cond.wait_for(
                lambda: scope in self._mem or scope in self._partial or scope not in self._threads, timeout=wait_s
            )
            full = self._mem.get(scope)
            part = self._partial.get(scope)
            err = self._errors.get(scope)
        if full:
            return self._decorate(scope, full, stale=False)
        if part:
            return self._decorate(scope, part, stale=False, partial=True)
        raise RuntimeError(err or "The map is still being built — try again in a moment.")

    def wait_idle(self, scope: str, timeout: float = 30.0) -> bool:
        """Block until no rebuild runs for ``scope`` (tests, synchronous callers)."""
        with self._cond:
            return self._cond.wait_for(lambda: scope not in self._threads, timeout=timeout)

    def put(self, scope: str, result: dict[str, Any]) -> bool:
        """Replace a scope's result with an enriched one (e.g. late WAN circuits), keeping its build time.

        Skipped (False) when the cache already holds a newer build than the one ``result`` was derived
        from (compared by ``generated_at``), so a slow enrichment never overwrites a fresher map."""
        base = float(result.get("generated_at") or 0)
        with self._cond:
            have = self._mem.get(scope)
            if have is not None and float(have[1].get("generated_at") or 0) > base:
                return False
            built_at = have[0] if have else time.time()
            self._mem[scope] = (built_at, result)
        self._save(scope, built_at, result)
        return True

    def invalidate(self) -> None:
        """Every result built before now is out of date (e.g. the site mapping changed): the next request
        for a scope answers with what is there, marked stale, and rebuilds it in the background."""
        with self._cond:
            self._invalidated_at = time.time()

    def clear_memory(self) -> None:
        with self._cond:
            self._mem.clear()
            self._partial.clear()
            self._errors.clear()

    # ---------------------------------------------------------------- internals
    def _decorate(
        self, scope: str, hit: tuple[float, dict[str, Any]], *, stale: bool, partial: bool = False
    ) -> dict[str, Any]:
        built_at, result = hit
        with self._cond:
            running = scope in self._threads
            err = self._errors.get(scope, "")
        return {
            **result,
            "built_at": built_at,
            "age_s": round(max(0.0, time.time() - built_at), 1),
            "stale": bool(stale),
            "refreshing": running,
            "partial": bool(partial or result.get("partial")),
            "refresh_error": err,
        }

    def _publish_partial(self, scope: str, result: dict[str, Any]) -> None:
        with self._cond:
            self._partial[scope] = (time.time(), {**result, "partial": True})
            self._cond.notify_all()

    def _run(self, scope: str) -> None:
        try:
            result = self._build(scope, lambda r: self._publish_partial(scope, r))
            built_at = time.time()
            if result.get("degraded"):
                prev = self.peek(scope)
                if prev and not prev[1].get("degraded") and built_at - prev[0] < KEEP_GOOD_S:
                    # A source failed and has no last-good fallback: keep the complete map.
                    failed = set(result.get("failed_sources") or [])
                    text = "; ".join(
                        f"{s.get('product') or s.get('source')}: {s.get('error')}"
                        for s in result.get("sources") or []
                        if s.get("source") in failed
                    )
                    log.info(
                        "topology: %s rebuild of %r degraded (%s); keeping the last complete map",
                        self.kind,
                        scope,
                        text,
                    )
                    with self._cond:
                        self._errors[scope] = f"Not refreshed — a source could not be read ({text})."
                        self._partial.pop(scope, None)
                        self._dirty.discard(scope)
                    return
            with self._cond:
                self._mem[scope] = (built_at, result)
                self._partial.pop(scope, None)
                self._errors.pop(scope, None)
                self._dirty.discard(scope)
                while len(self._mem) > MAX_MEMORY_SCOPES:
                    self._mem.pop(next(iter(self._mem)))
            if not result.get("degraded"):
                self._save(scope, built_at, result)
            self.builds += 1
        except Exception as exc:  # noqa: BLE001 - the stale graph keeps being served; the error is shown
            log.info("topology: %s rebuild of %r failed: %s", self.kind, scope, exc)
            with self._cond:
                self._errors[scope] = str(exc) or type(exc).__name__
                self._partial.pop(scope, None)
        finally:
            with self._cond:
                self._threads.pop(scope, None)
                self._cond.notify_all()
