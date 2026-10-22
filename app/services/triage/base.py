"""Triage store interface (v0.10.18) — where acknowledge / snooze / dismiss / mute / notes / assignments live.

Like vendor connectors, triage stores are plug-ins: a module under ``app/services/triage/backends/``
that exposes ``MANIFEST`` (a :class:`BackendManifest`, which also draws the Settings form) and
``BACKEND`` (a :class:`BaseBackend` subclass). They are discovered at start-up by
:mod:`app.services.triage.registry`.

Every store speaks the same five verbs (:class:`TriageBackend`):

``append(event)``          persist one validated event (or queue it while offline)
``events_since(cursor)``   events this store has seen after ``cursor`` (an opaque int), and the new cursor
``current_state()``        the folded state ``{alerts, mutes, assign}`` (see :mod:`.fold`)
``health()``               sync status for Settings › Team triage
``describe()``             manifest + where the data lives (no secrets)

Outbound integrations (ticketing, chat) are *sinks*, not stores: see :class:`TriageSink`.
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from app.integrations.connectors.sdk import FIELD_TYPES, SettingField
from app.services.triage.events import EventError, order_key, validate_event, writer_id, writer_matches
from app.services.triage.fold import Fold

log = logging.getLogger("nodewatch.triage")
MATURITY = ("stable", "preview", "planned")


class TriageStoreError(RuntimeError):
    """Base class for store problems shown to the user."""


class ReadOnlyError(TriageStoreError):
    """The store can be read but this user cannot write to it (HTTP 403)."""


class StoreUnavailableError(TriageStoreError):
    """The store cannot be used at all (planned backend, misconfiguration) (HTTP 503)."""


@dataclass(frozen=True)
class BackendManifest:
    backend_id: str  # "local", "shared_folder", "nodewatch_server"
    label: str  # what Settings shows: "Only this PC"
    description: str
    settings: tuple[SettingField, ...] = ()
    shared: bool = False  # True when teammates see each other's actions
    maturity: str = "stable"  # stable | preview | planned (planned = listed, cannot be selected)
    order: int = 50

    @property
    def available(self) -> bool:
        return self.maturity != "planned"

    def validate(self) -> list[str]:
        errors = []
        if not self.backend_id or not self.backend_id.replace("_", "").isalnum():
            errors.append("backend_id must be letters, digits and underscores")
        if not self.label:
            errors.append("label is required")
        if self.maturity not in MATURITY:
            errors.append(f"maturity must be one of {MATURITY}")
        for f in self.settings:
            if f.type not in FIELD_TYPES:
                errors.append(f"setting {f.key}: unknown type {f.type!r}")
            if f.type == "secret":
                # Triage settings are a plain JSON file; a backend that needs a credential must keep it
                # in Windows Credential Manager (app.integrations.secrets) — never in a manifest field.
                errors.append(f"setting {f.key}: triage backends may not declare secret fields")
        keys = [f.key for f in self.settings]
        if len(keys) != len(set(keys)):
            errors.append("setting keys must be unique")
        return errors

    def public_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["settings"] = [asdict(s) for s in self.settings]
        d["available"] = self.available
        return d


@runtime_checkable
class TriageBackend(Protocol):
    manifest: BackendManifest

    def append(self, event: dict) -> None: ...

    def events_since(self, cursor: int) -> tuple[list[dict], int]: ...

    def current_state(self) -> dict: ...

    def health(self) -> dict: ...

    def describe(self) -> dict: ...


@runtime_checkable
class TriageSink(Protocol):
    """An outbound integration told about every triage event *made on this PC*.

    ``on_event`` runs after the event is stored, must return quickly (queue slow work) and must be
    idempotent by ``event["id"]``. Only locally authored events are dispatched, so a team of ten
    NodeWatch PCs reading the same shared folder creates one ticket, not ten.
    """

    sink_id: str

    def on_event(self, event: dict) -> None: ...


class BaseBackend:
    """Shared machinery: the fold, per-writer sequence, ingest with validation, cursors, health."""

    manifest: BackendManifest

    def __init__(self, settings: dict | None = None, *, state_dir: Path, actor: dict) -> None:
        self.settings = dict(settings or {})
        self.state_dir = Path(state_dir)
        self.actor = dict(actor)
        self.fold = Fold()
        self.lock = threading.RLock()
        self.seq = 0
        self.arrival: list[str] = []
        # events stamped beyond the clock-skew tolerance, retried every sync: {(writer, id): (writer, raw, loc)}
        self.deferred: dict[tuple[str, str], tuple[str | None, dict, tuple | None]] = {}
        self.deferred_overflow = 0  # future events not kept in memory (re-read from the file later)
        self.fold.local_writer = writer_id(self.actor)
        self.rejected = 0
        self.last_sync: float | None = None
        self.last_error = ""

    # ------------------------------------------------------------------ class-level hooks
    @classmethod
    def clean_settings(cls, values: dict) -> dict:
        """Validate the Settings form for this backend; raise ValueError with a readable message."""
        return {}

    @classmethod
    def test_settings(cls, values: dict, *, actor: dict) -> dict:
        """Settings › Test. Must not change any state other than a probe file."""
        return {"ok": True, "message": "Nothing to test."}

    # ------------------------------------------------------------------ ingest
    DEFERRED_PER_WRITER = 1000
    # v0.10.22: an event stamped more than this far ahead is refused, not held. Holding events from
    # far in the future let one be planted to win last-writer-wins against everything done before
    # its time ("time bomb"). An hour still covers a badly set clock on a teammate's PC.
    MAX_DEFER_S = 3600.0

    def _rewind(self, loc: tuple) -> None:
        """Hook: read the file again from ``loc`` later (folder stores)."""

    def _too_far_ahead(self, raw, now: float) -> bool:
        try:
            return float(raw.get("ts")) > now + self.MAX_DEFER_S
        except (TypeError, ValueError, AttributeError):
            return True

    def ingest(self, items, *, now: float | None = None) -> int:
        """Validate and fold raw events ``[(writer or None, raw[, (file, offset)])]``; returns how many were new.

        ``writer`` is the log file the event came from (None = this PC's own data). An event whose actor
        does not match its file is ignored. Events from the future (beyond the skew tolerance) wait in
        :attr:`deferred` and are accepted once the clock passes them; if one writer has too many waiting,
        the extra ones are re-read from their file later instead of being kept — never lost.
        """
        now = time.time() if now is None else now
        added = 0
        with self.lock:
            pending = list(self.deferred.values())
            self.deferred.clear()
            per_writer: dict[str, int] = {}
            overflow = 0
            from_files = False
            for item in pending + [tuple(x) + (None,) * (3 - len(x)) for x in items]:
                writer, raw, loc = item
                from_files = from_files or loc is not None
                try:
                    ev = validate_event(raw, now=now, strict=False)
                except EventError as exc:
                    if "future" not in str(exc) or self._too_far_ahead(raw, now):
                        self.rejected += 1
                        continue
                    wkey = writer or ""
                    key = (wkey, str(raw.get("id")))
                    if key in self.deferred:
                        continue
                    if loc is not None and per_writer.get(wkey, 0) >= self.DEFERRED_PER_WRITER:
                        overflow += 1
                        self._rewind(loc)
                        continue
                    per_writer[wkey] = per_writer.get(wkey, 0) + 1
                    self.deferred[key] = (writer, raw, loc)
                    continue
                if writer is not None and not writer_matches(ev["actor"], writer):
                    self.rejected += 1  # an event in someone's file claiming another identity
                    continue
                if writer_id(ev["actor"]) == self.fold.local_writer:
                    self.seq = max(self.seq, ev["seq"])
                if self.fold.apply(ev):
                    self.arrival.append(ev["id"])
                    added += 1
            if from_files:
                self.deferred_overflow = overflow
        return added

    def next_seq(self) -> int:
        with self.lock:
            self.seq += 1
            return self.seq

    # ------------------------------------------------------------------ protocol
    def sync(self, force: bool = False) -> None:
        """Read what is new (shared stores). Local stores have nothing to do."""

    def append(self, event: dict) -> None:
        self.append_many([event])

    def append_many(self, events: list[dict]) -> None:  # pragma: no cover - abstract
        raise NotImplementedError

    def import_events(self, events: list[dict]) -> int:
        """Copy existing events (keeping ids and authors) — used when switching stores."""
        return self.append_many_imported(events)

    def append_many_imported(self, events: list[dict]) -> int:  # pragma: no cover - abstract
        raise NotImplementedError

    def events_since(self, cursor: int) -> tuple[list[dict], int]:
        self.sync()
        with self.lock:
            cursor = max(0, int(cursor or 0))
            ids = self.arrival[cursor:]
            return [self.fold.events[i] for i in ids if i in self.fold.events], len(self.arrival)

    def current_state(self) -> dict:
        self.sync()
        return self.fold.snapshot()

    @property
    def writable(self) -> bool:
        return True

    def pending(self) -> int:
        return 0

    def health(self) -> dict:
        with self.lock:
            others = [
                {k: a[k] for k in ("user", "display", "machines", "last_ts", "events")}
                for a in self.fold.actors.values()
            ]
        conflicts = self.fold.conflicts()
        for a in others:
            a["conflict"] = a["user"].lower() in conflicts
        others.sort(key=lambda a: -a["last_ts"])
        return {
            "backend": self.manifest.backend_id,
            "label": self.manifest.label,
            "shared": self.manifest.shared,
            "mode": "ok",
            "writable": self.writable,
            "last_sync": self.last_sync,
            "last_error": self.last_error,
            "pending": self.pending(),
            "events": len(self.fold.events),
            "rejected": self.rejected,
            "future_events": len(self.deferred) + self.deferred_overflow,
            "users": others[:50],
            "me": self.actor,
        }

    def describe(self) -> dict:
        return {**self.manifest.public_dict(), "location": ""}

    def latest_order(self) -> tuple:
        with self.lock:
            return max((order_key(e) for e in self.fold.events.values()), default=())
