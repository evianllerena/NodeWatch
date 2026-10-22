"""The triage store as the Command Center sees it: a dict of records, backed by events.

:class:`TriageStoreFacade` keeps the interface ``attention_service`` has always used — ``load()`` returns
``{"alerts": {key: record}, "mutes": {id: rule}, "assign": {...}}`` and ``update(fn)`` lets a function
change that dict — but underneath it turns every *change* into triage events and appends them to the
active store (this PC only, a shared folder, …). Undo works the same way: restoring the previous
records produces compensating events.

Two kinds of change are deliberately *not* events, because each PC works them out for itself and
publishing them would only add noise to a shared log:

* bookkeeping (``last_present`` — when an alert was last seen), and
* housekeeping clean-ups made by ``housekeep(fn)``: forgetting records of alerts that vanished,
  expired snoozes / mutes, "until it changes" snoozes whose alert changed. These hide the record on
  this PC only (keyed by the deciding event's order, so a newer action by anyone shows again).

Both live in a small per-PC overlay file next to the store.
"""

from __future__ import annotations

import copy
import json
import threading
import time
from collections import defaultdict
from pathlib import Path
from typing import Any, Callable

from app.core.config import STATE_ROOT
from app.core.file_utils import write_private_text
from app.services.triage import sinks
from app.services.triage.base import BaseBackend
from app.services.triage.events import MAX_SKEW_S, MAX_TARGETS, event_keys, new_event

STATE_OF = {"acknowledged": "ack", "snoozed": "snooze", "dismissed": "dismiss"}
CLEAR_OF = {"acknowledged": "unack", "snoozed": "unsnooze", "dismissed": "restore"}
RECORD_FIELDS = ("until", "until_change", "duration", "reason", "via")
MUTE_FIELDS = ("type", "label", "source", "site_key", "site_name", "reason", "until")
CONTEXT_FIELDS = ("title", "type", "source", "site_name", "device_name")


def _via(rec: dict) -> str:
    if rec.get("via"):
        return str(rec["via"])[:60]
    by = str(rec.get("by") or "")
    if "in Mist" in by:
        return "in Mist"
    return "NodeWatch" if by.startswith("NodeWatch") else ""


def _sig(rec: dict | None) -> tuple:
    if not rec:
        return ()
    return (rec.get("state"), *(rec.get(f) or "" for f in ("until", "until_change", "duration", "reason")), _via(rec))


def _mute_sig(rule: dict | None) -> tuple:
    return tuple((rule or {}).get(f) or "" for f in MUTE_FIELDS) if rule else ()


class TriageStoreFacade:
    def __init__(
        self,
        path: Path | None = None,
        *,
        backend: BaseBackend | None = None,
        overlay_path: Path | None | bool = None,
    ) -> None:
        from app.services.triage.backends.local import LocalBackend
        from app.services.triage.manager import MANAGER

        self.manager = MANAGER
        self._lock = threading.RLock()
        self._tl = threading.local()
        if backend is not None:
            self._backend = backend
            self.path = Path(path) if path else Path("/nonexistent/preview")
        elif path is not None:
            self.path = Path(path)
            self._backend = LocalBackend(state_dir=self.path.parent, actor=MANAGER.actor(), legacy_path=self.path)
        else:
            self.path = STATE_ROOT / "attention_state.json"
            self._backend = None  # follow Settings › Team triage
        if overlay_path is False:
            self.overlay_path = None
        else:
            self.overlay_path = (
                Path(overlay_path) if overlay_path else self.path.with_name(self.path.stem + ".local.json")
            )
        self._overlay: dict | None = None if self.overlay_path else self._empty_overlay()

    # ------------------------------------------------------------------ plumbing
    @property
    def backend(self) -> BaseBackend:
        return self._backend if self._backend is not None else self.manager.backend()

    def actor(self) -> dict:
        b = self.backend
        display = self.manager.config()["display_name"]
        return {**b.actor, "display": display or b.actor.get("display") or b.actor["user"]}

    @staticmethod
    def _empty_overlay() -> dict:
        return {"presence": {}, "hidden": {}, "hidden_mutes": {}, "flags": {}}

    def _load_overlay(self) -> dict:
        if self._overlay is not None:
            return self._overlay
        ov = self._empty_overlay()
        try:
            data = json.loads(self.overlay_path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                for k in ov:
                    if isinstance(data.get(k), dict):
                        ov[k] = data[k]
        except (OSError, ValueError):
            self._seed_from_v1(ov)
        self._overlay = ov
        return ov

    def _seed_from_v1(self, ov: dict) -> None:
        """First start after the migration: keep each record's 'last seen' and the legacy flag."""
        backup = self.path.with_name(self.path.stem + ".v1-backup.json")
        try:
            data = json.loads(backup.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return
        for key, rec in (data.get("alerts") or {}).items():
            if isinstance(rec, dict) and rec.get("last_present") is not None:
                ov["presence"][key] = rec["last_present"]
        if data.get("legacy_migrated"):
            ov["flags"]["legacy_migrated"] = True

    def _save_overlay(self) -> None:
        if self.overlay_path is None or self._overlay is None:
            return
        try:
            write_private_text(self.overlay_path, json.dumps(self._overlay, separators=(",", ":")))
        except OSError:
            pass

    # ------------------------------------------------------------------ read
    def load(self) -> dict:
        snap = self.backend.current_state()
        with self._lock:
            ov = self._load_overlay()
            alerts = {}
            for key, rec in snap["alerts"].items():
                hidden = ov["hidden"].get(key)
                if hidden and rec["order"] <= hidden:
                    continue
                r = dict(rec)
                r["last_present"] = ov["presence"].get(key, rec["at"])
                alerts[key] = r
            mutes = {}
            for rid, rule in snap["mutes"].items():
                hidden = ov["hidden_mutes"].get(rid)
                if hidden and rule["order"] <= hidden:
                    continue
                mutes[rid] = dict(rule)
            return {
                "alerts": alerts,
                "mutes": mutes,
                "assign": {k: dict(v) for k, v in snap["assign"].items()},
                "legacy_migrated": bool(ov["flags"].get("legacy_migrated")),
            }

    # ------------------------------------------------------------------ write
    def update(self, fn: Callable[[dict], Any]) -> Any:
        """A user action: every changed record becomes an event (removals are compensating events)."""
        return self._change(fn, housekeeping=False)

    def housekeep(self, fn: Callable[[dict], Any]) -> Any:
        """Local clean-up: removals only hide records on this PC; real additions are still events."""
        return self._change(fn, housekeeping=True)

    def last_emitted(self) -> dict[str, str]:
        """{key: event id} written by this thread's last update (undo uses it)."""
        return dict(getattr(self._tl, "emitted", {}) or {})

    def _change(self, fn, *, housekeeping: bool) -> Any:
        with self._lock:
            before = self.load()
            data = copy.deepcopy(before)
            result = fn(data)
            ov = self._load_overlay()
            dirty = False
            groups: dict[tuple, list[tuple[str, dict]]] = defaultdict(list)
            b_alerts, a_alerts = before["alerts"], data.get("alerts") or {}
            for key in sorted(set(b_alerts) | set(a_alerts)):
                b, a = b_alerts.get(key), a_alerts.get(key)
                if a is not None and a.get("last_present") is not None and ov["presence"].get(key) != a["last_present"]:
                    if b is None or a.get("last_present") != b.get("last_present"):
                        ov["presence"][key] = a["last_present"]
                        dirty = True
                if _sig(a) == _sig(b):
                    continue
                if a is None:
                    if housekeeping:
                        ov["hidden"][key] = b["order"]
                        ov["presence"].pop(key, None)
                        dirty = True
                        continue
                    action, fields, rec = CLEAR_OF.get(b.get("state"), "restore"), {}, b
                else:
                    action = STATE_OF.get(a.get("state"))
                    if not action:
                        continue
                    fields = {f: a.get(f) for f in RECORD_FIELDS if f != "via" and a.get(f) not in (None, "")}
                    if _via(a):
                        fields["via"] = _via(a)
                    rec = a
                groups[(action, json.dumps(fields, sort_keys=True, default=str))].append((key, rec))
            events = self._group_events(groups, kind="alert")
            b_m, a_m = before["mutes"], data.get("mutes") or {}
            for rid in sorted(set(b_m) | set(a_m)):
                b, a = b_m.get(rid), a_m.get(rid)
                if _mute_sig(a) == _mute_sig(b):
                    continue
                if a is None:
                    if housekeeping:
                        ov["hidden_mutes"][rid] = b["order"]
                        dirty = True
                        continue
                    events.append(self._event("unmute", rid, target_kind="mute"))
                else:
                    fields = {f: a.get(f) for f in MUTE_FIELDS if a.get(f) not in (None, "")}
                    events.append(
                        self._event("mute", rid, target_kind="mute", fields=fields, vendor=a.get("source", ""))
                    )
            if bool(data.get("legacy_migrated")) != bool(before.get("legacy_migrated")):
                ov["flags"]["legacy_migrated"] = bool(data.get("legacy_migrated"))
                dirty = True
            self._commit(events)
            if dirty:
                self._save_overlay()
            return result

    def _commit(self, events: list[dict]) -> None:
        self._tl.emitted = {k: e["id"] for e in events for k in event_keys(e)}
        if events:
            self.backend.append_many(events)
            sinks.dispatch(events)

    def _ts(self, keys) -> float:
        now = time.time()
        last = self.backend.fold.last_ts(keys)
        return min(max(now, last + 0.001), now + MAX_SKEW_S - 1)

    def _event(self, action, target, *, target_kind="alert", targets=(), fields=None, context=None, vendor=""):
        keys = [target, *targets]
        return new_event(
            action,
            target,
            actor=self.actor(),
            ts=self._ts(keys),
            seq=self.backend.next_seq(),
            target_kind=target_kind,
            targets=list(targets),
            fields=fields,
            context=context,
            source_vendor=vendor,
        )

    def _group_events(self, groups: dict, *, kind: str) -> list[dict]:
        events = []
        for (action, fields_json), items in groups.items():
            fields = json.loads(fields_json)
            for i in range(0, len(items), MAX_TARGETS):
                chunk = items[i : i + MAX_TARGETS]
                rec = chunk[0][1] or {}
                context = {f: str(rec.get(f) or "") for f in CONTEXT_FIELDS if rec.get(f)}
                if len(chunk) > 1:
                    context.pop("site_name", None)
                    context.pop("device_name", None)
                keys = [k for k, _ in chunk]
                events.append(
                    self._event(
                        action,
                        keys[0],
                        target_kind=kind,
                        targets=keys[1:],
                        fields=fields,
                        context=context,
                        vendor=str(rec.get("source") or ""),
                    )
                )
        return events

    def record(
        self,
        action: str,
        keys: list[str],
        *,
        fields: dict | None = None,
        context: dict | None = None,
        target: str | None = None,
        target_kind: str = "alert",
        vendor: str = "",
    ) -> list[dict]:
        """Write team events that are not record changes (note, assign, unassign)."""
        keys = list(dict.fromkeys(keys))
        with self._lock:
            events = []
            if target:
                first = keys[:MAX_TARGETS]
                events.append(
                    self._event(
                        action,
                        target,
                        target_kind=target_kind,
                        targets=first,
                        fields=fields,
                        context=context,
                        vendor=vendor,
                    )
                )
            else:
                for i in range(0, len(keys), MAX_TARGETS):
                    chunk = keys[i : i + MAX_TARGETS]
                    events.append(
                        self._event(
                            action,
                            chunk[0],
                            target_kind=target_kind,
                            targets=chunk[1:],
                            fields=fields,
                            context=context,
                            vendor=vendor,
                        )
                    )
            self._commit(events)
            return events

    def current_event(self, key: str) -> str:
        """Id of the event that currently decides ``key``'s triage state ('' if none)."""
        winner = self.backend.fold.state_reg.get(key)
        return winner["id"] if winner else ""

    # ------------------------------------------------------------------ team views
    def history(self, keys, *, limit: int = 40, actions=None) -> list[dict]:
        self.backend.sync()
        return self.backend.fold.history(keys, limit=limit, actions=actions)
