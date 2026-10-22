"""Fold triage events into state — deterministic and independent of arrival order.

Each piece of state is a *last-writer-wins register* keyed by what it is about:

* the triage state of one alert key (ack / snooze / dismiss set it; unack / unsnooze / restore clear it),
* the assignee of one alert key (assign / unassign),
* one mute rule (mute / unmute).

An event updates a register only if its :func:`~app.services.triage.events.order_key`
``(ts, user, machine, seq, id)`` is greater than the event currently held there. Because that order is
total and every reader applies the same rule, any set of events gives the same state whatever order the
logs were read in (two PCs reading the share at different moments converge). Notes are an append-only
set. Duplicate events (same id — e.g. our own event read back from the share) are ignored; if two
*different* events carry the same id, every PC keeps the one with the smaller content hash (copies
whose actor does not match their file never get here — the store rejects them first).

Attribution is shown as ``Display (user@machine)``; a display name also used by another user is
flagged, and a ``via`` claim ("in Mist") is only shown as fact for events this PC wrote itself —
anyone else's is shown as their claim. Names are not authenticated: see docs/TEAM_TRIAGE.md › Trust.
"""

from __future__ import annotations

import bisect
import threading
from typing import Any

from app.services.triage.events import (
    CLEAR_ACTIONS,
    STATE_ACTIONS,
    content_hash,
    event_keys,
    ident,
    name_skeleton,
    order_key,
    writer_id,
)

HISTORY_PER_KEY = 30


def actor_label(event: dict, *, local_writer: str = "", conflicts: frozenset = frozenset()) -> str:
    """``Display (user@machine)`` + a flag when the display name is also used by someone else + ``via``
    (a fact for this PC's own events, "says …" for anyone else's)."""
    a = event.get("actor") or {}
    user = a.get("user") or "someone"
    display = a.get("display") or user
    who = ident(a) if display.lower() == user.lower() else f"{display} ({ident(a)})"
    if user.lower() in conflicts:
        who += " ⚠ name also used by another user"
    via = (event.get("fields") or {}).get("via")
    if via:
        trusted = bool(local_writer) and writer_id(a) == local_writer
        who += f" · {via}" if trusted else f" · says “{via}”"
    return who


class Fold:
    def __init__(self) -> None:
        self.lock = threading.RLock()
        self.events: dict[str, dict] = {}
        self.state_reg: dict[str, dict] = {}
        self.assign_reg: dict[str, dict] = {}
        self.mute_reg: dict[str, dict] = {}
        self.index: dict[str, list[tuple]] = {}
        self.max_ts: dict[str, float] = {}
        self.actors: dict[str, dict] = {}
        self.hashes: dict[str, str] = {}
        self.version = 0
        self.local_writer = ""  # this PC's writer id: its own "via" claims are facts
        self._snap: tuple[int, dict] | None = None
        self._conflicts: tuple[int, frozenset] | None = None

    def _reset(self) -> None:
        self.state_reg, self.assign_reg, self.mute_reg = {}, {}, {}
        self.index, self.max_ts, self.actors = {}, {}, {}

    # ------------------------------------------------------------------ apply
    def apply(self, event: dict) -> bool:
        """Apply one *validated* event. Returns False for a duplicate (same id)."""
        with self.lock:
            eid = event["id"]
            h = content_hash(event)
            if eid in self.events:
                if h < self.hashes[eid]:  # same id, different content: the smaller hash wins everywhere
                    self.events[eid], self.hashes[eid] = event, h
                    self._rebuild()
                return False
            self.events[eid], self.hashes[eid] = event, h
            self._fold_one(event)
            self.version += 1
            return True

    def _rebuild(self) -> None:
        self._reset()
        for ev in sorted(self.events.values(), key=order_key):
            self._fold_one(ev)
        self.version += 1

    def _fold_one(self, event: dict) -> None:
        eid = event["id"]
        okey = order_key(event)
        action = event["action"]
        keys = event_keys(event)
        if event["target_kind"] == "mute":
            self._win(self.mute_reg, event["target"], event, okey)
        elif action in STATE_ACTIONS or action in CLEAR_ACTIONS:
            for k in keys:
                self._win(self.state_reg, k, event, okey)
        elif action in {"assign", "unassign"}:
            for k in keys:
                self._win(self.assign_reg, k, event, okey)
        for k in keys:
            lst = self.index.setdefault(k, [])
            bisect.insort(lst, (okey, eid))
            if len(lst) > HISTORY_PER_KEY:
                del lst[0]
            if event["ts"] > self.max_ts.get(k, 0.0):
                self.max_ts[k] = event["ts"]
        a = event["actor"]
        seen = self.actors.setdefault(
            a["user"].lower(),
            {"user": a["user"], "display": a["display"], "machines": [], "last_ts": 0, "events": 0},
        )
        seen["events"] += 1
        if event["ts"] >= seen["last_ts"]:
            seen.update(last_ts=event["ts"], display=a["display"] or a["user"])
        if a["machine"] not in seen["machines"]:
            seen["machines"] = sorted([*seen["machines"], a["machine"]])[:20]

    def conflicts(self) -> frozenset:
        """Users (lower case) whose display name is also another user's display or user name."""
        with self.lock:
            if self._conflicts and self._conflicts[0] == self.version:
                return self._conflicts[1]
            # Compared by look-alike skeleton (v0.10.22), so "аlice" with a Cyrillic "а" or an
            # accented copy is flagged like an exact duplicate.
            names: dict[str, set] = {}
            users = {name_skeleton(u): u for u in self.actors}
            for u, a in self.actors.items():
                names.setdefault(name_skeleton(a.get("display") or u), set()).add(u)
            out = set()
            for u, a in self.actors.items():
                d = name_skeleton(a.get("display") or u)
                if len(names.get(d, ())) > 1 or (d != name_skeleton(u) and users.get(d, u) != u):
                    out.add(u)
            res = frozenset(out)
            self._conflicts = (self.version, res)
            return res

    def label(self, event: dict) -> str:
        return actor_label(event, local_writer=self.local_writer, conflicts=self.conflicts())

    def via_trusted(self, event: dict) -> bool:
        return bool(self.local_writer) and writer_id(event.get("actor") or {}) == self.local_writer

    def who(self, event: dict) -> dict:
        a = event.get("actor") or {}
        return {
            "by_user": a.get("user", ""),
            "by_display": a.get("display", ""),
            "by_ident": ident(a),
            "by_conflict": str(a.get("user", "")).lower() in self.conflicts(),
        }

    @staticmethod
    def _win(reg: dict, key: str, event: dict, okey: tuple) -> None:
        cur = reg.get(key)
        if cur is None or order_key(cur) < okey:
            reg[key] = event

    # ------------------------------------------------------------------ views
    def snapshot(self) -> dict[str, Any]:
        """{alerts: {key: record}, mutes: {id: rule}, assign: {key: record}} in the classic store shape."""
        with self.lock:
            if self._snap and self._snap[0] == self.version:
                return self._snap[1]
            alerts = {}
            for key, ev in self.state_reg.items():
                state = STATE_ACTIONS.get(ev["action"])
                if not state:
                    continue
                f = ev["fields"]
                rec = {
                    "state": state,
                    "at": ev["ts"],
                    "by": self.label(ev),
                    **self.who(ev),
                    "event": ev["id"],
                    "order": list(order_key(ev)),
                    **{k: v for k, v in ev["context"].items()},
                }
                for name in ("until", "until_change", "duration", "reason", "via"):
                    if f.get(name) not in (None, ""):
                        rec[name] = f[name]
                if f.get("via"):
                    rec["via_trusted"] = self.via_trusted(ev)
                alerts[key] = rec
            mutes = {}
            for rid, ev in self.mute_reg.items():
                if ev["action"] != "mute":
                    continue
                f = ev["fields"]
                mutes[rid] = {
                    "id": rid,
                    "type": f.get("type", ""),
                    "label": f.get("label") or f.get("type", ""),
                    "source": f.get("source", ""),
                    "site_key": f.get("site_key", ""),
                    "site_name": f.get("site_name", ""),
                    "reason": f.get("reason", ""),
                    "created_at": ev["ts"],
                    "until": f.get("until"),
                    "by": self.label(ev),
                    "event": ev["id"],
                    "order": list(order_key(ev)),
                }
            assign = {
                key: {
                    "assignee": ev["fields"].get("assignee", ""),
                    "by": self.label(ev),
                    "at": ev["ts"],
                    "event": ev["id"],
                    "order": list(order_key(ev)),
                }
                for key, ev in self.assign_reg.items()
                if ev["action"] == "assign"
            }
            snap = {"alerts": alerts, "mutes": mutes, "assign": assign}
            self._snap = (self.version, snap)
            return snap

    def history(self, keys, *, limit: int = 40, actions: tuple[str, ...] | None = None) -> list[dict]:
        """Newest-first events about any of ``keys`` (each event once, even when it names many keys)."""
        with self.lock:
            found: dict[str, tuple] = {}
            for k in keys:
                for okey, eid in self.index.get(k, ()):
                    ev = self.events.get(eid)
                    if ev and (actions is None or ev["action"] in actions):
                        found[eid] = okey
            ordered = sorted(found.items(), key=lambda kv: kv[1], reverse=True)[:limit]
            return [self.events[eid] for eid, _ in ordered]

    def winners(self) -> list[dict]:
        """The events that currently determine state (for copying state into another store)."""
        with self.lock:
            out = {}
            for reg in (self.state_reg, self.assign_reg, self.mute_reg):
                for ev in reg.values():
                    out[ev["id"]] = ev
            return sorted(out.values(), key=order_key)

    def all_events(self) -> list[dict]:
        with self.lock:
            return sorted(self.events.values(), key=order_key)

    def last_ts(self, keys) -> float:
        with self.lock:
            return max((self.max_ts.get(k, 0.0) for k in keys), default=0.0)
