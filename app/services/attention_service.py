"""Command Center "Requires Attention" (v0.10.16): incidents, triage state and counts.

Pipeline (once per dashboard refresh, cached in memory):

1. ``collect_alerts()`` — vendor-neutral :class:`~app.integrations.domain.Alert` records from every
   connected source of the ``alerts`` capability (``sdk.gather``). Mist today; FortiGate / Silver Peak /
   anything else that implements ``list_alerts`` appears automatically.
2. Triage state (local, per stable alert key) is applied: *new*, *acknowledged* (Mist ack or local),
   *snoozed* (1 h / 4 h / 24 h / until it changes), *dismissed* (with a reason), *muted* (rule: type,
   optionally one site). Alerts flagged by the source as *possibly resolved* get their own bucket.
3. Alerts are grouped into incidents: devices disconnected at one site → one site-outage incident;
   single disconnected devices scattered over many sites → one roll-up; every other type → one incident
   per type with a per-site breakdown.

Every count shown in the UI (tiles, tabs, header, incident rows) comes from the same pass, so they
always agree, and nothing is truncated: incident members are paginated by ``incident_detail``.
"""

from __future__ import annotations

import math
import threading
import time
import uuid
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime, timezone
from typing import Any

from app.core.auth import ALERTS_ACK as PERM_ALERTS_ACK, require
from app.modules.system.presence import holds_exit
from app.integrations.contracts import ALERTS, ALERTS_ACK
from app.integrations.domain import Alert, stable_key
from app.services.audit_service import AuditService
from app.services.condition_explainer import explain_condition
from app.services.triage.events import event_keys
from app.services.triage.identity import current_actor, is_me
from app.services.triage.store import TriageStoreFacade

SEV_RANK = {"critical": 0, "major": 1, "warning": 2, "info": 3}
SNOOZE_SECONDS = {"1h": 3600, "4h": 4 * 3600, "24h": 24 * 3600}
PRUNE_ABSENT_S = 24 * 3600  # triage records for alerts gone (resolved) this long are forgotten
MAX_SOURCE_ACK = 300  # alarms acknowledged in the vendor system per request
DISMISS_REASONS = ("Known issue", "Expected / maintenance", "Not actionable", "False positive", "Other")
ROLE_WORDS = {
    "switch": ("switch", "switches"),
    "wireless_ap": ("AP", "APs"),
    "sdwan_edge": ("gateway", "gateways"),
    "firewall": ("firewall", "firewalls"),
    "router": ("router", "routers"),
    "": ("device", "devices"),
}
SUPPRESSED_STATES = ("snoozed", "dismissed", "muted")


def _now() -> float:
    return time.time()


def _iso(ts: float | None = None) -> str:
    return datetime.fromtimestamp(ts or _now(), tz=timezone.utc).isoformat()


def _plural(n: int, role: str) -> str:
    one, many = ROLE_WORDS.get(role, ROLE_WORDS[""])
    return f"{n} {one if n == 1 else many}"


def is_offline(alert: Alert) -> bool:
    from app.integrations.connectors.mist.alerts import is_disconnect_type

    return (
        alert.category == "connectivity"
        and is_disconnect_type(alert.type)
        or alert.type.upper().endswith("_CURRENTLY_DOWN")
    )


def type_key(alert: Alert) -> str:
    """What a mute rule matches: 'offline' for any disconnect, else the source's type code."""
    return "offline" if is_offline(alert) else alert.type.lower()


def fingerprint(alert: Alert) -> str:
    return f"{alert.severity}|{alert.count}"


# --------------------------------------------------------------------------- triage store


class TriageStore(TriageStoreFacade):
    """Triage records per stable alert key + mute rules (v0.10.18: event-sourced, pluggable).

    ``TriageStore()`` follows Settings › Team triage (this PC only, or a shared folder …);
    ``TriageStore(path)`` is a store on this PC at ``path`` (tests, tools). Records go in and out
    exactly as before (``load()`` / ``update(fn)``); every change is written as a triage event — see
    :mod:`app.services.triage`.
    """


STORE = TriageStore()


class MemoryStore(TriageStore):
    """Throw-away store for preview/simulation alerts: they must never touch the user's real triage."""

    def __init__(self):
        from app.services.triage.backends._memory import MemoryBackend

        super().__init__(backend=MemoryBackend(actor=current_actor()), overlay_path=False)


_PREVIEW_STORE = MemoryStore()


class ConflictError(Exception):
    """What the user confirmed no longer matches the current alerts (HTTP 409)."""


def _store() -> TriageStore:
    with _LOCK:
        preview = bool(_CACHE.get("preview"))
    return _PREVIEW_STORE if preview else STORE


# --------------------------------------------------------------------------- cache

_LOCK = threading.RLock()
_CACHE: dict[str, Any] = {
    "alerts": [],
    "errors": [],
    "at": 0.0,
    "site_totals": {},
    "sources": {},
    "known_down": set(),
    "healthy": False,  # at least one ALERTS source answered and none failed
    "preview": False,  # simulation/sample alerts: use the in-memory store, never the real one
}
_UNDO: dict[str, dict] = {}


def collect_alerts() -> tuple[list[Alert], list[dict]]:
    alerts, errors, _ = collect()
    return alerts, errors


def collect() -> tuple[list[Alert], list[dict], bool]:
    """(alerts, per-source errors, healthy). Healthy = at least one source answered and none failed:
    an empty list from zero connected sources is *not* evidence that alerts resolved."""
    from app.integrations.connectors import sdk

    answered = len(sdk.sources(ALERTS))
    alerts, errors = sdk.gather(ALERTS, "list_alerts")
    healthy = answered > 0 and not errors
    return [a for a in alerts if isinstance(a, Alert)], errors, healthy


def source_labels() -> dict[str, dict]:
    from app.integrations.connectors import sdk

    out = {}
    for c in sdk.all_connectors():
        m = c.manifest
        out[m.connector_id] = {
            "label": f"{m.vendor} {m.product}".strip(),
            "short": m.product.replace(" Cloud", "") if m.product else m.vendor,
            "can_ack": ALERTS_ACK in m.capabilities,
        }
    return out


def remember(
    alerts: list[Alert],
    errors: list[dict],
    *,
    site_totals: dict[str, int] | None = None,
    known_down: set[str] | None = None,
    healthy: bool = False,
    preview: bool = False,
) -> None:
    """Cache one refresh. ``known_down`` = alert keys Disconnect Watch marked known-down (shown as dismissed).

    ``healthy`` must be True only when a real source answered (see :func:`collect`); triage records
    of vanished alerts are aged out only then. ``preview`` alerts use a throw-away in-memory store."""
    with _LOCK:
        _CACHE.update(
            alerts=list(alerts),
            errors=list(errors),
            at=_now(),
            site_totals=dict(site_totals or {}),
            known_down=set(known_down or ()),
            healthy=bool(healthy) and not errors and not preview,
            preview=bool(preview),
        )
        try:
            _CACHE["sources"] = source_labels()
        except Exception:  # noqa: BLE001 - labels are cosmetic
            _CACHE["sources"] = {}


def cached_alerts() -> list[Alert]:
    with _LOCK:
        return list(_CACHE["alerts"])


def fresh_cached_alerts(max_age: float) -> tuple[list[Alert], list[dict]] | None:
    """(alerts, per-source errors) of the last real (non-preview) gather when it is at most ``max_age``
    seconds old, else None (v0.10.24: the notification feed reuses Command Center's gather; the errors
    travel with it so a source that failed there is not mistaken for one whose alerts all resolved)."""
    with _LOCK:
        if _CACHE["preview"] or not _CACHE["at"] or _now() - float(_CACHE["at"]) > max_age:
            return None
        return list(_CACHE["alerts"]), [e for e in _CACHE.get("errors") or [] if isinstance(e, dict)]


# --------------------------------------------------------------------------- state


def _migrate_legacy(data: dict, alerts: list[Alert]) -> bool:
    """Old v0.10.12 dismissals were keyed 'alarm:<id>': carry them over to the stable key once."""
    try:
        from app.services.local_state import local_state

        legacy = local_state.dismissed()
    except Exception:  # noqa: BLE001
        return False
    if not legacy or data.get("legacy_migrated"):
        return False
    changed = False
    for a in alerts:
        for alarm_id in a.vendor.get("alarm_ids") or []:
            rec = legacy.get(f"alarm:{alarm_id}")
            if rec and a.key not in data["alerts"]:
                data["alerts"][a.key] = {
                    "state": "dismissed",
                    "reason": "Dismissed before v0.10.16",
                    "at": _now(),
                    "title": a.title,
                    "site_name": a.site_name,
                    "device_name": a.device_name,
                    "type": a.type,
                    "source": a.source,
                }
                changed = True
    data["legacy_migrated"] = True
    return changed


def _mute_matches(rule: dict, alert: Alert, now: float) -> bool:
    if rule.get("until") and float(rule["until"]) < now:
        return False
    if rule.get("source") and rule["source"] != alert.source:
        return False
    if rule.get("type") and rule["type"] != type_key(alert):
        return False
    if rule.get("site_key") and rule["site_key"] != alert.site_key:
        return False
    return True


def annotate(alerts: list[Alert], *, now: float | None = None, healthy: bool | None = None) -> list[tuple[Alert, dict]]:
    """[(alert, {state, bucket, record, mute})] with expired snoozes/mutes cleaned and records pruned.

    ``healthy`` = every source answered; only then are records of vanished alerts aged out (an outage
    of the vendor API must not wipe the user's triage).
    """
    now = now or _now()
    present = {a.key for a in alerts}
    with _LOCK:
        known_down = set(_CACHE.get("known_down") or ())
        if healthy is None:
            healthy = bool(_CACHE.get("healthy"))
        preview = bool(_CACHE.get("preview"))

    def work(data: dict) -> list[tuple[Alert, dict]]:
        if not preview:
            _migrate_legacy(data, alerts)
        recs = data["alerts"]
        for rid, rule in list(data["mutes"].items()):
            if rule.get("until") and float(rule["until"]) < now:
                data["mutes"].pop(rid, None)
        for key, rec in list(recs.items()):
            if key in present:
                if now - float(rec.get("last_present") or 0) > 600:
                    rec["last_present"] = now
            elif healthy and now - float(rec.get("last_present", rec.get("at", now)) or 0) > PRUNE_ABSENT_S:
                recs.pop(key, None)
        out = []
        mutes = list(data["mutes"].values())
        assign = data.get("assign") or {}
        by_key = {a.key: a for a in alerts}
        for key, rec in list(recs.items()):
            a = by_key.get(key)
            if not a or rec.get("state") != "snoozed":
                continue
            if rec.get("until") and float(rec["until"]) <= now:
                recs.pop(key, None)
            elif rec.get("until_change") and rec["until_change"] != fingerprint(a):
                recs.pop(key, None)
        for a in alerts:
            rec = recs.get(a.key) or {}
            mute = next((m for m in mutes if _mute_matches(m, a, now)), None)
            if mute:
                state = "muted"
            elif rec.get("state") in {"dismissed", "snoozed"}:
                state = rec["state"]
            elif a.key in known_down:
                state, rec = "dismissed", {"state": "dismissed", "reason": "Known down (Disconnect Watch)"}
            elif a.acknowledged or rec.get("state") == "acknowledged":
                state = "acknowledged"
            else:
                state = "new"
            bucket = state
            if state in {"new", "acknowledged"} and a.vendor.get("possibly_resolved"):
                bucket = "possibly_resolved"
            out.append(
                (a, {"state": state, "bucket": bucket, "record": rec, "mute": mute, "assign": assign.get(a.key)})
            )
        return out

    # Bookkeeping and clean-ups (expired snoozes, vanished alerts) are decided by each PC for itself:
    # housekeep() keeps them out of the shared event log.
    return _store().housekeep(work)


# --------------------------------------------------------------------------- incidents


def _incident_key(a: Alert, bucket: str) -> tuple:
    if bucket == "possibly_resolved":
        return ("resolved", a.source, type_key(a))
    if is_offline(a):
        return ("offline", a.site_key or a.site_name)
    return ("type", a.source, a.type.lower())


def _scope(alerts: list[Alert]) -> tuple[Counter, Counter]:
    sites = Counter(a.site_name or "Site not reported" for a in alerts)
    roles = Counter({a.device_key or a.key: a.device_role for a in alerts}.values())
    return sites, roles


def _roles_text(roles: Counter) -> str:
    parts = [_plural(n, r) for r, n in sorted(roles.items(), key=lambda kv: (-kv[1], kv[0]))]
    if len(parts) <= 2:
        return " and ".join(parts)
    return ", ".join(parts[:-1]) + f" and {parts[-1]}"


def _minutes(seconds: float) -> str:
    m = max(1, int(round(seconds / 60)))
    return f"{m} minute{'s' if m != 1 else ''}" if m < 120 else f"{m // 60} hours"


def _describe(kind: str, members: list[Alert], site_totals: dict[str, int]) -> tuple[str, str]:
    """(title, one-line roll-up) for an incident."""
    sites, roles = _scope(members)
    devices = sum(roles.values())
    lead = members[0]
    if kind == "offline":
        site = lead.site_name or "an unknown site"
        title = f"{_roles_text(roles)} disconnected at {site}"
        # When each device went offline: its last contact, else when the alarm was first raised.
        firsts = sorted(
            a.vendor.get("device_last_seen") or a.first_seen
            for a in members
            if a.vendor.get("device_last_seen") or a.first_seen
        )
        total = site_totals.get(lead.vendor.get("site_id") or "") or site_totals.get(lead.site_key) or 0
        bits = []
        if total:
            bits.append(f"{devices} of {total} devices at this site are offline")
        if len(firsts) >= 2 and firsts[-1] - firsts[0] <= 15 * 60 and devices >= 3:
            bits.append(
                f"they dropped within {_minutes(firsts[-1] - firsts[0] or 60)} — probably one power or uplink event"
            )
        elif devices >= 3:
            bits.append("several devices at one site — check site power, core switching and WAN first")
        return title, ("; ".join(bits) + ".") if bits else "One device is offline."
    if kind == "offline-isolated":
        title = f"{_roles_text(roles)} offline, one per site"
        return (
            title,
            f"Single devices disconnected at {len(sites)} different sites — likely unrelated, individual failures.",
        )
    name = lead.title
    top = sites.most_common(1)[0] if sites else ("", 0)
    where = f"at {top[0]}" if len(sites) == 1 else f"across {len(sites)} sites"
    on = f"on {_roles_text(roles)}" if devices and any(a.device_key for a in members) else ""
    title = f"{name} {where}".strip()
    roll = f"{len(members)} open alert{'s' if len(members) != 1 else ''} {on} {where}".replace("  ", " ").strip()
    if len(sites) > 1 and top[1] > 1:
        roll += f" — most at {top[0]} ({top[1]})"
    flapping = sum(1 for a in members if a.vendor.get("flaps"))
    if flapping:
        roll += f"; {flapping} flapping repeatedly"
    if kind == "resolved":
        title = f"{name} — possibly resolved"
        roll = f"{len(members)} alert{'s' if len(members) != 1 else ''} still open in the source, but the device is connected now or the alarm has not repeated for 24 h."
    return title, roll + ("." if not roll.endswith(".") else "")


def _incident_summary(iid: str, kind: str, rows: list[tuple[Alert, dict]], site_totals: dict, sources: dict) -> dict:
    members = [a for a, _ in rows]
    members.sort(key=lambda a: (SEV_RANK.get(a.severity, 9), -(a.last_seen or 0)))
    title, roll = _describe(kind, members, site_totals)
    sites, roles = _scope(members)
    states = Counter(s["state"] for _, s in rows)
    sev = min((a.severity for a in members), key=lambda s: SEV_RANK.get(s, 9))
    srcs = sorted({a.source for a in members})
    names = list(dict.fromkeys(a.device_name for a in members if a.device_name))
    search = " ".join(
        dict.fromkeys(
            [title, members[0].type, members[0].title]
            + list(sites)
            + names[:400]
            + [a.vendor.get("mac", "") for a in members[:400]]
        )
    ).lower()[:6000]
    ackable = any(
        sources.get(a.source, {}).get("can_ack") and a.vendor.get("alarm_ids") and not a.acknowledged for a in members
    )
    from app.services.dashboard_service import _group_for_type

    assignees = Counter((s.get("assign") or {}).get("assignee") for _, s in rows if s.get("assign"))
    return {
        "id": iid,
        "kind": kind,
        "title": title,
        "summary": roll,
        "severity": sev,
        "category": members[0].category,
        "group": "Connectivity / Availability"
        if kind.startswith("offline")
        else members[0].vendor.get("group") or _group_for_type(members[0].type),
        "type": "offline" if kind.startswith("offline") else members[0].type,
        "type_label": "Device offline" if kind.startswith("offline") else members[0].title,
        "mute_type": type_key(members[0]),
        "sources": [{"id": s, "label": sources.get(s, {}).get("short") or s.title()} for s in srcs],
        "sites": [{"name": n, "count": c} for n, c in sites.most_common(40)],
        "site_count": len(sites),
        "site_key": members[0].site_key if len(sites) == 1 else "",
        "site_id": members[0].vendor.get("site_id", "") if len(sites) == 1 else "",
        "roles": dict(roles),
        "device_count": sum(roles.values()),
        "count": len(members),
        "states": {k: states.get(k, 0) for k in ("new", "acknowledged", "snoozed", "dismissed", "muted")},
        "first_seen": min((a.first_seen for a in members if a.first_seen), default=None),
        "last_seen": max((a.last_seen for a in members if a.last_seen), default=None),
        "flapping": sum(1 for a in members if a.vendor.get("flaps")),
        "preview": names[:4],
        "ackable": bool(ackable),
        "assignees": [{"name": n, "display": _display_name(n), "count": c} for n, c in assignees.most_common(5)],
        "assigned": sum(assignees.values()),
        "search": search,
    }


def build(
    rows: list[tuple[Alert, dict]],
    *,
    site_totals: dict | None = None,
    sources: dict | None = None,
    me: dict | None = None,
) -> dict:
    """Incidents + counts from annotated alerts. Pure (no I/O). ``me`` marks incidents assigned to me."""
    site_totals = site_totals or {}
    sources = sources or {}
    groups: dict[tuple, list[tuple[Alert, dict]]] = defaultdict(list)
    suppressed = Counter()
    for a, s in rows:
        if s["state"] in SUPPRESSED_STATES:
            suppressed[s["state"]] += 1
            continue
        groups[_incident_key(a, s["bucket"])].append((a, s))
    # Single offline devices scattered over several sites roll up into one incident.
    singles = [k for k, v in groups.items() if k[0] == "offline" and len(v) == 1]
    if len(singles) >= 2:
        merged = []
        for k in singles:
            merged += groups.pop(k)
        groups[("offline-isolated",)] = merged
    incidents = []
    members: dict[str, list[tuple[Alert, dict]]] = {}
    for key, items in groups.items():
        iid = stable_key("incident", *key)
        kind = key[0]
        members[iid] = items
        inc = _incident_summary(iid, kind, items, site_totals, sources)
        inc["bucket"] = "possibly_resolved" if kind == "resolved" else "open"
        inc["mine"] = bool(me) and any(is_me(x["name"], me) for x in inc["assignees"])
        incidents.append(inc)
    incidents.sort(
        key=lambda i: (
            i["bucket"] != "open",
            i["states"]["new"] == 0,
            SEV_RANK.get(i["severity"], 9),
            -i["count"],
            -(i["last_seen"] or 0),
        )
    )
    open_rows = [(a, s) for a, s in rows if s["bucket"] in {"new", "acknowledged"}]
    state_counts = Counter(s["state"] for a, s in open_rows)
    open_inc = [i for i in incidents if i["bucket"] == "open"]
    noisy = Counter()
    labels = {}
    for a, s in rows:
        if s["bucket"] in {"new", "acknowledged"}:
            noisy[(a.source, type_key(a))] += 1
            labels[(a.source, type_key(a))] = "Device offline" if type_key(a) == "offline" else a.title
    counts = {
        "alerts_total": len(rows),
        # distinct vendor alarm records behind the alerts (several alarms about one thing merge)
        "source_alarms": len({i for a, _ in rows for i in a.vendor.get("alarm_ids") or []}),
        "new": state_counts.get("new", 0),
        "acknowledged": state_counts.get("acknowledged", 0),
        "open": len(open_rows),
        "possibly_resolved": sum(1 for _, s in rows if s["bucket"] == "possibly_resolved"),
        "snoozed": suppressed.get("snoozed", 0),
        "dismissed": suppressed.get("dismissed", 0),
        "muted": suppressed.get("muted", 0),
        "suppressed": sum(suppressed.values()),
        "critical": sum(1 for a, _ in open_rows if a.severity in {"critical", "major"}),
        "warning": sum(1 for a, _ in open_rows if a.severity not in {"critical", "major"}),
        "incidents": {
            "needs": sum(1 for i in open_inc if i["states"]["new"]),
            "acknowledged": sum(1 for i in open_inc if i["states"]["acknowledged"]),
            "all": len(open_inc),
            "possibly_resolved": sum(1 for i in incidents if i["bucket"] == "possibly_resolved"),
            "mine": sum(1 for i in open_inc if i["mine"]),
        },
    }
    return {
        "incidents": incidents,
        "counts": counts,
        "noisy_types": [
            {"source": src, "type": t, "label": labels[(src, t)], "count": n}
            for (src, t), n in noisy.most_common(6)
            if n >= 5
        ],
        "_members": members,
    }


def payload(*, rows: list[tuple[Alert, dict]] | None = None) -> dict:
    """The JSON the Command Center needs (no members: those come from ``incident_detail``)."""
    with _LOCK:
        alerts = list(_CACHE["alerts"])
        errors = list(_CACHE["errors"])
        totals = dict(_CACHE["site_totals"])
        sources = dict(_CACHE["sources"])
        at = _CACHE["at"]
    rows = rows if rows is not None else annotate(alerts)
    built = build(rows, site_totals=totals, sources=sources, me=_store().actor())
    built.pop("_members")
    built["source_errors"] = errors
    built["generated_at"] = _iso(at) if at else ""
    built["sources"] = [{"id": k, **v} for k, v in sources.items() if any(a.source == k for a in alerts)]
    built["dismiss_reasons"] = list(DISMISS_REASONS)
    built["team"] = team_summary()
    return built


def _display_name(name: str) -> str:
    """Assignee as stored (Windows user name or free text) → ``Display (user@machine)`` for people seen
    in the store (display names are free text, so the real identity is always shown next to them)."""
    try:
        fold = _store().backend.fold
        key = str(name or "").lower()
        seen = fold.actors.get(key)
        conflict = key in fold.conflicts()
    except Exception:  # noqa: BLE001
        seen, conflict = None, False
    if not seen:
        return str(name or "")
    machines = seen.get("machines") or ["?"]
    where = f"{seen['user']}@{machines[0]}" + (f" +{len(machines) - 1}" if len(machines) > 1 else "")
    display = seen.get("display") or seen["user"]
    text = where if display.lower() == seen["user"].lower() else f"{display} ({where})"
    return text + (" ⚠ name also used by another user" if conflict else "")


def team_summary() -> dict:
    """Small status block for the Command Center header (which store, synced when, who am I)."""
    store = _store()
    try:
        h = store.backend.health()
    except Exception as exc:  # noqa: BLE001
        h = {"mode": "error", "last_error": str(exc)[:200]}
    return {
        "backend": h.get("backend", ""),
        "label": h.get("label", ""),
        "shared": bool(h.get("shared")),
        "mode": h.get("mode", ""),
        "writable": h.get("writable", True),
        "last_sync": h.get("last_sync"),
        "pending": h.get("pending", 0),
        # "unavailable": the share does not keep file owners, so who wrote an entry is not verified.
        "owner_check": h.get("owner_check", ""),
        "users": len(h.get("users") or []),
        "last_error": h.get("last_error", ""),
        "me": store.actor(),
    }


# --------------------------------------------------------------------------- detail


def full_facts(a: Alert) -> list[dict]:
    """All readable facts. Connectors may build the costly part lazily (optional ``alert_facts`` hook)."""
    if a.vendor.get("facts_complete", True):
        return a.facts
    try:
        from app.integrations.connectors import sdk

        hook = getattr(sdk.get_connector(a.source), "alert_facts", None)
        return hook(a) if hook else a.facts
    except Exception:  # noqa: BLE001 - details are best-effort; never break the drawer
        return a.facts


def _member_view(a: Alert, s: dict, sources: dict) -> dict:
    facts = full_facts(a)
    evidence = [f for f in facts if f.get("group") == "evidence"][:8]
    reported = [f for f in facts if f.get("group") != "evidence"][:10]
    return {
        "key": a.key,
        "title": a.title,
        "type": a.type,
        "severity": a.severity,
        "source": a.source,
        "source_label": sources.get(a.source, {}).get("short") or a.source,
        "device": a.device_name,
        "role": a.device_role,
        "device_type": a.vendor.get("device_type", ""),
        "mac": a.vendor.get("mac", ""),
        "device_id": a.vendor.get("device_id", ""),
        "site": a.site_name,
        "site_id": a.vendor.get("site_id", ""),
        "interface": a.interface,
        "first_seen": a.first_seen,
        "last_seen": a.last_seen,
        "device_last_seen": a.vendor.get("device_last_seen"),
        "connected_now": a.vendor.get("connected_now"),
        "possibly_resolved": bool(a.vendor.get("possibly_resolved")),
        "flaps": a.vendor.get("flaps", 0),
        "count": a.count,
        "state": s["state"],
        "acknowledged_by": a.acknowledged_by
        if a.acknowledged
        else (s["record"].get("by") or ("NodeWatch" if s["state"] == "acknowledged" else "")),
        "snoozed_until": s["record"].get("until") if s["state"] == "snoozed" else None,
        "snooze_until_change": bool(s["record"].get("until_change")) if s["state"] == "snoozed" else False,
        "dismiss_reason": s["record"].get("reason", "") if s["state"] == "dismissed" else "",
        # who set the NodeWatch state, and when (team triage)
        "state_by": s["record"].get("by", "") if s["state"] in {"snoozed", "dismissed", "acknowledged"} else "",
        "state_at": s["record"].get("at") if s["state"] in {"snoozed", "dismissed", "acknowledged"} else None,
        "assignee": (s.get("assign") or {}).get("assignee", ""),
        "assignee_display": _display_name((s.get("assign") or {}).get("assignee", "")),
        "console_url": a.console_url,
        "detail": a.detail,
        "evidence": evidence,
        "reported": reported,
        "ackable": bool(sources.get(a.source, {}).get("can_ack") and a.vendor.get("alarm_ids") and not a.acknowledged),
    }


def _timeline(members: list[Alert], now: float) -> dict:
    hours = [0] * 24
    for a in members:
        t = a.first_seen or a.last_seen
        if t and 0 <= now - t < 24 * 3600:
            hours[23 - int((now - t) // 3600)] += 1
    ordered = sorted((a for a in members if a.first_seen), key=lambda a: a.first_seen or 0)
    marks = []
    for label, a in (("First seen", ordered[0] if ordered else None), ("Latest", ordered[-1] if ordered else None)):
        if a:
            marks.append({"label": label, "time": a.first_seen, "text": f"{a.device_name or a.site_name} — {a.title}"})
    last = max((a.last_seen for a in members if a.last_seen), default=None)
    if last:
        marks.append({"label": "Last reported", "time": last, "text": "Most recent report from the source"})
    return {
        "hours": hours,
        "older": sum(1 for a in members if (a.first_seen or a.last_seen or now) < now - 24 * 3600),
        "marks": marks,
    }


def _explanation(inc: dict, members: list[Alert]) -> dict:
    lead = members[0]
    row = {
        "type": "device_currently_down" if inc["kind"].startswith("offline") else lead.type,
        "timestamp": inc.get("first_seen"),
        "last_seen": inc.get("last_seen"),
        "impacted_entities": lead.vendor.get("entities") or [],
    }
    definition = {"description": lead.vendor.get("definition", ""), "display": lead.title}
    device = lead.device_name if inc["device_count"] <= 1 else f"{inc['device_count']} devices"
    site = lead.site_name if inc["site_count"] <= 1 else f"{inc['site_count']} sites"
    ex = explain_condition(row, definition, site=site, device=device, evidence=[])
    ex["rollup"] = inc["summary"]
    if not inc["kind"].startswith("offline") and (inc["device_count"] > 1 or inc["site_count"] > 1):
        scope = _roles_text(Counter(inc.get("roles") or {})) if inc["device_count"] else f"{inc['count']} alerts"
        where = f"at {lead.site_name}" if inc["site_count"] == 1 else f"across {inc['site_count']} sites"
        ex["summary"] = f"{ex['headline']} on {scope} {where}." + (
            f" {lead.vendor.get('definition')}" if lead.vendor.get("definition") else ""
        )
    if inc["kind"].startswith("offline"):
        ex["headline"] = "Devices offline" if inc["device_count"] > 1 else "Device offline"
        ex["summary"] = (
            f"{inc['device_count']} managed devices can no longer reach the cloud"
            if inc["device_count"] > 1
            else f"{lead.device_name or 'A managed device'} at {lead.site_name} can no longer reach the cloud"
        ) + " — clients and ports behind them may be down too."
        roles = inc.get("roles") or {}
        ex["next_steps"] = (
            [
                "If switches are in the list, start with them: APs and phones behind an offline switch drop as a consequence, not as separate failures.",
                "Check site power / UPS and the closet that feeds these devices; then the core or distribution uplink and the WAN circuit.",
                "Ask someone on site whether the devices have link lights — up but unreachable points at WAN/DNS/firewall, dark points at power.",
                "When power or uplink is back the devices reconnect by themselves; acknowledge this incident meanwhile so the team knows it is being handled.",
            ]
            if inc["kind"] == "offline" and (inc["device_count"] >= 3 or roles.get("switch"))
            else [
                "Use Find on the device to see the switch port it was last connected to, then check that port (PoE, link, errors) in Port Toolkit.",
                "Check whether it was rebooted or upgraded (Mist audit log) before dispatching.",
                "If it is decommissioned or moved, dismiss it with a reason or mark it known-down in Disconnect Watch.",
            ]
        )
    if inc["kind"] == "offline" and inc["device_count"] >= 3:
        ex["likely_causes"] = [
            "Site power loss / UPS failure in the closet feeding these devices.",
            "Upstream core/distribution switch or uplink down (devices behind it lose the cloud together).",
            "WAN / internet outage at the site (devices up but cannot reach the cloud).",
        ] + ex.get("likely_causes", [])[:1]
    if inc.get("flapping"):
        ex["likely_causes"] = [
            "Flapping: the same device/port went down and up 3+ times recently — suspect cabling, optics or power."
        ] + ex.get("likely_causes", [])
    return ex


def incident_detail(incident_id: str, *, offset: int = 0, limit: int = 50, state: str = "") -> dict | None:
    with _LOCK:
        alerts = list(_CACHE["alerts"])
        totals = dict(_CACHE["site_totals"])
        sources = dict(_CACHE["sources"])
    rows = annotate(alerts)
    built = build(rows, site_totals=totals, sources=sources, me=_store().actor())
    inc = next((i for i in built["incidents"] if i["id"] == incident_id), None)
    if inc is None:
        return None
    items = built["_members"][incident_id]
    # Team history also covers this incident's alerts that were snoozed / dismissed / muted meanwhile.
    all_keys = [a.key for a, _ in items] + [
        a.key
        for a, s in rows
        if s["state"] in SUPPRESSED_STATES and stable_key("incident", *_incident_key(a, s["bucket"])) == incident_id
    ]
    items.sort(key=lambda x: (x[1]["state"] != "new", SEV_RANK.get(x[0].severity, 9), x[0].site_name, x[0].device_name))
    if state:
        items = [x for x in items if x[1]["state"] == state]
    members = [a for a, _ in items] or [a for a, _ in built["_members"][incident_id]]
    page = items[max(0, offset) : max(0, offset) + max(1, min(limit, 500))]
    return {
        "incident": {k: v for k, v in inc.items() if k != "search"},
        "explanation": _explanation(inc, members),
        "timeline": _timeline(members, _now()),
        "members": [_member_view(a, s, sources) for a, s in page],
        "total": len(items),
        # Fingerprint of exactly these alerts: a confirmed write sends it back and gets 409 if it changed.
        "version": membership_version([a.key for a, _ in items]),
        "offset": offset,
        "limit": limit,
        "team": incident_team(incident_id, all_keys, inc),
    }


# --------------------------------------------------------------------------- team triage (v0.10.18)

NOTE_MAX = 500


def _event_view(e: dict, keyset: set[str], me: dict) -> dict:
    f = e.get("fields") or {}
    a = e.get("actor") or {}
    fold = _store().backend.fold
    return {
        "ident": f"{a.get('user', '')}@{a.get('machine', '')}",
        "conflict": str(a.get("user", "")).lower() in fold.conflicts(),
        "via_trusted": fold.via_trusted(e),
        "id": e["id"],
        "ts": e["ts"],
        "action": e["action"],
        "who": a.get("display") or a.get("user"),
        "user": a.get("user"),
        "machine": a.get("machine"),
        "mine": a.get("user", "").lower() == me.get("user", "").lower()
        and a.get("machine", "").lower() == me.get("machine", "").lower(),
        "count": len(set(event_keys(e)) & keyset),
        "until": f.get("until"),
        "duration": f.get("duration", ""),
        "reason": f.get("reason", ""),
        "via": f.get("via", ""),
        "assignee": f.get("assignee", ""),
        "assignee_display": _display_name(f.get("assignee", "")) if f.get("assignee") else "",
        "note": f.get("note", ""),
    }


def incident_team(incident_id: str, keys: list[str], inc: dict) -> dict:
    """Who did what on this incident (any member alert or the incident itself), notes and assignees."""
    store = _store()
    me = store.actor()
    keyset = set(keys)
    targets = [incident_id, *keys]
    try:
        activity = [e for e in store.history(targets, limit=60) if e["action"] != "note"][:30]
        notes = store.history(targets, limit=50, actions=("note",))
        actors = [
            {"user": x["user"], "display": x["display"]}
            for x in sorted(store.backend.fold.actors.values(), key=lambda x: x["display"].lower())
        ]
    except Exception as exc:  # noqa: BLE001 - the drawer must open even if the store is unhappy
        return {"error": str(exc)[:200], "activity": [], "notes": [], "assignees": inc.get("assignees", []), "me": me}
    if not any(x["user"].lower() == me["user"].lower() for x in actors):
        actors.append({"user": me["user"], "display": me["display"]})
    return {
        "me": me,
        "store": team_summary(),
        "assignees": inc.get("assignees", []),
        "assigned": inc.get("assigned", 0),
        "activity": [_event_view(e, keyset, me) for e in activity],
        "notes": [_event_view(e, keyset, me) for e in sorted(notes, key=lambda e: e["ts"])],
        "actors": actors[:100],
    }


def team_assign(keys: list[str] | None, incident_id: str | None, payload_in: dict) -> dict:
    """Assign the alerts of an incident (or explicit keys) to someone, or clear the assignment."""
    action = str(payload_in.get("action"))
    store = _store()
    fields = {}
    if action == "assign":
        who = str(payload_in.get("assignee") or "").strip()
        if who.lower() == "me":
            who = store.actor()["user"]
        if not who:
            raise ValueError("Choose who to assign this to")
        if len(who) > 80:
            raise ValueError("Assignee is too long (80 characters max)")
        fields["assignee"] = who
    items = _targets(keys, incident_id, None)
    if not items:
        raise LookupError("No alerts to assign — refresh to see the current list.")
    lead = items[0][0]
    store.record(
        action,
        [a.key for a, _ in items],
        fields=fields,
        context={"title": lead.title, "type": lead.type, "source": lead.source},
        vendor=lead.source,
    )
    return {"ok": True, "action": action, "changed": len(items), **payload()}


def team_note(keys: list[str] | None, incident_id: str | None, payload_in: dict) -> dict:
    text = str(payload_in.get("note") or "").strip()
    if not text:
        raise ValueError("Write a note first")
    if len(text) > NOTE_MAX:
        raise ValueError(f"Notes are short: {NOTE_MAX} characters max")
    items = _targets(keys, incident_id, None)
    if not items:
        raise LookupError("No alerts to attach the note to — refresh to see the current list.")
    lead = items[0][0]
    member_keys = [a.key for a, _ in items][:2000]
    ctx = {"title": lead.title, "type": lead.type, "source": lead.source}
    store = _store()
    if incident_id:
        store.record(
            "note", member_keys, target=incident_id, target_kind="incident", fields={"note": text}, context=ctx
        )
    else:
        store.record("note", member_keys, fields={"note": text}, context=ctx, vendor=lead.source)
    return {"ok": True, "action": "note", "changed": 1, **payload()}


# --------------------------------------------------------------------------- triage actions


def membership_version(keys) -> str:
    return stable_key("members", *sorted(keys))


def _targets(
    keys: list[str] | None, incident_id: str | None, only_states: tuple[str, ...] | None
) -> list[tuple[Alert, dict]]:
    with _LOCK:
        alerts = list(_CACHE["alerts"])
        totals = dict(_CACHE["site_totals"])
        sources = dict(_CACHE["sources"])
    rows = annotate(alerts)
    if incident_id:
        built = build(rows, site_totals=totals, sources=sources)
        items = built["_members"].get(incident_id)
        if items is None:
            raise LookupError("This incident is no longer open — refresh to see the current list.")
    else:
        wanted = set(keys or [])
        items = [(a, s) for a, s in rows if a.key in wanted]
    if only_states:
        items = [(a, s) for a, s in items if s["state"] in only_states]
    return items


def _record(a: Alert, **extra) -> dict:
    return {
        "at": _now(),
        "last_present": _now(),
        "title": a.title,
        "type": a.type,
        "source": a.source,
        "site_name": a.site_name,
        "device_name": a.device_name,
        **extra,
    }


def _remember_undo(previous: dict[str, Any], mute_id: str = "", emitted: dict[str, str] | None = None) -> str:
    token = uuid.uuid4().hex
    _UNDO[token] = {"records": previous, "mute_id": mute_id, "emitted": emitted, "at": _now()}
    while len(_UNDO) > 50:
        _UNDO.pop(next(iter(_UNDO)))
    return token


def _apply(items: list[tuple[Alert, dict]], make) -> tuple[int, str]:
    keys = [a.key for a, _ in items]

    def work(data: dict) -> dict:
        prev = {k: data["alerts"].get(k) for k in keys}
        for a, _ in items:
            rec = make(a)
            if rec is None:
                data["alerts"].pop(a.key, None)
            else:
                data["alerts"][a.key] = rec
        return prev

    store = _store()
    previous = store.update(work)
    return len(items), _remember_undo(previous, emitted=store.last_emitted())


def triage(payload_in: dict) -> dict:
    action = str(payload_in.get("action") or "")
    keys = payload_in.get("keys") if isinstance(payload_in.get("keys"), list) else None
    if keys is not None and len(keys) > 20_000:
        raise ValueError("Too many alerts in one request")
    incident_id = str(payload_in.get("incident_id") or "") or None
    if not keys and not incident_id:
        raise ValueError("Choose an incident or at least one alert")
    view_state = str(payload_in.get("state") or "")
    states = (view_state,) if view_state else None
    now = _now()

    if action == "snooze":
        duration = str(payload_in.get("duration") or "1h")
        if duration not in {*SNOOZE_SECONDS, "change"}:
            raise ValueError("Snooze for 1h, 4h, 24h or until it changes")
        items = _targets(keys, incident_id, states or ("new", "acknowledged"))
        n, token = _apply(
            items,
            lambda a: _record(
                a,
                state="snoozed",
                until=None if duration == "change" else now + SNOOZE_SECONDS[duration],
                until_change=fingerprint(a) if duration == "change" else "",
                duration=duration,
            ),
        )
    elif action == "dismiss":
        reason = str(payload_in.get("reason") or "").strip()[:200]
        if not reason:
            raise ValueError("Give a reason for dismissing")
        items = _targets(keys, incident_id, states or ("new", "acknowledged"))
        n, token = _apply(items, lambda a: _record(a, state="dismissed", reason=reason))
    elif action == "ack_local":
        items = _targets(keys, incident_id, states or ("new",))
        n, token = _apply(items, lambda a: _record(a, state="acknowledged"))
    elif action in {"restore", "unsnooze", "undismiss"}:
        items = _targets(keys, incident_id, None)
        n, token = _apply(items, lambda a: None)
        with _LOCK:
            known = _CACHE["known_down"] & {a.key for a, _ in items}
            _CACHE["known_down"] = _CACHE["known_down"] - known
        if known:  # restoring a Disconnect Watch "known down" device restores it there too
            from app.services.local_state import local_state

            for a, _ in items:
                if a.key in known:
                    local_state.restore_disconnect(f"mac:{a.vendor.get('mac') or ''}")
    elif action == "ack_source":
        return acknowledge_in_source(keys, incident_id, payload_in)
    elif action in {"assign", "unassign"}:
        return team_assign(keys, incident_id, payload_in)
    elif action == "note":
        return team_note(keys, incident_id, payload_in)
    else:
        raise ValueError(f"Unknown action {action!r}")
    return {"ok": True, "action": action, "changed": n, "undo": token, **payload()}


@holds_exit
def acknowledge_in_source(keys: list[str] | None, incident_id: str | None, payload_in: dict) -> dict:
    """Acknowledge in the vendor system (Mist). Explicitly confirmed and audited; never implicit."""
    require(PERM_ALERTS_ACK)  # v0.10.22: per-person permission (desktop: always granted)
    if payload_in.get("confirmed") is not True:
        raise PermissionError("Acknowledging in the source system must be explicitly confirmed")
    from app.integrations.connectors import sdk

    note = str(payload_in.get("note") or "Acknowledged from NodeWatch Command Center")[:500]
    # The write is bound to what the user confirmed: explicit alert keys, or the incident's membership
    # version + count shown in the dialog. Any difference → 409, nothing is written.
    if incident_id and not payload_in.get("version"):
        raise ValueError("Confirm the exact alerts: send the incident version shown in the dialog")
    try:
        items = _targets(keys, incident_id, ("new",))
    except LookupError as exc:
        raise ConflictError(
            "This incident changed since you confirmed (it was regrouped or resolved). Review it again."
        ) from exc
    current = [a.key for a, _ in items]
    if incident_id:
        expected_count = payload_in.get("count")
        if membership_version(current) != str(payload_in.get("version")) or (
            expected_count is not None and int(expected_count) != len(current)
        ):
            raise ConflictError(
                f"This incident now has {len(current)} unacknowledged alerts, not the ones you confirmed. "
                "Review it again."
            )
    elif keys is not None and set(current) != set(keys):
        raise ConflictError("Some of the alerts you confirmed changed state meanwhile. Review them again.")
    with _LOCK:
        sources = dict(_CACHE["sources"])
    writable = [(a, s) for a, s in items if sources.get(a.source, {}).get("can_ack") and a.vendor.get("alarm_ids")]
    writable_keys = {a.key for a, _ in writable}
    local_only = [(a, s) for a, s in items if a.key not in writable_keys]
    alarm_total = sum(len(a.vendor.get("alarm_ids") or []) for a, _ in writable)
    if alarm_total > MAX_SOURCE_ACK:
        raise ValueError(
            f"This would acknowledge {alarm_total} alarms in the source; the limit is {MAX_SOURCE_ACK} per action. "
            "Acknowledge locally, or open the incident and acknowledge a page of alerts."
        )

    def one(item):
        a, _ = item
        conn = sdk.get_connector(a.source)
        ack = sdk.hook(conn, "acknowledge_alert") if conn is not None else None
        if ack is None:
            return a, {"ok": False, "acked": [], "failed": [{"error": "source cannot acknowledge"}]}
        try:
            return a, ack(a, note)
        except Exception as exc:  # noqa: BLE001
            return a, {"ok": False, "acked": [], "failed": [{"error": str(exc)[:300]}]}

    results = []
    if writable:
        with ThreadPoolExecutor(max_workers=6, thread_name_prefix="ack") as pool:
            results = list(pool.map(one, writable))
    # Fully acknowledged = every alarm behind the alert acked and nothing failed; a partial ack is a failure.
    done = [a for a, r in results if r.get("acked") and not r.get("failed")]
    failed = [
        {
            "key": a.key,
            "device": a.device_name,
            "partial": bool(r.get("acked")),
            "acked": r.get("acked") or [],
            "failed": r.get("failed"),
        }
        for a, r in results
        if r.get("failed") or not r.get("acked")
    ]
    audit = AuditService().write(
        {
            "timestamp": _iso(),
            "tool": "command-center",
            "action": "acknowledge_alerts",
            "confirmed": True,
            "note": note,
            "incident_id": incident_id or "",
            "alerts": [
                {
                    "key": a.key,
                    "source": a.source,
                    "type": a.type,
                    "site": a.site_name,
                    "device": a.device_name,
                    "result": r,
                }
                for a, r in results
            ],
            "local_only": [a.key for a, _ in local_only],
        },
        "command_center_ack",
    )
    with _LOCK:  # reflect immediately; the next refresh reads Mist's own ack state
        acked_keys = {a.key for a in done}
        _CACHE["alerts"] = [
            replace(a, acknowledged=True, acknowledged_by="you (from NodeWatch)") if a.key in acked_keys else a
            for a in _CACHE["alerts"]
        ]
    done_keys = {a.key for a in done}
    n, token = _apply(
        [(a, {}) for a in done] + local_only,
        lambda a: _record(
            a,
            state="acknowledged",
            via=f"in {sources.get(a.source, {}).get('short') or a.source}" if a.key in done_keys else "",
        ),
    )
    return {
        "ok": not failed,
        "action": "ack_source",
        "changed": n,
        "acknowledged_in_source": len(done),
        "partially_acknowledged": sum(1 for f in failed if f["partial"]),
        "acknowledged_locally": len(local_only),
        "failed": failed[:20],
        "audit": audit.name,
        "undo": token,
        "undo_note": "Undo only clears NodeWatch state; Mist acknowledgements stay.",
        **payload(),
    }


def undo(token: str) -> dict:
    entry = _UNDO.pop(str(token or ""), None)
    if entry is None:
        raise LookupError("Nothing to undo (already undone or too old)")
    store = _store()
    emitted = entry.get("emitted")
    skipped = []

    def work(data: dict) -> None:
        for key, rec in entry["records"].items():
            if emitted is not None:
                # Undo is a compensating event — but only where our action is still the latest word:
                # if a teammate acted on the alert since, their action stands.
                if not emitted.get(key):
                    continue
                if store.current_event(key) != emitted[key]:
                    skipped.append(key)
                    continue
            if rec is None:
                data["alerts"].pop(key, None)
            else:
                data["alerts"][key] = rec
        if entry.get("mute_id"):
            data["mutes"].pop(entry["mute_id"], None)

    store.update(work)
    return {"ok": True, "kept_teammate_changes": len(skipped), **payload()}


def add_mute(body: dict) -> dict:
    mtype = str(body.get("type") or "").strip().lower()
    if not mtype:
        raise ValueError("Choose the alert type to mute")
    if len(mtype) > 120:
        raise ValueError("Alert type is too long (120 characters max)")
    hours = body.get("hours")
    until = None
    if hours not in (None, ""):
        try:
            h = float(hours)
        except (TypeError, ValueError) as exc:
            raise ValueError("hours must be a number") from exc
        if not math.isfinite(h) or h <= 0 or h > 8760:
            raise ValueError("hours must be more than 0 and at most 8760 (one year)")
        until = _now() + h * 3600
    rule = {
        "id": uuid.uuid4().hex[:12],
        "type": mtype,
        "label": str(body.get("label") or mtype)[:120],
        "source": str(body.get("source") or "")[:40],
        "site_key": str(body.get("site_key") or "")[:64],
        "site_name": str(body.get("site_name") or "")[:120] if body.get("site_key") else "",
        "reason": str(body.get("reason") or "")[:200],
        "created_at": _now(),
        "until": until,
    }
    _store().update(lambda data: data["mutes"].__setitem__(rule["id"], rule))
    token = _remember_undo({}, rule["id"])
    return {"ok": True, "rule": rule, "undo": token, **payload()}


def remove_mute(rule_id: str) -> dict:
    removed = _store().update(lambda data: data["mutes"].pop(rule_id, None))
    if removed is None:
        raise LookupError("Mute rule not found")
    return {"ok": True, **payload()}


def suppressed(*, kind: str = "", offset: int = 0, limit: int = 200) -> dict:
    """Snoozed / dismissed alerts and mute rules, for the 'Snoozed & muted' view."""
    with _LOCK:
        alerts = list(_CACHE["alerts"])
    rows = annotate(alerts)
    data = _store().load()
    items = []
    muted_by_rule = Counter()
    for a, s in rows:
        if s["state"] == "muted" and s["mute"]:
            muted_by_rule[s["mute"]["id"]] += 1
        if s["state"] in {"snoozed", "dismissed"} and (not kind or kind == s["state"]):
            rec = s["record"]
            items.append(
                {
                    "key": a.key,
                    "state": s["state"],
                    "title": a.title,
                    "device": a.device_name,
                    "site": a.site_name,
                    "source": a.source,
                    "severity": a.severity,
                    "until": rec.get("until"),
                    "until_change": bool(rec.get("until_change")),
                    "reason": rec.get("reason", ""),
                    "at": rec.get("at"),
                    "by": rec.get("by", ""),
                }
            )
    items.sort(key=lambda x: (x["state"], x["title"], x["site"], x["device"]))
    mutes = sorted(data["mutes"].values(), key=lambda m: -(m.get("created_at") or 0))
    for m in mutes:
        m["matching"] = muted_by_rule.get(m["id"], 0)
    return {
        "items": items[offset : offset + limit],
        "total": len(items),
        "mutes": mutes,
        "counts": {
            "snoozed": sum(1 for x in items if x["state"] == "snoozed"),
            "dismissed": sum(1 for x in items if x["state"] == "dismissed"),
            "muted": sum(muted_by_rule.values()),
        },
    }


# --------------------------------------------------------------------------- legacy rows


def legacy_items(rows: list[tuple[Alert, dict]], *, details: bool = True) -> list[dict]:
    """Old Command Center row shape (still read by the AI Engineer and the assistant).

    ``details=False`` skips facts and the engineer summary (the HTTP dashboard drops these rows anyway)."""
    from app.services.dashboard_service import _age

    out = []
    for a, s in rows:
        if s["state"] in SUPPRESSED_STATES:
            continue
        all_facts = full_facts(a) if details else []
        evidence = [f for f in all_facts if f.get("group") == "evidence"]
        facts = [f for f in all_facts if f.get("group") != "evidence"]
        row = {
            "type": a.type,
            "timestamp": a.first_seen,
            "last_seen": a.last_seen,
            "impacted_entities": a.vendor.get("entities") or [],
        }
        out.append(
            {
                "key": a.key,
                "severity": "critical" if a.severity in {"critical", "major"} else "warning",
                "type": a.type,
                "group": a.vendor.get("group", ""),
                "title": a.title,
                "device": a.device_name or "Unknown device",
                "device_type": a.vendor.get("device_type", ""),
                "mac": a.vendor.get("mac", ""),
                "site": a.site_name,
                "site_id": a.vendor.get("site_id", ""),
                "detail": a.detail,
                "age": _age(a.last_seen or a.first_seen or 0),
                "source": {"alarm": "Mist Alert", "event": "Device event", "status": "Device status"}.get(
                    a.vendor.get("origin", ""), a.source
                ),
                "vendor_source": a.source,
                "timestamp": a.first_seen or 0,
                "alarm_id": a.native_id,
                "acked": s["state"] == "acknowledged",
                "facts": facts,
                "engineer": explain_condition(
                    row,
                    {"description": a.vendor.get("definition", ""), "display": a.title},
                    site=a.site_name,
                    device=a.device_name,
                    evidence=evidence,
                )
                if details
                else {},
                "mist_url": a.console_url,
                "device_id": a.vendor.get("device_id", ""),
                "dismiss_key": a.key,
                "possibly_resolved": s["bucket"] == "possibly_resolved",
                "dismissed": False,
            }
        )
    out.sort(key=lambda x: (0 if x["severity"] == "critical" else 1, -(x.get("timestamp") or 0)))
    return out


def alerts_from_legacy(items: list[dict], *, source: str = "mist") -> list[Alert]:
    """Sample/preview rows (old Command Center shape) → Alerts, so preview mode uses the same pipeline."""
    from app.integrations.connectors.mist.alerts import _CATEGORY, is_disconnect_type
    from app.integrations.domain import normalize_mac
    from app.services.dashboard_service import _epoch, _facts, _group_for_type

    out = []
    for x in items:
        atype = str(x.get("type") or "ALERT")
        mac = normalize_mac(x.get("mac"))
        group = x.get("group") or _group_for_type(atype)
        sev = str(x.get("severity") or "warning")
        ts = _epoch(x.get("timestamp")) or None
        facts = _facts(x.get("details") or {})
        for f in facts:
            f["group"] = "reported"
        out.append(
            Alert(
                key=stable_key(
                    source, "offline" if is_disconnect_type(atype) else atype.lower(), x.get("site_id"), mac, ""
                ),
                source=source,
                type=atype,
                category=_CATEGORY.get(group, "other"),
                severity=sev if sev in SEV_RANK else "warning",
                title=str(x.get("title") or atype),
                detail=str(x.get("detail") or ""),
                site_key=stable_key("site", source, x.get("site_id")) if x.get("site_id") else "",
                site_name=str(x.get("site") or ""),
                device_key=stable_key("mac", mac) if mac else "",
                device_name=str(x.get("device") or "") if x.get("device") != "Unknown device" else "",
                device_role={"ap": "wireless_ap", "switch": "switch", "gateway": "sdwan_edge"}.get(
                    str(x.get("device_type") or ""), ""
                ),
                first_seen=ts,
                last_seen=ts,
                acknowledged=bool(x.get("acked")),
                acknowledged_by="Mist" if x.get("acked") else "",
                native_id=str(x.get("alarm_id") or ""),
                facts=facts,
                vendor={
                    "alarm_ids": [],  # preview data is never written to Mist
                    "group": group,
                    "device_type": str(x.get("device_type") or ""),
                    "mac": mac,
                    "site_id": str(x.get("site_id") or ""),
                    "origin": "preview",
                },
            )
        )
    return out
