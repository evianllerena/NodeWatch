"""Live health on the topology map (v0.10.17, topology phase 2).

Vendor-neutral: everything comes through capabilities, never a vendor API.

    HEALTH      list_health(site) → {"devices": [Device], "interfaces": [Interface], "tunnels": [Tunnel]}
    INTERFACES  list_interfaces(dev) → rates/errors from sources that have no HEALTH capability
    ALERTS      list_alerts(site)    → open-alert counts per device (enrichment only)

The raw readings are gathered once per scope and cached ``HEALTH_TTL_S`` seconds; thresholds are
applied on every request (cheap), so each user's threshold settings take effect immediately.

Per node:  CPU, memory, sessions (of max when known), PoE budget, HA state, up/down, open alerts.
Per link:  utilization % (LAG: summed rates over summed speed), error % of packets (or raw error
           counters when packet counts are unknown), flaps, LAG members up/total, tunnel
           latency / loss / jitter and state.
Each metric → good | warning | critical with a readable reason ("HQ-IDF1 ge-0/0/48 2.1% errors",
"tunnel to BR-NYC loss 3.4%") and the source it came from.

Neutral domain fields used (v0.10.24): Interface.rx_pkts / tx_pkts / last_flapped, Device.sessions_max /
poe_used_w / poe_budget_w, Tunnel.jitter_ms. During the transition the same names are still read from a
record's ``vendor`` dict when the field is empty. WAN-port latency / loss / jitter come from
Interface.latency_ms / loss_pct / jitter_ms (same vendor fallback).
"""

from __future__ import annotations

import json
import logging
import threading
import time
from collections import OrderedDict, defaultdict
from typing import Any

from app.integrations.connectors import sdk
from app.integrations.contracts import ALERTS, HEALTH, INTERFACES
from app.integrations.domain import normalize_mac
from app.services import topology_service as topo

log = logging.getLogger("nodewatch.topology.health")

HEALTH_TTL_S = 45.0  # readings served from cache this long; older ones are served while a refresh runs
HEALTH_MAX_AGE_S = 600.0  # older than this a reading is not served stale: the request waits for a fresh one
CACHE_MAX_SCOPES = 16
MAX_INTERFACE_CALLS = 30  # per source without HEALTH, per refresh
RECENT_FLAP_S = 15 * 60
WORST_LIMIT = 12

# metric → (warning, critical, label, unit). Higher is worse for every metric.
DEFAULT_THRESHOLDS: dict[str, dict[str, float]] = {
    "cpu_pct": {"warning": 80, "critical": 95},
    "memory_pct": {"warning": 85, "critical": 95},
    "sessions_pct": {"warning": 80, "critical": 95},
    "poe_pct": {"warning": 85, "critical": 95},
    "util_pct": {"warning": 70, "critical": 90},
    "error_pct": {"warning": 0.1, "critical": 1.0},
    "errors": {"warning": 1000, "critical": 10000},
    "flaps_24h": {"warning": 3, "critical": 10},
    "loss_pct": {"warning": 1.0, "critical": 3.0},
    "latency_ms": {"warning": 150, "critical": 300},
    "jitter_ms": {"warning": 30, "critical": 60},
}
METRIC_LABELS = {
    "cpu_pct": ("CPU", "%"),
    "memory_pct": ("Memory", "%"),
    "sessions_pct": ("Sessions", "% of max"),
    "poe_pct": ("PoE budget", "%"),
    "util_pct": ("Utilization", "%"),
    "error_pct": ("Errors", "% of packets"),
    "errors": ("Error counters", ""),
    "flaps_24h": ("Flaps (24 h)", ""),
    "loss_pct": ("Loss", "%"),
    "latency_ms": ("Latency", "ms"),
    "jitter_ms": ("Jitter", "ms"),
}
_RANK = {"critical": 3, "warning": 2, "good": 1, "unknown": 0}
_HA_BAD = ("degrad", "fail", "suspend", "non-functional", "nonfunctional", "split", "unknown-peer", "out of sync")

_raw_cache: OrderedDict[str, tuple[float, dict[str, Any]]] = OrderedDict()
_cache_lock = threading.Lock()
_scope_locks: OrderedDict[str, threading.Lock] = OrderedDict()
MAX_SCOPE_LOCKS = 32


# --------------------------------------------------------------------------- thresholds


def clean_thresholds(value: Any) -> dict[str, dict[str, float]]:
    """User overrides (dict or JSON text) merged over the defaults; invalid entries are ignored."""
    if isinstance(value, str):
        try:
            value = json.loads(value) if value.strip() else {}
        except ValueError:
            value = {}
    out = {k: dict(v) for k, v in DEFAULT_THRESHOLDS.items()}
    if not isinstance(value, dict):
        return out
    for metric, pair in value.items():
        if metric not in out or not isinstance(pair, dict):
            continue
        try:
            w = float(pair.get("warning", out[metric]["warning"]))
            c = float(pair.get("critical", out[metric]["critical"]))
        except (TypeError, ValueError):
            continue
        if not (0 <= w <= 1e7 and 0 <= c <= 1e7) or c < w:
            continue
        out[metric] = {"warning": w, "critical": c}
    return out


def grade(metric: str, value: float | None, th: dict[str, dict[str, float]]) -> str:
    if value is None:
        return "unknown"
    t = th.get(metric) or DEFAULT_THRESHOLDS[metric]
    if value >= t["critical"]:
        return "critical"
    if value >= t["warning"]:
        return "warning"
    return "good"


def _worst(states: list[str]) -> str:
    return max(states, key=lambda s: _RANK.get(s, 0)) if states else "unknown"


def _fmt(value: float | None, unit: str = "") -> str:
    if value is None:
        return "—"
    v = float(value)
    text = f"{v:,.0f}" if abs(v) >= 100 or v == int(v) else f"{v:,.1f}" if abs(v) >= 1 else f"{v:.2f}"
    return f"{text}{'%' if unit.startswith('%') else (' ' + unit if unit else '')}"


def _num(value: Any) -> float | None:
    try:
        return None if value in (None, "") else float(value)
    except (TypeError, ValueError):
        return None


# --------------------------------------------------------------------------- raw collection


def _collect(scope: str) -> dict[str, Any]:
    """One read of every health source for a scope (devices, interfaces, tunnels, alerts)."""
    started = time.monotonic()
    site = scope or None
    graph = topo.graph_for(site)
    # Each source returns one dict of three lists; call them directly to keep the lists apart.
    devices: list[Any] = []
    interfaces: list[Any] = []
    tunnels: list[Any] = []
    status = topo._Sources()
    health_sources = sdk.sources(HEALTH)
    # Same cross-source site scope as the map: a source that names the site differently is asked for
    # everything and filtered to the devices on this map.
    site_scope = topo.resolve_scope(site)
    on_map = {rec["key"] for n in graph.get("nodes", []) for rec in n.get("records", [])}
    on_map_sources = {rec["source"] for n in graph.get("nodes", []) for rec in n.get("records", [])}
    calls: list[tuple[Any, str | None, bool]] = []
    for c in health_sources:
        if site and c.provider_id not in on_map_sources:
            continue  # nothing of this source on the map: no reason to ask it
        args = site_scope.args_for(c.provider_id)
        filtered = args is None or (bool(site) and args == [None])
        for a in [None] if args is None else args:
            calls.append((c, a, filtered))
    bundles = topo._pool_run(
        [
            lambda c=c, a=a: status.call(c, HEALTH, lambda: [c.list_health(a) or {}], ("list_health", a))
            for c, a, _f in calls
        ]
    )
    for (c, a, filtered), got in zip(calls, bundles):
        for bundle in got:
            if not isinstance(bundle, dict):
                continue
            devs = list(bundle.get("devices") or [])
            ifs = list(bundle.get("interfaces") or [])
            tuns = list(bundle.get("tunnels") or [])
            if filtered:
                devs = [d for d in devs if d.key in on_map]
                ifs = [i for i in ifs if i.device_key in on_map]
                tuns = [t for t in tuns if t.device_key in on_map]
            devices += devs
            interfaces += ifs
            tunnels += tuns
    # Sources with interface counters but no HEALTH capability (e.g. an SNMP poller): ask per device
    # for the boxes on the map's links, bounded.
    covered = {c.provider_id for c in health_sources}
    linked = {x for link in graph.get("links", []) for x in (link["a_device"], link["b_device"])}
    jobs = []
    for c in sdk.sources(INTERFACES):
        if c.provider_id in covered:
            continue
        targets = [
            rec["key"]
            for node in graph.get("nodes", [])
            if node["id"] in linked and node["role"] not in ("wireless_ap", "endpoint", "cloud")
            for rec in node.get("records", [])
            if rec["source"] == c.provider_id
        ]
        if len(targets) > MAX_INTERFACE_CALLS:
            status.cap(
                f"Port counters were read from {MAX_INTERFACE_CALLS} of {len(targets)} devices of "
                f"{c.manifest.product or c.provider_id} (limit per refresh)."
            )
        for k in targets[:MAX_INTERFACE_CALLS]:
            jobs.append(
                lambda c=c, k=k: status.call(c, INTERFACES, lambda: c.list_interfaces(k), ("list_interfaces", k))
            )
    alert_sources = [c for c in sdk.sources(ALERTS) if not site or c.provider_id in on_map_sources]
    jobs += [
        lambda c=c: (
            "alerts",
            site_scope.call(
                status, c, ALERTS, "list_alerts", lambda a: a.device_key in on_map or site_scope.record_in(a)
            ),
        )
        for c in alert_sources
    ]
    alerts: list[Any] = []
    for got in topo._pool_run(jobs):
        if isinstance(got, tuple):
            alerts += got[1]
        else:
            interfaces += got
    return {
        "scope": scope,  # the site key string (never the SiteScope object)
        "site_name": site_scope.name,
        "collected_at": time.time(),
        "collect_ms": round((time.monotonic() - started) * 1000),
        "graph": graph,
        "devices": devices,
        "interfaces": interfaces,
        "tunnels": tunnels,
        "alerts": [a for a in alerts if not getattr(a, "resolved", False)],
        "sources": list(status.status.values()),
        "caps": list(status.caps),
        "health_sources": [c.provider_id for c in health_sources],
    }


def collect(scope: str = "", *, fresh: bool = False) -> tuple[dict[str, Any], bool]:
    """Cached raw readings for a scope → (raw, cached?). Concurrent callers share one read.

    v0.10.23: stale-while-revalidate — readings younger than ``HEALTH_TTL_S`` are served as they are;
    older ones (up to ``HEALTH_MAX_AGE_S``) are served at once while one background refresh runs.
    Only a scope never read (or ``fresh``) waits for the sources."""
    scope = str(scope or "").strip()
    if not topo._SCOPE_RE.match(scope):
        raise ValueError("Invalid site key")
    now = time.time()
    with _cache_lock:
        hit = _raw_cache.get(scope)
        if hit and not fresh and now - hit[0] < HEALTH_TTL_S:
            _raw_cache.move_to_end(scope)
            return hit[1], True
        lock = _scope_lock(scope)
    if hit and not fresh and now - hit[0] < HEALTH_MAX_AGE_S:
        _refresh_async(scope, lock)
        return hit[1], True
    with lock:
        with _cache_lock:
            hit = _raw_cache.get(scope)
        if hit and hit[0] >= now:  # someone else read this scope while we waited
            return hit[1], True
        raw = _collect(scope)
        _put(scope, raw)
        return raw, False


def _put(scope: str, raw: dict[str, Any]) -> None:
    with _cache_lock:
        _raw_cache[scope] = (time.time(), raw)
        _raw_cache.move_to_end(scope)
        while len(_raw_cache) > CACHE_MAX_SCOPES:
            _raw_cache.popitem(last=False)


def _refresh_async(scope: str, lock: threading.Lock) -> None:
    """One background refresh per scope (skipped while a read of it is running)."""
    if not lock.acquire(blocking=False):
        return

    def run() -> None:
        try:
            _put(scope, _collect(scope))
        except Exception as exc:  # noqa: BLE001 - the previous readings stay
            log.info("topology health: background refresh of %r failed: %s", scope, exc)
        finally:
            lock.release()

    threading.Thread(target=run, name="topology-health", daemon=True).start()


def refreshing(scope: str) -> bool:
    with _cache_lock:
        lock = _scope_locks.get(str(scope or ""))
    return bool(lock and lock.locked())


def _scope_lock(scope: str) -> threading.Lock:
    """Per-scope single-flight lock (caller holds _cache_lock); idle locks beyond MAX_SCOPE_LOCKS are dropped."""
    lock = _scope_locks.get(scope)
    if lock is None:
        lock = _scope_locks[scope] = threading.Lock()
    _scope_locks.move_to_end(scope)
    if len(_scope_locks) > MAX_SCOPE_LOCKS:
        for old in [k for k, v in _scope_locks.items() if k != scope and not v.locked()]:
            if len(_scope_locks) <= MAX_SCOPE_LOCKS:
                break
            del _scope_locks[old]
    return lock


def cached_raw(scope: str | None) -> dict[str, Any] | None:
    """Raw readings already collected for a scope (no source is asked); None when absent or stale."""
    with _cache_lock:
        hit = _raw_cache.get(str(scope or ""))
    return hit[1] if hit and time.time() - hit[0] < HEALTH_TTL_S else None


def clear_cache() -> None:
    with _cache_lock:
        _raw_cache.clear()
        _scope_locks.clear()


# --------------------------------------------------------------------------- mapping records → nodes


class _Index:
    """Maps vendor records (source, device_key / MAC) onto topology node ids."""

    def __init__(self, graph: dict[str, Any]) -> None:
        self.nodes = {n["id"]: n for n in graph.get("nodes", [])}
        self.alias: dict[str, str] = {}
        self.by_mac: dict[str, str] = {}
        for n in graph.get("nodes", []):
            for rec in n.get("records", []):
                self.alias[f"{rec['source']}:{rec['key']}"] = n["id"]
                self.alias.setdefault(rec["key"], n["id"])
            for m in n.get("macs", []):
                self.by_mac.setdefault(m, n["id"])

    def node(self, source: str, device_key: str, mac: str = "") -> str:
        return (
            self.alias.get(f"{source}:{device_key}")
            or self.alias.get(device_key)
            or self.by_mac.get(normalize_mac(mac))
            or ""
        )


def interface_metrics(itf: Any) -> dict[str, Any]:
    """Numbers for one Interface record (utilization computed from rates when not given)."""
    # transition fallback (v0.10.24): remove when all connectors fill
    # Interface.rx_pkts / tx_pkts / last_flapped / latency_ms / loss_pct / jitter_ms
    v = getattr(itf, "vendor", None) or {}

    def field_or_vendor(name: str) -> float | None:
        value = getattr(itf, name, None)
        # transition fallback (v0.10.24): remove when all connectors fill Interface.<name>
        return _num(value if value is not None else v.get(name))

    speed = _num(itf.speed_mbps)
    rx_bps, tx_bps = _num(itf.rx_bps), _num(itf.tx_bps)
    util = _num(itf.utilization_pct)
    if util is None and speed and (rx_bps is not None or tx_bps is not None):
        util = max(rx_bps or 0.0, tx_bps or 0.0) / (speed * 1e6) * 100
    errors = None
    if itf.rx_errors is not None or itf.tx_errors is not None:
        errors = int(itf.rx_errors or 0) + int(itf.tx_errors or 0)
    pkts = None
    rx_pkts, tx_pkts = field_or_vendor("rx_pkts"), field_or_vendor("tx_pkts")
    if rx_pkts is not None or tx_pkts is not None:
        pkts = (rx_pkts or 0.0) + (tx_pkts or 0.0)
    error_pct = (errors / pkts * 100) if errors is not None and pkts else None
    last_flap = field_or_vendor("last_flapped")
    return {
        "name": itf.name,
        "oper_up": itf.oper_up,
        "speed_mbps": speed,
        "rx_bps": rx_bps,
        "tx_bps": tx_bps,
        "util_pct": round(util, 2) if util is not None else None,
        "errors": errors,
        "rx_errors": itf.rx_errors,
        "tx_errors": itf.tx_errors,
        "error_pct": round(error_pct, 3) if error_pct is not None else None,
        "flaps_24h": itf.flaps_24h,
        "last_flapped": last_flap,
        "latency_ms": field_or_vendor("latency_ms"),
        "loss_pct": field_or_vendor("loss_pct"),
        "jitter_ms": field_or_vendor("jitter_ms"),
        "poe_watts": _num(itf.poe_watts),
        "source": itf.source,
    }


# --------------------------------------------------------------------------- evaluation


def _reason(metric: str, value: float | None, state: str, text: str, source: str = "") -> dict[str, Any]:
    return {"metric": metric, "value": value, "state": state, "text": text, "source": source}


def _grade_interface(
    reasons: list[dict[str, Any]], m: dict[str, Any], who: str, th: dict[str, dict[str, float]], now: float
) -> None:
    src = m.get("source", "")
    if m.get("error_pct") is not None:
        s = grade("error_pct", m["error_pct"], th)
        if s != "good":
            reasons.append(_reason("error_pct", m["error_pct"], s, f"{who} {_fmt(m['error_pct'], '%')} errors", src))
    elif m.get("errors") is not None:
        s = grade("errors", m["errors"], th)
        if s != "good":
            reasons.append(_reason("errors", m["errors"], s, f"{who} {m['errors']:,} error counters", src))
    if m.get("flaps_24h") is not None:
        s = grade("flaps_24h", m["flaps_24h"], th)
        if s != "good":
            reasons.append(_reason("flaps_24h", m["flaps_24h"], s, f"{who} flapped {m['flaps_24h']}× in 24 h", src))
    elif m.get("last_flapped") and 0 <= now - m["last_flapped"] < RECENT_FLAP_S:
        mins = max(1, round((now - m["last_flapped"]) / 60))
        reasons.append(_reason("flaps_24h", None, "warning", f"{who} flapped {mins} min ago", src))
    for metric, word in (("loss_pct", "loss"), ("latency_ms", "latency"), ("jitter_ms", "jitter")):
        if m.get(metric) is not None:
            s = grade(metric, m[metric], th)
            if s != "good":
                unit = METRIC_LABELS[metric][1]
                reasons.append(_reason(metric, m[metric], s, f"{who} {word} {_fmt(m[metric], unit)}", src))


def _evaluate_device(d: dict[str, Any], th: dict[str, dict[str, float]]) -> tuple[str, list[dict[str, Any]]]:
    reasons: list[dict[str, Any]] = []
    for metric in ("cpu_pct", "memory_pct", "sessions_pct", "poe_pct"):
        val = d["metrics"].get(metric)
        s = grade(metric, val, th)
        if s in ("warning", "critical"):
            label, unit = METRIC_LABELS[metric]
            reasons.append(_reason(metric, val, s, f"{label} {_fmt(val, unit)}", d["metric_sources"].get(metric, "")))
    if d.get("status") == "down":
        reasons.append(_reason("status", None, "critical", "Device is down", d.get("status_source", "")))
    elif d.get("status") == "degraded":
        reasons.append(_reason("status", None, "warning", "Device reports degraded", d.get("status_source", "")))
    ha = str(d["metrics"].get("ha_state") or "").lower()
    if ha and any(w in ha for w in _HA_BAD):
        reasons.append(_reason("ha_state", None, "warning", f"HA {ha}", d["metric_sources"].get("ha_state", "")))
    alerts = d["metrics"].get("alerts") or 0
    sev = d.get("alert_worst", "")
    if alerts and sev in ("critical", "major"):
        reasons.append(
            _reason("alerts", alerts, "warning", f"{alerts} open alert{'s' if alerts != 1 else ''} ({sev})", "alerts")
        )
    has_data = any(d["metrics"].get(k) is not None for k in ("cpu_pct", "memory_pct", "sessions", "poe_pct")) or bool(
        d.get("status") in ("up", "down", "degraded")
    )
    state = _worst([r["state"] for r in reasons]) if reasons else ("good" if has_data else "unknown")
    return state, sorted(reasons, key=lambda r: -_RANK[r["state"]])


_BADGE_WORDS = {
    "cpu_pct": "CPU",
    "memory_pct": "mem",
    "sessions_pct": "sessions",
    "poe_pct": "PoE",
    "util_pct": "util",
    "error_pct": "err",
    "errors": "err",
    "flaps_24h": "flaps",
    "loss_pct": "loss",
    "latency_ms": "latency",
    "jitter_ms": "jitter",
}
_BADGE_FIXED = {"status": "down", "state": "down", "ha_state": "HA", "alerts": "alerts", "members": "LAG degraded"}


def _badge(reasons: list[dict[str, Any]]) -> str:
    """Short map label for the worst reason: 'CPU 97%', 'loss 3.4%', 'err 2.1%', 'down'."""
    if not reasons:
        return ""
    r = reasons[0]
    metric, val = r["metric"], r["value"]
    if metric == "flaps_24h" and val is None:
        return "flapped"
    if metric == "members" and val is not None and r["state"] == "critical":
        return "LAG down"
    if metric in _BADGE_WORDS and val is not None:
        unit = METRIC_LABELS[metric][1]
        v = round(val) if abs(val) >= 10 else val
        text = _fmt(v, unit if unit.startswith("%") or unit == "ms" else "")
        return f"{_BADGE_WORDS[metric]} {text}"
    return _BADGE_FIXED.get(metric, "alert")


def evaluate(raw: dict[str, Any], thresholds: Any = None) -> dict[str, Any]:
    """Apply thresholds to raw readings → per-node / per-link health, worst list and summary."""
    th = clean_thresholds(thresholds)
    graph = raw["graph"]
    idx = _Index(graph)
    now = time.time()

    # ---- devices
    dev: dict[str, dict[str, Any]] = {}

    def node_row(nid: str) -> dict[str, Any]:
        if nid not in dev:
            n = idx.nodes[nid]
            dev[nid] = {
                "metrics": {},
                "metric_sources": {},
                "status": n.get("status", "unknown"),
                "status_source": ", ".join(n.get("sources", [])[:1]),
                "sources": [],
                "ports": [],
            }
        return dev[nid]

    for d in raw["devices"]:
        nid = idx.node(d.source, d.key, d.mac)
        if not nid:
            continue
        row = node_row(nid)
        topo._add_unique(row["sources"], d.source)
        # transition fallback (v0.10.24): remove when all connectors fill Device.sessions_max/poe_used_w/poe_budget_w
        v = d.vendor or {}

        def dev_field(name: str, d: Any = d, v: dict = v) -> float | None:
            value = getattr(d, name, None)
            # transition fallback (v0.10.24): remove when all connectors fill Device.<name>
            return _num(value if value is not None else v.get(name))

        sessions_max = dev_field("sessions_max")
        poe_used, poe_budget = dev_field("poe_used_w"), dev_field("poe_budget_w")
        values = {
            "cpu_pct": _num(d.cpu_pct),
            "memory_pct": _num(d.memory_pct),
            "sessions": d.sessions,
            "sessions_max": sessions_max,
            "sessions_pct": (d.sessions / sessions_max * 100) if d.sessions is not None and sessions_max else None,
            "poe_used_w": poe_used,
            "poe_budget_w": poe_budget,
            "poe_pct": (poe_used / poe_budget * 100) if poe_used is not None and poe_budget else None,
            "ha_state": d.ha_state or "",
        }
        for k, val in values.items():
            if val not in (None, "") and row["metrics"].get(k) in (None, ""):
                row["metrics"][k] = round(val, 2) if isinstance(val, float) else val
                row["metric_sources"][k] = d.source
        if d.status in ("up", "down", "degraded"):
            row["status"] = d.status
            row["status_source"] = d.source
    sev_rank = {"critical": 4, "major": 3, "warning": 2, "info": 1}
    for a in raw.get("alerts", []):
        nid = idx.node(a.source, a.device_key) if a.device_key else ""
        if not nid:
            continue
        row = node_row(nid)
        row["metrics"]["alerts"] = (row["metrics"].get("alerts") or 0) + 1
        if sev_rank.get(a.severity, 0) > sev_rank.get(row.get("alert_worst", ""), 0):
            row["alert_worst"] = a.severity

    # ---- interfaces, keyed by (node, normalized name)
    ifaces: dict[tuple[str, str], dict[str, Any]] = {}
    for itf in raw["interfaces"]:
        nid = idx.node(itf.source, itf.device_key)
        if not nid:
            continue
        key = (nid, topo.norm_if(itf.name))
        m = interface_metrics(itf)
        if key in ifaces:  # two sources describe one port: keep the richer reading, list it once
            old = ifaces[key]
            for k, val in m.items():
                if old.get(k) is None and val is not None:
                    old[k] = val
        else:
            ifaces[key] = m
            node_row(nid)["ports"].append(key)

    for nid, n in idx.nodes.items():  # nodes no health source reads: their up/down state still counts
        if nid not in dev and n.get("status") in ("up", "down", "degraded") and not n.get("synthetic"):
            node_row(nid)
    nodes_out: dict[str, Any] = {}
    for nid, row in dev.items():
        state, reasons = _evaluate_device(row, th)
        port_issues = []
        for key in row["ports"]:
            m = ifaces.get(key)
            if not m:
                continue
            rs: list[dict[str, Any]] = []
            _grade_interface(rs, m, m["name"], th, now)
            if rs:
                port_issues.append({"interface": m["name"], "state": _worst([r["state"] for r in rs]), "reasons": rs})
        port_issues.sort(key=lambda p: -_RANK[p["state"]])
        nodes_out[nid] = {
            "state": state,
            "reasons": reasons,
            "badge": _badge(reasons),
            "metrics": row["metrics"],
            "metric_sources": row["metric_sources"],
            "sources": row["sources"],
            "port_issues": port_issues[:8],
            "port_issue_count": len(port_issues),
        }

    # ---- tunnels from HEALTH (fresher latency/loss than the topology build)
    tun: dict[tuple[str, str], Any] = {}
    for t in raw["tunnels"]:
        nid = idx.node(t.source, t.device_key)
        if nid:
            tun[(nid, topo.norm_if(t.name))] = t

    links_out: dict[str, Any] = {}
    for link in graph.get("links", []):
        links_out[link["key"]] = _evaluate_link(link, idx, ifaces, tun, th, now)

    # ---- worst right now
    worst = []
    for nid, h in nodes_out.items():
        if h["state"] in ("warning", "critical"):
            n = idx.nodes[nid]
            worst.append(
                {"type": "node", "id": nid, "name": n["name"], "role": n["role"], "state": h["state"],
                 "text": h["reasons"][0]["text"] if h["reasons"] else "", "count": len(h["reasons"])}
            )  # fmt: skip
    for key, h in links_out.items():
        if h["state"] in ("warning", "critical"):
            worst.append(
                {"type": "link", "id": key, "name": h["name"], "layer": h["layer"], "state": h["state"],
                 "text": h["reasons"][0]["text"] if h["reasons"] else "", "count": len(h["reasons"])}
            )  # fmt: skip
    worst.sort(key=lambda w: (-_RANK[w["state"]], -w["count"], w["name"].lower()))
    summary: dict[str, int] = defaultdict(int)
    for h in list(nodes_out.values()) + list(links_out.values()):
        summary[h["state"]] += 1
    gaps = []
    if not raw.get("health_sources"):
        gaps.append(
            "No connected source offers live health yet — connect one under Settings › Connections "
            "(switch/AP/firewall/SD-WAN management) to colour the map."
        )
    for s in raw.get("sources", []):
        if not s.get("ok"):
            if s.get("stale"):
                gaps.append(
                    f"{s['product']} health could not be read just now — showing its last readings: {s['error']}"
                )
            else:
                gaps.append(f"{s['product']} health could not be read: {s['error']}")
    gaps.extend(raw.get("caps") or [])
    return {
        "scope": raw["scope"],
        "generated_at": raw["collected_at"],
        "collect_ms": raw.get("collect_ms", 0),
        "topology_generated_at": graph.get("generated_at"),
        "thresholds": th,
        "defaults": DEFAULT_THRESHOLDS,
        "labels": {k: {"label": v[0], "unit": v[1]} for k, v in METRIC_LABELS.items()},
        "nodes": nodes_out,
        "links": links_out,
        "worst": worst[:WORST_LIMIT],
        "worst_total": len(worst),
        "summary": {k: summary.get(k, 0) for k in ("critical", "warning", "good", "unknown")},
        "sources": raw.get("sources", []),
        "gaps": gaps,
    }


def _evaluate_link(
    link: dict[str, Any],
    idx: _Index,
    ifaces: dict[tuple[str, str], dict[str, Any]],
    tun: dict[tuple[str, str], Any],
    th: dict[str, dict[str, float]],
    now: float,
) -> dict[str, Any]:
    a, b = link["a_device"], link["b_device"]
    an, bn = idx.nodes.get(a, {}).get("name", a), idx.nodes.get(b, {}).get("name", b)
    reasons: list[dict[str, Any]] = []
    metrics: dict[str, Any] = {}
    sources: list[str] = []
    ends: list[dict[str, Any]] = []
    layer = link["layer"]
    name = f"{an} ↔ {bn}"
    if layer == "overlay":
        rows = []
        for m in link.get("members", []):
            frm = m.get("from") or a
            t = tun.get((frm, topo.norm_if(m.get("tunnel"))))
            far = idx.nodes.get(b if frm == a else a, {}).get("name", "")
            row = {
                "tunnel": m.get("tunnel") or "",
                "from": idx.nodes.get(frm, {}).get("name", ""),
                "to": far,
                "state": (t.state if t else m.get("state")) or "unknown",
                "latency_ms": _num(t.latency_ms) if t and t.latency_ms is not None else _num(m.get("latency_ms")),
                "loss_pct": _num(t.loss_pct) if t and t.loss_pct is not None else _num(m.get("loss_pct")),
                "jitter_ms": _num(topo.tunnel_jitter(t)) if t else _num(m.get("jitter_ms")),
                "source": t.source if t else ", ".join(link.get("sources", [])),
            }
            rows.append(row)
            if row["source"]:
                topo._add_unique(sources, row["source"].split(", ")[0])
            label = f"tunnel {row['tunnel']} to {far}" if row["tunnel"] else f"tunnel to {far}"
            if row["state"] == "down":
                reasons.append(_reason("state", None, "critical", f"{label} is down", row["source"]))
            for metric, word in (("loss_pct", "loss"), ("latency_ms", "latency"), ("jitter_ms", "jitter")):
                s = grade(metric, row[metric], th)
                if s in ("warning", "critical"):
                    unit = METRIC_LABELS[metric][1]
                    reasons.append(
                        _reason(metric, row[metric], s, f"{label} {word} {_fmt(row[metric], unit)}", row["source"])
                    )
        up = sum(1 for r in rows if r["state"] == "up")
        metrics.update(
            tunnels_up=up,
            tunnels_total=len(rows),
            latency_ms=max((r["latency_ms"] for r in rows if r["latency_ms"] is not None), default=None),
            loss_pct=max((r["loss_pct"] for r in rows if r["loss_pct"] is not None), default=None),
            jitter_ms=max((r["jitter_ms"] for r in rows if r["jitter_ms"] is not None), default=None),
        )
        if rows and 0 < up < len(rows) and not any(r["metric"] == "state" for r in reasons):
            reasons.append(_reason("members", None, "warning", f"{up}/{len(rows)} tunnels up", ""))
        has_data = any(r["state"] in ("up", "down") or r["latency_ms"] is not None for r in rows)
        state = _worst([r["state"] for r in reasons]) if reasons else ("good" if has_data else "unknown")
        reasons.sort(key=lambda r: -_RANK[r["state"]])
        return {
            "state": state, "reasons": reasons, "badge": _badge(reasons), "metrics": metrics,
            "tunnels": rows, "sources": sources, "name": name, "layer": layer, "weight": None,
        }  # fmt: skip

    # physical / lag / l2 / l3: interface counters on either end
    members = link.get("members") or [{"a_interface": link.get("a_interface"), "b_interface": link.get("b_interface")}]
    up_count, total = 0, 0
    rates: dict[str, list[float]] = {"a_interface": [0.0, 0.0], "b_interface": [0.0, 0.0]}  # [bps, capacity]
    util_max = None
    seen_ports: set[tuple[str, str]] = set()
    for mem in members:
        total += 1
        mem_up = mem.get("state") == "up" if mem.get("state") in ("up", "down") else None
        for nid, nname, side in ((a, an, "a_interface"), (b, bn, "b_interface")):
            for port in [p.strip() for p in str(mem.get(side) or "").split(",") if p.strip()]:
                key = (nid, topo.norm_if(port))
                m = ifaces.get(key)
                if m is None or key in seen_ports:
                    continue
                seen_ports.add(key)
                topo._add_unique(sources, m["source"])
                ends.append({"device": nname, **m})
                if m["oper_up"] is False:
                    mem_up = False
                elif m["oper_up"] is True and mem_up is None:
                    mem_up = True
                _grade_interface(reasons, m, f"{nname} {m['name']}", th, now)
                if m["util_pct"] is not None:
                    util_max = max(util_max or 0.0, m["util_pct"])
                if m["speed_mbps"] and (m["rx_bps"] is not None or m["tx_bps"] is not None):
                    rates[side][0] += max(m["rx_bps"] or 0.0, m["tx_bps"] or 0.0)
                    rates[side][1] += m["speed_mbps"] * 1e6
        if mem_up:
            up_count += 1
    # LAG: bundle utilization from summed member rates (busier end), else the busiest member.
    sums = [bps / cap * 100 for bps, cap in rates.values() if cap]
    util = max(sums) if total > 1 and sums else util_max
    if util is not None:
        util = round(util, 2)
        metrics["util_pct"] = util
        s = grade("util_pct", util, th)
        if s in ("warning", "critical"):
            reasons.append(
                _reason("util_pct", util, s, f"{name} {_fmt(util, '%')} utilized", sources[0] if sources else "")
            )
    if layer in ("physical", "lag") and total:
        metrics["members_up"], metrics["members_total"] = up_count, total
        if total > 1 and up_count < total:
            s = "critical" if up_count == 0 else "warning"
            reasons.append(_reason("members", up_count, s, f"{name}: {up_count}/{total} LAG members up", ""))
        elif total == 1 and link.get("state") == "down":
            reasons.append(_reason("state", None, "critical", f"{name} is down", ""))
    errs = [e["error_pct"] for e in ends if e.get("error_pct") is not None]
    if errs:
        metrics["error_pct"] = max(errs)
    flaps = [e["flaps_24h"] for e in ends if e.get("flaps_24h") is not None]
    if flaps:
        metrics["flaps_24h"] = sum(flaps)
    has_data = bool(ends) or link.get("state") in ("up", "down")
    state = _worst([r["state"] for r in reasons]) if reasons else ("good" if has_data else "unknown")
    reasons.sort(key=lambda r: -_RANK[r["state"]])
    return {
        "state": state, "reasons": reasons, "badge": _badge(reasons), "metrics": metrics, "ends": ends,
        "sources": sources, "name": name, "layer": layer, "weight": util,
    }  # fmt: skip


def topology_health(site_key: str | None = None, *, thresholds: Any = None, fresh: bool = False) -> dict[str, Any]:
    """GET /api/v1/topology/health: live per-node / per-link health for one site (cached 25 s)."""
    raw, cached = collect(site_key or "", fresh=fresh)
    out = evaluate(raw, thresholds)
    out["cached"] = cached
    out["age_s"] = round(time.time() - raw["collected_at"], 1)
    out["refreshing"] = refreshing(site_key or "")
    return out
