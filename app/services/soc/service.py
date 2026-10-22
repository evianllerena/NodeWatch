"""Security Operations API assembly (v0.10.30): one call per page view, every number from neutral records."""

from __future__ import annotations

import re
import threading
import time
from typing import Any

from app.integrations.contracts import (
    CAPABILITY_LABELS,
    SECURITY_EVENTS,
    SECURITY_EXPOSURES,
    SECURITY_INCIDENTS,
)
from app.integrations.domain import SECURITY_EVENT_KIND_LABELS
from app.integrations.geo import COUNTRIES, country_name
from app.services.soc import cases_state, context, demo, engine, exposure
from app.services.soc.collector import Collector
from app.services.soc.store import EventStore

SOC_CAPABILITIES = (SECURITY_EVENTS, SECURITY_EXPOSURES, SECURITY_INCIDENTS)
WINDOWS = {"1h": 3600, "6h": 6 * 3600, "24h": 24 * 3600, "3d": 3 * 24 * 3600, "7d": 7 * 24 * 3600}
CACHE_S = 15.0

# Every country NodeWatch can place, as faint points on the origin map: [code, lat, lon].
WORLD = [[code, row[1], row[2]] for code, row in COUNTRIES.items()]

STORE = EventStore()
COLLECTOR = Collector(STORE)
_cache: dict[tuple, tuple[float, Any]] = {}
_cache_lock = threading.Lock()


def window_s(window: str) -> int:
    return WINDOWS.get(str(window or "24h"), WINDOWS["24h"])


# --------------------------------------------------------------------------- sources & coverage


def coverage() -> list[dict[str, Any]]:
    """Every connector that can feed Security Operations, whether it is connected, and what it delivered."""
    from app.integrations.connectors import sdk

    stats = STORE.stats()
    out = []
    for c in sdk.all_connectors():
        caps = [cap for cap in c.manifest.capabilities if cap in SOC_CAPABILITIES]
        if not caps:
            continue
        try:
            state = sdk.connector_state(c)
        except Exception:  # noqa: BLE001
            state = {"state": "error", "label": "Error"}
        connected = any(c in sdk.sources(cap) for cap in caps)
        read = COLLECTOR.status.get(c.provider_id) or {}
        out.append(
            {
                "source": c.provider_id,
                "product": c.manifest.product,
                "vendor": c.manifest.vendor,
                "capabilities": [{"id": cap, "label": CAPABILITY_LABELS.get(cap, cap)} for cap in caps],
                "connected": connected,
                "state": state.get("state"),
                "state_label": state.get("label"),
                "stored": int((stats.get("by_source") or {}).get(c.provider_id, 0)),
                "last_read": read.get("read_at"),
                "last_ok": read.get("last_ok"),
                "last_error": read.get("error") or "",
                "last_new": read.get("new"),
                "read_ms": read.get("ms"),
                "settings_location": c.manifest.settings_location or "Settings › Connections",
            }
        )
    out.sort(key=lambda r: (not r["connected"], r["product"]))
    return out


def _available() -> bool:
    from app.integrations.connectors import sdk

    return bool(sdk.sources(SECURITY_EVENTS) or sdk.sources(SECURITY_INCIDENTS))


# --------------------------------------------------------------------------- dataset


def _vendor_incidents(hours: float) -> list[dict[str, Any]]:
    from app.integrations.connectors import sdk

    if not sdk.sources(SECURITY_INCIDENTS):
        return []
    rows, _errors = sdk.gather(SECURITY_INCIDENTS, "list_security_incidents", hours=max(1, int(hours)))
    return [r.to_dict() for r in rows]


def _dataset(window: str, site: str, sample: bool) -> dict[str, Any]:
    span = window_s(window)
    now = time.time()
    key = (window, site, sample, int(now // CACHE_S), 0 if sample else STORE.version)
    with _cache_lock:
        hit = _cache.get(key)
        if hit:
            return hit[1]
    if sample:
        raw = [e for e in demo.events(hours=168, now=now) if e["timestamp"] >= now - span]  # one week, sliced
        ctx: Any = demo.DemoContext()
        vendor = []
    else:
        COLLECTOR.touch()
        raw = STORE.window(now - span, now + 60)
        ctx = context.current()
        vendor = _vendor_incidents(span / 3600)
    events = engine.enrich(raw, ctx)
    sites = sorted({(e["site"]["key"], e["site"]["name"]) for e in events if e["site"]["key"]}, key=lambda x: x[1])
    if site:
        events = [e for e in events if e["site"]["key"] == site]
    data = {
        "now": now,
        "since": now - span,
        "events": events,
        "sites": [{"key": k, "name": n or k} for k, n in sites],
        "ctx_ready": bool(getattr(ctx, "ready", False)),
        "vendor": vendor,
    }
    with _cache_lock:
        _cache.clear()
        _cache[key] = (now, data)
    return data


def _cases(data: dict[str, Any], sample: bool) -> list[dict[str, Any]]:
    state = {} if sample else cases_state.load()
    return engine.build_cases(data["events"], state, data["vendor"])


def _event_row(e: dict[str, Any]) -> dict[str, Any]:
    t = e.get("target") or {}
    a = e.get("actor") or {}
    return {
        "key": e.get("key"),
        "t": e.get("timestamp"),
        "kind": e.get("kind"),
        "kind_label": SECURITY_EVENT_KIND_LABELS.get(e.get("kind") or "other", e.get("kind")),
        "severity": e.get("severity"),
        "outcome": e.get("outcome"),
        "direction": e.get("direction"),
        "reach": e.get("reach"),
        "name": e.get("name"),
        "cves": e.get("cves") or [],
        "src": e.get("src_ip"),
        "dst": e.get("dst_ip"),
        "dst_port": e.get("dst_port"),
        "host": e.get("dst_host"),
        "user": e.get("src_user"),
        "app": e.get("application"),
        "country": a.get("country") or "",
        "country_name": country_name(a.get("country")) if a.get("country") else "",
        "attacker": a.get("ip") if not a.get("inside") else "",
        "target": t.get("name") or t.get("ip") or "",
        "target_ip": t.get("ip") or "",
        "target_node": t.get("node_id") or "",
        "site": (e.get("site") or {}).get("name") or "",
        "sensor": e.get("sensor_name") or "",
        "sensor_node": e.get("sensor_node") or "",
        "rule": e.get("rule") or "",
        "source": e.get("source"),
        "count": e.get("count") or 1,
        "file": e.get("file_name") or "",
        "url": e.get("url") or "",
        # v0.10.32: everything the detection page shows
        "signature_id": e.get("signature_id") or "",
        "category": e.get("category") or "",
        "src_port": e.get("src_port"),
        "src_zone": e.get("src_zone") or "",
        "dst_zone": e.get("dst_zone") or "",
        "protocol": e.get("protocol") or "",
        "file_hash": e.get("file_hash") or "",
        "native_id": e.get("native_id") or "",
        "action": (e.get("vendor") or {}).get("action") or "",
        "sub_type": (e.get("vendor") or {}).get("sub_type") or "",
        "log": (e.get("vendor") or {}).get("log") or "",
        "site_key": (e.get("site") or {}).get("key") or "",
        "target_role": t.get("role") or "",
        "target_managed": bool(t.get("managed")),
        "dst_country": e.get("dst_country") or "",
        "src_country": e.get("src_country") or "",
        "through": engine.got_through(e),
    }


def _products(sample: bool) -> dict[str, str]:
    if sample:
        return {k: v[0] for k, v in demo.PRODUCTS.items()}
    from app.integrations.connectors import sdk

    return {c.provider_id: c.manifest.product for c in sdk.all_connectors()}


# --------------------------------------------------------------------------- endpoints


def soc(window: str = "24h", site: str = "", sample: bool = False) -> dict[str, Any]:
    cov = coverage() if not sample else [
        {"source": k, "product": v[0], "vendor": v[1], "capabilities": [{"id": SECURITY_EVENTS, "label": CAPABILITY_LABELS[SECURITY_EVENTS]}], "connected": True, "state": "connected", "state_label": "Sample data", "stored": 0}
        for k, v in demo.PRODUCTS.items()
    ]
    if not sample and not _available():
        return {"available": False, "sample": False, "coverage": cov, "window": window, "generated_at": time.time()}
    data = _dataset(window, site, sample)
    events = data["events"]
    ov = engine.overview(events, since=data["since"], until=data["now"])
    cases = _cases(data, sample)
    open_cases = [c for c in cases if c["state"] not in ("resolved", "dismissed")]
    feed = sorted(events, key=lambda e: -float(e.get("timestamp") or 0))[:60]
    stats = STORE.stats()
    first_read = (not sample) and not stats["events"] and not COLLECTOR.last_run
    return {
        "available": True,
        "sample": sample,
        "generated_at": data["now"],
        "window": window,
        "since": data["since"],
        "site": site,
        "sites": data["sites"],
        "first_read_pending": first_read,
        "collecting": COLLECTOR.running,
        "last_collect": COLLECTOR.last_run or None,
        "context_ready": data["ctx_ready"],
        "products": _products(sample),
        "coverage": cov,
        **ov,
        "countries": engine.countries(events),
        "callouts": engine.countries(events, outbound=True, limit=15),
        "destinations": engine.countries(events, destinations=True, limit=20),
        "targets": engine.top(events, "target", limit=12),
        "attackers": engine.top(events, "attacker", limit=12),
        "sensors": engine.top(events, "sensor", limit=10),
        "pressure": engine.top(events, "site", limit=12),
        "signatures": engine.top(events, "signature", limit=12),
        "cves": engine.cve_pressure(events, limit=12),
        "cases": {
            "open": len(open_cases),
            "new": sum(1 for c in open_cases if c["state"] == "new"),
            "critical": sum(1 for c in open_cases if c["severity"] == "critical"),
            "items": [engine.case_brief(c) for c in cases[:60]],
        },
        "feed": [_event_row(e) for e in feed],
        "reach_scale": [{"level": k, "label": v[0], "help": v[1]} for k, v in engine.REACH.items()],
        "world": WORLD,
    }


def case_detail(case_id: str, window: str = "7d", sample: bool = False) -> dict[str, Any] | None:
    data = _dataset(window, "", sample)
    for c in _cases(data, sample):
        if c["id"] == case_id:
            keys = set(c.get("event_keys") or [])
            evs = [e for e in data["events"] if e.get("key") in keys]
            evs.sort(key=lambda e: -float(e.get("timestamp") or 0))
            span = max(3600.0, float(c["last_seen"] or 0) - float(c["first_seen"] or 0))
            tl = engine.overview(evs, since=float(c["first_seen"] or 0) - span * 0.05, until=float(c["last_seen"] or 0) + span * 0.05, buckets=30)["timeline"]
            return {**{k: v for k, v in c.items() if k != "event_keys"}, "timeline": tl, "events_list": [_event_row(e) for e in evs[:300]], "products": _products(sample)}
    return None


def update_case(case_id: str, *, state: str | None, owner: str | None, note: str | None) -> dict[str, Any]:
    if not re.fullmatch(r"(NW|V)-[0-9A-F]{7}", case_id or ""):
        raise ValueError("Unknown case")
    return cases_state.update(case_id, state=state, owner=owner, note=note)


_FILTERS = ("kind", "outcome", "severity", "direction", "country", "site", "source")


def events(
    window: str = "24h",
    *,
    sample: bool = False,
    q: str = "",
    reach: int | None = None,
    through: bool = False,
    signature: str = "",
    key: str = "",
    cve: str = "",
    limit: int = 200,
    offset: int = 0,
    **filters: str,
) -> dict[str, Any]:
    data = _dataset(window, "", sample)
    rows = data["events"]
    for f in _FILTERS:
        v = str(filters.get(f) or "").strip()
        if not v:
            continue
        if f == "country":
            rows = [e for e in rows if (e.get("actor") or {}).get("country") == v.upper()]
        elif f == "site":
            rows = [e for e in rows if (e.get("site") or {}).get("key") == v]
        else:
            rows = [e for e in rows if str(e.get(f) or "") == v]
    if reach:
        rows = [e for e in rows if int(e.get("reach") or 0) == int(reach)]
    if through:
        rows = [e for e in rows if engine.got_through(e)]
    if signature:
        rows = [e for e in rows if (e.get("signature_id") or e.get("name") or "") == signature or e.get("name") == signature]
    if key:
        rows = [e for e in rows if e.get("key") == key]
    if cve:
        want = cve.strip().upper()
        rows = [e for e in rows if want in {str(x).upper() for x in (e.get("cves") or [])}]
    needle = str(q or "").strip().lower()
    if needle:
        def hay(e: dict[str, Any]) -> str:
            t = e.get("target") or {}
            return " ".join(
                str(x or "")
                for x in (e.get("name"), e.get("src_ip"), e.get("dst_ip"), e.get("dst_host"), e.get("src_user"), e.get("sensor_name"), t.get("name"), e.get("rule"), " ".join(e.get("cves") or []), e.get("signature_id"), e.get("application"))
            ).lower()

        rows = [e for e in rows if needle in hay(e)]
    rows = sorted(rows, key=lambda e: -float(e.get("timestamp") or 0))
    limit = max(1, min(int(limit or 200), 1000))
    offset = max(0, int(offset or 0))
    return {
        "total": len(rows),
        "offset": offset,
        "rows": [_event_row(e) for e in rows[offset : offset + limit]],
        "products": _products(sample),
    }


def vulnerabilities(window: str = "7d", sample: bool = False) -> dict[str, Any]:
    data = _dataset(window, "", sample)
    exposures, errors = ([], []) if sample else exposure.from_sources()
    return {
        "window": window,
        "sample": sample,
        "cves": engine.cve_pressure(data["events"], limit=60),
        "exposures": exposures,
        "exposure_errors": errors,
        "exposure_sources": [c for c in coverage() if any(x["id"] == SECURITY_EXPOSURES for x in c["capabilities"])] if not sample else [],
        "software": demo.software() if sample else exposure.software(data["events"]),
        "targets": engine.top(data["events"], "target", limit=25),
    }


def refresh() -> dict[str, Any]:
    COLLECTOR.kick()
    return {"ok": True, "requested_at": time.time()}


def diagnostics() -> dict[str, Any]:
    """For the support export: counts and source health only — never detection content."""
    stats = STORE.stats()
    return {
        "stored_detections": stats["events"],
        "by_source": stats["by_source"],
        "oldest_age_h": round((time.time() - stats["oldest"]) / 3600, 1) if stats.get("oldest") else None,
        "last_collect": COLLECTOR.last_run or None,
        "reads": {k: {x: v.get(x) for x in ("ok", "read", "new", "ms", "error", "truncated")} for k, v in dict(COLLECTOR.status).items()},
        "sources": [{k: c[k] for k in ("source", "product", "connected", "state")} for c in coverage()],
    }
