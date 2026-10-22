"""Organization map (v0.10.18): every site as one node, WAN / SD-WAN tunnels between sites as links.

The multi-level map (organization → site → device) starts here. Built through capabilities only:

    INVENTORY  list_sites()            → the sites (same-named sites of different sources are one)
    INVENTORY  list_devices(None)      → one organization-wide call per source: device counts per site
    TUNNELS    list_tunnels(None)      → overlay tunnels; both ends resolved to sites

Cost: one call per source and capability per build (cached 60 s), never one call per site, so a
50-site organization costs the same as a single site.

Hubs: a site whose tunnels reach at least three other sites (and at least a quarter of all tunnelled
sites) is drawn as a hub; everything else is a branch. Tunnel health uses the same loss / latency /
jitter thresholds as the live-health overlay.
"""

from __future__ import annotations

import logging
import threading
import time
from collections import defaultdict
from typing import Any

from app.integrations.contracts import INVENTORY, TUNNELS, WAN_CIRCUITS
from app.services import topology_sites as site_registry
from app.services.topology_health_service import _RANK, _worst, clean_thresholds, grade
from app.services.topology_service import (
    _ip,
    _Sources,
    graph_version,
    tunnel_jitter,
    norm_host,
    site_name_loose,
    site_name_norm,
)

log = logging.getLogger("nodewatch.topology")

ORG_CACHE_TTL_S = 120.0
CIRCUITS = WAN_CIRCUITS
HUB_MIN_PEERS = 3
MAX_DOWN_NAMES = 8
_UPSTREAM = {"sdwan_edge", "firewall", "router"}

_cache: dict[str, Any] = {}
_lock = threading.Lock()


def clear_cache() -> None:
    if _swr is not None:
        _swr.clear_memory()
    with _lock:
        _cache.clear()


def _site_index(rows: list[dict[str, Any]]) -> tuple[dict[str, str], dict[str, str]]:
    """(site key → row key, normalized/loose site name → row key)."""
    by_key: dict[str, str] = {}
    by_name: dict[str, str] = {}
    loose_count: dict[str, int] = defaultdict(int)
    for r in rows:
        for name in r.get("names") or [r["name"]]:
            loose_count[site_name_loose(name)] += 1
    for r in rows:
        for k in r.get("keys") or [r["key"]]:
            by_key[str(k)] = r["key"]
        for name in r.get("names") or [r["name"]]:
            by_name.setdefault(site_name_norm(name), r["key"])
            loose = site_name_loose(name)
            if loose and loose_count[loose] == 1:
                by_name.setdefault(loose, r["key"])
    return by_key, by_name


def _site_of(d: Any, by_key: dict[str, str], by_name: dict[str, str]) -> str:
    key = by_key.get(str(getattr(d, "site_key", "") or ""))
    if key:
        return key
    name = getattr(d, "site_name", "") or ""
    return by_name.get(site_name_norm(name)) or by_name.get(site_name_loose(name)) or ""


def _tunnel_state(states: list[str]) -> str:
    if not states:
        return "unknown"
    if all(s == "up" for s in states):
        return "up"
    if all(s == "down" for s in states):
        return "down"
    return "degraded" if "up" in states else "unknown"


def _max(values: list[Any]) -> float | None:
    nums = [float(v) for v in values if isinstance(v, (int, float))]
    return max(nums) if nums else None


def build_org(*, fresh: bool = False, thresholds: Any = None) -> dict[str, Any]:
    """GET /api/v1/topology/org: sites as nodes, inter-site tunnels as links (cached 60 s)."""
    now = time.time()
    with _lock:
        hit = _cache.get("org")
    if hit and not fresh and now - hit[0] < ORG_CACHE_TTL_S:
        raw = hit[1]
        cached = True
    else:
        raw = _collect(circuits_now=True)
        with _lock:
            _cache["org"] = (time.time(), raw)
        _index(raw)
        cached = False
    out = _evaluate(raw, clean_thresholds(thresholds))
    out["cached"] = cached
    out["age_s"] = round(time.time() - raw["generated_at"], 1)
    return out


# WAN circuits are read beside the organisation read, never inside it: the map, the search index and the
# prefix index never wait for them. The last complete list is used (and patched in when a read finishes).
_circuits_state: dict[str, Any] = {"rows": [], "at": 0.0}
_circuits_lock = threading.Lock()


def _read_circuits() -> list[dict[str, Any]]:
    from app.services.topology_service import circuit_dict, circuit_sources

    status = _Sources()
    rows: list[dict[str, Any]] = []
    for part in status.run(
        CIRCUITS, [(c, lambda c=c: c.list_circuits(None), ("list_circuits", None)) for c in circuit_sources()]
    ):
        rows += [x for x in map(circuit_dict, part) if x is not None]
    if status.status:
        log.info("topology: WAN circuits read — %d circuits; sources: %s", len(rows), status.timing_text())
    with _lock:
        _circuits_state.update(rows=rows, at=time.time())
    return rows


def _refresh_circuits_async() -> None:
    from app.services.topology_service import circuit_sources

    if not circuit_sources() or not _circuits_lock.acquire(blocking=False):
        return

    def run() -> None:
        try:
            rows = _read_circuits()
            with _lock:
                hit = _cache.get("org")
                if hit is not None:
                    hit[1]["circuits"] = rows
            if hit is not None and swr().put("", _evaluate(hit[1], clean_thresholds(None))):
                _index(hit[1])  # skipped when a newer organisation build is already stored
        except Exception as exc:  # noqa: BLE001 - circuits are a nicety on the organisation map
            log.info("topology: WAN circuits not read: %s", exc)
        finally:
            _circuits_lock.release()

    threading.Thread(target=run, name="topology-circuits", daemon=True).start()


def _collect(on_partial: Any = None, *, circuits_now: bool = False) -> dict[str, Any]:
    from concurrent.futures import ThreadPoolExecutor

    from app.integrations.connectors import sdk
    from app.services.topology_service import _list_sites_store as list_sites

    started = time.monotonic()
    status = _Sources()
    listed = list_sites()
    rows = listed["sites"]
    has_tunnels = bool(sdk.sources(TUNNELS))
    if on_partial is not None:  # the site tiles first; devices and tunnels follow
        on_partial(
            {"generated_at": time.time(), "build_ms": 0, "rows": rows, "devices": [], "tunnels": [],
             "sources": listed.get("sources", []), "has_tunnel_source": has_tunnels}
        )  # fmt: skip
    # Every source and capability is independent (and each can take seconds): read them in parallel.
    jobs = [(c, INVENTORY, "list_devices") for c in sdk.sources(INVENTORY)]
    jobs += [(c, TUNNELS, "list_tunnels") for c in sdk.sources(TUNNELS)]
    with ThreadPoolExecutor(max_workers=max(1, min(6, len(jobs)))) as pool:
        futures = [
            (cap, pool.submit(status.call, c, cap, lambda c=c, m=m: getattr(c, m)(None), (m, None)))
            for c, cap, m in jobs
        ]
        devices = [x for cap, f in futures if cap == INVENTORY for x in f.result()]
        tunnels = [x for cap, f in futures if cap == TUNNELS for x in f.result()]
    if circuits_now:
        circuits = _read_circuits()
    else:
        with _lock:
            circuits = list(_circuits_state["rows"])
        _refresh_circuits_async()
    build_ms = round((time.monotonic() - started) * 1000)
    log.info(
        "topology: organization read in %d ms — %d devices, %d tunnels; sources: %s",
        build_ms,
        len(devices),
        len(tunnels),
        status.timing_text(),
    )
    return {
        "generated_at": time.time(),
        "build_ms": build_ms,
        "rows": rows,
        "devices": devices,
        "tunnels": tunnels,
        "circuits": circuits,
        "sources": list({**{s["source"]: s for s in listed.get("sources", [])}, **status.status}.values()),
        "has_tunnel_source": has_tunnels,
        "degraded": status.degraded,
        "failed_sources": sorted(status.uncovered),
    }


def _index(raw: dict[str, Any]) -> None:
    try:
        from app.services import topology_search

        topology_search.rebuild(raw)
    except Exception as exc:  # noqa: BLE001 - search is a nicety; the map still answers
        log.info("topology: search index not rebuilt: %s", exc)


def raw_devices() -> dict[str, Any] | None:
    """The last organisation read (devices + tunnels) held in memory, or None."""
    with _lock:
        hit = _cache.get("org")
    return hit[1] if hit else None


# --------------------------------------------------------------------------- stale-while-revalidate (v0.10.21)

_swr = None


def _swr_build(_scope: str, on_partial: Any) -> dict[str, Any]:
    raw = _collect(lambda r: on_partial(_evaluate(r, clean_thresholds(None))))
    with _lock:
        prev = _cache.get("org")
        keep = raw.get("degraded") and prev is not None and not prev[1].get("degraded")
        if not keep:  # a degraded read never replaces complete readings
            if _circuits_state["at"] > raw["generated_at"] - raw["build_ms"] / 1000:
                raw["circuits"] = list(_circuits_state["rows"])  # finished while the rest was read
            _cache["org"] = (time.time(), raw)
    if not keep:
        _index(raw)
    return _evaluate(raw, clean_thresholds(None))


def swr():
    global _swr
    if _swr is None:
        from app.services.topology_cache import SwrCache

        _swr = SwrCache("org", ORG_CACHE_TTL_S, _swr_build)
    return _swr


def org_view(*, fresh: bool = False, thresholds: Any = None) -> dict[str, Any]:
    """GET /api/v1/topology/org: instant answer from the last build (``stale`` when old), rebuilt in the
    background. Custom thresholds (and a changed site mapping) are applied to the in-memory readings
    when they are current."""
    th = clean_thresholds(thresholds)
    out = swr().get("", fresh=fresh)
    with _lock:
        hit = _cache.get("org")
    current = _registry_version()
    reg_changed = bool(out.get("registry_version")) and bool(current) and out.get("registry_version") != current
    if hit and (th != clean_thresholds(None) or reg_changed) and not out.get("partial"):
        evaluated = _evaluate(hit[1], th)
        meta = {k: out[k] for k in ("built_at", "age_s", "stale", "refreshing", "partial", "refresh_error") if k in out}
        return {**evaluated, **meta}
    return out


_FIREWALL_CATEGORIES = ("firewall", "logging", "security")


def firewall_hint(devices: list[Any], place: dict[str, tuple[str, str]]) -> dict[str, Any] | None:
    """Why firewalls may be missing, in plain words (None when no firewall-related source is connected).

    Vendor-neutral: counts firewall records listed by a management system vs found only in traffic logs
    (``Device.labels`` "seen in logs"), and whether a connected source reads firewall ports / neighbours."""
    from app.integrations.connectors import sdk
    from app.integrations.contracts import INTERFACES, NEIGHBORS
    from app.services.topology_search import firewall_evidence

    listers = [c for c in sdk.sources(INVENTORY) if c.manifest.category in _FIREWALL_CATEGORIES]
    fw = firewall_evidence(devices, place) if place else firewall_evidence(devices, {})
    if not listers and not fw["total"]:
        return None
    readers = [
        c
        for c in sdk.sources(INVENTORY)
        if c.manifest.category == "firewall"
        and (NEIGHBORS in c.manifest.capabilities or INTERFACES in c.manifest.capabilities)
    ]
    names = ", ".join(sorted({c.manifest.product or c.provider_id for c in listers})) or "No connected system"
    if fw["listed"]:
        text = f"{fw['listed']} firewall{'s are' if fw['listed'] != 1 else ' is'} listed by {names}."
    else:
        text = f"{names} list{'s' if len(listers) <= 1 else ''} no firewalls."
    if fw["logs_only"]:
        text += (
            f" {fw['logs_only']} firewall{'s were' if fw['logs_only'] != 1 else ' was'} found in their traffic logs;"
        )
        text += f" {fw['placed']} of {fw['total']} are on the map."
    elif fw["total"]:
        text += f" {fw['placed']} of {fw['total']} are on the map."
    # HA: a passive unit passes no traffic, so a firewall known only from traffic logs shows one unit per
    # pair until another source (system logs, a firewall manager) names the partner. Say so plainly.
    fws = [d for d in devices if getattr(d, "role", "") == "firewall" and not getattr(d, "cloud_kind", "")]
    with_partner = [
        d for d in fws if str(getattr(d, "ha_state", "") or "") not in ("", "standalone") or getattr(d, "members", None)
    ]
    if fw["logs_only"] and not with_partner and not readers:
        text += (
            " Firewalls in HA pairs show only the unit passing traffic: the passive unit writes no traffic logs,"
            " and no connected source names it yet."
        )
    if not readers:
        offer = sorted(
            {
                c.manifest.product
                for c in sdk.sources(INVENTORY, include_disabled=True)
                if c.manifest.category == "firewall" and NEIGHBORS in c.manifest.capabilities and c.manifest.product
            }
        )
        what = " or ".join(offer) if offer else "your firewall manager"
        text += f" Connect {what} (Settings › Connections) to see both units of each pair, their ports, routes and neighbours."
    if fw["unplaced"]:
        text += " Assign the rest under Topology › Site mapping."
    return {
        "scm_listed": fw["listed"],
        "listed": fw["listed"],
        "seen_in_logs": fw["seen_in_logs"],
        "logs_only": fw["logs_only"],
        "placed": fw["placed"],
        "total": fw["total"],
        "unplaced": fw["unplaced"],
        "panorama_connected": bool(readers),
        "manager_connected": bool(readers),
        "listed_by": sorted({c.manifest.product or c.provider_id for c in listers}),
        "ha_partners_known": len(with_partner),
        "text": text,
    }


def _registry_version() -> str:
    """Version of the registry already in memory — never lists sites (first paint stays instant)."""
    return site_registry.cached_version() or ""


def _cloud_reach(
    devices: list[Any], place: dict[str, tuple[str, str]], sites: dict[str, dict[str, Any]], reg: Any
) -> tuple[list[dict[str, Any]], dict[str, set[str]]]:
    """Cloud gateway → the sites its traffic reaches (``lan_prefixes`` / observed peer addresses in a site's
    prefix index): one org link per (cloud site, site), evidence "traffic-logs". Vendor-neutral."""
    import ipaddress

    if reg is None:
        return [], {}
    pairs: dict[tuple[str, str], dict[str, Any]] = {}
    for d in devices:
        if getattr(d, "role", "") != "cloud_gateway":
            continue
        ck = place.get(f"{d.source}:{d.key}", ("", ""))[0]
        if ck not in sites:
            continue
        probes = []
        for p in getattr(d, "lan_prefixes", None) or []:
            try:
                net = ipaddress.ip_network(str(p), strict=False)
            except ValueError:
                continue
            probes.append(str(net.network_address + 1 if net.num_addresses > 2 else net.network_address))
        probes += [str(p.get("ip") or "") for p in getattr(d, "observed_peers", None) or [] if isinstance(p, dict)]
        for ip in probes:
            target = reg.from_subnet(ip) if ip else ""
            if not target or target == ck or target not in sites:
                continue
            row = pairs.setdefault((ck, target), {"via": set(), "networks": set()})
            row["via"].add(d.name)
            if ":" not in ip:
                row["networks"].add(str(ipaddress.ip_network(f"{ip}/24", strict=False)))
    links = []
    reach: dict[str, set[str]] = defaultdict(set)
    for (ck, target), row in sorted(pairs.items()):
        reach[ck].add(target)
        links.append(
            {
                "id": f"cloud:{ck}|{target}",
                "a": ck,
                "b": target,
                "kind": "cloud",
                "evidence": "traffic-logs",
                "via": sorted(row["via"])[:12],
                "networks": sorted(row["networks"])[:12],
                "tunnels": 0,
                "up": 0,
                "down": 0,
                "state": "unknown",
                "health": "unknown",
                "badge": "",
                "reasons": [],
                "latency_ms": None,
                "loss_pct": None,
                "jitter_ms": None,
                "kinds": ["cloud"],
                "sources": [],
                "members": [],
                "member_total": 0,
            }
        )
    return links, reach


def _evaluate(raw: dict[str, Any], th: dict[str, dict[str, float]]) -> dict[str, Any]:
    rows = raw["rows"]
    by_key, by_name = _site_index(rows)
    try:
        reg = site_registry.registry()
    except Exception as exc:  # noqa: BLE001 - fall back to the site keys and names the rows carry
        log.info("topology: site registry unavailable: %s", exc)
        reg = None
    sites: dict[str, dict[str, Any]] = {}
    for r in rows:
        sites[r["key"]] = {
            "key": r["key"],
            "name": r["name"],
            "keys": list(r.get("keys") or [r["key"]]),
            "names": list(r.get("names") or [r["name"]]),
            "sources": list(r.get("sources") or []),
            "devices": 0,
            "by_role": defaultdict(int),
            "role_sources": defaultdict(set),  # v0.10.37: which connected system reports each layer here
            "down": 0,
            "degraded": 0,
            "down_names": [],
            "upstream_down": 0,
            "edges": [],
            "hub": False,
            "peers": 0,
            "tunnels": 0,
            "external_tunnels": 0,
            "circuits_total": 0,
            "circuits_down": 0,
            "firewalls": 0,
            # v0.10.27: "cloud" = a cloud service's own site (drawn as the cloud tier, never a hub/branch)
            "kind": r.get("kind") or "site",
            "cloud": (r.get("kind") or "") == "cloud",
            "cloud_gateways": 0,
            "cloud_kinds": defaultdict(int),
        }
    dev_site: dict[str, str] = {}
    by_ip: dict[str, str] = {}
    by_host: dict[str, list[str]] = defaultdict(list)
    unassigned = 0
    place: dict[str, tuple[str, str]] = {}
    if reg is not None:
        from app.services.topology_service import propagate_name_partners, propagate_peers

        place = {f"{d.source}:{d.key}": reg.place(d) for d in raw["devices"]}
        propagate_peers(raw["devices"], place)
        propagate_name_partners(raw["devices"], place)
    for d in raw["devices"]:
        sk = place.get(f"{d.source}:{d.key}", ("", ""))[0]
        sk = by_key.get(sk, sk) if sk else _site_of(d, by_key, by_name)
        if not sk or sk not in sites:
            unassigned += 1
            continue
        s = sites[sk]
        dev_site[f"{d.source}:{d.key}"] = sk
        dev_site.setdefault(d.key, sk)
        if _ip(d.mgmt_ip):
            by_ip.setdefault(_ip(d.mgmt_ip), sk)
        h = norm_host(d.name)
        if h and sk not in by_host[h]:
            by_host[h].append(sk)
        s["devices"] += 1
        s["by_role"][d.role or "unknown"] += 1
        s["role_sources"][d.role or "unknown"].add(d.source)
        if d.role == "cloud_gateway":
            s["cloud_gateways"] += 1
            s["cloud_kinds"][getattr(d, "cloud_kind", "") or "other"] += 1
        if d.role in _UPSTREAM and len(s["edges"]) < 6:
            s["edges"].append({"name": d.name, "role": d.role, "status": d.status, "model": d.model})
        if d.status == "down":
            s["down"] += 1
            if d.role in _UPSTREAM:
                s["upstream_down"] += 1
            if len(s["down_names"]) < MAX_DOWN_NAMES:
                s["down_names"].append({"name": d.name, "role": d.role})
        elif d.status == "degraded":
            s["degraded"] += 1
    from app.services.topology_overview import merge_circuits

    def _circuit_site(c: dict[str, Any]) -> str:
        return dev_site.get(f"{c.get('source')}:{c.get('device_key')}") or dev_site.get(str(c.get("device_key") or "")) or ""

    # v0.10.32: one line shared by an HA pair (or reported by two sources) counts once per site.
    for c in merge_circuits([dict(x) for x in raw.get("circuits") or []], _circuit_site):
        sk = _circuit_site(c)
        if sk in sites:
            sites[sk]["circuits_total"] += 1
            if c.get("source"):
                sites[sk]["role_sources"]["circuit"].add(str(c["source"]))
            sites[sk]["circuits_down"] += c.get("state") == "down"
    for s_ in sites.values():
        s_["firewalls"] = int(s_["by_role"].get("firewall", 0))
    # Tunnel endpoints: a tunnel's local IP identifies the far end of the tunnel coming back.
    for t in raw["tunnels"]:
        sk = dev_site.get(f"{t.source}:{t.device_key}") or dev_site.get(t.device_key)
        if sk and _ip(t.local_ip):
            by_ip.setdefault(_ip(t.local_ip), sk)

    pairs: dict[tuple[str, str], dict[str, Any]] = {}
    for t in raw["tunnels"]:
        a = dev_site.get(f"{t.source}:{t.device_key}") or dev_site.get(t.device_key)
        if not a:
            continue
        b = ""
        if t.remote_device_key:
            b = dev_site.get(f"{t.source}:{t.remote_device_key}") or dev_site.get(t.remote_device_key) or ""
        if not b and _ip(t.remote_ip):
            b = by_ip.get(_ip(t.remote_ip), "")
        if not b and norm_host(t.remote_name) and len(by_host.get(norm_host(t.remote_name), [])) == 1:
            b = by_host[norm_host(t.remote_name)][0]
        sites[a]["tunnels"] += 1
        if not b:
            sites[a]["external_tunnels"] += 1
            continue
        if b == a:
            continue
        lo, hi = sorted((a, b))
        p = pairs.setdefault(
            (lo, hi),
            {"a": lo, "b": hi, "from_a": [], "from_b": [], "kinds": set(), "sources": set()},
        )
        rec = {
            "name": t.name,
            "kind": t.kind,
            "state": t.state or "unknown",
            "latency_ms": t.latency_ms,
            "loss_pct": t.loss_pct,
            "jitter_ms": tunnel_jitter(t),
            "from": sites[a]["name"],
            "source": t.source,
        }
        (p["from_a"] if a == lo else p["from_b"]).append(rec)
        p["kinds"].add(t.kind or "other")
        p["sources"].add(t.source)

    peers: dict[str, set[str]] = defaultdict(set)
    links = []
    for (lo, hi), p in sorted(pairs.items()):
        members = p["from_a"] + p["from_b"]
        count = max(len(p["from_a"]), len(p["from_b"]))
        peers[lo].add(hi)
        peers[hi].add(lo)
        states = [m["state"] for m in members]
        latency = _max([m["latency_ms"] for m in members])
        loss = _max([m["loss_pct"] for m in members])
        jitter = _max([m["jitter_ms"] for m in members])
        reasons = []
        st_state = _tunnel_state(states)
        grades = []
        if st_state == "down":
            grades.append("critical")
            reasons.append({"metric": "state", "state": "critical", "text": "All tunnels down"})
        elif st_state == "degraded":
            down = sum(1 for s in states if s == "down")
            grades.append("warning")
            reasons.append({"metric": "state", "state": "warning", "text": f"{down} of {len(states)} tunnels down"})
        for metric, value, unit, word in (
            ("loss_pct", loss, "%", "loss"),
            ("latency_ms", latency, " ms", "latency"),
            ("jitter_ms", jitter, " ms", "jitter"),
        ):
            g = grade(metric, value, th)
            if g != "unknown":
                grades.append(g)
            if g in ("warning", "critical"):
                reasons.append({"metric": metric, "state": g, "text": f"{word} {value:g}{unit}"})
        state = _worst(grades) if grades else ("good" if st_state == "up" else "unknown")
        badge = reasons[0]["text"] if reasons else ""
        links.append(
            {
                "id": f"site:{lo}|{hi}",
                "a": lo,
                "b": hi,
                "tunnels": count,
                "up": sum(1 for s in states if s == "up"),
                "down": sum(1 for s in states if s == "down"),
                "state": st_state,
                "health": state,
                "badge": badge,
                "reasons": reasons,
                "latency_ms": latency,
                "loss_pct": loss,
                "jitter_ms": jitter,
                "kinds": sorted(p["kinds"]),
                "sources": sorted(p["sources"]),
                "members": members[:24],
                "member_total": len(members),
            }
        )
    tunnelled = [k for k in sites if peers.get(k)]
    need = max(HUB_MIN_PEERS, (len(tunnelled) + 3) // 4)
    for k, s in sites.items():
        s["peers"] = len(peers.get(k, ()))
        s["hub"] = s["peers"] >= need and not s["cloud"]
    cloud_links, reach = _cloud_reach(raw["devices"], place, sites, reg)
    links += cloud_links
    out_sites = []
    worst_link: dict[str, str] = {}
    for link in links:
        for end in (link["a"], link["b"]):
            worst_link[end] = _worst([worst_link.get(end, "unknown"), link["health"]])
    for s in sites.values():
        reasons = []
        dev_state = "good" if s["devices"] else "unknown"
        if s["upstream_down"]:
            dev_state = "critical"
            reasons.append(
                {
                    "state": "critical",
                    "text": f"{s['upstream_down']} WAN / security device{'s' if s['upstream_down'] > 1 else ''} down",
                }
            )
        if s["down"] - s["upstream_down"] > 0:
            other = s["down"] - s["upstream_down"]
            share = other / max(1, s["devices"])
            st = "critical" if share >= 0.25 and other >= 3 else "warning"
            dev_state = _worst([dev_state, st])
            reasons.append({"state": st, "text": f"{other} device{'s' if other > 1 else ''} down"})
        if s["degraded"]:
            dev_state = _worst([dev_state, "warning"])
            reasons.append({"state": "warning", "text": f"{s['degraded']} degraded"})
        wl = worst_link.get(s["key"], "unknown")
        mine = [link for link in links if s["key"] in (link["a"], link["b"])]
        bad = [link for link in mine if link["health"] in ("warning", "critical")]
        if s["hub"] and bad and len(bad) * 4 < len(mine):
            # A few branches with bad tunnels say little about the hub itself.
            reasons.append({"state": "good", "text": f"{len(bad)} of {len(mine)} peer sites with tunnel issues"})
            wl = "good"
        elif wl in ("warning", "critical"):
            reasons.append({"state": "warning", "text": "WAN tunnel above thresholds"})
            wl = "warning"  # a bad tunnel degrades a site; it does not make it critical on its own
        health = _worst([dev_state, wl]) if s["devices"] or wl != "unknown" else "unknown"
        # Short text for the map badge: the most urgent fact first.
        worst_tunnel = max(
            (link for link in bad if wl == "warning"),
            key=lambda link: _RANK.get(link["health"], 0),
            default=None,
        )
        if s["upstream_down"]:
            badge = "edge down"
        elif s["down"]:
            badge = f"{s['down']} down"
        elif worst_tunnel is not None:
            badge = worst_tunnel["badge"] or "WAN"
        elif s["degraded"]:
            badge = f"{s['degraded']} degraded"
        else:
            badge = ""
        out_sites.append(
            {
                **{k: v for k, v in s.items() if k not in ("by_role", "cloud_kinds", "role_sources")},
                "by_role": dict(s["by_role"]),
                "role_sources": {r: sorted(v) for r, v in s["role_sources"].items()},
                "cloud_kinds": dict(s["cloud_kinds"]),
                "reaches": sorted(reach.get(s["key"], ())),
                "health": health,
                "reasons": reasons,
                "badge": badge if health in ("warning", "critical") else "",
                "status": "down"
                if s["upstream_down"]
                else ("degraded" if s["down"] or s["degraded"] else ("up" if s["devices"] else "unknown")),
            }
        )
    out_sites.sort(key=lambda r: (not r["cloud"], not r["hub"], str(r["name"]).lower()))
    gaps = []
    if not raw["has_tunnel_source"]:
        gaps.append(
            "No SD-WAN or VPN source is connected, so tunnels between sites are not drawn — each site is shown with its device health only."
        )
    if unassigned:
        gaps.append(
            f"{unassigned} device(s) are not assigned to any site — assign them (or map their source's sites) "
            "under Topology › Site mapping."
        )
    ext = sum(s["external_tunnels"] for s in sites.values())
    if ext:
        gaps.append(f"{ext} tunnel(s) end at peers outside the listed sites (cloud or partner gateways).")
    for row in raw["sources"]:
        if not row.get("ok", True):
            gaps.append(f"{row.get('product') or row.get('source')} could not be read: {row.get('error')}")
    summary = defaultdict(int)
    for s in out_sites:
        summary[s["health"]] += 1
    version_nodes = [{"id": s["key"], "status": s["status"], "name": s["name"], "tier": s["health"]} for s in out_sites]
    version_links = [{"key": link["id"], "state": f"{link['state']}|{link['health']}"} for link in links]
    return {
        "generated_at": raw["generated_at"],
        "build_ms": raw["build_ms"],
        "degraded": bool(raw.get("degraded")),
        "failed_sources": list(raw.get("failed_sources") or []),
        "unassigned": unassigned,
        "firewall_hint": firewall_hint(raw["devices"], place),
        "registry_version": reg.version if reg is not None else "",
        "version": graph_version(version_nodes, version_links),
        "sites": out_sites,
        "links": links,
        # v0.10.27: cloud services (kind "cloud") — one entry per provider site, with the sites they reach
        "cloud": [
            {
                "key": s["key"],
                "name": s["name"],
                "gateways": s["cloud_gateways"],
                "by_kind": s["cloud_kinds"],
                "reaches": s["reaches"],
                "status": s["status"],
            }
            for s in out_sites
            if s["cloud"]
        ],
        "sources": raw["sources"],
        "gaps": gaps,
        "summary": dict(summary),
        "stats": {
            "sites": len(out_sites),
            "hubs": sum(1 for s in out_sites if s["hub"]),
            "links": len(links),
            "tunnels": sum(link["tunnels"] for link in links),
            "devices": sum(s["devices"] for s in out_sites),
        },
    }
