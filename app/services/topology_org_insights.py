"""Organisation insights (v0.10.37): what the whole-organisation views say, vendor-neutral.

Everything here is derived from the evaluated organisation map (sites with their device roles, links between
sites with their kinds, cloud services) — never from a product name — so a new connector of any vendor feeds it
without changes:

* ``site_types``: hub / large / branch / small / standalone / cloud on-ramp (suggested) / empty / staging, each
  with the reason, plus the user's own choice when they set one (``state/topology/site-types.json``);
* ``overlays``: one entry per kind of site-to-site tunnel network (SD-WAN, VPN, MPLS, …) with its detected shape,
  and one per cloud service sites tunnel to;
* ``coverage``: for every layer of the network, how many sites have it and which connected systems report it;
* ``attention``: what needs a decision, ranked;
* ``sentence`` and ``kpis`` for the Overview.
"""

from __future__ import annotations

import json
import logging
import threading
from typing import Any

from app.core.config import DATA_ROOT
from app.core.file_utils import write_private_text

log = logging.getLogger("nodewatch.topology.insights")

TYPES = ("hub", "large", "branch", "small", "standalone", "onramp", "empty", "staging", "cloud")
TYPE_LABEL = {
    "hub": "Hubs and data centers",
    "large": "Large sites",
    "branch": "Branches",
    "small": "Small sites",
    "standalone": "Standalone",
    "onramp": "Cloud on-ramps",
    "empty": "Empty",
    "staging": "Staging / retired",
    "cloud": "Cloud services",
}
OVERLAY_LABEL = {
    "sdwan": "SD-WAN overlay",
    "vpn": "VPN overlay",
    "ipsec": "IPsec VPN overlay",
    "mpls": "MPLS network",
    "gre": "GRE tunnels",
    "evpn": "EVPN fabric",
    "tunnel": "Tunnels",
}
LAN_ROLES = ("switch", "wireless_ap", "firewall", "wireless_controller", "server", "load_balancer")
EDGE_ROLES = ("sdwan_edge", "router")
_TYPES_FILE = DATA_ROOT / "state" / "topology" / "site-types.json"
_lock = threading.Lock()


# --------------------------------------------------------------------------- user choices
def user_types() -> dict[str, str]:
    try:
        raw = json.loads(_TYPES_FILE.read_text(encoding="utf-8"))
        return {str(k): str(v) for k, v in raw.items() if str(v) in TYPES} if isinstance(raw, dict) else {}
    except (OSError, ValueError):
        return {}


def set_user_type(site_key: str, site_type: str) -> dict[str, str]:
    site_key = str(site_key or "")[:200]
    if not site_key:
        raise ValueError("site is required")
    if site_type and site_type not in TYPES:
        raise ValueError("unknown site type")
    with _lock:
        cur = user_types()
        if site_type:
            cur[site_key] = site_type
        else:
            cur.pop(site_key, None)
        _TYPES_FILE.parent.mkdir(parents=True, exist_ok=True)
        write_private_text(_TYPES_FILE, json.dumps(cur, indent=1))  # atomic, owner-only (v0.10.40)
    return cur


# --------------------------------------------------------------------------- helpers
def _lan(s: dict[str, Any]) -> int:
    r = s.get("by_role") or {}
    return sum(int(r.get(x, 0)) for x in LAN_ROLES)


def _edges(s: dict[str, Any]) -> int:
    r = s.get("by_role") or {}
    return sum(int(r.get(x, 0)) for x in EDGE_ROLES)


def _overlay_kind(link: dict[str, Any]) -> str:
    kinds = [str(k).lower() for k in link.get("kinds") or [] if k]
    kinds = [k for k in kinds if k != "cloud"]
    return kinds[0] if kinds else ("" if "cloud" in [str(k).lower() for k in link.get("kinds") or []] else "tunnel")


def _shape(keys: set[str], pairs: set[tuple[str, str]], circuits: dict[str, int]) -> dict[str, Any]:
    n = len(keys)
    possible = n * (n - 1) // 2
    density = len(pairs) / possible if possible else 0.0
    deg = {k: 0 for k in keys}
    for a, b in pairs:
        deg[a] = deg.get(a, 0) + 1
        deg[b] = deg.get(b, 0) + 1
    hubs = sorted((k for k in keys if n > 2 and deg[k] >= 0.8 * (n - 1)), key=lambda k: -deg[k])
    if n < 2:
        shape = "single"
    elif density >= 0.9:
        shape = "full_mesh"
    elif hubs and all(deg[k] <= len(hubs) + 1 for k in keys if k not in hubs):
        shape = "hub_and_spoke"
    else:
        shape = "partial_mesh"
    if shape == "full_mesh":
        # In a mesh every site is a "hub" by degree: the main sites are the ones with the most circuits
        # and (when known) few LAN devices — data centers and aggregation points.
        main = sorted(keys, key=lambda k: -circuits.get(k, 0))[:3]
        main = [k for k in main if circuits.get(k, 0) >= max(4, 0.6 * max(circuits.values() or [0]))]
    else:
        main = hubs[:6]
    return {
        "shape": shape,
        "label": {"full_mesh": "full mesh", "hub_and_spoke": "hub and spoke", "partial_mesh": "partial mesh", "single": "single site"}[shape],
        "pairs": len(pairs),
        "possible": possible,
        "density": round(density, 3),
        "hubs": main,
    }


def _labels(org: dict[str, Any]) -> dict[str, str]:
    out = {}
    for s in org.get("sources") or []:
        sid = s.get("source") or ""
        if sid:
            out[sid] = s.get("product") or sid.replace("_", " ")
    return out


# --------------------------------------------------------------------------- insights
def insights(org: dict[str, Any]) -> dict[str, Any]:
    sites = [s for s in org.get("sites") or [] if s.get("key")]
    names = {s["key"]: s.get("name") or s["key"] for s in sites}
    labels = _labels(org)
    real = [s for s in sites if not s.get("cloud")]
    circuits = {s["key"]: int(s.get("circuits_total") or 0) for s in real}

    # overlays (site-to-site), grouped by kind
    groups: dict[str, dict[str, Any]] = {}
    for l in org.get("links") or []:
        a, b = l.get("a"), l.get("b")
        if a not in names or b not in names or a == b:
            continue
        kind = _overlay_kind(l)
        if not kind:
            continue
        if any((s.get("cloud") and s["key"] in (a, b)) for s in sites):
            continue
        g = groups.setdefault(kind, {"keys": set(), "pairs": set(), "degraded": [], "down": [], "tunnels": 0, "sources": set()})
        g["keys"].update((a, b))
        g["pairs"].add(tuple(sorted((a, b))))
        g["tunnels"] += int(l.get("tunnels") or 0)
        g["sources"].update(l.get("sources") or [])
        st = l.get("state")
        if st == "degraded":
            g["degraded"].append({"a": a, "b": b, "text": "; ".join(r.get("text", "") for r in l.get("reasons") or [] if isinstance(r, dict))})
        elif st == "down":
            g["down"].append({"a": a, "b": b})
    overlays = []
    hub_keys: set[str] = set()
    for kind, g in sorted(groups.items(), key=lambda kv: -len(kv[1]["keys"])):
        sh = _shape(g["keys"], g["pairs"], circuits)
        hub_keys.update(sh["hubs"])
        overlays.append(
            {
                "id": kind,
                "kind": "site_to_site",
                "label": OVERLAY_LABEL.get(kind, f"{kind.upper()} overlay"),
                "shape": sh["shape"],
                "shape_label": sh["label"],
                "sites": sorted(g["keys"]),
                "pairs": sh["pairs"],
                "possible": sh["possible"],
                "hubs": sh["hubs"],
                "degraded": g["degraded"],
                "down": g["down"],
                "tunnels": g["tunnels"],
                "sources": sorted(labels.get(x, x) for x in g["sources"]),
            }
        )
    for c in org.get("cloud") or []:
        kinds = c.get("by_kind") or {}
        security = any(k in kinds for k in ("mobile_users", "remote_network", "service_connection"))
        overlays.append(
            {
                "id": f"cloud:{c.get('key')}",
                "kind": "cloud_service",
                "label": "Cloud security service" if security else "Cloud service",
                "name": c.get("name") or "",
                "sites": list(c.get("reaches") or []),
                "gateways": c.get("gateways") or 0,
                "status": c.get("status") or "unknown",
                "sources": sorted({labels.get(x, x) for s in sites if s["key"] == c.get("key") for x in (s.get("sources") or [])}),
            }
        )
    on_overlay = {k for o in overlays if o["kind"] == "site_to_site" for k in o["sites"]}

    # site types
    chosen = user_types()
    types: dict[str, dict[str, Any]] = {}
    for s in sites:
        k = s["key"]
        dev, down = int(s.get("devices") or 0), int(s.get("down") or 0)
        if s.get("cloud"):
            t, why = "cloud", "a cloud service's own gateways"
        elif not dev:
            t, why = "empty", "no device is assigned to it"
        elif dev >= 20 and down == dev:
            t, why = "staging", f"all {dev} devices offline"
        elif k in hub_keys:
            t, why = "hub", "a main site of the overlay (most circuits, reached by every site)"
        elif k in on_overlay and not _lan(s) and _edges(s) <= 1:
            t, why = "onramp", "one WAN edge and no LAN devices: looks like a cloud on-ramp"
        elif k not in on_overlay:
            t, why = "standalone", "not on any site-to-site overlay"
        elif dev >= 50:
            t, why = "large", f"{dev} devices"
        elif dev >= 10:
            t, why = "branch", f"{dev} devices"
        else:
            t, why = "small", f"{dev} devices"
        detected = t
        if chosen.get(k):
            t, why = chosen[k], "set by you"
        types[k] = {"type": t, "detected": detected, "why": why, "user": bool(chosen.get(k)), "suggested": detected == "onramp" and not chosen.get(k)}

    # coverage by layer
    def cov(roles: tuple[str, ...]) -> dict[str, Any]:
        keys, srcs = set(), set()
        for s in real:
            r = s.get("by_role") or {}
            rs = s.get("role_sources") or {}
            if any(int(r.get(x, 0)) for x in roles) or any(rs.get(x) for x in roles):
                keys.add(s["key"])
                for x in roles:
                    srcs.update(rs.get(x) or [])
        return {"sites": len(keys), "sources": sorted(labels.get(x, x) for x in srcs)}

    circ_sites = [s for s in real if s.get("circuits_total")]
    circ_src = sorted({labels.get(x, x) for s in real for x in (s.get("role_sources") or {}).get("circuit", [])})
    coverage = [
        {"layer": "Internet circuits", "sites": len(circ_sites), "sources": circ_src},
        {"layer": "WAN edges / routers", **cov(EDGE_ROLES)},
        {"layer": "Site-to-site overlay", "sites": len(on_overlay), "sources": sorted({x for o in overlays if o["kind"] == "site_to_site" for x in o["sources"]})},
        {"layer": "Firewalls", **cov(("firewall",))},
        {"layer": "Cloud security", "sites": len({k for o in overlays if o["kind"] == "cloud_service" for k in o["sites"]}), "sources": sorted({x for o in overlays if o["kind"] == "cloud_service" for x in o["sources"]})},
        {"layer": "Switching", **cov(("switch",))},
        {"layer": "Wi-Fi", **cov(("wireless_ap", "wireless_controller"))},
    ]

    # attention
    att: list[dict[str, Any]] = []
    for s in real:
        k, dev, down = s["key"], int(s.get("devices") or 0), int(s.get("down") or 0)
        t = types[k]["type"]
        if t in ("staging", "empty"):
            continue
        if dev and down == dev:
            att.append({"level": "now", "title": f"{s['name']} is dark", "detail": f"all {dev} device(s) offline", "site": k, "action": "site"})
        elif s.get("upstream_down"):
            att.append({"level": "now", "title": f"{s['name']}: WAN edge or firewall offline", "detail": f"{down} device(s) down", "site": k, "action": "site"})
    for o in overlays:
        if o["kind"] != "site_to_site":
            continue
        for p in o["down"]:
            att.append({"level": "now", "title": f"{o['label']}: {names[p['a']]} ⇄ {names[p['b']]} down", "detail": "every tunnel between the two is down", "site": p["a"], "action": "wiring"})
        if o["degraded"]:
            att.append({"level": "today", "title": f"{len(o['degraded'])} {o['label']} pair(s) degraded",
                        "detail": "; ".join(f"{names[p['a']]} ⇄ {names[p['b']]}" + (f" ({p['text']})" if p["text"] else "") for p in o["degraded"][:3]),
                        "site": o["degraded"][0]["a"], "action": "wiring"})  # fmt: skip
    for s in real:
        if s.get("circuits_down"):
            att.append({"level": "today", "title": f"{s['name']}: {s['circuits_down']} of {s['circuits_total']} circuits down", "detail": "traffic runs on the others" if s["circuits_total"] > s["circuits_down"] else "no circuit left", "site": s["key"], "action": "site"})
    single = [s for s in real if s["key"] in on_overlay and int(s.get("circuits_total") or 0) == 1]
    if single:
        att.append({"level": "plan", "title": f"{len(single)} site(s) on one internet circuit", "detail": ", ".join(s["name"] for s in single[:6]), "site": single[0]["key"], "action": "site"})
    tidy = [s for s in real if types[s["key"]]["type"] in ("staging", "empty")]
    if tidy:
        att.append({"level": "tidy", "title": f"{len(tidy)} empty or staging site(s)", "detail": ", ".join(s["name"] for s in tidy[:6]) + " — they inflate offline counts", "site": tidy[0]["key"], "action": "site"})
    rank = {"now": 0, "today": 1, "plan": 2, "tidy": 3}
    att.sort(key=lambda x: rank[x["level"]])

    # KPIs + sentence
    devices = sum(int(s.get("devices") or 0) for s in real)
    down = sum(int(s.get("down") or 0) for s in real)
    staging_down = sum(int(s.get("down") or 0) for s in real if types[s["key"]]["type"] == "staging")
    circ = sum(int(s.get("circuits_total") or 0) for s in real)
    circ_down = sum(int(s.get("circuits_down") or 0) for s in real)
    s2s = [o for o in overlays if o["kind"] == "site_to_site"]
    pairs = sum(o["pairs"] for o in s2s)
    bad_pairs = sum(len(o["degraded"]) + len(o["down"]) for o in s2s)
    fw_pairs = sum(int((s.get("by_role") or {}).get("firewall", 0)) // 2 for s in real)
    dark = [a for a in att if a["level"] == "now" and a["title"].endswith("is dark")]
    parts = [f"{len(real)} sites."]
    for o in s2s:
        parts.append(f"{len(o['sites'])} are joined by the {o['label']} ({o['shape_label']}).")
    for o in overlays:
        if o["kind"] == "cloud_service" and o["sites"]:
            parts.append(f"{len(o['sites'])} also tunnel to {o.get('name') or 'a cloud service'}.")
    standalone = sum(1 for k, t in types.items() if t["type"] == "standalone")
    if standalone:
        parts.append(f"{standalone} stand alone on their own internet.")
    issues = []
    if dark:
        issues.append(f"{len(dark)} site(s) are dark")
    if bad_pairs:
        issues.append(f"{bad_pairs} overlay pair(s) are degraded or down")
    if circ_down:
        issues.append(f"{circ_down} circuit(s) are down")
    parts.append((", ".join(issues) + "; everything else is up.") if issues else "Everything NodeWatch can see is up.")
    return {
        "site_types": types,
        "type_labels": TYPE_LABEL,
        "overlays": overlays,
        "coverage": coverage,
        "attention": att[:12],
        "sentence": " ".join(parts),
        "kpis": {
            "sites": len(real),
            "on_overlay": len(on_overlay),
            "standalone": standalone,
            "devices": devices,
            "devices_up": devices - down,
            "staging_down": staging_down,
            "circuits": circ,
            "circuits_up": circ - circ_down,
            "pairs": pairs,
            "pairs_ok": pairs - bad_pairs,
            "firewall_pairs": fw_pairs,
        },
    }
