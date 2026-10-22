"""Plain-language site summary, WAN section and light payloads for the topology map (v0.10.24).

Pure functions over a built site graph (``topology_service._build``):

* ``wan_section``  — internet circuits of the site's edges (from ``list_circuits`` sources) and the other
                     sites its SD-WAN / VPN tunnels reach (aggregated per remote site);
* ``overview``     — stages from the internet down to Wi-Fi with counts and node ids, wiring closets, and
                     one or two sentences describing how the site connects, for a non-expert;
* ``trim``         — the ``?view=overview`` payload: heavy per-node lists replaced by counts.
"""

from __future__ import annotations

import re
from collections import defaultdict
from typing import Any, Callable

PHYSICAL = ("physical", "lag", "l2")
UPSTREAM_ROLES = {"cloud", "sdwan_edge", "firewall", "router"}
_CORE_RE = re.compile(r"(^|[^a-z])(core|mdf|bb|backbone|spine)([^a-z]|$)", re.I)
_DIST_RE = re.compile(r"(^|[^a-z])(dist|distribution|agg|aggregation)([^a-z]|$)", re.I)
_CLOSET_RE = re.compile(r"(?:^|[^a-z0-9])(idf|mdf|tr|closet|wc|ter)[-_ ]?(\d+[a-z]?)?(?=$|[^a-z0-9])", re.I)
_FLOOR_RE = re.compile(r"(?:^|[^a-z0-9])(?:f|fl|flr|floor|lvl|level)[-_ ]?(\d+)(?=$|[^a-z0-9])", re.I)
_SITE_TO_SITE_KINDS = {"sdwan", "ipsec", "gre", "vxlan"}


def is_overlay(t: Any) -> bool:
    """A site-to-site tunnel users' traffic takes (``Tunnel.layer``); unknown layer: by tunnel kind."""
    layer = str(getattr(t, "layer", "") or "")
    if layer:
        return layer == "overlay"
    return str(getattr(t, "kind", "") or "") in _SITE_TO_SITE_KINDS


STAGES = (
    ("internet", "Internet circuits"),
    ("sdwan", "SD-WAN routers"),
    ("firewall", "Firewalls"),
    ("unmanaged", "Devices behind the router (not managed by a connected system)"),
    ("core", "Core switches"),
    ("distribution", "Distribution switches"),
    ("access", "Closet switches"),
    ("wireless", "Wi-Fi access points"),
    ("other", "Other devices"),
)
_RANK = {"down": 0, "degraded": 1, "unknown": 2, "up": 3}


def _natural(text: Any) -> list[Any]:
    return [int(t) if t.isdigit() else t.lower() for t in re.split(r"(\d+)", str(text or ""))]


def _num(v: Any) -> float | None:
    try:
        return None if v in (None, "") else float(v)
    except (TypeError, ValueError):
        return None


# --------------------------------------------------------------------------- WAN

def _public_ip(ip: Any) -> str:
    """The address when it is a public (internet-routable) IPv4/IPv6 address, else ''."""
    import ipaddress

    raw = str(ip or "").strip().split("/")[0]
    try:
        addr = ipaddress.ip_address(raw)
    except ValueError:
        return ""
    if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast or addr.is_unspecified:
        return ""
    if addr.version == 4 and addr in ipaddress.ip_network("100.64.0.0/10"):  # carrier-grade NAT
        return ""
    return str(addr)


def merge_circuits(rows: list[dict[str, Any]], site_of: Callable[[dict[str, Any]], str]) -> list[dict[str, Any]]:
    """One entry per physical internet circuit (v0.10.32).

    The same line was listed more than once when (a) two sources report the same router's WAN port, or
    (b) both routers of an HA pair use one line - EdgeConnect HA shares each circuit with the peer over the
    HA link, so both appliances list it with the same public address. Rows are the same circuit when they
    share the router and interface, or the site and public IP. The merged circuit keeps the best state, sums
    tunnels and traffic, and lists every router that uses it in ``routers`` (``node_ids`` for the map)."""
    out: list[dict[str, Any]] = []
    by_port: dict[tuple[str, str], dict[str, Any]] = {}
    by_public: dict[tuple[str, str], dict[str, Any]] = {}
    for c in rows:
        node = str(c.get("node_id") or c.get("device_key") or "")
        port = (node, str(c.get("interface") or "").strip().lower())
        public = _public_ip(c.get("public_ip"))
        site = str(site_of(c) or "")
        twin = by_port.get(port) if port[1] else None
        if twin is None and public and site:
            twin = by_public.get((site, public))
        router = {
            "node_id": c.get("node_id") or "",
            "device_name": c.get("device_name") or c.get("appliance") or "",
            "interface": c.get("interface") or "",
            "state": c.get("state") or "unknown",
        }
        if twin is None:
            first = {**c, "routers": [router], "node_ids": [x for x in [c.get("node_id")] if x]}
            out.append(first)
            if port[1]:
                by_port[port] = first
            if public and site:
                by_public[(site, public)] = first
            continue
        if port[1]:
            by_port.setdefault(port, twin)
        same_router = any(
            r["node_id"] == router["node_id"] and str(r["interface"]).lower() == str(router["interface"]).lower()
            for r in twin["routers"]
        )
        if same_router:  # the same port reported twice: fill gaps only
            for k, v in c.items():
                if twin.get(k) in (None, "", 0) and v not in (None, ""):
                    twin[k] = v
            continue
        twin["routers"].append(router)
        if router["node_id"] and router["node_id"] not in twin["node_ids"]:
            twin["node_ids"].append(router["node_id"])
        if _RANK.get(str(c.get("state")), 2) > _RANK.get(str(twin.get("state")), 2):
            twin["state"] = c.get("state")
        for k in ("tunnels_up", "tunnels_total", "rx_bps", "tx_bps"):
            a, b = _num(twin.get(k)), _num(c.get(k))
            if b is not None:
                twin[k] = (a or 0) + b if k in ("rx_bps", "tx_bps") else int((a or 0) + b)
        for k in ("latency_ms", "loss_pct", "jitter_ms", "bandwidth_down_kbps", "bandwidth_up_kbps", "speed_mbps"):
            if twin.get(k) is None and c.get(k) is not None:
                twin[k] = c.get(k)
    for c in out:
        if len(c["routers"]) > 1:
            c["shared"] = True
            c["device_name"] = c["appliance"] = " + ".join(dict.fromkeys(r["device_name"] for r in c["routers"] if r["device_name"]))
    return out


def wan_section(
    nodes: dict[str, dict[str, Any]],
    alias: dict[str, str],
    circuits: list[dict[str, Any]],
    tunnels: list[Any],
    canonical: str,
    site_of_record: Callable[[str, str], tuple[str, str]],
    site_of_ip: Callable[[str], tuple[str, str]],
    hubs: set[str],
) -> dict[str, Any]:
    """{circuits: [...], remote_sites: [...]} for one site.

    ``site_of_record(source, key)`` / ``site_of_ip(ip)`` → (canonical site key, name) from the
    organisation index ('' when unknown)."""

    def node_of(source: str, key: str) -> str:
        nid = alias.get(f"{source}:{key}") or alias.get(key) or ""
        n = nodes.get(nid)
        return nid if n is not None and not n.get("remote") and not n.get("synthetic") else ""

    out_c = []
    seen: set[str] = set()
    for c in circuits:
        if not isinstance(c, dict):
            continue
        nid = node_of(str(c.get("source") or ""), str(c.get("device_key") or ""))
        if not nid:
            continue
        ident = str(c.get("key") or f"{c.get('source')}:{c.get('device_key')}:{c.get('interface')}")
        if ident in seen:
            continue
        seen.add(ident)
        name = c.get("device_name") or c.get("appliance") or nodes[nid].get("name", "")
        out_c.append({**c, "node_id": nid, "device_name": name, "appliance": name})
    out_c = merge_circuits(out_c, lambda c: canonical)
    out_c.sort(
        key=lambda c: (_RANK.get(str(c.get("state")), 2), _natural(c.get("appliance")), _natural(c.get("interface")))
    )

    groups: dict[str, dict[str, Any]] = {}
    for t in tunnels:
        if not is_overlay(t):
            continue
        if not node_of(t.source, t.device_key):
            continue
        ck, name = "", ""
        if t.remote_device_key:
            if node_of(t.source, t.remote_device_key):
                continue  # both ends at this site
            ck, name = site_of_record(t.source, t.remote_device_key)
        if not ck and t.remote_ip:
            ck, name = site_of_ip(t.remote_ip)
        if ck and ck == canonical:
            continue
        if not ck and not (t.remote_name or t.remote_ip):
            continue
        gkey = ck or f"peer:{(t.remote_name or t.remote_ip).lower()}"
        g = groups.setdefault(
            gkey,
            {
                "site_key": ck or None,
                "name": name or t.remote_name or t.remote_ip,
                "tunnels_up": 0,
                "tunnels_down": 0,
                "tunnels_total": 0,
                "latency_ms": None,
                "loss_pct": None,
                "jitter_ms": None,
                "hub": bool(ck and ck in hubs),
                "_states": [],
            },
        )
        st = str(t.state or "unknown")
        g["tunnels_total"] += 1
        g["tunnels_up"] += st == "up"
        g["tunnels_down"] += st == "down"
        g["_states"].append(st)
        jitter = getattr(t, "jitter_ms", None)
        if jitter is None:  # transition: connectors that predate Tunnel.jitter_ms
            # transition fallback (v0.10.24): remove when all connectors fill Tunnel.jitter_ms
            jitter = (getattr(t, "vendor", None) or {}).get("jitter_ms")
        for k, v in (("latency_ms", t.latency_ms), ("loss_pct", t.loss_pct), ("jitter_ms", jitter)):
            v = _num(v)
            if v is not None:
                g[k] = v if g[k] is None else max(g[k], v)
    remote = []
    for g in groups.values():
        states = g.pop("_states")
        g["state"] = (
            "up"
            if all(s == "up" for s in states)
            else "down"
            if all(s == "down" for s in states)
            else "degraded"
            if "down" in states
            else "unknown"
        )
        remote.append(g)
    remote.sort(key=lambda g: (_RANK.get(g["state"], 2), not g["hub"], _natural(g["name"])))
    return {"circuits": out_c, "remote_sites": remote}


# --------------------------------------------------------------------------- overview


# Role → stage. Routers are WAN edges (like the map draws them); wireless controllers and load balancers
# are infrastructure with no stage of their own ("other"), never counted as access points or switches.
_ROLE_STAGE = {
    "cloud": "internet",
    "sdwan_edge": "sdwan",
    "router": "sdwan",
    "firewall": "firewall",
    "wireless_ap": "wireless",
    "wireless_controller": "other",
    "load_balancer": "other",
}


def _stage_label(sid: str, label: str, items: list[dict[str, Any]]) -> str:
    if sid == "sdwan":
        edges = sum(1 for n in items if n.get("role") == "sdwan_edge")
        return label if edges == len(items) else ("WAN routers" if not edges else "SD-WAN / WAN routers")
    return label


def _stage_of(n: dict[str, Any], up_neighbors: set[str]) -> str:
    role, tier = n.get("role"), n.get("tier", 5)
    # v0.10.35: an HA partner the user confirmed (evidence "ha-user") is a real unit too - it was counted as
    # "unmanaged", so the site sentence said "1 firewall" for a pair.
    ha_unit = n.get("ha_inferred") or n.get("evidence") in ("ha-user", "ha-inferred", "ha") or bool(n.get("ha_peer"))
    if n.get("inferred") and not (ha_unit and role in _ROLE_STAGE):
        return "unmanaged"  # seen only as a router's LAN next hop (an inferred HA unit keeps its role's stage)
    if role in _ROLE_STAGE:
        return _ROLE_STAGE[role]
    if role == "switch":
        nt = n.get("network_tier") or ""
        if nt in ("core", "distribution", "access"):  # Device.network_tier: the vendor knows
            return nt
        if tier <= 3:
            name = str(n.get("name") or "")
            if _CORE_RE.search(name):
                return "core"
            if _DIST_RE.search(name):
                return "distribution"
            return "core" if up_neighbors else "distribution"
        return "access"
    return "other"


def _closet_key(n: dict[str, Any], parents: list[dict[str, Any]], floors: dict[str, int]) -> tuple[str, str]:
    name = str(n.get("name") or "")
    m = _CLOSET_RE.search(name)
    if m:
        label = (m.group(1) + (m.group(2) or "")).upper()
        return f"cl:{label}", label
    fid = str(n.get("floor_key") or n.get("floor_id") or "")  # Device.floor_key; facts floor_id fallback
    if fid:
        return f"floor:{fid}", str(n.get("floor_name") or f"Floor plan {floors.get(fid, 0)}")
    m = _FLOOR_RE.search(name)
    if m:
        return f"fl:{int(m.group(1))}", f"Floor {int(m.group(1))}"
    if parents:
        p = parents[0]
        return f"up:{p['id']}", f"Behind {p.get('name') or 'switch'}"
    return f"sw:{n['id']}", name or "Switch"


def overview(
    result_nodes: list[dict[str, Any]],
    links: list[dict[str, Any]],
    circuits: list[dict[str, Any]],
    site_name: str,
) -> dict[str, Any]:
    nodes = {n["id"]: n for n in result_nodes if not n.get("remote") and not n.get("ghost")}
    adj: dict[str, set[str]] = defaultdict(set)
    for link in links:
        if link.get("layer") in PHYSICAL:
            a, b = link["a_device"], link["b_device"]
            adj[a].add(b)
            adj[b].add(a)
    by_stage: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for n in sorted(nodes.values(), key=lambda n: _natural(n.get("name"))):
        if n.get("synthetic") and n.get("role") != "cloud":
            continue
        up = {x for x in adj.get(n["id"], ()) if (nodes.get(x) or {}).get("role") in UPSTREAM_ROLES}
        by_stage[_stage_of(n, up)].append(n)
    stages = []
    for sid, label in STAGES:
        items = [n for n in by_stage.get(sid, []) if sid != "internet" or n.get("role") != "cloud"]
        if sid == "internet":
            if not circuits and not by_stage.get("internet"):
                continue
            stages.append(
                {
                    "id": sid,
                    "label": label,
                    "count": len(circuits),
                    "up": sum(1 for c in circuits if c.get("state") == "up"),
                    "down": sum(1 for c in circuits if c.get("state") == "down"),
                    "degraded": sum(1 for c in circuits if c.get("state") == "degraded"),
                    "node_ids": sorted({c["node_id"] for c in circuits if c.get("node_id")})
                    or [n["id"] for n in by_stage.get("internet", [])],
                    "circuit_keys": [c.get("key") for c in circuits],
                }
            )
            continue
        if not items:
            continue
        stages.append(
            {
                "id": sid,
                "label": _stage_label(sid, label, items),
                "count": len(items),
                "up": sum(1 for n in items if n.get("status") == "up"),
                "down": sum(1 for n in items if n.get("status") == "down"),
                "degraded": sum(1 for n in items if n.get("status") == "degraded"),
                "node_ids": [n["id"] for n in items],
                # v0.10.27: inferred HA units (e.g. a passive firewall that writes no logs) — "probable"
                "probable_ids": [n["id"] for n in items if n.get("inferred")],
                "ha_pairs": len({frozenset((n["id"], n["ha_peer"])) for n in items if n.get("ha_peer") and n["ha_peer"] in {x["id"] for x in items}}),
            }
        )

    # wiring closets: access switches (and the APs behind them)
    access = by_stage.get("access", [])
    floor_ids = {str(n.get("floor_key") or n.get("floor_id") or "") for n in access} - {""}
    floors = {fid: i + 1 for i, fid in enumerate(sorted(floor_ids))}
    closets: dict[str, dict[str, Any]] = {}
    for n in access:
        parents = sorted(
            (nodes[x] for x in adj.get(n["id"], ()) if x in nodes and nodes[x].get("tier", 5) < 4),
            key=lambda p: (p.get("tier", 5), _natural(p.get("name"))),
        )
        key, label = _closet_key(n, parents, floors)
        c = closets.setdefault(
            key,
            {
                "id": f"closet:{key}",
                "name": label,
                "switch_ids": [],
                "ap_ids": [],
                "ap_count": 0,
                "aps_down": 0,
                "switches_down": 0,
                "clients": None,
                "uplink_ids": [],
            },
        )
        c["switch_ids"].append(n["id"])
        c["switches_down"] += n.get("status") == "down"
        if n.get("clients") is not None:
            c["clients"] = (c["clients"] or 0) + int(n["clients"])
        for p in parents:
            if p["id"] not in c["uplink_ids"]:
                c["uplink_ids"].append(p["id"])
    sw_closet = {sid: c for c in closets.values() for sid in c["switch_ids"]}
    for n in by_stage.get("wireless", []):
        c = sw_closet.get(n.get("uplink") or "")
        if c is None:
            continue
        c["ap_ids"].append(n["id"])
        c["ap_count"] += 1
        c["aps_down"] += n.get("status") == "down"
        if n.get("clients") is not None:
            c["clients"] = (c["clients"] or 0) + int(n["clients"])
    closet_list = sorted(closets.values(), key=lambda c: _natural(c["name"]))

    return {"stages": stages, "closets": closet_list, "sentence": _sentence(site_name, stages)}


def _plural(n: int, one: str, many: str | None = None) -> str:
    return f"{n} {one if n == 1 else (many or one + 's')}"


def _sentence(site: str, stages: list[dict[str, Any]]) -> str:
    st = {s["id"]: s for s in stages}
    site = site or "This site"
    sdwan_label = st.get("sdwan", {}).get("label", "SD-WAN routers")
    words = {
        "sdwan": ("SD-WAN router" if sdwan_label == "SD-WAN routers" else "WAN router", None),
        "firewall": ("firewall", None),
        "core": ("core switch", "core switches"),
        "distribution": ("distribution switch", "distribution switches"),
    }
    if "internet" in st and st["internet"]["count"]:
        i = st["internet"]
        text = f"{site} reaches the internet over {_plural(i['count'], 'circuit')} ({i['up']} up)"
        if i.get("degraded"):
            text = text[:-1] + f", {i['degraded']} idle)"
    elif "internet" in st or "sdwan" in st or "firewall" in st:
        text = f"{site} reaches the internet"
    else:
        text = f"{site} has no internet connection NodeWatch can see"
    chain = [_plural(st[k]["count"], *words[k]) for k in ("sdwan", "firewall", "core", "distribution") if k in st]
    fw = st.get("firewall")
    if fw and fw.get("ha_pairs"):
        pairs = fw["ha_pairs"]
        idx = [k for k in ("sdwan", "firewall", "core", "distribution") if k in st].index("firewall")
        chain[idx] += (
            " (an HA pair)" if pairs == 1 and fw["count"] == 2 else f" ({_plural(pairs, 'HA pair')})"
        )
    if chain:
        text += " through " + chain[0] + "".join(f", then {x}" for x in chain[1:])
    tail = []
    if "access" in st:
        tail.append(_plural(st["access"]["count"], "closet switch", "closet switches"))
    if "wireless" in st:
        tail.append(_plural(st["wireless"]["count"], "Wi-Fi access point"))
    if tail:
        text += (" feeding " if chain else ", with ") + " and ".join(tail)
    text += "."
    if "unmanaged" in st:
        u = st["unmanaged"]["count"]
        text += (
            f" Behind its router NodeWatch also sees {_plural(u, 'device')} that no connected system manages"
            " (found from the router's routes)."
        )
    down = [(s, s["down"]) for s in stages if s["id"] != "internet" and s["down"]]
    circuits_down = st.get("internet", {}).get("down", 0)
    circuits_idle = st.get("internet", {}).get("degraded", 0)
    if down or circuits_down:
        nouns = {
            "sdwan": ("SD-WAN router", None),
            "firewall": ("firewall", None),
            "core": ("core switch", "core switches"),
            "distribution": ("distribution switch", "distribution switches"),
            "access": ("closet switch", "closet switches"),
            "wireless": ("Wi-Fi access point", None),
            "other": ("other device", None),
            "unmanaged": ("unmanaged device", None),
        }
        bits = [_plural(n, *nouns.get(s["id"], ("device", None))) for s, n in down]
        if circuits_down:
            bits.insert(0, _plural(circuits_down, "internet circuit"))
        text += " Right now down: " + ", ".join(bits) + "."
    elif stages and not circuits_idle:
        text += " Everything NodeWatch can see is up."
    if circuits_idle:
        verb = "is" if circuits_idle == 1 else "are"
        text += f" {_plural(circuits_idle, 'internet circuit')} {verb} up but carrying no traffic."
    return text


# --------------------------------------------------------------------------- light payload

_NODE_HEAVY = ("records", "seen_by", "members")


def trim(result: dict[str, Any]) -> dict[str, Any]:
    """``?view=overview``: heavy per-node lists replaced by counts (fetch one node with /node/{id})."""
    nodes = []
    for n in result.get("nodes") or []:
        m = {k: v for k, v in n.items() if k not in _NODE_HEAVY}
        for k in _NODE_HEAVY:
            m[f"{k}_count"] = len(n.get(k) or [])
        m["record_sources"] = sorted({r.get("source", "") for r in n.get("records") or []})
        nodes.append(m)
    links = []
    for link in result.get("links") or []:
        m = {k: v for k, v in link.items() if k != "evidence"}
        m["evidence_count"] = len(link.get("evidence") or [])
        links.append(m)
    return {**result, "nodes": nodes, "links": links, "view": "overview"}
