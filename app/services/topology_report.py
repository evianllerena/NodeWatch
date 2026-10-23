"""Topology report (v0.10.36): one document for an executive, a CIO or an engineer.

``start()`` gathers, in the background, the organisation map plus the site map of every site in scope
(from the caches the Topology page already keeps; a site never built before is built once) and turns it
into one vendor-neutral report: KPIs, the WAN shape, a ranked risk register, one section per site
(sentence, layers, HA pairs, circuits, aggregated links, closets, devices), circuit / device / fabric-link
registers and the data gaps. The browser renders it for print (Save as PDF); :func:`data_zip` gives the
same data as CSV + JSON files.

Read-only: nothing here changes a device or a setting.
"""

from __future__ import annotations

import csv
import io
import json
import logging
import secrets
import threading
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from app.core.security import redact_text
from app.core.version import APP_VERSION

log = logging.getLogger("nodewatch.topology.report")

MAX_JOBS = 6
SITE_WORKERS = 4
SITE_TIMEOUT_S = 90.0
_jobs: dict[str, dict[str, Any]] = {}
_lock = threading.Lock()

SECTIONS = ("cover", "summary", "orgmap", "risks", "sites", "circuits", "inventory", "fabric", "routes", "gaps")
INFRA_ROLES = {"sdwan_edge", "router", "firewall", "switch", "wireless_controller", "load_balancer", "cloud_gateway"}
CABLE = {"physical", "lag", "l2", "ha"}


# --------------------------------------------------------------------------- jobs
class TooManyJobs(RuntimeError):
    """Every job slot holds a report that is still running."""


def start(*, scope: str = "org", site: str = "", sites: list[str] | None = None, sections: list[str] | None = None,
          skip_empty: bool = True, mask: bool = False, audience: str = "engineer") -> dict[str, Any]:
    job_id = secrets.token_hex(8)
    job = {
        "id": job_id,
        "state": "running",
        "done": 0,
        "total": 0,
        "started": time.time(),
        "result": None,
        "error": "",
        "params": {
            "scope": scope if scope in ("org", "fabric", "site", "pick") else "org",
            "site": site,
            "sites": list(sites or [])[:500],
            "sections": [s for s in (sections or SECTIONS) if s in SECTIONS],
            "skip_empty": bool(skip_empty),
            "mask": bool(mask),
            "audience": audience if audience in ("executive", "leadership", "engineer", "custom") else "engineer",
        },
    }
    with _lock:
        if len(_jobs) >= MAX_JOBS:
            # Evict the oldest finished jobs only; a running job keeps its slot until it ends.
            finished = sorted((k for k in _jobs if _jobs[k]["state"] != "running"), key=lambda k: _jobs[k]["started"])
            for old in finished[: len(_jobs) - MAX_JOBS + 1]:
                _jobs.pop(old, None)
            if len(_jobs) >= MAX_JOBS:
                raise TooManyJobs(f"{len(_jobs)} topology reports are already being built; wait for one to finish")
        _jobs[job_id] = job
    threading.Thread(target=_run, args=(job,), name=f"topology-report-{job_id}", daemon=True).start()
    return status(job_id)


def status(job_id: str) -> dict[str, Any]:
    with _lock:
        job = _jobs.get(job_id)
    if job is None:
        raise KeyError(job_id)
    out = {k: job[k] for k in ("id", "state", "done", "total", "error")}
    out["elapsed_s"] = round(time.time() - job["started"], 1)
    if job["state"] == "done":
        out["report"] = job["result"]
    return out


def _run(job: dict[str, Any]) -> None:
    try:
        job["result"] = build(job["params"], progress=lambda d, t: job.update(done=d, total=t))
        job["state"] = "done"
    except Exception as exc:  # noqa: BLE001 - shown to the user
        log.exception("Topology report failed")
        job["state"] = "error"
        job["error"] = redact_text(exc)[:300] or type(exc).__name__


# --------------------------------------------------------------------------- build
def _mask_ip(v: str) -> str:
    if not v:
        return v
    parts = str(v).split(".")
    return ".".join(parts[:2] + ["x", "x"]) if len(parts) == 4 else "masked"


def _mask_serial(v: str) -> str:
    v = str(v or "")
    return (v[:3] + "•" * max(0, len(v) - 5) + v[-2:]) if len(v) > 5 else ("•" * len(v))


def _public(ip: str) -> bool:
    import ipaddress

    try:
        a = ipaddress.ip_address(str(ip).split("/")[0])
        return not (a.is_private or a.is_loopback or a.is_link_local or a.is_reserved)
    except ValueError:
        return False


def wan_shape(org: dict[str, Any]) -> dict[str, Any]:
    """Hub-and-spoke, full mesh, partial mesh or standalone, from who has tunnels to whom."""
    sites = [s for s in org.get("sites") or [] if not s.get("cloud")]
    fabric = [s for s in sites if (s.get("peers") or 0) > 0]
    keys = {s["key"] for s in fabric}
    pairs = {tuple(sorted((l["a"], l["b"]))) for l in org.get("links") or [] if l.get("a") in keys and l.get("b") in keys}
    n = len(fabric)
    possible = n * (n - 1) // 2
    density = len(pairs) / possible if possible else 0.0
    deg: dict[str, int] = {k: 0 for k in keys}
    for a, b in pairs:
        deg[a] += 1
        deg[b] += 1
    hubs = sorted((s for s in fabric if n > 2 and deg[s["key"]] >= 0.8 * (n - 1)), key=lambda s: -deg[s["key"]])
    if n < 2:
        shape, why = "standalone", "No site has tunnels to another site."
    elif density >= 0.9:
        shape = "full_mesh"
        why = f"{len(pairs)} of {possible} possible site pairs have tunnels ({round(density * 100)}%): every site reaches every other directly."
    elif hubs and all(deg[s["key"]] <= len(hubs) + 1 for s in fabric if s not in hubs):
        shape = "hub_and_spoke"
        why = f"{len(hubs)} hub site(s) reach almost every site; the other sites only reach the hubs."
    else:
        shape = "partial_mesh"
        why = f"{len(pairs)} of {possible} possible site pairs have tunnels ({round(density * 100)}%); sites reach some others directly."
    main = sorted(fabric, key=lambda s: -(s.get("circuits_total") or 0))[:3] if shape == "full_mesh" else hubs[:5]
    return {
        "shape": shape,
        "label": {"full_mesh": "Full mesh", "hub_and_spoke": "Hub and spoke", "partial_mesh": "Partial mesh", "standalone": "Standalone sites"}[shape],
        "why": why,
        "fabric_sites": n,
        "pairs": len(pairs),
        "possible": possible,
        "density": round(density, 3),
        "hubs": [{"key": s["key"], "name": s["name"]} for s in main],
        "standalone": len([s for s in sites if not (s.get("peers") or 0)]),
    }


def _site_row(s: dict[str, Any]) -> dict[str, Any]:
    roles = s.get("by_role") or {}
    return {
        "key": s.get("key"),
        "name": s.get("name"),
        "health": s.get("health") or "unknown",
        "devices": s.get("devices") or 0,
        "down": s.get("down") or 0,
        "circuits": s.get("circuits_total") or 0,
        "circuits_down": s.get("circuits_down") or 0,
        "edges": roles.get("sdwan_edge", 0) + roles.get("router", 0),
        "firewalls": s.get("firewalls") or roles.get("firewall", 0),
        "switches": roles.get("switch", 0),
        "aps": roles.get("wireless_ap", 0),
        "peers": s.get("peers") or 0,
        "fabric": bool(s.get("peers")),
        "cloud": bool(s.get("cloud")),
        "reasons": [str(r) for r in (s.get("reasons") or [])][:4],
    }


def _site_detail(key: str, mask: bool) -> dict[str, Any]:
    from app.services.topology_service import graph_for

    g = graph_for(key)
    nodes = [n for n in g.get("nodes") or [] if not n.get("remote") and not n.get("ghost") and not n.get("synthetic")]
    by_id = {n["id"]: n for n in nodes}
    ip = (lambda v: _mask_ip(v)) if mask else (lambda v: v)
    devices = []
    for n in nodes:
        devices.append(
            {
                "id": n["id"],
                "name": n.get("name") or "",
                "role": n.get("role") or "unknown",
                "model": n.get("model") or "",
                "serial": _mask_serial(n.get("serial")) if mask else (n.get("serial") or ""),
                "os_version": n.get("os_version") or "",
                "mgmt_ip": ip(n.get("mgmt_ip") or ""),
                "mac": "" if mask else (n.get("mac") or ""),
                "status": n.get("status") or "unknown",
                "ha_state": n.get("ha_state") or "",
                "ha_peer": (by_id.get(n.get("ha_peer") or "") or {}).get("name", ""),
                "inferred": bool(n.get("inferred")),
                "uplink": (by_id.get(n.get("uplink") or "") or {}).get("name", ""),
                "clients": n.get("clients"),
                "ports": f"{n.get('ports_up')}/{n.get('ports_total')}" if n.get("ports_total") is not None else "",
                "poe_w": n.get("poe_draw_w"),
                "sources": list(n.get("sources") or []),
            }
        )
    links = []
    for l in g.get("links") or []:
        if l.get("layer") not in CABLE:
            continue
        a, b = by_id.get(l.get("a_device")), by_id.get(l.get("b_device"))
        if not a or not b or "wireless_ap" in (a.get("role"), b.get("role")):
            continue
        members = l.get("members") or []
        links.append(
            {
                "a": a["name"],
                "a_role": a.get("role"),
                "a_if": l.get("a_interface") or "",
                "b": b["name"],
                "b_role": b.get("role"),
                "b_if": l.get("b_interface") or "",
                "layer": l.get("layer"),
                "speed_mbps": l.get("speed_mbps"),
                "members": len(members),
                "members_up": sum(1 for m in members if m.get("state") == "up"),
                "member_ports": [f"{m.get('a_interface') or '?'} ⇄ {m.get('b_interface') or '?'}" for m in members][:16],
                "state": l.get("state") or "unknown",
                "inferred": bool(l.get("inferred")),
            }
        )
    circuits = []
    for c in (g.get("wan") or {}).get("circuits") or []:
        routers = [r.get("device_name") for r in c.get("routers") or [] if r.get("device_name")] or [c.get("device_name") or c.get("appliance") or ""]
        pub = c.get("public_ip") or ""
        circuits.append(
            {
                "label": c.get("label") or c.get("interface") or "",
                "carrier": c.get("carrier") or "",
                "kind": c.get("kind") or "",
                "state": c.get("state") or "unknown",
                "routers": routers,
                "interface": c.get("interface") or "",
                "public_ip": (_mask_ip(pub) if mask and _public(pub) else pub),
                "down_kbps": c.get("bandwidth_down_kbps"),
                "up_kbps": c.get("bandwidth_up_kbps"),
                "speed_mbps": c.get("speed_mbps"),
                "rx_bps": c.get("rx_bps"),
                "tx_bps": c.get("tx_bps"),
                "latency_ms": c.get("latency_ms"),
                "loss_pct": c.get("loss_pct"),
                "jitter_ms": c.get("jitter_ms"),
                "tunnels_up": c.get("tunnels_up"),
                "tunnels_total": c.get("tunnels_total"),
            }
        )
    ov = g.get("overview") or {}
    stages = []
    for s in ov.get("stages") or []:
        stages.append(
            {
                "id": s.get("id"),
                "label": s.get("label"),
                "count": s.get("count"),
                "up": s.get("up"),
                "down": s.get("down"),
                "ha_pairs": s.get("ha_pairs") or 0,
                "devices": [by_id[x]["name"] for x in s.get("node_ids") or [] if x in by_id][:40],
            }
        )
    closets = []
    for c in ov.get("closets") or []:
        closets.append(
            {
                "name": c.get("name"),
                "switches": [by_id[x]["name"] for x in c.get("switch_ids") or [] if x in by_id],
                "uplinks": [by_id[x]["name"] for x in c.get("uplink_ids") or [] if x in by_id],
                "aps": c.get("ap_count") or 0,
                "aps_down": c.get("aps_down") or 0,
                "switches_down": c.get("switches_down") or 0,
                "clients": c.get("clients"),
            }
        )
    ha = []
    seen: set[str] = set()
    for n in nodes:
        p = by_id.get(n.get("ha_peer") or "")
        if not p or n["id"] in seen:
            continue
        seen.update({n["id"], p["id"]})
        ha.append(
            {
                "role": n.get("role"),
                "a": n["name"],
                "a_state": n.get("ha_state") or "",
                "a_status": n.get("status") or "",
                "b": p["name"],
                "b_state": p.get("ha_state") or "",
                "b_status": p.get("status") or "",
                "assumed": bool(p.get("inferred") or n.get("inferred")),
            }
        )
    remote = (g.get("wan") or {}).get("remote_sites") or []
    return {
        "sentence": ov.get("sentence") or "",
        "stages": stages,
        "closets": closets,
        "ha_pairs": ha,
        "circuits": circuits,
        "links": links,
        "devices": devices,
        "fabric_peers": len(remote),
        "fabric_peers_up": sum(1 for r in remote if r.get("state") == "up"),
        "gaps": [str(x) for x in g.get("gaps") or []][:10],
        "partial": bool(g.get("partial")),
    }


def _risks(org: dict[str, Any], sites: list[dict[str, Any]], details: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []

    def add(impact: str, risk: str, where: list[str], fix: str) -> None:
        if where:
            out.append({"impact": impact, "risk": risk, "where": where, "fix": fix})

    real = [s for s in sites if not s["cloud"]]
    add("High", "Site offline now", [s["name"] for s in real if s["devices"] and s["down"] == s["devices"] and s["devices"] < 20],
        "Check power and the internet line on site; confirm the site is still in use.")
    add("High", "Single internet circuit", [s["name"] for s in real if s["fabric"] and s["circuits"] == 1],
        "Add a second circuit from another provider (an LTE line is enough as backup).")
    add("Medium", "Single SD-WAN edge / router", [s["name"] for s in real if s["fabric"] and s["edges"] == 1],
        "Add a second edge at the larger sites, or keep a spare ready.")
    add("Medium", "Circuit down", [f"{s['name']} ({s['circuits_down']} of {s['circuits']})" for s in real if s["circuits_down"]],
        "Open a ticket with the provider; traffic runs on the remaining circuits.")
    bad_links = [l for l in org.get("links") or [] if l.get("state") in ("degraded", "down")]
    names = {s["key"]: s["name"] for s in sites}
    add("Medium", "Degraded or down fabric links",
        [f"{names.get(l['a'], l['a'])} ⇄ {names.get(l['b'], l['b'])} ({l.get('state')})" for l in bad_links][:20],
        "Check the circuits on both ends (loss, latency); see the fabric links register.")
    add("Medium", "No local firewall seen", [s["name"] for s in real if s["fabric"] and not s["firewalls"] and (s["switches"] + s["aps"]) >= 20],
        "Confirm internet traffic is inspected centrally (data center or cloud security).")
    for key, d in details.items():
        name = names.get(key, key)
        for p in d.get("ha_pairs") or []:
            if "down" in (p["a_status"], p["b_status"]):
                add("High", "HA pair running on one unit", [f"{name}: {p['a']} / {p['b']}"], "Bring the failed unit back; the site has no failover until then.")
        for l in d.get("links") or []:
            if l["members"] > 1 and l["members_up"] < l["members"]:
                add("Medium", "Aggregated link missing members", [f"{name}: {l['a']} {l['a_if']} ⇄ {l['b']} ({l['members_up']}/{l['members']} up)"],
                    "Check the failed member ports and optics; the bundle runs at reduced capacity.")
    add("Low", "Site with every device offline (staging or retired?)", [s["name"] for s in real if s["devices"] >= 20 and s["down"] == s["devices"]],
        "Rename, move or delete it so it stops inflating offline counts.")
    add("Low", "Empty sites", [s["name"] for s in real if not s["devices"]], "Remove them or add their devices.")
    merged: dict[tuple[str, str], dict[str, Any]] = {}
    for r in out:
        k = (r["impact"], r["risk"])
        if k in merged:
            merged[k]["where"].extend(r["where"])
        else:
            merged[k] = dict(r, where=list(r["where"]))
    order = {"High": 0, "Medium": 1, "Low": 2}
    return sorted(merged.values(), key=lambda r: (order[r["impact"]], -len(r["where"])))


def build(params: dict[str, Any], progress=lambda d, t: None) -> dict[str, Any]:
    from app.services.topology_org_service import org_view

    started = time.time()
    org = org_view()
    if org.get("partial") and not org.get("sites"):
        raise RuntimeError("The organization map is still being built. Try again in a minute.")
    all_sites = [_site_row(s) for s in org.get("sites") or []]
    scope = params["scope"]
    if scope == "site":
        chosen = [s for s in all_sites if s["key"] == params["site"]]
    elif scope == "pick":
        want = set(params["sites"])
        chosen = [s for s in all_sites if s["key"] in want]
    elif scope == "fabric":
        chosen = [s for s in all_sites if s["fabric"]]
    else:
        chosen = [s for s in all_sites if not s["cloud"]]
    if params["skip_empty"] and scope != "site":
        chosen = [s for s in chosen if s["devices"] and not (s["devices"] >= 20 and s["down"] == s["devices"])]
    want_sites = "sites" in params["sections"] or any(x in params["sections"] for x in ("circuits", "inventory", "routes"))
    details: dict[str, dict[str, Any]] = {}
    total = len(chosen) if want_sites else 0
    progress(0, total)
    if want_sites and chosen:
        done = 0

        def one(s: dict[str, Any]) -> tuple[str, dict[str, Any]]:
            try:
                return s["key"], _site_detail(s["key"], params["mask"])
            except Exception as exc:  # noqa: BLE001 - one site failing leaves a note, not a broken report
                log.info("report: site %s skipped: %s", s["name"], exc)
                return s["key"], {"error": str(exc)[:200]}

        with ThreadPoolExecutor(max_workers=SITE_WORKERS, thread_name_prefix="report-site") as pool:
            for key, d in pool.map(one, chosen, timeout=SITE_TIMEOUT_S * max(1, len(chosen) / SITE_WORKERS)):
                details[key] = d
                done += 1
                progress(done, total)
    if "routes" in params["sections"]:
        from app.services.topology_service import site_routes

        for s in chosen:
            try:
                r = site_routes(s["key"])
                details.setdefault(s["key"], {})["routes"] = [
                    {k: x.get(k) for k in ("device", "prefix", "next_hop", "interface", "protocol", "vrf")} for x in (r.get("routes") or [])[:400]
                ]
            except Exception as exc:  # noqa: BLE001
                details.setdefault(s["key"], {})["routes_error"] = str(exc)[:160]
    in_scope = chosen if scope in ("site", "pick") else [s for s in all_sites if not s["cloud"]]
    risks = _risks(org, in_scope, details)
    devices_total = sum(s["devices"] for s in in_scope)
    down_total = sum(s["down"] for s in in_scope)
    circuits_total = sum(s["circuits"] for s in in_scope)
    circuits_down = sum(s["circuits_down"] for s in in_scope)
    ha_pairs = sum(len(d.get("ha_pairs") or []) for d in details.values())
    links = org.get("links") or []
    health: dict[str, int] = {}
    for s in in_scope:
        health[s["health"]] = health.get(s["health"], 0) + 1
    biggest_down = max(in_scope, key=lambda s: s["down"], default=None)
    sources = sorted({(x.get("product") or x.get("source") or "") for x in org.get("sources") or [] if x.get("ok", True)} - {""})
    return {
        "generated_at": time.time(),
        "build_s": round(time.time() - started, 1),
        "app_version": APP_VERSION,
        "params": params,
        "sources": sources,
        "kpis": {
            "sites": len(in_scope),
            "sites_fabric": sum(1 for s in in_scope if s["fabric"]),
            "sites_empty": sum(1 for s in in_scope if not s["devices"]),
            "devices": devices_total,
            "devices_down": down_total,
            "circuits": circuits_total,
            "circuits_up": circuits_total - circuits_down,
            "ha_pairs": ha_pairs,
            "fabric_links": len(links),
            "fabric_links_ok": sum(1 for l in links if l.get("state") == "up"),
            "tunnels": (org.get("stats") or {}).get("tunnels"),
            "health": health,
            "most_down": {"name": biggest_down["name"], "down": biggest_down["down"]} if biggest_down and biggest_down["down"] else None,
        },
        "shape": wan_shape(org),
        "cloud": [{"name": c.get("name"), "gateways": c.get("gateways"), "kinds": c.get("by_kind") or {}, "reaches": len(c.get("reaches") or []), "status": c.get("status")} for c in org.get("cloud") or []],
        "sites": all_sites if scope not in ("site", "pick") else chosen,
        "chosen": [s["key"] for s in chosen],
        "details": details,
        "fabric_links": [
            {
                "a": next((s["name"] for s in all_sites if s["key"] == l.get("a")), l.get("a")),
                "b": next((s["name"] for s in all_sites if s["key"] == l.get("b")), l.get("b")),
                "tunnels": l.get("tunnels"),
                "up": l.get("up"),
                "state": l.get("state"),
                "latency_ms": l.get("latency_ms"),
                "loss_pct": l.get("loss_pct"),
                "kinds": l.get("kinds") or [],
            }
            for l in links
        ],
        "risks": risks,
        "gaps": [str(x) for x in org.get("gaps") or []][:20],
    }


# --------------------------------------------------------------------------- data files
def _csv(rows: list[dict[str, Any]], cols: list[str]) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(cols)
    for r in rows:
        w.writerow(["; ".join(map(str, r.get(c))) if isinstance(r.get(c), list) else ("" if r.get(c) is None else r.get(c)) for c in cols])
    return buf.getvalue()


def data_zip(job_id: str) -> bytes:
    with _lock:
        job = _jobs.get(job_id)
    if job is None or job["state"] != "done":
        raise KeyError(job_id)
    rep = job["result"]
    names = {s["key"]: s["name"] for s in rep["sites"]}
    devices, circuits, links = [], [], []
    for key, d in rep["details"].items():
        site = names.get(key, key)
        devices += [{"site": site, **x} for x in d.get("devices") or []]
        circuits += [{"site": site, **x} for x in d.get("circuits") or []]
        links += [{"site": site, **x} for x in d.get("links") or []]
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("sites.csv", _csv(rep["sites"], ["name", "health", "devices", "down", "circuits", "circuits_down", "edges", "firewalls", "switches", "aps", "peers"]))
        z.writestr("devices.csv", _csv(devices, ["site", "name", "role", "model", "serial", "os_version", "mgmt_ip", "mac", "status", "ha_state", "ha_peer", "uplink", "clients", "ports", "poe_w", "sources"]))
        z.writestr("circuits.csv", _csv(circuits, ["site", "label", "carrier", "kind", "state", "routers", "interface", "public_ip", "down_kbps", "up_kbps", "latency_ms", "loss_pct", "jitter_ms", "tunnels_up", "tunnels_total"]))
        z.writestr("links.csv", _csv(links, ["site", "a", "a_if", "b", "b_if", "layer", "speed_mbps", "members", "members_up", "state"]))
        z.writestr("fabric-links.csv", _csv(rep["fabric_links"], ["a", "b", "tunnels", "up", "state", "latency_ms", "loss_pct"]))
        z.writestr("risks.csv", _csv(rep["risks"], ["impact", "risk", "where", "fix"]))
        z.writestr("report.json", json.dumps(rep, indent=1, default=str))
    return buf.getvalue()
