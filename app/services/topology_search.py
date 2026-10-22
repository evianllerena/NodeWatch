"""Organisation-wide device index for the topology map (v0.10.23).

Built from the organisation map's inventory read (``topology_org_service._collect``: one
``list_devices(None)`` per source, cached / stale-while-revalidate), so it answers instantly:

* ``search(q)``       — names, every source's record name, HA / stack member names and serials, IPs,
                        MACs, serials and models → the node id the site map uses for that device
                        (``topology_service.node_id_for``), its canonical site and what matched;
* ``hint()``          — per source, how many devices are placed *without* their own site key (so a site
                        build knows which sources must be asked unscoped, and which can be skipped);
* ``unassigned()``    — device records no site claims (for the site-map API).

The index is persisted (``state/topology/search-index.json``) so search works right after a restart.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import re
import threading
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from app.core.config import STATE_ROOT
from app.services import topology_service as topo
from app.services import topology_sites as site_registry
from app.core.file_utils import write_private_text

log = logging.getLogger("nodewatch.topology")

ROOT: Path = STATE_ROOT / "topology"
INDEX_FILE = "search-index.json"
MAX_UNASSIGNED = 2000

_lock = threading.Lock()
_index: dict[str, Any] = {
    "built_at": 0.0,
    "nodes": [],
    "hint": None,
    "unassigned": [],
    "reg": "",
    "raw_at": None,
    "records": {},  # "source:key" → canonical site (placed records only)
    "bare": {},  # device key → canonical site
    "ips": {},  # management / circuit IP → canonical site
}
_PERSIST = ("built_at", "nodes", "hint", "unassigned", "reg", "records", "bare", "ips")
_loaded = False


def _path() -> Path:
    return ROOT / INDEX_FILE


def _load_disk() -> None:
    global _loaded
    if _loaded:
        return
    _loaded = True
    try:
        data = json.loads(_path().read_text(encoding="utf-8"))
    except FileNotFoundError:
        return
    except (OSError, ValueError) as exc:
        log.info("topology: search index unreadable: %s", exc)
        return
    if isinstance(data, dict) and isinstance(data.get("nodes"), list):
        _index.update(
            built_at=float(data.get("built_at") or 0),
            nodes=data["nodes"],
            hint=data.get("hint"),
            unassigned=data.get("unassigned") or [],
            reg=data.get("reg") or "",
            records=data.get("records") or {},
            bare=data.get("bare") or {},
            ips=data.get("ips") or {},
        )


def _save() -> None:
    p = _path()
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        with _lock:
            data = {k: _index[k] for k in _PERSIST}
        write_private_text(p, json.dumps(data, separators=(",", ":"), default=str))  # atomic, owner-only (v0.10.40)
    except (OSError, TypeError, ValueError) as exc:
        log.info("topology: search index not saved: %s", exc)


def rebuild(raw: dict[str, Any], *, save: bool = True) -> None:
    """(Re)build the index from an organisation collect (``raw["devices"]``)."""
    devices = [d for d in raw.get("devices") or [] if getattr(d, "key", "")]
    site_registry.set_shared_ips(shared_mgmt_ips(devices))
    reg = site_registry.registry()
    place = {f"{d.source}:{d.key}": reg.place(d) for d in devices}
    # Learned naming conventions (stems of devices placed by their own site) and the site joins they imply;
    # placement is re-run when either changed what the registry knows.
    try:
        base = reg.base()  # learners never see their own joins
        changed = site_registry.set_naming(site_registry.learn_naming(devices, place, base))
        links = site_registry.learn_naming_links(site_registry.registry(links=False), devices, place)
        complete = not raw.get("failed_sources")  # a failed source never removes joins
        if site_registry.add_site_links(links, via="naming", complete=complete):
            changed = True
            log.info("topology: site joins from naming conventions updated (%d current)", len(links))
        if changed:
            reg = site_registry.registry()
            place = {f"{d.source}:{d.key}": reg.place(d) for d in devices}
    except Exception as exc:  # noqa: BLE001 - naming is a nicety
        log.info("topology: naming conventions skipped: %s", exc)
    topo.propagate_peers(devices, place)  # the other unit of an HA pair follows a placed one
    try:  # v0.10.30: a unit named only by logs follows its partner by the pair's naming (PA-WHL1 → PA-WHL2)
        found = topo.propagate_name_partners(devices, place)
        if found:
            log.info("topology: %d HA unit(s) placed next to their partner by name", len(found))
    except Exception as exc:  # noqa: BLE001 - placement nicety
        log.info("topology: HA name partners skipped: %s", exc)
    try:
        topo.learn_ha_naming(devices, place)  # how often sites with unit-numbered names have both units
    except Exception as exc:  # noqa: BLE001 - diagnostics / inference only
        log.info("topology: HA naming stats skipped: %s", exc)
    site_names = {ck: s["name"] for ck, s in reg.sites.items()}
    g = topo._Graph()
    topo._resolve_devices(g, devices, place, site_names)
    topo._ha_user_partners(g)
    try:  # v0.10.35: the organisation counts include the passive unit a site map draws
        topo._ha_missing_units(g)
    except Exception as exc:  # noqa: BLE001 - inference only
        log.info("topology: HA partner inference skipped: %s", exc)
    _last_ha.clear()
    _last_ha.update(g.ha)
    nodes = []
    for n in g.nodes.values():
        nodes.append(
            {
                "id": n["id"],
                "name": n["name"],
                "role": n["role"],
                "status": n["status"],
                "model": n["model"],
                "mgmt_ip": n["mgmt_ip"],
                "serial": n["serial"],
                "macs": n["macs"],
                "ips": n["ips"],
                "site_key": n["site_key"],
                "site_name": n["site_name"],
                "site_via": n["site_via"],
                "sources": n["sources"],
                "records": [
                    {"source": r["source"], "key": r["key"], "name": r["name"], "serial": r.get("serial", "")}
                    for r in n["records"]
                ],
                "members": [
                    {"name": str(m.get("name") or ""), "serial": str(m.get("serial") or "")}
                    for m in n["members"]
                    if isinstance(m, dict)
                ],
            }
        )
    needs: Counter = Counter()
    unassigned = []
    for d in devices:
        ck, via = place[f"{d.source}:{d.key}"]
        if via != "site":
            needs[d.source] += 1
        if not ck and len(unassigned) < MAX_UNASSIGNED:
            sug = suggest_site(reg, d.name)
            why = site_registry.explain_unplaced(reg, d)
            unassigned.append(
                {
                    "record_key": f"{d.source}:{d.key}",
                    "source": d.source,
                    "key": d.key,
                    "name": d.name,
                    "role": d.role,
                    "model": d.model,
                    "mgmt_ip": d.mgmt_ip,
                    "serial": d.serial,
                    "status": d.status,
                    "site_name": d.site_name,
                    "node_id": g.alias.get(f"{d.source}:{d.key}", ""),
                    "suggested": sug,
                    # v0.10.27: plain words for the Assign-sites list
                    "kind": d.role or "unknown",
                    "what": describe_device(d, reg),
                    "why": _why_text(why),
                    "evidence": why.get("evidence") or [],
                }
            )
    records = {rk: ck for rk, (ck, _via) in place.items() if ck}
    bare: dict[str, str] = {}
    for rk, ck in records.items():
        bare.setdefault(rk.split(":", 1)[1], ck)
    ips: dict[str, str] = {}
    for d in devices:
        ck = place[f"{d.source}:{d.key}"][0]
        ip = topo._ip(d.mgmt_ip)
        if ck and ip:
            ips.setdefault(ip, ck)
    dev_site = {**bare, **records}
    for c in raw.get("circuits") or []:
        c = topo.circuit_dict(c)
        if c is None:
            continue
        ck = dev_site.get(f"{c.get('source')}:{c.get('device_key')}") or dev_site.get(str(c.get("device_key") or ""))
        for k in ("public_ip", "ip"):
            ip = topo._ip(c.get(k))
            if ck and ip:
                ips.setdefault(ip, ck)
    with _lock:
        _index.update(
            records=records,
            bare=bare,
            ips=ips,
            built_at=time.time(),
            nodes=nodes,
            hint={"needs_unscoped": dict(needs), "sources": sorted({d.source for d in devices})},
            unassigned=unassigned,
            reg=reg.version,
            raw_at=raw.get("generated_at"),
        )
    if save:
        _save()
    log_evidence(devices, place)
    log_unplaced(reg, devices, place)
    refresh_subnets_async(devices, place, circuits=raw.get("circuits") or [], complete=not raw.get("failed_sources"))


def shared_mgmt_ips(devices: list[Any]) -> set[str]:
    """Management IPs that more than one distinct device uses (factory defaults, NAT'd management …).

    The same box reported by two sources has one address once: devices are told apart by host name
    (falling back to their key)."""
    owners: dict[str, set[str]] = {}
    for d in devices:
        ip = topo._ip(getattr(d, "mgmt_ip", ""))
        if ip:
            owners.setdefault(ip, set()).add(topo.norm_host(d.name) or f"{d.source}:{d.key}")
    return {ip for ip, who in owners.items() if len(who) > 1}


LOG_LABEL = "seen in logs"


def firewall_evidence(devices: list[Any], place: dict[str, tuple[str, str]]) -> dict[str, Any]:
    """Firewalls by evidence: listed by a management system vs seen in traffic logs; placed or not."""
    by_id: dict[str, dict[str, Any]] = {}
    for d in devices:
        if d.role != "firewall":
            continue
        ident = topo.valid_serial(d.serial) or f"{d.source}:{d.key}"
        row = by_id.setdefault(ident, {"name": d.name, "serial": d.serial, "listed": False, "logs": False, "site": ""})
        if LOG_LABEL in (getattr(d, "labels", None) or []):
            row["logs"] = True
        else:
            row["listed"] = True
            row["name"] = d.name or row["name"]
        ck = place.get(f"{d.source}:{d.key}", ("", ""))[0]
        row["site"] = row["site"] or ck
    rows = list(by_id.values())
    return {
        "listed": sum(1 for r in rows if r["listed"]),
        "seen_in_logs": sum(1 for r in rows if r["logs"]),
        "logs_only": sum(1 for r in rows if r["logs"] and not r["listed"]),
        "placed": sum(1 for r in rows if r["site"]),
        "total": len(rows),
        "unplaced": [{"name": r["name"], "serial": r["serial"]} for r in rows if not r["site"]][:50],
    }


_last_ha: dict[str, int] = {}
_ROLE_WORDS = {
    "firewall": "Firewall",
    "sdwan_edge": "SD-WAN edge",
    "router": "Router",
    "switch": "Switch",
    "wireless_ap": "Wireless access point",
    "wireless_controller": "Wireless controller",
    "load_balancer": "Load balancer",
    "server": "Server",
    "endpoint": "Endpoint",
}
_CLOUD_WORDS = {
    "mobile_users": "mobile-user gateway — where remote VPN users connect",
    "service_connection": "service connection — the cloud's tunnel to a data center",
    "remote_network": "remote-network gateway — where a branch's tunnel ends in the cloud",
}


def describe_device(d: Any, reg: Any = None) -> str:
    """One plain sentence: what this record is (for people who do not know the product)."""
    role = str(getattr(d, "role", "") or "")
    labels = [str(x).lower() for x in getattr(d, "labels", None) or []]
    if role == "cloud_gateway":
        kind = _CLOUD_WORDS.get(str(getattr(d, "cloud_kind", "") or ""), "cloud security gateway")
        where = ""
        if reg is not None:
            ck = reg.resolve(str(getattr(d, "site_key", "") or ""))
            where = reg.name(ck) if ck else ""
        return (
            f"A {kind}{f' of {where}' if where else ''}. It runs in the provider's cloud and has no building, "
            "so it is listed under Cloud services."
        )
    what = _ROLE_WORDS.get(role, "Device")
    if "seen in system logs" in labels:
        return (
            f"{what} known only from the log service's system logs — it wrote no traffic logs (often the passive "
            "unit of an HA pair). No management system lists it."
        )
    if LOG_LABEL in labels:
        return (
            f"{what} found only in the log service's traffic logs; no connected management system lists it. "
            "NodeWatch places it by the networks in its logs, its name or its HA partner."
        )
    src = str(getattr(d, "source", "") or "")
    return f"{what} listed by {src} without a site that matches one of your sites."


def _why_text(why: dict[str, Any]) -> str:
    reason = str(why.get("reason") or "")
    ev = ", ".join(why.get("evidence") or [])
    if reason == "no private address or network known for it":
        return "No address or network of it is known, so no site can be matched."
    if reason == "no index hit":
        return f"Its networks ({ev}) do not belong to any known site." if ev else "No known site contains it."
    if why.get("candidate"):
        return f"Closest site: {why['candidate']} — {reason}."
    return reason[:1].upper() + reason[1:] + "." if reason else ""


def log_evidence(devices: list[Any], place: dict[str, tuple[str, str]]) -> None:
    """One line per organisation read: what the map is built from (diagnostics prove it)."""
    try:
        detail = site_registry.subnet_detail()
        fw = firewall_evidence(devices, place)
        log.info(
            "topology: org evidence — prefixes by origin %s (%s total); inferred LAN neighbours %d on %d sites; "
            "subnet site joins %d; firewalls: %d listed, %d from traffic logs (%d placed of %d); routes %s",
            detail.get("by_origin") or {},
            detail.get("prefixes", 0),
            sum(topo.inferred_counts().values()),
            sum(1 for v in topo.inferred_counts().values() if v),
            len(site_registry.site_links()),
            fw["listed"],
            fw["seen_in_logs"],
            fw["placed"],
            fw["total"],
            route_counts() or "not read yet",
        )
        clouds = Counter(
            str(getattr(d, "cloud_kind", "") or "other") for d in devices if getattr(d, "role", "") == "cloud_gateway"
        )
        unplaced = [d for d in devices if d.role == "firewall" and not place.get(f"{d.source}:{d.key}", ("", ""))[0]]
        log.info(
            "topology: org cloud / HA / plumbing — cloud gateways %s; HA pairs %d explicit, %d inferred, "
            "user-confirmed %d (%d peer nodes made); "
            "HA naming %s; plumbing links from logs %d on %d maps; firewalls still unplaced %d",
            dict(clouds) or "none",
            _last_ha.get("explicit", 0),
            _last_ha.get("inferred", 0),
            _last_ha.get("user_confirmed", 0),
            _last_ha.get("peer_nodes", 0),
            {k: v.get("ratio") for k, v in topo._ha_naming.items()} or "none",
            sum(topo.plumbing_counts().values()),
            sum(1 for v in topo.plumbing_counts().values() if v),
            len(unplaced),
        )
    except Exception as exc:  # noqa: BLE001 - diagnostics only
        log.info("topology: evidence line skipped: %s", exc)


def suggest_site(reg: Any, name: Any) -> dict[str, Any] | None:
    core = site_registry.core_tokens(name)
    best = (0.0, "")
    for ck, s in reg.sites.items():
        for m in s["members"]:
            words = set(core)
            sc = site_registry.name_score(m.core, core)
            if not sc and m.core and set(m.core) & words:
                sc = 0.5
            if sc > best[0]:
                best = (sc, ck)
    if best[0] >= site_registry.SUGGEST_MIN:
        return {"key": best[1], "name": reg.name(best[1]), "confidence": round(best[0], 2)}
    return None


def _current() -> dict[str, Any]:
    """The index, rebuilt when the site mapping changed since it was built (raw still in memory)."""
    with _lock:
        _load_disk()
    try:
        from app.services import topology_org_service as org

        raw = org.raw_devices()
    except Exception:  # noqa: BLE001
        raw = None
    if raw is not None:
        reg = site_registry.registry()
        with _lock:
            stale = _index.get("raw_at") != raw.get("generated_at") or _index.get("reg") != reg.version
        if stale:
            rebuild(raw)
    with _lock:
        return dict(_index)


def hint() -> dict[str, Any] | None:
    """{"needs_unscoped": {source: n}} from the latest index; None when there is none yet."""
    idx = _current()
    if not idx.get("built_at") or not idx.get("hint"):
        return None
    if time.time() - idx["built_at"] > 24 * 3600:
        return None
    return idx["hint"]


def unassigned() -> list[dict[str, Any]]:
    return list(_current().get("unassigned") or [])


def ready() -> bool:
    return bool(_current().get("built_at"))


def _match(n: dict[str, Any], q: str, bare: str) -> tuple[int, str, str, str] | None:
    """(score, field, value, source) of the best match of one node; None when nothing matches."""
    name = str(n.get("name") or "")
    low = name.lower()
    if low == q:
        return (100, "name", name, (n.get("sources") or [""])[0])
    if low.startswith(q):
        return (90, "name", name, (n.get("sources") or [""])[0])
    for r in n.get("records") or []:
        rn = str(r.get("name") or "")
        if rn.lower() == q or (rn.lower().startswith(q) and rn != name):
            return (85, "record_name", rn, r.get("source", ""))
    for m in n.get("members") or []:
        mn = str(m.get("name") or "")
        if mn and (mn.lower() == q or mn.lower().startswith(q)):
            return (84, "member_name", mn, "")
    for ip in [n.get("mgmt_ip") or "", *(n.get("ips") or [])]:
        if ip and (ip == q or (ip.startswith(q) and re.match(r"^[0-9a-f.:]+$", q))):
            return (88 if ip == q else 70, "ip", ip, "")
    if len(bare) >= 4:
        for m in n.get("macs") or []:
            if m and bare in m:
                return (87 if m == bare else 68, "mac", m, "")
    serials = [("serial", n.get("serial") or "")] + [("serial", r.get("serial") or "") for r in n.get("records") or []]
    serials += [("member_serial", m.get("serial") or "") for m in n.get("members") or []]
    for field, sn in serials:
        if sn and q in sn.lower():
            return (86 if sn.lower() == q else 66, field, sn, "")
    if q in low:
        return (60, "name", name, (n.get("sources") or [""])[0])
    for r in n.get("records") or []:
        rn = str(r.get("name") or "")
        if q in rn.lower():
            return (55, "record_name", rn, r.get("source", ""))
    for m in n.get("members") or []:
        mn = str(m.get("name") or "")
        if mn and q in mn.lower():
            return (54, "member_name", mn, "")
    model = str(n.get("model") or "")
    if len(q) >= 3 and q in model.lower():
        return (40, "model", model, "")
    return None


def search(q: str, limit: int = 50) -> dict[str, Any]:
    """Organisation-wide device search from the cached index (never calls a source)."""
    q = str(q or "").strip().lower()
    limit = max(1, min(int(limit or 50), 500))
    idx = _current()
    out = {
        "results": [],
        "total": 0,
        "index_built_at": idx.get("built_at") or None,
        "building": not idx.get("built_at"),
    }
    if not idx.get("built_at"):
        try:  # nothing indexed yet: start the organisation read the index is built from
            from app.services import topology_org_service as org

            org.swr().refresh("")
        except Exception:  # noqa: BLE001
            pass
    if not q:
        return out
    bare = re.sub(r"[^0-9a-f]", "", q) if re.match(r"^[0-9a-f:.\-]+$", q) else ""
    hits = []
    for n in idx.get("nodes") or []:
        m = _match(n, q, bare)
        if m:
            hits.append((m, n))
    hits.sort(key=lambda h: (-h[0][0], str(h[1].get("name") or "").lower()))
    out["total"] = len(hits)
    out["results"] = [
        {
            "node_id": n["id"],
            "name": n.get("name") or "",
            "role": n.get("role") or "unknown",
            "status": n.get("status") or "unknown",
            "model": n.get("model") or "",
            "mgmt_ip": n.get("mgmt_ip") or "",
            "site_key": n.get("site_key") or "",
            "site_name": n.get("site_name") or "",
            "match_field": field,
            "match_value": value,
            "source": source or (n.get("sources") or [""])[0],
        }
        for (_score, field, value, source), n in hits[:limit]
    ]
    return out


def clear() -> None:
    with _lock:
        _index.update(
            built_at=0.0, nodes=[], hint=None, unassigned=[], reg="", raw_at=None, records={}, bare={}, ips={}
        )


# --------------------------------------------------------------------------- lookups for the WAN section


class Lookups:
    """Organisation index read once per build: device record / IP → canonical site, site names."""

    def __init__(self) -> None:
        idx = _current()
        self.records: dict[str, str] = dict(idx.get("records") or {})
        self.bare: dict[str, str] = dict(idx.get("bare") or {})
        self.ips: dict[str, str] = dict(idx.get("ips") or {})
        self.reg = site_registry.registry()

    def _named(self, ck: str) -> tuple[str, str]:
        return (ck, self.reg.name(ck)) if ck else ("", "")

    def site_of_record(self, source: str, key: str) -> tuple[str, str]:
        return self._named(self.records.get(f"{source}:{key}") or self.bare.get(key) or "")

    def site_of_ip(self, ip: str) -> tuple[str, str]:
        ip = topo._ip(ip)
        if not ip:
            return "", ""
        return self._named(self.ips.get(ip) or self.reg.from_subnet(ip))


def site_of_record(source: str, key: str) -> tuple[str, str]:
    """(canonical site, name) of a device record anywhere in the organisation ('' when unknown)."""
    return Lookups().site_of_record(source, key)


def site_of_ip(ip: str) -> tuple[str, str]:
    return Lookups().site_of_ip(ip)


def hub_sites() -> set[str]:
    """Canonical keys of hub sites from the last organisation map (never builds one)."""
    try:
        from app.services import topology_org_service as org

        have = org.swr().peek("")
    except Exception:  # noqa: BLE001
        return set()
    return {s["key"] for s in (have[1].get("sites") or []) if s.get("hub")} if have else set()


# --------------------------------------------------------------------------- LAN prefixes per site

SUBNET_REFRESH_S = 30 * 60.0
MAX_ROUTE_DEVICES = 400
ROUTE_WORKERS = 4
_subnet_lock = threading.Lock()
_ROUTE_ROLES = {"sdwan_edge", "router", "firewall"}
# Placements trusted to teach the prefix index (never "subnet", nor an HA peer that may follow one).
_TRUSTED_VIA = {"site", "manual", "name", "lldp", "hostname"}
_TRUSTED_IFACE_VIA = {"site", "manual", "name", "lldp"}
_MGMT_ROLES = {"switch", "sdwan_edge", "router"}  # boxes whose management address sits in a site LAN
LOCAL_PROTOCOLS = topo.LOCAL_PROTOCOLS
is_local_route = topo.is_local_route


def refresh_subnets_async(
    devices: list[Any],
    place: dict[str, tuple[str, str]],
    *,
    force: bool = False,
    circuits: list[Any] | None = None,
    complete: bool = True,
) -> bool:
    """Rebuild the site prefix index in the background (at most every ``SUBNET_REFRESH_S``; at once when the
    stored index predates the current inputs)."""
    fresh_enough = time.time() - site_registry.subnets_built_at() < SUBNET_REFRESH_S
    if not force and fresh_enough and site_registry.subnets_schema() >= site_registry.SUBNET_SCHEMA:
        return False
    if not _subnet_lock.acquire(blocking=False):
        return False

    def run() -> None:
        try:
            refresh_subnets(devices, place, circuits, complete=complete)
        except Exception as exc:  # noqa: BLE001 - placement by subnet is a nicety
            log.info("topology: site prefix index not rebuilt: %s", exc)
        finally:
            _subnet_lock.release()

    threading.Thread(target=run, name="topology-subnets", daemon=True).start()
    return True


_route_counts: dict[str, dict[str, int]] = {}
_iface_cache: dict[tuple[str, str], tuple[float, list[Any]]] = {}
IFACE_CACHE_S = 2 * SUBNET_REFRESH_S + 60.0  # interfaces barely change: one read serves two index refreshes
_WAN_RELABEL = ("connected", "lan-next-hop", "interfaces", "device-addresses")
_CGNAT = ipaddress.ip_network("100.64.0.0/10")


def route_counts() -> dict[str, dict[str, int]]:
    """Per source: routes read for the prefix index — total / local / lan-next-hop / overlay (diagnostics)."""
    return {k: dict(v) for k, v in _route_counts.items()}


def refresh_subnets(
    devices: list[Any],
    place: dict[str, tuple[str, str]],
    circuits: list[Any] | None = None,
    *,
    complete: bool = True,
) -> dict[str, str]:
    """Prefixes per canonical site, vendor-neutral, from devices placed by a trusted method only:

    * ``connected``: routing devices' local routes and the networks of their own interfaces (INTERFACES);
    * ``lan-next-hop``: routes via a next hop on one of those networks (static / OSPF / BGP to a switch or
      firewall behind the router) — the site's LAN;
    * ``device-addresses``: the /24 around every distinct private address of a placed device (management IP,
      ``Device.addresses``, LAN-side interface addresses);
    * ``wan-addresses``: the /24 around a private ``Circuit.ip`` (not CGNAT) — it still places a box (a
      firewall in front of an edge) but never counts as a site LAN or joins sites;
    * ``interfaces``: interface networks of layer-3 builds already in memory.
    WAN / management ports, circuit networks, default routes, public / link-local networks are never LANs
    (``topology_service.WanSide``). Ambiguous prefixes (two sites) are dropped; a failed read keeps that
    device's previous share."""
    import ipaddress
    from concurrent.futures import ThreadPoolExecutor

    from app.integrations.connectors import sdk
    from app.integrations.contracts import INTERFACES, ROUTES

    started = time.monotonic()
    cands: list[tuple[str, str, str]] = []
    by_rk = {f"{d.source}:{d.key}": d for d in devices}

    current = site_registry.current_registry()
    base = current.base() if current is not None else None

    def trusted(d: Any) -> str:
        """The device's site as the registry *without learned joins* sees it: the index never feeds the
        joins it implies back to themselves."""
        ck, via = place.get(f"{d.source}:{d.key}", ("", ""))
        if not ck or via not in _TRUSTED_VIA:
            return ""
        if base is None:
            return ck
        own = str(getattr(d, "site_key", "") or "") if via == "site" else ""
        return base.resolve(own) or base.resolve(ck) or ck

    routers = [d for d in devices if d.role in _ROUTE_ROLES and trusted(d)][:MAX_ROUTE_DEVICES]
    route_src = {c.provider_id: c for c in sdk.sources(ROUTES)}
    iface_src = {c.provider_id: c for c in sdk.sources(INTERFACES)}
    failed: set[str] = set()  # origins whose read failed: their previous prefixes are kept
    counts: dict[str, Counter] = defaultdict(Counter)

    def interfaces_of(c: Any, d: Any) -> list[Any]:
        key = (d.source, d.key)
        hit = _iface_cache.get(key)
        if hit and time.time() - hit[0] < IFACE_CACHE_S:
            return hit[1]
        rows = list(c.list_interfaces(d.key) or [])
        _iface_cache[key] = (time.time(), rows)
        return rows

    def one(d: Any) -> list[tuple[str, str, str]]:
        ck = trusted(d)
        rk = f"{d.source}:{d.key}"
        origin, nh_origin = f"connected|{rk}", f"lan-next-hop|{rk}"
        routes: list[Any] = []
        itfs: list[Any] = []
        if d.source in route_src:
            try:
                routes = list(route_src[d.source].list_routes(d.key) or [])
            except Exception as exc:  # noqa: BLE001
                log.info("topology: routes of %s unavailable for the prefix index: %s", d.name, exc)
                failed.update((origin, nh_origin, f"routes|{rk}"))
        if d.source in iface_src:
            try:
                itfs = interfaces_of(iface_src[d.source], d)
            except Exception as exc:  # noqa: BLE001
                log.info("topology: interfaces of %s unavailable for the prefix index: %s", d.name, exc)
                failed.add(origin)
        keys = {d.key, rk}
        names = {str(d.name or "").lower(), *[str(x).lower() for x in getattr(d, "aliases", None) or []]} - {""}
        wan = topo.WanSide(itfs, *topo.circuit_wan(circuits, d.source, d.key))
        connected = topo.interface_nets(itfs, wan)
        out = []
        c = counts[d.source]
        for r in routes:
            c["total"] += 1
            remote = topo.route_is_remote(r, keys, names)
            if remote or str(getattr(r, "protocol", "") or "").lower() in topo._OVERLAY_PROTOCOLS:
                c["overlay"] += 1
            if not topo.is_local_route(r) or remote:
                continue
            net = topo.lan_route(r, wan)
            if net is None:
                c["wan_or_public"] += 1
                continue
            c["local"] += 1
            out.append((str(net), ck, origin))
        for net, _name in connected:
            if 16 <= net.prefixlen <= 30:
                out.append((str(net), ck, origin))
        hops = topo.lan_next_hops(routes, keys, names, connected, wan)
        c["lan_next_hop"] += len(hops)
        for prefix, _hop, _itf in hops:
            try:
                net = ipaddress.ip_network(prefix, strict=False)
            except ValueError:
                continue
            if topo._lan_net(net) and not wan.covers(net):
                out.append((str(net), ck, nh_origin))
        for itf in itfs:  # LAN-side interface addresses are addresses of this device too
            if itf.name in wan.ifaces or topo.wan_side(itf, wan.ifaces):
                continue  # WAN ports: only an explicit circuit record says where its address sits
            for cidr in getattr(itf, "ips", None) or []:
                ip = topo._ip(cidr)
                if ip:
                    extra_ips.append((ip, ck))
        return out

    extra_ips: list[tuple[str, str]] = []
    wan_book: list[tuple[str, str]] = []  # WAN-side addresses: place boxes, never a site LAN
    if routers:
        with ThreadPoolExecutor(
            max_workers=min(ROUTE_WORKERS, len(routers)), thread_name_prefix="topology-routes"
        ) as pool:
            for part in pool.map(one, routers):
                cands += part
    # Address book: the /24 around every distinct private address of a placed device.
    shared = set(site_registry.shared_ips()) | set(site_registry.DEFAULT_MGMT_IPS)
    book: list[tuple[str, str]] = list(extra_ips)
    for d in devices:
        ck = trusted(d)
        if not ck:
            continue
        for ip in [d.mgmt_ip, *(getattr(d, "addresses", None) or [])]:
            ip = topo._ip(ip)
            if ip:
                book.append((ip, ck))
    circuit_ips: dict[str, set[Any]] = defaultdict(set)
    for c in circuits or []:
        c = topo.circuit_dict(c)
        if c is None:
            continue
        d = by_rk.get(f"{c.get('source')}:{c.get('device_key')}") or next(
            (x for x in devices if x.key == c.get("device_key")), None
        )
        ck = trusted(d) if d is not None else ""
        ip = topo._ip(c.get("ip"))
        if ck and ip:
            wan_book.append((ip, ck))
            circuit_ips[ck].add(ipaddress.ip_address(ip))
    for rows, origin_kind in ((book, "device-addresses"), (wan_book, "wan-addresses")):
        for ip, ck in rows:
            if ip in shared or not topo._lan_private(ip):
                continue
            if origin_kind == "wan-addresses" and ipaddress.ip_address(ip) in _CGNAT:
                continue  # carrier-assigned: says nothing about the site
            net = ipaddress.ip_network(f"{ip}/24", strict=False) if ":" not in ip else None
            if net is not None:
                cands.append((str(net), ck, origin_kind))
    with topo._cache_lock:  # interface prefixes of layer-3 builds already in memory
        graphs = [(k, v[1]) for k, v in topo._cache.items()]
        sides = {k: dict(v) for k, v in topo._iface_side.items()}
    if not sides:  # no layer-3 build in memory (e.g. just restarted): keep what interfaces taught before
        failed.add("interfaces")
    for key, graph in graphs:
        site, _l3 = topo._split_scope(key)
        node_site = {
            n["id"]: n.get("site_key")
            for n in graph.get("nodes", [])
            if n.get("site_key") and n.get("site_via") in _TRUSTED_IFACE_VIA
        }
        for nid, itfs in (sides.get(site) or {}).items():
            ck = node_site.get(nid)
            for net, _n in topo.interface_nets(itfs) if ck else ():
                if 16 <= net.prefixlen <= 30:
                    cands.append((str(net), ck, "interfaces"))
    # A claim that equals or contains a circuit address of that same site is the WAN transit network
    # (e.g. between a firewall and the edge behind it): kept only as a WAN address (placement, never a LAN).
    if circuit_ips:
        relabeled = []
        for prefix, ck, origin in cands:
            if origin.split("|", 1)[0] in _WAN_RELABEL and circuit_ips.get(ck):
                try:
                    net = ipaddress.ip_network(prefix, strict=False)
                except ValueError:
                    continue
                if any(ip.version == net.version and ip in net for ip in circuit_ips[ck]):
                    relabeled.append((prefix, ck, "wan-addresses"))
                    continue
            relabeled.append((prefix, ck, origin))
        cands = relabeled
    out, changed = site_registry.set_subnets(cands, keep=failed)
    _route_counts.clear()
    _route_counts.update({k: dict(v) for k, v in counts.items()})
    log.info(
        "topology: site prefix index: %d prefixes from %d routing devices in %d ms; routes %s",
        len(out),
        len(routers),
        round((time.monotonic() - started) * 1000),
        {k: dict(v) for k, v in counts.items()} or "none read",
    )
    try:  # single-source sites living inside another site's prefixes are the same place
        links = site_registry.learn_site_links(site_registry.registry(links=False), devices, place)
        if site_registry.add_site_links(links, via="subnet", complete=complete):
            changed = True
            log.info("topology: site joins from subnet evidence updated (%d current)", len(links))
    except Exception as exc:  # noqa: BLE001
        log.info("topology: site joins from subnets skipped: %s", exc)
    if changed:
        topo.invalidate()  # only when the effective index changed: devices may move to their address's site
    return out


UNPLACED_LOG_S = 30 * 60.0
UNPLACED_LOG_MAX = 30
_unplaced_logged = {"at": 0.0}


def log_unplaced(reg: Any, devices: list[Any], place: dict[str, tuple[str, str]]) -> None:
    """Every device still without a site (firewalls first): its evidence and why no site took it.
    At most ``UNPLACED_LOG_MAX`` lines, once per ``UNPLACED_LOG_S``."""
    if time.time() - _unplaced_logged["at"] < UNPLACED_LOG_S:
        return
    rows = [d for d in devices if not place.get(f"{d.source}:{d.key}", ("", ""))[0]]
    if not rows:
        return
    _unplaced_logged["at"] = time.time()
    rows.sort(key=lambda d: (d.role != "firewall", str(d.name).lower()))
    for d in rows[:UNPLACED_LOG_MAX]:
        why = site_registry.explain_unplaced(reg, d)
        serial = str(d.serial or "")
        log.info(
            "topology: unplaced %s %s (serial …%s, %s): evidence %s; best candidate %s — %s",
            d.role,
            d.name,
            serial[-4:] if serial else "—",
            d.source,
            ", ".join(why["evidence"]) or "none",
            why["candidate"] or "none",
            why["reason"],
        )
    if len(rows) > UNPLACED_LOG_MAX:
        log.info("topology: … and %d more unplaced device(s)", len(rows) - UNPLACED_LOG_MAX)


# --------------------------------------------------------------------------- site mapping API


def site_map_view() -> dict[str, Any]:
    """GET /api/v1/topology/site-map: canonical sites, every connector site with its mapping and a
    suggestion, unassigned devices (with a suggested site) and devices placed without a site key."""
    reg = site_registry.registry()
    user = site_registry.user_map()
    idx = _current()
    placed = [
        {
            "node_id": n["id"],
            "name": n.get("name") or "",
            "role": n.get("role") or "",
            "site_key": n.get("site_key") or "",
            "site_name": n.get("site_name") or "",
            "via": n.get("site_via") or "",
            "record_keys": [f"{r['source']}:{r['key']}" for r in n.get("records") or []],
        }
        for n in idx.get("nodes") or []
        if n.get("site_via") in ("manual", "lldp", "hostname", "name", "subnet", "naming", "ha_peer", "ha_name")
    ]
    return {
        **reg.describe(),
        "mappings": dict(user.get("mappings") or {}),
        "device_sites": dict(user.get("device_sites") or {}),
        "ha_partners": dict(user.get("ha_partners") or {}),
        "updated_at": user.get("updated_at"),
        "unassigned_devices": list(idx.get("unassigned") or []),
        "placed_devices": placed,
        "index_built_at": idx.get("built_at") or None,
    }


def update_site_map(
    mappings: dict[str, Any] | None,
    device_sites: dict[str, Any] | None,
    ha_partners: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """PUT /api/v1/topology/site-map: merge the user's mappings, then mark every map out of date."""
    site_registry.save_user_map(mappings, device_sites, ha_partners)
    topo.invalidate()
    # Never list sites inside the request: /sites answers from cache (marked stale by invalidate())
    # and is rebuilt in the background; the view below is built from cached site lists too.
    topo._refresh_sites_async()
    try:
        from app.services import topology_health_service as health
        from app.services import topology_org_service as org

        org.swr().invalidate()
        health.clear_cache()
    except Exception as exc:  # noqa: BLE001
        log.info("topology: caches not reset after a site-map change: %s", exc)
    return site_map_view()
