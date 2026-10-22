"""Path trace (v0.10.17, topology phase 3): "how does traffic from A reach B, and is it allowed?"

Vendor-neutral and read-only. It walks the topology graph built by ``topology_service`` and asks the
connected sources only through capabilities:

    ENDPOINT_LOCATE  locate_endpoint(ip=, mac=)  → the switch port / AP an endpoint is attached to
    ARP_TABLE        list_arp()                  → IP ↔ MAC (+ which L3 box knows it) — fallback
    MAC_TABLE        list_mac_table(dev)         → which switch port learned a MAC — fallback
    INTERFACES       list_interfaces(dev)        → interface subnets (who is the gateway) and zones
    ROUTES           list_routes(dev)            → longest-prefix match at every L3 hop (VRF aware)
    POLICY_LOOKUP    policy_lookup(dev, …)       → allow / deny + rule at every firewall
    TUNNELS          list_tunnels()              → the overlay a route egresses through, far side

Walk
1. Locate source and destination (IP, MAC or host name): ENDPOINT_LOCATE across sources; else ARP
   then MAC tables; an address of a device on the map is that device.
2. Layer 2 from the source's access switch / AP up the physical links (LLDP/LAG/inferred) to its
   gateway: the L3 device owning the source's subnet (interface addresses), or the box whose ARP
   table holds the source.
3. At every L3 hop: destination directly connected? deliver. Otherwise the longest-prefix route
   (in the ingress interface's VRF when known). Firewalls: POLICY_LOOKUP with the zones of the ingress
   and egress interfaces → stop on deny. A route out of a tunnel (or via an SD-WAN peer) picks the
   best overlay to the peer (state, loss, latency) and continues on the far side.
4. Layer 2 down from the last L3 hop to the destination's access port.

Never invents a hop: anything unknown ends the walk with a plain-English gap ("no routes from
HQ-FW-A — connect its management system …") and a partial verdict. Loops and runaway paths are
guarded (visited set, ``MAX_HOPS``).
"""

from __future__ import annotations

import ipaddress
import logging
import re
import socket
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout
from typing import Any

from app.integrations.connectors import sdk
from app.integrations.contracts import (
    ARP_TABLE,
    ENDPOINT_LOCATE,
    INTERFACES,
    MAC_TABLE,
    POLICY_LOOKUP,
    ROUTES,
    TUNNELS,
)
from app.integrations.domain import normalize_mac
from app.services import topology_service as topo

log = logging.getLogger("nodewatch.topology.trace")

MAX_HOPS = 30
MAX_L2_DEPTH = 10
MAX_DEVICE_CALLS = 80  # per capability, per trace
MAX_MAC_TABLE_CALLS = 40
DNS_TIMEOUT_S = 2.0
PROTOCOLS = ("tcp", "udp", "icmp", "any")
L3_ROLES = {"firewall", "router", "sdwan_edge"}
_L2_TRANSIT = {"switch", "unknown", "wireless_ap"}
_HOST_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,252})$")
_DENY = ("deny", "drop", "reset", "block", "reject")
_DEFAULT_VRFS = ("", "0", "default", "global", "main", "inet.0", "master")
_TUNNEL_PROTOCOLS = ("sdwan", "overlay", "ipsec", "tunnel", "bgp-overlay")


# Long-lived pools: a ``with ThreadPoolExecutor()`` block would wait for a hung DNS lookup on exit,
# so the timeout would never take effect. A stuck lookup only occupies one worker until the OS gives up.
_DNS_POOL = ThreadPoolExecutor(max_workers=2, thread_name_prefix="trace-dns")
_FETCH_POOL = ThreadPoolExecutor(max_workers=6, thread_name_prefix="trace-fetch")


def resolve_hostname(name: str) -> str:
    """Host name → first IPv4/IPv6 address ('' when it does not resolve within DNS_TIMEOUT_S)."""
    fut = _DNS_POOL.submit(socket.getaddrinfo, name, None)
    try:
        infos = fut.result(timeout=DNS_TIMEOUT_S)
    except (FutureTimeout, OSError, UnicodeError):
        fut.cancel()
        return ""
    for info in infos:
        addr = info[4][0]
        if topo._ip(addr):
            return topo._ip(addr)
    return ""


def norm_vrf(value: Any) -> str:
    """VRF / virtual-router name, compared the same way on routes and interfaces ('' = default)."""
    text = str(value or "").strip().lower()
    return "" if text in _DEFAULT_VRFS else text


def interface_vrf(itf: Any) -> str | None:
    """VRF of an interface (``Interface.vrf``; older connectors: vendor extras); None when unknown."""
    if getattr(itf, "vrf", ""):
        return norm_vrf(itf.vrf)
    # transition fallback (v0.10.24): remove when all connectors fill Interface.vrf
    v = getattr(itf, "vendor", None) or {}
    # transition fallback (v0.10.24): remove when all connectors fill Interface.vrf
    for k in ("vrf", "virtual_router"):
        if v.get(k) not in (None, ""):
            return norm_vrf(v.get(k))
    return None


def _net(cidr: Any) -> ipaddress.IPv4Interface | ipaddress.IPv6Interface | None:
    try:
        return ipaddress.ip_interface(str(cidr).strip())
    except ValueError:
        return None


def _in(ip: str, network: Any) -> bool:
    try:
        return ipaddress.ip_address(ip) in network
    except (ValueError, TypeError):
        return False


# --------------------------------------------------------------------------- trace context


class _Ctx:
    """One trace: the graph, lazily-read per-device tables, and the gaps found on the way."""

    def __init__(self, site: str | None, thresholds: Any) -> None:
        self.site = site
        self.thresholds = thresholds
        self.status = topo._Sources()
        self.gaps: list[str] = []
        self.widened = site is None
        self.graph = topo.graph_for(site, l3=True)
        self._index()
        self._ifaces: dict[str, list[Any]] = {}
        self._iface_covered: dict[str, bool] = {}
        self._routes: dict[str, list[Any] | None] = {}
        self._arp: list[Any] | None = None
        self._tunnels: list[Any] | None = None
        self._l3_table: list[tuple[Any, str, str, Any]] | None = None
        self._by_if_ip: dict[str, list[tuple[str, str]]] = {}
        self._far: dict[str, str] = {}
        self._health: dict[str, dict[str, Any]] = {}
        self.calls: dict[str, int] = {}
        self._seed_interfaces()

    # ---- graph -----------------------------------------------------------------------------
    def _index(self) -> None:
        self.nodes: dict[str, dict[str, Any]] = {n["id"]: n for n in self.graph.get("nodes", [])}
        self.alias: dict[str, str] = {}
        self.by_mac: dict[str, str] = {}
        self.by_ip: dict[str, list[str]] = {}
        self.adj: dict[str, list[tuple[str, dict[str, Any]]]] = {}
        for n in self.nodes.values():
            for rec in n.get("records", []):
                self.alias[f"{rec['source']}:{rec['key']}"] = n["id"]
                self.alias.setdefault(rec["key"], n["id"])
            for m in n.get("macs", []):
                self.by_mac.setdefault(m, n["id"])
            for ip in {*n.get("ips", []), topo._ip(n.get("mgmt_ip"))} - {""}:
                self.by_ip.setdefault(ip, []).append(n["id"])
        for link in self.graph.get("links", []):
            for x, y in ((link["a_device"], link["b_device"]), (link["b_device"], link["a_device"])):
                self.adj.setdefault(x, []).append((y, link))

    def widen(self) -> bool:
        """Switch to the whole-network graph (the far side of a tunnel is at another site)."""
        if self.widened:
            return False
        self.widened = True
        try:
            self.graph = topo.graph_for(None, l3=True)
        except Exception as exc:  # noqa: BLE001
            self.gap(f"The rest of the network could not be read: {exc}")
            return False
        self._index()
        self._seed_interfaces()  # interface lists already read stay valid: node ids are stable
        self._l3_table = None
        self._far.clear()
        return True

    def _seed_interfaces(self) -> None:
        """Reuse interface lists the topology build already read for this scope (no new calls)."""
        for nid, items in topo.gathered_interfaces(None if self.widened and not self.site else self.site).items():
            self._ifaces.setdefault(nid, list(items))
        if self.widened and self.site:
            for nid, items in topo.gathered_interfaces(None).items():
                self._ifaces.setdefault(nid, list(items))

    def gap(self, text: str) -> None:
        if text and text not in self.gaps:
            self.gaps.append(text)

    def name(self, nid: str) -> str:
        return str(self.nodes.get(nid, {}).get("name") or nid)

    def node_for_key(self, source: str, key: str, mac: str = "") -> str:
        return self.alias.get(f"{source}:{key}") or self.alias.get(key) or self.by_mac.get(topo.valid_mac(mac)) or ""

    def sites(self, nid: str) -> list[str]:
        return self.nodes.get(nid, {}).get("site_keys", [])

    def node_by_name(self, text: str) -> str:
        h = topo.norm_host(text)
        if h:
            hits = [nid for nid, n in self.nodes.items() if topo.norm_host(n["name"]) == h and not n.get("synthetic")]
        else:  # very short names ("R1") only match exactly
            want = str(text or "").strip().lower()
            hits = [
                nid
                for nid, n in self.nodes.items()
                if str(n["name"]).strip().lower() == want and not n.get("synthetic")
            ]
        return hits[0] if len(hits) == 1 else ""

    def manager_hint(self, nid: str) -> str:
        n = self.nodes.get(nid, {})
        vendor = n.get("vendor_name") or ""
        return f"connect its {vendor + ' ' if vendor else ''}management system under Settings › Connections"

    # ---- per-device tables (lazy, bounded) ---------------------------------------------------
    def _budget(self, cap: str) -> bool:
        self.calls[cap] = self.calls.get(cap, 0) + 1
        return self.calls[cap] <= MAX_DEVICE_CALLS

    def _interface_jobs(self, nid: str) -> list[tuple[Any, str]]:
        node = self.nodes.get(nid, {})
        return [
            (c, rec["key"])
            for c in sdk.sources(INTERFACES)
            for rec in node.get("records", [])
            if rec["source"] == c.provider_id
        ]

    def _budget_gap(self) -> None:
        self.gap(
            f"Interface addresses of some routing devices were not read (limit of {MAX_DEVICE_CALLS} devices "
            "per trace) — a gateway or next hop among them may be missed."
        )

    def interfaces(self, nid: str) -> list[Any]:
        if nid in self._ifaces:
            return self._ifaces[nid]
        jobs = self._interface_jobs(nid)
        if jobs and self.calls.get(INTERFACES, 0) + len(jobs) > MAX_DEVICE_CALLS:
            self._budget_gap()
            return []  # not cached: a later call (after widening, say) may still read it
        out: list[Any] = []
        for c, key in jobs:
            self._budget(INTERFACES)
            out += self.status.call(c, INTERFACES, lambda c=c, k=key: c.list_interfaces(k))
        self._ifaces[nid] = out
        self._iface_covered[nid] = bool(jobs)
        return out

    def _prefetch_interfaces(self, nids: list[str]) -> None:
        """Read missing interface lists in parallel (pool of 6), within the per-trace budget."""
        jobs: list[tuple[str, Any, str]] = []
        skipped = False
        for nid in nids:
            if nid in self._ifaces:
                continue
            mine = self._interface_jobs(nid)
            if not mine:
                continue
            if self.calls.get(INTERFACES, 0) + len(mine) > MAX_DEVICE_CALLS:
                skipped = True
                continue
            for c, key in mine:
                self._budget(INTERFACES)
                jobs.append((nid, c, key))
        if skipped:
            self._budget_gap()
        if not jobs:
            return

        def fetch(c: Any, key: str) -> tuple[list[Any] | None, BaseException | None]:
            try:
                return list(c.list_interfaces(key) or []), None
            except BaseException as exc:  # noqa: BLE001 - reported through the source bookkeeping below
                return None, exc

        futures = [(nid, c, _FETCH_POOL.submit(fetch, c, key)) for nid, c, key in jobs]
        got: dict[str, list[Any]] = {}
        for nid, c, fut in futures:
            rows, err = fut.result()

            def replay(rows: list[Any] | None = rows, err: BaseException | None = err) -> list[Any]:
                if err is not None:
                    raise err
                return rows or []

            got.setdefault(nid, []).extend(self.status.call(c, INTERFACES, replay))
        for nid, rows in got.items():
            self._ifaces[nid] = rows
            self._iface_covered[nid] = True

    def interface(self, nid: str, name: str) -> Any:
        want = topo.norm_if(name)
        if not want:
            return None
        return next((i for i in self.interfaces(nid) if topo.norm_if(i.name) == want), None)

    def routes(self, nid: str) -> list[Any] | None:
        """Routes of a node; None when no connected source can report them."""
        if nid in self._routes:
            return self._routes[nid]
        node = self.nodes.get(nid, {})
        out: list[Any] = []
        covered = False
        for c in sdk.sources(ROUTES):
            for rec in node.get("records", []):
                if rec["source"] != c.provider_id or not self._budget(ROUTES):
                    continue
                covered = True
                out += self.status.call(c, ROUTES, lambda c=c, k=rec["key"]: c.list_routes(k))
        self._routes[nid] = out if covered else None
        return self._routes[nid]

    def arp(self) -> list[Any]:
        if self._arp is None:
            self._arp = self.status.gather(ARP_TABLE, "list_arp", None)
        return self._arp

    def tunnels(self) -> list[Any]:
        if self._tunnels is None:
            self._tunnels = self.status.gather(TUNNELS, "list_tunnels", None)
        return self._tunnels

    def l3_table(self) -> list[tuple[Any, str, str, Any]]:
        """[(ip_interface, node id, interface name, Interface)] for every box that may route."""
        if self._l3_table is not None:
            return self._l3_table
        rows: list[tuple[Any, str, str, Any]] = []
        candidates = [
            nid
            for nid, n in self.nodes.items()
            if not n.get("synthetic")
            and n.get("records")
            and (n["role"] in L3_ROLES or (n["role"] == "switch" and n.get("tier", 5) <= 3))
        ]
        self._prefetch_interfaces(candidates)
        seen: set[tuple[str, str, str]] = set()

        def add(nid: str, itf: Any) -> None:
            for cidr in itf.ips or []:
                net = _net(cidr)
                ident = (nid, topo.norm_if(itf.name), str(net))
                if net is not None and ident not in seen:
                    seen.add(ident)
                    rows.append((net, nid, itf.name, itf))

        for nid in candidates:
            for itf in self._ifaces.get(nid, []):
                add(nid, itf)
        for nid, itf in self._health_interface_ips():  # addresses a health source reported
            add(nid, itf)
        self._by_if_ip = {}
        for net, nid, ifname, _itf in rows:
            self._by_if_ip.setdefault(str(net.ip), []).append((nid, ifname))
        self._l3_table = rows
        return rows

    def _health_interface_ips(self) -> list[tuple[str, Any]]:
        from app.services import topology_health_service as th

        raw = th.cached_raw(self.site or "")
        out = []
        for itf in (raw or {}).get("interfaces", []):
            if itf.ips:
                nid = self.node_for_key(itf.source, itf.device_key)
                if nid:
                    out.append((nid, itf))
        return out

    def subnet_owner(self, ip: str, near: str = "") -> tuple[str, str, Any] | None:
        """(node, interface, network) of the longest subnet containing ``ip`` (the gateway)."""
        best = None
        near_sites = self.sites(near) if near else []
        for net, nid, ifname, _itf in self.l3_table():
            if net.network.prefixlen >= net.network.max_prefixlen or not _in(ip, net.network):
                continue  # /32 host routes and loopbacks are not a subnet
            local = topo._sites_ok(self.sites(nid), near_sites) if near_sites else True
            rank = (
                net.network.prefixlen,
                1 if local else 0,
                1 if self.nodes[nid]["role"] in ("firewall", "router") else 0,
                -topo.ha_rank(self.nodes[nid]),  # the active unit of an HA pair
            )
            if best is None or rank > best[0]:
                best = (rank, nid, ifname, net.network)
        return (best[1], best[2], best[3]) if best else None

    def ip_owner(self, ip: str, near: str = "") -> tuple[str, str]:
        """(node, interface) that has ``ip`` configured; ('', '') when unknown."""
        near_sites = self.sites(near) if near else []
        self.l3_table()
        hits = list(self._by_if_ip.get(ip, []))
        hits += [(nid, "") for nid in self.by_ip.get(ip, [])]
        if near_sites and topo._private(ip):
            local = [h for h in hits if topo._sites_ok(self.sites(h[0]), near_sites)]
            hits = local or hits
        hits.sort(key=lambda h: topo.ha_rank(self.nodes.get(h[0])))  # an HA pair answers through its active unit
        return hits[0] if hits else ("", "")

    def connected_net(self, nid: str, ip: str) -> tuple[str, Any] | None:
        best = None
        for itf in self.interfaces(nid):
            for cidr in itf.ips or []:
                net = _net(cidr)
                if net is None or net.network.prefixlen >= net.network.max_prefixlen:
                    continue
                if _in(ip, net.network) and (best is None or net.network.prefixlen > best[1].prefixlen):
                    best = (itf.name, net.network)
        return best

    def zone(self, nid: str, ifname: str) -> str:
        itf = self.interface(nid, ifname) if ifname else None
        return str(getattr(itf, "zone", "") or "")

    def health(self, nid: str) -> dict[str, Any]:
        """Live health of a node (its site's snapshot), {} when unavailable."""
        from app.services import topology_health_service as th

        node = self.nodes.get(nid, {})
        scope = self.site or "" if not self.widened else node.get("site_key") or (self.site or "")
        if scope not in self._health:
            try:
                raw, _ = th.collect(scope)
                self._health[scope] = th.evaluate(raw, self.thresholds)
            except Exception as exc:  # noqa: BLE001 - health is a nicety on a trace
                log.info("trace: health for %s unavailable: %s", scope or "all", exc)
                self._health[scope] = {}
        snap = self._health[scope]
        h = (snap.get("nodes") or {}).get(nid)
        if not h:
            return {}
        return {"state": h["state"], "badge": h["badge"], "reasons": h["reasons"][:4], "metrics": h["metrics"]}

    def link_health(self, key: str) -> dict[str, Any]:
        for snap in self._health.values():
            h = (snap.get("links") or {}).get(key)
            if h:
                return {"state": h["state"], "badge": h["badge"], "reasons": h["reasons"][:3]}
        return {}


# --------------------------------------------------------------------------- endpoints


def _parse(text: str) -> dict[str, str]:
    raw = str(text or "").strip()
    if not raw or len(raw) > 253:
        raise ValueError("Enter an IP address, MAC address or host name")
    ip = topo._ip(raw) if "/" not in raw else ""
    if ip:
        return {"kind": "ip", "ip": ip}
    mac = normalize_mac(raw) if re.fullmatch(r"[0-9A-Fa-f:.\-]{12,17}", raw) else ""
    if mac:
        return {"kind": "mac", "mac": mac}
    if not _HOST_RE.match(raw):
        raise ValueError(f"“{raw[:60]}” is not an IP address, MAC address or host name")
    return {"kind": "host", "host": raw}


def _locate(ctx: _Ctx, text: str, role: str) -> dict[str, Any]:
    """Resolve one end of the trace → {ip, mac, hostname, node, attach, interface, vlan, …}."""
    p = _parse(text)
    ep: dict[str, Any] = {
        "input": str(text).strip(),
        "ip": p.get("ip", ""),
        "mac": p.get("mac", ""),
        "hostname": p.get("host", ""),
        "node": "",  # the endpoint IS a device on the map
        "attach": "",  # the switch / AP / device it is attached to
        "interface": "",
        "vlan": None,
        "wireless": False,
        "evidence": [],
        "confidence": 0.0,
        "gateway_hint": "",
        "located_on": None,  # (source, device key, device name) from ENDPOINT_LOCATE, re-resolved after widening
    }
    if p["kind"] == "host":
        nid = ctx.node_by_name(p["host"])
        if nid:
            ep.update(node=nid, attach=nid, ip=topo._ip(ctx.nodes[nid].get("mgmt_ip")), confidence=1.0)
            ep["evidence"].append(
                {
                    "kind": "inventory",
                    "source": ", ".join(ctx.nodes[nid]["sources"]),
                    "detail": f"{ctx.name(nid)} is a device on the map",
                }
            )
            return ep
        ep["ip"] = resolve_hostname(p["host"])
        if not ep["ip"]:
            ctx.gap(f"The {role} “{p['host']}” does not resolve in DNS and is not a device on the map.")
            return ep
        ep["evidence"].append({"kind": "inferred", "source": "dns", "detail": f"{p['host']} resolves to {ep['ip']}"})
    # An address of a device on the map?
    nid = ""
    if ep["ip"]:
        nid = ctx.ip_owner(ep["ip"])[0]
    if not nid and ep["mac"]:
        nid = ctx.by_mac.get(ep["mac"], "")
    if nid:
        ep.update(node=nid, attach=nid, confidence=1.0)
        ep["evidence"].append(
            {
                "kind": "inventory",
                "source": ", ".join(ctx.nodes[nid]["sources"]),
                "detail": f"{ep['ip'] or ep['mac']} belongs to {ctx.name(nid)}",
            }
        )
        return ep
    # ENDPOINT_LOCATE across every source.
    locs: list[Any] = []
    for c in sdk.sources(ENDPOINT_LOCATE):
        locs += ctx.status.call(c, ENDPOINT_LOCATE, lambda c=c: c.locate_endpoint(ip=ep["ip"], mac=ep["mac"]))
    best = None
    for loc in locs:
        at = ctx.node_for_key(loc.source, loc.device_key)
        rank = (1 if at else 0, 0 if loc.wireless else 1, loc.last_seen or 0)
        if best is None or rank > best[0]:
            best = (rank, loc, at)
    if best:
        _, loc, at = best
        ep.update(
            mac=ep["mac"] or normalize_mac(loc.mac),
            ip=ep["ip"] or topo._ip(loc.ip),
            hostname=ep["hostname"] or loc.hostname,
            attach=at,
            interface=loc.interface,
            vlan=loc.vlan,
            wireless=bool(loc.wireless),
            confidence=0.9 if at else 0.5,
        )
        where = f"{loc.device_name or ctx.name(at) or 'unknown device'} {loc.interface}".strip()
        ep["evidence"].append(
            {
                "kind": "vendor_api",
                "source": loc.source,
                "detail": f"Seen on {where}" + (f" VLAN {loc.vlan}" if loc.vlan else ""),
            }
        )
        ep["located_on"] = (loc.source, loc.device_key, loc.device_name or loc.device_key)
        if not at and ctx.widened:
            ctx.gap(f"The {role} is attached to {loc.device_name or loc.device_key}, which is not on this map.")
    # ARP: IP ↔ MAC, and the L3 box that knows it (gateway hint).
    if ep["ip"] and (not ep["mac"] or not ep["attach"]):
        for e in ctx.arp():
            if topo._ip(e.ip) == ep["ip"] and normalize_mac(e.mac):
                ep["mac"] = ep["mac"] or normalize_mac(e.mac)
                gw = ctx.node_for_key(e.source, e.device_key)
                if gw:
                    ep["gateway_hint"] = ep["gateway_hint"] or gw
                    ep["evidence"].append(
                        {
                            "kind": "arp",
                            "source": e.source,
                            "detail": f"{ep['ip']} is in the ARP table of {ctx.name(gw)} ({e.interface or 'interface unknown'})",
                        }
                    )
                    ep["confidence"] = max(ep["confidence"], 0.4)
                break
    elif ep["mac"] and not ep["ip"]:
        for e in ctx.arp():
            if normalize_mac(e.mac) == ep["mac"] and topo._ip(e.ip):
                ep["ip"] = topo._ip(e.ip)
                gw = ctx.node_for_key(e.source, e.device_key)
                ep["gateway_hint"] = gw
                ep["evidence"].append(
                    {
                        "kind": "arp",
                        "source": e.source,
                        "detail": f"{fmt_mac(ep['mac'])} is {ep['ip']} in the ARP table of {ctx.name(gw)}",
                    }
                )
                break
    # MAC tables: the switch port that learned the MAC (an access port, not an uplink).
    if ep["mac"] and not ep["attach"]:
        _mac_table_attach(ctx, ep)
    if (
        not ep["attach"]
        and not ep["located_on"]
        and not ep["gateway_hint"]
        and not (ep["ip"] and ctx.subnet_owner(ep["ip"]))
    ):
        what = ep["ip"] or fmt_mac(ep["mac"]) or ep["input"]
        ctx.gap(f"Could not find where the {role} {what} is attached (no source reports it).")
    return ep


def _uplink_ports(ctx: _Ctx, nid: str) -> set[str]:
    out = set()
    for _other, link in ctx.adj.get(nid, []):
        if link["layer"] in ("physical", "lag", "l2"):
            for m in link.get("members", []):
                side = m.get("a_interface") if link["a_device"] == nid else m.get("b_interface")
                for p in str(side or "").split(","):
                    out.add(topo.norm_if(p))
                lag = m.get("a_lag") if link["a_device"] == nid else m.get("b_lag")
                if lag:
                    out.add(topo.norm_if(lag))
    out.discard("")
    return out


def _mac_table_attach(ctx: _Ctx, ep: dict[str, Any]) -> None:
    calls = 0
    candidates: list[tuple[int, str, Any]] = []
    for c in sdk.sources(MAC_TABLE):
        for nid, n in ctx.nodes.items():
            if n["role"] != "switch" or calls >= MAX_MAC_TABLE_CALLS:
                continue
            for rec in n.get("records", []):
                if rec["source"] != c.provider_id:
                    continue
                calls += 1
                for e in ctx.status.call(c, MAC_TABLE, lambda c=c, k=rec["key"]: c.list_mac_table(k)):
                    if normalize_mac(e.mac) == ep["mac"]:
                        access = topo.norm_if(e.interface) not in _uplink_ports(ctx, nid)
                        candidates.append((1 if access else 0, nid, e))
    if not candidates:
        return
    candidates.sort(key=lambda x: -x[0])
    access, nid, e = candidates[0]
    if not access:
        ctx.gap(
            f"{fmt_mac(ep['mac'])} was only seen on uplink ports — the access switch does not report its MAC table."
        )
        return
    ep.update(attach=nid, interface=e.interface, vlan=e.vlan, confidence=max(ep["confidence"], 0.7))
    ep["evidence"].append(
        {
            "kind": "mac_table",
            "source": e.source,
            "detail": f"MAC learned on {ctx.name(nid)} {e.interface}" + (f" VLAN {e.vlan}" if e.vlan else ""),
        }
    )


def fmt_mac(m: str) -> str:
    return ":".join(m[i : i + 2] for i in range(0, 12, 2)) if m and len(m) == 12 else m or ""


# --------------------------------------------------------------------------- hops


def _side_if(link: dict[str, Any], nid: str) -> str:
    return str(link["a_interface"] if link["a_device"] == nid else link["b_interface"]) or ""


def _l2_path(ctx: _Ctx, start: str, goal: str) -> list[tuple[str, dict[str, Any]]] | None:
    """Shortest physical/LAG/L2 path start → goal through switches only: [(node, link into node)]."""
    if start == goal:
        return []
    prev: dict[str, tuple[str, dict[str, Any]]] = {}
    q = deque([(start, 0)])
    seen = {start}
    while q:
        cur, depth = q.popleft()
        if depth >= MAX_L2_DEPTH:
            continue
        for other, link in ctx.adj.get(cur, []):
            if link["layer"] not in ("physical", "lag", "l2") or other in seen:
                continue
            if other != goal and ctx.nodes.get(other, {}).get("role") not in _L2_TRANSIT:
                continue
            if other != goal and ctx.nodes.get(other, {}).get("role") == "wireless_ap" and cur != start:
                continue  # never transit through an AP
            seen.add(other)
            prev[other] = (cur, link)
            if other == goal:
                path = []
                x = goal
                while x != start:
                    p, lk = prev[x]
                    path.append((x, lk))
                    x = p
                return list(reversed(path))
            q.append((other, depth + 1))
    return None


def _nearest_l3(ctx: _Ctx, start: str) -> tuple[str, list[tuple[str, dict[str, Any]]]] | None:
    """Closest upstream firewall/router/SD-WAN box over physical links (when no L3 data says which).

    Breadth-first by distance; at the same distance a firewall or router is a likelier gateway than an
    SD-WAN edge.
    """
    prev: dict[str, tuple[str, dict[str, Any]]] = {start: ("", {})}
    level = [start]
    prio = {"firewall": 0, "router": 1, "sdwan_edge": 2}
    while level:
        found: list[str] = []
        nxt: list[str] = []
        for cur in level:
            for other, link in ctx.adj.get(cur, []):
                if link["layer"] not in ("physical", "lag", "l2") or other in prev:
                    continue
                prev[other] = (cur, link)
                role = ctx.nodes.get(other, {}).get("role")
                if role in L3_ROLES:
                    found.append(other)
                elif role in ("switch", "unknown"):
                    nxt.append(other)
        if found:
            best = min(found, key=lambda x: (prio.get(ctx.nodes[x]["role"], 9), ctx.name(x)))
            path = []
            x = best
            while x != start:
                p, lk = prev[x]
                path.append((x, lk))
                x = p
            return best, list(reversed(path))
        level = nxt
    return None


class _Walk:
    def __init__(self, ctx: _Ctx) -> None:
        self.ctx = ctx
        self.hops: list[dict[str, Any]] = []
        self.unchecked_policy: list[str] = []
        self.policies: list[str] = []

    def add(self, nid: str, *, layer: str, decision: str, ingress: str = "", egress: str = "", action: str = "forward",
            evidence: list[dict[str, Any]] | None = None, confidence: float = 1.0, **extra: Any) -> dict[str, Any]:  # fmt: skip
        n = self.ctx.nodes.get(nid, {})
        hop = {
            "n": len(self.hops) + 1,
            "node": nid,
            "name": n.get("name") or nid,
            "role": n.get("role", "unknown"),
            "vendor_name": n.get("vendor_name", ""),
            "site_name": n.get("site_name", ""),
            "ingress": ingress,
            "egress": egress,
            "layer": layer,
            "decision": decision,
            "action": action,
            "evidence": evidence or [],
            "confidence": round(confidence, 2),
            "health": self.ctx.health(nid) if nid in self.ctx.nodes else {},
            "link": "",
            "link_health": {},
            **extra,
        }
        self.hops.append(hop)
        return hop

    def endpoint(self, ep: dict[str, Any], *, final: bool) -> None:
        label = ep.get("hostname") or ep.get("ip") or fmt_mac(ep.get("mac", "")) or ep["input"]
        bits = [x for x in (ep.get("ip"), fmt_mac(ep.get("mac", ""))) if x and x != label]
        self.hops.append(
            {
                "n": len(self.hops) + 1,
                "node": "",
                "name": label,
                "role": "endpoint",
                "vendor_name": "",
                "site_name": "",
                "ingress": "",
                "egress": "",
                "layer": "endpoint",
                "decision": ("Destination " if final else "Source ") + (" · ".join(bits) if bits else label),
                "action": "deliver" if final else "originate",
                "evidence": list(ep.get("evidence", [])),
                "confidence": round(ep.get("confidence", 0.0), 2),
                "health": {},
                "link": "",
                "link_health": {},
            }
        )

    def connect(self, link: dict[str, Any] | None) -> None:
        """Record the link the previous hop leaves on (for the map highlight)."""
        if self.hops and link:
            self.hops[-1]["link"] = link["key"]
            self.hops[-1]["link_health"] = self.ctx.link_health(link["key"])

    def l2(self, path: list[tuple[str, dict[str, Any]]], prev: str, *, last_layer: str = "l2", stop_before_last: bool = False,
           transit: str = "Switched toward the gateway") -> None:  # fmt: skip
        for i, (nid, link) in enumerate(path):
            if stop_before_last and i == len(path) - 1:
                break
            if self.hops and self.hops[-1].get("node") == prev:
                self.hops[-1]["egress"] = self.hops[-1]["egress"] or _side_if(link, prev)
            self.connect(link)
            ev = [dict(e) for e in link.get("evidence", [])]
            role = self.ctx.nodes.get(nid, {}).get("role")
            last = i == len(path) - 1
            self.add(
                nid,
                layer=last_layer if last else "l2",
                decision="" if last else (transit if role == "switch" else "Transit"),
                ingress=_side_if(link, nid),
                evidence=ev,
                confidence=float(link.get("confidence") or 0.7),
            )
            prev = nid


def _lpm(routes: list[Any], ip: str, vrf: str | None) -> Any:
    """Longest-prefix match in one VRF.

    ``vrf`` is the ingress interface's VRF ('' = default) or None when unknown; unknown uses the
    device's only VRF when all its routes are in one, else the default VRF.
    """
    if vrf is None:
        vrfs = {norm_vrf(r.vrf) for r in routes}
        vrf = next(iter(vrfs)) if len(vrfs) == 1 else ""
    want = norm_vrf(vrf)
    best = None
    for r in routes:
        net = _net(r.prefix)
        if net is None or not _in(ip, net.network) or norm_vrf(r.vrf) != want:
            continue
        rank = (net.network.prefixlen, 1 if (r.protocol or "") == "connected" else 0)
        if best is None or rank > best[0]:
            best = (rank, r)
    return best[1] if best else None


def _route_text(r: Any) -> str:
    via = f" via {r.next_hop}" if r.next_hop else ""
    out = f" out {r.interface}" if r.interface else ""
    proto = f" ({r.protocol})" if r.protocol else ""
    vrf = f" [vrf {r.vrf}]" if r.vrf and str(r.vrf).lower() not in _DEFAULT_VRFS else ""
    return f"route {r.prefix}{via}{out}{proto}{vrf}"


def _policy(ctx: _Ctx, w: _Walk, nid: str, *, src: str, dst: str, port: int | None, proto: str,
            ingress: str, egress: str) -> tuple[str, dict[str, Any] | None]:  # fmt: skip
    """('allow'|'deny'|'unchecked'|'nomatch', policy dict)."""
    node = ctx.nodes[nid]
    zin, zout = ctx.zone(nid, ingress), ctx.zone(nid, egress)
    srcs = [c for c in sdk.sources(POLICY_LOOKUP) if any(r["source"] == c.provider_id for r in node.get("records", []))]
    if not srcs:
        ctx.gap(
            f"Security policy on {node['name']} was not checked — {ctx.manager_hint(nid)} to see allow/deny and the matching rule."
        )
        w.unchecked_policy.append(node["name"])
        return "unchecked", {"zone_in": zin, "zone_out": zout}
    matches: list[Any] = []
    for c in srcs:
        for rec in node["records"]:
            if rec["source"] != c.provider_id:
                continue
            matches += ctx.status.call(
                c,
                POLICY_LOOKUP,
                lambda c=c, k=rec["key"]: c.policy_lookup(
                    k, src_ip=src, dst_ip=dst, dst_port=port, protocol="tcp" if proto == "any" else proto
                ),
            )
    if not matches:
        ctx.gap(
            f"No security rule on {node['name']} matched this flow (or the lookup failed); the default rule decides."
        )
        w.unchecked_policy.append(node["name"])
        return "nomatch", {"zone_in": zin, "zone_out": zout}
    m = matches[0]
    action = str(m.action or "unknown").lower()
    pol = {
        "rule": m.rule,
        "action": action,
        "zone_in": m.from_zone or zin,
        "zone_out": m.to_zone or zout,
        "nat": m.nat,
        "detail": m.detail,
        "source": m.source,
    }
    if any(a in action for a in _DENY):
        return "deny", pol
    if action.startswith("allow") or action == "permit":
        w.policies.append(f"{m.rule or 'rule'} on {node['name']}")
        return "allow", pol
    w.unchecked_policy.append(node["name"])
    return "nomatch", pol


def _tunnel_for(ctx: _Ctx, nid: str, route: Any, dst_ip: str) -> tuple[Any, str, int] | None:
    """Best overlay out of ``nid`` for this route: (tunnel, far node id or '', candidates)."""
    mine: list[tuple[Any, bool]] = []  # (tunnel, reported by the far side)
    for t in ctx.tunnels():
        a = ctx.node_for_key(t.source, t.device_key)
        b = ctx.node_for_key(t.source, t.remote_device_key) if t.remote_device_key else ""
        if a == nid:
            mine.append((t, False))
        elif b == nid:
            mine.append((t, True))
    if not mine:
        return None
    nh = topo._ip(route.next_hop)
    itf = ctx.interface(nid, route.interface) if route.interface else None
    by_name = [
        x for x in mine if not x[1] and route.interface and topo.norm_if(x[0].name) == topo.norm_if(route.interface)
    ]
    tunnel_route = (
        bool(by_name)
        or (itf is not None and itf.kind == "tunnel")
        or str(route.protocol or "").lower() in _TUNNEL_PROTOCOLS
    )

    def resolve_far(t: Any, reversed_: bool) -> str:
        if reversed_:
            return ctx.node_for_key(t.source, t.device_key)
        if t.remote_device_key:
            x = ctx.node_for_key(t.source, t.remote_device_key)
            if x:
                return x
        rip = topo._ip(t.remote_ip)
        if rip:
            x = ctx.ip_owner(rip)[0]
            if x and x != nid:
                return x
        return ctx.node_by_name(t.remote_name) if t.remote_name else ""

    def far(t: Any, reversed_: bool) -> str:
        """Far-side node of a tunnel, resolved once per trace (cleared when the graph widens)."""
        key = f"{nid}|{t.source}|{t.key}|{int(reversed_)}"
        if key not in ctx._far:
            ctx._far[key] = resolve_far(t, reversed_)
        return ctx._far[key]

    cands = by_name
    if not cands and nh:
        nh_owner = ctx.ip_owner(nh, nid)[0]
        cands = [
            x
            for x in mine
            if (topo._ip(x[0].local_ip if x[1] else x[0].remote_ip) == nh) or (nh_owner and far(*x) == nh_owner)
        ]
        tunnel_route = tunnel_route or bool(cands)
    if not cands and tunnel_route:
        owner = ctx.subnet_owner(dst_ip)
        if owner is None and ctx.widen():
            owner = ctx.subnet_owner(dst_ip)
        if owner:
            osites = set(ctx.sites(owner[0]))
            cands = [x for x in mine if far(*x) == owner[0] or (osites and set(ctx.sites(far(*x))) & osites)]
        if not cands:
            cands = mine if len({far(*x) for x in mine}) == 1 else []
    if not cands:
        return None

    def score(x: tuple[Any, bool]) -> tuple:
        t = x[0]
        return (
            0 if t.state == "up" else 1 if t.state in ("degraded", "unknown") else 2,
            t.loss_pct if t.loss_pct is not None else 50,
            t.latency_ms if t.latency_ms is not None else 1e6,
        )

    best = min(cands, key=score)
    return best[0], far(*best), len(cands)


# --------------------------------------------------------------------------- public API


def trace(
    src: str,
    dst: str,
    dst_port: int | None = None,
    protocol: str = "tcp",
    *,
    site: str | None = None,
    thresholds: Any = None,
) -> dict[str, Any]:
    """Trace src → dst (IP, MAC or host name). Read-only. Raises ValueError on bad input."""
    started = time.monotonic()
    protocol = str(protocol or "tcp").lower().strip()
    if protocol not in PROTOCOLS:
        raise ValueError(f"protocol must be one of {', '.join(PROTOCOLS)}")
    if dst_port not in (None, ""):
        try:
            dst_port = int(dst_port)  # type: ignore[arg-type]
        except (TypeError, ValueError):
            raise ValueError("port must be a number from 1 to 65535") from None
        if not 1 <= dst_port <= 65535:
            raise ValueError("port must be a number from 1 to 65535")
    else:
        dst_port = None
    scope = str(site or "").strip()
    if not topo._SCOPE_RE.match(scope):
        raise ValueError("Invalid site key")
    _parse(src), _parse(dst)  # validate both before any source is asked

    ctx = _Ctx(scope or None, thresholds)
    s = _locate(ctx, src, "source")
    d = _locate(ctx, dst, "destination")
    w = _Walk(ctx)
    verdict = _walk(ctx, w, s, d, dst_port, protocol)
    path_nodes = list(dict.fromkeys(h["node"] for h in w.hops if h["node"]))
    path_links = list(dict.fromkeys(h["link"] for h in w.hops if h["link"]))
    return {
        "src": _public_ep(ctx, s),
        "dst": _public_ep(ctx, d),
        "dst_port": dst_port,
        "protocol": protocol,
        "hops": w.hops,
        "path_nodes": path_nodes,
        "path_links": path_links,
        "verdict": verdict,
        "gaps": ctx.gaps,
        "sources": list(ctx.status.status.values()),
        "scope": scope,
        "widened": ctx.widened and bool(scope),
        "elapsed_ms": round((time.monotonic() - started) * 1000),
        "generated_at": time.time(),
    }


def _public_ep(ctx: _Ctx, ep: dict[str, Any]) -> dict[str, Any]:
    return {
        "input": ep["input"],
        "ip": ep["ip"],
        "mac": fmt_mac(ep["mac"]),
        "hostname": ep["hostname"],
        "device": ctx.name(ep["node"]) if ep["node"] else "",
        "attached_to": ctx.name(ep["attach"]) if ep["attach"] else "",
        "attached_node": ep["attach"],
        "interface": ep["interface"],
        "vlan": ep["vlan"],
        "wireless": ep["wireless"],
        "evidence": ep["evidence"],
        "located": bool(ep["attach"]),
    }


def _v(status: str, text: str) -> dict[str, str]:
    return {"status": status, "text": text}


def _walk(ctx: _Ctx, w: _Walk, s: dict[str, Any], d: dict[str, Any], port: int | None, proto: str) -> dict[str, str]:
    if not s["attach"] and s["located_on"]:
        if ctx.widen():
            s["attach"] = ctx.node_for_key(s["located_on"][0], s["located_on"][1])
        if s["attach"]:
            s["confidence"] = max(s["confidence"], 0.9)
        if not s["attach"]:
            ctx.gap(f"The source is attached to {s['located_on'][2]}, which is not on any connected map.")
    if not s["ip"] and not s["attach"]:
        return _v("unknown", f"Could not find the source {s['input']}.")
    if not d["ip"]:
        return _v("unknown", f"Could not find an IP address for the destination {d['input']}.")
    dst_ip = d["ip"]

    # ---- 1. source endpoint and its access device
    start = s["attach"]
    if not s["node"]:
        w.endpoint(s, final=False)
    if start:
        role = ctx.nodes[start]["role"]
        if not s["node"]:
            w.add(
                start,
                layer="wireless" if s["wireless"] else "l2",
                decision=("Access point" if role == "wireless_ap" else "Access port")
                + (f", VLAN {s['vlan']}" if s["vlan"] else ""),
                ingress=s["interface"],
                evidence=[e for e in s["evidence"] if e["kind"] in ("vendor_api", "mac_table")],
                confidence=s["confidence"] or 0.7,
            )
        else:
            w.add(start, layer="l3" if role in L3_ROLES else "l2", decision="Source device", confidence=1.0)

    # ---- 2. up to the gateway
    owner = ctx.subnet_owner(s["ip"], near=start) if s["ip"] else None
    gw, gw_if = (owner[0], owner[1]) if owner else (s["gateway_hint"], "")
    if s["node"] and ctx.nodes[s["node"]]["role"] in L3_ROLES:
        gw, gw_if = s["node"], (owner[1] if owner and owner[0] == s["node"] else "")
    if not gw:
        if start:
            up = _nearest_l3(ctx, start)
            if up:
                l3, path = up
                w.l2(path, start, stop_before_last=True)
                last = w.hops[-1]["node"] if w.hops and w.hops[-1]["node"] else start
                w.hops[-1]["egress"] = w.hops[-1]["egress"] or _side_if(path[-1][1], last)
                w.connect(path[-1][1])
                ctx.gap(
                    f"{ctx.name(l3)} is the likely gateway, but no source reports its interfaces or routes — "
                    f"{ctx.manager_hint(l3)}."
                )
                return _v("partial", f"Path unknown after {ctx.name(last)} (no L3 data).")
            ctx.gap("No connected source reports interface subnets, ARP or routes, so the gateway is unknown.")
            return _v("partial", f"Path unknown after {ctx.name(start)} (no L3 data).")
        return _v("unknown", f"Could not locate the source {s['input']} or its gateway.")

    # Same subnet as the destination: switched end to end, no L3 hop.
    if owner and _in(dst_ip, owner[2]) and d["attach"] and start and not d["node"]:
        path = _l2_path(ctx, start, d["attach"])
        if path is not None:
            w.l2(path, start)
            if w.hops and path:
                w.hops[-1]["decision"] = "Access port" + (f", VLAN {d['vlan']}" if d["vlan"] else "")
                w.hops[-1]["egress"] = d["interface"]
            w.endpoint(d, final=True)
            return _v("allowed", f"Same subnet ({owner[2]}): switched end to end, no firewall in the path.")

    if start and start != gw:
        path = _l2_path(ctx, start, gw)
        if path is None:
            ctx.gap(
                f"No cabled path from {ctx.name(start)} to its gateway {ctx.name(gw)} is known (LLDP missing on the way)."
            )
            w.add(
                gw,
                layer="l3",
                decision="",
                ingress=gw_if,
                confidence=0.5,
                evidence=[{"kind": "config", "source": "", "detail": "Gateway of the source subnet"}],
            )
        else:
            w.l2(path, start, last_layer="l3")
            w.hops[-1]["ingress"] = gw_if or w.hops[-1]["ingress"]
    elif not start or (w.hops and w.hops[-1]["node"] != gw):
        w.add(gw, layer="l3", decision="", ingress=gw_if, confidence=0.8 if owner else 0.4)
    if owner:
        w.hops[-1]["evidence"].append(
            {
                "kind": "config",
                "source": ", ".join(ctx.nodes[gw]["sources"]),
                "detail": f"Gateway: {owner[2]} is configured on {owner[1]}",
            }
        )

    # ---- 3. layer-3 hops
    cur, ingress = gw, gw_if or w.hops[-1]["ingress"]
    visited: set[tuple[str, str]] = set()
    while True:
        if len(w.hops) >= MAX_HOPS:
            ctx.gap(f"The trace stopped after {MAX_HOPS} hops.")
            return _v("partial", f"Stopped after {MAX_HOPS} hops at {ctx.name(cur)}.")
        hop = (
            w.hops[-1] if w.hops and w.hops[-1]["node"] == cur else w.add(cur, layer="l3", decision="", ingress=ingress)
        )
        hop["layer"] = "l3" if hop["layer"] not in ("overlay",) else hop["layer"]
        itf = ctx.interface(cur, ingress) if ingress else None
        vrf = interface_vrf(itf) if itf is not None else None
        if (cur, vrf or "") in visited:
            hop["action"] = "drop"
            hop["decision"] = "Routing loop: this device was already on the path"
            return _v("loop", f"Routing loop detected at {ctx.name(cur)}.")
        visited.add((cur, vrf or ""))
        is_fw = ctx.nodes[cur]["role"] == "firewall" or any(
            r["source"] == c.provider_id for c in sdk.sources(POLICY_LOOKUP) for r in ctx.nodes[cur].get("records", [])
        )

        conn = ctx.connected_net(cur, dst_ip)
        if conn:
            egress, net = conn
            hop["egress"] = egress
            hop["decision"] = f"Destination subnet {net} is connected on {egress}"
            hop["route"] = {"prefix": str(net), "next_hop": "", "interface": egress, "protocol": "connected"}
            hop["evidence"].append(
                {"kind": "config", "source": ", ".join(ctx.nodes[cur]["sources"]), "detail": f"{net} on {egress}"}
            )
            if is_fw:
                res, pol = _policy(
                    ctx, w, cur, src=s["ip"], dst=dst_ip, port=port, proto=proto, ingress=ingress, egress=egress
                )
                hop["policy"] = pol
                if res == "deny":
                    hop["action"] = "deny"
                    hop["decision"] = f"Denied by policy {pol.get('rule') or '(unnamed)'}"
                    return _v("denied", f"Denied by rule {pol.get('rule') or '(unnamed)'} on {ctx.name(cur)}.")
                if res == "allow":
                    hop["decision"] = f"Policy {pol['rule']} allows · {hop['decision']}"
            return _finish(ctx, w, cur, d)

        routes = ctx.routes(cur)
        if routes is None:
            hop["decision"] = hop["decision"] or "No routing data"
            hop["action"] = "unknown"
            ctx.gap(f"No routes from {ctx.name(cur)} — {ctx.manager_hint(cur)}.")
            return _v("partial", f"Path unknown after {ctx.name(cur)} (no L3 data).")
        r = _lpm(routes, dst_ip, vrf)
        if r is None:
            hop["action"] = "drop"
            hop["decision"] = f"No route to {dst_ip}" + (f" in VRF {vrf}" if vrf else "")
            return _v("no_route", f"Dropped at {ctx.name(cur)}: no route to {dst_ip}.")
        hop["route"] = {
            "prefix": r.prefix,
            "next_hop": r.next_hop,
            "interface": r.interface,
            "protocol": r.protocol,
            "vrf": r.vrf,
        }
        hop["egress"] = r.interface or hop["egress"]
        hop["decision"] = _route_text(r)
        hop["evidence"].append({"kind": "routing", "source": r.source, "detail": _route_text(r)})
        if is_fw:
            res, pol = _policy(
                ctx, w, cur, src=s["ip"], dst=dst_ip, port=port, proto=proto, ingress=ingress, egress=r.interface
            )
            hop["policy"] = pol
            if res == "deny":
                hop["action"] = "deny"
                hop["decision"] = f"Denied by policy {pol.get('rule') or '(unnamed)'}"
                return _v("denied", f"Denied by rule {pol.get('rule') or '(unnamed)'} on {ctx.name(cur)}.")
            if res == "allow":
                hop["decision"] = f"Policy {pol['rule']} allows · {hop['decision']}"

        # Overlay?
        picked = _tunnel_for(ctx, cur, r, dst_ip)
        if picked:
            t, far, n_cands = picked
            far_name = ctx.name(far) if far else (t.remote_name or t.remote_ip or "remote peer")
            hop["tunnel"] = {
                "name": t.name, "kind": t.kind, "state": t.state, "latency_ms": t.latency_ms, "loss_pct": t.loss_pct,
                "jitter_ms": topo.tunnel_jitter(t), "remote": far_name, "alternatives": n_cands - 1, "source": t.source,
            }  # fmt: skip
            hop["egress"] = hop["egress"] or t.name
            q = " · ".join(
                x for x in (
                    f"latency {t.latency_ms:g} ms" if t.latency_ms is not None else "",
                    f"loss {t.loss_pct:g}%" if t.loss_pct is not None else "",
                ) if x
            )  # fmt: skip
            hop["decision"] += f" → {t.kind} tunnel {t.name} to {far_name}" + (f" ({q})" if q else "")
            hop["evidence"].append(
                {
                    "kind": "tunnel",
                    "source": t.source,
                    "detail": f"{t.kind} tunnel {t.name} ({t.state})"
                    + (f", {n_cands - 1} other path(s) available" if n_cands > 1 else ""),
                }
            )
            if t.state == "down":
                hop["action"] = "drop"
                return _v("partial", f"The tunnel {t.name} from {ctx.name(cur)} to {far_name} is down.")
            if not far and ctx.widen():
                again = _tunnel_for(ctx, cur, r, dst_ip)
                far = again[1] if again else ""
            if not far:
                ctx.gap(f"The far side of tunnel {t.name} ({far_name}) is not in any connected source.")
                return _v("partial", f"Path unknown after the tunnel to {far_name} (far side not connected).")
            link = _link_between(ctx, cur, far, ("overlay",))
            w.connect(link)
            far_tunnel = next(
                (x.name for x in ctx.tunnels() if ctx.node_for_key(x.source, x.device_key) == far and (topo._ip(x.remote_ip) == topo._ip(t.local_ip) or ctx.node_for_key(x.source, x.remote_device_key) == cur)),
                "",
            )  # fmt: skip
            w.add(
                far,
                layer="overlay",
                decision="",
                ingress=far_tunnel or f"tunnel from {ctx.name(cur)}",
                confidence=float(link.get("confidence", 0.7)) if link else 0.7,
                evidence=[dict(e) for e in (link or {}).get("evidence", [])],
            )
            cur, ingress = far, far_tunnel
            continue

        nh = topo._ip(r.next_hop)
        if not nh:
            hop["action"] = "unknown"
            ctx.gap(
                f"The route on {ctx.name(cur)} leaves {r.interface or 'an interface'} without a next hop NodeWatch can follow."
            )
            return _v("partial", f"Path unknown after {ctx.name(cur)}.")
        owner_nid, owner_if = ctx.ip_owner(nh, cur)
        if not owner_nid and ctx.widen():
            owner_nid, owner_if = ctx.ip_owner(nh, cur)
        if not owner_nid or owner_nid == cur:
            if str(r.prefix) in ("0.0.0.0/0", "::/0") and not topo._private(dst_ip):
                hop["action"] = "forward"
                return _v(
                    "allowed" if not w.unchecked_policy else "reached",
                    f"Leaves toward the Internet via {nh} on {ctx.name(cur)}.",
                )
            ctx.gap(f"Next hop {nh} from {ctx.name(cur)} is not a device NodeWatch can see.")
            return _v("partial", f"Path unknown after {ctx.name(cur)} (next hop {nh} not on the map).")
        path = _l2_path(ctx, cur, owner_nid)
        if path and len(path) > 1:
            w.l2(path, cur, last_layer="l3", transit=f"Switched toward next hop {nh}")
        else:
            w.connect(_link_between(ctx, cur, owner_nid, ("physical", "lag", "l2", "l3")))
            w.add(owner_nid, layer="l3", decision="", ingress=owner_if, confidence=0.9)
        w.hops[-1]["ingress"] = owner_if or w.hops[-1]["ingress"]
        cur, ingress = owner_nid, owner_if or w.hops[-1]["ingress"]


def _link_between(ctx: _Ctx, a: str, b: str, layers: tuple[str, ...]) -> dict[str, Any] | None:
    for other, link in ctx.adj.get(a, []):
        if other == b and link["layer"] in layers:
            return link
    return None


def _finish(ctx: _Ctx, w: _Walk, cur: str, d: dict[str, Any]) -> dict[str, str]:
    """Last L3 hop reached the destination subnet: switch down to the endpoint."""
    if not d["attach"] and d["located_on"]:  # located at another site: resolvable on the wider graph
        d["attach"] = ctx.node_for_key(d["located_on"][0], d["located_on"][1])
        if not d["attach"] and ctx.widen():
            d["attach"] = ctx.node_for_key(d["located_on"][0], d["located_on"][1])
        if d["attach"]:
            d["confidence"] = max(d["confidence"], 0.9)
        if not d["attach"]:
            ctx.gap(f"The destination is attached to {d['located_on'][2]}, which is not on any connected map.")
    target = d["node"] or d["attach"]
    caveat = f" — policy not checked on {', '.join(dict.fromkeys(w.unchecked_policy))}" if w.unchecked_policy else ""
    status = "reached" if w.unchecked_policy else "allowed"
    if d["node"] == cur:
        w.hops[-1]["action"] = "deliver"
        return _v(status, ("Allowed end to end" if status == "allowed" else f"Reached {ctx.name(cur)}") + caveat + ".")
    if target:
        path = _l2_path(ctx, cur, target)
        if path is None:
            ctx.gap(f"No cabled path from {ctx.name(cur)} to {ctx.name(target)} is known.")
        else:
            w.l2(path, cur, transit="Switched toward the destination")
            if path and not d["node"]:
                w.hops[-1]["decision"] = ("Access point" if d["wireless"] else "Access port") + (
                    f", VLAN {d['vlan']}" if d["vlan"] else ""
                )
                w.hops[-1]["egress"] = d["interface"]
                w.hops[-1]["evidence"] += [e for e in d["evidence"] if e["kind"] in ("vendor_api", "mac_table")]
            elif path:
                w.hops[-1]["decision"] = "Destination device"
                w.hops[-1]["action"] = "deliver"
    else:
        ctx.gap(f"The destination {d['ip']} was not located on a switch port; the path ends at its subnet.")
    if not d["node"]:
        w.endpoint(d, final=True)
    rules = f" ({'; '.join(w.policies)})" if w.policies else ""
    if not target:
        text = f"{'Allowed' if status == 'allowed' else 'Reaches'} up to {d['ip']}'s subnet at {ctx.name(cur)}{rules}{caveat}; its switch port is unknown."
    elif status == "allowed":
        text = f"Allowed end to end{rules}."
    else:
        text = f"Reaches {d['ip']}{caveat}."
    return _v(status, text)
