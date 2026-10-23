"""Vendor-neutral topology engine (v0.10.16, phase 1; health and path trace build on it in v0.10.17).

Builds one graph of a site from whatever connected sources offer, through capabilities only:

    INVENTORY   list_devices(site)      → the boxes each system manages
    NEIGHBORS   list_neighbors(site)    → LLDP/CDP: "my port X sees box Y port Z"
    INTERFACES  list_interfaces(dev)    → L3 interface addresses (routed devices only)
    ROUTES      list_routes(dev)        → next hops (routed devices only)
    ARP_TABLE   list_arp()              → IP ↔ MAC, used to attach otherwise isolated boxes
    TUNNELS     list_tunnels(site)      → IPsec / SD-WAN overlays

No connector is named here: the only vendor knowledge is the LLDP fingerprint table in
``topology_fingerprints`` and the ``source`` field each record carries.

Pipeline
1. Entity resolution — every device record (from every source) is one identity; identities that
   share a chassis/member MAC or serial always merge; a shared management IP or normalized host
   name merges them only when that would not join two different boxes of the same source.
2. Neighbors → physical links. A cable seen from both ends = confidence 1.0, from one end = 0.7.
   Neighbors no source describes become "discovered" nodes (role guessed from LLDP fingerprints).
   Parallel cables between the same two boxes are one link with ``members`` (layer ``lag`` when an
   aggregate name is known).
3. ARP (0.4, inferred) attaches boxes that have no physical link at all.
4. L3 links from shared interface subnets and route next hops (0.7); unresolved default routes and
   tunnel endpoints hang off a synthetic "WAN / Internet" node.
5. Overlay links from tunnels (deduped across both ends).
6. Tiers (internet → SD-WAN edge → firewall/router → core → access → APs/endpoints) and plain-English
   data gaps.

Every link keeps ``a_device``/``b_device`` + interfaces + layer + evidence, so a later path trace can
walk the graph hop by hop (physical → l3 → overlay) without a new model.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import re
import threading
import time
from collections import Counter, OrderedDict, defaultdict
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable

from app.integrations.connectors import sdk
from app.integrations.contracts import (
    ALERTS,
    ARP_TABLE,
    CAPABILITY_LABELS,
    ENDPOINT_LOCATE,
    HEALTH,
    INTERFACES,
    INVENTORY,
    MAC_TABLE,
    NEIGHBORS,
    POLICY_LOOKUP,
    ROUTES,
    TUNNELS,
    WAN_CIRCUITS,
)
from app.integrations.domain import Link, normalize_mac, stable_key
from app.services import topology_overview
from app.services import topology_sites as site_registry
from app.services.topology_fingerprints import fingerprint
from app.core.file_utils import write_private_text

log = logging.getLogger("nodewatch.topology")

CACHE_TTL_S = 120.0
MAX_L3_DEVICE_CALLS = 40  # per source and capability, per build
CONF_BOTH = 1.0
CONF_ONE = 0.7
CONF_INFERRED = 0.4

TIERS = (
    (0, "internet", "Internet / WAN"),
    (1, "edge", "SD-WAN edge"),
    (2, "security", "Firewall / router"),
    (3, "core", "Core / distribution"),
    (4, "access", "Access switches"),
    (5, "endpoint", "Access points & endpoints"),
)
LAYERS = (
    ("physical", "Physical / L2", ("physical", "lag", "l2")),
    ("l3", "Layer 3", ("l3",)),
    ("overlay", "Overlay / SD-WAN", ("overlay",)),
)
_UPSTREAM_ROLES = {"cloud", "sdwan_edge", "firewall", "router"}
_L3_ROLES = {"firewall", "router", "sdwan_edge"}
_CORE_HINT = re.compile(r"(^|[^a-z])(core|dist|distribution|agg|spine|mdf|bb|backbone)([^a-z]|$)", re.I)
_ACCESS_HINT = re.compile(r"(^|[^a-z])(idf|access|acc|leaf|edge-sw|floor|fl\d)([^a-z]|$)", re.I)
_IF_LONG = (
    ("hundredgigabitethernet", "hu"),
    ("fortygigabitethernet", "fo"),
    ("twentyfivegige", "twe"),
    ("tengigabitethernet", "te"),
    ("gigabitethernet", "gi"),
    ("fastethernet", "fa"),
    ("port-channel", "po"),
    ("ethernet", "eth"),
)

CACHE_MAX_SCOPES = 32
MAX_WEAK_CANDIDATES = 8  # a host name / IP shared by more boxes than this is not an identity
_SCOPE_RE = re.compile(r"^[A-Za-z0-9_.:@-]{0,200}$")
_PLACEHOLDER_SERIALS = {
    "0",
    "N/A",
    "NA",
    "UNKNOWN",
    "NONE",
    "NULL",
    "-",
    "--",
    "DEFAULT",
    "123456789",
    "1234567890",
    "SERIAL",
    "TBD",
    "TBA",
    "NOT AVAILABLE",
    "UNAVAILABLE",
    "UNSPECIFIED",
    "TO BE FILLED BY O.E.M.",
}
MIN_SERIAL_LEN = 4

_cache: OrderedDict[str, tuple[float, dict[str, Any]]] = OrderedDict()
_cache_lock = threading.Lock()
_inflight: dict[str, list[Any]] = {}  # scope → [lock, waiters]: one build per scope at a time


# --------------------------------------------------------------------------- small helpers


def valid_mac(value: Any) -> str:
    """Normalized MAC usable as an identity; '' for placeholders, broadcast and multicast MACs."""
    m = normalize_mac(value)
    if not m or m in ("000000000000", "ffffffffffff") or int(m[:2], 16) & 1:
        return ""
    return m


def valid_serial(value: Any) -> str:
    """Upper-cased serial usable as an identity; '' for placeholders such as 'N/A' or '0'."""
    text = re.sub(r"\s+", " ", str(value or "").strip()).upper()
    if len(text) < MIN_SERIAL_LEN or text in _PLACEHOLDER_SERIALS or len(set(text)) == 1:
        return ""
    return text


# Address space a site LAN uses (RFC 1918, carrier-grade NAT, IPv6 ULA). Python's ``is_private`` also
# counts documentation / benchmarking / link-local ranges, which are never anyone's LAN.
LAN_NETS = tuple(
    ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fc00::/7")
)
# Not globally routed, so reused at many places (BGP-over-IPsec 169.254/16 inside addresses, benchmarking
# 198.18/15, IETF 192.0.0/24, CGNAT, documentation ranges …) on top of everything ``is_private`` covers.
_NON_GLOBAL = tuple(
    ipaddress.ip_network(n)
    for n in (
        "169.254.0.0/16",
        "198.18.0.0/15",
        "192.0.0.0/24",
        "100.64.0.0/10",
        "192.0.2.0/24",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "fe80::/10",
        "2001:db8::/32",
    )
)


def _addr(ip: Any) -> Any:
    try:
        return ipaddress.ip_address(str(ip).split("/")[0].strip())
    except ValueError:
        return None


def _lan_private(ip: Any) -> bool:
    """An address (or network) in LAN space: RFC 1918, CGNAT or IPv6 ULA. For the prefix index, placement and
    LAN-neighbour inference only."""
    addr = _addr(ip)
    return addr is not None and any(addr.version == n.version and addr in n for n in LAN_NETS)


def _site_scoped(ip: Any) -> bool:
    """Not globally routed (private, link-local, CGNAT, benchmarking, documentation …): the same address may
    exist at several sites, so links / peers / path-trace owners on it are only matched within a site."""
    addr = _addr(ip)
    if addr is None:
        return False
    return addr.is_private or any(addr.version == n.version and addr in n for n in _NON_GLOBAL)


def _private(ip: Any) -> bool:
    """Site scoping (see :func:`_site_scoped`); kept for path trace and older callers."""
    return _site_scoped(ip)


def _sites_ok(a: Any, b: Any) -> bool:
    """Two things may be the same box / adjacent unless both name sites and none is shared."""
    a, b = set(a or ()), set(b or ())
    return not a or not b or bool(a & b)


def norm_host(name: Any) -> str:
    """'CORE-SW1.corp.example.com' → 'core-sw1' (IPs and MACs → '')."""
    text = str(name or "").strip().lower()
    if not text or normalize_mac(text) or _is_ip(text):
        return ""
    text = text.split(".")[0]
    text = re.sub(r"[^a-z0-9_-]", "", text)
    return text if len(text) >= 3 else ""


def norm_if(name: Any) -> str:
    """Comparable interface name: 'GigabitEthernet1/0/1' ≡ 'Gi1/0/1', 'ge-0/0/1.0' ≡ 'ge-0/0/1'."""
    text = re.sub(r"\s+", "", str(name or "").strip().lower())
    for long, short in _IF_LONG:
        if text.startswith(long):
            text = short + text[len(long) :]
            break
    return re.sub(r"\.0$", "", text)


def _is_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(str(text).split("/")[0])
        return True
    except ValueError:
        return False


def _ip(text: Any) -> str:
    raw = str(text or "").strip().split("/")[0]
    try:
        return str(ipaddress.ip_address(raw))
    except ValueError:
        return ""


def _tier_label(tier: int) -> str:
    return next((label for t, _, label in TIERS if t == tier), "")


# --------------------------------------------------------------------------- source access


LAST_GOOD_MAX = 1024
POOL_WORKERS = 8  # concurrent source / device calls per build
_last_good: OrderedDict[tuple, tuple[float, list[Any]]] = OrderedDict()
_fail_since: dict[tuple, float] = {}
_last_good_lock = threading.Lock()


class _Sources:
    """Per-source call bookkeeping → the ``sources`` list in the response.

    v0.10.23: thread-safe (builds call sources concurrently), timed per source, and backed by a
    last-good snapshot per (source, capability, call): when a call fails and an earlier answer exists,
    that answer is used and the source is marked ``stale`` (with ``stale_since``) instead of its
    devices disappearing from the map. Failures without a fallback are recorded in ``uncovered`` so
    the caller can keep serving the previous complete map.
    """

    def __init__(self) -> None:
        self.status: dict[str, dict[str, Any]] = {}
        self.uncovered: set[str] = set()  # sources whose failure left a hole in this build
        self.caps: list[str] = []  # limits hit during this build (shown as data gaps)
        self._lock = threading.RLock()

    def _row(self, c: Any) -> dict[str, Any]:
        sid = c.provider_id
        with self._lock:
            if sid not in self.status:
                self.status[sid] = {
                    "source": sid,
                    "product": f"{c.manifest.vendor} {c.manifest.product}".strip(),
                    "category": c.manifest.category,
                    "capabilities": [x for x in c.manifest.capabilities if x in _REPORT_CAPS],
                    "ok": True,
                    "error": "",
                    "records": 0,
                    "stale": False,
                    "stale_since": None,
                    "ms": 0,
                    "calls": 0,
                }
            return self.status[sid]

    def cap(self, message: str) -> None:
        with self._lock:
            if message not in self.caps:
                self.caps.append(message)

    def call(self, c: Any, capability: str, fn: Callable[[], Any], key: Any = None) -> list[Any]:
        """Run one source call. ``key`` (e.g. ``(method, arg)``) enables the last-good fallback."""
        row = self._row(c)
        lg = (c.provider_id, capability, key) if key is not None else None
        t0 = time.monotonic()
        try:
            out = list(fn() or [])
        except Exception as exc:  # noqa: BLE001 - one failing source never hides the others
            ms = round((time.monotonic() - t0) * 1000)
            log.info("topology: %s %s failed after %d ms: %s", c.provider_id, capability, ms, exc)
            label = CAPABILITY_LABELS.get(capability, capability)
            msg = f"{label}: {exc}" if str(exc) else f"{label}: {type(exc).__name__}"
            fallback = None
            if lg is not None:
                with _last_good_lock:
                    fallback = _last_good.get(lg)
                    since = _fail_since.setdefault(lg, time.time())
            with self._lock:
                row["ok"] = False
                row["ms"] += ms
                row["calls"] += 1
                if msg not in row["error"]:
                    row["error"] = f"{row['error']}; {msg}" if row["error"] else msg
                if fallback is not None:
                    row["stale"] = True
                    row["stale_since"] = min(x for x in (row["stale_since"], since) if x is not None)
                    row["records"] += len(fallback[1])
                else:
                    self.uncovered.add(c.provider_id)
            return list(fallback[1]) if fallback is not None else []
        ms = round((time.monotonic() - t0) * 1000)
        if lg is not None:
            with _last_good_lock:
                _last_good[lg] = (time.time(), out)
                _last_good.move_to_end(lg)
                _fail_since.pop(lg, None)
                while len(_last_good) > LAST_GOOD_MAX:
                    _last_good.popitem(last=False)
        with self._lock:
            row["records"] += len(out)
            row["ms"] += ms
            row["calls"] += 1
        return out

    def gather(self, capability: str, method: str, *args: Any) -> list[Any]:
        jobs = [
            (c, lambda c=c: getattr(c, method)(*args), (method, *[str(a) for a in args]))
            for c in sdk.sources(capability)
        ]
        return [x for part in self.run(capability, jobs) for x in part]

    def run(self, capability: str, jobs: list[tuple[Any, Callable[[], Any], Any]]) -> list[list[Any]]:
        """Run ``[(connector, fn, last-good key)]`` concurrently; results in job order."""
        if not jobs:
            return []
        if len(jobs) == 1:
            c, fn, key = jobs[0]
            return [self.call(c, capability, fn, key)]
        with ThreadPoolExecutor(max_workers=min(POOL_WORKERS, len(jobs)), thread_name_prefix="topology") as pool:
            futures = [pool.submit(self.call, c, capability, fn, key) for c, fn, key in jobs]
            return [f.result() for f in futures]

    @property
    def degraded(self) -> bool:
        return bool(self.uncovered)

    def timing_text(self) -> str:
        return ", ".join(
            f"{r['source']}={r['ms']}ms/{r['calls']}/{r['records']}rec{'!' if not r['ok'] else ''}"
            for r in self.status.values()
        )


_TOPO_CAPS = (INVENTORY, NEIGHBORS, INTERFACES, ARP_TABLE, ROUTES, TUNNELS)
# Also shown per source by live health (phase 2) and path trace (phase 3).
_REPORT_CAPS = (*_TOPO_CAPS, HEALTH, ALERTS, ENDPOINT_LOCATE, MAC_TABLE, POLICY_LOOKUP)


# --------------------------------------------------------------------------- cross-source site scope

SITE_CACHE_TTL_S = 120.0
# Words that often differ between systems naming the same place ("HQ Campus" vs "HQ"). Dropped only
# when that never makes two different sites of one source look alike (see SiteScope.loose_ok).
_SITE_AFFIXES = ("site", "campus", "clinic", "office")
_site_cache: dict[str, tuple[float, list[Any]]] = {}


def site_name_norm(name: Any) -> str:
    """'HQ-Campus ' → 'hq campus': case-insensitive, punctuation and whitespace collapsed."""
    return " ".join(re.sub(r"[^0-9a-z]+", " ", str(name or "").lower()).split())


def site_name_loose(name: Any) -> str:
    """'hq campus' → 'hq', 'site hq' → 'hq' (a lone affix word is kept: 'campus' stays 'campus')."""
    words = site_name_norm(name).split()
    if len(words) > 1 and words[0] == "site":
        words = words[1:]
    if len(words) > 1 and words[-1] in _SITE_AFFIXES:
        words = words[:-1]
    return " ".join(words)


_site_last_good: dict[str, list[Any]] = {}
_site_refreshing: set[str] = set()
_site_refreshing_lock = threading.Lock()
SITE_RETRY_S = 30.0


def listed_sites() -> tuple[dict[str, list[Any]], dict[str, str]]:
    """({source id: [Site]}, {source id: product}) for every inventory source.

    Answers are cached briefly; a failing ``list_sites`` is never cached: the last good list of that
    source is used instead (so a DNS blip does not empty every site of that source for minutes).
    """
    now = time.time()
    out: dict[str, list[Any]] = {}
    products: dict[str, str] = {}
    todo = []
    background = []
    for c in sdk.sources(INVENTORY):
        products[c.provider_id] = f"{c.manifest.vendor} {c.manifest.product}".strip()
        hit = _site_cache.get(c.provider_id)
        if hit and now - hit[0] < SITE_CACHE_TTL_S:
            out[c.provider_id] = hit[1]
        elif hit:
            # Stale-while-revalidate (v0.10.23 review): answer with the previous list at once and
            # refresh in the background, so a source that is down never holds up a request.
            out[c.provider_id] = hit[1]
            background.append(c)
        else:
            todo.append(c)

    def one(c: Any) -> tuple[str, list[Any]]:
        try:
            rows = list(c.list_sites() or [])
        except Exception as exc:  # noqa: BLE001 - keep the last good list, never cache a failure
            log.info("topology: %s list_sites failed: %s", c.provider_id, exc)
            _site_errors[c.provider_id] = f"Sites: {exc}" if str(exc) else f"Sites: {type(exc).__name__}"
            rows = list(_site_last_good.get(c.provider_id, []))
            # Retry this source after SITE_RETRY_S, not on every request.
            _site_cache[c.provider_id] = (time.time() - SITE_CACHE_TTL_S + SITE_RETRY_S, rows)
            return c.provider_id, rows
        _site_errors.pop(c.provider_id, None)
        _site_cache[c.provider_id] = (time.time(), rows)
        _site_last_good[c.provider_id] = rows
        return c.provider_id, rows

    for c in background:
        with _site_refreshing_lock:
            if c.provider_id in _site_refreshing:
                continue
            _site_refreshing.add(c.provider_id)

        def refresh(c: Any = c) -> None:
            try:
                one(c)
            finally:
                with _site_refreshing_lock:
                    _site_refreshing.discard(c.provider_id)

        threading.Thread(target=refresh, name=f"topology-sites-{c.provider_id}", daemon=True).start()
    if len(todo) == 1:
        out.update([one(todo[0])])
    elif todo:
        with ThreadPoolExecutor(max_workers=min(POOL_WORKERS, len(todo)), thread_name_prefix="topology-sites") as pool:
            out.update(pool.map(one, todo))
    return out, products


def _listed_sites() -> dict[str, list[Any]]:
    """{source id: [Site]} for every inventory source that lists sites (compatibility helper)."""
    return {k: v for k, v in listed_sites()[0].items() if v}


class SiteScope:
    """One canonical site as every connected source knows it (v0.10.23: through ``topology_sites``).

    The selected key may be a canonical key, any connector site key, a native site id or a site name.
    A record is in scope when the registry places it at this canonical site (its connector site, a
    user mapping, LLDP adjacency learned earlier or its host name). Per source, ``args_for`` says how
    to ask it:

    * ``[None]``            no site selected: everything;
    * ``[key, …]``          the source's own site keys of this canonical site;
    * ``None``              ask unscoped and filter (the source has devices placed without a site key,
                            or no organisation index tells us it does not);
    * ``[]``                the source has nothing at this site: skip it.
    """

    def __init__(self, site_key: str | None, reg: Any = None, hint: dict[str, Any] | None = None) -> None:
        self.key = str(site_key or "")
        self.reg = reg if reg is not None else site_registry.registry()
        self.canonical = self.reg.resolve(self.key) if self.key else ""
        if self.canonical:
            self.keys = self.reg.keys_of(self.canonical)
            self.name = self.reg.name(self.canonical)
            self.by_source = self.reg.by_source(self.canonical)
        else:
            self.keys = {self.key} if self.key else set()
            self.name = ""
            self.by_source = {}
        self.hint = hint
        self.extra: set[str] = set()  # sources with devices placed here by a user mapping / LLDP
        if self.canonical:
            for rk, target in (self.reg.user.get("device_sites") or {}).items():
                if ":" in rk and self.reg.resolve(target) == self.canonical:
                    self.extra.add(rk.split(":", 1)[0])
            for rk, v in (self.reg.learned or {}).items():
                if ":" in rk and v.get("site") == self.canonical:
                    self.extra.add(rk.split(":", 1)[0])
        self._placed: dict[str, tuple[str, str]] = {}

    # compatibility (older callers)
    @property
    def listing(self) -> set[str]:
        return set(self.by_source)

    def name_matches(self, name: Any) -> bool:
        return bool(self.canonical) and self.reg.from_name(name) == self.canonical

    def place(self, rec: Any) -> tuple[str, str]:
        rk = f"{getattr(rec, 'source', '')}:{getattr(rec, 'key', '')}"
        hit = self._placed.get(rk)
        if hit is None:
            hit = self._placed[rk] = self.reg.place(rec)
        return hit

    def args_for(self, source_id: str) -> list[str | None] | None:
        """Site arguments to call a source with (see the class docs)."""
        if not self.key:
            return [None]
        if not self.canonical:
            return [self.key]  # a key no source lists: let the source answer for it
        if source_id in self.extra:
            return None
        if self.hint is None:
            return list(dict.fromkeys(self.by_source[source_id])) if source_id in self.by_source else None
        if (self.hint.get("needs_unscoped") or {}).get(source_id):
            return None
        return list(dict.fromkeys(self.by_source.get(source_id, [])))

    def record_in(self, rec: Any) -> bool:
        if not self.key:
            return True
        if not self.canonical:
            return getattr(rec, "site_key", "") in self.keys
        return self.place(rec)[0] == self.canonical

    def unplaced(self, rec: Any) -> bool:
        return not self.place(rec)[0]

    def call(self, status: "_Sources", c: Any, capability: str, method: str, keep: Callable[[Any], bool]) -> list[Any]:
        """Call ``method`` on one source for this scope (see the class docs)."""
        args = self.args_for(c.provider_id)
        if args is None:
            rows = status.call(c, capability, lambda: getattr(c, method)(None), (method, None))
            return [r for r in rows if keep(r)]
        out: list[Any] = []
        for a in args:
            out += status.call(c, capability, lambda a=a: getattr(c, method)(a), (method, a))
        return out


def resolve_scope(site_key: str | None, hint: dict[str, Any] | None = None) -> SiteScope:
    return SiteScope(site_key, hint=hint)


# --------------------------------------------------------------------------- graph builder


class _Graph:
    def __init__(self) -> None:
        self.nodes: dict[str, dict[str, Any]] = {}
        self.alias: dict[str, str] = {}  # source device key → node id
        self.by_mac: dict[str, str] = {}
        self.by_ip: dict[str, list[str]] = defaultdict(list)
        self.by_host: dict[str, list[str]] = defaultdict(list)
        self.links: dict[tuple[str, str, str], dict[str, Any]] = {}
        # v0.10.27: addresses a node saw on its own ports (Device.observed_peers), kept off the payload
        self.observed: dict[str, list[dict[str, Any]]] = defaultdict(list)
        self.ha: dict[str, int] = {}  # HA pairs found by the last _ha_pairs pass (diagnostics)

    # ---- node index ------------------------------------------------------------------------
    def index(self, nid: str) -> None:
        n = self.nodes[nid]
        for m in n["macs"]:
            if valid_mac(m):
                self.by_mac.setdefault(m, nid)
        for ip in n["ips"]:
            if nid not in self.by_ip[ip]:
                self.by_ip[ip].append(nid)
        h = norm_host(n["name"])
        if h and nid not in self.by_host[h]:
            self.by_host[h].append(nid)

    def sites(self, nid: str) -> list[str]:
        return self.nodes[nid]["site_keys"] if nid in self.nodes else []

    def resolve(self, *, mac: str = "", ip: str = "", name: str = "", sites: Any = None, unique: bool = False) -> str:
        """Node for a neighbor/peer identity. MAC is global; IP and host name are site-scoped.

        ``sites``: the sites of the box reporting the identity (LLDP is physically local, so an IP or
        name only matches a node at a compatible site). ``unique``: the reporter is elsewhere (tunnel
        peers) — a private IP or a host name must then be unique across the whole graph.
        """
        mac = valid_mac(mac)
        if mac and mac in self.by_mac:
            return self.by_mac[mac]
        if ip:
            cands = self.by_ip.get(ip, [])
            if unique and _private(ip):
                cands = cands if len(cands) == 1 else []
            elif not unique:
                cands = [c for c in cands if _sites_ok(self.sites(c), sites)]
            if cands:
                return cands[0]
        h = norm_host(name)
        if h:
            cands = self.by_host.get(h, [])
            if not unique:
                cands = [c for c in cands if _sites_ok(self.sites(c), sites)]
            if len(cands) == 1:
                return cands[0]
        return ""

    # ---- links -------------------------------------------------------------------------------
    def add_link(
        self,
        a: str,
        b: str,
        layer: str,
        *,
        a_if: str = "",
        b_if: str = "",
        confidence: float,
        evidence: dict[str, Any],
        state: str = "unknown",
        extra: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        if a > b:
            a, b, a_if, b_if = b, a, b_if, a_if
        k = (a, b, layer)
        link = self.links.get(k)
        if link is None:
            link = Link(
                key=stable_key("link", a, b, layer), a_device=a, b_device=b, layer=layer, confidence=confidence
            ).to_dict()
            link.update(members=[], sources=[], label="")
            self.links[k] = link
        member = {"a_interface": a_if, "b_interface": b_if, "confidence": confidence, "state": state}
        if extra:
            member.update(extra)
        link["members"].append(member)
        if evidence not in link["evidence"]:
            link["evidence"].append(evidence)
        if evidence.get("source") and evidence["source"] not in link["sources"]:
            link["sources"].append(evidence["source"])
        link["confidence"] = max(link["confidence"], confidence)
        return link

    def linked(self, a: str, b: str, layers: tuple[str, ...]) -> bool:
        lo, hi = sorted((a, b))
        return any((lo, hi, layer) in self.links for layer in layers)


def _new_node(nid: str, name: str, role: str) -> dict[str, Any]:
    return {
        "id": nid,
        "name": name,
        "role": role or "unknown",
        "tier": 5,
        "tier_label": "",
        "status": "unknown",
        "discovered": False,
        "remote": False,
        "synthetic": False,
        "vendor_name": "",
        "vendor_names": [],
        "model": "",
        "serial": "",
        "mac": "",
        "macs": [],
        "mgmt_ip": "",
        "ips": [],
        "os_version": "",
        "site_key": "",
        "site_keys": [],
        "site_name": "",
        "site_via": "",  # how the canonical site was decided: site, name, manual, lldp, hostname
        "native_site_keys": [],  # the connectors' own site keys (site_key/site_keys are canonical)
        "sources": [],
        "records": [],
        "members": [],
        "console_url": "",
        "evidence": "inventory",
        "description": "",
        "seen_by": [],
        "uplink": "",
        # Closets map (v0.10.21): counts a source already read for the map; None / "" = not reported.
        "ports_total": None,
        "ports_up": None,
        "ports_warn": None,
        "port_map": "",
        "poe_draw_w": None,
        "clients": None,
        "floor_id": "",
        # v0.10.24 neutral Device fields (first record that has them wins)
        "network_tier": "",  # core | distribution | access | ""
        "floor_key": "",
        "floor_name": "",
        "aliases": [],
        "labels": [],
        # v0.10.25 placement evidence (Device.addresses / lan_prefixes) and inferred LAN neighbours
        "addresses": [],
        "lan_prefixes": [],
        "inferred": False,  # True: not in any connected system; seen only as a router's LAN next hop
        "inferred_reason": "",
        # v0.10.27 high availability: every unit is its own node; ``ha_peer`` = the other unit's node id
        "ha_state": "",  # active | passive | primary | secondary | "ha-pair (inferred)" | ""
        "ha_peer": "",
        "ha_inferred": False,  # the pair (or this unit) comes from naming, not from the vendor
        # v0.10.27 cloud security edges (role "cloud_gateway"): mobile_users | service_connection | remote_network
        "cloud": False,
        "cloud_kind": "",
        "ha_user": False,  # the user confirmed this unit's HA partner (site-map ha_partners)
    }


def _add_unique(lst: list, value: Any) -> None:
    if value not in (None, "") and value not in lst:
        lst.append(value)


def _alias_macs(d: Any) -> list[str]:
    raw = [d.mac]
    if not _ha_unit(d):  # an HA peer's MAC is another box (v0.10.27)
        raw += [m.get("mac") for m in d.members or [] if isinstance(m, dict)]
    raw += list(getattr(d, "alias_macs", None) or [])
    if not getattr(d, "alias_macs", None):
        # transition fallback (v0.10.24): remove when all connectors fill Device.alias_macs
        v = d.vendor or {}
        # transition fallback (v0.10.24): remove when all connectors fill Device.alias_macs
        raw += [v.get("vc_mac"), *list(v.get("chassis_macs") or [])]
    return [m for m in dict.fromkeys(valid_mac(x) for x in raw) if m]


# Roles whose ``members`` are the units of an HA pair (each its own box), not stack members of one box.
_HA_ROLES = {"firewall", "sdwan_edge", "router", "load_balancer", "wireless_controller"}


_HA_EVIDENCE = re.compile(r"^(active|passive|primary|secondary|standby|ha\b|ha[-_ ]|ha$)", re.I)


def _ha_unit(d: Any) -> bool:
    """The record is one unit of an HA pair: an HA-capable role AND HA evidence — its own ``ha_state``
    (not standalone) or members whose role / state says active, passive, primary, secondary or ha-…, or an
    ``ha_peer``. Plain chassis / stack / virtual-chassis members (no such words) stay one box."""
    if str(getattr(d, "role", "") or "") not in _HA_ROLES:
        return False
    state = str(getattr(d, "ha_state", "") or "").strip().lower()
    if state and state != "standalone":
        return True
    for m in getattr(d, "members", None) or []:
        if not isinstance(m, dict):
            continue
        if m.get("ha_peer") or any(
            _HA_EVIDENCE.match(str(m.get(k) or "").strip()) for k in ("role", "state", "ha_state")
        ):
            return True
    return False


def _serials(d: Any, *, members: bool = True) -> list[str]:
    """Serials that identify the record. ``members=False`` (node identity, v0.10.27): an HA unit is only its
    own serial — the two units of a pair are two boxes, drawn as two nodes with an HA link."""
    raw = [d.serial]
    if members or not _ha_unit(d):
        raw += [m.get("serial") for m in d.members or [] if isinstance(m, dict)]
    return [x for x in dict.fromkeys(valid_serial(r) for r in raw) if x]


class _Clusters:
    """Union-find that keeps, per root, which source keys and sites it holds (O(1) compatibility)."""

    def __init__(self, devices: list[Any], site_of: Callable[[Any], str] | None = None) -> None:
        self.p = list(range(len(devices)))
        self.keys: dict[int, dict[str, set[str]]] = {i: {d.source: {d.key}} for i, d in enumerate(devices)}
        site_of = site_of or (lambda d: d.site_key or "")
        self.sites: dict[int, set[str]] = {}
        for i, d in enumerate(devices):
            s = site_of(d)
            self.sites[i] = {s} if s else set()

    def find(self, i: int) -> int:
        while self.p[i] != i:
            self.p[i] = self.p[self.p[i]]
            i = self.p[i]
        return i

    def union(self, a: int, b: int) -> int:
        ra, rb = self.find(a), self.find(b)
        if ra == rb:
            return ra
        if sum(map(len, self.keys[ra].values())) < sum(map(len, self.keys[rb].values())):
            ra, rb = rb, ra
        self.p[rb] = ra
        for src, ks in self.keys.pop(rb).items():
            self.keys[ra].setdefault(src, set()).update(ks)
        self.sites[ra] |= self.sites.pop(rb)
        return ra

    def compatible(self, a: int, b: int) -> bool:
        """Weak merges never join two boxes of one source, nor records at different sites."""
        ra, rb = self.find(a), self.find(b)
        if not _sites_ok(self.sites[ra], self.sites[rb]):
            return False
        ka, kb = self.keys[ra], self.keys[rb]
        if len(ka) > len(kb):
            ka, kb = kb, ka
        return not any(src in kb and ks != kb[src] for src, ks in ka.items())


def tunnel_jitter(t: Any) -> float | None:
    """``Tunnel.jitter_ms`` (v0.10.24); older connectors put it in ``vendor``."""
    value = getattr(t, "jitter_ms", None)
    if value is None:
        # transition fallback (v0.10.24): remove when all connectors fill Tunnel.jitter_ms
        value = (getattr(t, "vendor", None) or {}).get("jitter_ms")
    return value


def _record_key(d: Any) -> str:
    return f"{getattr(d, 'source', '')}:{getattr(d, 'key', '')}"


def _merge_members(group: list[Any]) -> list[dict[str, Any]]:
    """Stack / VC / HA members of one merged node, each with name, serial and status when any record
    of the cluster describes that unit (an HA pair reported by both units stays one node, but both
    units are listed — and searchable — with their own name and state)."""
    base: list[dict[str, Any]] = []
    for d in group:
        if d.members:
            base = [dict(m) for m in d.members if isinstance(m, dict)]
            break
    by_serial = {valid_serial(d.serial): d for d in group if valid_serial(d.serial)}
    seen: set[str] = set()
    for m in base:
        rec = by_serial.get(valid_serial(m.get("serial")))
        if rec is not None:
            seen.add(_record_key(rec))
            for attr, value in (
                ("name", rec.name),
                ("status", rec.status),
                ("model", rec.model),
                ("mgmt_ip", rec.mgmt_ip),
            ):
                if value and not m.get(attr):
                    m[attr] = value
            m.setdefault("record_key", _record_key(rec))
    per_source = Counter(d.source for d in group)
    if any(n > 1 for n in per_source.values()):
        names = {str(m.get("name") or "").lower() for m in base}
        serials = {valid_serial(m.get("serial")) for m in base} - {""}
        for d in group:
            if per_source[d.source] < 2 or _record_key(d) in seen:
                continue
            if (valid_serial(d.serial) and valid_serial(d.serial) in serials) or d.name.lower() in names:
                continue
            base.append(
                {
                    "name": d.name,
                    "serial": d.serial,
                    "model": d.model,
                    "status": d.status,
                    "role": getattr(d, "ha_state", "") or "member",
                    "mgmt_ip": d.mgmt_ip,
                    "record_key": _record_key(d),
                }
            )
    return base


def _resolve_devices(
    g: _Graph,
    devices: list[Any],
    place: dict[str, tuple[str, str]] | None = None,
    site_names: dict[str, str] | None = None,
) -> None:
    """Entity resolution over device records from every source.

    Strong ids (valid chassis/member MAC, real serial) always merge. Weak ids (management IP, host
    name) merge only when compatible: never two keys of one source, never records at different sites.
    ``place`` ({record key: (canonical site, via)}) puts every record on its canonical site
    (v0.10.23); without it the connector's own site key is used, as before.
    """
    devices = [d for d in devices if getattr(d, "key", "")]
    place = place or {}
    site_names = site_names or {}

    def site_of(d: Any) -> str:
        hit = place.get(_record_key(d))
        return hit[0] if hit is not None else (d.site_key or "")

    uf = _Clusters(devices, site_of)
    strong: dict[str, int] = {}
    for i, d in enumerate(devices):
        idents = [f"mac:{m}" for m in _alias_macs(d)] + [f"sn:{x}" for x in _serials(d, members=False)]
        idents.append(f"key:{d.source}:{d.key}")
        for ident in idents:
            if ident in strong:
                uf.union(strong[ident], i)
            else:
                strong[ident] = i
    # Weak ids, bucketed by site so lookups stay small: ident → site ('' = none) → representatives.
    weak: dict[str, dict[str, list[int]]] = defaultdict(lambda: defaultdict(list))
    for i, d in enumerate(devices):  # management IP first, then host name
        idents = ([f"ip:{_ip(d.mgmt_ip)}"] if _ip(d.mgmt_ip) else []) + (
            [f"host:{norm_host(d.name)}"] if norm_host(d.name) else []
        )
        site = site_of(d)
        for ident in idents:
            buckets = weak[ident]
            pools = [buckets[site], buckets[""]] if site else list(buckets.values())
            merged = False
            for pool in pools:
                for c in pool[:MAX_WEAK_CANDIDATES]:
                    if uf.find(c) == uf.find(i) or uf.compatible(c, i):
                        uf.union(c, i)
                        merged = True
                        break
                if merged:
                    break
            if not merged and len(buckets[site]) < MAX_WEAK_CANDIDATES + 1:
                buckets[site].append(i)

    clusters: dict[int, list[Any]] = defaultdict(list)
    for i, d in enumerate(devices):
        clusters[uf.find(i)].append(d)
    for group in clusters.values():
        # Prefer the record of a source whose category manages this kind of box (first wins otherwise).
        group.sort(key=lambda d: (d.role == "unknown", d.source))
        first = group[0]
        nid = node_id_for(group)
        node = _new_node(nid, first.name, first.role)
        statuses = []
        for d in group:
            g.alias[d.key] = nid
            g.alias[f"{d.source}:{d.key}"] = nid
            _add_unique(node["sources"], d.source)
            _add_unique(node["vendor_names"], d.vendor_name)
            for m in _alias_macs(d):
                _add_unique(node["macs"], m)
            csite, via = place.get(_record_key(d), (d.site_key or "", "site" if d.site_key else ""))
            _add_unique(node["site_keys"], csite)
            _add_unique(node["native_site_keys"], d.site_key)
            if csite and not node["site_key"]:
                node["site_key"] = csite
                node["site_name"] = site_names.get(csite) or d.site_name or ""
                node["site_via"] = via
            _add_unique(node["ips"], _ip(d.mgmt_ip))
            if not node["serial"] and valid_serial(d.serial):
                node["serial"] = d.serial
            for attr in ("model", "mgmt_ip", "os_version", "site_name", "console_url"):
                if not node[attr] and getattr(d, attr, ""):
                    node[attr] = getattr(d, attr)
            if node["role"] == "unknown" and d.role != "unknown":
                node["role"] = d.role
            for attr in ("network_tier", "floor_key", "floor_name"):
                if not node[attr] and getattr(d, attr, ""):
                    node[attr] = str(getattr(d, attr))
            for attr in ("aliases", "labels", "lan_prefixes"):
                for x in getattr(d, attr, None) or []:
                    _add_unique(node[attr], str(x))
            for x in getattr(d, "addresses", None) or []:
                if _ip(x):
                    _add_unique(node["addresses"], _ip(x))
                    _add_unique(node["ips"], _ip(x))  # indexed: a router's next hop can resolve to it
            if node["clients"] is None and getattr(d, "clients", None) is not None:
                node["clients"] = getattr(d, "clients")
            ha = _ha_word(getattr(d, "ha_state", ""))
            if ha and not node["ha_state"]:
                node["ha_state"] = ha
            if getattr(d, "role", "") == "cloud_gateway":
                node["cloud"] = True
                node["cloud_kind"] = node["cloud_kind"] or str(getattr(d, "cloud_kind", "") or "")
            for p in getattr(d, "observed_peers", None) or []:
                if isinstance(p, dict) and len(g.observed[nid]) < 400:
                    g.observed[nid].append(dict(p, source=d.source))
            statuses.append(d.status)
            node["records"].append(
                {
                    "source": d.source,
                    "key": d.key,
                    "native_id": d.native_id,
                    "name": d.name,
                    "role": d.role,
                    "model": d.model,
                    "status": d.status,
                    "site_key": d.site_key,
                    "serial": d.serial,
                    "console_url": d.console_url,
                    "vendor": dict(d.vendor or {}),
                }
            )
        node["members"] = [] if group and all(_ha_unit(d) for d in group) else _merge_members(group)
        node["_ha_members"] = [dict(m) for d in group if _ha_unit(d) for m in d.members or [] if isinstance(m, dict)]
        node["mac"] = valid_mac(first.mac) or (node["macs"][0] if node["macs"] else "")
        node["vendor_name"] = node["vendor_names"][0] if node["vendor_names"] else ""
        node["status"] = (
            "up"
            if "up" in statuses and "down" not in statuses
            else "degraded"
            if "up" in statuses
            else "down"
            if "down" in statuses
            else "degraded"
            if "degraded" in statuses
            else "unknown"
        )
        g.nodes[nid] = node
        g.index(nid)
    _ha_pairs(g)


# --------------------------------------------------------------------------- HA pairs (v0.10.27)

_HA_WORDS = {
    "active": "active",
    "passive": "passive",
    "primary": "primary",
    "secondary": "secondary",
    "active-primary": "active",
    "active-secondary": "active",
    "master": "primary",
    "slave": "secondary",
    "backup": "passive",
    "standby": "passive",
    "non-functional": "non-functional",
    "suspended": "suspended",
}
_UNIT = re.compile(r"^(?P<stem>.*?[A-Z0-9])[-_ ]?(?P<unit>0?[12]|[AB])$")
_PAIRS = ({"1", "2"}, {"A", "B"})


def _ha_word(value: Any) -> str:
    return _HA_WORDS.get(str(value or "").strip().lower(), "")


def unit_of(name: Any) -> tuple[str, str]:
    """'PAEHWC1' → ('PAEHWC', '1'); 'fw-hq-b' → ('FW-HQ', 'B'); ('', '') when the name has no unit suffix."""
    text = str(name or "").strip().upper()
    if not text or _is_ip(text):
        return "", ""
    text = text.split(".", 1)[0]
    m = _UNIT.match(text)
    if not m or len(m.group("stem")) < 3:
        return "", ""
    return m.group("stem").rstrip("-_ "), m.group("unit").lstrip("0") or "0"


_OTHER_UNIT = {"1": "2", "2": "1", "A": "B", "B": "A"}


def partner_name(name: Any) -> str:
    """The other unit's name under the 1/2 or A/B convention, keeping case and zero padding:
    'PA-WHL1' → 'PA-WHL2', 'fw-hq-b' → 'fw-hq-a', 'EDGE01' → 'EDGE02' ('' when the name has no unit)."""
    raw = str(name or "").strip().split(".", 1)[0]
    stem, unit = unit_of(raw)
    other = _OTHER_UNIT.get(unit)
    if not stem or not other:
        return ""
    last = raw[-1]
    return raw[:-1] + (other.lower() if last.islower() else other)


# v0.10.30: record key → canonical site of HA units placed by their partner's name (organisation-wide,
# refreshed by every organisation read; see propagate_name_partners). Site maps read it.
_name_partner_site: dict[str, str] = {}


def propagate_name_partners(devices: list[Any], place: dict[str, tuple[str, str]]) -> dict[str, str]:
    """Organisation-wide, vendor-neutral: an HA-capable record with no site evidence takes the site of its
    partner when the names say they are the two units of one pair — same source, same role, same name stem,
    units 1/2 or A/B — and that stem lives at exactly one site. A passive unit that is named only by system
    or event logs (it passes no traffic, so it carries no addresses) lands next to the active unit this way.

    Ambiguous stems (the same stem placed at two sites, or two unplaced candidates for one unit) place nothing.
    """
    placed: dict[tuple[str, str, str], dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
    for d in devices:
        if str(getattr(d, "role", "") or "") not in _HA_ROLES:
            continue
        ck = place.get(_record_key(d), ("", ""))[0]
        stem, unit = unit_of(d.name)
        if ck and stem:
            placed[(d.source, d.role, stem)][ck].add(unit)
    wanted: dict[tuple[str, str, str, str], list[str]] = defaultdict(list)
    for d in devices:
        rk = _record_key(d)
        if str(getattr(d, "role", "") or "") not in _HA_ROLES or place.get(rk, ("", ""))[0]:
            continue
        stem, unit = unit_of(d.name)
        if stem:
            wanted[(d.source, d.role, stem, unit)].append(rk)
    found: dict[str, str] = {}
    for (src, role, stem, unit), rks in wanted.items():
        sites = placed.get((src, role, stem)) or {}
        if len(rks) != 1 or len(sites) != 1:
            continue
        ck, units = next(iter(sites.items()))
        if unit in units or not any(unit in pair and units & pair for pair in _PAIRS):
            continue
        found[rks[0]] = ck
        place[rks[0]] = (ck, "ha_name")
    global _name_partner_site
    _name_partner_site = dict(found)  # swapped, never emptied in place: site builds may be reading it
    return found


def _ha_link(g: _Graph, a: str, b: str, *, inferred: bool, detail: str, source: str = "") -> None:
    link = g.add_link(
        a,
        b,
        "ha",
        confidence=0.6 if inferred else 1.0,
        evidence={"kind": "ha-inferred" if inferred else "ha-config", "source": source, "detail": detail},
        state="unknown",
    )
    link["label"] = "HA pair"
    link["inferred"] = inferred
    link["ha_states"] = {a: g.nodes[a]["ha_state"], b: g.nodes[b]["ha_state"]}
    for x, y in ((a, b), (b, a)):
        g.nodes[x]["ha_peer"] = g.nodes[x]["ha_peer"] or y
        if inferred:
            g.nodes[x]["ha_inferred"] = True


def _ha_pairs(g: _Graph) -> dict[str, int]:
    """Every HA unit its own node, an "ha" link between the two (vendor-neutral):

    * explicit: a record's ``members`` name the peer's serial → linked to the node with that serial, or to a
      node made for the peer from what the record says about it (name, state);
    * inferred: two units of one source at the same site whose names differ only by unit 1/2 or A/B."""
    by_serial: dict[str, str] = {}
    for nid, n in g.nodes.items():
        for x in [n["serial"], *[r.get("serial") for r in n["records"]]]:
            if valid_serial(x):
                by_serial.setdefault(valid_serial(x), nid)
    made = {"explicit": 0, "inferred": 0, "peer_nodes": 0}
    for nid in list(g.nodes):
        n = g.nodes[nid]
        members = n.pop("_ha_members", None) or []
        if n["role"] not in _HA_ROLES or not members:
            continue
        own = {valid_serial(n["serial"])} | {valid_serial(r.get("serial")) for r in n["records"]}
        for m in members:
            sn = valid_serial(m.get("serial"))
            state = _ha_word(m.get("role"))
            if not sn:
                continue
            if sn in own:
                n["ha_state"] = n["ha_state"] or state
                continue
            peer = by_serial.get(sn)
            if peer is None:
                peer = stable_key("ha-peer", sn)
                p = _new_node(peer, str(m.get("name") or "") or f"HA peer of {n['name']}", n["role"])
                p.update(
                    serial=str(m.get("serial") or ""),
                    model=str(m.get("model") or n["model"]),
                    status=str(m.get("status") or "unknown"),
                    ha_state=state,
                    discovered=True,
                    evidence="ha",
                    site_key=n["site_key"],
                    site_name=n["site_name"],
                    site_via="ha_peer",
                    vendor_name=n["vendor_name"],
                    description=f"The other unit of {n['name']}'s HA pair (named by {', '.join(n['sources'])}).",
                )
                p["site_keys"] = list(n["site_keys"])
                p["sources"] = list(n["sources"])
                g.nodes[peer] = p
                g.index(peer)
                by_serial[sn] = peer
                made["peer_nodes"] += 1
            elif state and not g.nodes[peer]["ha_state"]:
                g.nodes[peer]["ha_state"] = state
            if peer != nid and not g.linked(nid, peer, ("ha",)):
                _ha_link(g, nid, peer, inferred=False, source=n["sources"][0] if n["sources"] else "",
                         detail=f"{n['name']} and {g.nodes[peer]['name']} are an HA pair (reported by "
                         f"{', '.join(n['sources'])})")  # fmt: skip
                made["explicit"] += 1
    # Inferred from names: same source, same site, same stem, units 1/2 or A/B.
    groups: dict[tuple[str, str, str, str], dict[str, str]] = defaultdict(dict)
    for nid, n in g.nodes.items():
        if n["role"] not in _HA_ROLES or n["inferred"] or not n["site_key"]:
            continue
        stem, unit = unit_of(n["name"])
        if stem and n["sources"]:
            groups[(n["sources"][0], n["site_key"], n["role"], stem)].setdefault(unit, nid)
    for (_src, _site, _role, _stem), units in groups.items():
        for pair in _PAIRS:
            if pair <= set(units):
                a, b = (units[u] for u in sorted(pair))
                if g.linked(a, b, ("ha",)) or g.nodes[a]["ha_peer"] or g.nodes[b]["ha_peer"]:
                    continue
                for x in (a, b):
                    g.nodes[x]["ha_state"] = g.nodes[x]["ha_state"] or "ha-pair (inferred)"
                _ha_link(g, a, b, inferred=True, source=_src,
                         detail=f"{g.nodes[a]['name']} and {g.nodes[b]['name']}: same site, same name with unit "
                         f"{'/'.join(sorted(pair))} — probably an HA pair")  # fmt: skip
                made["inferred"] += 1
    g.ha = made
    return made


_ha_naming: dict[str, dict[str, Any]] = {}  # "source|role" → {"paired": n, "single": n, "ratio": x}
HA_PAIR_SHARE = 0.7
HA_MIN_PAIRED_SITES = 3


def learn_ha_naming(devices: list[Any], place: dict[str, tuple[str, str]]) -> dict[str, dict[str, Any]]:
    """Organisation-wide: per (source, role), how many sites with unit-numbered names have both units."""
    units: dict[tuple[str, str, str, str], set[str]] = defaultdict(set)
    for d in devices:
        if str(getattr(d, "role", "") or "") not in _HA_ROLES:
            continue
        ck = place.get(_record_key(d), ("", ""))[0]
        stem, unit = unit_of(d.name)
        if ck and stem:
            units[(d.source, d.role, ck, stem)].add(unit)
    stats: dict[str, dict[str, Any]] = defaultdict(lambda: {"paired": 0, "single": 0})
    for (src, role, _ck, _stem), got in units.items():
        key = f"{src}|{role}"
        if any(p <= got for p in _PAIRS):
            stats[key]["paired"] += 1
        elif got & {"1", "A"}:
            stats[key]["single"] += 1
    out = {}
    for k, v in stats.items():
        total = v["paired"] + v["single"]
        out[k] = {**v, "ratio": round(v["paired"] / total, 2) if total else 0.0}
    _ha_naming.clear()
    _ha_naming.update(out)
    return out


def _partner_candidates(n: dict[str, Any], expected: str, unplaced: list[Any] | None) -> list[dict[str, Any]]:
    """Records that could be the missing unit of ``n``'s pair: unplaced records of the same role whose name is
    the expected partner name or carries the same stem, and units with the expected name placed at another
    site (from the organisation index). Vendor-neutral: names and roles only."""
    stem, unit = unit_of(n["name"])
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for d in unplaced or []:
        if str(getattr(d, "role", "") or "") != n["role"]:
            continue
        d_stem, d_unit = unit_of(d.name)
        exact = expected and str(d.name).strip().lower() == expected.lower()
        if not exact and not (stem and d_stem == stem and d_unit != unit):
            continue
        rk = _record_key(d)
        seen.add(rk)
        labels = [str(x) for x in getattr(d, "labels", None) or []]
        out.append(
            {
                "record_key": rk,
                "name": d.name,
                "serial": str(getattr(d, "serial", "") or ""),
                "model": str(getattr(d, "model", "") or ""),
                "status": str(getattr(d, "status", "") or "unknown"),
                "source": d.source,
                "site_name": "",
                "labels": labels[:4],
                "why": "Same name pattern, and no site evidence: it carries no address NodeWatch could place.",
                "placeable": True,
            }
        )
    if expected:
        try:
            from app.services import topology_search

            nodes = topology_search._current().get("nodes") or []
        except Exception:  # noqa: BLE001 - the organisation index is optional here
            nodes = []
        for x in nodes:
            if str(x.get("name") or "").strip().lower() != expected.lower() or x.get("role") != n["role"]:
                continue
            recs = x.get("records") or []
            rk = f"{recs[0]['source']}:{recs[0]['key']}" if recs else ""
            if rk in seen or (x.get("site_key") and x.get("site_key") == n["site_key"]):
                continue
            out.append(
                {
                    "record_key": rk,
                    "name": x.get("name") or "",
                    "serial": x.get("serial") or "",
                    "model": x.get("model") or "",
                    "status": x.get("status") or "unknown",
                    "source": (x.get("sources") or [""])[0],
                    "site_name": x.get("site_name") or "",
                    "labels": [],
                    "why": (
                        f"Has the expected name but is placed at {x.get('site_name')}."
                        if x.get("site_name")
                        else "Has the expected name but no site."
                    ),
                    "placeable": bool(rk),
                }
            )
    return out[:6]


def _partner_brief(
    g: _Graph, n: dict[str, Any], *, expected: str, confirmed_at: Any = None, unplaced: list[Any] | None = None
) -> dict[str, Any]:
    """What NodeWatch knows about the missing unit of ``n``'s pair and why it believes in it (v0.10.30).

    Every line is evidence that exists in this build — the confirmation, the naming convention across the
    organisation, the partner's own state and which systems were asked — so the card reads as reasoning,
    not as boilerplate."""
    stem, unit = unit_of(n["name"])
    stats = _ha_naming.get(f"{(n['sources'] or [''])[0]}|{n['role']}") or {}
    try:
        at = float(confirmed_at) if confirmed_at else None
    except (TypeError, ValueError):
        at = None
    return {
        "partner": {
            "id": n["id"],
            "name": n["name"],
            "ha_state": n["ha_state"],
            "status": n["status"],
            "model": n["model"],
            "os_version": n.get("os_version") or "",
            "serial": n["serial"],
            "mgmt_ip": n["mgmt_ip"],
            "labels": list(n.get("labels") or [])[:6],
        },
        "expected_name": expected,
        "unit": unit,
        "stem": stem,
        "confirmed_at": at,
        "naming": {
            "paired_sites": int(stats.get("paired") or 0),
            "single_sites": int(stats.get("single") or 0),
            "share": float(stats.get("ratio") or 0.0),
        },
        "asked": sorted({*n["sources"]}),
        "candidates": _partner_candidates(n, expected, unplaced),
    }


def _ha_user_partners(g: _Graph, partners: dict[str, Any] | None = None, unplaced: list[Any] | None = None) -> int:
    """HA partners the user confirmed (site-map ``ha_partners``: {unit record key or node id: {name, state}}):
    when the unit has no real partner node, draw one ("ha-user"), passive by default, linked by an "ha" link.
    A real partner found later (system logs, a firewall manager, the other unit's logs) replaces it by itself.

    v0.10.30: the drawn unit is named by the pair's convention (PA-WHL1 → PA-WHL2) and carries ``ha_brief``
    (see :func:`_partner_brief`); a unit whose confirmed partner has since been found by a system says so
    (``ha_user_found``)."""
    if partners is None:
        try:
            partners = site_registry.user_map().get("ha_partners") or {}
        except Exception:  # noqa: BLE001
            partners = {}
    made = 0
    for key, want in (partners or {}).items():
        nid = key if key in g.nodes else g.alias.get(key, "")
        n = g.nodes.get(nid)
        if n is None or n["inferred"]:
            continue
        n["ha_user"] = True  # the UI offers "remove" on this unit
        want = want if isinstance(want, dict) else {}
        peer = g.nodes.get(n.get("ha_peer") or "")
        if peer is not None and not peer.get("inferred"):
            # a real partner exists: the assertion is not needed, and the card says it was right
            n["ha_user_found"] = {"name": peer["name"], "sources": list(peer.get("sources") or [])}
            continue
        if peer is not None:  # replace a guess from naming with what the user confirmed
            g.links.pop((min(nid, peer["id"]), max(nid, peer["id"]), "ha"), None)
            g.nodes.pop(peer["id"], None)
            n["ha_peer"] = ""
        pid = f"ha-user:{key}"
        state = str(want.get("state") or "passive")
        expected = partner_name(n["name"])
        p = _new_node(pid, str(want.get("name") or "") or expected or f"{n['name']} partner", n["role"])
        p.update(
            inferred=True,
            evidence="ha-user",
            inferred_reason=f"{state.capitalize()} HA partner of {n['name']} (you confirmed it; it writes no traffic logs)",
            ha_state=state,
            ha_user=True,
            status="unknown",
            site_key=n["site_key"],
            site_name=n["site_name"],
            site_via="ha_peer",
            vendor_name=n["vendor_name"],
            model=n["model"],
            os_version=n.get("os_version") or "",
        )
        p["site_keys"] = list(n["site_keys"])
        p["sources"] = list(n["sources"])
        p["ha_brief"] = _partner_brief(
            g, n, expected=expected, confirmed_at=want.get("confirmed_at"), unplaced=unplaced
        )
        g.nodes[pid] = p
        if n["ha_state"] in ("", "ha-pair (inferred)", "active (inferred)"):
            n["ha_state"] = "active" if state == "passive" else n["ha_state"]
        p["ha_brief"]["partner"]["ha_state"] = n["ha_state"]
        link = g.add_link(
            nid,
            pid,
            "ha",
            confidence=0.9,
            evidence={"kind": "ha-user", "source": "user", "detail": p["inferred_reason"]},
            state="unknown",
        )
        link.update(label="HA pair", inferred=True, ha_user=True, ha_states={nid: n["ha_state"], pid: state})
        n["ha_peer"], p["ha_peer"] = pid, nid
        made += 1
    g.ha["user_confirmed"] = made
    return made


def _ha_missing_units(g: _Graph, unplaced: list[Any] | None = None) -> int:
    """A site showing only unit 1 (or A) of a pair, where ≥ 70 % of the sites with this naming have both: draw
    the other unit as inferred — usually the passive unit, which writes no logs."""
    made = 0
    # v0.10.35: pairs the user confirmed elsewhere teach the convention too (a passive unit never appears in
    # any system, so naming statistics alone undercount real pairs), and a unit a system reports as
    # active/passive is half of a pair by definition - its partner is drawn without asking.
    try:
        confirmed = len(site_registry.user_map().get("ha_partners") or {})
    except Exception:  # noqa: BLE001
        confirmed = 0
    for nid in list(g.nodes):
        n = g.nodes[nid]
        if n["role"] not in _HA_ROLES or n["ha_peer"] or n["inferred"] or not n["sources"] or not n["site_key"]:
            continue
        if n["ha_state"] in ("standalone",):
            continue
        reported = str(n["ha_state"] or "").split(" ")[0] in ("active", "passive", "primary", "secondary")
        stats = _ha_naming.get(f"{n['sources'][0]}|{n['role']}") or {}
        paired = int(stats.get("paired", 0)) + confirmed
        single = max(0, int(stats.get("single", 0)) - confirmed)
        ratio = paired / (paired + single) if paired + single else 0.0
        by_naming = paired >= HA_MIN_PAIRED_SITES and ratio >= HA_PAIR_SHARE
        stem, unit = unit_of(n["name"])
        if not reported and (not by_naming or unit not in ("1", "A")):
            continue
        guess = partner_name(n["name"]) or f"{n['name']} partner"
        pid = stable_key("ha-inferred", n["site_key"], stem or n["name"])
        if pid in g.nodes:
            continue
        p = _new_node(pid, guess, n["role"])
        pct = round(ratio * 100)
        own = str(n["ha_state"] or "").split(" ")[0]
        mine = "passive" if own in ("active", "primary") else "active" if own in ("passive", "secondary") else "passive"
        p.update(
            inferred=True,
            inferred_reason=(
                f"{n['name']} reports HA state {own}, so it has a partner; no connected system lists it "
                f"({mine} units pass no traffic and send no logs)."
                if reported
                else f"Probably {guess} (passive, sends no logs): {pct}% of sites with this naming have both units, "
                f"and no connected system lists this one."
            ),
            evidence="ha-inferred",
            status="unknown",
            ha_state=f"{mine} (inferred)",
            ha_inferred=True,
            site_key=n["site_key"],
            site_name=n["site_name"],
            site_via="ha_peer",
            vendor_name=n["vendor_name"],
            model=n["model"],
        )
        p["site_keys"] = list(n["site_keys"])
        p["sources"] = list(n["sources"])
        p["ha_brief"] = _partner_brief(g, n, expected=guess, unplaced=unplaced)
        g.nodes[pid] = p
        n["ha_state"] = n["ha_state"] or "active (inferred)"
        p["ha_brief"]["partner"]["ha_state"] = n["ha_state"]
        _ha_link(g, nid, pid, inferred=True, source=n["sources"][0],
                 detail=f"{p['inferred_reason']}")  # fmt: skip
        made += 1
    return made


def node_id_for(group: list[Any]) -> str:
    """The stable node id of a cluster of device records (shared by site maps and org search)."""
    group = sorted(group, key=lambda d: (d.role == "unknown", d.source))
    first = group[0]
    macs = sorted({valid_mac(d.mac) for d in group if valid_mac(d.mac)})
    return stable_key("node", macs[0] if macs else f"{first.source}:{first.key}")


def _discovered_node(g: _Graph, nb: Any, local_name: str, sites: list[str]) -> str:
    mac = valid_mac(nb.remote_mac)
    ip = _ip(nb.remote_mgmt_ip)
    scope = ",".join(sorted(sites))  # an IP/name is only an identity within one site
    weak = ip or norm_host(nb.remote_name)
    ident = mac or (f"{scope}|{weak}" if weak else f"{nb.device_key}:{nb.local_interface}")
    nid = stable_key("discovered", ident)
    node = g.nodes.get(nid)
    if node is None:
        node = _new_node(
            nid,
            nb.remote_name
            or nb.remote_mgmt_ip
            or (mac and ":".join(mac[i : i + 2] for i in range(0, 12, 2)))
            or f"Unknown device ({nb.local_interface or 'a port'} on {local_name})",
            "unknown",
        )
        node.update(discovered=True, evidence="lldp", mac=mac, description=nb.remote_description or "")
        node["_caps"] = []
        g.nodes[nid] = node
    _add_unique(node["macs"], mac)
    _add_unique(node["ips"], ip)
    for site in sites:
        _add_unique(node["site_keys"], site)
    if ip and not node["mgmt_ip"]:
        node["mgmt_ip"] = ip
    if not node["description"] and nb.remote_description:
        node["description"] = nb.remote_description
    for c in nb.remote_capabilities or []:
        _add_unique(node["_caps"], c)
    _add_unique(node["sources"], nb.source)
    node["seen_by"].append(
        {
            "device": local_name,
            "interface": nb.local_interface,
            "remote_interface": nb.remote_interface,
            "source": nb.source,
        }
    )
    g.index(nid)
    return nid


def _apply_fingerprints(g: _Graph) -> None:
    for node in g.nodes.values():
        caps = node.pop("_caps", None)
        if not node["discovered"]:
            continue
        fp = fingerprint(node["description"], node["name"], caps or [])
        node["role"] = fp["role"]
        node["vendor_name"] = node["vendor_name"] or fp["vendor_name"]
        _add_unique(node["vendor_names"], fp["vendor_name"])
        node["model"] = node["model"] or fp["model"]
        node["capabilities"] = caps or []


def _neighbors_to_links(g: _Graph, neighbors: list[Any]) -> None:
    halves: list[dict[str, Any]] = []
    for nb in neighbors:
        a = g.alias.get(f"{nb.source}:{nb.device_key}") or g.alias.get(nb.device_key)
        if not a:
            # A neighbor source that no inventory describes: still show the reporting box.
            a = stable_key("node", f"{nb.source}:{nb.device_key}")
            if a not in g.nodes:
                seen = nb.remote_name or nb.remote_mgmt_ip or "a neighbor"
                label = f"Unknown {nb.source} device (sees {seen} on {nb.local_interface or 'a port'})"
                g.nodes[a] = _new_node(a, label, "unknown")
                g.nodes[a]["sources"].append(nb.source)
                g.nodes[a]["evidence"] = "neighbor-source"
            g.alias[nb.device_key] = a
        sites = g.sites(a)
        b = g.resolve(mac=nb.remote_mac, ip=_ip(nb.remote_mgmt_ip), name=nb.remote_name, sites=sites)
        if b == a:
            continue  # a box seeing itself (VC member ports, loopback cables)
        if not b:
            b = _discovered_node(g, nb, g.nodes[a]["name"], sites)
        else:
            _add_unique(g.nodes[b]["sources"], nb.source)  # also described by the neighbor's LLDP
            if not g.nodes[b]["description"] and nb.remote_description:
                g.nodes[b]["description"] = nb.remote_description
        halves.append(
            {
                "a": a,
                "b": b,
                "ai": nb.local_interface,
                "bi": nb.remote_interface,
                "src": nb.source,
                "proto": nb.protocol or "lldp",
                "lag": nb.local_lag or "",
                "up": nb.local_up,
                "speed": nb.speed_mbps,
                "used": False,
            }
        )
    halves = _unique_halves(halves)
    pairs: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for h in halves:
        pairs[tuple(sorted((h["a"], h["b"])))].append(h)  # type: ignore[arg-type]
    for (p0, p1), hs in pairs.items():
        side_a = [h for h in hs if h["a"] == p0]
        side_b = [h for h in hs if h["a"] == p1]
        for h in side_a:
            match = None
            for o in side_b:
                if o["used"]:
                    continue
                if (norm_if(h["ai"]) and norm_if(h["ai"]) == norm_if(o["bi"])) or (
                    norm_if(h["bi"]) and norm_if(h["bi"]) == norm_if(o["ai"])
                ):
                    match = o
                    break
            if match is None and len(side_a) == 1 and len([o for o in side_b if not o["used"]]) == 1:
                match = next(o for o in side_b if not o["used"])  # one cable, ports named differently
            h["used"] = True
            if match:
                match["used"] = True
                _emit_physical(g, h, match)
            else:
                _emit_physical(g, h, None)
        for o in side_b:
            if not o["used"]:
                o["used"] = True
                _emit_physical(g, o, None)
    # LAG labelling: parallel cables become one link with members; layer "lag" when a bundle is named.
    for k in list(g.links):
        link = g.links[k]
        if link["layer"] != "physical":
            continue
        link["members"] = _unique_members(link["members"])
        lags = {m.get("a_lag") or "" for m in link["members"]} | {m.get("b_lag") or "" for m in link["members"]}
        lags.discard("")
        n = len(link["members"])
        if n > 1 and lags:
            del g.links[k]
            link["layer"] = "lag"
            link["key"] = stable_key("link", link["a_device"], link["b_device"], "lag")
            a_l = sorted({m.get("a_lag") for m in link["members"] if m.get("a_lag")})
            b_l = sorted({m.get("b_lag") for m in link["members"] if m.get("b_lag")})
            link["a_interface"], link["b_interface"] = ", ".join(a_l), ", ".join(b_l)
            link["label"] = f"{', '.join(a_l or b_l)} · {n} links"
            g.links[(link["a_device"], link["b_device"], "lag")] = link
        elif n > 1:
            link["label"] = f"{n} links"
            link["a_interface"] = ", ".join(m["a_interface"] for m in link["members"] if m["a_interface"])
            link["b_interface"] = ", ".join(m["b_interface"] for m in link["members"] if m["b_interface"])
        else:
            link["a_interface"], link["b_interface"] = (
                link["members"][0]["a_interface"],
                link["members"][0]["b_interface"],
            )
        speeds = [m.get("speed_mbps") for m in link["members"] if m.get("speed_mbps")]
        link["speed_mbps"] = sum(speeds) if speeds else None
        states = [m["state"] for m in link["members"]]
        link["state"] = "up" if all(s == "up" for s in states) else "degraded" if "up" in states else states[0]


def _unique_halves(halves: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """One cable reported twice from the same end (v0.10.32).

    Two sources describing the same box (a cloud controller and SNMP, Mist and an orchestrator) each report
    its LLDP neighbours, so the same local port → neighbour pair arrived twice and was drawn as two parallel
    cables ("2 links"). Keep one half per (box, local port, neighbour), filling gaps from the others."""
    out: dict[tuple[str, str, str], dict[str, Any]] = {}
    loose: list[dict[str, Any]] = []
    for h in halves:
        port = norm_if(h["ai"])
        if not port:
            loose.append(h)  # no local port named: cannot tell two of these apart
            continue
        key = (h["a"], h["b"], port)
        prev = out.get(key)
        if prev is None:
            out[key] = h
            continue
        for field in ("bi", "lag", "speed"):
            if not prev.get(field) and h.get(field):
                prev[field] = h[field]
        if prev.get("up") is None and h.get("up") is not None:
            prev["up"] = h["up"]
    return list(out.values()) + loose


def _unique_members(members: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Members of one physical link that are the same cable (same port on one end, the other end the same
    or unnamed) collapse into one; the more complete description wins (v0.10.32)."""
    kept: list[dict[str, Any]] = []
    for m in members:
        ka, kb = norm_if(m.get("a_interface")), norm_if(m.get("b_interface"))
        twin = None
        for x in kept:
            xa, xb = norm_if(x.get("a_interface")), norm_if(x.get("b_interface"))
            if (ka and ka == xa and (not kb or not xb or kb == xb)) or (kb and kb == xb and (not ka or not xa)):
                twin = x
                break
        if twin is None:
            kept.append(m)
            continue
        for field in ("a_interface", "b_interface", "a_lag", "b_lag", "speed_mbps"):
            if not twin.get(field) and m.get(field):
                twin[field] = m[field]
        twin["sides"] = max(int(twin.get("sides") or 1), int(m.get("sides") or 1))
        twin["confidence"] = max(float(twin.get("confidence") or 0), float(m.get("confidence") or 0))
        if twin.get("state") != "down" and m.get("state") == "down":
            twin["state"] = "down"
    return kept


def _emit_physical(g: _Graph, h: dict[str, Any], other: dict[str, Any] | None) -> None:
    a, b = h["a"], h["b"]
    a_if = h["ai"]
    b_if = other["ai"] if other else h["bi"]
    ups = [x for x in (h["up"], other["up"] if other else None) if x is not None]
    node_down = g.nodes[a]["status"] == "down" or g.nodes[b]["status"] == "down"
    state = "down" if (ups and not all(ups)) or node_down else "up"
    if other:
        evidence = {
            "kind": h["proto"],
            "source": h["src"],
            "detail": f"{h['proto'].upper()} seen from both ends",
            "sides": 2,
        }
        conf = CONF_BOTH
    else:
        evidence = {
            "kind": h["proto"],
            "source": h["src"],
            "detail": f"{h['proto'].upper()} seen only from {g.nodes[a]['name']}",
            "sides": 1,
        }
        conf = CONF_ONE
    speed = h["speed"] or (other["speed"] if other else None)
    a_lag, b_lag = h["lag"], other["lag"] if other else ""
    if a > b:
        a_lag, b_lag = b_lag, a_lag
    g.add_link(
        a,
        b,
        "physical",
        a_if=a_if,
        b_if=b_if,
        confidence=conf,
        evidence=evidence,
        state=state,
        extra={"a_lag": a_lag, "b_lag": b_lag, "speed_mbps": speed, "sides": 2 if other else 1},
    )


_FACT_FIELDS = {
    "ports_total": int,
    "ports_up": int,
    "ports_warn": int,
    "port_map": str,
    "poe_draw_w": float,
    "clients": int,
    "floor_id": str,
}
_PORT_MAP_RE = re.compile(r"^[uwd]{0,2048}$")


def _device_facts_rows(c: Any, arg: str | None, in_scope: set[str]) -> list[dict[str, Any]]:
    """Optional ``list_device_facts(site)`` hook of a neighbor source (ports, PoE, clients, floor).

    Sources answer from statistics they already read for LLDP, so this costs no extra API call. A
    failure only leaves the Closets rows empty; it is logged, never shown as a data gap.
    """
    fn = sdk.hook(c, "list_device_facts")
    if fn is None:
        return []
    try:
        rows = list(fn(arg) or [])
    except Exception as exc:  # noqa: BLE001 - facts are a nicety
        log.info("topology: %s device facts failed: %s", c.provider_id, exc)
        return []
    return [
        r
        for r in rows
        if isinstance(r, dict) and f"{r.get('source') or c.provider_id}:{r.get('device_key')}" in in_scope
    ]


def _device_facts(scope: SiteScope, in_scope: set[str]) -> list[dict[str, Any]]:
    """Compatibility wrapper: facts of every neighbor source for a scope."""
    out: list[dict[str, Any]] = []
    for c in sdk.sources(NEIGHBORS):
        args = scope.args_for(c.provider_id)
        for arg in [None] if args is None else args:
            out += _device_facts_rows(c, arg, in_scope)
    return out


def _apply_facts(g: _Graph, facts: list[dict[str, Any]]) -> None:
    """Copy reported counts onto nodes (first source wins per field; malformed values are dropped)."""
    for f in facts:
        nid = g.alias.get(f"{f.get('source')}:{f.get('device_key')}") or g.alias.get(str(f.get("device_key") or ""))
        node = g.nodes.get(nid or "")
        if node is None:
            continue
        for name, kind in _FACT_FIELDS.items():
            value = f.get(name)
            if value is None or node[name] not in (None, ""):
                continue
            try:
                value = kind(value)
            except (TypeError, ValueError):
                continue
            if kind is str:
                value = value[:2048] if name == "port_map" else value[:120]
                if name == "port_map" and not _PORT_MAP_RE.match(value):
                    continue
            elif value < 0:
                continue
            node[name] = value


def _arp_links(g: _Graph, arp: list[Any]) -> None:
    has_physical = {x for k in g.links for x in k[:2] if k[2] in ("physical", "lag")}
    for e in arp:
        a = g.alias.get(f"{e.source}:{e.device_key}") or g.alias.get(e.device_key)
        b = g.by_mac.get(valid_mac(e.mac))
        if not a or not b or a == b or b in has_physical or g.linked(a, b, ("physical", "lag", "l2")):
            continue
        g.add_link(
            a,
            b,
            "l2",
            a_if=e.interface,
            confidence=CONF_INFERRED,
            evidence={"kind": "arp", "source": e.source, "detail": f"{e.ip} in the ARP table of {g.nodes[a]['name']}"},
            state="unknown",
        )


def _cloud_node(g: _Graph) -> str:
    nid = stable_key("cloud", "wan")
    if nid not in g.nodes:
        node = _new_node(nid, "WAN / Internet", "cloud")
        node.update(synthetic=True, evidence="inferred", status="unknown")
        g.nodes[nid] = node
    return nid


def ha_rank(node: dict[str, Any] | None) -> int:
    """0 for the unit that answers for an HA pair's shared (floating) addresses — active / primary, else unit
    1 / A — and for boxes not in a pair; 1 for the other unit."""
    if not node or not node.get("ha_peer"):
        return 0
    state = str(node.get("ha_state") or "")
    if state.startswith(("active", "primary")):
        return 0
    if state.startswith(("passive", "secondary", "standby")):
        return 1
    return 0 if unit_of(node.get("name"))[1] in ("1", "A") else 1


def _l3_links(g: _Graph, interfaces: list[tuple[str, Any]], routes: list[tuple[str, Any]]) -> None:
    owners: dict[str, list[tuple[str, str]]] = defaultdict(list)  # ip → [(node, interface)]
    subnets: dict[str, list[tuple[str, str, str]]] = defaultdict(list)
    rows = []
    for nid, itf in interfaces:
        for cidr in itf.ips or []:
            try:
                iface = ipaddress.ip_interface(str(cidr))
            except ValueError:
                continue
            rows.append((nid, itf, iface))
            owners[str(iface.ip)].append((nid, itf.name))
            _add_unique(g.nodes[nid]["ips"], str(iface.ip))
    # The two units of an HA pair carry the same (floating) addresses: the active unit answers for them.
    shadowed: set[tuple[str, str]] = set()
    for ip, lst in owners.items():
        nids = {n for n, _i in lst}
        for n in nids:
            peer = g.nodes[n].get("ha_peer")
            if (
                peer in nids
                and ha_rank(g.nodes[n]) > ha_rank(g.nodes[peer])
                or (peer in nids and ha_rank(g.nodes[n]) == ha_rank(g.nodes[peer]) and n > peer)
            ):
                shadowed.add((n, ip))
        owners[ip] = [(n, i) for n, i in lst if (n, ip) not in shadowed]
    for nid, itf, iface in rows:
        if (nid, str(iface.ip)) in shadowed:
            continue
        if iface.network.prefixlen < iface.network.max_prefixlen:
            subnets[str(iface.network)].append((nid, itf.name, itf.source))
    for nid in {nid for nid, _ in interfaces}:
        g.index(nid)  # interface addresses identify the box too (route next hops, tunnel peers)
    for net, members in subnets.items():
        distinct = {m[0] for m in members}
        if not 2 <= len(distinct) <= 6:
            continue  # shared user VLANs with dozens of boxes are not adjacencies worth drawing
        private = _private(net)
        for i, (a, ai, src) in enumerate(members):
            for b, bi, _ in members[i + 1 :]:
                if g.nodes[a].get("ha_peer") == b:
                    continue  # the HA link covers the two units of a pair
                # 10.0.0.0/30 at two different sites is two different links, not one.
                if a != b and (not private or _sites_ok(g.sites(a), g.sites(b))):
                    g.add_link(
                        a,
                        b,
                        "l3",
                        a_if=ai,
                        b_if=bi,
                        confidence=CONF_ONE,
                        evidence={"kind": "config", "source": src, "detail": f"Both on {net}"},
                        state="unknown",
                    )
    for nid, r in routes:
        hop = _ip(r.next_hop)
        if not hop:
            continue
        here = g.sites(nid)
        private = _private(hop)

        def scoped(x: str, here: list[str] = here, private: bool = private) -> bool:
            return not private or _sites_ok(g.sites(x), here)

        owner = next((o for o in owners.get(hop, []) if scoped(o[0])), None) or next(
            ((x, "") for x in sorted(g.by_ip.get(hop, []), key=lambda x: ha_rank(g.nodes.get(x))) if scoped(x)), None
        )
        detail = f"{r.prefix} via {hop}" + (f" ({r.protocol})" if r.protocol else "")
        if owner and owner[0] != nid:
            g.add_link(
                nid,
                owner[0],
                "l3",
                a_if=r.interface,
                b_if=owner[1],
                confidence=CONF_ONE,
                evidence={"kind": "routing", "source": r.source, "detail": detail},
            )
        elif not owner and str(r.prefix).strip() in ("0.0.0.0/0", "::/0"):
            g.add_link(
                nid,
                _cloud_node(g),
                "l3",
                a_if=r.interface,
                confidence=CONF_INFERRED,
                evidence={"kind": "routing", "source": r.source, "detail": f"default route {detail}"},
            )


def _tunnel_links(g: _Graph, tunnels: list[Any]) -> None:
    for t in tunnels:
        a = g.alias.get(f"{t.source}:{t.device_key}") or g.alias.get(t.device_key)
        if not a:
            continue
        b = (
            (g.alias.get(f"{t.source}:{t.remote_device_key}") or g.alias.get(t.remote_device_key))
            if t.remote_device_key
            else ""
        )
        # The peer is (usually) at another site: a private IP or a name must be unique graph-wide.
        b = b or g.resolve(ip=_ip(t.remote_ip), name=t.remote_name, unique=True)
        me = f"{t.source}:{t.device_key}"
        if b and g.nodes[b].get("peer_of") not in (None, me):
            b = ""  # a non-routable peer address another device's tunnel created: not the same box
        if not b:
            rip = _ip(t.remote_ip)
            scoped = bool(rip) and _site_scoped(rip)
            ident = t.remote_device_key or (f"{me}|{rip}" if scoped else rip)
            ident = ident or norm_host(t.remote_name) or t.key
            b = stable_key("remote", ident)
            if b not in g.nodes:
                node = _new_node(b, t.remote_name or t.remote_ip or "Remote peer", "sdwan_edge")
                node.update(remote=True, discovered=True, evidence="tunnel", status="unknown")
                if scoped and not t.remote_device_key and not _lan_private(rip):
                    node["peer_of"] = me  # e.g. 169.254.x.x BGP-over-IPsec: every gateway reuses it
                g.nodes[b] = node
            _add_unique(g.nodes[b]["ips"], _ip(t.remote_ip))
            _add_unique(g.nodes[b]["sources"], t.source)
            g.index(b)
        if a == b:
            continue
        a_name, b_name = g.nodes[a]["name"], g.nodes[b]["name"]
        g.add_link(
            a,
            b,
            "overlay",
            a_if=t.name,
            confidence=CONF_BOTH if t.remote_device_key else CONF_ONE,
            evidence={
                "kind": "tunnel",
                "source": t.source,
                "detail": f"{t.kind} tunnel {t.name} ({a_name} → {b_name})",
            },
            state=t.state,
            extra={
                "tunnel": t.name,
                "kind": t.kind,
                "local_ip": t.local_ip,
                "remote_ip": t.remote_ip,
                "latency_ms": t.latency_ms,
                "loss_pct": t.loss_pct,
                "jitter_ms": tunnel_jitter(t),
                "from": a,
            },
        )
        cloud = _cloud_node(g)
        if not g.nodes[a]["remote"] and not g.linked(a, cloud, ("l3",)):
            g.add_link(
                a,
                cloud,
                "l3",
                confidence=CONF_INFERRED,
                evidence={"kind": "inferred", "source": t.source, "detail": "Tunnel endpoint reaches the WAN"},
            )
    for link in g.links.values():
        if link["layer"] != "overlay" or link.get("cloud"):
            continue
        # One tunnel reported from both appliances is one tunnel.
        seen: dict[str, dict[str, Any]] = {}
        for m in link["members"]:
            ident = norm_if(m.get("tunnel"))
            rev = next(
                (
                    x
                    for x in seen.values()
                    if x.get("from") != m.get("from") and x.get("remote_ip") == m.get("local_ip") and m.get("local_ip")
                ),
                None,
            )
            if rev:
                rev["sides"] = 2
                continue
            seen.setdefault(f"{m.get('from')}:{ident}", m)
        link["members"] = list(seen.values())
        if any(m.get("sides") == 2 for m in link["members"]):
            link["confidence"] = CONF_BOTH
        states = [m.get("state") or "unknown" for m in link["members"]]
        link["state"] = (
            "up"
            if all(s == "up" for s in states)
            else "down"
            if all(s == "down" for s in states)
            else "degraded"
            if "up" in states
            else "unknown"
        )
        n = len(link["members"])
        link["label"] = f"{n} tunnels" if n > 1 else link["members"][0].get("tunnel") or ""
        for side, end in (("a_interface", link["a_device"]), ("b_interface", link["b_device"])):
            names = sorted({m.get("tunnel") or "" for m in link["members"] if m.get("from") == end} - {""})
            link[side] = ", ".join(names)


def _assign_tiers(g: _Graph) -> None:
    adj: dict[str, set[str]] = defaultdict(set)
    for a, b, layer in g.links:
        if layer in ("physical", "lag", "l2"):
            adj[a].add(b)
            adj[b].add(a)
    role = {nid: n["role"] for nid, n in g.nodes.items()}
    any_upstream = any(r in _UPSTREAM_ROLES for r in role.values())
    for nid, node in g.nodes.items():
        r = node["role"]
        if r in ("cloud", "cloud_gateway") or node["remote"]:
            tier = 0
        elif r == "sdwan_edge":
            tier = 1
        elif r in ("firewall", "router", "load_balancer", "wireless_controller"):
            tier = 2
        elif r == "switch":
            neigh = adj.get(nid, set())
            name = node["name"]
            if node.get("network_tier") in ("core", "distribution"):  # the vendor knows (Device.network_tier)
                tier = 3
            elif node.get("network_tier") == "access":
                tier = 4
            elif _CORE_HINT.search(name):
                tier = 3
            elif _ACCESS_HINT.search(name):
                tier = 4
            elif any(role.get(x) in _UPSTREAM_ROLES for x in neigh):
                tier = 3
            elif not any_upstream:
                sw = sum(1 for x in neigh if role.get(x) == "switch")
                aps = sum(1 for x in neigh if role.get(x) == "wireless_ap")
                tier = 3 if sw >= 2 and aps == 0 else 4
            else:
                tier = 4
        else:
            tier = 5
        node["tier"] = tier
        node["tier_label"] = _tier_label(tier)
    up_nodes = {x for link in g.links.values() if link["state"] == "up" for x in (link["a_device"], link["b_device"])}
    for nid, node in g.nodes.items():
        if node["discovered"] and node["status"] == "unknown" and nid in up_nodes:
            node["status"] = "up"  # it is answering LLDP on a live port right now
        if node["role"] in ("wireless_ap", "endpoint"):
            ups = [x for x in adj.get(nid, ()) if role.get(x) == "switch"]
            node["uplink"] = ups[0] if len(ups) == 1 else (ups[0] if ups else "")


_SCOPE_GAP = {
    "firewall": ("firewalls", "map device groups to site names"),
    "sdwan": ("SD-WAN edges", "map its sites to the same site names"),
}


def _scope_gaps(scope: SiteScope, contributed: dict[str, int]) -> list[str]:
    """A firewall / SD-WAN manager that adds nothing to this site usually names the site differently."""
    if not scope.key:
        return []
    out = []
    for c in sdk.sources(INVENTORY):
        words = _SCOPE_GAP.get(c.manifest.category)
        if words and not contributed.get(c.provider_id):
            product = c.manifest.product or c.provider_id
            out.append(
                f"No {words[0]} from {product} at this site — if it has some here, map its site or devices to this "
                "site under Topology › Site mapping."
            )
    return out


def _gaps(g: _Graph, status: _Sources, caps_present: dict[str, list[str]]) -> list[str]:
    gaps: list[str] = []
    if not any(caps_present.values()):
        return ["No network source is connected yet. Connect one under Settings › Connections to build the topology."]
    if not caps_present[NEIGHBORS]:
        gaps.append("No connected source reports LLDP/CDP neighbors, so cables between devices cannot be drawn.")
    by_role: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for n in g.nodes.values():
        if n["discovered"] and not n["remote"]:
            by_role[n["role"]].append(n)
    words = {
        "firewall": ("firewall", "firewalls", "interfaces, zones, routes and HA state"),
        "sdwan_edge": ("SD-WAN edge", "SD-WAN edges", "tunnels, WAN links and path health"),
        "router": ("router", "routers", "interfaces and routes"),
        "switch": ("switch", "switches", "ports and their own neighbors"),
        "wireless_ap": ("access point", "access points", "radio and client details"),
    }
    for role, nodes in by_role.items():
        if role not in words:
            continue
        one, many, what = words[role]
        vendors = sorted({n["vendor_name"] for n in nodes if n["vendor_name"]})
        who = f" ({', '.join(vendors)})" if vendors else ""
        gaps.append(
            f"{len(nodes)} {one if len(nodes) == 1 else many}{who} seen only through LLDP from neighboring "
            f"switches — connect {'its' if len(nodes) == 1 else 'their'} management system under Settings › "
            f"Connections to see {what}."
        )
    other = [n for r, ns in by_role.items() if r not in words for n in ns]
    if other:
        gaps.append(f"{len(other)} neighbor(s) could not be identified from what they advertise over LLDP.")
    if not caps_present[TUNNELS]:
        gaps.append("No SD-WAN or VPN source is connected, so overlay tunnels are not shown.")
    if not caps_present[ROUTES] and not caps_present[ARP_TABLE] and not caps_present[INTERFACES]:
        gaps.append("No source provides routing, ARP or interface address tables, so layer-3 links are not shown.")
    linked = {x for k in g.links for x in k[:2]}
    isolated = [n for n in g.nodes.values() if n["id"] not in linked and not n["synthetic"]]
    if isolated:
        gaps.append(
            f"{len(isolated)} device(s) have no known links — LLDP may be disabled on them or on their neighbors, "
            "or they are offline."
        )
    one_sided = sum(1 for l in g.links.values() if l["layer"] in ("physical", "lag") and l["confidence"] < CONF_BOTH)
    if one_sided:
        gaps.append(f"{one_sided} cable(s) are seen from one end only (confidence 70%).")
    for row in status.status.values():
        if row["ok"]:
            continue
        if row.get("stale"):
            since = time.strftime("%H:%M", time.localtime(row["stale_since"])) if row.get("stale_since") else "earlier"
            gaps.append(
                f"{row['product']} could not be read just now — showing its last known data (failing since {since}): "
                f"{row['error']}"
            )
        else:
            gaps.append(f"{row['product']} could not be read: {row['error']}")
    gaps.extend(status.caps)
    return gaps


# --------------------------------------------------------------------------- public API

MAX_ARP_CALLS = 40  # per source, per site build
KEEP_GOOD_S = 6 * 3600.0  # a degraded build never replaces a complete map younger than this
L3_SUFFIX = "#l3"  # cache key suffix of graphs built with the layer-3 layer


def scope_key(site_key: str | None, l3: bool = False) -> str:
    return f"{str(site_key or '').strip()}{L3_SUFFIX if l3 else ''}"


def _split_scope(key: str) -> tuple[str, bool]:
    return (key[: -len(L3_SUFFIX)], True) if key.endswith(L3_SUFFIX) else (key, False)


def _check_scope(site_key: str | None) -> str:
    scope = str(site_key or "").strip()
    if not _SCOPE_RE.match(scope):
        raise ValueError("Invalid site key")
    return scope


def build_topology(site_key: str | None = None, *, fresh: bool = False, l3: bool = False) -> dict[str, Any]:
    """Topology of one site (or everything) from every connected source.

    Cached ``CACHE_TTL_S`` per scope (LRU of ``CACHE_MAX_SCOPES``); concurrent requests for one scope
    share a single build. A build where a source failed without a last-good fallback never replaces a
    complete map: the previous one is returned (``refresh_error`` set). Raises ValueError for a
    malformed site key.
    """
    site = _check_scope(site_key)
    scope = scope_key(site, l3)
    asked = time.time()
    if not fresh:
        hit = _cache_get(scope, asked)
        if hit:
            return hit
    with _cache_lock:
        slot = _inflight.setdefault(scope, [threading.Lock(), 0])
        slot[1] += 1
    try:
        with slot[0]:
            # Someone else built this scope while we waited: share their result.
            with _cache_lock:
                done = _cache.get(scope)
            if done and done[0] >= asked:
                return {**done[1], "cached": True, "age_s": round(time.time() - done[0], 1)}
            if not fresh:
                hit = _cache_get(scope, time.time())
                if hit:
                    return hit
            result = _build(site or None, l3=l3)
            if result.get("degraded"):
                prev = _good_previous(scope)
                if prev is not None:
                    built_at, old = prev
                    return {
                        **old,
                        "cached": True,
                        "age_s": round(time.time() - built_at, 1),
                        "refresh_error": _degraded_text(result),
                    }
            _store(scope, result)
            return {**result, "cached": False, "age_s": 0.0}
    finally:
        with _cache_lock:
            slot[1] -= 1
            if slot[1] <= 0 and _inflight.get(scope) is slot:
                del _inflight[scope]


def _store(scope: str, result: dict[str, Any]) -> None:
    with _cache_lock:
        _cache[scope] = (time.time(), result)
        _cache.move_to_end(scope)
        while len(_cache) > CACHE_MAX_SCOPES:
            _cache.popitem(last=False)


def _degraded_text(result: dict[str, Any]) -> str:
    bad = [s for s in result.get("sources", []) if s.get("source") in set(result.get("failed_sources") or [])]
    text = "; ".join(f"{s.get('product') or s.get('source')}: {s.get('error')}" for s in bad)
    return f"Not refreshed — a source could not be read ({text}). Showing the last complete map."


def _good_previous(scope: str) -> tuple[float, dict[str, Any]] | None:
    """The last complete (non-degraded) graph of a scope, when recent enough to prefer it."""
    with _cache_lock:
        hit = _cache.get(scope)
    if hit is None and _swr is not None:
        hit = _swr.peek(scope)
    if hit and not hit[1].get("degraded") and not hit[1].get("partial") and time.time() - hit[0] < KEEP_GOOD_S:
        return hit
    return None


def _cache_get(scope: str, now: float) -> dict[str, Any] | None:
    with _cache_lock:
        hit = _cache.get(scope)
        if hit and now - hit[0] < CACHE_TTL_S:
            _cache.move_to_end(scope)
            return {**hit[1], "cached": True, "age_s": round(now - hit[0], 1)}
    return None


def clear_cache() -> None:
    if _swr is not None:
        _swr.clear_memory()
    with _cache_lock:
        _cache.clear()
        _site_cache.clear()
        _iface_side.clear()
    site_registry.clear()
    with _sites_lock:
        _sites_answer["at"] = 0.0


def invalidate() -> None:
    """Site mapping changed: every map is out of date (served stale and rebuilt on the next request)."""
    with _cache_lock:
        _cache.clear()
    if _swr is not None:
        _swr.invalidate()
    site_registry.clear()
    with _sites_lock:
        _sites_answer["at"] = 0.0


# Interface records the last build of each scope already read (path trace reuses them instead of
# asking the sources again). Not part of the API response.
_iface_side: OrderedDict[str, dict[str, list[Any]]] = OrderedDict()
_iface_macs: dict[str, set[str]] = {}  # node id → interface MACs seen by any layer-3 read
IFACE_MACS_MAX = 20000


def _remember_interfaces(scope: str, queried: set[str], interfaces: list[tuple[str, Any]]) -> None:
    by_node: dict[str, list[Any]] = {nid: [] for nid in queried}
    for nid, itf in interfaces:
        by_node.setdefault(nid, []).append(itf)
    with _cache_lock:
        _iface_side[scope] = by_node
        _iface_side.move_to_end(scope)
        while len(_iface_side) > CACHE_MAX_SCOPES:
            _iface_side.popitem(last=False)
        for nid, itf in interfaces:
            m = valid_mac(getattr(itf, "mac", ""))
            if m:
                _iface_macs.setdefault(nid, set()).add(m)
        while len(_iface_macs) > IFACE_MACS_MAX:
            _iface_macs.pop(next(iter(_iface_macs)))


def gathered_interfaces(site_key: str | None) -> dict[str, list[Any]]:
    """{node id: [Interface]} read by the most recent build of this scope ({} when none)."""
    with _cache_lock:
        return dict(_iface_side.get(str(site_key or ""), {}))


_site_errors: dict[str, str] = {}


SITES_TTL_S = 120.0
_sites_answer: dict[str, Any] = {"at": 0.0, "data": None, "loaded": False}
_sites_lock = threading.Lock()


def _sites_file() -> Any:
    return site_registry.ROOT / "sites.json"


def list_sites() -> dict[str, Any]:
    """GET /api/v1/topology/sites, stale-while-revalidate (v0.10.24): the last answer (also from disk right
    after a restart) comes back at once and is refreshed in the background when older than ``SITES_TTL_S``;
    only the very first call ever waits for the sources."""
    with _sites_lock:
        if not _sites_answer["loaded"]:
            _sites_answer["loaded"] = True
            try:
                disk = json.loads(_sites_file().read_text(encoding="utf-8"))
                if isinstance(disk, dict) and isinstance(disk.get("data"), dict):
                    _sites_answer.update(at=float(disk.get("at") or 0), data=disk["data"])
            except (OSError, ValueError):
                pass
        data, at = _sites_answer["data"], _sites_answer["at"]
    if data is not None:
        age = time.time() - at
        if age >= SITES_TTL_S:
            _refresh_sites_async()
        return {**data, "age_s": round(age, 1), "stale": age >= SITES_TTL_S}
    return {**_list_sites_store(), "age_s": 0.0, "stale": False}


_sites_refreshing = threading.Lock()


def _refresh_sites_async() -> None:
    if not _sites_refreshing.acquire(blocking=False):
        return

    def run() -> None:
        try:
            _list_sites_store()
        except Exception as exc:  # noqa: BLE001
            log.info("topology: site list refresh failed: %s", exc)
        finally:
            _sites_refreshing.release()

    threading.Thread(target=run, name="topology-sites", daemon=True).start()


def _list_sites_store() -> dict[str, Any]:
    data = list_sites_now()
    now = time.time()
    with _sites_lock:
        _sites_answer.update(at=now, data=data, loaded=True)
    try:
        f = _sites_file()
        f.parent.mkdir(parents=True, exist_ok=True)
        write_private_text(f, json.dumps({"at": now, "data": data}, default=str))  # atomic, owner-only (v0.10.40)
    except OSError as exc:
        log.info("topology: site list not persisted: %s", exc)
    return data


def list_sites_now() -> dict[str, Any]:
    """Canonical sites (v0.10.23): same place in different sources = one entry (``keys``/``names``/``sources``
    list every connector site joined into it). Secondary sites (SCM folders, remote networks) appear only
    when they are mapped to a real site."""
    listed, products = listed_sites()
    reg = site_registry.registry(listed, products)
    rows: list[dict[str, Any]] = []
    for ck, s in reg.sites.items():
        members = sorted(s["members"], key=lambda m: m.key != ck)
        rows.append(
            {
                "key": ck,
                "name": s["name"],
                "keys": list(dict.fromkeys(m.key for m in members)),
                "names": list(dict.fromkeys(m.name for m in members)),
                "sources": list(dict.fromkeys(m.source for m in members)),
                "kind": s.get("kind") or "site",  # v0.10.27: "cloud" = a cloud service (no building)
            }
        )
    status = _Sources()
    for c in sdk.sources(INVENTORY):
        row = status._row(c)
        row["records"] = len(listed.get(c.provider_id, []))
        err = _site_errors.get(c.provider_id)
        if err:
            row["ok"] = False
            row["error"] = err
            row["stale"] = bool(listed.get(c.provider_id))
    return {
        "sites": sorted(rows, key=lambda r: str(r["name"]).lower()),
        "sources": list(status.status.values()),
        "registry_version": reg.version,
    }


def _org_hint() -> dict[str, Any] | None:
    try:
        from app.services import topology_search

        return topology_search.hint()
    except Exception as exc:  # noqa: BLE001 - the hint only saves calls
        log.info("topology: organisation index unavailable: %s", exc)
        return None


def _pool_run(fns: list[Callable[[], Any]]) -> list[Any]:
    if not fns:
        return []
    if len(fns) == 1:
        return [fns[0]()]
    with ThreadPoolExecutor(max_workers=min(POOL_WORKERS, len(fns)), thread_name_prefix="topology") as pool:
        futures = [pool.submit(fn) for fn in fns]
        return [f.result() for f in futures]


def _identities(d: Any) -> set[str]:
    return {f"sn:{x}" for x in _serials(d)} | {f"mac:{m}" for m in _alias_macs(d)}


def peers_of(placed: list[Any], candidates: list[Any], skip: set[str] | None = None) -> list[Any]:
    """Unplaced records sharing a serial / MAC identity with a placed one (the other unit of an HA pair,
    a stack member reported separately)."""
    idents: set[str] = set()
    for d in placed:
        idents |= _identities(d)
    skip = skip or set()
    return [d for d in candidates if _record_key(d) not in skip and _identities(d) & idents]


def propagate_peers(devices: list[Any], place: dict[str, tuple[str, str]]) -> None:
    """Organisation-wide: an unplaced record takes the site of a placed record it shares an identity with."""
    site_of_ident: dict[str, str] = {}
    for d in devices:
        ck = place.get(_record_key(d), ("", ""))[0]
        if ck:
            for i in _identities(d):
                site_of_ident.setdefault(i, ck)
    for d in devices:
        rk = _record_key(d)
        if place.get(rk, ("", ""))[0]:
            continue
        hits = {site_of_ident[i] for i in _identities(d) if i in site_of_ident}
        if len(hits) == 1:
            place[rk] = (hits.pop(), "ha_peer")


def _place_by_adjacency(
    scope: SiteScope,
    devices: list[Any],
    candidates: list[Any],
    neighbors: list[Any],
) -> list[Any]:
    """Unassigned devices that an in-scope device sees over LLDP belong to this site (remembered)."""
    if not candidates or not scope.canonical:
        return []
    by_mac: dict[str, Any] = {}
    by_ip: dict[str, list[Any]] = defaultdict(list)
    by_host: dict[str, list[Any]] = defaultdict(list)
    for d in candidates:
        for m in _alias_macs(d):
            by_mac.setdefault(m, d)
        if _ip(d.mgmt_ip):
            by_ip[_ip(d.mgmt_ip)].append(d)
        if norm_host(d.name):
            by_host[norm_host(d.name)].append(d)
    names = {_record_key(d): d.name for d in devices}
    in_scope = set(names)
    placed: list[Any] = []
    for nb in neighbors:
        reporter = f"{nb.source}:{nb.device_key}"
        if reporter not in in_scope:
            continue
        hit = by_mac.get(valid_mac(nb.remote_mac))
        if hit is None:
            ips = by_ip.get(_ip(nb.remote_mgmt_ip), [])
            hit = ips[0] if len(ips) == 1 else None
        if hit is None:
            hosts = by_host.get(norm_host(nb.remote_name), [])
            hit = hosts[0] if len(hosts) == 1 else None
        if hit is None or _record_key(hit) in in_scope:
            continue
        rk = _record_key(hit)
        in_scope.add(rk)
        placed.append(hit)
        scope._placed[rk] = (scope.canonical, "lldp")
        site_registry.learn(
            rk, scope.canonical, "lldp", f"LLDP neighbor of {names.get(reporter, '')} {nb.local_interface}"
        )
    # HA peers / stack members of any box at this site (same serial or MAC identity) come along.
    placed += [d for d in peers_of([*devices, *placed], candidates, in_scope) if _record_key(d) not in in_scope]
    for d in placed:
        rk = _record_key(d)
        in_scope.add(rk)
        scope._placed.setdefault(rk, (scope.canonical, "ha_peer"))
    if placed:
        log.info("topology: placed %d unassigned device(s) at %s by LLDP adjacency", len(placed), scope.name)
        site_registry.flush_learned()
    return placed


CIRCUITS = WAN_CIRCUITS
LOCAL_PROTOCOLS = {"connected", "local", "direct", "interface"}
_OVERLAY_PROTOCOLS = {"sdwan", "overlay", "omp", "bgp-evpn"}


def is_local_route(r: Any) -> bool:
    """A route that is a LAN of the device itself (vendor-neutral).

    ``Route.local`` (when a connector sets it) decides; otherwise only connected / local protocols count —
    a *static* route usually points at a remote network (firewalls, routers), so it never does."""
    local = getattr(r, "local", None)
    if local is not None:
        return bool(local)
    return str(getattr(r, "protocol", "") or "").lower() in LOCAL_PROTOCOLS


# Interface names / zones that face the transport, for ports whose role no connector reported (generic
# networking words, no vendor names). Only a whole name / zone or its leading word counts ("wan1",
# "Internet", "untrust"), never a word further in ("trust-uplink", "LAN-Outside-Vendors"), and never one
# that also names an inside network ("Internet_Guest"). Management ports are recognised by kind / role.
_WAN_WORDS = {"wan", "internet", "inet", "isp", "untrust", "untrusted", "outside", "mpls", "lte", "cellular"}
_INSIDE_WORDS = {"trust", "trusted", "lan", "inside", "internal", "guest", "dmz", "vlan"}
_DEFAULT_ROUTES = ("0.0.0.0/0", "::/0")


def _words(text: Any) -> list[str]:
    """'wan1' → ['wan']; 'Internet_Guest' → ['internet', 'guest']; 'ethernet1/2' → ['ethernet']."""
    out = [re.sub(r"\d+$", "", t) for t in re.split(r"[^a-z0-9]+", str(text or "").lower()) if t]
    return [t for t in out if t]


def _transport_word(text: Any) -> bool:
    words = _words(text)
    return bool(words) and words[0] in _WAN_WORDS and not (set(words) & _INSIDE_WORDS)


def wan_side(itf: Any, circuit_ifaces: set[str] | frozenset[str] = frozenset()) -> bool:
    """A port that faces the WAN / transport or out-of-band management, never a site LAN (vendor-neutral):
    ``Interface.role`` "wan" / "mgmt", kind "mgmt", a port a WAN circuit of the device names, or — when the
    role is unknown — a name / security zone that is (or starts with) a transport word: wan1, Internet,
    untrust, outside, mpls … (not "trust-uplink", "Internet_Guest", "MGMT_VLAN")."""
    role = str(getattr(itf, "role", "") or "").lower()
    if role in ("wan", "mgmt"):
        return True
    if str(getattr(itf, "kind", "") or "") == "mgmt":
        return True
    name = str(getattr(itf, "name", "") or "")
    if name and name in circuit_ifaces:
        return True
    if role == "lan":
        return False
    return _transport_word(name) or _transport_word(getattr(itf, "zone", ""))


def _lan_net(net: Any) -> bool:
    """Private (RFC 1918 / CGNAT / ULA), not link-local, not a /31–/32 host route."""
    return (
        net.prefixlen < net.max_prefixlen - 1
        and not net.is_link_local
        and any(net.version == n.version and net.subnet_of(n) for n in LAN_NETS)
    )


class WanSide:
    """What of one device faces the WAN: port names and their networks, plus its WAN circuit addresses."""

    def __init__(
        self, itfs: list[Any] | None = None, circuit_ifaces: Any = (), circuit_ips: Any = (), circuit_nets: Any = ()
    ) -> None:
        self.ifaces: set[str] = {str(x) for x in circuit_ifaces or () if x}
        self.ips = []
        for ip in circuit_ips or ():
            try:
                self.ips.append(ipaddress.ip_address(str(ip).split("/")[0].strip()))
            except ValueError:
                continue
        self.nets: list[Any] = []
        for n in circuit_nets or ():
            try:
                self.nets.append(ipaddress.ip_network(str(n), strict=False))
            except ValueError:
                continue
        for itf in itfs or []:
            if not wan_side(itf, self.ifaces):
                continue
            if getattr(itf, "name", ""):
                self.ifaces.add(str(itf.name))
            for cidr in getattr(itf, "ips", None) or []:
                try:
                    self.nets.append(ipaddress.ip_interface(str(cidr)).network)
                except ValueError:
                    continue
        for itf in itfs or []:  # the network around a circuit address is WAN too
            for cidr in getattr(itf, "ips", None) or []:
                try:
                    iface = ipaddress.ip_interface(str(cidr))
                except ValueError:
                    continue
                if iface.ip in self.ips:
                    self.ifaces.add(str(getattr(itf, "name", "") or ""))
                    self.nets.append(iface.network)
        self.ifaces.discard("")

    def covers(self, net: Any) -> bool:
        """``net`` is (or contains, or lies in) a WAN network, or contains a circuit address."""
        for w in self.nets:
            if w.version == net.version and (net.subnet_of(w) or net.supernet_of(w)):
                return True
        return any(ip.version == net.version and ip in net for ip in self.ips)

    def hop(self, addr: Any) -> bool:
        return any(addr.version == w.version and addr in w for w in self.nets)


def circuit_wan(circuits: list[Any] | None, source: str, device_key: str) -> tuple[set[str], set[str], set[str]]:
    """(interface names, addresses, networks) of one device's WAN circuits (``Circuit`` records or dicts)."""
    ifaces: set[str] = set()
    ips: set[str] = set()
    nets: set[str] = set()
    for c in circuits or []:
        c = circuit_dict(c)
        if not c or str(c.get("device_key") or "") != device_key:
            continue
        if c.get("source") and source and c.get("source") != source:
            continue
        if c.get("interface"):
            ifaces.add(str(c["interface"]))
        ip = _ip(c.get("ip"))
        if ip:
            ips.add(ip)
            if c.get("prefix_len"):
                try:
                    nets.add(str(ipaddress.ip_network(f"{ip}/{int(c['prefix_len'])}", strict=False)))
                except (TypeError, ValueError):
                    pass
    return ifaces, ips, nets


def interface_nets(itfs: list[Any], wan: WanSide | None = None) -> list[tuple[Any, str]]:
    """``[(network, interface name)]`` of the site LANs a device is attached to, from its Interface.ips.
    Not LANs: tunnel / loopback / management ports, WAN-side ports (see :func:`wan_side`) and networks of
    WAN circuits, link-local and public networks, /31–/32 host addresses."""
    wan = wan if wan is not None else WanSide(itfs)
    out = []
    for itf in itfs or []:
        if str(getattr(itf, "kind", "") or "") in ("tunnel", "loopback", "mgmt"):
            continue
        name = str(getattr(itf, "name", "") or "")
        if name in wan.ifaces or wan_side(itf, wan.ifaces):
            continue
        for cidr in getattr(itf, "ips", None) or []:
            try:
                iface = ipaddress.ip_interface(str(cidr))
            except ValueError:
                continue
            if _lan_net(iface.network) and not wan.covers(iface.network):
                out.append((iface.network, name))
    return out


def route_is_remote(
    r: Any, own_keys: set[str] | frozenset[str] = frozenset(), own_names: set[str] | frozenset[str] = frozenset()
) -> bool:
    """Learned from another device (overlay peer). A peer that is the route's own device — some vendors put
    the device's own host name there for its own routes, sometimes fully qualified — is not remote."""
    key = str(getattr(r, "remote_device_key", "") or "")
    name = str(getattr(r, "remote_name", "") or "").strip().lower()
    if key and key not in own_keys:
        return True
    if not name or name in own_names:
        return False
    return _short_name(name) not in {_short_name(n) for n in own_names}


def _short_name(name: str) -> str:
    return name if _is_ip(name) else name.split(".", 1)[0]


def lan_route(r: Any, wan: WanSide | None = None) -> Any:
    """The network of a route that may be a site LAN: not a default route, not out of a WAN port, private,
    not link-local, not a WAN / circuit network. → ``ip_network`` or None."""
    prefix = str(getattr(r, "prefix", "") or "").strip()
    if not prefix or prefix in _DEFAULT_ROUTES:
        return None
    try:
        net = ipaddress.ip_network(prefix, strict=False)
    except ValueError:
        return None
    if not _lan_net(net):
        return None
    if wan is not None and (str(getattr(r, "interface", "") or "") in wan.ifaces or wan.covers(net)):
        return None
    return net


def lan_next_hops(
    routes: list[Any],
    own_keys: set[str] | frozenset[str] = frozenset(),
    own_names: set[str] | frozenset[str] = frozenset(),
    connected: list[tuple[Any, str]] | None = None,
    wan: WanSide | None = None,
) -> list[tuple[str, str, str]]:
    """``[(prefix, next hop, interface)]`` of one device's routes that point at a LAN-side layer-3 neighbour:
    the next hop is a private address inside one of the device's own LAN networks (local routes, plus
    ``connected`` = LAN networks of its own interfaces) and the route was not learned over the overlay.
    Never: default routes, routes out of a WAN / management port (``wan``), next hops on a WAN network,
    public / documentation / link-local next hops. Vendor-neutral: uses Route.local / protocol / next_hop /
    interface / remote_* only (a "remote" peer equal to the device itself is ignored)."""
    wan = wan if wan is not None else WanSide()
    nets: list[tuple[Any, str]] = list(connected or [])
    for r in routes:
        if is_local_route(r) and not route_is_remote(r, own_keys, own_names):
            net = lan_route(r, wan)
            if net is not None:
                nets.append((net, str(getattr(r, "interface", "") or "")))
    out = []
    for r in routes:
        if is_local_route(r) or route_is_remote(r, own_keys, own_names):
            continue
        if str(getattr(r, "protocol", "") or "").lower() in _OVERLAY_PROTOCOLS:
            continue
        prefix = str(getattr(r, "prefix", "") or "").strip()
        if prefix in _DEFAULT_ROUTES or str(getattr(r, "interface", "") or "") in wan.ifaces:
            continue
        hop = _ip(getattr(r, "next_hop", ""))
        if not hop or not _lan_private(hop):
            continue
        addr = ipaddress.ip_address(hop)
        if addr.is_link_local or wan.hop(addr):
            continue
        lan = next((n for n in nets if addr.version == n[0].version and addr in n[0]), None)
        if lan is None:
            continue
        out.append((prefix, hop, str(getattr(r, "interface", "") or "") or lan[1]))
    return out


def circuit_sources() -> list[Any]:
    """Connected sources offering the WAN-circuits capability (``CircuitSource.list_circuits``)."""
    return sdk.sources(WAN_CIRCUITS)


def circuit_dict(c: Any) -> dict[str, Any] | None:
    """A :class:`Circuit` record (or a legacy dict) as the payload dict; ``appliance`` = ``device_name``."""
    if c is None:
        return None
    if hasattr(c, "to_dict"):
        out = c.to_dict()
    elif isinstance(c, dict):
        out = dict(c)
    else:
        return None
    out["device_name"] = out.get("device_name") or out.get("appliance") or ""
    out["appliance"] = out["device_name"]  # compatibility (v0.10.24 payloads)
    return out


def _wan(g: _Graph, circuits: list[dict[str, Any]], tunnels: list[Any], scope: SiteScope) -> dict[str, Any]:
    try:
        from app.services import topology_search

        look = topology_search.Lookups()  # the organisation index, read once for this build
        return topology_overview.wan_section(
            g.nodes,
            g.alias,
            circuits,
            tunnels,
            scope.canonical,
            look.site_of_record,
            look.site_of_ip,
            topology_search.hub_sites(),
        )
    except Exception as exc:  # noqa: BLE001 - the WAN section never breaks the map
        log.info("topology: WAN section skipped: %s", exc)
        return {"circuits": [], "remote_sites": []}


def node_detail(site_key: str | None, node_id: str) -> dict[str, Any] | None:
    """One node of a site map with every link touching it (``GET /topology/node/{id}``)."""
    graph = graph_for(site_key)
    node = next((n for n in graph.get("nodes", []) if n["id"] == node_id), None)
    if node is None:
        return None
    names = {n["id"]: {"name": n["name"], "role": n["role"], "status": n["status"]} for n in graph.get("nodes", [])}
    links = [l for l in graph.get("links", []) if node_id in (l["a_device"], l["b_device"])]
    peers = {x: names.get(x, {}) for l in links for x in (l["a_device"], l["b_device"]) if x != node_id}
    circuits = [
        c for c in (graph.get("wan") or {}).get("circuits", []) if node_id in (c.get("node_ids") or [c.get("node_id")])
    ]
    return {
        "scope": graph.get("scope", ""),
        "version": graph.get("version"),
        "node": node,
        "links": links,
        "neighbors": peers,
        "circuits": circuits,
    }


def _build(
    site_key: str | None,
    on_partial: Callable[[dict[str, Any]], None] | None = None,
    *,
    l3: bool = False,
) -> dict[str, Any]:
    started = time.monotonic()
    status = _Sources()
    caps_present = {cap: [c.provider_id for c in sdk.sources(cap)] for cap in _TOPO_CAPS}
    for cap in caps_present:
        for c in sdk.sources(cap):
            status._row(c)
    listed, products = listed_sites()
    reg = site_registry.registry(listed, products)
    scope = SiteScope(site_key, reg, _org_hint() if site_key else None)
    site_names = {ck: s["name"] for ck, s in reg.sites.items()}

    # 1. Inventory: every source (and every site key of it) at once.
    inv_sources = sdk.sources(INVENTORY)
    jobs: list[tuple[Any, Callable[[], Any], Any]] = []
    for c in inv_sources:
        args = scope.args_for(c.provider_id)
        for a in [None] if args is None else args:
            jobs.append((c, lambda c=c, a=a: c.list_devices(a), ("list_devices", a)))
    devices: list[Any] = []
    candidates: list[Any] = []  # records no site claims: LLDP adjacency may place them here
    contributed: dict[str, int] = {c.provider_id: 0 for c in inv_sources}
    seen: set[str] = set()

    clouds: list[Any] = []  # cloud security edges (any source): linked to this site when their traffic reaches it

    def take(rows: list[Any]) -> None:
        for d in rows:
            rk = _record_key(d)
            if not getattr(d, "key", "") or rk in seen:
                continue
            seen.add(rk)
            if getattr(d, "role", "") == "cloud_gateway":
                clouds.append(d)
            if scope.canonical and scope.unplaced(d) and _name_partner_site.get(rk) == scope.canonical:
                scope._placed[rk] = (scope.canonical, "ha_name")  # v0.10.30: placed by its partner's name
            if scope.record_in(d):
                devices.append(d)
                contributed[d.source] = contributed.get(d.source, 0) + 1
            elif scope.canonical and scope.unplaced(d):
                candidates.append(d)

    for rows in status.run(INVENTORY, jobs):
        take(rows)
    covered = {d.source for d in devices}
    for c in sdk.sources(NEIGHBORS):  # a neighbor source no inventory covers may describe its own boxes
        if c.provider_id not in covered and sdk.hook(c, "list_topology_devices"):
            args = scope.args_for(c.provider_id)
            for a in [None] if args is None else args:
                take(
                    status.call(c, INVENTORY, lambda c=c, a=a: c.list_topology_devices(a), ("list_topology_devices", a))
                )
    in_scope = {_record_key(d) for d in devices}
    if on_partial is not None:
        # Progressive map (v0.10.21): the boxes are known now; cabling (port statistics) is the slow part.
        try:
            pg = _Graph()
            _resolve_devices(pg, devices, {_record_key(d): scope.place(d) for d in devices}, site_names)
            _assign_tiers(pg)
            on_partial(_result(pg, site_key, scope, status, contributed, caps_present, started, partial=True))
        except Exception as exc:  # noqa: BLE001 - a partial map is a nicety, never a failure
            log.info("topology: partial result skipped: %s", exc)

    # 2. Neighbors, tunnels and device facts of every source at once (only sources with devices here).
    wanted = in_scope | {_record_key(d) for d in candidates}
    wanted_bare = {k.split(":", 1)[1] for k in wanted}
    with_devices = {k.split(":", 1)[0] for k in wanted}
    work: list[tuple[str, Callable[[], Any]]] = []
    for cap, method in ((NEIGHBORS, "list_neighbors"), (TUNNELS, "list_tunnels")):
        for c in sdk.sources(cap):
            if scope.key and c.provider_id not in with_devices:
                continue
            args = scope.args_for(c.provider_id)
            for a in [None] if args is None else args:
                work.append(
                    (cap, lambda c=c, cap=cap, m=method, a=a: status.call(c, cap, lambda: getattr(c, m)(a), (m, a)))
                )
    for c in sdk.sources(NEIGHBORS):
        if scope.key and c.provider_id not in with_devices:
            continue
        args = scope.args_for(c.provider_id)
        for a in [None] if args is None else args:
            work.append(("facts", lambda c=c, a=a: _device_facts_rows(c, a, wanted)))
    inventory_ids = {c.provider_id for c in inv_sources}
    for c in circuit_sources():
        # A circuit source with its own inventory is asked like any other source; one without (circuits
        # of boxes another source inventories) is asked unscoped and filtered by device below.
        own = c.provider_id in inventory_ids
        if scope.key and own and c.provider_id not in with_devices:
            continue
        args = scope.args_for(c.provider_id) if own else None
        for a in [None] if args is None else args:
            work.append(
                (
                    CIRCUITS,
                    lambda c=c, a=a: status.call(c, CIRCUITS, lambda: c.list_circuits(a), ("list_circuits", a)),
                )
            )
    neighbors: list[Any] = []
    tunnels: list[Any] = []
    facts: list[dict[str, Any]] = []
    circuits: list[dict[str, Any]] = []
    for (kind, _fn), rows in zip(work, _pool_run([fn for _k, fn in work])):
        if kind == NEIGHBORS:
            neighbors += [n for n in rows if f"{n.source}:{n.device_key}" in wanted]
        elif kind == TUNNELS:
            tunnels += [t for t in rows if t.device_key in wanted_bare]
        elif kind == CIRCUITS:
            circuits += [
                x for x in map(circuit_dict, rows) if x is not None and str(x.get("device_key") or "") in wanted_bare
            ]
        else:
            facts += rows

    # 3. LLDP adjacency places unassigned devices (an EdgeConnect with a blank site, …) here.
    placed = _place_by_adjacency(scope, devices, candidates, neighbors)
    devices += placed
    in_scope |= {_record_key(d) for d in placed}
    in_bare = {k.split(":", 1)[1] for k in in_scope}
    neighbors = [n for n in neighbors if f"{n.source}:{n.device_key}" in in_scope]
    tunnels = [t for t in tunnels if t.device_key in in_bare]
    circuits = [x for x in circuits if str(x.get("device_key") or "") in in_bare]
    facts = [f for f in facts if f"{f.get('source')}:{f.get('device_key')}" in in_scope]
    unplaced = [d for d in candidates if _record_key(d) not in in_scope]

    g = _Graph()
    _resolve_devices(g, devices, {_record_key(d): scope.place(d) for d in devices}, site_names)
    with _cache_lock:  # interface MACs read earlier identify boxes LLDP reports by port MAC
        for nid in g.nodes:
            for m in _iface_macs.get(nid, ()):
                g.by_mac.setdefault(m, nid)

    # 4. Layer 3 (only when asked for): interface addresses and routes of routed devices, concurrently.
    interfaces: list[tuple[str, Any]] = []
    routes: list[tuple[str, Any]] = []
    queried: set[str] = set()  # nodes whose interfaces every source covering them answered for
    if l3:
        l3_jobs: list[tuple[str, str, Callable[[], list[Any]]]] = []
        for cap, method in ((INTERFACES, "list_interfaces"), (ROUTES, "list_routes")):
            for c in sdk.sources(cap):
                targets = [
                    (node["id"], rec["key"])
                    for node in g.nodes.values()
                    if node["role"] in _L3_ROLES
                    for rec in node["records"]
                    if rec["source"] == c.provider_id
                ]
                if len(targets) > MAX_L3_DEVICE_CALLS:
                    status.cap(
                        f"Layer-3 tables were read for {MAX_L3_DEVICE_CALLS} of {len(targets)} routed devices from "
                        f"{c.manifest.product or c.provider_id} (limit per map); some L3 links may be missing."
                    )
                for nid, key in targets[:MAX_L3_DEVICE_CALLS]:
                    if cap == INTERFACES:
                        queried.add(nid)
                    l3_jobs.append(
                        (
                            cap,
                            nid,
                            lambda c=c, cap=cap, m=method, k=key: status.call(c, cap, lambda: getattr(c, m)(k), (m, k)),
                        )
                    )
        for (cap, nid, _fn), rows in zip(l3_jobs, _pool_run([fn for _c, _n, fn in l3_jobs])):
            (interfaces if cap == INTERFACES else routes).extend((nid, item) for item in rows)
        _remember_interfaces(site_key or "", queried, interfaces)
        for nid, itf in interfaces:
            m = valid_mac(getattr(itf, "mac", ""))
            if m:
                g.by_mac.setdefault(m, nid)

    _neighbors_to_links(g, neighbors)
    _apply_fingerprints(g)
    _apply_facts(g, facts)
    _l3_links(g, interfaces, routes)
    # LAN-side layer-3 neighbours (the switch / firewall behind a router), from this build's routes or the
    # routes the last layer-3 build of this map read.
    if l3:
        _remember_routes(site_key or "", routes)
    if l3:
        by_node_ifs: dict[str, list[Any]] = defaultdict(list)
        for nid, itf in interfaces:
            by_node_ifs[nid].append(itf)
    else:
        by_node_ifs = gathered_interfaces(site_key or "")
    _infer_lan_neighbors(g, routes if l3 else _cached_routes(site_key or "", g), scope, status, by_node_ifs, circuits)
    _plumbing_by_site[site_key or ""] = _observed_peer_links(g, circuits, by_node_ifs)
    _link_firewalls_to_circuits(g, circuits)
    _ha_user_partners(g, unplaced=unplaced)
    _ha_missing_units(g, unplaced=unplaced)
    if not clouds:
        try:
            from app.services import topology_org_service

            raw = topology_org_service.raw_devices() or {}
            clouds = [d for d in raw.get("devices") or [] if getattr(d, "role", "") == "cloud_gateway"]
        except Exception:  # noqa: BLE001 - the org read is optional here
            clouds = []
    _cloud_by_site[site_key or ""] = _cloud_links(g, scope, reg, [d for d in clouds if not scope.record_in(d)])

    # 5. ARP (attaches boxes without a cable): scoped to this site's routed devices and switches.
    if not scope.key:
        arp = status.gather(ARP_TABLE, "list_arp", None)
    else:
        arp_jobs: list[Callable[[], list[Any]]] = []
        for c in sdk.sources(ARP_TABLE):
            targets = [
                rec["key"]
                for node in g.nodes.values()
                if node["role"] in _L3_ROLES | {"switch"}
                for rec in node["records"]
                if rec["source"] == c.provider_id
            ]
            if len(targets) > MAX_ARP_CALLS:
                status.cap(
                    f"ARP tables were read from {MAX_ARP_CALLS} of {len(targets)} devices of "
                    f"{c.manifest.product or c.provider_id} (limit per map)."
                )
            for key in targets[:MAX_ARP_CALLS]:
                arp_jobs.append(lambda c=c, k=key: status.call(c, ARP_TABLE, lambda: c.list_arp(k), ("list_arp", k)))
        arp = [x for rows in _pool_run(arp_jobs) for x in rows]
    _arp_links(g, arp)
    _tunnel_links(g, tunnels)
    _assign_tiers(g)
    for n in g.nodes.values():
        if n["inferred"]:  # behind a router: drawn with the core / distribution layer
            n["tier"], n["tier_label"] = 3, _tier_label(3)
    for link in g.links.values():  # l3/l2 links: show every interface their members name
        for side in ("a_interface", "b_interface"):
            if not link[side] and link["layer"] != "overlay":
                link[side] = ", ".join(dict.fromkeys(m[side] for m in link["members"] if m.get(side)))
    _limit_gaps(status, devices)
    if unplaced and scope.canonical:
        by_src = Counter(d.source for d in unplaced)
        text = ", ".join(f"{n} from {products.get(s, s)}" for s, n in sorted(by_src.items()))
        status.cap(
            f"{len(unplaced)} device(s) have no site ({text}) and none of this site's devices sees them over LLDP — "
            "assign them under Topology › Site mapping."
        )
    wan = _wan(g, circuits, tunnels, scope)
    result = _result(g, site_key, scope, status, contributed, caps_present, started, wan=wan)
    log.info(
        "topology: built %s%s in %d ms — %d nodes, %d links; sources: %s",
        scope.name or site_key or "all sites",
        " (+L3)" if l3 else "",
        result["build_ms"],
        len(result["nodes"]),
        len(result["links"]),
        status.timing_text(),
    )
    return result


# Optional, vendor-neutral connector hooks for safety limits (no vendor is named here):
#   inventory_limit() → max devices one inventory read returns (the list is cut there)
#   fanout_limit()    → max devices per-device reads (LLDP, tunnels, ARP …) are sent to
# Documented fallback for connectors written before the hooks existed: ``_max_appliances()`` (inventory)
# and ``_max_firewalls()`` (fan-out) — the same numbers under their old private names.


def _call_limit(fn: Any) -> int | None:
    if not callable(fn):
        return None
    try:
        return int(fn())
    except Exception:  # noqa: BLE001 - a broken hook only hides a hint
        return None


def inventory_limit(c: Any) -> int | None:
    hook = getattr(c, "inventory_limit", None)
    if hook is None:  # transition fallback (v0.10.24): remove when all connectors implement inventory_limit
        hook = getattr(c, "_max_appliances", None)
    return _call_limit(hook)


def fanout_limit(c: Any) -> int | None:
    hook = getattr(c, "fanout_limit", None)
    if hook is None:  # transition fallback (v0.10.24): remove when all connectors implement fanout_limit
        hook = getattr(c, "_max_firewalls", None)
    return _call_limit(hook)


MAX_INFERRED = 20  # inferred LAN neighbours per map
_routes_side: OrderedDict[str, list[tuple[str, Any]]] = OrderedDict()
_inferred_by_site: dict[str, int] = {}


def _remember_routes(scope: str, routes: list[tuple[str, Any]]) -> None:
    with _cache_lock:
        _routes_side[scope] = list(routes)
        _routes_side.move_to_end(scope)
        while len(_routes_side) > CACHE_MAX_SCOPES:
            _routes_side.popitem(last=False)


def _cached_routes(scope: str, g: _Graph) -> list[tuple[str, Any]]:
    with _cache_lock:
        rows = list(_routes_side.get(scope, []))
    return [(nid, r) for nid, r in rows if nid in g.nodes]


def inferred_counts() -> dict[str, int]:
    """Inferred LAN neighbours per map, from the last build of each (diagnostics)."""
    return dict(_inferred_by_site)


def own_identity(node: dict[str, Any]) -> tuple[set[str], set[str]]:
    """(record keys, lower-case names) a node is known by — to recognise "peer = itself" in its routes."""
    keys = {r["key"] for r in node.get("records", [])} | {f"{r['source']}:{r['key']}" for r in node.get("records", [])}
    names = {str(node.get("name") or "").lower()} | {str(r.get("name") or "").lower() for r in node.get("records", [])}
    names |= {str(x).lower() for x in node.get("aliases") or []}
    return keys, names - {""}


def _infer_lan_neighbors(
    g: _Graph,
    routes: list[tuple[str, Any]],
    scope: SiteScope,
    status: _Sources,
    ifaces: dict[str, list[Any]] | None = None,
    circuits: list[Any] | None = None,
) -> None:
    """For every router's LAN next hop: link the device that owns the address (management IP, interface
    address or ``Device.addresses``), else add an inferred "Device at <ip>" node. Vendor-neutral. WAN-side
    next hops (WAN / management ports, circuit networks, default routes, public addresses) never count."""
    by_dev: dict[str, list[Any]] = defaultdict(list)
    for nid, r in routes:
        by_dev[nid].append(r)
    made = skipped = 0
    for nid in sorted(by_dev):
        node = g.nodes.get(nid)
        if node is None or node["remote"] or node["synthetic"]:
            continue
        hops: dict[str, dict[str, Any]] = {}
        keys, names = own_identity(node)
        c_if: set[str] = set()
        c_ip: set[str] = set()
        c_net: set[str] = set()
        for rec in node.get("records", []):
            a, b, c = circuit_wan(circuits, rec.get("source", ""), rec.get("key", ""))
            c_if |= a
            c_ip |= b
            c_net |= c
        itfs = (ifaces or {}).get(nid, [])
        wan = WanSide(itfs, c_if, c_ip, c_net)
        connected = interface_nets(itfs, wan)
        for prefix, hop, itf in lan_next_hops(by_dev[nid], keys, names, connected, wan):
            grp = hops.setdefault(hop, {"prefixes": [], "iface": itf, "source": by_dev[nid][0].source})
            grp["prefixes"].append(prefix)
        for hop, grp in sorted(hops.items()):
            prefixes = grp["prefixes"]
            first = prefixes[0]
            more = f" (+{len(prefixes) - 1} more)" if len(prefixes) > 1 else ""
            via = f" {grp['iface']}" if grp["iface"] else ""
            reason = f"Next hop for {first}{more} from {node['name']}{via}"
            evidence = {"kind": "route-next-hop", "source": grp["source"], "detail": reason}
            owners = [x for x in g.by_ip.get(hop, []) if x != nid and _sites_ok(g.sites(x), g.sites(nid))]
            if nid in g.by_ip.get(hop, []):
                continue  # its own address
            if owners:
                if g.linked(nid, owners[0], ("physical", "lag", "l2", "l3")):
                    continue
                link = g.add_link(
                    nid, owners[0], "l3", a_if=grp["iface"], confidence=0.5, evidence=evidence, state="unknown"
                )
                link["inferred"] = True
                continue
            if made >= MAX_INFERRED:
                skipped += 1
                continue
            site = scope.canonical or node.get("site_key") or ""
            iid = f"inferred:{site}:{hop}"
            if iid not in g.nodes:
                n = _new_node(iid, f"Device at {hop}", "unknown")
                n.update(
                    inferred=True,
                    inferred_reason=reason,
                    evidence="route-next-hop",
                    mgmt_ip=hop,
                    status="unknown",
                    site_key=site,
                    site_name=node.get("site_name") or "",
                    site_via="lan-next-hop",
                )
                n["ips"].append(hop)
                if site:
                    n["site_keys"].append(site)
                n["sources"].append(grp["source"])
                g.nodes[iid] = n
                g.index(iid)
                made += 1
            link = g.add_link(nid, iid, "l3", a_if=grp["iface"], confidence=0.5, evidence=evidence, state="unknown")
            link["inferred"] = True
    _inferred_by_site[scope.key or ""] = made
    if skipped:
        status.cap(
            f"{skipped} more router next hop(s) on this map lead to devices no connected system manages; only the "
            f"first {MAX_INFERRED} are drawn."
        )


def _link_firewalls_to_circuits(g: _Graph, circuits: list[dict[str, Any]]) -> None:
    """A firewall in front of an edge: the edge's circuit address is one of the firewall's addresses or lies in
    a network seen behind the firewall (``Device.addresses`` / ``lan_prefixes``) → inferred link, the
    firewall upstream of the edge's WAN port. Vendor-neutral."""
    firewalls = []
    for nid, n in g.nodes.items():
        if n["role"] != "firewall" or not (n.get("addresses") or n.get("lan_prefixes")):
            continue
        nets = []
        for p in n.get("lan_prefixes") or []:
            try:
                nets.append(ipaddress.ip_network(str(p), strict=False))
            except ValueError:
                continue
        firewalls.append((nid, set(n.get("addresses") or []), nets))
    if not firewalls:
        return
    for c in circuits:
        ip = _ip(c.get("ip"))
        edge = g.alias.get(f"{c.get('source')}:{c.get('device_key')}") or g.alias.get(str(c.get("device_key") or ""))
        if not ip or not edge or edge not in g.nodes:
            continue
        addr = ipaddress.ip_address(ip)
        for fw, addrs, nets in firewalls:
            if fw == edge or g.linked(edge, fw, ("physical", "lag", "l2", "l3")):
                continue
            if ip in addrs or any(addr.version == net.version and addr in net for net in nets):
                why = "is one of its addresses" if ip in addrs else "is inside a network seen behind it"
                detail = (
                    f"{g.nodes[edge]['name']} circuit {c.get('interface') or ''} ({ip}) {why}: "
                    f"{g.nodes[fw]['name']} sits in front of the edge"
                )
                link = g.add_link(
                    edge,
                    fw,
                    "l3",
                    a_if=str(c.get("interface") or ""),
                    confidence=0.5,
                    evidence={"kind": "circuit-address", "source": str(c.get("source") or ""), "detail": detail},
                    state="unknown",
                )
                link["inferred"] = True
                link["upstream_device"] = fw


# --------------------------------------------------------------------------- plumbing from logs (v0.10.27)

PLUMB_CONFIDENCE = 0.6
_plumbing_by_site: dict[str, int] = {}
_cloud_by_site: dict[str, int] = {}


def plumbing_counts() -> dict[str, int]:
    return dict(_plumbing_by_site)


def _observed_peer_links(g: _Graph, circuits: list[dict[str, Any]], ifaces: dict[str, list[Any]] | None = None) -> int:
    """A box that logged traffic of another box's address on one of its ports (``Device.observed_peers``,
    e.g. a firewall's traffic logs) is cabled to it: the other box's circuit / interface / management
    address at the same site → link with both interface names, evidence "traffic-logs". The firewall is in
    front of an edge whose WAN (circuit) address it sees; behind an edge or router whose LAN address it
    sees. Vendor-neutral."""
    owners: dict[str, list[tuple[str, str, str]]] = defaultdict(list)  # ip → [(node, interface, side)]
    for c in circuits:
        ip = _ip(c.get("ip"))
        nid = g.alias.get(f"{c.get('source')}:{c.get('device_key')}") or g.alias.get(str(c.get("device_key") or ""))
        if ip and nid:
            owners[ip].append((nid, str(c.get("interface") or ""), "wan"))
    for nid, itfs in (ifaces or {}).items():
        if nid not in g.nodes:
            continue
        for itf in itfs:
            side = "wan" if wan_side(itf) else "lan"
            for cidr in getattr(itf, "ips", None) or []:
                ip = _ip(cidr)
                if ip:
                    owners[ip].append((nid, str(getattr(itf, "name", "") or ""), side))
    for nid, n in g.nodes.items():
        ip = _ip(n.get("mgmt_ip"))
        # a switch's / AP's management address in a firewall's logs is syslog / RADIUS / SNMP traffic, not a cable
        if ip and not n["synthetic"] and n["role"] in ("sdwan_edge", "router"):
            owners[ip].append((nid, "", "mgmt"))

    def port_nets(fw: str, port: str) -> list[Any]:
        """Networks (/24–/29) of the firewall's own port, when its interface addresses are known."""
        out = []
        for itf in (ifaces or {}).get(fw, []):
            if str(getattr(itf, "name", "") or "") != port:
                continue
            for cidr in getattr(itf, "ips", None) or []:
                try:
                    net = ipaddress.ip_interface(str(cidr)).network
                except ValueError:
                    continue
                if 24 <= net.prefixlen <= 29:
                    out.append(net)
        return out

    def cabled(a: str, b: str) -> bool:
        """Already connected by cables / LLDP (directly or through other boxes)."""
        adj: dict[str, set[str]] = defaultdict(set)
        for x, y, layer in g.links:
            if layer in ("physical", "lag", "l2"):
                adj[x].add(y)
                adj[y].add(x)
        seen, todo = {a}, [a]
        while todo:
            for nb in adj[todo.pop()]:
                if nb == b:
                    return True
                if nb not in seen:
                    seen.add(nb)
                    todo.append(nb)
        return False

    made = 0
    for fw, peers in g.observed.items():
        if fw not in g.nodes:
            continue
        done: set[str] = set()
        # WAN (circuit) matches first: they decide the orientation when one box matches twice
        ranked = []
        for p in peers:
            ip = _ip(p.get("ip"))
            if not p.get("interface"):
                continue  # no port named: says where traffic goes, not how the box is cabled
            for t, t_if, side in owners.get(ip, []) if ip else []:
                ranked.append((0 if side == "wan" else 1 if side == "lan" else 2, ip, t, t_if, side, p))
        for _rank, ip, t, t_if, side, p in sorted(ranked, key=lambda x: x[0]):
            if t == fw or t in done or not _sites_ok(g.sites(fw), g.sites(t)):
                continue
            role = g.nodes[t]["role"]
            if role not in ("sdwan_edge", "router", "switch"):
                continue
            if role == "switch":
                # only a routed interface of the switch on the firewall's own port network, and never when
                # cables / LLDP already connect the two
                addr = ipaddress.ip_address(ip)
                nets = port_nets(fw, str(p.get("interface") or ""))
                if side == "mgmt" or not any(addr in n for n in nets if n.version == addr.version) or cabled(fw, t):
                    continue
            if g.linked(fw, t, ("physical", "lag")):
                done.add(t)
                continue
            done.add(t)
            fw_if, zone = str(p.get("interface") or ""), str(p.get("zone") or "")
            verb = "leaves through" if p.get("dir") == "out" else "enters on"
            what = f"{g.nodes[t]['name']} {t_if}".strip()
            detail = f"Seen in {g.nodes[fw]['name']}'s traffic logs: {ip} ({what}) {verb} {fw_if}" + (
                f" (zone {zone})" if zone else ""
            )
            existing = g.links.get((min(fw, t), max(fw, t), "l3"))
            if existing is not None and existing.get("inferred"):
                existing["evidence"].append(
                    {"kind": "traffic-logs", "source": str(p.get("source") or ""), "detail": detail}
                )
                for m in existing["members"]:  # give the earlier inferred link its interface names
                    key_fw, key_t = (
                        ("a_interface", "b_interface") if existing["a_device"] == fw else ("b_interface", "a_interface")
                    )
                    m[key_fw] = m.get(key_fw) or fw_if
                    m[key_t] = m.get(key_t) or t_if
                link = existing
            else:
                link = g.add_link(
                    fw,
                    t,
                    "l3",
                    a_if=fw_if,
                    b_if=t_if,
                    confidence=PLUMB_CONFIDENCE,
                    evidence={"kind": "traffic-logs", "source": str(p.get("source") or ""), "detail": detail},
                    state="unknown",
                )
                link["inferred"] = True
            link["zone"] = zone
            # orientation: the edge's WAN behind the firewall → firewall in front; an edge's / router's LAN
            # address seen → the firewall sits behind it; a switch's management address → behind the firewall
            if side == "wan" or g.nodes[t]["role"] in ("switch",):
                link["upstream_device"] = fw
            elif g.nodes[t]["role"] in ("sdwan_edge", "router"):
                link["upstream_device"] = t
            made += 1
    return made


CLOUD_MAX_PER_SITE = 8


def _cloud_links(g: _Graph, scope: SiteScope, reg: Any, clouds: list[Any]) -> int:
    """Cloud security edges (role "cloud_gateway") whose networks reach this site — their ``lan_prefixes`` or
    observed peer addresses fall in this site's prefix index — are drawn as remote cloud nodes linked to the
    site's firewall (else edge / router), evidence "traffic-logs". Vendor-neutral."""
    if not clouds or not scope.canonical or reg is None:
        return 0
    targets = [nid for nid, n in g.nodes.items() if n["role"] == "firewall" and not n["inferred"]]
    targets = targets or [nid for nid, n in g.nodes.items() if n["role"] in ("sdwan_edge", "router")]
    if not targets:
        return 0
    target = sorted(targets, key=lambda x: g.nodes[x]["name"])[0]
    made = 0
    for d in clouds:
        if made >= CLOUD_MAX_PER_SITE:
            break
        probes: list[str] = []
        for p in getattr(d, "lan_prefixes", None) or []:
            try:
                net = ipaddress.ip_network(str(p), strict=False)
            except ValueError:
                continue
            probes.append(str(net.network_address + 1 if net.num_addresses > 2 else net.network_address))
        probes += [_ip(p.get("ip")) for p in getattr(d, "observed_peers", None) or [] if isinstance(p, dict)]
        hits = sorted({str(ipaddress.ip_network(f"{ip}/24", strict=False)) for ip in probes if ip and ":" not in ip
                       and reg.from_subnet(ip) == scope.canonical})  # fmt: skip
        if not hits:
            continue
        nid = node_id_for([d])
        if nid not in g.nodes:
            n = _new_node(nid, d.name, "cloud_gateway")
            ck, _via = reg.place(d)
            n.update(
                remote=True,
                cloud=True,
                cloud_kind=str(getattr(d, "cloud_kind", "") or ""),
                status=d.status,
                serial=d.serial,
                vendor_name=d.vendor_name,
                site_key=ck,
                site_name=reg.name(ck) if ck else "",
                site_via="site" if ck else "",
                evidence="traffic-logs",
            )
            n["sources"].append(d.source)
            n["records"].append({"source": d.source, "key": d.key, "native_id": d.native_id, "name": d.name,
                                 "role": d.role, "model": d.model, "status": d.status, "site_key": d.site_key,
                                 "serial": d.serial, "console_url": d.console_url, "vendor": {}})  # fmt: skip
            g.nodes[nid] = n
            g.alias.setdefault(f"{d.source}:{d.key}", nid)
        detail = (
            f"{d.name} carries traffic to {len(hits)} network(s) of this site ({', '.join(hits[:3])}"
            f"{' …' if len(hits) > 3 else ''}) — seen in traffic logs"
        )
        link = g.add_link(
            nid,
            target,
            "overlay",
            confidence=0.5,
            evidence={"kind": "traffic-logs", "source": d.source, "detail": detail},
        )
        link["inferred"] = True
        link["cloud"] = True
        link["label"] = "cloud"
        link["upstream_device"] = nid
        made += 1
    return made


def _limit_gaps(status: _Sources, devices: list[Any]) -> None:
    """Connector safety limits that were reached (the list behind them is probably incomplete)."""
    per_source = Counter(d.source for d in devices)
    for c in sdk.sources(INVENTORY):
        product = c.manifest.product or c.provider_id
        limit = inventory_limit(c)
        if limit is not None and per_source.get(c.provider_id, 0) >= limit:
            status.cap(
                f"{product} returned its limit of {limit} devices; raise the device limit in its connection "
                "settings to see the rest."
            )
        limit = fanout_limit(c)
        if limit is not None:
            live = sum(1 for d in devices if d.source == c.provider_id and d.status == "up")
            if live > limit:
                status.cap(
                    f"{product} reads per-device details (LLDP, tunnels, ARP) from at most {limit} of {live} "
                    "devices on this map; raise its limit to see the rest."
                )


def graph_version(nodes: list[dict[str, Any]], links: list[dict[str, Any]]) -> str:
    """Stable hash of what the map shows: node ids + status and link keys + state."""
    h = hashlib.sha256()
    for n in sorted(nodes, key=lambda n: n["id"]):
        h.update(f"n|{n['id']}|{n.get('status')}|{n.get('name')}|{n.get('tier')}\n".encode())
    for link in sorted(links, key=lambda l: l["key"]):
        h.update(f"l|{link['key']}|{link.get('state')}\n".encode())
    return h.hexdigest()[:16]


def _result(
    g: _Graph,
    site_key: str | None,
    scope: SiteScope,
    status: _Sources,
    contributed: dict[str, int],
    caps_present: dict[str, list[str]],
    started: float,
    *,
    partial: bool = False,
    wan: dict[str, Any] | None = None,
) -> dict[str, Any]:
    nodes = sorted(g.nodes.values(), key=lambda n: (n["tier"], n["role"], str(n["name"]).lower()))
    deg: dict[str, int] = defaultdict(int)
    for a, b, _layer in g.links:
        deg[a] += 1
        deg[b] += 1
    for n in nodes:
        n["degree"] = deg[n["id"]]
    links = sorted(g.links.values(), key=lambda l: (l["layer"], l["a_device"], l["b_device"]))
    for link in links:
        link.setdefault("inferred", False)
    layers = [
        {"id": lid, "label": label, "count": sum(1 for l in links if l["layer"] in kinds), "kinds": list(kinds)}
        for lid, label, kinds in LAYERS
    ]
    wan = wan or {"circuits": [], "remote_sites": []}
    try:
        summary = topology_overview.overview(nodes, links, wan["circuits"], scope.name or site_key or "This network")
    except Exception as exc:  # noqa: BLE001 - the summary never breaks the map
        log.info("topology: overview skipped: %s", exc)
        summary = {"stages": [], "closets": [], "sentence": ""}
    gaps = (
        ["Reading cables and links from the connected sources — devices are shown first."]
        if partial
        else _scope_gaps(scope, contributed) + _gaps(g, status, caps_present)
    )
    return {
        "scope": site_key or "",
        "generated_at": time.time(),
        "build_ms": round((time.monotonic() - started) * 1000),
        "partial": partial,
        "degraded": status.degraded,
        "failed_sources": sorted(status.uncovered),
        "version": graph_version(nodes, links),
        "nodes": nodes,
        "links": links,
        "layers": layers,
        "tiers": [{"tier": t, "id": i, "label": label} for t, i, label in TIERS],
        "wan": wan,
        "overview": summary,
        "sources": list(status.status.values()),
        "gaps": gaps,
        "site": {
            "key": scope.key,
            "name": scope.name,
            "keys": sorted(scope.keys),
            "canonical": scope.canonical,
            "by_source": scope.by_source,
        },
        "stats": {
            "nodes": len(nodes),
            "links": len(links),
            "discovered": sum(1 for n in nodes if n["discovered"]),
            "merged": sum(1 for n in nodes if len(n["sources"]) > 1),
        },
    }


# --------------------------------------------------------------------------- stale-while-revalidate (v0.10.21)

GRAPH_TTL_S = CACHE_TTL_S


def _swr_build(scope: str, on_partial: Callable[[dict[str, Any]], None]) -> dict[str, Any]:
    site, l3 = _split_scope(scope)
    result = _build(site or None, on_partial, l3=l3)
    if not result.get("degraded"):  # also the synchronous cache, so health / path trace reuse this build
        _store(scope, result)
    return result


_swr = None


def swr():
    """The site-graph stale-while-revalidate cache (created lazily so tests can patch its root)."""
    global _swr
    if _swr is None:
        from app.services.topology_cache import SwrCache

        _swr = SwrCache("site", GRAPH_TTL_S, _swr_build)
    return _swr


def topology_view(site_key: str | None = None, *, fresh: bool = False, l3: bool = False) -> dict[str, Any]:
    """GET /api/v1/topology: the last built graph instantly (``stale`` when old) while a rebuild runs."""
    return swr().get(scope_key(_check_scope(site_key), l3), fresh=fresh)


def graph_for(site_key: str | None = None, *, l3: bool = False) -> dict[str, Any]:
    """A graph for health and path trace without waiting for a slow rebuild: the current or last built
    one (refreshed in the background when old); built synchronously only when none exists yet.
    ``l3`` asks for a graph with layer-3 links (path trace); without it either variant is fine."""
    site = _check_scope(site_key)
    keys = [scope_key(site, True)] if l3 else [scope_key(site), scope_key(site, True)]
    for key in keys:
        hit = _cache_get(key, time.time())
        if hit:
            return hit
    for key in keys:
        have = swr().peek(key)
        if have:
            if time.time() - have[0] >= GRAPH_TTL_S:
                swr().refresh(key)
            return have[1]
    return build_topology(site or None, l3=l3)


# --------------------------------------------------------------------------- routing table (v0.10.32)

MAX_ROUTE_ROWS = 20000


def site_routes(site_key: str | None, node_id: str = "") -> dict[str, Any]:
    """Routing tables of the routed devices (firewalls, routers, SD-WAN edges) of one site map, for the
    Topology › Routing panel: one row per route with the device it belongs to. ``node_id`` limits it to one
    device. Read-only; every source caches its own route reads."""
    graph = graph_for(site_key)
    nodes = [n for n in graph.get("nodes", []) if n.get("role") in _L3_ROLES and not n.get("synthetic")]
    if node_id:
        nodes = [n for n in nodes if n["id"] == node_id]
    by_source = {c.provider_id: c for c in sdk.sources(ROUTES)}
    jobs: list[tuple[dict[str, Any], Any, str]] = []
    for n in nodes:
        for rec in n.get("records") or []:
            c = by_source.get(str(rec.get("source") or ""))
            if c is not None and rec.get("key"):
                jobs.append((n, c, str(rec["key"])))
    jobs = jobs[:MAX_L3_DEVICE_CALLS]
    errors: list[str] = []

    def read(job: tuple[dict[str, Any], Any, str]) -> list[Any]:
        _n, c, key = job
        try:
            return list(c.list_routes(key) or [])
        except Exception as exc:  # noqa: BLE001 - one device's table never breaks the panel
            errors.append(f"{c.manifest.product or c.provider_id}: {exc}")
            return []

    rows: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str, str, str]] = set()
    for (n, c, _key), routes in zip(jobs, _pool_run([lambda j=j: read(j) for j in jobs])):
        for r in routes:
            prefix = str(getattr(r, "prefix", "") or "")
            hop = str(getattr(r, "next_hop", "") or "")
            itf = str(getattr(r, "interface", "") or "")
            vrf = str(getattr(r, "vrf", "") or "")
            ident = (n["id"], vrf, prefix, hop, itf)
            if not prefix or ident in seen:
                continue
            seen.add(ident)
            rows.append(
                {
                    "node_id": n["id"],
                    "device": n.get("name") or "",
                    "role": n.get("role") or "",
                    "prefix": prefix,
                    "next_hop": hop,
                    "interface": itf,
                    "protocol": str(getattr(r, "protocol", "") or "").lower(),
                    "vrf": vrf,
                    "peer": str(getattr(r, "remote_name", "") or ""),
                    "local": getattr(r, "local", None),
                    "source": c.manifest.product or c.provider_id,
                }
            )
            if len(rows) >= MAX_ROUTE_ROWS:
                break
    return {
        "scope": graph.get("scope", ""),
        "devices": [{"node_id": n["id"], "name": n.get("name") or "", "role": n.get("role") or ""} for n in nodes],
        "routes": rows,
        "truncated": len(rows) >= MAX_ROUTE_ROWS,
        "no_source": not by_source,
        "errors": errors[:10],
    }
