"""HPE Aruba Networking EdgeConnect SD-WAN (Silver Peak) Orchestrator connector — PREVIEW.

Validated against the Orchestrator 9.4 REST API specification (OpenAPI 3.0, 725 paths, the
"Support › REST API" page of a 9.4.11 Orchestrator) — every call below is checked against it for
method, path, parameters and response shape. Not yet run against a live Orchestrator, so it stays
``preview``. Read-only: it never calls an endpoint that changes anything.

Base path ``https://<orchestrator>/gms/rest``. 9.3+ query-parameter forms (``?nePk=``), not the
older ``/{nePk}`` path forms.

Authentication: an Orchestrator API key in the ``X-Auth-Token`` header (Orchestrator ›
Orchestrator Server › Users & Authentication › API Keys; permission ``net_read`` = read-only).
API-key requests are stateless: no login, no session cookie and therefore no CSRF
``X-XSRF-TOKEN`` (that is only needed for cookie sessions from ``POST /authentication/login``).
TLS is always verified (a private CA file can be configured instead).

Endpoints (spec path → capability):

* ``GET  /gmsserver/info``                       — hostName, release            → test connection
* ``GET  /appliance``                            — ApplianceItem[]: nePk, hostName, model, serial,
  IP, softwareVersion, state (0 unknown, 1 normal, 2 unreachable, 3 unsupported version,
  4 out of sync, 5 sync in progress), site, groupId, networkRole (0 spoke, 1 hub, 3 non-routing
  hub), hasUnsavedChanges, rebootRequired                                         → INVENTORY
* ``GET  /appliance/haPeerMeta``                 — {nePk: {nePk: peer, group}} HA pairs (optional)
* ``GET  /regions/appliances``                   — nePk → regionName (optional)
* ``POST /alarm/appliance?view=active&maxAlarms=N&orderBySeverity=true`` body ``{"nePks": [...]}``
  — active alarms (a read query; ``maxAlarms`` defaults to 5 server-side, so it is always sent).
  Orchestrators before 9.3 named the list ``ids``; that body is retried on HTTP 400/500 → ALERTS
* ``GET  /tunnels2/physical?limit=N[&nePk=]``    — {nePk: {tunnelId: {alias, tag, srcNePk,
  destNePk, sourceIpAddress, destIpAddress, operStatus, adminStatus, fecStatus, mode}}} (underlay)
* ``GET  /tunnels2/bonded?limit=N[&nePk=]``      — same map for bonded (overlay) tunnels: alias,
  tag (overlay name), overlayId, destNePk, operStatus                              → TUNNELS
* ``GET  /interfaceState?nePk=&cached=true``     — ifInfo[]: ifname, admin, oper, ipv4, ipv4mask,
  ifSpeed, duplex, mac, mtu, wan-if, lan-if, label (label id), publicIp, vrf     → INTERFACES
* ``GET  /gms/interfaceLabels?type=wan|lan``     — {labelId: {name, active}} (label id → name)
* ``GET  /subnets/all?nePk=&cached=true``        — {subnets: {segmentId: {subnets: {entries:
  [{state: {prefix, nextHop, ifName, metric, local, configured, automatic, learned, learned_bgp,
  learned_ospf, peername, peerid}}]}}}} — local and learned routes per VRF segment → ROUTES
* HEALTH (batched, ≤50 appliances per call, last 15 minutes, cached 45 s; each part optional):
  ``POST /stats/timeseries/memory?startTime&endTime`` body ``{"nePks"}`` (used/total memory),
  ``POST /stats/aggregate/flow/active`` body ``{"nePks"}`` (active flows),
  ``POST /stats/aggregate/tunnel?startTime&endTime&granularity=minute`` body ``{"nePks"}``
  (AVG_LATENCY_AVG ms, MAX_POST_PCT_LOSS % per tunnel), and
  ``POST /stats/aggregate/interface?…&trafficType=all_traffic`` (SUM_RX/TX_BYTES and _PKTS per
  interface) and ``POST /stats/aggregate/jitter?…&granularity=minute`` (AVG_JITTER per tunnel; the
  tunnel aggregate has no jitter column) → Tunnel.vendor["jitter_ms"].
  These POSTs are documented read queries; :data:`READ_QUERY_POSTS` is the closed list.

Not used (deliberately): LLDP (the 9.4 API documents none for appliances), the per-CPU
``/stats/timeseries/cpustat`` (needs a CPU id per call, no batch form), alarm acknowledgement
(``POST /alarm/acknowledgement/appliance`` needs an alarm ``id`` the alarm list does not return,
and NodeWatch keeps this connector read-only) and ``/appliance/rest`` (raw appliance pass-through).
"""

from __future__ import annotations

import ipaddress
import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable

from app.core.freshness import stale_allowed
from app.integrations.base import IntegrationError
from app.integrations.connectors.sdk import (
    Connector,
    ConnectorManifest,
    ConnectorSetup,
    HttpJsonClient,
    SettingField,
    SetupIssue,
    SetupStep,
    device_key,
    url_origin,
    epoch_seconds,
    site_key as make_site_key,
)
from app.integrations.contracts import ALERTS, HEALTH, INTERFACES, INVENTORY, ROUTES, TUNNELS, WAN_CIRCUITS
from app.integrations.domain import (
    Circuit,
    circuit_kind,
    Alert,
    Device,
    Interface,
    Route,
    Site,
    Tunnel,
    normalize_mac,
    stable_key,
)

log = logging.getLogger("nodewatch.connectors.silverpeak")

CONNECTOR_ID = "silverpeak_orchestrator"
API_PREFIX = "/gms/rest"

# Bounds: every call is limited in time (HttpJsonClient timeout), size (20 MB response cap) and count.
DEFAULT_MAX_APPLIANCES = 500
TUNNEL_LIMIT_PER_APPLIANCE = 2000
TUNNEL_LIMIT_ALL = 20000
MAX_ALARMS = 2000
MAX_ROUTES_PER_APPLIANCE = 5000
POOL_WORKERS = 8
STATS_BATCH = 50  # nePks per stats POST
# v0.10.23: tunnel stats are ~70 counters per tunnel; 25 appliances x 15 min x per-minute hit the
# 20 s timeout every time in the field, so latency/loss were never filled in.
TUNNEL_STATS_BATCH = 5
TUNNEL_STATS_WINDOW_S = 5 * 60
STATS_TIMEOUT_S = 60.0  # read-only stats queries may take longer than ordinary reads
STATS_BACKOFF_S = 600.0  # after a stats query timed out, skip that section for 10 minutes
STATS_WINDOW_S = 15 * 60
INVENTORY_CACHE_S = 60.0
TUNNEL_CACHE_S = 90.0  # raw tunnel lists shared by topology, org map and health (v0.10.23)
STALE_OK_S = 900.0  # serve the last good answer for this long when Orchestrator cannot be reached
PER_APPLIANCE_MEMO_S = 6 * 3600.0  # remember that the org-wide tunnel list is too large
CIRCUIT_CACHE_S = 120.0  # WAN interface state per appliance, one site (v0.10.24)
CIRCUIT_ORG_CACHE_S = 300.0  # the same for the whole organization (org board counts)
DEPLOYMENT_CACHE_S = 3600.0  # WAN bandwidth / next hop / comments per appliance (configuration: changes rarely)
HEALTH_CACHE_S = 45.0
LABEL_CACHE_S = 600.0
# Route tables (v0.10.26): which of /subnets/all, /subnets?nePk=, /subnets/true/{nePk} an appliance answers.
SUBNETS_MODES = ("all", "query", "path")
SUBNETS_CACHE_S = 300.0  # one appliance's route table
SUBNETS_MODE_TTL_S = 3600.0  # remember a working read per appliance (and log a failure once) for an hour
SUBNETS_GLOBAL_OFF_AFTER = 3  # appliances failing one read before it is skipped for every appliance
AGGREGATE_MAX_PREFIX = 22  # a configured local subnet wider than this (next hop 0.0.0.0) is an aggregate

_LARGE_FABRIC: dict[tuple[str, str], float] = {}  # (Orchestrator, tunnel kind) -> when it was too large
_LARGE_FABRIC_LOCK = threading.Lock()

# The only POSTs this connector may send: documented read queries that take a list of appliances.
READ_QUERY_POSTS = frozenset(
    {
        "/alarm/appliance",
        "/stats/timeseries/memory",
        "/stats/aggregate/flow/active",
        "/stats/aggregate/tunnel",
        "/stats/aggregate/interface",
        "/stats/aggregate/jitter",
    }
)

API_KEY_DOC = "https://arubanetworking.hpe.com/techdocs/sdwan/docs/orch/orchestrator/server/api-key/"

SETUP = ConnectorSetup(
    summary="EdgeConnect appliances, HA pairs, alarms, tunnels, interfaces, routes and live health from Orchestrator.",
    prerequisites=(
        "Orchestrator 9.3 or later, reachable over HTTPS (443) from this PC",
        "An Orchestrator administrator who may create API keys",
        "The address you open Orchestrator at, for example https://orchestrator.example.com",
        "Only if Orchestrator uses an internal certificate: your company root CA as a PEM file",
    ),
    steps=(
        SetupStep(
            "Open API Keys",
            "In Orchestrator open Orchestrator Server › Users & Authentication › API Keys and click the "
            "Edit (pencil) icon to add a key.",
            link=API_KEY_DOC,
            copy="Orchestrator Server › Users & Authentication › API Keys",
        ),
        SetupStep(
            "Create a read-only key",
            "Key Name: nodewatch-readonly. Permission: Read-Only (shown as net_read in the API). "
            "Description: NodeWatch monitoring (read-only). Active: Yes.",
            copy="nodewatch-readonly",
        ),
        SetupStep(
            "Restrict it (recommended)",
            "IP Allow List: this PC's address, so the key is useless anywhere else. Expiration: as your "
            "policy requires — when it expires, the Test here fails with 'Authenticated'.",
        ),
        SetupStep(
            "Copy the key",
            "Copy the Key value and paste it in the next step. NodeWatch stores it in the secure credential store "
            "(Windows Credential Manager or the macOS Keychain) and never shows it again.",
        ),
    ),
    permissions="One Orchestrator API key with Permission = Read-Only (net_read). NodeWatch only reads: "
    "GET requests plus six documented read-only query POSTs (active alarms and statistics). It never "
    "changes Orchestrator or an appliance.",
    verify="Reads Orchestrator's hostname and release, then one cheap read per capability: the appliance "
    "list, HA pairs, regions, one appliance's interfaces and routes, the underlay and overlay tunnel "
    "lists, active alarms, and one memory and one flow statistics query. Nothing is changed. At most 20 s.",
    troubleshooting=(
        SetupIssue(
            "Authenticated: fail (HTTP 401)",
            "The key is wrong, inactive or expired. Check Active = Yes and the expiration date, or create a new key.",
        ),
        SetupIssue(
            "Every read refused (HTTP 403)",
            "This PC is not in the key's IP Allow List, or the key is not allowed. Add this PC's address.",
        ),
        SetupIssue(
            "TLS certificate: fail",
            "Orchestrator uses a certificate from your company CA. Export the root CA as PEM and set "
            "'Private CA certificate'. Do not turn verification off.",
        ),
        SetupIssue(
            "Only Live health is refused",
            "Your Orchestrator refuses statistics queries for a Read-Only key. Everything else works; raise "
            "the key to Read-Write only if you want live health (NodeWatch still only reads).",
        ),
        SetupIssue(
            "Fewer appliances than expected",
            "Check 'Maximum appliances' in the form, and whether your Orchestrator limits what this key can see.",
        ),
        SetupIssue(
            "Reachable: fail",
            "Use the address you open Orchestrator at (NodeWatch adds /gms/rest). Check that HTTPS from this "
            "PC to Orchestrator is allowed (proxy, firewall).",
        ),
    ),
    data_you_get=(
        "Every EdgeConnect appliance: model, serial, software, state, site, region, hub/spoke role",
        "HA pairs",
        "Active alarms (in Requires Attention)",
        "Underlay and overlay tunnels with state, latency, loss and jitter",
        "Interfaces with their WAN/LAN labels",
        "Routes per segment, including routes learned over the SD-WAN",
        "Live health: memory, active flows, interface bit rates",
    ),
    estimated_minutes=5,
    uncertain=(
        "Whether a Read-Only key may send the alarm and statistics query POSTs. The Test answers this for "
        "your Orchestrator.",
    ),
)

MANIFEST = ConnectorManifest(
    connector_id=CONNECTOR_ID,
    vendor="HPE Aruba Networking (Silver Peak)",
    product="EdgeConnect Orchestrator",
    category="sdwan",
    capabilities=(INVENTORY, INTERFACES, ALERTS, TUNNELS, ROUTES, HEALTH, WAN_CIRCUITS),
    settings=(
        SettingField(
            "base_url",
            "Orchestrator URL",
            "url",
            required=True,
            placeholder="https://orchestrator.example.com",
            help="The address you open Orchestrator at. HTTPS only. A pasted page address is reduced to the server.",
            origin_only=True,
        ),
        SettingField(
            "api_token",
            "API key",
            "secret",
            required=True,
            help="A read-only (net_read) API key from Orchestrator › Orchestrator Server › "
            "Users & Authentication › API Keys. Stored in the secure credential store (Windows Credential Manager or the macOS Keychain).",
        ),
        SettingField(
            "verify_tls",
            "Verify TLS certificate",
            "boolean",
            default=True,
            help="Keep on. Use a CA file for private certificates.",
        ),
        SettingField(
            "ca_file",
            "Private CA certificate (optional)",
            "text",
            placeholder=r"C:\certs\company-root-ca.pem",
            help="PEM file that signed the Orchestrator certificate, instead of turning verification off.",
        ),
        SettingField("timeout", "Request timeout (seconds)", "number", default=20),
        SettingField(
            "max_appliances",
            "Maximum appliances",
            "number",
            default=DEFAULT_MAX_APPLIANCES,
            help="Safety limit on how many appliances NodeWatch reads per refresh.",
        ),
    ),
    description="EdgeConnect appliances, HA pairs, alarms, underlay and overlay tunnels, interfaces, "
    "routes and live health (memory, flows, tunnel latency/loss/jitter, interface rates) from Orchestrator. "
    "Validated against the Orchestrator 9.4 REST API specification; not yet run on a live system.",
    docs_url="https://developer.arubanetworks.com/edgeconnect/docs",
    maturity="preview",
    setup=SETUP,
)

# Appliance "state" → device status.
APPLIANCE_STATE = {1: "up", 2: "down", 3: "degraded", 4: "degraded", 5: "degraded"}
APPLIANCE_STATE_LABEL = {
    0: "Unknown",
    1: "Normal",
    2: "Unreachable",
    3: "Unsupported version",
    4: "Out of sync",
    5: "Sync in progress",
}
NETWORK_ROLE = {"0": "Spoke", "1": "Hub", "3": "Non-routing hub"}
ALARM_SEVERITY = {"critical": "critical", "major": "major", "minor": "warning", "warning": "warning"}
ALARM_CATEGORY = {
    "tunnel": "connectivity",
    "equipment": "hardware",
    "software": "system",
    "traffic class": "performance",
    "threshold crossing": "performance",
}


def _text(value: Any) -> str:
    return "" if value is None else str(value).strip()


def _int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _num(value: Any) -> float | None:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if number == number else None  # NaN → None


def _ip(value: Any) -> str:
    """A usable host address, or '' (0.0.0.0, '::', '', names …)."""
    text = _text(value).split("/", 1)[0]
    try:
        addr = ipaddress.ip_address(text)
    except ValueError:
        return ""
    return "" if addr.is_unspecified else str(addr)


def _cidr(ip: Any, mask: Any) -> str:
    ip_text = _ip(ip)
    if not ip_text:
        return ""
    mask_text = _text(mask)
    try:
        prefix = int(mask_text) if mask_text.isdigit() else ipaddress.IPv4Network(f"0.0.0.0/{mask_text}").prefixlen
        return str(ipaddress.ip_interface(f"{ip_text}/{prefix}"))
    except ValueError:
        return ip_text


def _prefix(value: Any) -> str:
    try:
        return str(ipaddress.ip_network(_text(value), strict=False))
    except ValueError:
        return ""


def _speed(value: Any) -> float | None:
    text = _text(value).lower().replace("mbps", "").replace("m", "").strip()
    try:
        return float(text)
    except ValueError:
        return None


def _chunks(items: list[str], size: int) -> list[list[str]]:
    return [items[i : i + size] for i in range(0, len(items), size)]


def tunnel_state(oper: Any, admin: Any = "") -> str:
    o, a = _text(oper).lower(), _text(admin).lower()
    if a == "down" or o.startswith("down"):
        return "down"
    if o.startswith("degraded") or o.startswith("partial"):
        return "degraded"
    if o.startswith("up"):  # "Up - active", "Up - idle" (no traffic right now), "Up" (bonded) …
        return "up"
    return "unknown"


def interface_kind(name: str) -> str:
    n = name.lower()
    if n.startswith("mgmt"):
        return "mgmt"
    if n.startswith(("lo", "loopback")):
        return "loopback"
    if n.startswith(("bvi", "blan", "bwan")):
        return "logical"
    if "." in n:
        return "vlan"
    return "physical"


def _short(name: str) -> str:
    """'spehwc1.corp.example' → 'spehwc1' (addresses unchanged)."""
    text = name.strip().lower()
    return text if not text or text.replace(".", "").isdigit() or ":" in text else text.split(".", 1)[0]


def _peer_is_self(state: dict, own_names: set[str] | frozenset[str] = frozenset()) -> bool:
    """``peername`` names the appliance that shares the route; for the appliance's OWN routes Orchestrator
    puts its own host name there (pyedgeconnect ``get_appliance_subnets``: "Peer appliance hostname"),
    sometimes fully qualified."""
    peer = _text(state.get("peername")).lower()
    return not peer or peer in own_names or _short(peer) in {_short(n) for n in own_names}


def _peer_directory(data: Any, segments: dict) -> tuple[dict[str, str], str]:
    """(peerid → peer host name, this appliance's own system id) from a subnets answer, wherever the
    ``peers`` list and ``moduleInfo`` sit (top level or inside ``subnets``)."""
    names: dict[str, str] = {}
    my_id = ""
    for holder in (data if isinstance(data, dict) else {}, segments if isinstance(segments, dict) else {}):
        for p in holder.get("peers") or []:
            if isinstance(p, dict) and _text(p.get("peerid")):
                names[_text(p.get("peerid"))] = _text(p.get("peerName") or p.get("peername"))
        info = holder.get("moduleInfo")
        if isinstance(info, dict) and not my_id:
            my_id = _text(info.get("my system id") or info.get("mySystemId"))
    return names, my_id


def _with_peername(state: dict, peer_names: dict[str, str], my_id: str, row: dict) -> dict:
    """Give a per-VRF entry (``peerid`` only) the ``peername`` the rest of the reader understands: the
    appliance's own host name for its own routes, the peer's host name for routes shared by another one."""
    if _text(state.get("peername")) or not _text(state.get("peerid")):
        return state
    pid = _text(state.get("peerid"))
    own = _text(row.get("hostName"))
    fabric = _text(state.get("learnFrom")).upper().startswith("LRN_SPS") or bool(_text(state.get("nexthopTunnel")))
    if pid == "0" or (my_id and pid == my_id):
        name = own  # peerid 0: no fabric peer (own subnet, or learned from a local OSPF / BGP neighbour)
    elif pid in peer_names:
        name = peer_names[pid] or f"peer {pid}"
    elif fabric:
        name = f"peer {pid}"  # shared by an appliance the peers list does not name
    else:
        name = own  # not a known peer and not from the fabric: the appliance's own route
    return {**state, "peername": name}


def _aggregate(state: dict) -> bool:
    """A configured (not automatic) local subnet with next hop 0.0.0.0 wider than /22: a summary the
    appliance advertises for a whole region, not a network attached to it."""
    if state.get("automatic"):
        return False
    try:
        net = ipaddress.ip_network(_text(state.get("prefix")), strict=False)
    except ValueError:
        return False
    return net.version == 4 and net.prefixlen < AGGREGATE_MAX_PREFIX


def _overlay_route(state: dict, own_names: set[str] | frozenset[str] = frozenset()) -> bool:
    """Shared by another EdgeConnect over the fabric (subnet sharing), not a route of this site's LAN."""
    learn_from = _text(state.get("learnFrom")).upper()
    return (
        learn_from.startswith("LRN_SPS")
        or bool(_text(state.get("nexthopTunnel")))
        or not _peer_is_self(state, own_names)
    )


def route_is_local(state: dict, own_names: set[str] | frozenset[str] = frozenset()) -> bool | None:
    """EdgeConnect: an automatic (interface) or configured local subnet is this appliance's own LAN.

    Routes learned from a fabric peer (another appliance, ``LRN_SPS_*``, over a tunnel) are not; neither
    are BGP / OSPF routes (learned from a LAN or WAN neighbour: their next hop tells which)."""
    if _overlay_route(state, own_names):
        return False
    if state.get("learned_bgp") or state.get("learned_ospf"):
        return False
    hop = _text(state.get("nextHop") or state.get("nexthop") or state.get("resolvedNexthop"))
    if hop in ("", "0.0.0.0", "::") and _aggregate(state):
        return False
    if state.get("automatic") or state.get("local"):
        return hop in ("", "0.0.0.0", "::") or not state.get("configured")
    if state.get("configured"):
        return hop in ("", "0.0.0.0", "::")
    if state.get("learned"):
        return False
    return None


def route_protocol(state: dict, own_names: set[str] | frozenset[str] = frozenset()) -> str:
    if _overlay_route(state, own_names):
        return "sdwan"  # shared by another EdgeConnect over the overlay (subnet sharing)
    if state.get("learned_bgp"):
        return "bgp"
    if state.get("learned_ospf"):
        return "ospf"
    if state.get("automatic"):
        return "connected"
    if state.get("configured") or state.get("local"):
        hop = _text(state.get("nextHop") or state.get("nexthop") or state.get("resolvedNexthop"))
        if hop in ("", "0.0.0.0", "::"):
            return "aggregate" if _aggregate(state) else "connected"
        return "static"
    if state.get("learned"):
        return "sdwan"
    return ""


def _is_public(ip: str) -> bool:
    try:
        return bool(ip) and ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def _prefix_len(mask: Any) -> int | None:
    """``255.255.255.248`` / ``29`` / ``"29"`` → 29."""
    text = _text(mask)
    if not text:
        return None
    if text.isdigit():
        n = int(text)
        return n if 0 <= n <= 32 else None
    try:
        return ipaddress.IPv4Network(f"0.0.0.0/{text}").prefixlen
    except ValueError:
        return None


class SilverPeakOrchestratorConnector(Connector):
    manifest = MANIFEST

    def __init__(self) -> None:
        super().__init__()
        self._lock = threading.Lock()
        self._cache: dict[str, tuple[float, Any]] = {}
        self._gates: dict[str, threading.Lock] = {}
        self._subnet_modes: dict[str, tuple[str, float]] = {}  # nePk → (working route read, when)
        self._subnet_fail: dict[str, set[str]] = {m: set() for m in SUBNETS_MODES}  # read → failing nePks
        self._subnet_logged: dict[str, float] = {}
        self._subnet_off: dict[str, float] = {}  # read → skipped for every appliance until (monotonic)
        self._subnet_all_tried: dict[str, float] = {}  # nePk → last /subnets/all attempt
        self._subnet_vrfs: set[str] = set()  # nePks whose last good /subnets/all had VRF segments

    def reset_state(self) -> None:
        super().reset_state()
        with self._lock:
            self._cache = {}
            self._subnet_modes = {}
            self._subnet_fail = {m: set() for m in SUBNETS_MODES}
            self._subnet_logged = {}
            self._subnet_off = {}
            self._subnet_all_tried = {}
            self._subnet_vrfs = set()

    @property
    def configured(self) -> bool:
        s = self.settings()
        return bool(s.get("base_url") and s.get("api_token"))

    def build_http(self) -> HttpJsonClient:
        s = self.settings()
        base = url_origin(_text(s.get("base_url"))) or _text(s.get("base_url")).rstrip("/")
        token = self.secret("api_token")
        if not base or not token:
            raise IntegrationError("Orchestrator URL and API key are required", code="NOT_CONFIGURED")
        return HttpJsonClient(
            base + API_PREFIX,
            headers={"X-Auth-Token": token},  # API keys: stateless, no session cookie / CSRF token
            product=MANIFEST.product,
            verify_tls=bool(s.get("verify_tls", True)),
            ca_file=_text(s.get("ca_file")),
            timeout=float(s.get("timeout") or 20),
            secrets=(token,),
        )

    def _console_url(self) -> str:
        return url_origin(_text(self.settings().get("base_url")))

    def _max_appliances(self) -> int:
        try:
            value = int(float(self.settings().get("max_appliances") or DEFAULT_MAX_APPLIANCES))
        except (TypeError, ValueError):
            value = DEFAULT_MAX_APPLIANCES
        return max(1, min(value, 5000))

    # ---- small helpers --------------------------------------------------------------------------
    def _refresh_cached(self, name: str, ttl: float, fn: Callable[[], Any]) -> None:
        gate = self._gates.get(name)
        if gate is None or not gate.acquire(blocking=False):
            return  # someone is already reading it
        cache = self._cache  # reset_state() replaces it: an answer read with old settings is dropped
        try:
            value = fn()
        except Exception:  # noqa: BLE001 - the stale answer stays; the next read retries
            return
        finally:
            gate.release()
        with self._lock:
            if self._cache is cache:
                self._cache[name] = (time.monotonic(), value)

    def _cached(self, name: str, ttl: float, fn: Callable[[], Any]) -> Any:
        """Cached read, one build at a time per name (concurrent callers wait for the same answer),
        and the last good answer (up to STALE_OK_S old) when Orchestrator cannot be reached."""
        with self._lock:
            hit = self._cache.get(name)
            if hit and time.monotonic() - hit[0] < ttl:
                return hit[1]
            gate = self._gates.setdefault(name, threading.Lock())
            # v0.10.40: just expired (within 3x its lifetime, at most STALE_OK_S): answer with it now and
            # refresh in the background, so a page does not wait for Orchestrator on every expiry.
            age = time.monotonic() - hit[0] if hit else None
            serve_stale = age is not None and age < min(STALE_OK_S, ttl * 3) and not gate.locked() and stale_allowed()
        if serve_stale:
            threading.Thread(
                target=self._refresh_cached, args=(name, ttl, fn), name="orchestrator-refresh", daemon=True
            ).start()
            return hit[1]
        with gate:
            with self._lock:
                hit = self._cache.get(name)
                if hit and time.monotonic() - hit[0] < ttl:
                    return hit[1]
            try:
                value = fn()
            except IntegrationError as exc:
                if (
                    hit
                    and exc.code in ("PROVIDER_UNAVAILABLE", "RATE_LIMITED")
                    and time.monotonic() - hit[0] < STALE_OK_S
                ):
                    log.info(
                        "Orchestrator %s unavailable (%s); using the answer from %.0f s ago",
                        name,
                        exc.code,
                        time.monotonic() - hit[0],
                    )
                    return hit[1]
                raise
            with self._lock:
                self._cache[name] = (time.monotonic(), value)
            return value

    def _warm_health(self, site_key: str | None, wait_s: float = 8.0) -> None:
        """Run one health-statistics read in the background (one at a time) and wait up to ``wait_s``."""
        with self._lock:
            t = getattr(self, "_warm_thread", None)
            last = getattr(self, "_warm_at", -1e9)
            if (t is None or not t.is_alive()) and time.monotonic() - last < 300:
                return  # tried a moment ago without figures: do not hold every map read up
            if t is None or not t.is_alive():
                self._warm_at = time.monotonic()
                def run() -> None:
                    try:
                        self.list_health(site_key)
                    except Exception as exc:  # noqa: BLE001 - enrichment only
                        log.info("Orchestrator health statistics for circuits unavailable: %s", type(exc).__name__)

                t = threading.Thread(target=run, name="sp-circuit-stats", daemon=True)
                self._warm_thread = t
                t.start()
        t.join(max(0.0, wait_s))

    def _peek(self, name: str, ttl: float) -> Any:
        with self._lock:
            hit = self._cache.get(name)
        return hit[1] if hit and time.monotonic() - hit[0] < ttl else None

    def _query(self, http: Any, path: str, *, params: dict[str, Any] | None = None, body: Any = None) -> Any:
        """POST a documented read query (never anything that changes Orchestrator)."""
        if path not in READ_QUERY_POSTS:
            raise IntegrationError(f"{path} is not an allowed read query", code="UNSUPPORTED")
        return http.request("POST", path, params=params, body=body, timeout=STATS_TIMEOUT_S)

    @staticmethod
    def _optional(fn: Callable[[], Any], what: str) -> Any:
        """Enrichment calls: a failure (e.g. no permission) leaves the field empty, never the whole read."""
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001 - optional data
            log.info("Orchestrator %s unavailable (%s)", what, type(exc).__name__)
            return None

    @staticmethod
    def _pool_map(fn: Callable[[Any], Any], items: list[Any]) -> list[Any]:
        if len(items) <= 1:
            return [fn(x) for x in items]
        with ThreadPoolExecutor(max_workers=min(POOL_WORKERS, len(items)), thread_name_prefix="sp-orch") as pool:
            return list(pool.map(fn, items))

    # ---- raw reads ------------------------------------------------------------------------------
    def _appliances(self) -> list[dict]:
        def load() -> list[dict]:
            rows = self.call(lambda: self.http().get("/appliance"), "list appliances")
            if isinstance(rows, dict):  # one appliance (the spec documents the single-item shape)
                rows = [rows]
            rows = [r for r in rows or [] if isinstance(r, dict) and self._ne_pk(r)]
            limit = self._max_appliances()
            if len(rows) > limit:
                log.warning("Orchestrator lists %d appliances; reading the first %d", len(rows), limit)
                rows = rows[:limit]
            return rows

        return self._cached("appliances", INVENTORY_CACHE_S, load)

    def _ha_peers(self) -> dict[str, str]:
        """nePk → HA peer nePk, from ``GET /appliance/haPeerMeta``."""

        def load() -> dict[str, str]:
            data = self._optional(lambda: self.http().get("/appliance/haPeerMeta"), "HA peers")
            out: dict[str, str] = {}
            for ne_pk, value in (data or {}).items() if isinstance(data, dict) else ():
                peer = ""
                if isinstance(value, dict):
                    peer = _text(value.get("nePk")) or next(
                        (_text(k) for k in value if _text(k).upper().endswith(".NE")), ""
                    )
                elif isinstance(value, str):
                    peer = _text(value)
                if peer and peer != ne_pk:
                    out[_text(ne_pk)] = peer
            return out

        return self._cached("ha_peers", INVENTORY_CACHE_S, load)

    def _regions(self) -> dict[str, str]:
        """nePk → region name, from ``GET /regions/appliances``."""

        def load() -> dict[str, str]:
            data = self._optional(lambda: self.http().get("/regions/appliances"), "regions")
            rows = [data] if isinstance(data, dict) and "nePk" in data else data
            if isinstance(rows, dict):  # {nePk: {...}} form
                rows = [{"nePk": k, **v} for k, v in rows.items() if isinstance(v, dict)]
            return {
                _text(r.get("nePk")): _text(r.get("regionName"))
                for r in rows or []
                if isinstance(r, dict) and _text(r.get("nePk")) and _text(r.get("regionName"))
            }

        return self._cached("regions", INVENTORY_CACHE_S, load)

    def _labels(self) -> dict[str, dict[str, str]]:
        """{"wan": {labelId: name}, "lan": {...}} from ``GET /gms/interfaceLabels?type=``."""

        def load() -> dict[str, dict[str, str]]:
            out: dict[str, dict[str, str]] = {}
            for kind in ("wan", "lan"):
                data = self._optional(lambda k=kind: self.http().get("/gms/interfaceLabels", type=k), "labels")
                if isinstance(data, dict) and isinstance(data.get(kind), dict):
                    data = data[kind]
                out[kind] = {
                    _text(k): _text(v.get("name"))
                    for k, v in (data or {}).items()
                    if isinstance(v, dict) and _text(v.get("name"))
                }
            return out

        return self._cached("labels", LABEL_CACHE_S, load)

    @staticmethod
    def _ne_pk(row: dict) -> str:
        return _text(row.get("nePk") or row.get("id"))

    def _key(self, row: dict) -> str:
        return device_key(serial=row.get("serial"), source=CONNECTOR_ID, native_id=self._ne_pk(row))

    @staticmethod
    def _site_of(row: dict) -> str:
        return _text(row.get("site"))

    def _scoped(self, site: str | None) -> list[dict]:
        rows = self._appliances()
        if not site:
            return rows
        return [r for r in rows if self._site_of(r) and make_site_key(CONNECTOR_ID, self._site_of(r)) == site]

    def _directory(self) -> tuple[dict[str, str], dict[str, str], dict[str, str]]:
        """(nePk → device key, nePk → hostname, lower-case hostname → device key) over all appliances."""
        rows = self._appliances()
        keys = {self._ne_pk(r): self._key(r) for r in rows}
        names = {self._ne_pk(r): _text(r.get("hostName")) for r in rows}
        by_name = {_text(r.get("hostName")).lower(): self._key(r) for r in rows if _text(r.get("hostName"))}
        return keys, names, by_name

    def _device_by_key(self, key: str) -> dict | None:
        return next((r for r in self._appliances() if self._key(r) == key), None)

    # ---- INVENTORY ------------------------------------------------------------------------------
    def list_sites(self) -> list[Site]:
        rows = self._appliances()
        regions = self._regions()
        out = []
        for name in sorted({self._site_of(r) for r in rows if self._site_of(r)}):
            members = [r for r in rows if self._site_of(r) == name]
            region = next((regions.get(self._ne_pk(r)) for r in members if regions.get(self._ne_pk(r))), "")
            out.append(
                Site(
                    key=make_site_key(CONNECTOR_ID, name),
                    source=CONNECTOR_ID,
                    name=name,
                    native_id=name,
                    vendor={k: v for k, v in {"region": region, "appliances": len(members)}.items() if v},
                )
            )
        return out

    def list_devices(self, site_key: str | None = None) -> list[Device]:
        console = self._console_url()
        rows = self._scoped(site_key)
        peers = self._ha_peers()
        regions = self._regions()
        by_ne = {self._ne_pk(r): r for r in self._appliances()}
        out = []
        for r in rows:
            ne_pk = self._ne_pk(r)
            state = _int(r.get("state"))
            site = self._site_of(r)
            peer = by_ne.get(peers.get(ne_pk, ""))
            members = []
            if peer is not None:
                members = [
                    {
                        "name": _text(peer.get("hostName")) or self._ne_pk(peer),
                        "serial": _text(peer.get("serial")),
                        "model": _text(peer.get("model")),
                        "role": "ha_peer",
                        "device_key": self._key(peer),
                        "status": APPLIANCE_STATE.get(_int(peer.get("state")) or 0, "unknown"),
                    }
                ]
            out.append(
                Device(
                    key=self._key(r),
                    source=CONNECTOR_ID,
                    name=_text(r.get("hostName")) or ne_pk,
                    role="sdwan_edge",
                    native_id=ne_pk,
                    site_key=make_site_key(CONNECTOR_ID, site) if site else "",
                    site_name=site,
                    vendor_name="HPE Aruba Networking",
                    model=_text(r.get("model")),
                    serial=_text(r.get("serial")),
                    mgmt_ip=_ip(r.get("IP") or r.get("ip")),
                    os_version=_text(r.get("softwareVersion")),
                    status=APPLIANCE_STATE.get(state, "unknown") if state is not None else "unknown",
                    members=members,
                    # EdgeConnect HA pairs forward active/active; "standalone" when no peer is known.
                    ha_state=("active" if peer is not None else "standalone"),
                    console_url=console,
                    vendor={
                        k: v
                        for k, v in {
                            "nePk": ne_pk,
                            "state": APPLIANCE_STATE_LABEL.get(state, "") if state is not None else "",
                            "mode": _text(r.get("mode")),
                            "network_role": NETWORK_ROLE.get(_text(r.get("networkRole")), _text(r.get("networkRole"))),
                            "group_id": _text(r.get("groupId")),
                            "region": regions.get(ne_pk, ""),
                            "ha_peer": _text(peer.get("hostName")) if peer is not None else "",
                            "hardware_revision": _text(r.get("hardwareRevision")),
                            "unsaved_changes": r.get("hasUnsavedChanges"),
                            "reboot_required": r.get("rebootRequired"),
                            "bypass": r.get("bypass"),
                        }.items()
                        if v not in (None, "")
                    },
                )
            )
        return out

    # ---- INTERFACES -----------------------------------------------------------------------------
    def list_interfaces(self, device_key: str) -> list[Interface]:
        row = self._device_by_key(device_key)
        if row is None:
            return []
        ne_pk = self._ne_pk(row)
        data = self._interface_state(ne_pk)  # shared with circuits and route reads (cached)
        info = data.get("ifInfo") if isinstance(data, dict) else None
        info = info if isinstance(info, list) else []
        labels = self._labels() if info else {}
        out = []
        for i in info:
            if not isinstance(i, dict) or not _text(i.get("ifname")):
                continue
            name = _text(i["ifname"])
            cidr = _cidr(i.get("ipv4"), i.get("ipv4mask"))
            duplex = _text(i.get("duplex")).lower()
            wan, lan = i.get("wan-if"), i.get("lan-if")
            label_id = _text(i.get("label"))
            label = ""
            if label_id:
                side = "wan" if wan else ("lan" if lan else "")
                label = (labels.get(side) or {}).get(label_id, "") if side else ""
                label = label or next((m[label_id] for m in labels.values() if label_id in m), "")
            sub = name.rsplit(".", 1)[1] if "." in name else ""
            out.append(
                Interface(
                    key=stable_key(device_key, name),
                    source=CONNECTOR_ID,
                    device_key=device_key,
                    name=name,
                    kind=interface_kind(name),
                    role="wan" if wan else ("lan" if lan else ("mgmt" if interface_kind(name) == "mgmt" else "")),
                    admin_up=bool(i["admin"]) if i.get("admin") is not None else None,
                    oper_up=bool(i["oper"]) if i.get("oper") is not None else None,
                    speed_mbps=_speed(i.get("ifSpeed")),
                    duplex="full" if duplex.startswith("full") else ("half" if duplex.startswith("half") else ""),
                    mac=normalize_mac(i.get("mac")),
                    ips=[cidr] if cidr else [],
                    vlans=[int(sub)] if sub.isdigit() else [],
                    vrf="" if _text(i.get("vrf")) in ("", "0") else _text(i.get("vrf")),
                    description=_text(i.get("comment")),
                    vendor={
                        k: v
                        for k, v in {
                            "role": "WAN" if wan else ("LAN" if lan else ""),
                            "label": label or label_id,
                            "public_ip": _text(i.get("publicIp")),
                            "dhcp": i.get("ipv4dhcp") or None,
                            "mtu": i.get("mtu"),
                            "vrf": i.get("vrf"),
                        }.items()
                        if v not in (None, "")
                    },
                )
            )
        return out

    # ---- ROUTES ---------------------------------------------------------------------------------
    _ROUTE_FIELDS_LOGGED = False

    def _subnets(self, ne_pk: str) -> Any:
        """The route table: ``GET /subnets/all`` (every VRF segment); some appliances answer 500 there
        (Orchestrator proxies ``/subnets3/all/vrfs``), then ``GET /subnets?nePk=&cached=true`` and the
        single-table ``GET /subnets/true/{nePk}``.

        * The read that works is remembered per appliance for ``SUBNETS_MODE_TTL_S``; ``/subnets/all`` is
          retried per appliance once per that period, and always first for an appliance whose last good
          ``/subnets/all`` had VRF segments (a default-table fallback is used only when it fails right now).
        * A read failing on ``SUBNETS_GLOBAL_OFF_AFTER`` appliances is skipped for appliances not yet tried,
          for one period; any success of that read clears it.
        * A failure is logged once per appliance per period."""
        http = self.http()
        calls = {
            "all": lambda: http.get("/subnets/all", nePk=ne_pk, cached="true"),
            "query": lambda: http.get("/subnets", nePk=ne_pk, cached="true"),
            "path": lambda: http.get(f"/subnets/true/{ne_pk}"),
        }
        now = time.monotonic()
        ttl = SUBNETS_MODE_TTL_S
        with self._lock:
            off = {m for m, until in self._subnet_off.items() if until > now}
            known = self._subnet_modes.get(ne_pk)
            tried = self._subnet_all_tried.get(ne_pk)
            if ne_pk in self._subnet_vrfs:
                retry_all = True
            elif tried is None:
                retry_all = "all" not in off
                if not retry_all:
                    self._subnet_all_tried[ne_pk] = now  # skipped org-wide: its own retry comes in one period
            else:
                retry_all = now - tried >= ttl
            rest = [m for m in SUBNETS_MODES if m != "all" and m not in off] or [SUBNETS_MODES[-1]]
            if retry_all or (known and known[0] == "all" and now - known[1] < ttl):
                order = ["all", *rest]
            elif known and now - known[1] < ttl:
                order = [known[0], *[m for m in rest if m != known[0]]]
            else:
                order = rest
        last: IntegrationError | None = None
        for mode in order:
            if mode == "all":
                with self._lock:
                    self._subnet_all_tried[ne_pk] = now
            try:
                data = self.call(calls[mode], "read routes")
            except IntegrationError as exc:
                if getattr(exc, "status_code", None) not in (400, 404, 405, 500, 501, 502, 503, 504):
                    raise
                last = exc
                with self._lock:
                    self._subnet_fail[mode].add(ne_pk)
                    turn_off = len(self._subnet_fail[mode]) >= SUBNETS_GLOBAL_OFF_AFTER and mode not in off
                    if turn_off and mode != SUBNETS_MODES[-1]:
                        self._subnet_off[mode] = now + ttl
                        off.add(mode)
                    quiet = now - self._subnet_logged.get(f"{ne_pk}|{mode}", -ttl - 1) < ttl
                    if not quiet:
                        self._subnet_logged[f"{ne_pk}|{mode}"] = now
                if not quiet:
                    log.info("Orchestrator route read %s of %s failed (%s)", mode, ne_pk, exc.status_code)
                if turn_off and mode != SUBNETS_MODES[-1]:
                    log.info(
                        "Orchestrator route read %s failed on %d appliances: skipped for appliances not yet "
                        "tried during the next %d s",
                        mode,
                        SUBNETS_GLOBAL_OFF_AFTER,
                        int(ttl),
                    )
                continue
            with self._lock:
                self._subnet_modes[ne_pk] = (mode, now)
                self._subnet_fail[mode].discard(ne_pk)
                self._subnet_off.pop(mode, None)  # it works again somewhere: no longer skipped org-wide
                if mode == "all":
                    segs = data.get("subnets") if isinstance(data, dict) else None
                    vrfs = isinstance(segs, dict) and any(str(k) not in ("0", "", "entries") for k in segs)
                    if vrfs:
                        self._subnet_vrfs.add(ne_pk)
                    else:
                        self._subnet_vrfs.discard(ne_pk)
            return data
        if last is not None:
            raise last
        return {}

    def _wan_ifnames(self, ne_pk: str) -> set[str]:
        """Names of the appliance's WAN interfaces (``wan-if``), from the cached interface state; empty when
        that cannot be read (route reads never fail because of it)."""

        def read() -> set[str]:
            try:
                data = self._interface_state(ne_pk)
            except Exception as exc:  # noqa: BLE001 - optional for route reads
                log.info("Orchestrator interface state of %s unavailable for routes (%s)", ne_pk, type(exc).__name__)
                return set()
            info = data.get("ifInfo") if isinstance(data, dict) else None
            rows = info if isinstance(info, list) else []
            return {
                _text(i.get("ifname"))
                for i in rows
                if isinstance(i, dict) and i.get("wan-if") and _text(i.get("ifname"))
            }

        return set(self._cached(f"wanifs:{ne_pk}", CIRCUIT_ORG_CACHE_S, read))

    def list_routes(self, device_key: str) -> list[Route]:
        row = self._device_by_key(device_key)
        if row is None:
            return []
        ne_pk = self._ne_pk(row)
        # v0.10.40: a route table is kept 5 minutes (route view, path trace and the subnet index share it).
        data = self._cached(f"subnets:{ne_pk}", SUBNETS_CACHE_S, lambda: self._subnets(ne_pk))
        segments = data.get("subnets") if isinstance(data, dict) else None
        if not isinstance(segments, dict):
            return []
        if "entries" in segments:  # single-table (/subnets) shape — possibly beside VRF segments (mixed shape)
            top = {k: segments[k] for k in ("entries", "count", "max") if k in segments}
            rest = {k: v for k, v in segments.items() if k not in ("entries", "count", "max")}
            segments = {**rest, "0": {"subnets": top}}
        # Per-VRF shape (ECOS /subnets3/all/vrfs, what Orchestrator proxies /subnets/all to — pyedgeconnect
        # get_appliance_subnets_all_vrfs): subnets → {<vrf id>: {count, max, entries: [...]}, peers: [...],
        # moduleInfo: {...}}. Entries carry ``peerid`` instead of ``peername``: the peers list names
        # them, and moduleInfo["my system id"] is the appliance itself.
        peer_names, my_id = _peer_directory(data, segments)
        _keys, names, by_name = self._directory()
        own = {n.lower() for n in (_text(row.get("hostName")), names.get(ne_pk, ""), ne_pk) if n}
        wan_ifs = self._wan_ifnames(ne_pk)
        out: list[Route] = []
        seen: set[tuple] = set()
        for seg_id, seg in (segments or {}).items():
            if not isinstance(seg, dict) or seg_id in ("peers", "moduleInfo"):
                continue
            table = seg if isinstance(seg.get("entries"), list) else seg.get("subnets")
            entries = table.get("entries") if isinstance(table, dict) else None
            for entry in entries if isinstance(entries, list) else ():
                if len(out) >= MAX_ROUTES_PER_APPLIANCE:
                    break
                state = (
                    entry.get("state") if isinstance(entry, dict) and isinstance(entry.get("state"), dict) else entry
                )
                if not isinstance(state, dict):
                    continue
                state = _with_peername(state, peer_names, my_id, row)
                if not SilverPeakOrchestratorConnector._ROUTE_FIELDS_LOGGED:
                    SilverPeakOrchestratorConnector._ROUTE_FIELDS_LOGGED = True
                    log.info("Orchestrator route entry fields: %s", ", ".join(sorted(map(str, state))))
                prefix = _prefix(state.get("prefix"))
                if not prefix:
                    continue
                peer = _text(state.get("peername"))
                is_self = _peer_is_self(state, own)
                remote = "" if is_self else (by_name.get(peer.lower(), "") if peer else "")
                if remote == device_key:
                    remote = ""
                vrf = "" if _text(seg_id) in ("", "0") else _text(seg_id)
                hop = _ip(state.get("nextHop") or state.get("nexthop")) or _ip(state.get("resolvedNexthop"))
                ifname = _text(state.get("ifName") or state.get("resolvedInterface"))
                local = route_is_local(state, own)
                if local and ifname in wan_ifs:
                    local = False  # a WAN interface subnet (ISP / MPLS / firewall transit), not a site LAN
                route = Route(
                    source=CONNECTOR_ID,
                    device_key=device_key,
                    prefix=prefix,
                    next_hop="" if hop in ("0.0.0.0", "::") else hop,
                    interface=ifname,
                    protocol=route_protocol(state, own),
                    vrf=vrf,
                    local=local,
                    remote_device_key=remote,
                    remote_name="" if is_self else peer,
                )
                ident = (route.prefix, route.next_hop, route.remote_name, route.vrf, route.protocol)
                if ident not in seen:
                    seen.add(ident)
                    out.append(route)
        return out

    # ---- ALERTS ---------------------------------------------------------------------------------
    def list_alerts(self, site_key: str | None = None) -> list[Alert]:
        appliances = self._scoped(site_key)
        if not appliances:
            return []
        by_ne = {self._ne_pk(r): r for r in appliances}
        ids = list(by_ne)
        http = self.http()
        params = {"view": "active", "maxAlarms": MAX_ALARMS, "orderBySeverity": "true"}

        def fetch() -> Any:
            try:
                return self._query(http, "/alarm/appliance", params=params, body={"nePks": ids})
            except IntegrationError as exc:
                if exc.status_code not in (400, 500):
                    raise
                # Orchestrator before 9.3 names the list "ids".
                return self._query(http, "/alarm/appliance", params=params, body={"ids": ids})

        rows = self.call(fetch, "read appliance alarms")
        console = self._console_url()
        out = []
        for a in rows or []:
            if not isinstance(a, dict) or a.get("closed"):
                continue
            ne_pk = _text(a.get("applianceId"))
            appliance = by_ne.get(ne_pk, {})
            atype = _text(a.get("type"))
            name = _text(a.get("name")) or atype or "Alarm"
            description = _text(a.get("description"))
            site = self._site_of(appliance) if appliance else ""
            facts = [{"label": "Alarm type", "value": atype, "kind": "text"}] if atype else []
            if _text(a.get("source")):
                facts.append({"label": "Source", "value": _text(a["source"]), "kind": "text"})
            if a.get("recommendedAction"):
                facts.append({"label": "Recommended action", "value": _text(a["recommendedAction"]), "kind": "text"})
            if a.get("serviceAffect") is not None:
                facts.append(
                    {"label": "Service affecting", "value": "Yes" if a["serviceAffect"] else "No", "kind": "text"}
                )
            out.append(
                Alert(
                    key=stable_key(CONNECTOR_ID, ne_pk, a.get("typeId") or name, a.get("source"), description),
                    source=CONNECTOR_ID,
                    type=f"silverpeak.{_text(a.get('typeId') or name)}",
                    category=ALARM_CATEGORY.get(atype.lower(), "system"),
                    severity=ALARM_SEVERITY.get(_text(a.get("severity")).lower(), "info"),
                    title=name,
                    detail=description,
                    site_key=make_site_key(CONNECTOR_ID, site) if site else "",
                    site_name=site,
                    device_key=self._key(appliance) if appliance else "",
                    device_name=_text(a.get("hostName")) or _text(appliance.get("hostName")),
                    device_role="sdwan_edge",
                    interface=_text(a.get("source")) if atype.lower() == "equipment" else "",
                    first_seen=epoch_seconds(a.get("timeOccurredInMills")),
                    last_seen=epoch_seconds(a.get("timeOccurredInMills")),
                    count=max(1, _int(a.get("occurrenceCount")) or 1),
                    acknowledged=bool(a.get("acknowledged")),
                    native_id=_text(a.get("sequenceId")),
                    console_url=console,
                    facts=facts,
                    vendor={"nePk": ne_pk, "source": _text(a.get("source")), "clearable": a.get("clearable")},
                )
            )
        return out

    # ---- TUNNELS --------------------------------------------------------------------------------
    @staticmethod
    def _tunnel_rows(payload: Any) -> list[dict]:
        """``{nePk: {tunnelId: {...}}}`` (the documented map), ``{tunnelId: {...}}`` or a list."""
        if isinstance(payload, list):
            return [r for r in payload if isinstance(r, dict)]
        if not isinstance(payload, dict):
            return []
        rows: list[dict] = []
        for outer, value in payload.items():
            if not isinstance(value, dict):
                continue
            if any(k in value for k in ("operStatus", "alias", "destNePk", "srcNePk")):
                rows.append({"id": outer, **value})
            else:
                rows.extend({"id": t, "srcNePk": outer, **v} for t, v in value.items() if isinstance(v, dict))
        return rows

    def _fetch_tunnels(self, http: HttpJsonClient, kind: str, ne_pk: str | None) -> list[dict]:
        """One /tunnels2/{kind} read. Bonded (overlay) reads ask Orchestrator to leave out the embedded
        physical member tunnels (``children=false``): with them a large fabric answers tens of MB."""
        limit = TUNNEL_LIMIT_ALL if ne_pk is None else TUNNEL_LIMIT_PER_APPLIANCE
        params: dict[str, Any] = {"nePk": ne_pk, "limit": limit}
        if kind == "bonded":
            params["children"] = "false"
        payload = self.call(lambda: http.get(f"/tunnels2/{kind}", **params), f"read {kind} tunnels")
        rows = self._tunnel_rows(payload)
        if len(rows) >= limit:
            log.warning("Orchestrator returned the %s-tunnel limit (%d); list may be incomplete", kind, limit)
        return [r for r in rows if ne_pk is None or _text(r.get("srcNePk")) in ("", ne_pk)]

    def _all_tunnels(self, http: HttpJsonClient, kind: str) -> list[dict]:
        """Every tunnel of one kind: one org-wide read, or one read per appliance when the org-wide
        answer is too big.

        v0.10.23: "too big" is remembered for PER_APPLIANCE_MEMO_S (before, every refresh downloaded
        ~20 MB, threw it away and then read per appliance), the failed attempt no longer marks the
        connection unhealthy, and one appliance that cannot be read no longer discards every tunnel.
        """
        memo = (url_origin(_text(self.settings().get("base_url"))), kind)
        with _LARGE_FABRIC_LOCK:
            known_large = time.monotonic() - _LARGE_FABRIC.get(memo, -1e18) < PER_APPLIANCE_MEMO_S
        if not known_large:
            try:
                limit = TUNNEL_LIMIT_ALL
                params: dict[str, Any] = {"limit": limit}
                if kind == "bonded":
                    params["children"] = "false"
                rows = self._tunnel_rows(http.get(f"/tunnels2/{kind}", **params))
                self._health.mark_success()
                if len(rows) >= limit:
                    log.warning("Orchestrator returned the %s-tunnel limit (%d); list may be incomplete", kind, limit)
                return rows
            except IntegrationError as exc:
                if getattr(exc, "code", "") != "RESPONSE_TOO_LARGE":
                    self._health.mark_error(self.redact(exc), status_code=exc.status_code)
                    raise
                with _LARGE_FABRIC_LOCK:  # shared with Test/Re-test instances of the same Orchestrator
                    _LARGE_FABRIC[memo] = time.monotonic()
                log.info("Orchestrator %s-tunnel list too large in one answer; reading per appliance from now on", kind)
        ne_pks = [n for n in (self._ne_pk(r) for r in self._appliances()) if n]
        return self._appliances_tunnels(http, kind, ne_pks)

    def _appliance_tunnels(self, http: HttpJsonClient, kind: str, ne_pk: str) -> list[dict]:
        """One appliance's tunnels, cached per appliance (shared by site maps, the org map and
        health); a read that fails falls back to that appliance's last good list (STALE_OK_S)."""

        def load() -> list[dict]:
            try:
                return self._fetch_tunnels(http, kind, ne_pk)
            except IntegrationError as exc:
                if exc.code != "PROVIDER_UNAVAILABLE":
                    raise
                return self._fetch_tunnels(http, kind, ne_pk)  # one retry for a network hiccup

        return self._cached(f"tunnels:{kind}:{ne_pk}", TUNNEL_CACHE_S, load)

    def _appliances_tunnels(self, http: HttpJsonClient, kind: str, ne_pks: list[str]) -> list[dict]:
        failures: list[IntegrationError] = []

        def one(ne_pk: str) -> list[dict]:
            try:
                return self._appliance_tunnels(http, kind, ne_pk)
            except IntegrationError as exc:
                failures.append(exc)
                return []

        rows: list[dict] = []
        for part in self._pool_map(one, ne_pks):
            rows.extend(part)
        if failures:
            if len(failures) == len(ne_pks):
                raise failures[0]
            log.warning(
                "Orchestrator %s tunnels: %d of %d appliances could not be read", kind, len(failures), len(ne_pks)
            )
            self._health.mark_error(
                f"{len(failures)} of {len(ne_pks)} appliances' {kind} tunnels could not be read: {self.redact(failures[0])}"
            )
        return rows

    def _raw_tunnels(self, ne_pks: list[str] | None) -> list[tuple[str, dict]]:
        """[(type, row)] for physical (underlay) and bonded (overlay) tunnels of these appliances (None = all)."""
        http = self.http()
        jobs: list[tuple[str, str | None]] = []
        for kind in ("physical", "bonded"):
            if ne_pks is None:
                jobs.append((kind, None))
            else:
                jobs.extend((kind, n) for n in ne_pks)

        def fetch(job: tuple[str, str | None]) -> list[tuple[str, dict]]:
            kind, ne_pk = job
            rows = self._all_tunnels(http, kind) if ne_pk is None else self._fetch_tunnels(http, kind, ne_pk)
            return [(kind, r) for r in rows]

        out: list[tuple[str, dict]] = []
        for part in self._pool_map(fetch, jobs):
            out.extend(part)
        return out

    def list_tunnels(self, site_key: str | None = None) -> list[Tunnel]:
        appliances = self._scoped(site_key)
        if not appliances:
            return []
        scoped = {self._ne_pk(r) for r in appliances}
        keys, names, _ = self._directory()
        # v0.10.23: one cached org-wide read shared by every site map, the org map and health
        # (filtered to the site below) instead of a fresh set of reads per caller.
        if site_key:
            # A site: only its own appliances, each from the per-appliance cache (v0.10.23 review).
            http = self.http()
            raw = []
            for kind in ("physical", "bonded"):
                raw.extend((kind, r) for r in self._appliances_tunnels(http, kind, sorted(scoped)))
        else:
            raw = self._cached("raw_tunnels", TUNNEL_CACHE_S, lambda: self._raw_tunnels(None))
        metrics = self._peek("tunnel_stats", HEALTH_CACHE_S * 2) or {}
        out: list[Tunnel] = []
        seen: set[str] = set()
        for kind, t in raw:
            src = _text(t.get("srcNePk"))
            if src not in scoped:
                continue
            tid = _text(t.get("id"))
            alias = _text(t.get("alias"))
            dest = _text(t.get("destNePk"))
            overlay = kind == "bonded"
            key = (
                stable_key(CONNECTOR_ID, src, "bonded", tid or alias)
                if overlay
                else stable_key(CONNECTOR_ID, src, tid or alias)
            )
            if key in seen:
                continue
            seen.add(key)
            passthrough = tid.lower().startswith("passthrough") or (not dest and not overlay)
            m = metrics.get((src, tid)) or metrics.get((src, alias)) or {}
            out.append(
                Tunnel(
                    key=key,
                    source=CONNECTOR_ID,
                    device_key=keys.get(src, ""),
                    name=alias or tid,
                    kind="other" if passthrough else "sdwan",
                    layer="passthrough" if passthrough else ("overlay" if overlay else "underlay"),
                    jitter_ms=m.get("jitter_ms"),
                    local_ip=_ip(t.get("sourceIpAddress")),
                    remote_ip=_ip(t.get("destIpAddress")),
                    remote_device_key=keys.get(dest, ""),
                    remote_name=names.get(dest, "") or _text(t.get("destTunnelAlias")),
                    state=tunnel_state(t.get("operStatus"), t.get("adminStatus")),
                    latency_ms=m.get("latency_ms"),
                    loss_pct=m.get("loss_pct"),
                    vendor={
                        k: v
                        for k, v in {
                            "tunnel_id": tid,
                            "tunnel_type": "passthrough" if passthrough else ("overlay" if overlay else "underlay"),
                            "overlay": _text(t.get("tag")),
                            "overlay_id": t.get("overlayId"),
                            "oper_status": _text(t.get("operStatus")),
                            "admin_status": _text(t.get("adminStatus")),
                            "fec": _text(t.get("fecStatus")),
                            "mode": _text(t.get("mode")),
                            "peer_tunnel": _text(t.get("destTunnelAlias")),
                            "members": len(t["children"]) if isinstance(t.get("children"), list) else None,
                            "jitter_ms": m.get("jitter_ms"),
                        }.items()
                        if v not in (None, "")
                    },
                )
            )
        return out

    # ---- WAN CIRCUITS (v0.10.24) ------------------------------------------------------------------
    def _interface_state(self, ne_pk: str, ttl: float = CIRCUIT_CACHE_S) -> dict:
        return self._cached(
            f"ifstate:{ne_pk}",
            ttl,
            lambda: self.call(lambda: self.http().get("/interfaceState", nePk=ne_pk, cached="true"), "read interface state")
            or {},
        )

    def _deployment(self, ne_pk: str) -> dict:
        """``GET /deployment?nePk=``: per WAN address the configured bandwidth, next hop, NAT and comment.
        Optional: older Orchestrators or read-only keys without it still list circuits."""
        return self._cached(
            f"deployment:{ne_pk}",
            DEPLOYMENT_CACHE_S,
            lambda: self._optional(lambda: self.http().get("/deployment", nePk=ne_pk), "deployment") or {},
        )

    @staticmethod
    def _deployment_ips(dep: Any) -> dict[str, dict]:
        """interface name → its first configured WAN address entry (ip, mask, wanNexthop, maxBW, ...)."""
        out: dict[str, dict] = {}
        for mode_if in (dep or {}).get("modeIfs") or [] if isinstance(dep, dict) else []:
            if not isinstance(mode_if, dict):
                continue
            name = _text(mode_if.get("ifName") or mode_if.get("ifname"))
            ips = [x for x in mode_if.get("applianceIPs") or [] if isinstance(x, dict)]
            if name and ips:
                out[name] = ips[0]
        return out

    def list_circuits(self, site_key: str | None = None) -> list[Circuit]:
        """Every WAN (internet / MPLS / LTE) circuit of the appliances in scope: one per WAN interface.

        Joins interface state (address, public IP, speed, up/down, WAN label), the deployment (configured
        bandwidth, next hop, NAT, comment - often the carrier), the underlay tunnels leaving that address
        (how many are up, their latency / loss / jitter from the last health read) and the interface
        throughput from the last health read. Read-only; cached per appliance.
        """
        appliances = self._scoped(site_key)
        if not appliances:
            return []
        labels = self._labels()
        wan_labels = labels.get("wan") or {}
        rates = self._peek("if_rates", HEALTH_CACHE_S * 4) or {}
        metrics = self._peek("tunnel_stats", HEALTH_CACHE_S * 4) or {}
        if not rates or not metrics:
            # v0.10.38: traffic and latency come from the health statistics. They used to be filled only when
            # Live health was switched on, so circuits showed no usage or quality. Read them now (bounded wait;
            # the read continues in the background and the next map refresh has them).
            self._warm_health(site_key, wait_s=8.0)
            rates = self._peek("if_rates", HEALTH_CACHE_S * 4) or {}
            metrics = self._peek("tunnel_stats", HEALTH_CACHE_S * 4) or {}
        http = self.http()
        org_scope = site_key is None
        underlay_by_src: dict[str, list[dict]] = {}
        if org_scope:
            # Whole organization: reuse the tunnel list the maps already read (one shared cache)
            # instead of one underlay read per appliance (v0.10.24 review).
            try:
                for kind, t in self._cached("raw_tunnels", TUNNEL_CACHE_S, lambda: self._raw_tunnels(None)):
                    if kind == "physical":
                        underlay_by_src.setdefault(_text(t.get("srcNePk")), []).append(t)
            except IntegrationError:
                underlay_by_src = {}

        def one(row: dict) -> list[Circuit]:
            ne_pk = self._ne_pk(row)
            try:
                state = self._interface_state(ne_pk, CIRCUIT_ORG_CACHE_S if org_scope else CIRCUIT_CACHE_S)
            except IntegrationError as exc:
                log.info("Orchestrator circuits of %s unavailable: %s", ne_pk, exc.code)
                return []
            info = [i for i in (state.get("ifInfo") or []) if isinstance(i, dict)] if isinstance(state, dict) else []
            wans = [i for i in info if i.get("wan-if") and _text(i.get("ifname"))]
            if not wans:
                return []
            deploy = self._deployment_ips(self._deployment(ne_pk))
            if org_scope:
                underlay = underlay_by_src.get(ne_pk, [])
            else:
                try:
                    underlay = self._appliance_tunnels(http, "physical", ne_pk)
                except IntegrationError:
                    underlay = []
            out = []
            for i in wans:
                name = _text(i["ifname"])
                ip = _text(i.get("ipv4"))
                public_ip = _text(i.get("publicIp"))
                dep = deploy.get(name) or deploy.get(name.split(".")[0]) or {}
                label_id = _text(i.get("label") or dep.get("label"))
                label = wan_labels.get(label_id, "") or label_id
                max_bw = dep.get("maxBW") if isinstance(dep.get("maxBW"), dict) else {}
                mine = [
                    t
                    for t in underlay
                    if _text(t.get("sourceIpAddress")) in {x for x in (ip, public_ip) if x}
                    or (label and f"_{label}-" in _text(t.get("alias")))
                ]
                up = [t for t in mine if _text(t.get("operStatus")).lower().startswith("up")]
                tm = [
                    metrics.get((ne_pk, _text(t.get("alias")))) or metrics.get((ne_pk, _text(t.get("id")))) or {}
                    for t in mine
                ]
                lat = [m["latency_ms"] for m in tm if m.get("latency_ms") is not None]
                loss = [m["loss_pct"] for m in tm if m.get("loss_pct") is not None]
                jit = [m["jitter_ms"] for m in tm if m.get("jitter_ms") is not None]
                r = rates.get((ne_pk, name)) or {}
                oper = i.get("oper")
                admin = i.get("admin")
                state_txt = "down" if admin is False or oper is False else "up" if oper else "unknown"
                if state_txt == "up" and mine and not up:
                    state_txt = "degraded"  # link up, but no tunnel over it is
                comment = _text(dep.get("comment") or i.get("comment"))
                out.append(
                    Circuit(
                        key=stable_key(CONNECTOR_ID, ne_pk, "circuit", name),
                        source=CONNECTOR_ID,
                        device_key=self._key(row),
                        interface=name,
                        device_name=_text(row.get("hostName")),
                        site_key=make_site_key(CONNECTOR_ID, self._site_of(row)) if self._site_of(row) else "",
                        label=label,
                        carrier=comment or label,
                        kind=circuit_kind(label, comment),
                        public_ip=public_ip or (ip if _is_public(ip) else ""),
                        ip=ip,
                        prefix_len=_prefix_len(i.get("ipv4mask") or dep.get("mask")),
                        gateway=_text(dep.get("wanNexthop") or dep.get("nexthop")),
                        dhcp=bool(i.get("ipv4dhcp") or dep.get("dhcp")),
                        behind_nat=_text(dep.get("behindNAT")) not in ("", "none", "None", "false", "False"),
                        speed_mbps=_speed(i.get("ifSpeed")),
                        bandwidth_down_kbps=_int(max_bw.get("inbound")),
                        bandwidth_up_kbps=_int(max_bw.get("outbound")),
                        admin_up=None if admin is None else bool(admin),
                        state=state_txt,
                        tunnels_up=len(up),
                        tunnels_total=len(mine),
                        latency_ms=round(sum(lat) / len(lat), 1) if lat else None,
                        loss_pct=max(loss) if loss else None,
                        jitter_ms=round(sum(jit) / len(jit), 1) if jit else None,
                        rx_bps=r.get("rx_bps"),
                        tx_bps=r.get("tx_bps"),
                        comment=comment,
                        vendor={k: v for k, v in {"label_id": label_id, "ne_pk": ne_pk}.items() if v},
                    )
                )
            return out

        rows: list[Circuit] = []
        for part in self._pool_map(one, appliances):
            rows.extend(part)
        return rows

    # ---- HEALTH ---------------------------------------------------------------------------------
    def _stats(self, path: str, ne_pks: list[str], batch: int, params: dict[str, Any]) -> list[Any]:
        http = self.http()

        def fetch(chunk: list[str]) -> Any:
            return self.call(lambda: self._query(http, path, params=params, body={"nePks": chunk}), f"read {path}")

        return self._pool_map(fetch, _chunks(ne_pks, batch))

    @staticmethod
    def _memory(parts: list[Any]) -> dict[str, float]:
        """nePk → used memory % from the latest row of ``POST /stats/timeseries/memory``."""
        out: dict[str, float] = {}
        for part in parts:
            if not isinstance(part, dict):
                continue
            cols = [str(c) for c in part.get("column_def") or []]
            data = part.get("data")
            if not isinstance(data, dict):
                continue
            for ne_pk, rows in data.items():
                if not isinstance(rows, list):
                    continue
                records = [
                    dict(zip(cols, r)) if isinstance(r, list) else r for r in rows if isinstance(r, (list, dict))
                ]
                records = [r for r in records if _num(r.get("totalMemory"))]
                if not records:
                    continue
                last = max(records, key=lambda r: _num(r.get("time")) or 0)
                used, total = _num(last.get("usedMemory")), _num(last.get("totalMemory"))
                if used is not None and total:
                    out[_text(ne_pk)] = round(100.0 * used / total, 1)
        return out

    @staticmethod
    def _flows(parts: list[Any]) -> dict[str, int]:
        out: dict[str, int] = {}
        for part in parts:
            for ne_pk, v in (part or {}).items() if isinstance(part, dict) else ():
                if isinstance(v, dict):
                    counts = [
                        _int(v.get(k)) for k in ("TCP_ACCELERATED_COUNT", "TCP_NOT_ACCELERATED_COUNT", "NON_TCP_COUNT")
                    ]
                    if any(c is not None for c in counts):
                        out[_text(ne_pk)] = sum(c or 0 for c in counts)
        return out

    @staticmethod
    def _tunnel_metrics(parts: list[Any]) -> dict[tuple[str, str], dict[str, Any]]:
        """(nePk, tunnel name) → {latency_ms, loss_pct} from ``POST /stats/aggregate/tunnel``."""
        out: dict[tuple[str, str], dict[str, Any]] = {}
        for part in parts:
            for tname, per_ne in (part or {}).items() if isinstance(part, dict) else ():
                if not isinstance(per_ne, dict):
                    continue
                for ne_pk, s in per_ne.items():
                    if not isinstance(s, dict):
                        continue
                    latency = _num(s.get("AVG_LATENCY_AVG"))
                    loss = _num(s.get("MAX_POST_PCT_LOSS"))
                    if latency is None and loss is None:
                        continue
                    out[(_text(ne_pk), _text(tname))] = {
                        "latency_ms": latency,
                        "loss_pct": max(0.0, min(loss, 100.0)) if loss is not None else None,
                        "max_latency_ms": _num(s.get("MAX_LATENCY_MAX")),
                    }
        return out

    @staticmethod
    def _jitter(parts: list[Any]) -> dict[tuple[str, str], float]:
        """(nePk, tunnel name) → average jitter (ms) from ``POST /stats/aggregate/jitter`` rows."""
        out: dict[tuple[str, str], float] = {}
        for part in parts:
            for row in part if isinstance(part, list) else ():
                if not isinstance(row, dict) or not _text(row.get("nePk")) or not _text(row.get("TUNNEL")):
                    continue
                jitter = _num(row.get("AVG_JITTER"))
                if jitter is not None:
                    out[(_text(row["nePk"]), _text(row["TUNNEL"]))] = max(0.0, jitter)
        return out

    @staticmethod
    def _interface_rates(parts: list[Any], window_s: int) -> dict[tuple[str, str], dict[str, Any]]:
        """(nePk, interface) → {rx_bps, tx_bps} from ``POST /stats/aggregate/interface`` byte sums."""
        out: dict[tuple[str, str], dict[str, float]] = {}
        for part in parts:
            for row in part if isinstance(part, list) else ():
                if not isinstance(row, dict) or not _text(row.get("nePk")) or not _text(row.get("INTERFACE")):
                    continue
                lo, hi = _num(row.get("MIN_TIMESTAMP")), _num(row.get("MAX_TIMESTAMP"))
                span = (hi - lo + 60) if lo and hi and hi >= lo else float(window_s)
                if span > 10 * window_s:  # timestamps in ms, not s
                    span = span / 1000.0
                span = max(60.0, span)
                rx, tx = _num(row.get("SUM_RX_BYTES")), _num(row.get("SUM_TX_BYTES"))
                if rx is None and tx is None:
                    continue
                out[(_text(row["nePk"]), _text(row["INTERFACE"]))] = {
                    "rx_bps": round((rx or 0) * 8 / span, 1),
                    "tx_bps": round((tx or 0) * 8 / span, 1),
                    "rx_pkts": _int(row.get("SUM_RX_PKTS")),
                    "tx_pkts": _int(row.get("SUM_TX_PKTS")),
                }
        return out

    def list_health(self, site_key: str | None = None) -> dict[str, list[Any]]:
        def build() -> dict[str, list[Any]]:
            appliances = self._scoped(site_key)
            ne_pks = [self._ne_pk(r) for r in appliances]
            if not ne_pks:
                return {"devices": [], "interfaces": [], "tunnels": []}
            end = int(time.time())
            window = {"startTime": end - STATS_WINDOW_S, "endTime": end}
            errors: list[IntegrationError] = []

            def section(fn: Callable[[], Any]) -> Any:
                try:
                    return fn()
                except IntegrationError as exc:
                    errors.append(exc)
                    return None

            tunnel_window = {"startTime": end - TUNNEL_STATS_WINDOW_S, "endTime": end, "granularity": "minute"}

            def tunnel_section() -> Any:
                if self._peek("tunnel_stats_backoff", STATS_BACKOFF_S) is not None:
                    return self._peek("tunnel_stats", STATS_BACKOFF_S * 2)  # last good figures, if any
                try:
                    return self._tunnel_metrics(
                        self._stats("/stats/aggregate/tunnel", ne_pks, TUNNEL_STATS_BATCH, tunnel_window)
                    )
                except IntegrationError as exc:
                    if exc.code == "PROVIDER_UNAVAILABLE":
                        with self._lock:
                            self._cache["tunnel_stats_backoff"] = (time.monotonic(), True)
                        log.info("Orchestrator tunnel statistics timed out; retrying in %.0f min", STATS_BACKOFF_S / 60)
                    raise

            sections: list[Callable[[], Any]] = [
                lambda: self._memory(self._stats("/stats/timeseries/memory", ne_pks, STATS_BATCH, window)),
                lambda: self._flows(self._stats("/stats/aggregate/flow/active", ne_pks, STATS_BATCH, {})),
                tunnel_section,
                lambda: self._interface_rates(
                    self._stats(
                        "/stats/aggregate/interface",
                        ne_pks,
                        STATS_BATCH,
                        {**window, "granularity": "minute", "trafficType": "all_traffic"},
                    ),
                    STATS_WINDOW_S,
                ),
                lambda: self._jitter(self._stats("/stats/aggregate/jitter", ne_pks, TUNNEL_STATS_BATCH, tunnel_window)),
            ]
            # v0.10.23: the five stats queries run side by side (were one after another).
            with ThreadPoolExecutor(max_workers=len(sections), thread_name_prefix="sp-health") as pool:
                futures = [pool.submit(section, fn) for fn in sections]
                memory, flows, tunnel_metrics, rates, jitter = (f.result() for f in futures)
            if len(errors) == len(sections):
                raise errors[0]
            if tunnel_metrics is not None or jitter:
                tunnel_metrics = dict(tunnel_metrics or {})
                for ident, value in (jitter or {}).items():
                    tunnel_metrics[ident] = {**tunnel_metrics.get(ident, {}), "jitter_ms": value}
                with self._lock:
                    # v0.10.38: merged, so a site's health read never hides the other sites' figures
                    prev = self._cache.get("tunnel_stats")
                    merged = dict(prev[1]) if prev and time.monotonic() - prev[0] < HEALTH_CACHE_S * 8 else {}
                    merged.update(tunnel_metrics)
                    self._cache["tunnel_stats"] = (time.monotonic(), merged)

            devices = self.list_devices(site_key)
            for d in devices:
                d.memory_pct = (memory or {}).get(d.native_id)
                d.sessions = (flows or {}).get(d.native_id)
            keys = {self._ne_pk(r): self._key(r) for r in appliances}
            interfaces = []
            if rates:
                with self._lock:
                    prev = self._cache.get("if_rates")
                    merged = dict(prev[1]) if prev and time.monotonic() - prev[0] < HEALTH_CACHE_S * 8 else {}
                    merged.update(rates)
                    self._cache["if_rates"] = (time.monotonic(), merged)
            for (ne_pk, ifname), r in sorted((rates or {}).items()):
                dkey = keys.get(ne_pk)
                if not dkey:
                    continue
                interfaces.append(
                    Interface(
                        key=stable_key(dkey, ifname),  # same key list_interfaces gives this port
                        source=CONNECTOR_ID,
                        device_key=dkey,
                        name=ifname,
                        kind=interface_kind(ifname),
                        rx_bps=r["rx_bps"],
                        tx_bps=r["tx_bps"],
                        rx_pkts=r.get("rx_pkts"),
                        tx_pkts=r.get("tx_pkts"),
                        vendor={k: r[k] for k in ("rx_pkts", "tx_pkts") if r.get(k) is not None},
                    )
                )
            tunnels = section(lambda: self.list_tunnels(site_key)) or []
            return {"devices": devices, "interfaces": interfaces, "tunnels": tunnels}

        return self._cached(f"health:{site_key or ''}", HEALTH_CACHE_S, build)

    # ---- capability probe (Settings › Connections › Test; see probe.py) ------------------------------
    def probe_plan(self) -> list[Any]:
        from app.integrations.connectors.silverpeak_orchestrator.probe import plan

        return plan(self)

    # ---- connection test --------------------------------------------------------------------------
    def test_connection(self) -> dict[str, Any]:
        if not self.configured:
            return {
                "ok": False,
                "provider": CONNECTOR_ID,
                "configured": False,
                "detail": "Enter the Orchestrator URL and API key.",
            }
        info = self.call(lambda: self.http().get("/gmsserver/info"), "read Orchestrator info") or {}
        release = _text(info.get("release") or info.get("version"))
        host = _text(info.get("hostName"))
        detail = (
            " · ".join(x for x in (host, f"Orchestrator {release}" if release else "") if x) or "Orchestrator answered"
        )
        return {"ok": True, "provider": CONNECTOR_ID, "configured": True, "detail": detail}


CONNECTOR = SilverPeakOrchestratorConnector
