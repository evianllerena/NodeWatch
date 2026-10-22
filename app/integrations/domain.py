"""Vendor-neutral NodeWatch domain model (v0.10.16).

Every connector — Juniper Mist, Palo Alto, Silver Peak, Fortinet, Cisco … — translates its own API
into these records. Feature modules (Command Center, Port Toolkit, Topology, …) only ever see these
types, never a vendor payload, so adding a vendor never changes a feature.

Rules for every record:
* ``source`` names the connector that produced it (``"mist"``, ``"fortigate"`` …).
* ``key`` is stable for the same real-world thing across refreshes (used for dismiss/snooze, diffing
  and correlation). Build it with :func:`stable_key` from vendor-independent identifiers when possible
  (MAC, serial), so two vendors describing the same box produce records that correlate.
* Timestamps are epoch seconds (float, UTC). Unknown values are ``None`` / ``""`` — never invented.
* ``vendor`` holds a small dict of extra vendor fields worth showing (already human-safe, no secrets);
  raw payloads stay in the connector.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import asdict, dataclass, field
from typing import Any

SCHEMA_VERSION = 1

# --------------------------------------------------------------------------- vocabularies

DEVICE_ROLES = (
    "switch",  # L2/L3 access, distribution, core
    "router",
    "firewall",
    "sdwan_edge",  # Silver Peak EdgeConnect, FortiGate SD-WAN, Meraki MX, Mist WAN Edge …
    "wireless_ap",
    "wireless_controller",
    "load_balancer",
    "server",
    "endpoint",
    "cloud",  # a cloud/SaaS/internet node in a topology
    # v0.10.27: a cloud security edge run by a provider (mobile-user gateways, service connections,
    # remote-network gateways of a SASE / SSE service). ``Device.cloud_kind`` says which.
    "cloud_gateway",
    "unknown",
)
SEVERITIES = ("critical", "major", "warning", "info")
LINK_LAYERS = (
    "physical",  # cable seen by LLDP/CDP on both or one end
    "lag",  # aggregated bundle (ae, port-channel)
    "l2",  # shared VLAN / broadcast domain
    "l3",  # routed adjacency: same subnet, routing neighbor, next hop
    "overlay",  # tunnel: IPsec, SD-WAN, GRE, VXLAN
    "wireless",  # AP <-> client
    "ha",  # the two units of a high-availability pair (v0.10.27)
)
EVIDENCE_KINDS = ("lldp", "cdp", "mac_table", "arp", "routing", "tunnel", "config", "vendor_api", "inferred")

_MAC_CHARS = re.compile(r"[^0-9a-f]")


def normalize_mac(value: Any) -> str:
    """'AA:BB:CC:DD:EE:FF' / 'aabb.ccdd.eeff' → 'aabbccddeeff' ('' when not a MAC)."""
    text = _MAC_CHARS.sub("", str(value or "").lower())
    return text if len(text) == 12 else ""


def stable_key(*parts: Any) -> str:
    """Short stable id from identifying parts (order matters)."""
    joined = "|".join(str(p or "").strip().lower() for p in parts)
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()[:20]


class _Record:
    def to_dict(self) -> dict[str, Any]:
        return asdict(self)  # type: ignore[call-overload]


# --------------------------------------------------------------------------- inventory


@dataclass
class Site(_Record):
    key: str
    source: str
    name: str
    native_id: str = ""
    address: str = ""
    timezone: str = ""
    # v0.10.24: what this "site" really is. Only "site" (a place) gets its own map; containers
    # (SCM folders, Meraki organizations, Aruba Central groups, FortiManager ADOMs …) and remote
    # networks are kept as groupings. parent_key links buildings/floors/areas to their parent.
    kind: str = "site"  # site | container | remote_network | building | floor | area
    parent_key: str = ""
    vendor: dict[str, Any] = field(default_factory=dict)


SITE_KINDS = ("site", "container", "remote_network", "building", "floor", "area", "cloud")
# v0.10.27 ``Device.cloud_kind`` of a "cloud_gateway": where remote users connect, the tunnel to a data
# center, or the gateway a branch's tunnel ends on.
CLOUD_KINDS = ("mobile_users", "service_connection", "remote_network", "")


@dataclass
class Device(_Record):
    key: str
    source: str
    name: str
    role: str = "unknown"
    native_id: str = ""
    site_key: str = ""
    site_name: str = ""
    vendor_name: str = ""  # "Juniper", "Palo Alto Networks", "Fortinet"
    model: str = ""
    serial: str = ""
    mac: str = ""  # normalized base MAC
    mgmt_ip: str = ""
    os_version: str = ""
    status: str = "unknown"  # up | down | degraded | unknown
    last_seen: float | None = None
    uptime_s: float | None = None
    members: list[dict[str, Any]] = field(default_factory=list)  # stack/VC/HA members
    # Live health (v0.10.17, optional): filled by connectors that offer HEALTH.
    cpu_pct: float | None = None
    memory_pct: float | None = None
    sessions: int | None = None  # firewall/SD-WAN active sessions
    ha_state: str = ""  # active | passive | standalone | degraded …
    console_url: str = ""  # deep link into the vendor's own UI
    # v0.10.24 (shared code reads these; vendors fill what they know):
    aliases: list[str] = field(default_factory=list)  # other names: display name, host name, DNS name
    labels: list[str] = field(default_factory=list)  # tags / labels from the management system
    alias_macs: list[str] = field(default_factory=list)  # chassis / virtual-chassis / HA MACs (normalized)
    network_tier: str = ""  # core | distribution | access | "" (when the vendor knows the device's tier)
    floor_key: str = ""  # vendor floor / map id (stable)
    floor_name: str = ""  # human floor name when known
    clients: int | None = None  # connected clients right now
    sessions_max: int | None = None  # firewall/SD-WAN session capacity
    poe_budget_w: float | None = None
    poe_used_w: float | None = None
    # v0.10.25 placement evidence (vendor-neutral; topology uses it to put a device on its site):
    addresses: list[str] = field(default_factory=list)  # other IPs this device uses (NAT / untrust / inside)
    lan_prefixes: list[str] = field(default_factory=list)  # networks seen behind it (CIDR, e.g. "10.40.1.0/24")
    # v0.10.27: cloud security edges (role "cloud_gateway") — see CLOUD_KINDS
    cloud_kind: str = ""
    # v0.10.27: addresses of other boxes this device saw on its own ports (traffic logs, ARP …), bounded:
    # [{"ip": "10.0.51.24", "interface": "ethernet1/1", "zone": "untrust-sdwan", "dir": "in" | "out"}]
    observed_peers: list[dict[str, Any]] = field(default_factory=list)
    vendor: dict[str, Any] = field(default_factory=dict)


NETWORK_TIERS = ("core", "distribution", "access", "")
INTERFACE_ROLES = ("lan", "wan", "mgmt", "")


@dataclass
class Interface(_Record):
    key: str
    source: str
    device_key: str
    name: str  # vendor name: ge-0/0/1, ethernet1/1, port1, Gi1/0/1
    kind: str = "physical"  # physical | lag | vlan | loopback | tunnel | mgmt | logical
    admin_up: bool | None = None
    oper_up: bool | None = None
    speed_mbps: float | None = None
    duplex: str = ""
    mac: str = ""
    ips: list[str] = field(default_factory=list)  # CIDR strings
    vlans: list[int] = field(default_factory=list)
    native_vlan: int | None = None
    lag_parent: str = ""
    description: str = ""
    zone: str = ""  # security zone (firewalls)
    # v0.10.26: which side of the device the port faces, when the system knows it — "lan" (site networks),
    # "wan" (ISP / MPLS / LTE / transport), "mgmt" (out-of-band management) or "" (unknown). Topology never
    # counts a "wan" / "mgmt" port's network as the site's LAN.
    role: str = ""
    poe_watts: float | None = None
    rx_errors: int | None = None
    tx_errors: int | None = None
    # Live rates (v0.10.17, optional)
    rx_bps: float | None = None
    tx_bps: float | None = None
    utilization_pct: float | None = None  # max(rx, tx) / speed
    flaps_24h: int | None = None
    rx_pkts: int | None = None  # v0.10.24
    tx_pkts: int | None = None
    last_flapped: float | None = None  # epoch seconds of the last link change
    vrf: str = ""  # routing instance / virtual router the interface belongs to
    # WAN port quality (v0.10.24) when the device measures it on the port itself
    latency_ms: float | None = None
    loss_pct: float | None = None
    jitter_ms: float | None = None
    vendor: dict[str, Any] = field(default_factory=dict)


# --------------------------------------------------------------------------- health


@dataclass
class Alert(_Record):
    """An open condition someone may need to act on (alarm, failing check, device down)."""

    key: str  # stable across refreshes: same condition on same thing → same key
    source: str
    type: str  # vendor type code, e.g. SW_DISCONNECTED, fortigate.ha.out_of_sync
    category: str  # vendor-neutral bucket: connectivity, hardware, switching, routing, security …
    severity: str
    title: str
    detail: str = ""
    site_key: str = ""
    site_name: str = ""
    device_key: str = ""
    device_name: str = ""
    device_role: str = ""
    interface: str = ""
    first_seen: float | None = None
    last_seen: float | None = None
    count: int = 1
    acknowledged: bool = False
    acknowledged_by: str = ""
    resolved: bool = False
    native_id: str = ""  # vendor alarm id (for acknowledge in the vendor system)
    console_url: str = ""
    facts: list[dict[str, Any]] = field(default_factory=list)  # [{label, value, kind}] readable evidence
    vendor: dict[str, Any] = field(default_factory=dict)


@dataclass
class Event(_Record):
    key: str
    source: str
    type: str
    timestamp: float
    severity: str = "info"
    text: str = ""
    site_key: str = ""
    device_key: str = ""
    device_name: str = ""
    interface: str = ""
    vendor: dict[str, Any] = field(default_factory=dict)


# --------------------------------------------------------------------------- topology


@dataclass
class Neighbor(_Record):
    """One side's view of a directly connected neighbor (LLDP/CDP, or a vendor's own peer table)."""

    source: str
    device_key: str
    local_interface: str
    remote_name: str = ""
    remote_interface: str = ""
    remote_mac: str = ""  # chassis MAC when advertised
    remote_mgmt_ip: str = ""
    remote_description: str = ""  # system description (often contains vendor + model)
    remote_capabilities: list[str] = field(default_factory=list)  # bridge, router, wlan-ap …
    protocol: str = "lldp"
    local_lag: str = ""  # aggregate the local port belongs to (ae0, Port-channel1) when known
    local_up: bool | None = None  # local port oper state when the source reports it
    speed_mbps: float | None = None  # negotiated speed of the local port when known


@dataclass
class L2Entry(_Record):
    """MAC table row: MAC learned on a switch interface/VLAN."""

    source: str
    device_key: str
    mac: str
    interface: str
    vlan: int | None = None


@dataclass
class L3Entry(_Record):
    """ARP / neighbor-discovery row: IP ↔ MAC on a routed interface."""

    source: str
    device_key: str
    ip: str
    mac: str
    interface: str = ""


@dataclass
class Route(_Record):
    source: str
    device_key: str
    prefix: str  # CIDR
    next_hop: str = ""
    interface: str = ""
    protocol: str = ""  # connected | static | bgp | ospf | sdwan …
    vrf: str = ""
    # v0.10.17 (optional): the peer device a route was learned from when the vendor knows it
    # (SD-WAN overlay routes have no IP next hop, only a peer appliance).
    remote_device_key: str = ""
    remote_name: str = ""
    # v0.10.24: True when the prefix is a LAN of the device itself (connected / local interface / a
    # site subnet it owns), False when learned or pointing at a remote network, None when unknown.
    # Topology uses only local routes to learn which subnets belong to which site.
    local: bool | None = None

    def __post_init__(self) -> None:
        if self.local is None and str(self.protocol or "").lower() in ("connected", "local", "direct", "interface"):
            self.local = True


@dataclass
class Tunnel(_Record):
    """Overlay path between two devices (IPsec, SD-WAN, GRE, VXLAN)."""

    key: str
    source: str
    device_key: str
    name: str
    kind: str = "ipsec"  # ipsec | sdwan | gre | vxlan | other
    local_ip: str = ""
    remote_ip: str = ""
    remote_device_key: str = ""  # when the vendor knows the peer appliance
    remote_name: str = ""
    state: str = "unknown"  # up | down | degraded | unknown
    latency_ms: float | None = None
    loss_pct: float | None = None
    # v0.10.24: overlay = site-to-site path users' traffic takes; underlay = transport tunnel on one
    # circuit (EdgeConnect underlay, Viptela TLOC BFD, Meraki uplink VPN); passthrough = to the internet.
    layer: str = ""  # overlay | underlay | passthrough | "" (unknown)
    jitter_ms: float | None = None
    circuit_key: str = ""  # Circuit.key this tunnel rides on, when known
    vendor: dict[str, Any] = field(default_factory=dict)


TUNNEL_LAYERS = ("overlay", "underlay", "passthrough", "")


@dataclass
class Circuit(_Record):
    """A WAN circuit (v0.10.24): one internet / MPLS / LTE / private line on one device's WAN port.

    Vendor-neutral: EdgeConnect WAN interfaces, Meraki MX uplinks, FortiGate SD-WAN members, Mist WAN
    Edge / SRX WAN ports, Cisco SD-WAN TLOCs and Versa/Prisma SD-WAN circuits all map onto it. Keep the
    provider's own words in ``label`` (the WAN label / transport colour) and ``carrier`` (ISP name or
    the circuit comment); figures the vendor does not offer stay ``None``.
    """

    key: str
    source: str
    device_key: str  # the device the circuit terminates on (same key the INVENTORY record uses)
    interface: str  # port / uplink name on that device
    device_name: str = ""
    site_key: str = ""  # the connector's own site key of that device ("" when unknown)
    label: str = ""  # WAN label / transport (INET1, MPLS, LTE, biz-internet …)
    carrier: str = ""  # ISP / provider or the circuit's comment
    kind: str = "unknown"  # internet | mpls | lte | private | unknown
    public_ip: str = ""
    ip: str = ""
    prefix_len: int | None = None
    gateway: str = ""
    dhcp: bool | None = None
    behind_nat: bool | None = None
    speed_mbps: float | None = None  # negotiated port speed
    bandwidth_down_kbps: int | None = None  # configured / contracted
    bandwidth_up_kbps: int | None = None
    admin_up: bool | None = None
    state: str = "unknown"  # up | down | degraded (link up, nothing flowing) | unknown
    tunnels_up: int | None = None  # overlay/underlay tunnels carried by this circuit
    tunnels_total: int | None = None
    latency_ms: float | None = None
    loss_pct: float | None = None
    jitter_ms: float | None = None
    rx_bps: float | None = None
    tx_bps: float | None = None
    comment: str = ""
    vendor: dict[str, Any] = field(default_factory=dict)


CIRCUIT_KINDS = ("internet", "mpls", "lte", "private", "unknown")


def circuit_kind(*texts: Any) -> str:
    """Best guess of the transport from a WAN label / carrier text (vendor-neutral words only).

    Whole words only: "Alternate" is not LTE and "Media" is not DIA.
    """
    t = " ".join(str(x or "") for x in texts).lower()
    raw = re.findall(r"[a-z0-9]+", t)
    words = set(raw) | {w.rstrip("0123456789") for w in raw if w[:1].isalpha()}  # INET1, MPLS2, LTE0
    phrase = " ".join(re.findall(r"[a-z0-9]+", t))
    if words & {"lte", "4g", "5g", "cell", "cellular"} or "wireless wan" in phrase:
        return "lte"
    if "mpls" in words:
        return "mpls"
    if words & {"inet", "internet", "broadband", "fiber", "fibre", "cable", "dsl", "dia", "isp"}:
        return "internet"
    if words & {"private", "metro", "p2p"} or "point to point" in phrase:
        return "private"
    return "unknown"


@dataclass
class Link(_Record):
    """An edge in the NodeWatch topology graph, built by the topology engine from the records above."""

    key: str
    a_device: str
    b_device: str
    layer: str
    a_interface: str = ""
    b_interface: str = ""
    state: str = "unknown"
    speed_mbps: float | None = None
    evidence: list[dict[str, Any]] = field(default_factory=list)  # [{kind, source, detail}]
    confidence: float = 1.0  # 1.0 seen from both ends … 0.4 inferred


def as_dicts(items: list[Any]) -> list[dict[str, Any]]:
    return [x.to_dict() if hasattr(x, "to_dict") else dict(x) for x in items]


@dataclass
class EndpointLocation(_Record):
    """Where an endpoint (IP and/or MAC) is attached: the switch port or AP that sees it (v0.10.17)."""

    source: str
    mac: str = ""
    ip: str = ""
    hostname: str = ""
    device_key: str = ""  # switch / AP / gateway that sees it
    device_name: str = ""
    interface: str = ""  # port, or SSID/radio for wireless
    vlan: int | None = None
    wireless: bool = False
    last_seen: float | None = None


@dataclass
class PolicyMatch(_Record):
    """Answer to "would this flow be allowed?" from a firewall (v0.10.17)."""

    source: str
    device_key: str
    rule: str = ""  # matching rule name ('' when none)
    action: str = ""  # allow | deny | drop | reset | unknown
    from_zone: str = ""
    to_zone: str = ""
    nat: str = ""
    detail: str = ""
    vendor: dict[str, Any] = field(default_factory=dict)


# --------------------------------------------------------------------------- audit (v0.10.24)


@dataclass
class Actor(_Record):
    """Who can make changes in a management system: a person, an API token or the system itself.

    Vendors translate their own role model into readable ``roles`` rows, e.g.
    ``{"role": "Network admin (can make changes)", "scope": "Site Bird Road"}``.
    """

    key: str
    source: str
    kind: str = "unknown"  # person | api_token | system | unknown
    name: str = ""
    email: str = ""
    roles: list[dict[str, str]] = field(default_factory=list)  # [{"role": ..., "scope": ...}]
    two_factor: bool | None = None
    last_login: float | None = None
    last_used: float | None = None  # API tokens
    created_by: str = ""  # API tokens
    vendor: dict[str, Any] = field(default_factory=dict)


ACTOR_KINDS = ("person", "api_token", "system", "unknown")


@dataclass
class AuditEntry(_Record):
    """One change (or sign-in) recorded by a management system's audit log."""

    key: str
    source: str
    timestamp: float
    message: str = ""
    actor_key: str = ""  # Actor.key when known
    actor_name: str = ""
    actor_email: str = ""
    src_ip: str = ""
    user_agent: str = ""
    site_key: str = ""
    site_name: str = ""
    device_keys: list[str] = field(default_factory=list)
    object_type: str = ""  # device | site | wlan | policy | template | admin | …
    object_name: str = ""
    action: str = "other"  # create | update | delete | login | other
    action_label: str = ""  # the source's own readable verb ("Accessed", "Upgraded", "Rebooted") when finer than ``action``
    changes: list[dict[str, Any]] = field(default_factory=list)  # [{"field", "before", "after"}]
    vendor: dict[str, Any] = field(default_factory=dict)


AUDIT_ACTIONS = ("create", "update", "delete", "login", "other")


# --------------------------------------------------------------------------- security operations (v0.10.30)
#
# The Security Operations Center reads only these records. A connector translates its own threat, URL, DNS,
# malware, IPS, wireless-intrusion or EDR vocabulary into them; the SOC never sees a vendor field name. See
# docs/architecture/SECURITY_DATA_PLANE.md.

SECURITY_EVENT_KINDS = (
    "exploit",  # an attempt to use a software vulnerability (IPS / vulnerability protection)
    "malware",  # a malicious file or a sandbox verdict
    "command_control",  # an inside host calling a known attacker (spyware, C2, beaconing, bad DNS)
    "reconnaissance",  # scans, sweeps, probing
    "flood",  # volumetric / protocol floods, packet-based attacks
    "web",  # a malicious or blocked web destination (URL filtering, phishing)
    "data_loss",  # sensitive data leaving, blocked file transfers
    "credential",  # brute force, credential theft, authentication abuse
    "wireless",  # rogue access points, honeypot SSIDs, wireless intrusion
    "policy",  # traffic a security policy refused that matters to security
    "other",
)
SECURITY_EVENT_KIND_LABELS = {
    "exploit": "Exploit attempt",
    "malware": "Malware",
    "command_control": "Callout to attacker",
    "reconnaissance": "Scanning / probing",
    "flood": "Flood",
    "web": "Malicious web",
    "data_loss": "Data leaving",
    "credential": "Credential attack",
    "wireless": "Wireless intrusion",
    "policy": "Policy refusal",
    "other": "Other",
}
# What the security control did with it. "allowed" = it went through and nothing stopped it; "alerted" = the
# control saw it and only reported it (also went through); "contained" = redirected / quarantined / sinkholed.
SECURITY_OUTCOMES = ("blocked", "contained", "alerted", "allowed", "unknown")
# Relative to the organisation's own networks (RFC 1918 / CGNAT / ULA and the networks NodeWatch learned).
SECURITY_DIRECTIONS = ("inbound", "outbound", "internal", "unknown")


@dataclass
class SecurityEvent(_Record):
    """One security detection: something a firewall, IPS, sandbox, DNS filter, wireless IDS or EDR saw.

    ``name`` keeps the vendor's own words for the threat (signature or verdict name); ``kind``, ``severity``,
    ``outcome`` and ``direction`` are NodeWatch vocabulary so every vendor's events count the same way.
    Countries are ISO 3166-1 alpha-2 codes ("US", "CN"); "" when private or unknown.
    """

    key: str  # stable for the same detection (log row) across reads
    source: str
    timestamp: float
    kind: str = "other"  # SECURITY_EVENT_KINDS
    severity: str = "info"  # SEVERITIES
    outcome: str = "unknown"  # SECURITY_OUTCOMES
    direction: str = "unknown"  # SECURITY_DIRECTIONS
    name: str = ""  # threat / signature / verdict name in the vendor's words
    signature_id: str = ""
    cves: list[str] = field(default_factory=list)  # ["CVE-2024-3400"]
    category: str = ""  # the vendor's own category text
    src_ip: str = ""
    src_port: int | None = None
    src_country: str = ""
    src_user: str = ""
    src_zone: str = ""
    dst_ip: str = ""
    dst_port: int | None = None
    dst_country: str = ""
    dst_host: str = ""  # domain / URL host when the detection names one
    dst_zone: str = ""
    application: str = ""
    protocol: str = ""
    sensor_key: str = ""  # Device.key of the box that saw it (firewall, AP, sensor) when known
    sensor_name: str = ""
    site_key: str = ""  # the connector's own site key when it knows one
    rule: str = ""  # policy rule that matched
    url: str = ""
    file_name: str = ""
    file_hash: str = ""  # sha256 when known
    count: int = 1  # repeats the source folded into this one record
    native_id: str = ""
    console_url: str = ""
    vendor: dict[str, Any] = field(default_factory=dict)


EXPOSURE_STATES = ("open", "mitigated", "accepted", "fixed")


@dataclass
class Exposure(_Record):
    """A known weakness on one asset: a CVE on a device's software, an end-of-support release, a risky setting.

    Sources: vulnerability scanners, endpoint / IoT security platforms, a vendor's own advisories matched to
    the devices it manages. ``asset_key`` is the INVENTORY ``Device.key`` when the asset is a managed device,
    else "" with ``asset_ip`` / ``asset_name`` describing it.
    """

    key: str
    source: str
    title: str
    severity: str = "warning"  # SEVERITIES
    cve: str = ""
    cvss: float | None = None
    exploited_in_wild: bool | None = None
    asset_key: str = ""
    asset_name: str = ""
    asset_ip: str = ""
    asset_kind: str = ""  # a DEVICE_ROLES value, or endpoint / iot / server
    site_key: str = ""
    product: str = ""
    version: str = ""
    fixed_in: str = ""
    state: str = "open"  # EXPOSURE_STATES
    first_seen: float | None = None
    last_seen: float | None = None
    detail: str = ""
    console_url: str = ""
    vendor: dict[str, Any] = field(default_factory=dict)


SECURITY_INCIDENT_STATES = ("new", "investigating", "contained", "resolved", "dismissed")


@dataclass
class SecurityIncident(_Record):
    """An incident a security platform already correlated (SIEM, XDR, a vendor's incident service).

    NodeWatch also builds its own incidents from :class:`SecurityEvent` records; those never come through a
    connector. Vendor incidents appear next to them, keyed by ``source``.
    """

    key: str
    source: str
    title: str
    severity: str = "warning"
    state: str = "new"  # SECURITY_INCIDENT_STATES
    opened: float | None = None
    updated: float | None = None
    category: str = ""
    assets: list[str] = field(default_factory=list)  # asset names / IPs as the source gives them
    detail: str = ""
    native_id: str = ""
    console_url: str = ""
    vendor: dict[str, Any] = field(default_factory=dict)
