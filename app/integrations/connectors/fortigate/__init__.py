"""Fortinet FortiGate (FortiOS REST API) connector — PREVIEW.

Built from the public FortiOS REST API documentation and published sample responses, not yet
validated against a live FortiGate. Read-only. One connection = one FortiGate (or HA cluster);
fleets managed by FortiManager would be a separate ``fortimanager`` connector.

Authentication: REST API administrator token sent as ``Authorization: Bearer <token>``
(System › Administrators › REST API Admin; FortiOS 6.4+ accepts the header, so the token never
appears in a URL). Optional ``vdom`` query parameter.

Endpoints (https://docs.fortinet.com/document/fortigate/latest/administration-guide — "REST API";
full reference on the Fortinet Developer Network):

* ``GET /api/v2/monitor/system/status``         — hostname, model_name/model_number, serial,
  version, build                                                    → INVENTORY, test connection
* ``GET /api/v2/monitor/system/ha-peer``        — HA members: serial_no, hostname, priority, primary
* ``GET /api/v2/monitor/system/interface``      — {name: {mac, ip, mask, link, speed, duplex,
  rx_errors, tx_errors}}                                                         → INTERFACES
* ``GET /api/v2/cmdb/system/interface``         — configured interfaces: type, status, vlanid,
  interface (parent), member, alias, description (optional; merged when readable)
* ``GET /api/v2/monitor/network/lldp/neighbors`` — chassis_id, port (local), port_id, port_desc,
  system_name, system_desc, addresses[]                                          → NEIGHBORS
* ``GET /api/v2/monitor/network/arp``           — ip, mac, interface, age        → ARP_TABLE
* ``GET /api/v2/monitor/router/ipv4``           — ip_mask, gateway, interface, type, vrf → ROUTES
* ``GET /api/v2/monitor/vpn/ipsec``             — name, rgwy, proxyid[] (phase-2 status) → TUNNELS
"""

from __future__ import annotations

import ipaddress
from typing import Any
from urllib.parse import urlparse

from app.integrations.base import IntegrationError
from app.integrations.connectors.sdk import (
    Connector,
    ConnectorManifest,
    ConnectorSetup,
    HttpJsonClient,
    SettingField,
    SetupIssue,
    SetupStep,
    device_key as make_device_key,
    site_key as make_site_key,
)
from app.integrations.contracts import ARP_TABLE, INTERFACES, INVENTORY, NEIGHBORS, ROUTES, TUNNELS
from app.integrations.domain import Device, Interface, L3Entry, Neighbor, Route, Site, Tunnel, normalize_mac, stable_key

CONNECTOR_ID = "fortigate"

SETUP = ConnectorSetup(
    summary="One FortiGate (or HA cluster): system, HA, interfaces, LLDP neighbors, ARP, routes and IPsec tunnels.",
    prerequisites=(
        "FortiOS 6.4 or later (accepts the token as an Authorization header)",
        "A FortiGate super_admin who may create admin profiles and REST API administrators",
        "HTTPS administrative access on an interface this PC can reach, and this PC's IP address",
        "Only if the FortiGate uses an internal certificate: your company root CA as a PEM file",
    ),
    steps=(
        SetupStep(
            "Create a read-only admin profile",
            "System › Admin Profiles › Create New. Name: nodewatch-readonly. Set every permission area to Read "
            "(at least System, Network and VPN) and none to Read/Write.",
            copy="nodewatch-readonly",
        ),
        SetupStep(
            "Create a REST API administrator",
            "System › Administrators › Create New › REST API Admin. Username: nodewatch-ro. Administrator "
            "profile: nodewatch-readonly. Trusted Hosts: this PC's address (for example 10.0.0.25/32). On a "
            "multi-VDOM unit pick the VDOM NodeWatch should read.",
            link="https://docs.fortinet.com/document/fortigate/latest/administration-guide/940602/using-apis",
            copy="nodewatch-ro",
        ),
        SetupStep(
            "Copy the token",
            "FortiOS shows the new API token once when you click OK. Copy it and paste it in the next step; "
            "NodeWatch stores it in the secure credential store (Windows Credential Manager or the macOS Keychain).",
        ),
        SetupStep(
            "Check HTTPS access",
            "Network › Interfaces › (the interface NodeWatch connects to) › Administrative Access: HTTPS on. "
            "Include the admin port in the URL if it is not 443.",
        ),
    ),
    permissions="A REST API administrator with a custom admin profile set to Read (never Read/Write) for the "
    "areas NodeWatch reads — System, Network (including routing) and VPN — and Trusted Hosts limited to this "
    "PC. The token is sent as an Authorization: Bearer header, never in a URL.",
    verify="Reads system status (hostname, model, serial, FortiOS version), then HA peers, interfaces and "
    "their settings, LLDP neighbors, ARP, IPv4 routes and IPsec tunnels — one GET each. Nothing is changed.",
    troubleshooting=(
        SetupIssue(
            "Authenticated: fail (HTTP 401)",
            "The token is wrong or was regenerated, or this PC is not in the administrator's Trusted Hosts.",
        ),
        SetupIssue(
            "One capability refused (HTTP 403)",
            "The admin profile has no Read access for that area. Set it to Read and test again.",
        ),
        SetupIssue(
            "Reachable: fail",
            "HTTPS is not allowed on that interface, the admin port is different (add :port to the URL), or a "
            "firewall policy blocks this PC.",
        ),
        SetupIssue(
            "Empty results on a multi-VDOM FortiGate",
            "Enter the VDOM in the form; without it FortiOS answers for the token's default VDOM.",
        ),
        SetupIssue(
            "TLS certificate: fail",
            "The FortiGate uses its factory or an internal certificate. Install a certificate from your CA and set "
            "'Private CA certificate', rather than turning verification off.",
        ),
    ),
    data_you_get=(
        "The FortiGate: model, serial, FortiOS version, HA members",
        "Interfaces with state, speed, addresses, VLANs and aggregate members",
        "LLDP neighbors (links to switches in Topology)",
        "ARP and IPv4 routing tables (path trace)",
        "IPsec tunnels with phase-2 state",
    ),
    estimated_minutes=10,
    uncertain=(
        "Which admin-profile area each FortiOS monitor endpoint checks varies by release; Read on System, Network "
        "and VPN covers what NodeWatch reads. The Test shows any area that is still missing.",
    ),
)

MANIFEST = ConnectorManifest(
    connector_id=CONNECTOR_ID,
    vendor="Fortinet",
    product="FortiGate",
    category="firewall",
    capabilities=(INVENTORY, INTERFACES, NEIGHBORS, ARP_TABLE, ROUTES, TUNNELS),
    settings=(
        SettingField(
            "base_url",
            "FortiGate URL",
            "url",
            required=True,
            placeholder="https://fw1.example.com:443",
            help="Management address of the FortiGate (include the admin port if it is not 443). HTTPS only.",
            origin_only=True,
        ),
        SettingField(
            "api_token",
            "REST API token",
            "secret",
            required=True,
            help="Token of a REST API administrator with a read-only profile. Stored in the secure credential store (Windows Credential Manager or the macOS Keychain).",
        ),
        SettingField(
            "vdom", "VDOM (optional)", "text", placeholder="root", help="Leave blank for the token's default VDOM."
        ),
        SettingField(
            "site_name",
            "Site name (optional)",
            "text",
            placeholder="Main office",
            help="Groups this firewall with a site in NodeWatch.",
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
            help="PEM file that signed the FortiGate certificate, instead of turning verification off.",
        ),
        SettingField("timeout", "Request timeout (seconds)", "number", default=20),
    ),
    description="FortiGate system, interfaces, LLDP neighbors, ARP, routes and IPsec tunnels.",
    docs_url="https://docs.fortinet.com/document/fortigate/latest/administration-guide/940602/using-apis",
    maturity="preview",
    setup=SETUP,
)

INTERFACE_KIND = {
    "physical": "physical",
    "aggregate": "lag",
    "redundant": "lag",
    "vlan": "vlan",
    "loopback": "loopback",
    "tunnel": "tunnel",
    "vdom-link": "logical",
    "hard-switch": "logical",
    "switch": "logical",
}
# FortiOS interface role → Interface.role (a DMZ is a network of the site, like a LAN)
_ROLE = {"lan": "lan", "dmz": "lan", "wan": "wan"}
ROUTE_PROTOCOL = {
    "connect": "connected",
    "static": "static",
    "bgp": "bgp",
    "ospf": "ospf",
    "rip": "rip",
    "isis": "isis",
}


def _text(value: Any) -> str:
    return "" if value is None else str(value).strip()


def _num(value: Any) -> float | None:
    try:
        return float(value) if value not in (None, "") else None
    except (TypeError, ValueError):
        return None


def _mac(value: Any) -> str:
    mac = normalize_mac(value)
    return "" if mac == "000000000000" else mac


def _ip_literal(host: str) -> str:
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        return ""


def _cidr(ip: Any, mask: Any) -> str:
    ip_text = _text(ip)
    if not ip_text or ip_text in {"0.0.0.0", "::"}:
        return ""
    mask_text = _text(mask)
    if " " in ip_text:  # cmdb form "10.0.0.1 255.255.255.0"
        ip_text, mask_text = ip_text.split(" ", 1)
        if ip_text == "0.0.0.0":
            return ""
    try:
        prefix = int(mask_text) if mask_text.isdigit() else ipaddress.IPv4Network(f"0.0.0.0/{mask_text}").prefixlen
        return str(ipaddress.ip_interface(f"{ip_text}/{prefix}"))
    except ValueError:
        return ip_text


def _results(payload: Any) -> Any:
    """FortiOS wraps answers as {"status": "success", "results": ...}; a vdom=* call returns a list of those."""
    if isinstance(payload, dict):
        if _text(payload.get("status")).lower() == "error":
            raise IntegrationError(
                f"FortiGate: request failed ({_text(payload.get('error') or payload.get('http_status'))})",
                status_code=payload["http_status"] if isinstance(payload.get("http_status"), int) else None,
            )
        return payload.get("results")
    return None


def ipsec_state(row: dict) -> str:
    phase2 = [p for p in row.get("proxyid") or [] if isinstance(p, dict)]
    if not phase2:
        return "unknown"
    up = sum(1 for p in phase2 if _text(p.get("status")).lower() == "up")
    if up == len(phase2):
        return "up"
    return "down" if up == 0 else "degraded"


class FortiGateConnector(Connector):
    manifest = MANIFEST

    def __init__(self) -> None:
        super().__init__()
        self._status: dict[str, Any] | None = None

    def reset_state(self) -> None:
        super().reset_state()
        self._status = None

    @property
    def configured(self) -> bool:
        s = self.settings()
        return bool(s.get("base_url") and s.get("api_token"))

    def build_http(self) -> HttpJsonClient:
        s = self.settings()
        token = self.secret("api_token")
        if not s.get("base_url") or not token:
            raise IntegrationError("FortiGate URL and API token are required", code="NOT_CONFIGURED")
        return HttpJsonClient(
            _text(s.get("base_url")),
            headers={"Authorization": f"Bearer {token}"},
            product=MANIFEST.product,
            verify_tls=bool(s.get("verify_tls", True)),
            ca_file=_text(s.get("ca_file")),
            timeout=float(s.get("timeout") or 20),
            secrets=(token,),
        )

    def _get(self, path: str, what: str) -> Any:
        vdom = _text(self.settings().get("vdom"))
        params = {"vdom": vdom} if vdom else {}
        return self.call(lambda: _results(self.http().get(path, **params)), what)

    # ---- identity -------------------------------------------------------------------------------
    def _system(self) -> dict[str, Any]:
        vdom = _text(self.settings().get("vdom"))
        params = {"vdom": vdom} if vdom else {}
        payload = self.call(lambda: self.http().get("/api/v2/monitor/system/status", **params), "read system status")
        results = _results(payload) or {}
        status = {
            "serial": _text(payload.get("serial")) if isinstance(payload, dict) else "",
            "version": _text(payload.get("version")) if isinstance(payload, dict) else "",
            "build": _text(payload.get("build")) if isinstance(payload, dict) else "",
            "hostname": _text(results.get("hostname")) if isinstance(results, dict) else "",
            "model_name": _text(results.get("model_name")) if isinstance(results, dict) else "",
            "model_number": _text(results.get("model_number")) if isinstance(results, dict) else "",
            "model": _text(results.get("model")) if isinstance(results, dict) else "",
        }
        self._status = status
        return status

    def _device_key(self) -> str:
        status = self._status or self._system()
        return make_device_key(serial=status["serial"], source=CONNECTOR_ID, native_id=self.settings().get("base_url"))

    def _site(self) -> tuple[str, str]:
        name = _text(self.settings().get("site_name"))
        return (make_site_key(CONNECTOR_ID, name), name) if name else ("", "")

    def _mine(self, device_key: str | None) -> bool:
        return not device_key or device_key == self._device_key()

    # ---- INVENTORY ------------------------------------------------------------------------------
    def list_sites(self) -> list[Site]:
        key, name = self._site()
        return [Site(key=key, source=CONNECTOR_ID, name=name, native_id=name)] if key else []

    def list_devices(self, site_key: str | None = None) -> list[Device]:
        skey, sname = self._site()
        if site_key and site_key != skey:
            return []
        status = self._system()
        members: list[dict[str, Any]] = []
        try:
            peers = self._get("/api/v2/monitor/system/ha-peer", "read HA peers") or []
        except IntegrationError:
            peers = []  # standalone units / restricted profiles: HA is optional detail
        if isinstance(peers, list) and len(peers) > 1:
            members = [
                {
                    "serial": _text(p.get("serial_no")),
                    "name": _text(p.get("hostname")),
                    "role": "primary" if (p.get("primary") or p.get("master")) else "secondary",
                    "priority": p.get("priority"),
                }
                for p in peers
                if isinstance(p, dict)
            ]
        base = _text(self.settings().get("base_url"))
        version = status["version"] + (f" build {status['build']}" if status["build"] else "")
        model = " ".join(x for x in (status["model_name"], status["model_number"]) if x) or status["model"]
        return [
            Device(
                key=self._device_key(),
                source=CONNECTOR_ID,
                name=status["hostname"] or urlparse(base).hostname or "FortiGate",
                role="firewall",
                native_id=status["serial"],
                site_key=skey,
                site_name=sname,
                vendor_name="Fortinet",
                model=model,
                serial=status["serial"],
                mgmt_ip=_ip_literal(urlparse(base).hostname or ""),
                os_version=version.strip(),
                status="up",  # it answered the API just now
                members=members,
                console_url=base,
                vendor={"vdom": _text(self.settings().get("vdom"))} if self.settings().get("vdom") else {},
            )
        ]

    # ---- INTERFACES -----------------------------------------------------------------------------
    def list_interfaces(self, device_key: str) -> list[Interface]:
        if not self._mine(device_key):
            return []
        dkey = self._device_key()
        live = self._get("/api/v2/monitor/system/interface", "read interfaces") or {}
        try:
            config = self._get("/api/v2/cmdb/system/interface", "read interface configuration") or []
        except IntegrationError:
            config = []  # monitor data alone is still useful
        if isinstance(live, list):  # some versions answer a list
            live = {_text(r.get("name")): r for r in live if isinstance(r, dict)}
        conf = {_text(c.get("name")): c for c in config if isinstance(c, dict) and c.get("name")}
        lag_parent: dict[str, str] = {}
        for name, c in conf.items():
            for m in c.get("member") or []:
                if isinstance(m, dict) and m.get("interface-name"):
                    lag_parent[_text(m["interface-name"])] = name
        out = []
        for name in sorted(set(live) | set(conf)):
            if not name:
                continue
            row = live.get(name) or {}
            c = conf.get(name) or {}
            ctype = _text(c.get("type")).lower()
            ips = [x for x in (_cidr(row.get("ip"), row.get("mask")) or _cidr(c.get("ip"), ""),) if x]
            vlan = c.get("vlanid") or row.get("vlanid")
            duplex = row.get("duplex")
            admin = _text(c.get("status")).lower()
            out.append(
                Interface(
                    key=stable_key(dkey, name),
                    source=CONNECTOR_ID,
                    device_key=dkey,
                    name=name,
                    kind=INTERFACE_KIND.get(ctype, "vlan" if vlan else "physical" if not c else "logical"),
                    admin_up=(admin == "up") if admin else None,
                    oper_up=bool(row["link"]) if row.get("link") is not None else None,
                    speed_mbps=_num(row.get("speed")),
                    duplex={1: "full", 0: "half"}.get(duplex, "")
                    if isinstance(duplex, int) and row.get("link")
                    else "",
                    mac=_mac(row.get("mac") or c.get("macaddr")),
                    ips=ips,
                    vlans=[int(vlan)] if isinstance(vlan, int) and vlan > 0 else [],
                    lag_parent=lag_parent.get(name, ""),
                    role=_ROLE.get(_text(c.get("role")).lower(), "mgmt" if ctype == "mgmt" else ""),
                    description=_text(c.get("description")) or _text(row.get("alias") or c.get("alias")),
                    rx_errors=int(row["rx_errors"]) if isinstance(row.get("rx_errors"), (int, float)) else None,
                    tx_errors=int(row["tx_errors"]) if isinstance(row.get("tx_errors"), (int, float)) else None,
                    vendor={
                        k: v
                        for k, v in {
                            "parent": _text(c.get("interface")),
                            "role": _text(c.get("role")),
                            "type": ctype,
                        }.items()
                        if v
                    },
                )
            )
        return out

    # ---- NEIGHBORS ------------------------------------------------------------------------------
    def list_neighbors(self, site_key: str | None = None) -> list[Neighbor]:
        skey, _ = self._site()
        if site_key and site_key != skey:
            return []
        dkey = self._device_key()
        rows = self._get("/api/v2/monitor/network/lldp/neighbors", "read LLDP neighbors") or []
        lag_of: dict[str, str] = {}
        try:
            for c in self._get("/api/v2/cmdb/system/interface", "read interface configuration") or []:
                for m in (c.get("member") or []) if isinstance(c, dict) else []:
                    if isinstance(m, dict) and m.get("interface-name"):
                        lag_of[_text(m["interface-name"])] = _text(c.get("name"))
        except IntegrationError:
            lag_of = {}
        out = []
        for r in rows if isinstance(rows, list) else []:
            if not isinstance(r, dict):
                continue
            ips = [
                _text(a.get("address"))
                for a in r.get("addresses") or []
                if isinstance(a, dict) and _text(a.get("type")).lower() in ("ipv4", "ipv6", "")
            ]
            caps = r.get("capabilities") or r.get("enabled_capabilities") or []
            local = _text(r.get("port_name") or r.get("interface") or r.get("port"))
            out.append(
                Neighbor(
                    source=CONNECTOR_ID,
                    device_key=dkey,
                    local_interface=local,
                    local_lag=lag_of.get(local, ""),
                    remote_name=_text(r.get("system_name")),
                    remote_interface=_text(r.get("port_id") or r.get("port_desc")),
                    remote_mac=_mac(r.get("chassis_id") or r.get("mac")),
                    remote_mgmt_ip=ips[0] if ips else "",
                    remote_description=_text(r.get("system_desc")),
                    remote_capabilities=[_text(c).lower() for c in caps if _text(c)] if isinstance(caps, list) else [],
                    protocol="lldp",
                )
            )
        return out

    # ---- ARP ------------------------------------------------------------------------------------
    def list_arp(self, device_key: str | None = None) -> list[L3Entry]:
        if not self._mine(device_key):
            return []
        dkey = self._device_key()
        rows = self._get("/api/v2/monitor/network/arp", "read ARP table") or []
        return [
            L3Entry(
                source=CONNECTOR_ID,
                device_key=dkey,
                ip=_text(r.get("ip")),
                mac=_mac(r.get("mac")),
                interface=_text(r.get("interface")),
            )
            for r in rows
            if isinstance(r, dict) and _text(r.get("ip")) and _mac(r.get("mac"))  # skip incomplete entries
        ]

    # ---- ROUTES ---------------------------------------------------------------------------------
    def list_routes(self, device_key: str) -> list[Route]:
        if not self._mine(device_key):
            return []
        dkey = self._device_key()
        rows = self._get("/api/v2/monitor/router/ipv4", "read routing table") or []
        out = []
        for r in rows if isinstance(rows, list) else []:
            if not isinstance(r, dict) or not _text(r.get("ip_mask")):
                continue
            gw = _text(r.get("gateway"))
            rtype = _text(r.get("type")).lower()
            out.append(
                Route(
                    source=CONNECTOR_ID,
                    device_key=dkey,
                    prefix=_text(r.get("ip_mask")),
                    next_hop="" if gw in ("", "0.0.0.0") else gw,
                    interface=_text(r.get("interface")),
                    protocol=ROUTE_PROTOCOL.get(rtype, rtype),
                    vrf=_text(r.get("vrf")) if r.get("vrf") not in (None, 0, "0") else "",
                )
            )
        return out

    # ---- TUNNELS --------------------------------------------------------------------------------
    def list_tunnels(self, site_key: str | None = None) -> list[Tunnel]:
        skey, _ = self._site()
        if site_key and site_key != skey:
            return []
        dkey = self._device_key()
        rows = self._get("/api/v2/monitor/vpn/ipsec", "read IPsec tunnels") or []
        out = []
        for r in rows if isinstance(rows, list) else []:
            if not isinstance(r, dict) or not _text(r.get("name")):
                continue
            phase2 = [p for p in r.get("proxyid") or [] if isinstance(p, dict)]
            out.append(
                Tunnel(
                    key=stable_key(CONNECTOR_ID, dkey, r["name"]),
                    source=CONNECTOR_ID,
                    device_key=dkey,
                    name=_text(r["name"]),
                    kind="ipsec",
                    local_ip=_text(r.get("lgwy")),
                    remote_ip="" if _text(r.get("rgwy")) in ("", "0.0.0.0") else _text(r.get("rgwy")),
                    remote_name=_text(r.get("comments")),
                    state=ipsec_state(r),
                    vendor={
                        "phase2_up": sum(1 for p in phase2 if _text(p.get("status")).lower() == "up"),
                        "phase2_total": len(phase2),
                        "type": _text(r.get("type")),
                    },
                )
            )
        return out

    # ---- capability probe (Settings › Connections › Test; see probe.py) ------------------------------
    def probe_plan(self) -> list[Any]:
        from app.integrations.connectors.fortigate.probe import plan

        return plan(self)

    # ---- connection test --------------------------------------------------------------------------
    def test_connection(self) -> dict[str, Any]:
        if not self.configured:
            return {
                "ok": False,
                "provider": CONNECTOR_ID,
                "configured": False,
                "detail": "Enter the FortiGate URL and API token.",
            }
        status = self._system()
        detail = " · ".join(
            x for x in (status["hostname"], f"FortiOS {status['version']}" if status["version"] else "") if x
        )
        return {"ok": True, "provider": CONNECTOR_ID, "configured": True, "detail": detail or "FortiGate answered"}


CONNECTOR = FortiGateConnector
