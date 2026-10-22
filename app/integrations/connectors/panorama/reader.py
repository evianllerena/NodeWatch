"""Read capabilities of the Panorama connector (PAN-OS XML API, through Panorama).

Every firewall-level command is sent to Panorama with ``target=<firewall serial>`` so NodeWatch needs
one URL and one API key for the whole fleet. Commands (operational ``type=op``), with the source
that documents each one and the XML shape parsed:

* ``<show><devices><all/></devices></show>`` (Panorama) — every managed firewall: serial, hostname,
  ip-address, model, family, sw-version, connected, uptime, multi-vsys, vsys/entry, ha/state,
  ha/peer/serial. Documented in "Query a Firewall from Panorama (API)"
  (https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-panorama-api/pan-os-xml-api-use-cases/query-a-firewall-from-panorama-api);
  also what Palo Alto's own SDK parses (pan-os-python ``Panorama.refresh_devices`` /
  ``Firewall.refreshall_from_xml``).                                                    → INVENTORY
* ``<show><devicegroups/></show>`` (Panorama) — result/devicegroups/entry[@name]/devices/entry[@name=serial]
  with shared-policy-status (pan-os-python ``Panorama.refresh_devices``).    → sites, device groups, ALERTS
* ``<show><system><info/></system></show>`` (Panorama) — test connection (same doc page).
* ``<show><interface>all</interface></show>`` + target — result/ifnet/entry (name, zone, fwd, vsys,
  tag, ip, addr/member, addr6/member) and result/hw/entry (name, state, speed, duplex, mac)
  (PAN-OS CLI ``show interface all``; shape as parsed by NAPALM's PAN-OS driver
  ``get_interfaces_ip``).                                                         → INTERFACES (+ zones)
* ``<show><arp><entry name='all'/></arp></show>`` + target — result/entries/entry (ip, mac, interface,
  status, ttl) (NAPALM PAN-OS ``get_arp_table``).                                         → ARP_TABLE
* ``<show><routing><route/></routing></show>`` + target — result/entry (virtual-router, destination,
  nexthop, metric, flags "A S", interface) (NAPALM PAN-OS ``get_route_to``). On firewalls running the
  Advanced Routing Engine (PAN-OS 10.2+) the legacy command is rejected and NodeWatch falls back to
  ``<show><advanced-routing><route/></advanced-routing></show>``.                           → ROUTES
* ``<show><lldp><neighbors>all</neighbors></lldp></show>`` + target — result/entry[@name=local port]/
  neighbors/entry (chassis-id, port-id, port-description, system-name, system-description,
  enabled-capabilities, management-address/entry[@name]) (NAPALM PAN-OS ``get_lldp_neighbors``).
  Empty when LLDP is not enabled on the firewall's interfaces.                               → NEIGHBORS
* ``<show><vpn><flow/></vpn></show>`` + target — result/IPSec/entry (name, state active|init, localip,
  peerip, inner-if, outer-if). Panorama itself rejects ``show vpn`` (code 17 "not available to xmlapi
  client"), so it is always targeted at a firewall.                                          → TUNNELS
* ``<show><high-availability><state/></high-availability></show>`` + target — result/enabled,
  result/group/local-info/state, result/group/running-sync (pan-os-python
  ``show_highavailability_state`` / ``synchronize_config``), result/group/peer-info/state|conn-status.
                                                                                        → ALERTS, HEALTH
* ``<show><system><resources/></system></show>`` + target — ``top`` output: "%Cpu(s) … id",
  "MiB/KiB Mem : total, free, used" (pan-os-python ``Firewall.show_system_resources``).        → HEALTH
* ``<show><session><info/></session></show>`` + target — num-active, num-max.               → HEALTH
* ``<show><running><resource-monitor><minute><last>1</last></minute></resource-monitor></running></show>``
  + target — data-processor CPU load (optional; ignored when the shape differs).             → HEALTH
* ``<test><security-policy-match>…</security-policy-match></test>`` + target — source, destination,
  protocol required; from, to, destination-port, application optional; result/rules/entry[@name]
  with action, or the older "name; index: N" text form (pan-os-python ``test_security_policy_match``).
                                                                                     → POLICY_LOOKUP

Verified against documentation/SDK parsers: show devices all, show devicegroups, target=, show system
info, interface/arp/routing/lldp shapes, HA state paths, system resources, security-policy-match.
Assumed (not yet seen on a live system — the connector is ``preview``): the advanced-routing answer
shape, ``show vpn flow`` element names, ``show session info`` field names, resource-monitor shape and
HA peer-info/conn-status. Each parser tolerates a missing element by leaving the field empty.
"""

from __future__ import annotations

import ipaddress
import json
import re
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any, Callable

from app.integrations.base import IntegrationError
from app.integrations.connectors.panorama.client import PanApiError, entries, text
from app.integrations.connectors.sdk import device_key as make_device_key
from app.integrations.connectors.sdk import site_key as make_site_key
from app.integrations.domain import (
    Alert,
    Device,
    Interface,
    L3Entry,
    Neighbor,
    PolicyMatch,
    Route,
    Site,
    Tunnel,
    normalize_mac,
    stable_key,
)

CONNECTOR_ID = "panorama"

CMD_DEVICES_ALL = "<show><devices><all/></devices></show>"
CMD_DEVICE_GROUPS = "<show><devicegroups/></show>"
CMD_SYSTEM_INFO = "<show><system><info/></system></show>"
CMD_INTERFACES = "<show><interface>all</interface></show>"
CMD_ARP = "<show><arp><entry name='all'/></arp></show>"
CMD_ROUTES = "<show><routing><route/></routing></show>"
CMD_ROUTES_ARE = "<show><advanced-routing><route/></advanced-routing></show>"
CMD_LLDP = "<show><lldp><neighbors>all</neighbors></lldp></show>"
CMD_VPN_FLOW = "<show><vpn><flow/></vpn></show>"
CMD_HA_STATE = "<show><high-availability><state/></high-availability></show>"
CMD_RESOURCES = "<show><system><resources/></system></show>"
CMD_SESSION_INFO = "<show><session><info/></session></show>"
CMD_RESOURCE_MONITOR = (
    "<show><running><resource-monitor><minute><last>1</last></minute></resource-monitor></running></show>"
)

ROUTE_FLAGS = (("B", "bgp"), ("O", "ospf"), ("R", "rip"), ("S", "static"), ("C", "connected"))
LLDP_CAPS = {"B": "bridge", "R": "router", "W": "wlan-ap", "T": "telephone", "S": "station", "P": "repeater"}
PROTOCOL_NUMBERS = {"tcp": 6, "udp": 17, "icmp": 1, "icmp6": 58, "sctp": 132, "gre": 47, "esp": 50}
HA_BAD_STATES = {"suspended", "non-functional", "tentative"}
SESSION_WARN_PCT = 90.0


def _ip_only(value: str) -> str:
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return ""


def _cidr(value: str) -> str:
    value = (value or "").strip()
    if not value or value.upper() == "N/A":
        return ""
    try:
        return str(ipaddress.ip_interface(value))
    except ValueError:
        return ""


def _mac(value: str) -> str:
    mac = normalize_mac(value)
    return "" if mac in ("000000000000", "ffffffffffff") else mac


def _num(value: str) -> float | None:
    try:
        return float(str(value).strip())
    except (TypeError, ValueError):
        return None


def parse_uptime(value: str) -> float | None:
    """'12 days, 3:04:05' / '3:04:05' → seconds."""
    match = re.match(r"\s*(?:(\d+)\s+days?,?\s*)?(\d+):(\d+):(\d+)", value or "")
    if not match:
        return None
    days, h, m, s = (int(x or 0) for x in match.groups())
    return float(days * 86400 + h * 3600 + m * 60 + s)


def vrf_name(router: str) -> str:
    """Virtual/logical router → NodeWatch VRF: the default router is '' (as other connectors report it)."""
    router = (router or "").strip()
    return "" if router == "default" else router


def interface_kind(name: str) -> str:
    n = name.lower()
    if n.startswith("ae"):
        return "vlan" if "." in n else "lag"
    if n.startswith("ethernet"):
        return "vlan" if "." in n else "physical"
    if n.startswith("loopback"):
        return "loopback"
    if n.startswith("tunnel"):
        return "tunnel"
    if n.startswith("vlan"):
        return "vlan"
    if n in ("mgmt", "management"):
        return "mgmt"
    return "logical"


def parse_site_map(value: Any) -> dict[str, str]:
    """'DG-HQ=Headquarters; DG-Branch=Branch 1' (also newline/comma separated) → {dg: site}."""
    out: dict[str, str] = {}
    for part in re.split(r"[;\n,]", str(value or "")):
        if "=" in part:
            dg, site = part.split("=", 1)
            if dg.strip() and site.strip():
                out[dg.strip().lower()] = site.strip()
    return out


@dataclass
class Firewall:
    serial: str
    hostname: str = ""
    model: str = ""
    family: str = ""
    sw_version: str = ""
    mgmt_ip: str = ""
    connected: bool = False
    uptime_s: float | None = None
    ha_state: str = ""
    ha_peer: str = ""
    device_group: str = ""
    shared_policy: str = ""
    multi_vsys: bool = False
    vsys: list[str] = field(default_factory=list)
    site_name: str = ""

    @property
    def key(self) -> str:
        # Panorama does not report the base MAC; the serial is the identifier every Palo Alto source
        # (Panorama, Strata Cloud Manager) shares, so both produce the same device key.
        return make_device_key(serial=self.serial, source=CONNECTOR_ID, native_id=self.serial)

    @property
    def site_key(self) -> str:
        return make_site_key(CONNECTOR_ID, self.site_name.lower()) if self.site_name else ""

    @property
    def name(self) -> str:
        return self.hostname or self.serial


def parse_devices(result: ET.Element) -> list[Firewall]:
    out = []
    for e in entries(result.find("devices")):
        serial = text(e, "serial") or (e.get("name") or "").strip()
        if not serial:
            continue
        ha = e.find("ha")
        ha_state = ""
        ha_peer = ""
        if ha is not None:
            state = ha.find("state")
            ha_state = text(state) if state is not None and len(state) == 0 else text(ha, "state/state")
            ha_peer = text(ha, "peer/serial") or text(ha, "state/peer/serial")
        out.append(
            Firewall(
                serial=serial,
                hostname=text(e, "hostname"),
                model=text(e, "model"),
                family=text(e, "family"),
                sw_version=text(e, "sw-version"),
                mgmt_ip=_ip_only(text(e, "ip-address")),
                connected=text(e, "connected").lower() == "yes",
                uptime_s=parse_uptime(text(e, "uptime")),
                ha_state=ha_state.lower(),
                ha_peer=ha_peer,
                multi_vsys=text(e, "multi-vsys").lower() == "yes",
                vsys=[
                    text(v, "display-name") or (v.get("name") or "")
                    for v in entries(e.find("vsys"))
                    if (v.get("name") or text(v, "display-name"))
                ],
            )
        )
    return out


def parse_device_groups(result: ET.Element) -> dict[str, tuple[str, str]]:
    """{serial: (device group, shared-policy-status)}."""
    out: dict[str, tuple[str, str]] = {}
    for dg in entries(result.find("devicegroups")):
        name = (dg.get("name") or "").strip()
        for d in entries(dg.find("devices")):
            serial = (d.get("name") or text(d, "serial")).strip()
            if serial and name:
                status = text(d, "shared-policy-status") or text(d, "vsys/entry/shared-policy-status")
                out.setdefault(serial, (name, status))
    return out


def parse_interfaces(result: ET.Element) -> list[dict[str, Any]]:
    hw = {text(e, "name"): e for e in entries(result.find("hw")) if text(e, "name")}
    rows: dict[str, dict[str, Any]] = {}
    for e in entries(result.find("ifnet")):
        name = text(e, "name")
        if not name:
            continue
        ips = [x for x in [_cidr(text(e, "ip"))] + [_cidr(m.text or "") for m in e.findall("addr/member")] if x]
        ips += [x for x in (_cidr(m.text or "") for m in e.findall("addr6/member")) if x and not x.startswith("fe80")]
        tag = _num(text(e, "tag"))
        fwd = text(e, "fwd")
        rows[name] = {
            "name": name,
            "zone": text(e, "zone"),
            "ips": list(dict.fromkeys(ips)),
            "vlan": int(tag) if tag and tag > 0 else None,
            # "vr:<virtual router>" (legacy engine) or "lr:<logical router>" (Advanced Routing Engine)
            "router": fwd[3:] if fwd[:3] in ("vr:", "lr:") else ("" if fwd.upper() == "N/A" else fwd),
            "vsys": text(e, "vsys"),
        }
    for name in hw:
        rows.setdefault(name, {"name": name, "zone": "", "ips": [], "vlan": None, "router": "", "vsys": ""})
    out = []
    for name, row in rows.items():
        parent = name.split(".", 1)[0]
        h = hw.get(name) if name in hw else hw.get(parent)
        state = text(h, "state").lower() if h is not None else ""
        speed = _num(text(h, "speed")) if h is not None and name in hw else None
        duplex = text(h, "duplex").lower() if h is not None and name in hw else ""
        out.append(
            {
                **row,
                "oper_up": (state == "up") if state in ("up", "down") else None,
                "speed": speed,
                "duplex": duplex if duplex in ("full", "half") else "",
                "mac": _mac(text(h, "mac")) if h is not None and name in hw else "",
            }
        )
    return sorted(out, key=lambda r: r["name"])


def parse_routes(result: ET.Element) -> list[dict[str, str]]:
    out = []
    for e in entries(result):
        dest = text(e, "destination")
        flags = " ".join(text(e, "flags").split())
        if not dest or "H" in flags.split():  # host routes are the firewall's own addresses
            continue
        if flags and "A" not in flags.split():
            continue  # inactive candidate
        letters = set(flags.replace("?", " ").split())
        proto = next((p for letter, p in ROUTE_FLAGS if any(f.startswith(letter) for f in letters)), "")
        hop = text(e, "nexthop")
        out.append(
            {
                "prefix": dest,
                "next_hop": "" if hop in ("", "0.0.0.0", "::", "discard") or not _ip_only(hop) else hop,
                "interface": text(e, "interface"),
                "protocol": proto,
                "vrf": text(e, "virtual-router"),
            }
        )
    return out


def parse_advanced_routes(result: ET.Element) -> list[dict[str, str]]:
    """Advanced Routing Engine answer. Assumed shape (preview): JSON text (directly or in <json>) keyed
    by logical router then prefix, FRR style: {"<lr>": {"<prefix>": [{"protocol", "selected",
    "nexthops": [{"ip", "interfaceName", "active"}]}]}}; an XML <entry> list is parsed like legacy."""
    if entries(result):
        return parse_routes(result)
    raw = text(result, "json") or text(result)
    if not raw.startswith("{"):
        return []
    try:
        data = json.loads(raw)
    except ValueError:
        return []
    tables = data if all(isinstance(v, dict) for v in data.values()) else {"": data}
    out = []
    for router, table in tables.items():
        for prefix, paths in (table or {}).items():
            for path in paths if isinstance(paths, list) else []:
                if not isinstance(path, dict) or path.get("selected") is False:
                    continue
                proto = str(path.get("protocol") or "").lower()
                hops = [h for h in path.get("nexthops") or [] if isinstance(h, dict)] or [{}]
                for hop in hops:
                    if proto in ("local", "host"):
                        continue
                    out.append(
                        {
                            "prefix": str(path.get("prefix") or prefix),
                            "next_hop": _ip_only(str(hop.get("ip") or "")),
                            "interface": str(hop.get("interfaceName") or ""),
                            "protocol": "connected" if proto == "connected" else proto,
                            "vrf": str(router or path.get("vrfName") or ""),
                        }
                    )
    return out


def parse_mgmt_resources(result: ET.Element) -> tuple[float | None, float | None]:
    """(cpu %, memory %) of the management plane from ``show system resources`` (top output)."""
    raw = "".join(result.itertext())
    cpu = None
    m = re.search(r"Cpu\(s\):.*?([\d.]+)[ %]*id", raw)
    if m:
        cpu = round(max(0.0, 100.0 - float(m.group(1))), 1)
    mem = None
    m = re.search(r"(?:KiB|MiB|GiB)\s+Mem\s*:\s*([\d.]+)\s+total,\s*([\d.]+)\s+free,\s*([\d.]+)\s+used", raw)
    if m and float(m.group(1)) > 0:
        mem = round(float(m.group(3)) / float(m.group(1)) * 100.0, 1)
    return cpu, mem


def parse_dataplane_cpu(result: ET.Element) -> float | None:
    values: list[float] = []
    for avg in result.iter("cpu-load-average"):
        for e in avg.iter("entry"):
            first = text(e, "value").split(",")[0]
            number = _num(first)
            if number is not None:
                values.append(number)
    return round(sum(values) / len(values), 1) if values else None


def parse_policy_match(result: ET.Element) -> list[dict[str, Any]]:
    out = []
    for e in entries(result.find("rules")):
        if e.get("name"):
            action = text(e, "action").lower()
            action = "reset" if action.startswith("reset") else action
            out.append({"name": e.get("name"), "action": action, "index": text(e, "index")})
        else:
            parts = (e.text or "").split(";")
            if parts and parts[0].strip():
                index = parts[1].split(":", 1)[1].strip() if len(parts) > 1 and ":" in parts[1] else ""
                out.append({"name": parts[0].strip(), "action": "", "index": index})
    return out


class PanoramaReader:
    """Capability mixin: needs ``self.pan()`` (PanoramaClient), ``self.settings()`` and ``self.call``."""

    # ---- fleet --------------------------------------------------------------------------------
    def _fleet(self) -> list[Firewall]:
        client = self.pan()
        firewalls = parse_devices(client.op(CMD_DEVICES_ALL))
        try:
            groups = parse_device_groups(client.op(CMD_DEVICE_GROUPS))
        except PanApiError:
            groups = {}  # a role without device-group visibility still lists the firewalls
        settings = self.settings()
        wanted = {g.strip().lower() for g in str(settings.get("device_groups") or "").split(",") if g.strip()}
        site_map = parse_site_map(settings.get("site_map"))
        out = []
        for fw in firewalls:
            fw.device_group, fw.shared_policy = groups.get(fw.serial, ("", ""))
            if wanted and fw.device_group.lower() not in wanted:
                continue
            fw.site_name = site_map.get(fw.device_group.lower(), fw.device_group)
            out.append(fw)
        return out

    def _firewall(self, device_key: str | None) -> Firewall | None:
        return next((fw for fw in self._fleet() if fw.key == device_key), None)

    def _in_scope(self, site_key: str | None) -> list[Firewall]:
        return [fw for fw in self._fleet() if not site_key or fw.site_key == site_key]

    def _max_workers(self) -> int:
        try:
            return max(1, min(int(float(self.settings().get("max_workers") or 4)), 16))
        except (TypeError, ValueError):
            return 4

    def _max_firewalls(self) -> int:
        try:
            return max(1, min(int(float(self.settings().get("max_firewalls") or 100)), 1000))
        except (TypeError, ValueError):
            return 100

    def _fanout(self, firewalls: list[Firewall], fn: Callable[[Firewall], list[Any]]) -> list[Any]:
        """Run ``fn`` per connected firewall on a small pool. One unreachable firewall never hides the
        others; only when every firewall failed is the first error raised."""
        targets = [fw for fw in firewalls if fw.connected][: self._max_firewalls()]
        if not targets:
            return []
        results: list[Any] = []
        errors: list[IntegrationError] = []

        def run(fw: Firewall) -> tuple[list[Any], IntegrationError | None]:
            try:
                return fn(fw), None
            except IntegrationError as exc:
                return [], exc

        with ThreadPoolExecutor(
            max_workers=min(self._max_workers(), len(targets)), thread_name_prefix="panorama"
        ) as pool:
            for items, error in pool.map(run, targets):
                results.extend(items)
                if error is not None:
                    errors.append(error)
        if errors and len(errors) == len(targets):
            raise errors[0]
        return results

    # ---- INVENTORY ----------------------------------------------------------------------------
    def list_sites(self) -> list[Site]:
        def build() -> list[Site]:
            sites: dict[str, Site] = {}
            for fw in self._fleet():
                if fw.site_key and fw.site_key not in sites:
                    sites[fw.site_key] = Site(
                        key=fw.site_key,
                        source=CONNECTOR_ID,
                        name=fw.site_name,
                        native_id=fw.site_name,
                        vendor={"device_groups": []},
                    )
                if fw.site_key and fw.device_group not in sites[fw.site_key].vendor["device_groups"]:
                    sites[fw.site_key].vendor["device_groups"].append(fw.device_group)
            return sorted(sites.values(), key=lambda s: s.name.lower())

        return self.call(build, "list device groups")

    def _device(self, fw: Firewall, fleet: dict[str, Firewall] | None = None) -> Device:
        # HA pair → both units as members (the topology engine shows a pair as one node, like a stack).
        members = []
        if fw.ha_peer:
            peer = (fleet or {}).get(fw.ha_peer)
            members = [
                {"serial": fw.serial, "name": fw.name, "role": fw.ha_state or "ha-member"},
                {
                    "serial": fw.ha_peer,
                    "name": peer.name if peer else "",
                    "role": (peer.ha_state if peer else "") or "ha-peer",
                },
            ]
        return Device(
            key=fw.key,
            source=CONNECTOR_ID,
            name=fw.name,
            role="firewall",
            native_id=fw.serial,
            site_key=fw.site_key,
            site_name=fw.site_name,
            vendor_name="Palo Alto Networks",
            model=fw.model,
            serial=fw.serial,
            mgmt_ip=fw.mgmt_ip,
            os_version=f"PAN-OS {fw.sw_version}" if fw.sw_version else "",
            status="up" if fw.connected else "down",
            uptime_s=fw.uptime_s if fw.connected else None,
            members=members,
            ha_state=fw.ha_state,
            vendor={
                k: v
                for k, v in {
                    "device_group": fw.device_group,
                    "vsys": fw.vsys,
                    "multi_vsys": fw.multi_vsys,
                    "family": fw.family,
                    "panorama_connected": fw.connected,
                    "shared_policy": fw.shared_policy,
                }.items()
                if v not in ("", [], None)
            },
        )

    def list_devices(self, site_key: str | None = None) -> list[Device]:
        def build() -> list[Device]:
            fleet = self._fleet()
            by_serial = {fw.serial: fw for fw in fleet}
            return [self._device(fw, by_serial) for fw in fleet if not site_key or fw.site_key == site_key]

        return self.call(build, "list managed firewalls")

    # ---- INTERFACES ---------------------------------------------------------------------------
    def _interface_rows(self, fw: Firewall) -> list[dict[str, Any]]:
        return parse_interfaces(self.pan().op(CMD_INTERFACES, target=fw.serial))

    def list_interfaces(self, device_key: str) -> list[Interface]:
        def build() -> list[Interface]:
            fw = self._firewall(device_key)
            if fw is None or not fw.connected:
                return []
            out = []
            for r in self._interface_rows(fw):
                out.append(
                    Interface(
                        key=stable_key(fw.key, r["name"]),
                        source=CONNECTOR_ID,
                        device_key=fw.key,
                        name=r["name"],
                        kind=interface_kind(r["name"]),
                        role="mgmt" if interface_kind(r["name"]) == "mgmt" else "",
                        oper_up=r["oper_up"],
                        speed_mbps=r["speed"],
                        duplex=r["duplex"],
                        mac=r["mac"],
                        ips=r["ips"],
                        vlans=[r["vlan"]] if r["vlan"] else [],
                        zone=r["zone"],
                        vrf=vrf_name(r["router"]),
                        vendor={
                            **{k: v for k, v in {"virtual_router": r["router"], "vsys": r["vsys"]}.items() if v},
                            # Same normalisation as Route.vrf, so path trace can match ingress VRF to routes.
                            "vrf": vrf_name(r["router"]),
                        },
                    )
                )
            return out

        return self.call(build, "read firewall interfaces")

    # ---- ARP ----------------------------------------------------------------------------------
    def list_arp(self, device_key: str | None = None) -> list[L3Entry]:
        def one(fw: Firewall) -> list[L3Entry]:
            result = self.pan().op(CMD_ARP, target=fw.serial)
            return [
                L3Entry(
                    source=CONNECTOR_ID,
                    device_key=fw.key,
                    ip=_ip_only(text(e, "ip")),
                    mac=_mac(text(e, "mac")),
                    interface=text(e, "interface"),
                )
                for e in entries(result.find("entries"))
                if _ip_only(text(e, "ip")) and _mac(text(e, "mac"))  # skip incomplete entries
            ]

        def build() -> list[L3Entry]:
            fleet = self._fleet()
            scope = [fw for fw in fleet if fw.key == device_key] if device_key else fleet
            return self._fanout(scope, one)

        return self.call(build, "read ARP tables")

    # ---- ROUTES -------------------------------------------------------------------------------
    def _route_rows(self, fw: Firewall) -> list[dict[str, str]]:
        client = self.pan()
        try:
            return parse_routes(client.op(CMD_ROUTES, target=fw.serial))
        except PanApiError as exc:
            if exc.code not in ("UNSUPPORTED", "PROVIDER_ERROR"):
                raise
            return parse_advanced_routes(client.op(CMD_ROUTES_ARE, target=fw.serial))

    def list_routes(self, device_key: str) -> list[Route]:
        def build() -> list[Route]:
            fw = self._firewall(device_key)
            if fw is None or not fw.connected:
                return []
            return [
                Route(
                    source=CONNECTOR_ID,
                    device_key=fw.key,
                    prefix=r["prefix"],
                    next_hop=r["next_hop"],
                    interface=r["interface"],
                    protocol=r["protocol"],
                    vrf=vrf_name(r["vrf"]),
                )
                for r in self._route_rows(fw)
            ]

        return self.call(build, "read routing table")

    # ---- NEIGHBORS ----------------------------------------------------------------------------
    def list_neighbors(self, site_key: str | None = None) -> list[Neighbor]:
        def one(fw: Firewall) -> list[Neighbor]:
            result = self.pan().op(CMD_LLDP, target=fw.serial)
            out = []
            for port in entries(result):
                local = (port.get("name") or "").strip()
                for n in entries(port.find("neighbors")):
                    caps = text(n, "enabled-capabilities") or text(n, "system-capabilities")
                    mgmt = [m.get("name") or "" for m in entries(n.find("management-address"))]
                    out.append(
                        Neighbor(
                            source=CONNECTOR_ID,
                            device_key=fw.key,
                            local_interface=local,
                            remote_name=text(n, "system-name"),
                            remote_interface=text(n, "port-id") or text(n, "port-description"),
                            remote_mac=_mac(text(n, "chassis-id")),
                            remote_mgmt_ip=next((ip for ip in (_ip_only(m) for m in mgmt) if ip), ""),
                            remote_description=text(n, "system-description"),
                            remote_capabilities=[
                                LLDP_CAPS[c.strip()] for c in caps.split(",") if c.strip() in LLDP_CAPS
                            ],
                            protocol="lldp",
                        )
                    )
            return out

        return self.call(lambda: self._fanout(self._in_scope(site_key), one), "read LLDP neighbors")

    # ---- TUNNELS ------------------------------------------------------------------------------
    def _tunnels_of(self, fw: Firewall) -> list[Tunnel]:
        result = self.pan().op(CMD_VPN_FLOW, target=fw.serial)
        out = []
        for e in entries(result.find("IPSec")):
            name = text(e, "name")
            if not name:
                continue
            state = text(e, "state").lower()
            out.append(
                Tunnel(
                    key=stable_key(CONNECTOR_ID, fw.key, name),
                    source=CONNECTOR_ID,
                    device_key=fw.key,
                    name=name,
                    kind="ipsec",
                    local_ip=_ip_only(text(e, "localip")),
                    remote_ip=_ip_only(text(e, "peerip")),
                    state={"active": "up", "init": "down"}.get(state, "unknown"),
                    vendor={
                        k: v
                        for k, v in {
                            "tunnel_interface": text(e, "inner-if"),
                            "outer_interface": text(e, "outer-if"),
                            "monitor": text(e, "mon"),
                            "state": state,
                        }.items()
                        if v
                    },
                )
            )
        return out

    def list_tunnels(self, site_key: str | None = None) -> list[Tunnel]:
        return self.call(lambda: self._fanout(self._in_scope(site_key), self._tunnels_of), "read IPsec tunnels")

    # ---- ALERTS -------------------------------------------------------------------------------
    def _alert(self, fw: Firewall, kind: str, severity: str, title: str, detail: str, facts: list) -> Alert:
        return Alert(
            key=stable_key(CONNECTOR_ID, kind, fw.serial),
            source=CONNECTOR_ID,
            type=f"panorama.{kind}",
            category={"firewall.disconnected": "connectivity"}.get(kind, "availability" if "ha" in kind else "config"),
            severity=severity,
            title=title,
            detail=detail,
            site_key=fw.site_key,
            site_name=fw.site_name,
            device_key=fw.key,
            device_name=fw.name,
            device_role="firewall",
            native_id=fw.serial,
            facts=[{"label": k, "value": v, "kind": "text"} for k, v in facts if v],
        )

    def _ha_detail(self, fw: Firewall) -> dict[str, str]:
        result = self.pan().op(CMD_HA_STATE, target=fw.serial)
        return {
            "enabled": text(result, "enabled").lower(),
            "local": text(result, "group/local-info/state").lower(),
            "peer": text(result, "group/peer-info/state").lower(),
            "peer_conn": text(result, "group/peer-info/conn-status").lower(),
            "sync": text(result, "group/running-sync").lower(),
        }

    def list_alerts(self, site_key: str | None = None) -> list[Alert]:
        def ha_alerts(fw: Firewall) -> list[Alert]:
            ha = self._ha_detail(fw)
            out = []
            base = [("Serial", fw.serial), ("Device group", fw.device_group), ("HA state", ha["local"])]
            if ha["enabled"] != "yes":
                return out
            if ha["local"] in HA_BAD_STATES:
                out.append(
                    self._alert(
                        fw,
                        "ha.unhealthy",
                        "critical",
                        f"{fw.name}: HA state {ha['local']}",
                        "The firewall is not able to pass traffic as an HA member.",
                        base,
                    )
                )
            if ha["peer_conn"] and ha["peer_conn"] != "up":
                out.append(
                    self._alert(
                        fw,
                        "ha.peer_down",
                        "major",
                        f"{fw.name}: HA peer unreachable",
                        f"HA peer connection is {ha['peer_conn']}; the pair has no failover.",
                        base + [("Peer state", ha["peer"])],
                    )
                )
            if ha["sync"] and ha["sync"] not in ("synchronized", "synchronization in progress"):
                out.append(
                    self._alert(
                        fw,
                        "ha.config_not_synced",
                        "warning",
                        f"{fw.name}: HA configuration not synchronized",
                        f"Running configuration sync state is '{ha['sync']}'.",
                        base,
                    )
                )
            return out

        def build() -> list[Alert]:
            scope = self._in_scope(site_key)
            out: list[Alert] = []
            for fw in scope:
                if not fw.connected:
                    out.append(
                        self._alert(
                            fw,
                            "firewall.disconnected",
                            "major",
                            f"{fw.name} is disconnected from Panorama",
                            "Panorama cannot reach this firewall: no policy pushes, no log forwarding "
                            "status and no live data from it until it reconnects.",
                            [("Serial", fw.serial), ("Device group", fw.device_group), ("Management IP", fw.mgmt_ip)],
                        )
                    )
                status = fw.shared_policy.lower()
                if fw.connected and status and status not in ("in sync", "insync", "synced"):
                    out.append(
                        self._alert(
                            fw,
                            "policy.out_of_sync",
                            "warning",
                            f"{fw.name}: device-group policy {fw.shared_policy}",
                            "The firewall's shared policy differs from Panorama's device group "
                            "(a push is pending or failed).",
                            [("Device group", fw.device_group), ("Status", fw.shared_policy)],
                        )
                    )
            out += self._fanout([fw for fw in scope if fw.ha_state or fw.ha_peer], ha_alerts)
            return out

        return self.call(build, "check firewall health")

    # ---- HEALTH -------------------------------------------------------------------------------
    def list_health(self, site_key: str | None = None) -> dict[str, list[Any]]:
        def one(fw: Firewall) -> list[Device]:
            client = self.pan()
            device = self._device(fw, {f.serial: f for f in self._fleet()})
            mgmt_cpu, mem = parse_mgmt_resources(client.op(CMD_RESOURCES, target=fw.serial))
            session = client.op(CMD_SESSION_INFO, target=fw.serial)
            active, maximum = _num(text(session, "num-active")), _num(text(session, "num-max"))
            try:
                dp_cpu = parse_dataplane_cpu(client.op(CMD_RESOURCE_MONITOR, target=fw.serial))
            except PanApiError:
                dp_cpu = None
            if fw.ha_state or fw.ha_peer:
                try:
                    device.ha_state = self._ha_detail(fw)["local"] or device.ha_state
                except PanApiError:
                    pass
            device.cpu_pct = dp_cpu if dp_cpu is not None else mgmt_cpu
            device.memory_pct = mem
            device.sessions = int(active) if active is not None else None
            device.sessions_max = int(maximum) if maximum else None
            device.vendor.update(
                {
                    k: v
                    for k, v in {
                        "dataplane_cpu_pct": dp_cpu,
                        "mgmt_cpu_pct": mgmt_cpu,
                        "sessions_max": int(maximum) if maximum else None,
                        "session_util_pct": round(active / maximum * 100, 1)
                        if active is not None and maximum
                        else None,
                    }.items()
                    if v is not None
                }
            )
            return [device]

        def build() -> dict[str, list[Any]]:
            scope = self._in_scope(site_key)
            devices = self._fanout(scope, one)
            try:
                tunnels = self._fanout(scope, self._tunnels_of)
            except IntegrationError:
                tunnels = []
            return {"devices": devices, "interfaces": [], "tunnels": tunnels}

        return self.call(build, "read firewall health")

    # ---- POLICY_LOOKUP ------------------------------------------------------------------------
    def _zone_for(self, fw: Firewall, ip: str) -> str:
        """Zone of the interface that owns/routes ``ip``: connected subnet first, then longest-prefix route."""
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return ""
        rows = self._interface_rows(fw)
        zones = {r["name"]: r["zone"] for r in rows}
        best: tuple[int, str] = (-1, "")
        for r in rows:
            for cidr in r["ips"]:
                net = ipaddress.ip_interface(cidr).network
                if addr.version == net.version and addr in net and net.prefixlen > best[0] and r["zone"]:
                    best = (net.prefixlen, r["zone"])
        if best[1]:
            return best[1]
        for route in self._route_rows(fw):
            try:
                net = ipaddress.ip_network(route["prefix"], strict=False)
            except ValueError:
                continue
            zone = zones.get(route["interface"], "")
            if zone and addr.version == net.version and addr in net and net.prefixlen > best[0]:
                best = (net.prefixlen, zone)
        return best[1]

    def policy_lookup(
        self,
        device_key: str,
        *,
        src_ip: str,
        dst_ip: str,
        dst_port: int | None = None,
        protocol: str = "tcp",
        application: str = "",
        from_zone: str = "",
        to_zone: str = "",
    ) -> list[PolicyMatch]:
        def build() -> list[PolicyMatch]:
            fw = self._firewall(device_key)
            if fw is None:
                return []
            if not fw.connected:
                raise IntegrationError(
                    f"Panorama: {fw.name} is disconnected; policy lookup needs the firewall",
                    code="PROVIDER_UNAVAILABLE",
                )
            src, dst = _ip_only(src_ip), _ip_only(dst_ip)
            if not src or not dst:
                raise IntegrationError(
                    "Policy lookup needs valid source and destination IP addresses", code="BAD_REQUEST"
                )
            proto = str(protocol or "tcp").strip().lower()
            number = PROTOCOL_NUMBERS.get(proto) or (int(proto) if proto.isdigit() and 0 < int(proto) < 256 else None)
            if number is None:
                raise IntegrationError(f"Unknown protocol {protocol!r}", code="BAD_REQUEST")
            fz = from_zone or self._zone_for(fw, src)
            tz = to_zone or self._zone_for(fw, dst)
            root = ET.Element("test")
            match = ET.SubElement(root, "security-policy-match")
            for tag, value in (
                ("from", fz),
                ("to", tz),
                ("source", src),
                ("destination", dst),
                ("protocol", str(number)),
                ("destination-port", str(int(dst_port)) if dst_port else ""),
                ("application", application.strip()),
            ):
                if value:
                    ET.SubElement(match, tag).text = value
            cmd = ET.tostring(root, encoding="unicode")
            rules = parse_policy_match(self.pan().op(cmd, target=fw.serial, cache=False))
            nat = ""
            detail = f"test security-policy-match on {fw.name}" + (f" ({fz} → {tz})" if fz and tz else "")
            if not rules:
                # No explicit rule: PAN-OS's predefined defaults apply (intrazone-default allows,
                # interzone-default denies) — only stated when both zones are known.
                default = ("intrazone-default", "allow") if fz and fz == tz else ("interzone-default", "deny")
                known = bool(fz and tz)
                return [
                    PolicyMatch(
                        source=CONNECTOR_ID,
                        device_key=fw.key,
                        rule=default[0] if known else "",
                        action=default[1] if known else "unknown",
                        from_zone=fz,
                        to_zone=tz,
                        nat=nat,
                        detail=detail
                        + " — no security rule matched"
                        + ("; the predefined default rule applies" if known else ""),
                        vendor={"matched": False},
                    )
                ]
            first = rules[0]
            return [
                PolicyMatch(
                    source=CONNECTOR_ID,
                    device_key=fw.key,
                    rule=first["name"],
                    action=first["action"] or "unknown",
                    from_zone=fz,
                    to_zone=tz,
                    nat=nat,
                    detail=detail,
                    vendor={"matched": True, "index": first["index"], "device_group": fw.device_group},
                )
            ]

        return self.call(build, "test security policy")
