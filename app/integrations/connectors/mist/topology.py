"""Mist topology capabilities (see app/integrations/contracts.py).

``topology.endpoint_locate`` (v0.10.17): wired/wireless client search → the switch port + VLAN or the
AP + SSID where an IP/MAC was last seen.  ``health.metrics`` (v0.10.17): CPU/memory/PoE/sessions/HA
from device stats and rates/errors/flaps/PoE draw/WAN latency-loss-jitter from port stats.

Implements ``topology.neighbors`` from what Mist already reports:

* switch (and WAN edge) port statistics — the LLDP fields ``neighbor_system_name``,
  ``neighbor_port_desc``, ``neighbor_mac``, ``neighbor_mgmt_addr`` … on every port row;
* AP device statistics — ``lldp_stat`` describes the switch port each AP is cabled to.

Device keys use the same scheme as the Mist inventory capability:
``stable_key("mac", normalize_mac(device_mac))`` so neighbor records join inventory records, and a
box another vendor also reports (by MAC) correlates in the topology engine.

``list_topology_devices`` is an optional hook the topology engine uses when no inventory source
describes this connector's devices yet (it returns the boxes this capability saw, as Device records).
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

import re
import time
from typing import Any

from app.integrations.base import IntegrationError
from app.integrations.contracts import ENDPOINT_LOCATE, HEALTH, NEIGHBORS
from app.integrations.domain import Device, EndpointLocation, Interface, Neighbor, normalize_mac, stable_key

_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
_ROLE = {"switch": "switch", "ap": "wireless_ap", "gateway": "sdwan_edge"}
PORT_ROW_LIMIT = 20_000
URL_PARTS_TTL_S = 600.0


def mist_device_key(mac: Any) -> str:
    """The key every Mist capability uses for a device (shared with inventory)."""
    m = normalize_mac(mac)
    return stable_key("mac", m) if m else ""


def _text(value: Any) -> str:
    if isinstance(value, list):
        value = next((v for v in value if v not in (None, "")), "")
    return str(value or "").strip()


def _first(row: dict, *keys: str) -> str:
    for k in keys:
        v = _text(row.get(k))
        if v:
            return v
    return ""


def _caps(value: Any) -> list[str]:
    if isinstance(value, str):
        value = re.split(r"[,\s]+", value)
    if not isinstance(value, list):
        return []
    return [str(v).strip().lower() for v in value if str(v or "").strip()]


def _num(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    try:
        return float(value) if value not in (None, "") else None
    except (TypeError, ValueError):
        return None


def _scalar(value: Any) -> Any:
    """Mist client searches return some fields as history arrays: first non-empty item."""
    if isinstance(value, (list, tuple)):
        return next((v for v in value if v not in (None, "")), None)
    return value


def _epoch(value: Any) -> float | None:
    n = _num(_scalar(value))
    if n is None or n <= 0:
        return None
    while n > 1e11:
        n /= 1000.0
    return n


def _cpu_pct(dev: dict) -> float | None:
    """Switch/gateway ``cpu_stat.idle`` → busy %; APs report ``cpu_util`` or user+system."""
    cpu = dev.get("cpu_stat")
    if isinstance(cpu, dict):
        idle = _num(cpu.get("idle"))
        if idle is not None:
            return round(max(0.0, min(100.0, 100.0 - idle)), 1)
        parts = [_num(cpu.get(k)) for k in ("user", "system", "interrupt")]
        if any(p is not None for p in parts):
            return round(min(100.0, sum(p or 0.0 for p in parts)), 1)
    util = _num(dev.get("cpu_util"))
    if util is not None:
        return round(util, 1)
    parts = [_num(dev.get(k)) for k in ("cpu_user", "cpu_system")]
    if any(p is not None for p in parts):
        return round(min(100.0, sum(p or 0.0 for p in parts)), 1)
    return None


def _memory_pct(dev: dict) -> float | None:
    mem = dev.get("memory_stat")
    if isinstance(mem, dict) and _num(mem.get("usage")) is not None:
        return round(_num(mem.get("usage")) or 0.0, 1)
    used, total = _num(dev.get("mem_used_kb")), _num(dev.get("mem_total_kb"))
    if used is not None and total:
        return round(used / total * 100, 1)
    return None


def _ha_state(dev: dict) -> str:
    for field_name in ("cluster_stat", "cluster_config", "ha_stat"):
        block = dev.get(field_name)
        if isinstance(block, dict):
            for k in ("state", "status", "operational", "ha_state"):
                v = _text(block.get(k))
                if v:
                    low = v.lower()
                    if low in ("green", "ok", "healthy", "primary", "active"):
                        return "active"
                    if low in ("secondary", "passive", "backup", "standby"):
                        return "passive"
                    if low in ("red", "yellow", "degraded", "failed", "lost"):
                        return "degraded"
                    return low
    return ""


class MistTopology:
    CAPABILITIES: tuple[str, ...] = (NEIGHBORS, ENDPOINT_LOCATE, HEALTH)

    # ------------------------------------------------------------------ scope
    def _mist_site_id(self, site_key: str | None) -> str | None:
        """Accept a raw Mist site id or the inventory's stable site key."""
        if not site_key:
            return None
        key = str(site_key).strip()
        if _UUID.match(key):
            return key
        try:
            sites = self.call(self.client.list_sites, "list sites")  # type: ignore[attr-defined]
        except Exception:  # noqa: BLE001 - unresolved key → treated as unknown site below
            sites = []
        for s in sites or []:
            sid = str(s.get("id") or "")
            if (
                key
                in {
                    stable_key("site", "mist", sid),
                    stable_key("mist", sid),
                    stable_key("site", sid),
                    stable_key("mist-site", sid),
                }
                or key.lower() == str(s.get("name") or "").strip().lower()
            ):
                return sid
        return key  # let Mist answer (404 → IntegrationError) rather than guess

    def _device_stats(self, site_id: str | None) -> list[dict]:
        client = self.client  # type: ignore[attr-defined]
        rows = self.call(  # type: ignore[attr-defined]
            lambda: client.list_org_device_stats("all", site_id=site_id), "read device statistics"
        )
        return [r for r in rows or [] if isinstance(r, dict)]

    def _port_rows(self, site_id: str | None, device_type: str) -> list[dict]:
        """Port statistics for the map. Org-wide reads ask only for ``up`` ports (LLDP neighbours exist
        only on live ports; a whole organisation is ~20 pages otherwise); one site keeps every port so
        a down LAG member still shows. Unsorted, pages in parallel (v0.10.21)."""
        client = self.client  # type: ignore[attr-defined]
        fast = getattr(client, "search_ports_for_topology", None)
        if callable(fast):
            fn = lambda: fast(  # noqa: E731
                site_id=site_id, device_type=device_type, up_only=not site_id, limit=PORT_ROW_LIMIT
            )
        elif site_id:
            fn = lambda: client.search_site_ports(site_id, device_type=device_type, limit=PORT_ROW_LIMIT)  # noqa: E731
        else:
            fn = lambda: client.search_org_ports(device_type=device_type, limit=PORT_ROW_LIMIT)  # noqa: E731
        rows = self.call(fn, f"search {device_type} port statistics")  # type: ignore[attr-defined]
        return [r for r in rows or [] if isinstance(r, dict)]

    def _reads(self, site_id: str | None) -> tuple[list[dict], list[dict], list[dict]]:
        """(switch ports, gateway ports, device stats) read concurrently — they are independent and each
        takes seconds on a large organisation. A failing gateway search (orgs without WAN edges) is empty."""
        with ThreadPoolExecutor(max_workers=3) as pool:
            sw = pool.submit(self._port_rows, site_id, "switch")
            gw = pool.submit(self._port_rows, site_id, "gateway")
            dev = pool.submit(self._device_stats, site_id)
            try:
                gw_rows = gw.result()
            except Exception:  # noqa: BLE001
                gw_rows = []
            return sw.result(), gw_rows, dev.result()

    # ------------------------------------------------------------------ NEIGHBORS
    def list_neighbors(self, site_key: str | None = None) -> list[Neighbor]:
        site_id = self._mist_site_id(site_key)
        out: list[Neighbor] = []
        seen: set[tuple[str, str, str]] = set()

        def add(n: Neighbor) -> None:
            ident = (n.device_key, n.local_interface.lower(), n.remote_mac or n.remote_name.lower())
            if n.device_key and n.local_interface and ident not in seen:
                seen.add(ident)
                out.append(n)

        sw_rows, gw_rows, dev_rows = self._reads(site_id)
        for row in [*sw_rows, *gw_rows]:
            n = self._neighbor_from_port(row)
            if n:
                add(n)
        for dev in dev_rows:
            if str(dev.get("type") or "").lower() != "ap":
                continue
            for n in self._neighbors_from_ap(dev):
                add(n)
        return out

    @staticmethod
    def _neighbor_from_port(row: dict) -> Neighbor | None:
        remote_mac = normalize_mac(row.get("neighbor_mac"))
        remote_name = _first(row, "neighbor_system_name")
        if not (remote_mac or remote_name):
            return None
        key = mist_device_key(row.get("mac"))
        if not key:
            return None
        return Neighbor(
            source="mist",
            device_key=key,
            local_interface=_first(row, "port_id"),
            remote_name=remote_name,
            remote_interface=_first(row, "neighbor_port_id", "neighbor_port_desc", "neighbor_port"),
            remote_mac=remote_mac,
            remote_mgmt_ip=_first(row, "neighbor_mgmt_addr", "neighbor_mgmt_ip", "neighbor_ip"),
            remote_description=_first(row, "neighbor_system_desc"),
            remote_capabilities=_caps(row.get("neighbor_capabilities") or row.get("neighbor_system_capabilities")),
            protocol="lldp",
            local_lag=_first(row, "port_parent", "aggregated_parent"),
            local_up=row.get("up") if isinstance(row.get("up"), bool) else None,
            speed_mbps=float(row["speed"]) if isinstance(row.get("speed"), (int, float)) and row["speed"] else None,
        )

    @staticmethod
    def _neighbors_from_ap(dev: dict) -> list[Neighbor]:
        key = mist_device_key(dev.get("mac"))
        if not key:
            return []
        tables: list[dict] = []
        for field_name in ("lldp_stat", "lldp_stats"):
            table = dev.get(field_name)
            if isinstance(table, dict) and any(k in table for k in ("system_name", "chassis_id", "port_id")):
                tables.append({"local_port": "eth0", **table})
            elif isinstance(table, dict):
                tables.extend({"local_port": k, **v} for k, v in table.items() if isinstance(v, dict))
            elif isinstance(table, list):
                tables.extend(t for t in table if isinstance(t, dict))
        out = []
        for t in tables:
            remote_mac = normalize_mac(t.get("chassis_id"))
            remote_name = _first(t, "system_name")
            if not (remote_mac or remote_name):
                continue
            out.append(
                Neighbor(
                    source="mist",
                    device_key=key,
                    local_interface=_first(t, "local_port", "port") or "eth0",
                    remote_name=remote_name,
                    remote_interface=_first(t, "port_id", "port_desc"),
                    remote_mac=remote_mac,
                    remote_mgmt_ip=_first(t, "mgmt_addr", "mgmt_addrs", "management_address"),
                    remote_description=_first(t, "system_desc"),
                    remote_capabilities=["bridge"],
                    protocol="lldp",
                    local_up=True,
                )
            )
        return out

    # ------------------------------------------------------------------ ENDPOINT_LOCATE
    def locate_endpoint(self, *, ip: str = "", mac: str = "") -> list[EndpointLocation]:
        """Where Mist last saw a client: wired (switch + port + VLAN) and wireless (AP + SSID).

        Mist API (read-only): GET /orgs/{org}/wired_clients/search and /orgs/{org}/clients/search,
        filtered by MAC (preferred) or IP, last 24 h.
        """
        want_mac = normalize_mac(mac)
        want_ip = str(ip or "").strip()
        if not want_mac and not want_ip:
            return []
        client = self.client  # type: ignore[attr-defined]
        query: dict[str, Any] = {"mac": want_mac} if want_mac else {"ip": want_ip}
        rows: dict[str, list[dict]] = {}
        errors: list[IntegrationError] = []
        for kind, fn_name, what in (
            ("wired", "search_org_wired_clients", "search wired clients"),
            ("wireless", "search_org_wireless_clients", "search wireless clients"),
        ):
            fn = getattr(client, fn_name)
            try:
                got = self.call(lambda fn=fn: fn(**query, duration="1d", limit=20), what)  # type: ignore[attr-defined]
            except IntegrationError as exc:
                errors.append(exc)
                got = []
            rows[kind] = [r for r in got or [] if isinstance(r, dict)]
        if len(errors) == 2:
            raise errors[0]
        try:
            directory = client.device_directory() or {}
        except Exception:  # noqa: BLE001 - names are a nicety
            directory = {}

        def matches(row: dict) -> bool:
            if want_mac:
                return normalize_mac(row.get("mac")) == want_mac
            ips = row.get("ip") if isinstance(row.get("ip"), list) else [row.get("ip"), row.get("last_ip")]
            ips = list(ips or []) + [x.get("ip") for x in _as_list(row.get("device_mac_port")) if isinstance(x, dict)]
            return want_ip in {str(_scalar(x) or "").strip() for x in ips}

        out: list[EndpointLocation] = []
        for row in rows["wired"]:
            if not matches(row):
                continue
            attach = _latest_attachment(row)
            sw_mac = normalize_mac(attach.get("device_mac"))
            if not sw_mac:
                continue
            known = directory.get(sw_mac, {}) if isinstance(directory, dict) else {}
            out.append(
                EndpointLocation(
                    source="mist",
                    mac=normalize_mac(row.get("mac")),
                    ip=str(_scalar(attach.get("ip")) or _scalar(row.get("ip")) or ""),
                    hostname=_text(_scalar(row.get("hostname"))),
                    device_key=mist_device_key(sw_mac),
                    device_name=_text(known.get("name")),
                    interface=_text(_scalar(attach.get("port_id"))),
                    vlan=_int(_scalar(attach.get("vlan"))),
                    wireless=False,
                    last_seen=_epoch(attach.get("when") or row.get("timestamp") or row.get("last_seen")),
                )
            )
        for row in rows["wireless"]:
            if not matches(row):
                continue
            ap_mac = normalize_mac(_scalar(row.get("ap")) or _scalar(row.get("ap_mac")) or _scalar(row.get("last_ap")))
            if not ap_mac:
                continue
            known = directory.get(ap_mac, {}) if isinstance(directory, dict) else {}
            ssid = _text(_scalar(row.get("ssid")) or _scalar(row.get("last_ssid")))
            out.append(
                EndpointLocation(
                    source="mist",
                    mac=normalize_mac(row.get("mac")),
                    ip=str(_scalar(row.get("ip")) or _scalar(row.get("last_ip")) or ""),
                    hostname=_text(_scalar(row.get("hostname")) or _scalar(row.get("last_hostname"))),
                    device_key=mist_device_key(ap_mac),
                    device_name=_text(known.get("name")),
                    interface=f"SSID {ssid}" if ssid else "wireless",
                    vlan=_int(_scalar(row.get("vlan")) or _scalar(row.get("last_vlan"))),
                    wireless=True,
                    last_seen=_epoch(row.get("timestamp") or row.get("last_seen")),
                )
            )
        out.sort(key=lambda e: -(e.last_seen or 0))
        return out

    # ------------------------------------------------------------------ HEALTH
    def list_health(self, site_key: str | None = None) -> dict[str, list[Any]]:
        """Live health from Mist device and port statistics (read-only).

        devices:    CPU (cpu_stat.idle / cpu_util), memory (memory_stat.usage / mem_used_kb), PoE budget
                    (module_stat[].poe), gateway sessions (spu_stat) and HA (cluster state)
        interfaces: switch + WAN-edge ports — rates, utilization, errors, packets, last flap, PoE draw,
                    and WAN latency / loss / jitter where the gateway measures them
        """
        site_id = self._mist_site_id(site_key)
        sw_rows, gw_rows, dev_rows = self._reads(site_id)
        devices = []
        for dev in dev_rows:
            d = self._device_record(dev, site_id)
            if d is None:
                continue
            d.cpu_pct = _cpu_pct(dev)
            d.memory_pct = _memory_pct(dev)
            spu = [s for s in dev.get("spu_stat") or [] if isinstance(s, dict)]
            if spu:
                cur = [_num(s.get("spu_current_session")) for s in spu]
                mx = [_num(s.get("spu_max_session")) for s in spu]
                if any(c is not None for c in cur):
                    d.sessions = int(sum(c or 0 for c in cur))
                if any(m for m in mx):
                    d.sessions_max = int(sum(m or 0 for m in mx))
                    d.vendor["sessions_max"] = d.sessions_max
            d.ha_state = _ha_state(dev)
            budget = draw = 0.0
            seen_poe = False
            for m in dev.get("module_stat") or []:
                poe = m.get("poe") if isinstance(m, dict) else None
                if isinstance(poe, dict) and _num(poe.get("max_power")):
                    seen_poe = True
                    budget += _num(poe.get("max_power")) or 0.0
                    draw += _num(poe.get("power_draw")) or 0.0
            if seen_poe and budget:
                d.poe_budget_w, d.poe_used_w = round(budget, 1), round(draw, 1)
                d.vendor["poe_budget_w"], d.vendor["poe_used_w"] = d.poe_budget_w, d.poe_used_w
            devices.append(d)
        interfaces: list[Interface] = []
        for row in [*sw_rows, *gw_rows]:
            itf = self._health_interface(row)
            if itf is not None:
                interfaces.append(itf)
        return {"devices": devices, "interfaces": interfaces, "tunnels": []}

    @staticmethod
    def _health_interface(row: dict) -> Interface | None:
        key = mist_device_key(row.get("mac"))
        port = _text(row.get("port_id"))
        if not key or not port:
            return None
        speed = _num(row.get("speed")) or None
        rx_bps, tx_bps = _num(row.get("rx_bps")), _num(row.get("tx_bps"))
        util = None
        if speed and (rx_bps is not None or tx_bps is not None):
            util = round(max(rx_bps or 0.0, tx_bps or 0.0) / (speed * 1e6) * 100, 2)
        vendor: dict[str, Any] = {}
        for src, dst in (
            ("rx_pkts", "rx_pkts"),
            ("tx_pkts", "tx_pkts"),
            ("latency", "latency_ms"),
            ("loss", "loss_pct"),
            ("jitter", "jitter_ms"),
        ):
            v = _num(row.get(src))
            if v is not None:
                vendor[dst] = v
        flapped = _epoch(row.get("last_flapped"))
        if flapped:
            vendor["last_flapped"] = flapped
        if row.get("port_usage"):
            vendor["usage"] = _text(row.get("port_usage"))
        up = row.get("up")
        return Interface(
            key=stable_key(key, port),
            source="mist",
            device_key=key,
            name=port,
            kind="lag" if port.startswith("ae") else "physical",
            role={"wan": "wan", "lan": "lan"}.get(_text(row.get("port_usage")).lower(), ""),
            oper_up=up if isinstance(up, bool) else None,
            speed_mbps=speed,
            mac=normalize_mac(row.get("port_mac")),
            lag_parent=_first(row, "port_parent", "aggregated_parent"),
            poe_watts=_num(row.get("power_draw")),
            rx_errors=int(_num(row.get("rx_errors")) or 0) if _num(row.get("rx_errors")) is not None else None,
            tx_errors=int(_num(row.get("tx_errors")) or 0) if _num(row.get("tx_errors")) is not None else None,
            rx_bps=rx_bps,
            tx_bps=tx_bps,
            utilization_pct=util,
            latency_ms=vendor.get("latency_ms"),
            loss_pct=vendor.get("loss_pct"),
            jitter_ms=vendor.get("jitter_ms"),
            rx_pkts=int(vendor["rx_pkts"]) if vendor.get("rx_pkts") is not None else None,
            tx_pkts=int(vendor["tx_pkts"]) if vendor.get("tx_pkts") is not None else None,
            last_flapped=vendor.get("last_flapped"),
            vendor=vendor,
        )

    # ------------------------------------------------------------------ optional engine hooks
    def list_device_facts(self, site_key: str | None = None) -> list[dict[str, Any]]:
        """Per-device counts for the Closets map (v0.10.21): ports up / total, port faceplate, PoE draw,
        clients and the Mist floor plan id. No extra API call: the same device and port statistics
        :meth:`list_neighbors` has just read (the client caches each read for its endpoint TTL)."""
        site_id = self._mist_site_id(site_key)
        sw_rows, _gw_rows, dev_rows = self._reads(site_id)
        # Org-wide reads ask only for live ports, so port totals are honest only for one site.
        return device_facts(sw_rows, dev_rows, full_ports=bool(site_id))

    def list_topology_devices(self, site_key: str | None = None) -> list[Device]:
        """Devices seen by this capability (used only when no inventory source covers them)."""
        site_id = self._mist_site_id(site_key)
        return [d for d in (self._device_record(dev, site_id) for dev in self._device_stats(site_id)) if d]

    def _url_parts(self) -> tuple[Any, str, str]:
        """(url builder, api host, org id) for console links; cached URL_PARTS_TTL_S, failures not cached."""
        cached = getattr(self, "_mist_url_parts", None)
        if cached and time.monotonic() - cached[0] < URL_PARTS_TTL_S:
            return cached[1]
        try:
            from app.modules.history.activity import mist_device_url

            settings = self.client.settings  # type: ignore[attr-defined]
            parts = (
                mist_device_url,
                str(getattr(settings, "api_host", "") or ""),
                str(getattr(settings, "org_id", "") or ""),
            )
        except Exception:  # noqa: BLE001 - no console link this time; try again on the next call
            self._mist_url_parts = None
            return (None, "", "")
        if parts[1] and parts[2]:
            self._mist_url_parts = (time.monotonic(), parts)
        else:
            self._mist_url_parts = None  # not configured yet: don't remember the empty answer
        return parts

    def reset_state(self) -> None:
        """Settings changed: forget the cached console-link parts too (the SDK calls this)."""
        self._mist_url_parts = None
        super().reset_state()  # type: ignore[misc]

    def _device_record(self, dev: dict, site_id: str | None) -> Device | None:
        dtype = str(dev.get("type") or "").lower()
        key = mist_device_key(dev.get("mac"))
        if not key or dtype not in _ROLE:
            return None
        mist_device_url, api_host, org_id = self._url_parts()
        status_raw = str(dev.get("status") or "").lower()
        status = "up" if status_raw == "connected" else "down" if status_raw == "disconnected" else "unknown"
        members = []
        for m in dev.get("module_stat") or []:
            if isinstance(m, dict) and (m.get("serial") or m.get("mac")):
                members.append(
                    {
                        "name": f"fpc{m.get('fpc_idx', m.get('idx', ''))}",
                        "role": str(m.get("vc_role") or ""),
                        "model": str(m.get("model") or ""),
                        "serial": str(m.get("serial") or ""),
                        "mac": normalize_mac(m.get("mac")),
                    }
                )
        sid, did = str(dev.get("site_id") or site_id or ""), str(dev.get("id") or "")
        url = ""
        if mist_device_url and api_host and org_id:
            url = mist_device_url(
                api_host, org_id, site_id=sid, device_type=dtype, device_id=did, mac=str(dev.get("mac") or "")
            )
        return Device(
            key=key,
            source="mist",
            name=_text(dev.get("name")) or _text(dev.get("hostname")) or normalize_mac(dev.get("mac")),
            role=_ROLE[dtype],
            native_id=did,
            site_key=stable_key("site", "mist", sid) if sid else "",
            vendor_name="Juniper",
            model=_text(dev.get("model")),
            serial=_text(dev.get("serial")),
            mac=normalize_mac(dev.get("mac")),
            mgmt_ip=_text(dev.get("ip")) or _text((dev.get("ip_stat") or {}).get("ip")),
            os_version=_text(dev.get("version")),
            status=status,
            last_seen=float(dev["last_seen"]) if isinstance(dev.get("last_seen"), (int, float)) else None,
            uptime_s=float(dev["uptime"]) if isinstance(dev.get("uptime"), (int, float)) else None,
            members=members,
            console_url=url,
            alias_macs=[normalize_mac(dev.get("vc_mac"))] if normalize_mac(dev.get("vc_mac")) else [],
            floor_key=_text(dev.get("map_id")),
            vendor={"mist_type": dtype, "mist_site_id": sid, "mist_device_id": did}
            | ({"vc_mac": normalize_mac(dev.get("vc_mac"))} if dev.get("vc_mac") else {}),
        )


PORT_WARN_ERROR_RATIO = 0.001  # 0.1 % of packets: the live-health warning default for port errors
PORT_WARN_ERRORS = 1000  # error counters without packet counts (health "errors" warning default)


def _port_order(port_id: str) -> tuple:
    """'ge-1/0/10' → (1, 0, 10, 'ge'): faceplate order (member, PIC, port), then the media prefix."""
    nums = tuple(int(x) for x in re.findall(r"\d+", port_id))
    return (*nums, port_id.split("-", 1)[0])


def _port_state(row: dict) -> str:
    """'u' up, 'w' up with errors above the warning share, 'd' down / empty."""
    if row.get("up") is not True:
        return "d"
    errors = sum(_num(row.get(k)) or 0.0 for k in ("rx_errors", "tx_errors"))
    pkts = sum(_num(row.get(k)) or 0.0 for k in ("rx_pkts", "tx_pkts"))
    if errors and ((pkts and errors / pkts >= PORT_WARN_ERROR_RATIO) or (not pkts and errors >= PORT_WARN_ERRORS)):
        return "w"
    return "u"


def _wired_clients(dev: dict) -> int | None:
    stats = dev.get("clients_stats")
    total = stats.get("total") if isinstance(stats, dict) else None
    if isinstance(total, dict) and _num(total.get("num_wired_clients")) is not None:
        return int(_num(total.get("num_wired_clients")) or 0)
    if _num(dev.get("num_wired_clients")) is not None:
        return int(_num(dev.get("num_wired_clients")) or 0)
    if isinstance(dev.get("clients"), list):
        return len(dev["clients"])
    return None


def device_facts(sw_rows: list[dict], dev_rows: list[dict], *, full_ports: bool = True) -> list[dict[str, Any]]:
    """Facts per switch / AP from Mist statistics already read for the map.

    ``port_map`` is one character per physical port in faceplate order (see :func:`_port_state`);
    ``full_ports`` False (an org-wide read of live ports only) leaves port counts out.
    """
    from app.services.operations_service import port_kind

    ports: dict[str, dict[str, dict]] = {}
    for row in sw_rows:
        key = mist_device_key(row.get("mac"))
        pid = _text(row.get("port_id"))
        if key and pid and port_kind(pid) == "physical":
            ports.setdefault(key, {})[pid] = row
    out: dict[str, dict[str, Any]] = {}
    for key, by_port in ports.items():
        fact: dict[str, Any] = {"source": "mist", "device_key": key}
        if full_ports:
            states = "".join(_port_state(by_port[p]) for p in sorted(by_port, key=_port_order))
            fact.update(
                ports_total=len(states),
                ports_up=states.count("u") + states.count("w"),
                ports_warn=states.count("w"),
                port_map=states,
            )
        draws = [_num(r.get("power_draw")) for r in by_port.values() if _num(r.get("power_draw")) is not None]
        if draws:
            fact["poe_draw_w"] = round(sum(draws), 1)
        out[key] = fact
    for dev in dev_rows:
        dtype = str(dev.get("type") or "").lower()
        key = mist_device_key(dev.get("mac"))
        if not key or dtype not in ("switch", "ap"):
            continue
        fact = out.setdefault(key, {"source": "mist", "device_key": key})
        clients = _wired_clients(dev) if dtype == "switch" else None
        if dtype == "ap" and _num(dev.get("num_clients")) is not None:
            clients = int(_num(dev.get("num_clients")) or 0)
        if clients is not None:
            fact["clients"] = clients
        draw, seen = 0.0, False
        for m in dev.get("module_stat") or []:
            poe = m.get("poe") if isinstance(m, dict) else None
            if isinstance(poe, dict) and _num(poe.get("power_draw")) is not None:
                seen = True
                draw += _num(poe.get("power_draw")) or 0.0
        if seen:
            fact["poe_draw_w"] = round(draw, 1)  # the chassis figure beats the sum of port rows
        if _text(dev.get("map_id")):
            fact["floor_id"] = _text(dev.get("map_id"))
    return [f for f in out.values() if len(f) > 2]


def _as_list(value: Any) -> list:
    if isinstance(value, dict):
        return [value]
    return list(value) if isinstance(value, list) else []


def _int(value: Any) -> int | None:
    try:
        return int(str(value).strip()) if value not in (None, "") else None
    except (TypeError, ValueError):
        return None


def _latest_attachment(row: dict) -> dict:
    """Most recent switch/port of a wired client: ``device_mac_port`` keeps switch and port together."""
    rels = [r for r in _as_list(row.get("device_mac_port")) if isinstance(r, dict) and r.get("device_mac")]
    if rels:
        return max(rels, key=lambda r: max(_epoch(r.get(k)) or 0 for k in ("when", "last_seen", "timestamp", "start")))
    return {
        "device_mac": _scalar(row.get("device_mac")) or _scalar(row.get("switch_mac")),
        "port_id": _scalar(row.get("port_id")),
        "vlan": _scalar(row.get("vlan")),
        "ip": _scalar(row.get("ip")),
    }
