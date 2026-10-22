"""Mist inventory capability (see app/integrations/contracts.py).

INVENTORY  → list_sites(), list_devices(site_key)
INTERFACES → list_interfaces(device_key)   (switch ports reuse operations_service normalization)
EVENTS     → list_events(site_key, hours)

Keys follow the vendor-neutral scheme so other vendors' records about the same box correlate:
* device: ``stable_key("mac", normalized_mac)`` (``sdk.device_key``) — same as MistTopology/MistAlerts;
* site:   ``stable_key("site", "mist", site_id)`` (``sdk.site_key``).
Mist's own ids stay in ``native_id`` / ``vendor``.

Mist API used (all read-only, through the existing MistClient):
* GET /api/v1/orgs/{org_id}/sites
* GET /api/v1/orgs/{org_id}/stats/devices?type=all[&site_id=]
* GET /api/v1/sites/{site_id}/devices/{device_id} + /stats/devices/{device_id} + /stats/ports/search
  (via operations_service.get_switch_ports)
* GET /api/v1/orgs/{org_id}/devices/events/search | /api/v1/sites/{site_id}/devices/events/search
"""

from __future__ import annotations

import threading
from typing import Any

from app.integrations.contracts import EVENTS, INTERFACES, INVENTORY
from app.integrations.domain import Device, Event, Interface, Site, normalize_mac, stable_key

# Mist device type → vendor-neutral role.
MIST_ROLES = {"switch": "switch", "ap": "wireless_ap", "gateway": "sdwan_edge"}
# Mist "status" (stats API) → up | down | degraded | unknown.
MIST_STATUS = {
    "connected": "up",
    "disconnected": "down",
    "restarting": "degraded",
    "upgrading": "degraded",
}
_EVENT_WARNING_WORDS = ("DOWN", "DISCONNECT", "FAIL", "ERROR", "LOSS", "UNREACH", "TIMEOUT", "BLOCK", "REJECT")
_EVENT_MAJOR_WORDS = ("RESTART_BY_CRASH", "CRASH", "PANIC", "POWER_LOSS", "OVERHEAT")
_EVENT_LIMIT = 1000


def _text(value: Any) -> str:
    return "" if value is None else str(value).strip()


def _num(value: Any) -> float | None:
    try:
        return float(value) if value not in (None, "") else None
    except (TypeError, ValueError):
        return None


def mist_device_key(mac: Any, device_id: Any = "") -> str:
    from app.integrations.connectors.sdk import device_key

    return device_key(mac=mac, source="mist", native_id=device_id)


def mist_site_key(site_id: Any) -> str:
    from app.integrations.connectors.sdk import site_key

    return site_key("mist", site_id)


def event_severity(event_type: str) -> str:
    upper = str(event_type or "").upper()
    if any(w in upper for w in _EVENT_MAJOR_WORDS):
        return "major"
    if any(w in upper for w in _EVENT_WARNING_WORDS):
        return "warning"
    return "info"


# Mist gateway port usage → Interface.role (switch port profiles such as "ap" / "uplink" stay unknown)
_PORT_ROLE = {"wan": "wan", "lan": "lan"}


def _interface_kind(port_id: str) -> str:
    from app.services.operations_service import port_kind

    kind = port_kind(port_id)
    return {"physical": "physical", "vcp": "physical", "lag": "lag", "management": "mgmt"}.get(kind, "logical")


class MistInventory:
    CAPABILITIES: tuple[str, ...] = (INVENTORY, INTERFACES, EVENTS)

    # ---- helpers --------------------------------------------------------------------------------
    def _mist_inventory_state(self) -> dict[str, Any]:
        state = getattr(self, "_mist_inv", None)
        if state is None:
            state = {"lock": threading.Lock(), "devices": {}, "sites": {}}
            self._mist_inv = state
        return state

    def _console_url(self, *, site_id: str = "", device_type: str = "", device_id: str = "", mac: str = "") -> str:
        from app.modules.history.activity import mist_device_url

        settings = getattr(self.client, "settings", None)  # type: ignore[attr-defined]
        return mist_device_url(
            str(getattr(settings, "api_host", "") or ""),
            str(getattr(settings, "org_id", "") or ""),
            site_id=site_id,
            device_type=device_type,
            device_id=device_id,
            mac=mac,
        )

    def _site_rows(self) -> list[dict]:
        rows = self.call(self.client.list_sites, "list sites")  # type: ignore[attr-defined]
        return [r for r in rows or [] if isinstance(r, dict) and r.get("id")]

    def _site_names(self) -> dict[str, str]:
        state = self._mist_inventory_state()
        if not state["sites"]:
            state["sites"] = {str(r["id"]): _text(r.get("name")) for r in self._site_rows()}
        return state["sites"]

    def _resolve_site_id(self, site_key: str | None) -> str | None:
        """Accept a vendor-neutral site key or a raw Mist site id."""
        if not site_key:
            return None
        names = self._site_names()
        if site_key in names:
            return site_key
        for sid in names:
            if mist_site_key(sid) == site_key:
                return sid
        # Sites may have been added since the cache was filled.
        self._mist_inventory_state()["sites"] = {}
        for sid in self._site_names():
            if mist_site_key(sid) == site_key:
                return sid
        return None

    def _device_from_stats(self, row: dict, site_names: dict[str, str]) -> Device:
        dtype = _text(row.get("type")).lower()
        mac = normalize_mac(row.get("mac"))
        device_id = _text(row.get("id"))
        site_id = _text(row.get("site_id"))
        members = []
        for m in row.get("module_stat") or []:
            if not isinstance(m, dict):
                continue
            fpc = m.get("fpc_idx", m.get("idx"))
            if fpc is None and not m.get("serial"):
                continue
            members.append(
                {
                    "index": fpc,
                    "role": _text(m.get("vc_role")),
                    "model": _text(m.get("model")),
                    "serial": _text(m.get("serial")),
                    "mac": normalize_mac(m.get("mac")),
                    "version": _text(m.get("version")),
                }
            )
        if len(members) < 2 and not row.get("vc_mac"):
            members = []  # a stand-alone switch is not a stack
        ip = _text(row.get("ip"))
        if not ip and isinstance(row.get("ip_stat"), dict):
            ip = _text(row["ip_stat"].get("ip"))
        status = MIST_STATUS.get(_text(row.get("status")).lower(), "unknown")
        return Device(
            key=mist_device_key(mac, device_id),
            source="mist",
            name=_text(row.get("name") or row.get("hostname"))
            or (mac and ":".join(mac[i : i + 2] for i in range(0, 12, 2))),
            role=MIST_ROLES.get(dtype, "unknown"),
            native_id=device_id,
            site_key=mist_site_key(site_id) if site_id else "",
            site_name=site_names.get(site_id, ""),
            vendor_name="Juniper",
            model=_text(row.get("model")),
            serial=_text(row.get("serial")),
            mac=mac,
            mgmt_ip=ip,
            os_version=_text(row.get("version")),
            status=status,
            last_seen=_num(row.get("last_seen")),
            uptime_s=_num(row.get("uptime")),
            members=members,
            console_url=self._console_url(site_id=site_id, device_type=dtype, device_id=device_id, mac=mac),
            alias_macs=[normalize_mac(row.get("vc_mac"))] if normalize_mac(row.get("vc_mac")) else [],
            floor_key=_text(row.get("map_id")),
            vendor={"mist_type": dtype, "mist_site_id": site_id, "mist_device_id": device_id}
            | ({"vc_mac": normalize_mac(row.get("vc_mac"))} if row.get("vc_mac") else {}),
        )

    def _remember(self, devices: list[Device]) -> None:
        state = self._mist_inventory_state()
        with state["lock"]:
            for d in devices:
                state["devices"][d.key] = {
                    "site_id": d.vendor.get("mist_site_id", ""),
                    "device_id": d.native_id,
                    "type": d.vendor.get("mist_type", ""),
                    "mac": d.mac,
                    "name": d.name,
                }

    def _device_ref(self, device_key: str) -> dict[str, Any] | None:
        state = self._mist_inventory_state()
        ref = state["devices"].get(device_key)
        if ref is None:
            self.list_devices()
            ref = state["devices"].get(device_key)
        return ref

    # ---- INVENTORY ------------------------------------------------------------------------------
    def list_sites(self) -> list[Site]:
        rows = self._site_rows()
        self._mist_inventory_state()["sites"] = {str(r["id"]): _text(r.get("name")) for r in rows}
        out = []
        for r in rows:
            sid = str(r["id"])
            out.append(
                Site(
                    key=mist_site_key(sid),
                    source="mist",
                    name=_text(r.get("name")) or sid,
                    native_id=sid,
                    address=_text(r.get("address")),
                    timezone=_text(r.get("timezone")),
                    vendor={"country_code": _text(r.get("country_code"))} if r.get("country_code") else {},
                )
            )
        return out

    def list_devices(self, site_key: str | None = None) -> list[Device]:
        site_id = self._resolve_site_id(site_key) if site_key else None
        if site_key and not site_id:
            return []
        client = self.client  # type: ignore[attr-defined]
        rows = self.call(lambda: client.list_org_device_stats("all", site_id=site_id), "read device statistics")
        site_names = self._site_names()
        devices = [self._device_from_stats(r, site_names) for r in rows or [] if isinstance(r, dict)]
        self._remember(devices)
        return devices

    # ---- INTERFACES -----------------------------------------------------------------------------
    def list_interfaces(self, device_key: str) -> list[Interface]:
        ref = self._device_ref(device_key)
        if not ref or not ref.get("site_id") or not ref.get("device_id"):
            return []
        if ref["type"] == "switch":
            return self._switch_interfaces(device_key, ref)
        return self._device_stat_interfaces(device_key, ref)

    def _switch_interfaces(self, device_key: str, ref: dict[str, Any]) -> list[Interface]:
        from app.services.operations_service import get_switch_ports

        client = self.client  # type: ignore[attr-defined]
        data = self.call(
            lambda: get_switch_ports(ref["site_id"], ref["device_id"], client, include_clients=False),
            "read switch ports",
        )
        out = []
        for p in data.get("ports") or []:
            port_id = _text(p.get("port_id"))
            if not port_id or p.get("internal"):
                continue
            vlan = p.get("vlan_id")
            try:
                vlans = [int(vlan)] if vlan not in (None, "") else []
            except (TypeError, ValueError):
                vlans = []
            full = p.get("full_duplex")
            out.append(
                Interface(
                    key=stable_key(device_key, port_id),
                    source="mist",
                    device_key=device_key,
                    name=port_id,
                    kind=_interface_kind(port_id),
                    admin_up=not bool(p.get("admin_disabled")),
                    oper_up=bool(p.get("up")),
                    speed_mbps=p.get("speed_mbps"),
                    duplex="" if full is None else ("full" if full else "half"),
                    mac=normalize_mac(p.get("port_mac")),
                    ips=[str(x) for x in p.get("ips") or []],
                    vlans=vlans,
                    lag_parent=_text(p.get("lag_parent")),
                    role=_PORT_ROLE.get(_text(p.get("usage")).lower(), ""),
                    description=_text(p.get("description")),
                    poe_watts=p.get("poe_watts"),
                    rx_errors=int(p["rx_errors"]) if p.get("rx_errors") is not None else None,
                    tx_errors=int(p["tx_errors"]) if p.get("tx_errors") is not None else None,
                    vendor={
                        k: p.get(k)
                        for k in ("usage", "stp_state", "poe_on", "err_disabled", "xcvr_model", "last_flapped")
                        if p.get(k) not in (None, "", [], {})
                    },
                )
            )
        return out

    def _device_stat_interfaces(self, device_key: str, ref: dict[str, Any]) -> list[Interface]:
        """APs (port_stat) and gateways (if_stat / port_stat) from GET /sites/{id}/stats/devices/{id}."""
        client = self.client  # type: ignore[attr-defined]
        stats = self.call(
            lambda: client.get_site_device_stats(ref["site_id"], ref["device_id"]), "read device statistics"
        )
        out: dict[str, Interface] = {}
        for name, row in (stats.get("port_stat") or {}).items() if isinstance(stats.get("port_stat"), dict) else []:
            if not isinstance(row, dict):
                continue
            full = row.get("full_duplex")
            out[name] = Interface(
                key=stable_key(device_key, name),
                source="mist",
                device_key=device_key,
                name=str(name),
                kind="physical",
                oper_up=bool(row.get("up")) if row.get("up") is not None else None,
                speed_mbps=_num(row.get("speed")),
                duplex="" if full is None else ("full" if full else "half"),
                rx_errors=int(row["rx_errors"]) if isinstance(row.get("rx_errors"), (int, float)) else None,
                tx_errors=int(row["tx_errors"]) if isinstance(row.get("tx_errors"), (int, float)) else None,
            )
        for name, row in (stats.get("if_stat") or {}).items() if isinstance(stats.get("if_stat"), dict) else []:
            if not isinstance(row, dict) or name in out:
                continue
            vlan = row.get("vlan")
            out[name] = Interface(
                key=stable_key(device_key, name),
                source="mist",
                device_key=device_key,
                name=str(name),
                kind="vlan" if vlan else "logical",
                oper_up=bool(row.get("up")) if row.get("up") is not None else None,
                ips=[str(x) for x in row.get("ips") or []],
                vlans=[int(vlan)] if isinstance(vlan, int) else [],
                description=_text(row.get("network_name")),
                vendor={"port_id": _text(row.get("port_id"))} if row.get("port_id") else {},
            )
        return list(out.values())

    # ---- EVENTS ---------------------------------------------------------------------------------
    def list_events(self, site_key: str | None = None, *, hours: int = 24) -> list[Event]:
        hours = max(1, min(int(hours or 24), 24 * 7))
        client = self.client  # type: ignore[attr-defined]
        site_id = self._resolve_site_id(site_key) if site_key else None
        if site_key and not site_id:
            return []
        if site_id:
            rows = self.call(
                lambda: client.search_site_device_events(site_id, duration=f"{hours}h", limit=_EVENT_LIMIT),
                "search device events",
            )
        else:
            rows = self.call(
                lambda: client.search_org_device_events_window(duration=f"{hours}h", limit=_EVENT_LIMIT),
                "search device events",
            )
        directory: dict[str, dict] = {}
        try:
            directory = client.device_directory() or {}
        except Exception:  # noqa: BLE001 - names are a nicety; events still come back
            directory = {}
        out = []
        for r in rows or []:
            if not isinstance(r, dict):
                continue
            etype = _text(r.get("type")) or "EVENT"
            ts = _num(r.get("timestamp"))
            if ts is None:
                continue
            mac = normalize_mac(r.get("mac"))
            port = _text(r.get("port_id"))
            sid = _text(r.get("site_id")) or (site_id or "")
            known = directory.get(mac, {}) if mac else {}
            out.append(
                Event(
                    key=stable_key("mist", etype, mac, ts, port, _text(r.get("text"))[:80]),
                    source="mist",
                    type=etype,
                    timestamp=ts,
                    severity=event_severity(etype),
                    text=_text(r.get("text")) or etype.replace("_", " ").title(),
                    site_key=mist_site_key(sid) if sid else "",
                    device_key=mist_device_key(mac, known.get("id", "")) if mac else "",
                    device_name=_text(r.get("device_name")) or _text(known.get("name")),
                    interface=port,
                    vendor={"device_type": _text(r.get("device_type"))} if r.get("device_type") else {},
                )
            )
        return out
