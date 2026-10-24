from __future__ import annotations

import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Any

from app.core.auth import PORTS_WRITE, require
from app.modules.system.presence import holds_exit
from app.services.audit_service import AuditService
from app.services.detective_service import clean_mac, display_mac
from app.services.mist_client import MistApiError, MistClient, get_mist_client
from app.services.validation_service import run_validation


# Port names that carry inter-switch, Virtual Chassis or management traffic.
# Changing them can isolate the switch or a whole stack, so they need an explicit override.
_PROTECTED_PORT_PATTERN = re.compile(r"^(vcp-|ae\d|me\d|em\d|fxp\d|irb|vme|bme|lo\d|jsrv)", re.IGNORECASE)
_PROTECTED_USAGES = {"uplink", "vc", "vcp", "wan", "inet", "trunk"}
_ALLOWED_SPEEDS = {"auto", "10m", "100m", "1g", "2.5g", "5g", "10g", "25g", "40g", "100g"}
_ALLOWED_DUPLEX = {"auto", "full", "half"}
_BUILTIN_USAGES = {"default", "disabled"}
# Junos interface names: ge-0/0/12, xe-1/2/0, vcp-255/1/0, ae0, me0, irb.100
# Junos interface names: ge-0/0/12, xe-1/2/0:3 (channelized), vcp-255/1/0, ae0, me0, irb.100
_PORT_ID_PATTERN = re.compile(
    r"^[a-z]{2,4}-\d{1,3}/\d{1,3}/\d{1,3}(?::\d{1,2})?(?:\.\d{1,5})?$|^[a-z]{2,4}\d{0,3}(?:\.\d{1,5})?$",
    re.IGNORECASE,
)
_MAX_DESCRIPTION = 128
# Port settings the configuration panel can read and write (Mist device port_config keys).
#   critical            = "Up / Down Port Alerts"
#   no_local_overwrite  = NOT "Allow switch port operator to modify port profile"
#   dynamic_usage       = "Enable Dynamic Port Configuration" ("dynamic")
_PORT_CFG_FIELDS = (
    "usage",
    "description",
    "critical",
    "dynamic_usage",
    "no_local_overwrite",
    "aggregated",
    "ae_idx",
    "disabled",
    "poe_disabled",
    "speed",
    "duplex",
)
_MAX_PORTS_PER_CHANGE = 96


class PortActionError(ValueError):
    """Rejected port action; the message is safe to show to the user."""


def _num(value: Any) -> float | None:
    try:
        if value in (None, ""):
            return None
        return float(value)
    except (TypeError, ValueError):
        return None


# Junos/EVO internal, management and pseudo interfaces. They are real interfaces but
# are never patched to an endpoint, so the Port Toolkit hides them by default.
_INTERNAL_PORT_PATTERN = re.compile(
    r"^(bme|vme|jsrv|em\d|me\d|fxp|lo\d|pfe-|pfh-|esi|dsc|gr-|ip-|lsi|mtun|pim|pip|tap|vtep|cbp|demux|"
    r"rbeb|fti|lt-|mt-|sp-|vt-|ut-|pd-|pe-|pp\d|ppd|ppe|st\d|gre|ipip|eth\d|lc-)",
    re.IGNORECASE,
)
_SEARCH_LIMIT = 2000
_CLIENT_LIMIT = 1000


def is_internal_port(port_id: str) -> bool:
    return bool(_INTERNAL_PORT_PATTERN.match(str(port_id or "").strip()))


def speed_mbps(value: Any) -> float | None:
    """Mist reports port speed in Mbps (1000); older payloads may carry "1G"/"10Gbps"."""
    number = _num(value)
    if number is not None:
        return number if number > 0 else None
    match = re.match(r"^\s*([0-9]+(?:\.[0-9]+)?)\s*([mgt])?", str(value or ""), re.IGNORECASE)
    if not match:
        return None
    number = float(match.group(1))
    unit = (match.group(2) or "m").lower()
    return number * {"m": 1, "g": 1000, "t": 1_000_000}[unit] or None


def format_speed(mbps: float | None) -> str:
    if not mbps:
        return ""
    if mbps < 1000:
        return f"{mbps:g}M"
    return f"{round(mbps / 1000, 2):g}G"


def _as_list(value: Any) -> list:
    if value in (None, ""):
        return []
    if isinstance(value, (list, tuple, set)):
        return [x for x in value if x not in (None, "")]
    return [value]


def _first(value: Any) -> Any:
    items = _as_list(value)
    return items[0] if items else ""


def _port_rows(stats: dict, searched: list[dict] | None = None, *, switch_mac: str = "") -> list[dict]:
    rows: list[dict] = []
    ports = stats.get("ports") if isinstance(stats, dict) else None
    if isinstance(ports, list):
        rows.extend(x for x in ports if isinstance(x, dict))
    for key in ("port_stat", "port_stats"):
        table = stats.get(key) if isinstance(stats, dict) else None
        if isinstance(table, dict):
            for pid, data in table.items():
                if isinstance(data, dict):
                    rows.append({"port_id": pid, **data})
    # The port search is the most detailed and current source, so it is applied last.
    if searched:
        rows.extend(x for x in searched if isinstance(x, dict))
    out: dict[str, dict] = {}
    for row in rows:
        pid = str(row.get("port_id") or row.get("name") or "").strip()
        if not pid:
            continue
        current = out.setdefault(pid, {})
        current.update({k: v for k, v in row.items() if v not in (None, "")})
        current["port_id"] = pid
    return [normalize_port(x, switch_mac=switch_mac) for _, x in sorted(out.items())]


_PHYS_PORT = re.compile(r"^(ge|mge|xe|et|mxe|ce|xle|fte)-(\d+)/(\d+)/(\d+)(?::(\d+))?$", re.IGNORECASE)
_LOGICAL_PORT = re.compile(r"^(irb|vlan|lo\d*)(\.\d+)?$", re.IGNORECASE)
_MGMT_PORT = re.compile(r"^(me\d|em\d|fxp\d|vme|bme\d*|re\d)", re.IGNORECASE)


def port_kind(port_id: str) -> str:
    """physical | lag | logical | management | vcp | internal | other (drives "not applicable" marks)."""
    pid = str(port_id or "").strip()
    if _PHYS_PORT.match(pid):
        return "physical"
    if re.match(r"^ae\d+$", pid, re.IGNORECASE):
        return "lag"
    if pid.lower().startswith("vcp-"):
        return "vcp"
    if _LOGICAL_PORT.match(pid):
        return "logical"
    if _MGMT_PORT.match(pid):
        return "management"
    if is_internal_port(pid):
        return "internal"
    return "other"


def _first_key(row: dict, *keys: str) -> Any:
    for key in keys:
        value = row.get(key)
        if value not in (None, ""):
            return value
    return None


def _not_applicable(port: dict) -> dict[str, str]:
    """Why a column is empty for this port: column key -> human reason (only for empty columns).

    Mist only reports PoE for PoE-capable copper ports, ``auth_state`` only for up ports with an
    802.1X authenticator role, and LLDP neighbors only on physical links, so a dash is usually
    "does not apply" rather than "missing".
    """
    kind = port["kind"]
    out: dict[str, str] = {}
    if kind == "lag":
        out["poe"] = "Aggregated (LAG) interface - PoE is delivered per member port"
        out["auth"] = "802.1X runs on access ports, never on a LAG"
        out["xcvr"] = "Transceivers sit in the member ports"
        if not port["mac"]:
            out["mac"] = "LLDP runs on the member links; no member reported a neighbor"
        if not port["neighbor_system_name"]:
            out["neighbor"] = "LLDP runs on the member links; no member reported a neighbor"
    elif kind in ("logical", "internal"):
        label = "Logical L3 (IRB/VLAN) interface" if kind == "logical" else "Internal Junos interface"
        out["poe"] = f"{label} - no PoE"
        out["auth"] = f"{label} - no 802.1X"
        out["mac"] = f"{label} - no cable, no LLDP neighbor"
        out["neighbor"] = out["mac"]
        out["xcvr"] = f"{label} - no transceiver"
        out["speed"] = f"{label} - the speed Junos reports is nominal, not a link speed"
    elif kind in ("management", "vcp"):
        label = "Management port" if kind == "management" else "Virtual Chassis port"
        out["poe"] = f"{label} - no PoE"
        out["auth"] = f"{label} - no 802.1X"
    if kind in ("physical", "other"):
        ptype = (_PHYS_PORT.match(port["port_id"]) or [None, ""])[1].lower()
        raw = port.get("raw") or {}
        if port["poe_disabled"]:
            out["poe"] = "PoE is disabled in the port configuration"
        elif ptype in ("xe", "et", "ce", "xle", "fte") and not any(
            k in raw for k in ("poe_on", "poe_mode", "power_draw")
        ):
            out["poe"] = "Fibre/DAC (SFP/QSFP) port - no PoE"
        elif "poe_on" not in raw and "poe_mode" not in raw and "power_draw" not in raw:
            out["poe"] = (
                "Port is down - no PoE delivered"
                if not port["up"]
                else "Mist reports no PoE data for this port (not PoE-capable)"
            )
        elif not port["poe_on"] and not port["poe_watts"]:
            out["poe"] = "PoE-capable but no powered device is drawing power"
        if not port["auth_state"]:
            out["auth"] = (
                "Port is down - Mist reports 802.1X state only for up ports"
                if not port["up"]
                else "Not an 802.1X port (no authenticator role / port_auth in its profile)"
            )
        if not port["mac"]:
            out["mac"] = (
                "Port is down - nothing connected"
                if not port["up"]
                else "No LLDP neighbor and no wired client learned on this port"
            )
        if not port["neighbor_system_name"]:
            out["neighbor"] = (
                "Port is down" if not port["up"] else "Connected device does not send LLDP (or has no hostname)"
            )
        if not port["xcvr_model"]:
            out["xcvr"] = "Copper port or no transceiver reported" if ptype in ("ge", "mge") else "No optic reported"
    return out


def normalize_port(row: dict, *, switch_mac: str = "") -> dict:
    poe_w = None
    for key in ("power_draw", "poe_usage", "poe_watts", "poe_power", "power"):
        poe_w = _num(row.get(key))
        if poe_w is not None:
            break
    neighbor = row.get("neighbor") if isinstance(row.get("neighbor"), dict) else {}
    own = clean_mac(switch_mac)
    neighbor_mac = clean_mac(row.get("neighbor_mac") or neighbor.get("mac") or "")
    if neighbor_mac == own:
        neighbor_mac = ""
    # In Mist port stats ``mac`` is the SWITCH MAC and ``port_mac`` the interface MAC.
    # Neither identifies what is plugged in, so neither is used for the MAC column.
    port_mac = clean_mac(row.get("port_mac") or "")
    if port_mac == own:
        port_mac = ""
    mbps = speed_mbps(row.get("speed"))
    rx_bps, tx_bps = _num(row.get("rx_bps")), _num(row.get("tx_bps"))
    utilisation = None
    if mbps and (rx_bps is not None or tx_bps is not None):
        utilisation = round(max(rx_bps or 0, tx_bps or 0) / (mbps * 1_000_000) * 100, 1)
    port_id = str(row.get("port_id") or "")
    phys = _PHYS_PORT.match(port_id)
    rx_err, tx_err = _num(row.get("rx_errors")), _num(row.get("tx_errors"))
    crc = _num(_first_key(row, "rx_fcserrors", "rx_fcs_errors", "rx_crc_errors", "crc_errors", "fcs_errors"))
    port = {
        "port_id": port_id,
        "kind": port_kind(port_id),
        "fpc": int(phys.group(2)) if phys else None,
        "pic": int(phys.group(3)) if phys else None,
        "up": bool(row.get("up")),
        "speed": format_speed(mbps),
        "speed_mbps": mbps,
        "full_duplex": row.get("full_duplex"),
        "poe_on": bool(row.get("poe_on")),
        "poe_disabled": bool(row.get("poe_disabled")),
        "poe_mode": row.get("poe_mode") or "",
        "poe_priority": row.get("poe_priority") or "",
        "poe_watts": poe_w,
        "auth_state": row.get("auth_state") or "",
        "stp_state": row.get("stp_state") or "",
        "stp_role": row.get("stp_role") or "",
        "mac": display_mac(neighbor_mac),
        "port_mac": display_mac(port_mac),
        "neighbor_system_name": row.get("neighbor_system_name") or neighbor.get("system_name") or "",
        "neighbor_port_desc": row.get("neighbor_port_desc") or neighbor.get("port_desc") or "",
        "neighbor_mac": display_mac(neighbor_mac),
        "manufacturer": row.get("manufacturer")
        or row.get("vendor")
        or neighbor.get("manufacturer")
        or neighbor.get("vendor")
        or "",
        "client_mac": "",
        "client_hostname": row.get("hostname") or row.get("client_hostname") or "",
        "client_manufacturer": "",
        "client_ip": "",
        "client_count": 0,
        "clients": [],
        "vlan_id": row.get("vlan_id") or row.get("vlan") or "",
        "usage": row.get("usage") or row.get("port_usage") or "",
        "description": row.get("description") or row.get("port_desc") or "",
        "rx_bytes": row.get("rx_bytes") or row.get("rx_octets") or 0,
        "tx_bytes": row.get("tx_bytes") or row.get("tx_octets") or 0,
        "rx_pkts": _num(row.get("rx_pkts")),
        "tx_pkts": _num(row.get("tx_pkts")),
        "rx_bps": rx_bps,
        "tx_bps": tx_bps,
        "rx_errors": rx_err,
        "tx_errors": tx_err,
        "crc_errors": crc,
        "rx_bcast_pkts": _num(row.get("rx_bcast_pkts")),
        "tx_bcast_pkts": _num(row.get("tx_bcast_pkts")),
        "rx_mcast_pkts": _num(row.get("rx_mcast_pkts")),
        "tx_mcast_pkts": _num(row.get("tx_mcast_pkts")),
        "utilisation_pct": utilisation,
        "mac_count": _num(row.get("mac_count")),
        "mac_limit": _num(row.get("mac_limit")),
        "mtu": _num(row.get("mtu")),
        "poe_class": str(_first_key(row, "poe_class", "poe_device_class") or ""),
        "poe_status": str(_first_key(row, "poe_status", "poe_state", "poe_oper_status") or ""),
        "poe_max_watts": _num(_first_key(row, "poe_max_power", "poe_max", "max_power")),
        "neighbor_mgmt_ip": str(
            _first_key(row, "neighbor_mgmt_addr", "neighbor_mgmt_ip", "neighbor_ip") or neighbor.get("mgmt_addr") or ""
        ),
        "neighbor_system_desc": str(row.get("neighbor_system_desc") or neighbor.get("system_desc") or ""),
        "active": row.get("active"),
        "admin_disabled": bool(row.get("disabled")) or str(row.get("usage") or row.get("port_usage")) == "disabled",
        "err_disabled": _err_disabled(row),
        "xcvr_model": row.get("xcvr_model") or "",
        "xcvr_serial": row.get("xcvr_serial") or "",
        "xcvr_part_number": row.get("xcvr_part_number") or "",
        "last_flapped": _num(row.get("last_flapped")),
        "internal": is_internal_port(port_id),
        "lag_parent": "",
        "lag_members": [],
        "lag_neighbors": [],
        "ips": [],
        "networks": [],
        "issues": [],
        "raw": row,
    }
    port["not_applicable"] = _not_applicable(port)
    return port


def _err_disabled(row: dict) -> str:
    """Reason text when Mist reports the port error-disabled / blocked by a protection feature."""
    for key in ("err_disabled", "errdisable", "err_disable", "error_disabled", "disabled_reason", "err_reason"):
        value = row.get(key)
        if value in (None, "", False, 0):
            continue
        return str(value) if not isinstance(value, bool) else "err-disabled"
    role = str(row.get("stp_role") or "").lower()
    if role in ("root-prevented", "loop-inconsistent", "bpdu-inconsistent"):
        return f"STP {role}"
    return ""


def _wired_client_entries(rows: list[dict], switch_mac: str) -> list[tuple[str, dict]]:
    """(port_id, client) pairs from Mist wired-client search rows or switch stats ``clients``."""
    own = clean_mac(switch_mac)
    out = []
    for row in rows or []:
        if not isinstance(row, dict):
            continue
        mac = clean_mac(_first(row.get("mac")))
        if not mac or mac == own:
            continue
        client = {
            "mac": display_mac(mac),
            "hostname": str(_first(row.get("hostname")) or ""),
            "manufacturer": str(row.get("manufacture") or row.get("manufacturer") or row.get("vendor") or ""),
            "ip": str(_first(row.get("ip")) or ""),
            "vlan": str(_first(row.get("vlan")) or _first(row.get("vlan_id")) or ""),
            "last_seen": _num(row.get("last_seen")) or _num(row.get("timestamp")),
        }
        for pid in _as_list(row.get("port_id")) + _as_list(row.get("port_ids")):
            out.append((str(pid).strip(), client))
    return out


def merge_wired_clients(ports: list[dict], rows: list[dict], switch_mac: str = "") -> list[dict]:
    by_port = {p["port_id"]: p for p in ports}
    for pid, client in _wired_client_entries(rows, switch_mac):
        port = by_port.get(pid)
        if port is None:
            continue
        existing = next((c for c in port["clients"] if c["mac"] == client["mac"]), None)
        if existing is None:
            port["clients"].append(dict(client))
        else:
            for key, value in client.items():
                if value and not existing.get(key):
                    existing[key] = value
    for port in ports:
        clients = port["clients"]
        if not clients:
            continue
        clients.sort(key=lambda c: -(c.get("last_seen") or 0))
        top = clients[0]
        port["client_count"] = len(clients)
        port["client_mac"] = top["mac"]
        port["client_hostname"] = port["client_hostname"] or next((c["hostname"] for c in clients if c["hostname"]), "")
        port["client_manufacturer"] = next((c["manufacturer"] for c in clients if c["manufacturer"]), "")
        port["client_ip"] = next((c["ip"] for c in clients if c["ip"]), "")
        if not port["vlan_id"]:
            port["vlan_id"] = next((c["vlan"] for c in clients if c["vlan"]), "")
        if not port["mac"]:
            port["mac"] = top["mac"]
    return ports


def _expand_port_key(key: str) -> list[str]:
    out = []
    for part in str(key).lower().replace(" ", "").split(","):
        match = _RANGE_KEY.match(part)
        if match:
            lo, hi = int(match.group(2)), int(match.group(3))
            if 0 <= hi - lo <= 128:
                out.extend(f"{match.group(1)}{n}" for n in range(lo, hi + 1))
        elif part:
            out.append(part)
    return out


def _lag_name(row: dict) -> str:
    if not row.get("aggregated"):
        return ""
    try:
        return f"ae{int(row.get('ae_idx'))}"
    except (TypeError, ValueError):
        return ""


def apply_lag_membership(ports: list[dict], port_config: dict) -> dict[str, list[str]]:
    """Mark LAG members (port_config ``aggregated: true`` + ``ae_idx``) and their aeN parent."""
    port_config = port_config if isinstance(port_config, dict) else {}
    members: dict[str, set[str]] = {}
    for key, row in port_config.items():
        if isinstance(row, dict) and _lag_name(row):
            members.setdefault(_lag_name(row), set()).update(_expand_port_key(key))
    for port in ports:
        for row in _port_config_rows(port["port_id"], port_config):
            if _lag_name(row):
                members.setdefault(_lag_name(row), set()).add(port["port_id"].lower())
    parent_of = {m: ae for ae, items in members.items() for m in items}
    result = {ae: sorted(items, key=_port_sort_key) for ae, items in members.items()}
    for port in ports:
        pid = port["port_id"]
        port["lag_parent"] = parent_of.get(pid.lower(), "")
        port["lag_members"] = result.get(pid.lower(), [])
    return result


def aggregate_lag_neighbors(ports: list[dict]) -> None:
    """Give each aeN the LLDP neighbors of its member links (LLDP never runs on the ae itself)."""
    by_id = {p["port_id"].lower(): p for p in ports}
    for port in ports:
        if not port.get("lag_members"):
            continue
        rows = []
        for member in port["lag_members"]:
            mp = by_id.get(str(member).lower())
            rows.append(
                {
                    "member": mp["port_id"] if mp else member,
                    "up": mp["up"] if mp else None,
                    "speed": mp["speed"] if mp else "",
                    "system_name": mp["neighbor_system_name"] if mp else "",
                    "port_desc": mp["neighbor_port_desc"] if mp else "",
                    "mac": (mp["neighbor_mac"] or mp["mac"]) if mp else "",
                }
            )
        port["lag_neighbors"] = rows
        names = list(dict.fromkeys(r["system_name"] for r in rows if r["system_name"]))
        macs = list(dict.fromkeys(r["mac"] for r in rows if r["mac"]))
        if not port["neighbor_system_name"] and names:
            port["neighbor_system_name"] = ", ".join(names)
        if not port["neighbor_port_desc"]:
            port["neighbor_port_desc"] = ", ".join(f"{r['member']} → {r['port_desc']}" for r in rows if r["port_desc"])
        if not port["mac"] and macs:
            port["mac"] = macs[0]
            port["neighbor_mac"] = port["neighbor_mac"] or macs[0]


def apply_interface_stats(ports: list[dict], stats: dict) -> None:
    """Merge switch ``if_stat`` (IPs, VLAN/network per unit, e.g. irb.100) and any LLDP table."""
    by_id = {p["port_id"].lower(): p for p in ports}
    table = stats.get("if_stat") if isinstance(stats, dict) else None
    entries = list(table.items()) if isinstance(table, dict) else []
    for key, row in entries:
        if not isinstance(row, dict):
            continue
        pid = str(row.get("port_id") or key or "").lower()
        port = by_id.get(pid) or by_id.get(pid.split(".")[0])
        if port is None:
            continue
        for ip in _as_list(row.get("ips")):
            if str(ip) not in port["ips"]:
                port["ips"].append(str(ip))
        vlan, name = row.get("vlan"), row.get("network_name")
        label = f"{name}({vlan})" if name and vlan not in (None, "") else str(name or vlan or "")
        if label and label not in port["networks"]:
            port["networks"].append(label)
        if not port["vlan_id"] and vlan not in (None, "", 0) and port["kind"] != "logical":
            port["vlan_id"] = vlan
    for key in ("lldp_stat", "lldp_stats"):
        table = stats.get(key) if isinstance(stats, dict) else None
        rows = (
            [{"port_id": k, **v} for k, v in table.items() if isinstance(v, dict)]
            if isinstance(table, dict)
            else [x for x in table if isinstance(x, dict)]
            if isinstance(table, list)
            else []
        )
        for row in rows:
            port = by_id.get(str(row.get("local_port") or row.get("port_id") or "").lower())
            if port is None:
                continue
            if not port["neighbor_system_name"] and row.get("system_name"):
                port["neighbor_system_name"] = str(row["system_name"])
            if not port["neighbor_port_desc"] and (row.get("port_desc") or row.get("port_id_remote")):
                port["neighbor_port_desc"] = str(row.get("port_desc") or row.get("port_id_remote"))
            mgmt = _first(row.get("mgmt_addr") or row.get("mgmt_addrs") or row.get("management_address"))
            if not port["neighbor_mgmt_ip"] and mgmt:
                port["neighbor_mgmt_ip"] = str(mgmt)
            if not port["neighbor_system_desc"] and row.get("system_desc"):
                port["neighbor_system_desc"] = str(row["system_desc"])


def _port_sort_key(port_id: str) -> list:
    return [int(x) if x.isdigit() else x for x in re.split(r"(\d+)", port_id)]


def _apply_port_config(ports: list[dict], port_config: dict) -> None:
    port_config = port_config if isinstance(port_config, dict) else {}
    for port in ports:
        effective: dict[str, Any] = {}
        for row in _port_config_rows(port["port_id"], port_config):
            if not port["usage"] and row.get("usage"):
                port["usage"] = str(row["usage"])
            if not port["description"] and row.get("description"):
                port["description"] = str(row["description"])
            effective.update({k: row[k] for k in _PORT_CFG_FIELDS if k in row})
        # What this switch's own configuration sets for the port (site/template values are inherited).
        port["config"] = effective
        port["config_source"] = "switch" if effective else "inherited"


def list_switches(site_id: str, client: MistClient | None = None) -> list[dict]:
    client = client or get_mist_client()
    devices = client.list_site_devices(site_id, "switch")
    out = []
    for d in devices:
        if not isinstance(d, dict):
            continue
        out.append(
            {
                "id": str(d.get("id") or ""),
                "name": d.get("name") or d.get("hostname") or d.get("mac") or "Switch",
                "mac": clean_mac(d.get("mac")),
                "display_mac": display_mac(d.get("mac")),
                "model": d.get("model") or "",
                "serial": d.get("serial") or "",
            }
        )
    return out


def _search_switch_ports(client: MistClient, site_id: str, mac: str, fresh: bool) -> list[dict]:
    search = getattr(client, "search_switch_port_stats", None)
    if callable(search):
        return search(site_id, mac, limit=_SEARCH_LIMIT, fresh=fresh)
    return client.search_site_ports(site_id, device_type="switch", mac=mac, limit=_SEARCH_LIMIT)


def _search_wired_clients(client: MistClient, site_id: str, mac: str, fresh: bool) -> list[dict]:
    search = getattr(client, "search_org_wired_clients", None)
    if not callable(search):
        return []
    return search(site_id=site_id, device_mac=mac, duration="1d", limit=_CLIENT_LIMIT, fresh=fresh)


def get_switch_ports(
    site_id: str,
    device_id: str,
    client: MistClient | None = None,
    *,
    fresh: bool = False,
    include_clients: bool = True,
) -> dict:
    client = client or get_mist_client()
    with ThreadPoolExecutor(max_workers=3) as pool:
        f_cfg = pool.submit(client.get_site_device, site_id, device_id, fresh=fresh)
        f_stats = pool.submit(client.get_site_device_stats, site_id, device_id, fresh=fresh)
        config = f_cfg.result() or {}
        stats = f_stats.result() or {}
    mac = clean_mac(config.get("mac") or stats.get("mac"))
    warnings: list[str] = []
    searched: list[dict] = []
    wired: list[dict] = []
    if mac:
        with ThreadPoolExecutor(max_workers=2) as pool:
            f_ports = pool.submit(_search_switch_ports, client, site_id, mac, fresh)
            f_wired = pool.submit(_search_wired_clients, client, site_id, mac, fresh) if include_clients else None
            try:
                searched = f_ports.result() or []
            except MistApiError as exc:
                warnings.append(
                    f"Mist port statistics search failed ({exc}). Ports, speeds, PoE and neighbors may be "
                    "incomplete; press Refresh to retry."
                )
            if f_wired is not None:
                try:
                    wired = f_wired.result() or []
                except MistApiError as exc:
                    warnings.append(
                        f"Mist wired-client search failed ({exc}). Connected device hostnames and manufacturers "
                        "are not shown."
                    )
        if len(searched) >= _SEARCH_LIMIT:
            warnings.append(f"Mist returned the maximum of {_SEARCH_LIMIT} port rows; some ports may be missing.")
    else:
        # Without the switch MAC the port search would return every switch port in the
        # site, which must never be merged into this switch's view.
        warnings.append(
            "Mist did not report this switch's MAC address, so live per-port statistics could not be searched. "
            "Only the switch's own statistics are shown."
        )
    ports = _port_rows(stats, searched, switch_mac=mac)
    port_config = config.get("port_config") if isinstance(config.get("port_config"), dict) else {}
    _apply_port_config(ports, port_config)
    lags = apply_lag_membership(ports, port_config)
    stat_clients = stats.get("clients") if isinstance(stats.get("clients"), list) else []
    merge_wired_clients(ports, list(wired) + stat_clients, mac)
    apply_interface_stats(ports, stats)
    aggregate_lag_neighbors(ports)
    now = time.time()
    for port in ports:
        port["not_applicable"] = _not_applicable(port)
        port["issues"] = port_issues(port, now)
    members = []
    for m in stats.get("module_stat") or []:
        if not isinstance(m, dict) or m.get("fpc_idx", m.get("idx")) is None:
            continue
        poe = m.get("poe") if isinstance(m.get("poe"), dict) else {}
        members.append(
            {
                "fpc": int(m.get("fpc_idx", m.get("idx")) or 0),
                "role": str(m.get("vc_role") or ""),
                "model": str(m.get("model") or ""),
                "serial": str(m.get("serial") or ""),
                "poe_max_watts": _num(poe.get("max_power")),
                "poe_draw_watts": _num(poe.get("power_draw")),
            }
        )
    members.sort(key=lambda x: x["fpc"])
    return {
        "members": members,
        "switch": {
            "id": device_id,
            "name": config.get("name") or stats.get("name") or display_mac(mac),
            "mac": mac,
            "display_mac": display_mac(mac),
            "model": config.get("model") or stats.get("model") or "",
            "serial": config.get("serial") or stats.get("serial") or "",
            "version": stats.get("version") or config.get("version") or "",
            "status": stats.get("status") or "",
        },
        "ports": ports,
        "lags": lags,
        "warnings": warnings,
        "config": config,
        "stats": stats,
    }


def _target_ports(port_id: str, payload: dict | None) -> list[str]:
    ids = (payload or {}).get("port_ids")
    if isinstance(ids, list) and ids:
        out = []
        for value in ids:
            pid = str(value or "").strip()
            if pid and pid not in out:
                out.append(pid)
        if len(out) > _MAX_PORTS_PER_CHANGE:
            raise PortActionError(f"Change at most {_MAX_PORTS_PER_CHANGE} ports at a time")
        return out
    return [port_id] if port_id else []


def preview_port_action(site_id: str, device_id: str, port_id: str, action: str, payload: dict | None = None) -> dict:
    data = get_switch_ports(site_id, device_id)
    targets = _target_ports(port_id, payload) if action == "profile_update" else [port_id]
    port_id = targets[0] if targets else port_id
    port = next((p for p in data["ports"] if p["port_id"] == port_id), None)
    if not port:
        port = {"port_id": port_id, "up": None, "poe_on": None}
    warnings = []
    if action in {"bounce", "cable_test"}:
        warnings.append("This action can interrupt traffic on the selected switch port.")
    if action == "bounce" and port.get("poe_on"):
        warnings.append(
            "The port currently supplies PoE; bouncing the port can interrupt power to the attached device."
        )
    if action == "profile_update":
        warnings.append(
            "Port profile changes can change VLAN, authentication, PoE, and forwarding behavior inherited from the selected usage/profile."
        )
    by_id = {p["port_id"]: p for p in data["ports"]}
    protected_reason = ""
    for pid in targets:
        reason = _port_is_protected(pid, by_id.get(pid), data.get("config") or {})
        if reason:
            protected_reason = protected_reason or reason
            warnings.append(
                f"PROTECTED PORT: {pid} {reason.replace('it is', 'is', 1)}. Changing it can disconnect the switch or the whole stack."
            )
    if action == "profile_update" and (payload or {}).get("aggregated") is not None:
        protected_reason = protected_reason or "it changes link aggregation"
        warnings.append("Link aggregation changes can take the ports (and anything behind them) offline.")
    return {
        "action": action,
        "switch": data["switch"],
        "port": port,
        "payload": payload or {},
        "warnings": warnings,
        "requires_confirmation": True,
        "protected": bool(protected_reason),
    }


_RANGE_KEY = re.compile(r"^([a-z]{2,4}-\d{1,3}/\d{1,3}/)(\d{1,3})-(\d{1,3})$", re.IGNORECASE)


def _port_config_rows(port_id: str, port_config: dict) -> list[dict]:
    """All port_config entries that apply to ``port_id``.

    Mist accepts single ports ("ge-0/0/1"), comma lists ("ge-0/0/1,ge-0/0/2") and
    ranges ("ge-0/0/0-3") as keys, so an uplink defined by a range must still count.
    """
    rows = []
    wanted = port_id.lower()
    for key, row in port_config.items():
        if not isinstance(row, dict):
            continue
        for part in str(key).lower().replace(" ", "").split(","):
            if part == wanted:
                rows.append(row)
                break
            match = _RANGE_KEY.match(part)
            if match and wanted.startswith(match.group(1)):
                tail = wanted[len(match.group(1)) :]
                if tail.isdigit() and int(match.group(2)) <= int(tail) <= int(match.group(3)):
                    rows.append(row)
                    break
    return rows


def _port_is_protected(port_id: str, port: dict | None, config: dict) -> str:
    """Return a reason string when the port must not be changed without an override."""
    if _PROTECTED_PORT_PATTERN.match(port_id):
        return "it is an aggregated, Virtual Chassis or management interface"
    raw = (port or {}).get("raw") or {}
    if any(raw.get(flag) for flag in ("uplink", "is_uplink", "vc_port")):
        return "Mist reports it as an uplink/VC port"
    port_config = config.get("port_config") if isinstance(config.get("port_config"), dict) else {}
    for row in _port_config_rows(port_id, port_config):
        usage = str(row.get("usage") or "").lower()
        if usage in _PROTECTED_USAGES:
            return f"its current usage is '{usage}'"
        if row.get("aggregated") or row.get("ae_idx") is not None:
            return "it is a member of an aggregated link"
    return ""


def _allowed_usages(site_id: str, config: dict, client: MistClient) -> set[str]:
    usages = set(_BUILTIN_USAGES)
    for source in (config.get("port_usages"),):
        if isinstance(source, dict):
            usages.update(str(k) for k in source)
    port_config = config.get("port_config") if isinstance(config.get("port_config"), dict) else {}
    usages.update(str(row.get("usage")) for row in port_config.values() if isinstance(row, dict) and row.get("usage"))
    try:
        derived = client.get_site_setting_derived(site_id)
        if isinstance(derived.get("port_usages"), dict):
            usages.update(str(k) for k in derived["port_usages"])
    except MistApiError:
        pass
    return usages


def _validated_profile_patch(site_id: str, config: dict, payload: dict, client: MistClient) -> dict:
    patch: dict[str, Any] = {}
    if "usage" in payload and payload["usage"] not in (None, ""):
        usage = str(payload["usage"]).strip()
        allowed = _allowed_usages(site_id, config, client)
        if usage not in allowed:
            raise PortActionError(
                f"Unknown port usage '{usage}'. Defined usages for this switch/site: {', '.join(sorted(allowed))}"
            )
        if usage.lower() in _PROTECTED_USAGES and not payload.get("allow_protected_port") is True:
            raise PortActionError(
                f"Setting usage '{usage}' changes uplink behaviour and requires the protected-port override"
            )
        patch["usage"] = usage
    if "description" in payload and payload["description"] is not None:
        description = re.sub(r"[\x00-\x1f\x7f]", "", str(payload["description"])).strip()
        if len(description) > _MAX_DESCRIPTION:
            raise PortActionError(f"Port description must be at most {_MAX_DESCRIPTION} characters")
        patch["description"] = description
    if "speed" in payload and payload["speed"] not in (None, ""):
        speed = str(payload["speed"]).strip().lower()
        if speed not in _ALLOWED_SPEEDS:
            raise PortActionError(f"Unsupported speed '{speed}'. Allowed: {', '.join(sorted(_ALLOWED_SPEEDS))}")
        patch["speed"] = speed
    if "duplex" in payload and payload["duplex"] not in (None, ""):
        duplex = str(payload["duplex"]).strip().lower()
        if duplex not in _ALLOWED_DUPLEX:
            raise PortActionError("Duplex must be auto, full or half")
        patch["duplex"] = duplex
    for flag in ("poe_disabled", "disabled", "critical", "no_local_overwrite"):
        if flag in payload and payload[flag] is not None:
            if not isinstance(payload[flag], bool):
                raise PortActionError(f"{flag} must be true or false")
            patch[flag] = payload[flag]
    if "dynamic_usage" in payload and payload["dynamic_usage"] is not None:
        if not isinstance(payload["dynamic_usage"], bool):
            raise PortActionError("dynamic_usage must be true or false")
        patch["dynamic_usage"] = "dynamic" if payload["dynamic_usage"] else None  # None removes the key
    if "aggregated" in payload and payload["aggregated"] is not None:
        if not isinstance(payload["aggregated"], bool):
            raise PortActionError("aggregated must be true or false")
        if payload.get("allow_protected_port") is not True:
            raise PortActionError("Link aggregation changes require the protected-port override")
        patch["aggregated"] = payload["aggregated"]
        if payload["aggregated"]:
            try:
                ae_idx = int(payload.get("ae_idx"))
            except (TypeError, ValueError) as exc:
                raise PortActionError("An aggregated link needs an AE index (0-127)") from exc
            if not 0 <= ae_idx <= 127:
                raise PortActionError("AE index must be between 0 and 127")
            patch["ae_idx"] = ae_idx
        else:
            patch["ae_idx"] = None
    if not patch:
        raise PortActionError("No port settings to change")
    return patch


def _collapse_ports(ports: list[str]) -> list[str]:
    """['ge-0/0/1','ge-0/0/2','ge-0/0/3','ge-0/0/7'] -> ['ge-0/0/1-3', 'ge-0/0/7'] (Mist key syntax)."""
    groups: dict[str, list[int]] = {}
    singles: list[str] = []
    for pid in ports:
        m = re.match(r"^([a-z]{2,4}-\d{1,3}/\d{1,3}/)(\d{1,3})$", pid, re.IGNORECASE)
        if m:
            groups.setdefault(m.group(1), []).append(int(m.group(2)))
        else:
            singles.append(pid)
    out: list[str] = []
    for prefix, nums in groups.items():
        nums = sorted(set(nums))
        start = prev = nums[0]
        for n in nums[1:] + [None]:
            if n is not None and n == prev + 1:
                prev = n
                continue
            out.append(f"{prefix}{start}" if start == prev else f"{prefix}{start}-{prev}")
            if n is not None:
                start = prev = n
    return out + singles


def _safe_device_patch(config: dict, port_ids: str | list[str], patch: dict) -> dict:
    """New device ``port_config`` with ``patch`` applied to ``port_ids``.

    Mist rejects a port that appears under two keys, so a port inside an existing range or
    comma key ("ge-0/0/0-47") is split out of it first; the remaining ports keep their entry.
    The changed port starts from the settings it had under that key, then gets the patch.
    """
    targets = [port_ids] if isinstance(port_ids, str) else list(port_ids)
    wanted = {t.lower() for t in targets}
    port_config = config.get("port_config")
    if not isinstance(port_config, dict):
        port_config = {}
    new_table: dict[str, Any] = {}
    inherited: dict[str, dict] = {}
    for key, row in port_config.items():
        members = _expand_port_key(key)
        hit = [m for m in members if m in wanted]
        if not hit:
            new_table[key] = dict(row) if isinstance(row, dict) else row
            continue
        for m in hit:
            inherited[m] = dict(row) if isinstance(row, dict) else {}
        rest = [m for m in members if m not in wanted]
        for chunk in _collapse_ports(rest):
            new_table[chunk] = dict(row) if isinstance(row, dict) else row
    for pid in targets:
        row = dict(inherited.get(pid.lower()) or {})
        for key, value in patch.items():
            if key not in _PORT_CFG_FIELDS:
                continue
            if value is None:
                row.pop(key, None)
            else:
                row[key] = value
        new_table[pid] = row
    return {"port_config": new_table}


def _validate_port_target(before: dict, port_id: str, *, allow_protected: bool) -> dict:
    if not port_id or not _PORT_ID_PATTERN.match(port_id):
        raise PortActionError("A valid switch port ID (for example ge-0/0/12) is required")
    if not (before.get("switch") or {}).get("mac"):
        raise PortActionError("The switch MAC address is not reported by Mist, so its ports cannot be verified")
    port = next((p for p in before.get("ports") or [] if p.get("port_id") == port_id), None)
    if port is None:
        raise PortActionError(f"Port {port_id} does not exist on this switch")
    reason = _port_is_protected(port_id, port, before.get("config") or {})
    if reason and not allow_protected:
        raise PortActionError(
            f"Port {port_id} is protected because {reason}. Changing it can disconnect the switch or stack; "
            "resend with the protected-port override only if you are sure."
        )
    return port


def _pre_change_snapshot(site_id: str, device_id: str, reason: str) -> dict:
    """Config Backups safety snapshot right before a write. Never blocks the change."""
    try:
        from app.services import backup_service

        result = backup_service.snapshot_before_change(site_id, device_id, reason)
    except Exception as exc:  # noqa: BLE001 - a failed safety snapshot must not block a confirmed change
        return {"ok": False, "error": type(exc).__name__}
    return {k: result.get(k) for k in ("ok", "snapshot", "skipped", "reason", "error") if k in result}


@holds_exit
def execute_port_action(
    site_id: str, device_id: str, port_id: str, action: str, *, confirmed: bool, payload: dict | None = None
) -> dict:
    require(PORTS_WRITE)  # v0.10.22: per-person permission (desktop: always granted)
    if confirmed is not True:
        raise PortActionError("Explicit confirmation is required")
    if action not in {"bounce", "cable_test", "profile_update"}:
        raise PortActionError("Unsupported port action")
    payload = payload if isinstance(payload, dict) else {}
    allow_protected = payload.get("allow_protected_port") is True
    client = get_mist_client()
    before = get_switch_ports(site_id, device_id, client, fresh=True)
    targets = _target_ports(port_id, payload) if action == "profile_update" else [port_id]
    if not targets:
        raise PortActionError("Select at least one port")
    for target in targets:
        _validate_port_target(before, target, allow_protected=allow_protected)
    port_id = targets[0]
    audit = AuditService()
    response: Any
    request: dict
    safety: dict | None = None
    if action == "bounce":
        request = {"ports": [port_id]}
        response = client.bounce_device_port(site_id, device_id, [port_id])
    elif action == "cable_test":
        request = {"port": port_id}
        response = client.cable_test_from_switch(site_id, device_id, port_id)
    else:
        patch = _validated_profile_patch(site_id, before.get("config") or {}, payload, client)
        request = _safe_device_patch(before.get("config") or {}, targets, patch)
        safety = _pre_change_snapshot(site_id, device_id, f"Port Toolkit: {', '.join(_collapse_ports(targets))}")
        response = client.update_site_device(site_id, device_id, request)
    time.sleep(0.8 if action != "profile_update" else 1.2)
    client.clear_cache_matching(
        f"/sites/{site_id}/stats/ports",
        f"/sites/{site_id}/stats/devices/{device_id}",
        f"/sites/{site_id}/devices/{device_id}",
    )
    try:
        after = get_switch_ports(site_id, device_id, client, fresh=True)
    except MistApiError:
        after = {}

    def port_of(state: dict) -> dict:
        found = [p for p in state.get("ports", []) if p.get("port_id") in targets]
        if len(targets) == 1:
            return found[0] if found else {}
        return {"ports": found}

    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tool": "port-operations",
        "action": action,
        "site_id": site_id,
        "device_id": device_id,
        "port_id": port_id,
        "port_ids": targets,
        "protected_override": allow_protected,
        "pre_change_snapshot": safety,
        "before": {"switch": before.get("switch"), "port": port_of(before)},
        "request": request,
        "response": response,
        "after": {"switch": after.get("switch"), "port": port_of(after)},
    }
    label = port_id if len(targets) == 1 else f"{port_id}+{len(targets) - 1}"
    path = audit.write(record, f"port_{action}_{device_id}_{label.replace('/', '-')}")
    validation = run_validation(site_id, device_id, label=f"port-{action}")
    message = (
        "Cable test command accepted by Mist. Detailed TDR results are asynchronous in Mist."
        if action == "cable_test"
        else "Action submitted to Mist, state re-queried, and post-change validation recorded."
    )
    return {
        "ok": True,
        "action": action,
        "response": response,
        "after": record["after"],
        "audit_file": path.name,
        "validation": validation,
        "pre_change_snapshot": safety,
        "message": message,
    }


def _usage_summary(usage: dict, networks: dict) -> str:
    """Mist-style one-line summary, e.g. "WAP(199), trunk, edge"."""

    def vlan(name: str) -> str:
        net = networks.get(name) if isinstance(networks, dict) else None
        vid = (net or {}).get("vlan_id") if isinstance(net, dict) else None
        return f"{name}({vid})" if vid not in (None, "") else name

    parts: list[str] = []
    if usage.get("port_network"):
        parts.append(vlan(str(usage["port_network"])))
    if usage.get("all_networks"):
        parts.append("all VLANs")
    elif isinstance(usage.get("networks"), list) and usage["networks"]:
        nets = [vlan(str(n)) for n in usage["networks"][:4]]
        parts.append(", ".join(nets) + (f" +{len(usage['networks']) - 4}" if len(usage["networks"]) > 4 else ""))
    if usage.get("mode"):
        parts.append(str(usage["mode"]))
    if usage.get("stp_edge"):
        parts.append("edge")
    if usage.get("port_auth"):
        parts.append(str(usage["port_auth"]))
    if usage.get("poe_disabled"):
        parts.append("PoE off")
    if usage.get("disabled"):
        parts.append("disabled")
    return ", ".join(parts)


def port_profiles(site_id: str, device_id: str, client: MistClient | None = None) -> list[dict]:
    """Port profiles (usages) that can be assigned on this switch, with a short summary."""
    client = client or get_mist_client()
    config = client.get_site_device(site_id, device_id) or {}
    try:
        derived = client.get_site_setting_derived(site_id) or {}
    except MistApiError:
        derived = {}
    usages: dict[str, dict] = {}
    networks: dict[str, Any] = {}
    for source in (derived, config):
        if isinstance(source.get("port_usages"), dict):
            usages.update({str(k): v for k, v in source["port_usages"].items() if isinstance(v, dict)})
        if isinstance(source.get("networks"), dict):
            networks.update(source["networks"])
    rows = [{"name": name, "summary": _usage_summary(u, networks)} for name, u in usages.items()]
    rows.sort(key=lambda r: r["name"].casefold())
    for builtin, text in (("default", "Mist default profile"), ("disabled", "Port disabled")):
        if builtin not in usages:
            rows.append({"name": builtin, "summary": text})
    return rows


# --------------------------------------------------------------------------- port health overview
# Categories in display order. Severity: critical > warning > info.
ISSUE_CATEGORIES: tuple[tuple[str, str, str], ...] = (
    ("uplink_down", "Uplink / LAG down", "Uplink, trunk or aggregated ports that are down"),
    ("err_disabled", "Err-disabled · loop · BPDU", "Ports shut or blocked by a protection feature"),
    ("errors", "CRC / input errors", "Ports with a significant interface error count"),
    ("flapping", "Flapping", "Link changed state in the last 15 minutes or Mist raised a flap alarm"),
    ("poe_fault", "PoE faults", "PoE denied, overloaded or faulted"),
    ("down_expected", "Down · expected up", "Ports that went down in the last 24 h or have up/down alerts enabled"),
    ("stp_blocked", "STP blocking", "Up ports that spanning tree is blocking"),
    ("duplex", "Half duplex / low speed", "Half-duplex links or gigabit ports negotiated at 10/100M"),
    ("auth_fail", "802.1X failures", "Ports whose authenticator is held / failed"),
    ("alarm", "Other port alarms", "Other port-related Mist alarms"),
)
_CATEGORY_ORDER = {key: i for i, (key, _, _) in enumerate(ISSUE_CATEGORIES)}
_CATEGORY_LABEL = {key: label for key, label, _ in ISSUE_CATEGORIES}
_SEVERITY_RANK = {"critical": 0, "warning": 1, "info": 2}
_FLAP_WINDOW = 15 * 60
_RECENT_DOWN_WINDOW = 24 * 3600
_ERROR_MIN = 100
_ERROR_RATE_WARN = 0.0001  # 0.01 % of packets
_ERROR_RATE_CRIT = 0.01  # 1 % of packets
_POE_FAULT = re.compile(r"fault|denied|overload|short|error|invalid|disabled-by|power-limit", re.IGNORECASE)
_AUTH_FAIL = {"held", "failed", "unauthenticated", "unauthorized", "auth-fail", "auth_fail"}
_UPLINK_USAGE = re.compile(r"uplink|trunk|core|distribution|vc\b|wan|inter.?switch|isl", re.IGNORECASE)


def _issue(key: str, severity: str, detail: str, **extra: Any) -> dict:
    return {"category": key, "label": _CATEGORY_LABEL[key], "severity": severity, "detail": detail, **extra}


def _ago(seconds: float) -> str:
    seconds = max(0, int(seconds))
    if seconds < 90:
        return f"{seconds} s ago"
    if seconds < 5400:
        return f"{seconds // 60} min ago"
    if seconds < 172800:
        return f"{seconds // 3600} h ago"
    return f"{seconds // 86400} days ago"


def port_issues(port: dict, now: float | None = None) -> list[dict]:
    """Health findings for one normalized port (empty for healthy, unused or logical ports)."""
    now = time.time() if now is None else now
    kind = port.get("kind") or port_kind(port.get("port_id", ""))
    if kind in ("logical", "internal", "management", "other"):
        return []
    out: list[dict] = []
    up = bool(port.get("up"))
    usage = str((port.get("config") or {}).get("usage") or port.get("usage") or "")
    admin_off = (
        bool(port.get("admin_disabled")) or usage == "disabled" or bool((port.get("config") or {}).get("disabled"))
    )
    flapped = _num(port.get("last_flapped"))
    if flapped and flapped > 1e12:
        flapped /= 1000
    since = (now - flapped) if flapped else None
    raw = port.get("raw") or {}

    if port.get("err_disabled"):
        out.append(_issue("err_disabled", "critical", f"Port blocked: {port['err_disabled']}"))

    if not up and not admin_off:
        is_uplink = (
            kind == "lag"
            or bool(_UPLINK_USAGE.search(usage))
            or bool(raw.get("uplink") or raw.get("is_uplink"))
            or (kind == "physical" and (port.get("pic") or 0) > 0 and since is not None and since < _RECENT_DOWN_WINDOW)
        )
        if kind == "vcp":
            if since is not None and since < _RECENT_DOWN_WINDOW:
                out.append(_issue("uplink_down", "critical", f"Virtual Chassis port down since {_ago(since)}"))
        elif is_uplink:
            when = f" since {_ago(since)}" if since is not None else ""
            what = "Aggregated link" if kind == "lag" else f"Uplink ({usage})" if usage else "Uplink-module port"
            out.append(_issue("uplink_down", "critical", f"{what} is down{when}"))
        elif since is not None and since < _RECENT_DOWN_WINDOW:
            out.append(_issue("down_expected", "warning", f"Went down {_ago(since)}"))
        elif (port.get("config") or {}).get("critical"):
            out.append(_issue("down_expected", "warning", "Down with Up/Down port alerts enabled"))
    elif up and since is not None and since < _FLAP_WINDOW and kind != "lag":
        out.append(_issue("flapping", "warning", f"Link changed state {_ago(since)}"))

    errors = sum(_num(port.get(k)) or 0 for k in ("rx_errors", "tx_errors"))
    crc = _num(port.get("crc_errors")) or 0
    total = max(errors, crc)
    if total >= _ERROR_MIN:
        pkts = (_num(port.get("rx_pkts")) or 0) + (_num(port.get("tx_pkts")) or 0)
        rate = total / pkts if pkts else None
        if rate is None or rate >= _ERROR_RATE_WARN:
            sev = "critical" if rate is not None and rate >= _ERROR_RATE_CRIT and total >= 1000 else "warning"
            parts = [f"{int(errors):,} errors"]
            if crc:
                parts.append(f"{int(crc):,} CRC")
            if rate is not None:
                parts.append(f"{rate * 100:.2f}% of packets")
            out.append(_issue("errors", sev, " · ".join(parts), value=total))

    poe_status = str(port.get("poe_status") or "")
    if poe_status and _POE_FAULT.search(poe_status):
        out.append(_issue("poe_fault", "warning", f"PoE {poe_status}"))

    if up:
        stp = str(port.get("stp_state") or "").lower()
        if stp in ("blocking", "discarding") and not port.get("err_disabled"):
            role = str(port.get("stp_role") or "")
            out.append(
                _issue(
                    "stp_blocked",
                    "warning" if role not in ("alternate", "backup") else "info",
                    f"STP {stp}{f' ({role})' if role else ''}",
                )
            )
        if port.get("full_duplex") is False:
            out.append(_issue("duplex", "warning", f"Half duplex at {port.get('speed') or 'unknown speed'}"))
        elif kind == "physical" and (_num(port.get("speed_mbps")) or 0) in (10, 100):
            out.append(_issue("duplex", "info", f"Gigabit-capable port negotiated at {port.get('speed')}"))
        auth = str(port.get("auth_state") or "").lower()
        if auth in _AUTH_FAIL:
            out.append(_issue("auth_fail", "warning", f"802.1X {auth}"))
    return out


# Mist alarm types that concern switch ports. AP / gateway / WAN alarms are excluded.
_PORT_ALARM = re.compile(
    r"port|flap|bpdu|loop|stp|storm|poe|optic|xcvr|transceiver|dot1x|802_?1x|radius|auth_fail|mtu|negotiat|"
    r"duplex|cable|mac_limit|lacp|uplink|\bae_|lag|err_?disabl|crc",
    re.IGNORECASE,
)
_NOT_SWITCH_ALARM = re.compile(r"^(ap_|gw_|gateway|wan|vpn|tunnel|bgp|ospf|ssr|mxedge|wlan|wifi|rogue)", re.IGNORECASE)
_PORT_IN_TEXT = re.compile(r"\b((?:ge|mge|xe|et|mxe|ce|vcp)-\d+/\d+/\d+(?::\d+)?|ae\d+)\b", re.IGNORECASE)
_ALARM_CATEGORY = (
    (re.compile(r"flap", re.I), "flapping"),
    (re.compile(r"loop|bpdu|stp|storm|err_?disabl|mac_limit", re.I), "err_disabled"),
    (re.compile(r"poe", re.I), "poe_fault"),
    (re.compile(r"dot1x|802_?1x|radius|auth", re.I), "auth_fail"),
    (re.compile(r"optic|xcvr|transceiver|crc|error|cable", re.I), "errors"),
    (re.compile(r"duplex|negotiat|mtu", re.I), "duplex"),
    (re.compile(r"uplink|lacp|\bae_|lag", re.I), "uplink_down"),
)


def _alarm_severity(value: Any) -> str:
    text = str(value or "").lower()
    if text in ("critical", "major", "high", "emergency", "alert"):
        return "critical"
    if text in ("info", "informational", "low", "notice"):
        return "info"
    return "warning"


def _alarm_text(row: dict) -> str:
    parts = []
    for key in ("reasons", "reason", "text", "message", "details"):
        value = row.get(key)
        if isinstance(value, list):
            parts.extend(str(x) for x in value if x)
        elif isinstance(value, dict):
            parts.extend(f"{k}: {v}" for k, v in value.items())
        elif value:
            parts.append(str(value))
    return "; ".join(parts)


_ACRONYMS = {
    "poe": "PoE",
    "dot1x": "802.1X",
    "radius": "RADIUS",
    **{w: w.upper() for w in ("bpdu", "stp", "mtu", "crc", "lacp", "vc", "ae", "lag", "mac", "dhcp", "sfp")},
}


def _alarm_title(atype: str) -> str:
    """ "sw_bpdu_error" -> "BPDU error"."""
    words = [w for w in re.sub(r"^(sw|switch)_", "", atype, flags=re.IGNORECASE).split("_") if w]
    text = " ".join(_ACRONYMS.get(w.lower(), w.lower()) for w in words)
    return text[:1].upper() + text[1:] if text else atype


def _alarm_issues(rows: list[dict], site_id: str | None) -> list[dict]:
    out = []
    for row in rows or []:
        if not isinstance(row, dict) or row.get("acked"):
            continue
        atype = str(row.get("type") or row.get("alarm_type") or "")
        if not atype or _NOT_SWITCH_ALARM.match(atype) or not _PORT_ALARM.search(atype):
            continue
        if site_id and str(row.get("site_id") or "") != site_id:
            continue
        text = _alarm_text(row)
        ports = [
            str(x) for x in _as_list(row.get("port_ids")) + _as_list(row.get("ports")) + _as_list(row.get("port_id"))
        ]
        if not ports:
            ports = list(dict.fromkeys(m.group(1) for m in _PORT_IN_TEXT.finditer(text)))
        macs = []
        for key in ("switches", "macs", "device_mac", "mac", "devices"):
            macs.extend(clean_mac(x) for x in _as_list(row.get(key)) if isinstance(x, str) and clean_mac(x))
        category = next((cat for pattern, cat in _ALARM_CATEGORY if pattern.search(atype)), "alarm")
        ts = _num(row.get("last_seen")) or _num(row.get("timestamp"))
        if ts and ts > 1e12:
            ts /= 1000
        title = _alarm_title(atype)
        count = row.get("count")
        detail = f"Mist alarm: {title}" + (f" (×{count})" if count not in (None, "", 0, 1) else "")
        if text:
            detail += f" - {text[:160]}"
        hostnames = [str(h) for h in _as_list(row.get("hostnames"))]
        for port_id in ports or [""]:
            out.append(
                {
                    **_issue(category, _alarm_severity(row.get("severity")), detail),
                    "source": "alarm",
                    "alarm_type": atype,
                    "site_id": str(row.get("site_id") or ""),
                    "switch_mac": macs[0] if macs else "",
                    "switch_name": hostnames[0] if hostnames else "",
                    "port_id": port_id,
                    "timestamp": ts,
                }
            )
    return out


# v0.10.53 (report perf #5): the org-wide port overview is expensive (an org port search over up to 20,000
# ports). Keep each build longer, and once it is stale serve the last one at once while one background thread
# refreshes it, so no page waits for a rebuild. A build older than TTL + grace is rebuilt in-line.
_OVERVIEW_TTL = 120.0
_OVERVIEW_STALE_GRACE = 600.0
_OVERVIEW_PORT_LIMIT = 20_000
_OVERVIEW_ISSUE_LIMIT = 1000
_overview_cache: dict[str, tuple[float, dict]] = {}
_overview_lock = threading.Lock()
_overview_refreshing: set[str] = set()


def _device_id_for_mac(mac: str) -> str:
    """Mist switch device IDs are derived from the MAC: 00000000-0000-0000-1000-<mac>."""
    return f"00000000-0000-0000-1000-{mac}" if re.fullmatch(r"[0-9a-f]{12}", mac or "") else ""


def port_overview(
    site_id: str | None = None, client: MistClient | None = None, *, fresh: bool = False, _force_build: bool = False
) -> dict:
    """Most important switch-port problems for the org (or one site), ranked by severity.

    Two Mist reads: the org (or site) port-stats search and the org alarm search (shared,
    cached with the dashboard). Site names and switch names come from cached lookups.
    """
    site_id = (site_id or "").strip() or None
    key = site_id or "*"
    now = time.time()
    if not fresh and not _force_build:
        with _overview_lock:
            hit = _overview_cache.get(key)
        if hit:
            built_at, value = hit
            age = now - built_at
            if age < _OVERVIEW_TTL:
                return {**value, "cached": True}
            if age < _OVERVIEW_TTL + _OVERVIEW_STALE_GRACE:
                _overview_refresh_in_background(key, site_id, client)
                return {**value, "cached": True, "stale": True}
    client = client or get_mist_client()
    if fresh:
        clearer = getattr(client, "clear_cache_matching", None)
        if callable(clearer):
            clearer("/stats/ports/search")
    warnings: list[str] = []
    failed = False
    # v0.10.40: the org read uses the unsorted, parallel-paged port search (rows are de-duplicated by
    # timestamp below, so Mist's sort was wasted work), and the name lookups run alongside the reads.
    with ThreadPoolExecutor(max_workers=4) as pool:
        if site_id:
            f_ports = pool.submit(client.search_site_ports, site_id, device_type="switch", limit=_OVERVIEW_PORT_LIMIT)
        elif callable(getattr(client, "search_ports_for_topology", None)):
            f_ports = pool.submit(client.search_ports_for_topology, device_type="switch", limit=_OVERVIEW_PORT_LIMIT)
        else:
            f_ports = pool.submit(client.search_org_ports, device_type="switch", limit=_OVERVIEW_PORT_LIMIT)
        f_alarms = pool.submit(client.search_org_alarms, fresh=fresh)
        f_sites = pool.submit(client.site_name_map) if callable(getattr(client, "site_name_map", None)) else None
        f_dir = pool.submit(client.device_directory) if callable(getattr(client, "device_directory", None)) else None
        try:
            rows = f_ports.result() or []
        except MistApiError as exc:
            rows, failed = [], True
            warnings.append(f"Mist port statistics search failed ({exc}).")
        try:
            alarms = f_alarms.result() or []
        except MistApiError as exc:
            alarms = []
            warnings.append(f"Mist alarm search failed ({exc}); only port statistics are used.")
    sites = f_sites.result() if f_sites else {}
    directory = f_dir.result() if f_dir else {}
    if len(rows) >= _OVERVIEW_PORT_LIMIT:
        warnings.append(f"Mist returned the maximum of {_OVERVIEW_PORT_LIMIT:,} port rows; some ports are not checked.")

    def switch_info(mac: str, fallback_name: str = "") -> tuple[str, str]:
        entry = directory.get(mac) or {}
        return entry.get("id") or _device_id_for_mac(mac), entry.get("name") or fallback_name or display_mac(mac)

    # Mist can return the same port more than once (history rows); keep the newest.
    latest: dict[tuple[str, str], dict] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        mac, pid = clean_mac(row.get("mac")), str(row.get("port_id") or "").strip()
        if not mac or not pid or (site_id and row.get("site_id") and str(row.get("site_id")) != site_id):
            continue
        prev = latest.get((mac, pid))
        if prev is None or (_num(row.get("timestamp")) or 0) >= (_num(prev.get("timestamp")) or 0):
            latest[(mac, pid)] = row

    issues: list[dict] = []
    totals = {"ports": 0, "up": 0, "down": 0, "poe_watts": 0.0}
    switches: dict[str, dict] = {}
    for (mac, pid), row in latest.items():
        port = normalize_port(row, switch_mac=mac)
        if port["kind"] in ("logical", "internal", "management", "other"):
            continue
        sid = str(row.get("site_id") or site_id or "")
        sw = switches.setdefault(mac, {"site_id": sid, "ports": 0, "up": 0})
        sw["ports"] += 1
        totals["ports"] += 1
        if port["up"]:
            totals["up"] += 1
            sw["up"] += 1
        else:
            totals["down"] += 1
        totals["poe_watts"] += port["poe_watts"] or 0
        for found in port_issues(port, now):
            issues.append({**found, "source": "stats", "site_id": sid, "switch_mac": mac, "port_id": pid})

    # Alarms that name a port already flagged in the same category are merged into that row.
    seen = {(i["switch_mac"], i["port_id"].lower(), i["category"]) for i in issues}
    for alarm in _alarm_issues(alarms, site_id):
        ident = (alarm["switch_mac"], alarm["port_id"].lower(), alarm["category"])
        if ident in seen and alarm["port_id"]:
            for i in issues:
                if (i["switch_mac"], i["port_id"].lower(), i["category"]) == ident:
                    i["detail"] += f" · {alarm['detail']}"
                    if _SEVERITY_RANK[alarm["severity"]] < _SEVERITY_RANK[i["severity"]]:
                        i["severity"] = alarm["severity"]
            continue
        seen.add(ident)
        issues.append(alarm)

    for item in issues:
        mac = item.get("switch_mac") or ""
        device_id, name = switch_info(mac, item.get("switch_name") or "")
        item["device_id"] = device_id
        item["switch_name"] = name if mac else item.get("switch_name") or "Unknown switch"
        item["site_name"] = sites.get(item.get("site_id") or "", "") or (
            "Unknown site" if not item.get("site_id") else item["site_id"]
        )
        item.setdefault("timestamp", None)
    issues.sort(
        key=lambda i: (
            _SEVERITY_RANK.get(i["severity"], 3),
            _CATEGORY_ORDER.get(i["category"], 99),
            i["site_name"].casefold(),
            i["switch_name"].casefold(),
            _port_sort_key(i["port_id"]),
        )
    )
    categories = []
    for cat_key, label, description in ISSUE_CATEGORIES:
        mine = [i for i in issues if i["category"] == cat_key]
        sev = min((i["severity"] for i in mine), key=lambda s: _SEVERITY_RANK.get(s, 3), default="info")
        categories.append(
            {
                "key": cat_key,
                "label": label,
                "description": description,
                "count": len(mine),
                "critical": sum(1 for i in mine if i["severity"] == "critical"),
                "severity": sev if mine else "ok",
            }
        )
    affected: dict[str, dict] = {}
    for item in issues:
        sw = affected.setdefault(
            item["switch_mac"] or item["switch_name"],
            {
                "site_id": item["site_id"],
                "site_name": item["site_name"],
                "device_id": item["device_id"],
                "switch_name": item["switch_name"],
                "switch_mac": item["switch_mac"],
                "critical": 0,
                "warning": 0,
                "info": 0,
            },
        )
        sw[item["severity"]] = sw.get(item["severity"], 0) + 1
    result = {
        "scope": "site" if site_id else "org",
        "site_id": site_id or "",
        "site_name": sites.get(site_id or "", "") if site_id else "",
        "generated_at": now,
        "cached": False,
        "totals": {
            **totals,
            "poe_watts": round(totals["poe_watts"], 1),
            "switches": len(switches),
            "sites": len({s["site_id"] for s in switches.values() if s["site_id"]}),
            "issues": len(issues),
            "critical": sum(1 for i in issues if i["severity"] == "critical"),
            "warning": sum(1 for i in issues if i["severity"] == "warning"),
            "info": sum(1 for i in issues if i["severity"] == "info"),
            "affected_switches": len(affected),
        },
        "categories": categories,
        "issues": issues[:_OVERVIEW_ISSUE_LIMIT],
        "truncated": max(0, len(issues) - _OVERVIEW_ISSUE_LIMIT),
        "switches": sorted(
            affected.values(), key=lambda s: (-s["critical"], -s["warning"], -s["info"], s["switch_name"].casefold())
        ),
        "warnings": warnings,
    }
    if not failed:  # never keep a failed read (store the build-completion time; read side computes its age)
        with _overview_lock:
            _overview_cache[key] = (time.time(), result)
    return result


def _overview_refresh_in_background(key: str, site_id: str | None, client: MistClient | None) -> None:
    """Rebuild one overview off the request thread (report perf #5). One refresh per key at a time; never raises."""
    from app.core.freshness import in_context

    with _overview_lock:
        if key in _overview_refreshing:
            return
        _overview_refreshing.add(key)

    def run() -> None:
        try:
            port_overview(site_id, client, fresh=False, _force_build=True)
        except Exception:  # noqa: BLE001 - a background refresh failure just keeps the stale value
            pass
        finally:
            with _overview_lock:
                _overview_refreshing.discard(key)

    threading.Thread(target=in_context(run), name=f"overview-refresh-{key}", daemon=True).start()
