from __future__ import annotations

import ipaddress
import json
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Any

from app.services.mist_client import MistApiError, MistClient, get_mist_client

_MAC_RE = re.compile(r"^[0-9a-fA-F]{12}$")


def clean_mac(value: Any) -> str:
    return re.sub(r"[^0-9a-fA-F]", "", str(value or "")).lower()


def display_mac(value: Any) -> str:
    mac = clean_mac(value)
    if len(mac) != 12:
        return str(value or "")
    return ":".join(mac[i : i + 2] for i in range(0, 12, 2))


def _first(item: dict, *names: str, default: Any = "") -> Any:
    for name in names:
        value = item.get(name)
        if value is not None and value != "":
            return value
    return default


def _scalar(value: Any, default: Any = "") -> Any:
    """Return a display/query-safe scalar from Mist fields that may be arrays.

    Wired-client search intentionally aggregates history and can return fields such as
    device_mac, port_id, vlan, and ip as lists. Passing the Python list rendering back
    to a Mist filter (for example ``port_id=['ge-0/0/18']``) will never match.
    """
    if isinstance(value, (list, tuple)):
        for item in value:
            unwrapped = _scalar(item, default=None)
            if unwrapped is not None and unwrapped != "":
                return unwrapped
        return default
    return default if value is None else value


def _first_scalar(item: dict, *names: str, default: Any = "") -> Any:
    return _scalar(_first(item, *names, default=default), default=default)


def _time_rank(value: Any) -> float:
    numeric = _as_epoch(value)
    if numeric:
        return numeric
    text = str(value or "").strip()
    if not text:
        return 0.0
    try:
        # Mist examples use offsets such as +0000; fromisoformat accepts them.
        return datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp()
    except Exception:
        return 0.0


def _wired_attachment(*payloads: dict) -> dict[str, Any]:
    """Resolve the most recent switch/port pairing from Mist wired-client data.

    Prefer the explicit ``device_mac_port`` relationship because the top-level
    ``device_mac`` and ``port_id`` fields can independently contain historical arrays.
    The relationship preserves which port belongs to which switch.
    """
    relationships: list[dict] = []
    for payload in payloads:
        if not isinstance(payload, dict):
            continue
        rows = payload.get("device_mac_port")
        if isinstance(rows, dict):
            rows = [rows]
        if isinstance(rows, list):
            relationships.extend(row for row in rows if isinstance(row, dict))
    if relationships:
        row = max(
            relationships,
            key=lambda x: max(
                _time_rank(x.get("when")),
                _time_rank(x.get("last_seen")),
                _time_rank(x.get("timestamp")),
                _time_rank(x.get("start")),
            ),
        )
        return {
            "device_mac": clean_mac(_first_scalar(row, "device_mac", "switch_mac")),
            "port_id": str(_first_scalar(row, "port_id")),
            "vlan": _first_scalar(row, "vlan", "vlan_id"),
            "ip": _first_scalar(row, "ip", "ip_address"),
            "source": "device_mac_port",
        }

    for payload in payloads:
        if not isinstance(payload, dict):
            continue
        device_mac = clean_mac(_first_scalar(payload, "device_mac", "switch_mac"))
        port_id = str(_first_scalar(payload, "port_id"))
        if device_mac or port_id:
            return {
                "device_mac": device_mac,
                "port_id": port_id,
                "vlan": _first_scalar(payload, "vlan", "vlan_id"),
                "ip": _first_scalar(payload, "ip", "ip_address"),
                "source": "top_level",
            }
    return {"device_mac": "", "port_id": "", "vlan": "", "ip": "", "source": ""}


def _as_epoch(value: Any) -> float:
    try:
        return float(value or 0)
    except (TypeError, ValueError):
        return 0.0


def _iso_or_text(value: Any) -> str:
    if not value:
        return ""
    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(float(value), tz=timezone.utc).isoformat()
        except Exception:
            return str(value)
    return str(value)


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip())
        return True
    except ValueError:
        return False


# A partial dotted IPv4 such as "10.7", "10.7." or "10.7.12". At least one dot is
# required so a bare number ("10", "1234") stays a free-text hostname/serial search.
_IPV4_PREFIX_RE = re.compile(r"^\d{1,3}\.(?:\d{1,3}(?:\.\d{1,3}){0,2}\.?)?$")


def _is_ipv4_prefix(value: str) -> bool:
    raw = value.strip()
    if not _IPV4_PREFIX_RE.match(raw):
        return False
    return all(int(part) <= 255 for part in raw.split(".") if part)


def _query_kind(query: str) -> tuple[str, str]:
    raw = query.strip()
    mac = clean_mac(raw)
    if _MAC_RE.match(mac):
        return "mac", mac
    if _is_ip(raw):
        return "ip", raw
    if _is_ipv4_prefix(raw):
        # Mist's ``text`` filter matches MAC/hostname/username, not IP prefixes, so
        # "10.7" sent as text returned only the few clients whose *name* contained it.
        return "ip_prefix", raw
    return "text", raw


def _item_ips(item: dict) -> list[str]:
    """Every IP address a Mist client/device record carries (scalar or list fields)."""
    found: list[str] = []

    def add(value: Any) -> None:
        if isinstance(value, (list, tuple)):
            for entry in value:
                add(entry)
            return
        text = str(value or "").strip()
        if text and text not in found:
            found.append(text)

    for key in ("ip", "ip_address", "client_ip", "ips", "last_ip"):
        add(item.get(key))
    rows = item.get("device_mac_port")
    if isinstance(rows, dict):
        rows = [rows]
    if isinstance(rows, list):
        for row in rows:
            if isinstance(row, dict):
                add(row.get("ip"))
    return found


def _matches_ip_prefix(item: dict, prefix: str) -> bool:
    """Plain dotted-string prefix match: "10.7" matches 10.7.x.x and 10.70-79.x.x,
    exactly like typing a prefix into the Mist client search; "10.7." narrows to 10.7.x.x."""
    return any(ip.startswith(prefix) for ip in _item_ips(item))


def _client_profile(item: dict, *, hostname: str = "", subtitle: str = "", kind: str = "") -> dict:
    """Return a compact, best-effort client classification for the result list.

    Mist's client schemas expose slightly different identity fields across wireless,
    wired, and NAC records. Keep this heuristic presentation-only: it never changes
    matching or network decisions.
    """
    text = " ".join(
        str(_first(item, key))
        for key in (
            "device",
            "family",
            "model",
            "os",
            "manufacture",
            "manufacturer",
            "dhcp_vendor_class_identifier",
            "dhcp_hostname",
            "hostname",
            "name",
        )
        if _first(item, key)
    ).lower()
    text = f"{text} {hostname} {subtitle}".lower()
    profiles = [
        (("iphone",), "iP", "iPhone", "mobile"),
        (("android",), "A", "Android", "mobile"),
        (("ipad", "tablet"), "Tb", "Tablet", "mobile"),
        (("macbook", "mac os", "macos", "os x", "darwin"), "MB", "MacBook", "computer"),
        (("windows",), "W", "Windows", "computer"),
        (("laptop", "notebook"), "L", "Laptop", "computer"),
        (("desktop", "workstation", "pc"), "PC", "Desktop", "computer"),
        (("phone", "mobile", "smartphone"), "Ph", "Phone", "mobile"),
        (("apple",), "Ap", "Apple", "apple"),
        (("camera", "surveillance", "axis"), "Cam", "Camera", "iot"),
        (("printer",), "Pr", "Printer", "iot"),
    ]
    for needles, icon, label, family in profiles:
        if any(n in text for n in needles):
            return {"icon": icon, "label": label, "family": family}
    if kind == "wireless_client":
        return {"icon": "Wi", "label": "Wireless", "family": "client"}
    if kind == "wired_client":
        return {"icon": "PC", "label": "Wired", "family": "client"}
    return {"icon": "•", "label": "Client", "family": "client"}


def _embedded_port(device_stats: dict, port_id: str) -> dict:
    """Recover port telemetry embedded in switch stats when port-search returns nothing."""
    if not device_stats or not port_id:
        return {}
    ports = device_stats.get("ports")
    if isinstance(ports, list):
        for row in ports:
            if isinstance(row, dict) and str(row.get("port_id") or "") == port_id:
                return dict(row)
    for key in ("port_stat", "port_stats"):
        table = device_stats.get(key)
        if isinstance(table, dict):
            row = table.get(port_id)
            if isinstance(row, dict):
                return {"port_id": port_id, **row}
    return {}


def _site_map(client: MistClient) -> dict[str, str]:
    try:
        return {str(x.get("id")): str(x.get("name") or x.get("id")) for x in client.list_sites()}
    except MistApiError:
        return {}


def _normalize_wireless(item: dict, sites: dict[str, str]) -> dict:
    mac = clean_mac(_first_scalar(item, "mac", "client_mac"))
    site_id = str(_first_scalar(item, "site_id"))
    hostname = str(_first_scalar(item, "hostname", "name"))
    username = str(_first_scalar(item, "username", "user"))
    title = hostname or username or display_mac(mac) or "Wireless client"
    ap_mac = clean_mac(_first_scalar(item, "ap", "ap_mac"))
    profile = _client_profile(
        item,
        hostname=hostname,
        subtitle=username or str(_first(item, "device", "family", "model")),
        kind="wireless_client",
    )
    return {
        "kind": "wireless_client",
        "kind_label": "Wireless Client",
        "client_profile": profile,
        "mac": mac,
        "display_mac": display_mac(mac),
        "title": title,
        "subtitle": username or str(_first(item, "device", "family", "model", default="Wireless client")),
        "ip": str(_first_scalar(item, "ip", "ip_address")),
        "site_id": site_id,
        "site": sites.get(site_id, site_id or "Unknown site"),
        "attachment": str(_first_scalar(item, "ap_name", default=display_mac(ap_mac) or "AP unknown")),
        "attachment_mac": ap_mac,
        "port_id": "",
        "network": str(_first_scalar(item, "ssid", "wlan")),
        "vlan": str(_first_scalar(item, "vlan", "vlan_id")),
        "username": username,
        "hostname": hostname,
        "last_seen": _iso_or_text(_first_scalar(item, "last_seen", "timestamp")),
        "sort_time": _as_epoch(_first_scalar(item, "last_seen", "timestamp")),
        "raw": item,
    }


def _normalize_wired(item: dict, sites: dict[str, str]) -> dict:
    mac = clean_mac(_first_scalar(item, "mac", "client_mac"))
    site_id = str(_first_scalar(item, "site_id"))
    hostname = str(_first_scalar(item, "dhcp_hostname", "hostname", "name"))
    username = str(_first_scalar(item, "username", "last_username"))
    title = hostname or username or display_mac(mac) or "Wired client"
    attachment = _wired_attachment(item)
    switch_mac = attachment.get("device_mac") or clean_mac(_first_scalar(item, "device_mac", "switch_mac"))
    port_id = str(attachment.get("port_id") or _first_scalar(item, "port_id"))
    ip = str(attachment.get("ip") or _first_scalar(item, "ip", "ip_address"))
    vlan = str(
        attachment.get("vlan") if attachment.get("vlan") not in (None, "") else _first_scalar(item, "vlan", "vlan_id")
    )
    profile = _client_profile(
        item,
        hostname=hostname,
        subtitle=username or str(_first_scalar(item, "manufacture", "manufacturer")),
        kind="wired_client",
    )
    return {
        "kind": "wired_client",
        "kind_label": "Wired Client",
        "client_profile": profile,
        "mac": mac,
        "display_mac": display_mac(mac),
        "title": title,
        "subtitle": username or str(_first_scalar(item, "manufacture", "manufacturer", default="Wired client")),
        "ip": ip,
        "site_id": site_id,
        "site": sites.get(site_id, site_id or "Unknown site"),
        "attachment": str(
            _first_scalar(item, "device_name", "switch_name", default=display_mac(switch_mac) or "Switch unknown")
        ),
        "attachment_mac": switch_mac,
        "port_id": port_id,
        "network": "",
        "vlan": vlan,
        "username": username,
        "hostname": hostname,
        "last_seen": _iso_or_text(_first_scalar(item, "last_seen", "timestamp")),
        "sort_time": _as_epoch(_first_scalar(item, "last_seen", "timestamp")),
        "raw": item,
    }


def _normalize_inventory(item: dict, sites: dict[str, str]) -> dict:
    mac = clean_mac(_first(item, "mac"))
    site_id = str(_first_scalar(item, "site_id"))
    dtype = str(_first(item, "type", "device_type", default="device")).lower()
    title = str(_first(item, "name", "hostname", "serial", default=display_mac(mac) or "Mist device"))
    return {
        "kind": "infrastructure",
        "kind_label": {"ap": "Access Point", "switch": "Switch", "gateway": "Gateway", "router": "Router"}.get(
            dtype, "Mist Device"
        ),
        "device_type": dtype,
        "mac": mac,
        "display_mac": display_mac(mac),
        "title": title,
        "subtitle": str(_first(item, "model", default=dtype.title())),
        "ip": str(_first(item, "ip", "ip_address")),
        "site_id": site_id,
        "site": sites.get(site_id, site_id or "Unassigned"),
        "attachment": "Mist infrastructure",
        "attachment_mac": "",
        "port_id": "",
        "network": "",
        "vlan": "",
        "username": "",
        "hostname": str(_first(item, "hostname", "name")),
        "serial": str(_first(item, "serial")),
        "last_seen": _iso_or_text(_first(item, "last_seen", "timestamp", "last_disconnected")),
        "sort_time": _as_epoch(_first(item, "last_seen", "timestamp", "last_disconnected")),
        "raw": item,
    }


def _normalize_nac(item: dict, sites: dict[str, str]) -> dict:
    mac = clean_mac(_first_scalar(item, "mac", "client_mac"))
    site_id = str(_first_scalar(item, "site_id"))
    username = str(_first_scalar(item, "username", "last_username", "idp_username"))
    hostname = str(_first_scalar(item, "hostname"))
    title = hostname or username or display_mac(mac) or "NAC client"
    dtype = str(_first(item, "type", default="client")).lower()
    profile = _client_profile(
        item,
        hostname=hostname,
        subtitle=username or str(_first(item, "family", "model", "os")),
        kind=dtype if dtype in {"wireless_client", "wired_client"} else "",
    )
    return {
        "kind": "nac_client",
        "kind_label": "NAC Client",
        "client_profile": profile,
        "mac": mac,
        "display_mac": display_mac(mac),
        "title": title,
        "subtitle": str(_first(item, "auth_type", "family", "model", default="Access Assurance client")),
        "ip": str(_first(item, "ip", "client_ip")),
        "site_id": site_id,
        "site": sites.get(site_id, site_id or "Unknown site"),
        "attachment": str(_first(item, "last_ap", "device_mac", "nas_ip", default=dtype.title())),
        "attachment_mac": clean_mac(_first_scalar(item, "device_mac", "ap")),
        "port_id": str(_first_scalar(item, "port_id")),
        "network": str(_first(item, "ssid")),
        "vlan": str(_first_scalar(item, "vlan", "ingress_vlan")),
        "username": username,
        "hostname": hostname,
        "last_seen": _iso_or_text(_first(item, "last_seen", "timestamp")),
        "sort_time": _as_epoch(_first(item, "last_seen", "timestamp")),
        "raw": item,
    }


def _score(item: dict, query_type: str, query_value: str) -> int:
    score = 0
    q = query_value.lower()
    if query_type == "mac" and item.get("mac") == q:
        score += 100
    if query_type == "ip" and str(item.get("ip", "")).lower() == q:
        score += 100
    if query_type == "ip_prefix" and str(item.get("ip", "")).startswith(q):
        score += 60
    for key, weight in (
        ("title", 45),
        ("hostname", 40),
        ("username", 40),
        ("serial", 40),
        ("display_mac", 35),
        ("ip", 35),
        ("attachment", 20),
        ("port_id", 15),
    ):
        value = str(item.get(key, "")).lower()
        if value == q:
            score += weight
        elif q and q in value:
            score += max(5, weight // 2)
    if item.get("kind") in {"wireless_client", "wired_client"}:
        score += 5
    return score


def _identity_key(item: dict) -> str:
    """The MAC identifies a client/device. Records without one (rare, but Mist can
    return them) must not all collapse into a single row, so fall back to other
    distinguishing values."""
    mac = str(item.get("mac") or "")
    if mac:
        return mac
    fallback = "|".join(
        str(item.get(key) or "") for key in ("serial", "hostname", "username", "ip", "title", "attachment", "port_id")
    )
    return f"nomac:{fallback}" if fallback.strip("|") else f"nomac:{id(item)}"


def _dedupe(results: list[dict]) -> list[dict]:
    """Collapse the same client/device reported twice (e.g. by the exact and prefix
    text queries, or by several Mist sources). The key is kind + MAC + site, so two
    distinct clients are never merged; NAC rows are dropped only when the same MAC
    already has a wired/wireless row on the same site."""
    seen: dict[tuple[str, str, str], dict] = {}
    for item in results:
        kind = item.get("kind", "")
        # NAC entries are supplemental when a wired/wireless result for the same client/site exists.
        if kind == "nac_client":
            client_key_candidates = [
                ("wireless_client", item.get("mac", ""), item.get("site_id", "")),
                ("wired_client", item.get("mac", ""), item.get("site_id", "")),
            ]
            if any(k in seen for k in client_key_candidates):
                continue
        key = (kind, _identity_key(item), item.get("site_id", ""))
        current = seen.get(key)
        if current is None or item.get("sort_time", 0) > current.get("sort_time", 0):
            seen[key] = item
    return list(seen.values())


def _try(label: str, fn, errors: list[dict]) -> list[dict]:
    try:
        value = fn()
        return value if isinstance(value, list) else []
    except MistApiError as exc:
        errors.append({"source": label, "error": str(exc), "status_code": exc.status_code})
        return []


def _simulation_search(query: str, site_id: str | None = None) -> dict:
    samples = [
        {
            "kind": "wired_client",
            "kind_label": "Wired Client",
            "client_profile": {"icon": "Cam", "label": "Camera", "family": "iot"},
            "mac": "02ae3f9f208a",
            "display_mac": "02:ae:3f:9f:20:8a",
            "title": "CAMERA-102",
            "subtitle": "Axis Communications",
            "ip": "10.20.30.55",
            "site_id": "sim-remote",
            "site": "Remote Campus",
            "attachment": "DEMO-SW-03",
            "attachment_mac": "024011870f36",
            "port_id": "ge-0/0/18",
            "network": "",
            "vlan": "120",
            "username": "",
            "hostname": "CAMERA-102",
            "last_seen": "Now",
            "sort_time": 9999999999,
        },
        {
            "kind": "wireless_client",
            "kind_label": "Wireless Client",
            "client_profile": {"icon": "iP", "label": "iPhone", "family": "mobile"},
            "mac": "020c41f4a0e1",
            "display_mac": "02:0c:41:f4:a0:e1",
            "title": "JSMITH-IPHONE",
            "subtitle": "jsmith@example.org",
            "ip": "10.44.20.81",
            "site_id": "sim-clinic",
            "site": "Example Surgery Center",
            "attachment": "DEMO-AP-01",
            "attachment_mac": "022641b34d5f",
            "port_id": "",
            "network": "CORP",
            "vlan": "210",
            "username": "jsmith@example.org",
            "hostname": "JSMITH-IPHONE",
            "last_seen": "Now",
            "sort_time": 9999999998,
        },
        {
            "kind": "infrastructure",
            "kind_label": "Switch",
            "device_type": "switch",
            "mac": "028ae8f67509",
            "display_mac": "02:8a:e8:f6:75:09",
            "title": "NW-DEMO-EX4400-FL2",
            "subtitle": "EX4400-48MP",
            "ip": "10.10.20.12",
            "site_id": "00000000-0000-4000-8000-000000000001",
            "site": "Example Medical Center",
            "attachment": "Mist infrastructure",
            "attachment_mac": "",
            "port_id": "",
            "network": "",
            "vlan": "",
            "username": "",
            "hostname": "NW-DEMO-EX4400-FL2",
            "serial": "SIM-VC-FL2",
            "last_seen": "Now",
            "sort_time": 9999999997,
        },
    ]
    q = query.strip().lower()
    filtered = [
        x
        for x in samples
        if (not site_id or x.get("site_id") == site_id)
        and any(
            q in str(x.get(k, "")).lower()
            for k in ("title", "subtitle", "mac", "display_mac", "ip", "username", "hostname", "attachment", "serial")
        )
    ]
    if not filtered and q:
        filtered = [samples[0]] if "camera" in q or "10.20" in q else []
    return {
        "mode": "simulation",
        "query": query,
        "query_type": _query_kind(query)[0],
        "results": filtered,
        "total": len(filtered),
        "sources": {"simulation": len(filtered)},
        "errors": [],
    }


# Per-source row caps. A site investigation must return the complete working set
# (Mist search pages through ``next`` in 1000-row pages up to 100k), so the site cap
# is effectively "everything"; organisation-wide searches stay bounded.
SITE_SOURCE_LIMIT = 50_000
ORG_SOURCE_LIMIT = 1_000
# Mist client searches look back this far; the UI states it next to the result count.
CLIENT_LOOKBACK = "7d"
_SOURCE_LABELS = {
    "wireless": "wireless clients",
    "wired": "wired clients",
    "inventory": "Mist devices",
    "nac": "NAC clients",
}


def _merge_rows(*batches: list[dict]) -> list[dict]:
    """Concatenate result batches from several queries of one source (dedupe happens later)."""
    rows: list[dict] = []
    for batch in batches:
        if isinstance(batch, list):
            rows.extend(x for x in batch if isinstance(x, dict))
    return rows


def search_detective(query: str, site_id: str | None = None) -> dict:
    query = (query or "").strip()
    if len(query) < 2 and not site_id:
        return {
            "mode": "live",
            "query": query,
            "query_type": "text",
            "results": [],
            "total": 0,
            "sources": {},
            "errors": [],
        }
    client = get_mist_client()
    if not client.configured:
        return _simulation_search(query, site_id)

    query_type, value = _query_kind(query) if query else ("text", "")
    sites = _site_map(client)
    errors: list[dict] = []
    source_limit = SITE_SOURCE_LIMIT if site_id else ORG_SOURCE_LIMIT
    kwargs = {"site_id": site_id, "limit": source_limit, "duration": CLIENT_LOOKBACK}
    site_listing = bool(site_id) and (not query or query_type == "ip_prefix")

    # Each task returns one source's rows; a source may be fed by several queries
    # (task names "source" or "source:variant") that are merged afterwards. All
    # tasks are independent Mist round trips, so they run in parallel.
    tasks: dict[str, Any] = {}
    if site_listing:
        # Site + no text lists every client and device of the site. A site-scoped
        # partial-IP search uses the same complete listing and filters it locally
        # below: Mist's ``ip`` filter does not reliably support prefix wildcards, and
        # filtering the full site set is exact regardless of what Mist supports.
        tasks = {
            "wireless": lambda: client.search_org_wireless_clients(**kwargs),
            "wired": lambda: client.search_org_wired_clients(**kwargs),
            "inventory": lambda: client.search_org_inventory(site_id=site_id, limit=source_limit),
            "nac": lambda: client.search_org_nac_clients(**kwargs),
        }
    elif query_type == "mac":
        tasks = {
            "wireless": lambda: client.search_org_wireless_clients(**kwargs, mac=value),
            "wired": lambda: client.search_org_wired_clients(**kwargs, mac=value),
            "inventory": lambda: client.search_org_inventory(site_id=site_id, mac=value, limit=source_limit),
            "nac": lambda: client.search_org_nac_clients(**kwargs, mac=value),
        }
    elif query_type == "ip":
        tasks = {
            "wireless": lambda: client.search_org_wireless_clients(**kwargs, ip=value),
            "wired": lambda: client.search_org_wired_clients(**kwargs, ip=value),
            "inventory": lambda: client.search_org_inventory(site_id=site_id, text=value, limit=source_limit),
        }
    elif query_type == "ip_prefix":
        # Organisation-wide partial IP: ask Mist for an ``ip`` wildcard (supported by
        # the client search endpoints) and filter locally as a guard in case Mist
        # treats the value loosely. Inventory has no IP filter, so use a text prefix.
        wildcard = value if value.endswith("*") else f"{value}*"
        tasks = {
            "wireless": lambda: client.search_org_wireless_clients(**kwargs, ip=wildcard),
            "wired": lambda: client.search_org_wired_clients(**kwargs, ip=wildcard),
            "inventory": lambda: client.search_org_inventory(site_id=site_id, text=wildcard, limit=source_limit),
        }
    else:
        # Mist ``text`` matching is whole-token; a trailing ``*`` makes it a prefix match so "kend" also finds
        # "kendall-ap-01" and "jsm" finds "jsmith". A prefix match on ``value*`` already returns every exact match
        # of ``value`` (the token "kend" starts with "kend"), so v0.10.53 (report perf #8) runs the prefix form
        # only, halving the Mist calls from eight to four; exact matches are still included.
        prefix = value if value.endswith("*") else f"{value}*"
        tasks = {
            "wireless": lambda: client.search_org_wireless_clients(**kwargs, text=prefix),
            "wired": lambda: client.search_org_wired_clients(**kwargs, text=prefix),
            "inventory": lambda: client.search_org_inventory(site_id=site_id, text=prefix, limit=source_limit),
            "nac": lambda: client.search_org_nac_clients(**kwargs, text=prefix),
        }

    fetched: dict[str, list[dict]] = {}
    with ThreadPoolExecutor(max_workers=min(8, max(1, len(tasks)))) as pool:
        future_map = {pool.submit(fn): name for name, fn in tasks.items()}
        for future in as_completed(future_map):
            name = future_map[future]
            source = name.split(":", 1)[0]
            try:
                rows = future.result()
                fetched[name] = rows if isinstance(rows, list) else []
            except MistApiError as exc:
                errors.append({"source": source, "error": str(exc), "status_code": exc.status_code})
            except Exception as exc:
                errors.append({"source": source, "error": str(exc), "status_code": None})

    # A query that returned exactly its cap almost certainly had more rows in Mist.
    # Inventory fans out once per device type, so the cap applies to each type.
    def hit_cap(name: str, rows: list[dict]) -> bool:
        if name.startswith("inventory"):
            per_type: dict[str, int] = {}
            for row in rows:
                key = str(row.get("type") or "")
                per_type[key] = per_type.get(key, 0) + 1
            return any(count >= source_limit for count in per_type.values())
        return len(rows) >= source_limit

    truncated_sources = sorted(
        {_SOURCE_LABELS[name.split(":", 1)[0]] for name, rows in fetched.items() if hit_cap(name, rows)}
    )

    def source_rows(source: str) -> list[dict]:
        rows = _merge_rows(*(rows for name, rows in fetched.items() if name.split(":", 1)[0] == source))
        if query_type == "ip_prefix":
            rows = [row for row in rows if _matches_ip_prefix(row, value)]
        return rows

    wireless = source_rows("wireless")
    wired = source_rows("wired")
    inventory = source_rows("inventory")
    nac = source_rows("nac")
    results = [_normalize_wireless(x, sites) for x in wireless]
    results += [_normalize_wired(x, sites) for x in wired]
    results += [_normalize_inventory(x, sites) for x in inventory]
    results += [_normalize_nac(x, sites) for x in nac]
    if query_type == "ip_prefix":
        # A client can hold several addresses (wired history, dual-stack); show the
        # one that matched the prefix the user typed.
        for item in results:
            if not str(item.get("ip") or "").startswith(value):
                matched = next((ip for ip in _item_ips(item.get("raw") or {}) if ip.startswith(value)), "")
                if matched:
                    item["ip"] = matched
    results = _dedupe(results)
    for item in results:
        item["score"] = _score(item, query_type, value)
        item.pop("raw", None)
    results.sort(key=lambda x: (x.get("score", 0), x.get("sort_time", 0)), reverse=True)
    return {
        "mode": "live",
        "query": query,
        "query_type": query_type,
        "results": results,
        "total": len(results),
        "sources": {"wireless": len(wireless), "wired": len(wired), "inventory": len(inventory), "nac": len(nac)},
        "errors": errors,
        "site_listing": site_listing,
        "client_lookback": CLIENT_LOOKBACK,
        "source_limit": source_limit,
        "truncated": bool(truncated_sources),
        "truncated_sources": truncated_sources,
    }


# --------------------------------------------------------------- more information
# "More information" is a curated, labelled view. Mist records carry dozens of
# internal fields (ids, org/site/map ids, wxids, raw arrays); never dump them. Each
# entry is (label, candidate keys, formatter); the first non-empty key wins.


def _fmt_duration(value: Any) -> str:
    try:
        seconds = int(float(value))
    except (TypeError, ValueError):
        return ""
    if seconds < 0:
        return ""
    days, rem = divmod(seconds, 86_400)
    hours, rem = divmod(rem, 3_600)
    minutes, secs = divmod(rem, 60)
    parts = [f"{days}d" if days else "", f"{hours}h" if hours else "", f"{minutes}m" if minutes and not days else ""]
    text = " ".join(p for p in parts if p)
    return text or f"{secs}s"


def _fmt_band(value: Any) -> str:
    text = str(value).strip().lower().replace("ghz", "").strip()
    mapping = {"24": "2.4 GHz", "2.4": "2.4 GHz", "5": "5 GHz", "6": "6 GHz"}
    return mapping.get(text, f"{value}")


def _fmt_speed(value: Any) -> str:
    try:
        mbps = float(value)
    except (TypeError, ValueError):
        return str(value)
    if mbps <= 0:
        return ""
    if mbps >= 1000:
        gbps = mbps / 1000
        return f"{gbps:g} Gbps"
    return f"{mbps:g} Mbps"


def _fmt_number_unit(unit: str):
    def fmt(value: Any) -> str:
        try:
            number = float(value)
        except (TypeError, ValueError):
            return str(value)
        return f"{number:g} {unit}"

    return fmt


def _fmt_proto(value: Any) -> str:
    text = str(value).strip()
    return text if text.startswith("802") else f"802.11{text}"


def _fmt_bool(yes: str = "Yes", no: str = "No"):
    def fmt(value: Any) -> str:
        if isinstance(value, bool):
            return yes if value else no
        return str(value)

    return fmt


def _fmt_text(value: Any) -> str:
    return str(value)


_DETAIL_FORMATTERS: dict[str, Any] = {
    "text": _fmt_text,
    "mac": display_mac,
    "duration": _fmt_duration,
    "band": _fmt_band,
    "speed": _fmt_speed,
    "dbm": _fmt_number_unit("dBm"),
    "db": _fmt_number_unit("dB"),
    "mbps": _fmt_number_unit("Mbps"),
    "watts": _fmt_number_unit("W"),
    "proto": _fmt_proto,
    "yesno": _fmt_bool(),
    "updown": _fmt_bool("Up", "Down"),
    "onoff": _fmt_bool("On", "Off"),
    "duplex": _fmt_bool("Full", "Half"),
}

# ---- Device Finder "More information" (v0.10.24) -----------------------------------------------------
# Vendor-neutral by design: the section builders below read ONE neutral facts dict, never a vendor
# payload. A vendor adapter (today :func:`mist_detail_facts`) turns its own records into these keys;
# Meraki / Aruba Central / Cisco / Fortinet adapters only have to fill the same keys.
#
# Neutral fact keys (all optional; a missing or empty value simply does not show):
#   client            manufacturer, family, model, os, os_version, ipv6, random_mac (bool), guest (bool),
#                     first_seen (time), connected_since (time), uptime (s), idle (s), snr (dB), proto,
#                     key_mgmt, tx_rate / rx_rate (Mbps, AP→client / client→AP), tx_bytes / rx_bytes,
#                     tx_retries / rx_retries, dual_band (bool), locating_aps
#   switch port       link (bool up), speed (Mbps), duplex (bool full), poe_on (bool), poe_mode,
#                     power_draw (W), port_usage, port_mode, stp_state, mac_count, rx_errors, tx_errors,
#                     port_tx_bytes, port_rx_bytes, last_flapped (time), xcvr, lldp_name, lldp_port
#   access            auth_method, auth_state, nac_rule, nac_rule_matched (bool), username, idp_role,
#                     psk_name, cert_cn, cert_issuer, cert_expiry (time), mdm_compliance, mdm_provider,
#                     vlan, nas_vendor
#   history           hostname_history, ip_history, username_history, ssid_history, vlan_history,
#                     ap_history, port_history  (lists of display strings, current values excluded)
#   attached device   attached_name, attached_type, attached_model, attached_serial, attached_firmware,
#                     attached_mac, attached_ip, attached_status, attached_uptime (s),
#                     attached_last_seen (time), attached_clients, attached_hw_rev
#   upstream          upstream_switch, upstream_port, upstream_power (W), upstream_gateway
#
# The header and the Device / Connection / Security cards at the top already show the identity and
# live attachment (hostname, IP, MAC, vendor, model, site, connection type, SSID, VLAN, switch + port or
# access point, band, channel, signal, last seen, username, authentication method, NAC rule and state).
# The sections leave those out, and every row carries its fact ``key`` so the page can also drop a row
# whose fact and value already appear at the top (e.g. one vendor's manufacturer vs another's vendor).
# Section tables: (label, neutral key, format).
_ABOUT_FIELDS = (
    ("Manufacturer", "manufacturer", "text"),
    ("Device family", "family", "text"),
    ("Model", "model", "text"),
    ("Operating system", "os", "text"),
    ("OS version", "os_version", "text"),
    ("IPv6 address", "ipv6", "text"),
    ("Uses a private (random) MAC", "random_mac", "yesno"),
    ("Guest", "guest", "yesno"),
    ("First seen", "first_seen", "time"),
    ("Connected since", "connected_since", "time"),
)
_WIRELESS_QUALITY_FIELDS = (
    ("Connected for", "uptime", "duration"),
    ("Idle for", "idle", "duration"),
    ("Signal quality (SNR)", "snr", "db"),
    ("Wi-Fi standard", "proto", "proto"),
    ("Wi-Fi security", "key_mgmt", "text"),
    ("Download link rate", "tx_rate", "mbps"),
    ("Upload link rate", "rx_rate", "mbps"),
    ("Data downloaded", "tx_bytes", "bytes"),
    ("Data uploaded", "rx_bytes", "bytes"),
    ("Packets resent to the device", "tx_retries", "count"),
    ("Packets resent by the device", "rx_retries", "count"),
    ("Can use 5 GHz", "dual_band", "yesno"),
    ("Access points that can hear it", "locating_aps", "count"),
)
_WIRED_QUALITY_FIELDS = (
    ("Connected for", "uptime", "duration"),
    ("Idle for", "idle", "duration"),
)
_PORT_FIELDS = (
    ("Link", "link", "updown"),
    ("Speed", "speed", "speed"),
    ("Duplex", "duplex", "duplex"),
    ("Power (PoE)", "poe_on", "onoff"),
    ("PoE mode", "poe_mode", "text"),
    ("Power drawn", "power_draw", "watts"),
    ("Port profile", "port_usage", "text"),
    ("Port mode", "port_mode", "text"),
    ("Spanning tree", "stp_state", "text"),
    ("Devices learned on the port", "mac_count", "count"),
    ("Receive errors", "rx_errors", "count"),
    ("Send errors", "tx_errors", "count"),
    ("Data sent to the device", "port_tx_bytes", "bytes"),
    ("Data received from the device", "port_rx_bytes", "bytes"),
    ("Last link change", "last_flapped", "time"),
    ("Transceiver", "xcvr", "text"),
    ("Neighbor (LLDP)", "lldp_name", "text"),
    ("Neighbor port", "lldp_port", "text"),
)
# Method, result, rule and identity are shown at the top, so the access section starts after them.
_ACCESS_FIELDS = (
    ("Rule matched", "nac_rule_matched", "yesno"),
    ("Role", "idp_role", "text"),
    ("Shared key (PSK) name", "psk_name", "text"),
    ("Certificate name (CN)", "cert_cn", "text"),
    ("Certificate issuer", "cert_issuer", "text"),
    ("Certificate expires", "cert_expiry", "time"),
    ("Device compliance (MDM)", "mdm_compliance", "text"),
    ("MDM provider", "mdm_provider", "text"),
    ("Assigned VLAN", "vlan", "text"),
    ("Network access device", "nas_vendor", "text"),
)
_HISTORY_FIELDS = (
    ("Other names seen", "hostname_history", "list"),
    ("Other IP addresses seen", "ip_history", "list"),
    ("Other usernames seen", "username_history", "list"),
    ("Other Wi-Fi networks used", "ssid_history", "list"),
    ("Other VLANs used", "vlan_history", "list"),
    ("Other access points used", "ap_history", "list"),
    ("Other switch ports used", "port_history", "list"),
)
_ATTACHED_FIELDS = (
    ("Model", "attached_model", "text"),
    ("Serial number", "attached_serial", "text"),
    ("Firmware", "attached_firmware", "text"),
    ("MAC address", "attached_mac", "mac"),
    ("IP address", "attached_ip", "text"),
    ("Status", "attached_status", "text"),
    ("Uptime", "attached_uptime", "duration"),
    ("Last seen", "attached_last_seen", "time"),
    ("Connected clients", "attached_clients", "text"),
    ("Hardware revision", "attached_hw_rev", "text"),
)
# The device itself (infrastructure result): name, IP, MAC and model are the header's facts.
_SELF_FIELDS = (
    ("Type", "attached_type", "text"),
    ("Serial number", "attached_serial", "text"),
    ("Firmware", "attached_firmware", "text"),
    ("Status", "attached_status", "text"),
    ("Uptime", "attached_uptime", "duration"),
    ("Connected clients", "attached_clients", "text"),
    ("Hardware revision", "attached_hw_rev", "text"),
)
_UPSTREAM_FIELDS = (
    ("Connects to switch", "upstream_switch", "text"),
    ("On switch port", "upstream_port", "text"),
    ("Power it draws from the switch", "upstream_power", "watts"),
    ("Default gateway", "upstream_gateway", "text"),
)
_DEVICE_TYPE_LABELS = {"ap": "Access point", "switch": "Switch", "gateway": "Gateway", "router": "Router"}


def _fmt_bytes(value: Any) -> str:
    try:
        n = float(value)
    except (TypeError, ValueError):
        return ""
    if n < 0:
        return ""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return ""


def _fmt_count(value: Any) -> str:
    try:
        n = float(value)
    except (TypeError, ValueError):
        return str(value)
    return f"{int(n):,}" if n == int(n) else f"{n:,.1f}"


_DETAIL_FORMATTERS["bytes"] = _fmt_bytes
_DETAIL_FORMATTERS["count"] = _fmt_count


def _detail_value(raw: Any, fmt: str) -> tuple[str, str]:
    """Return (display value, format hint) or ("", "") when nothing presentable exists."""
    if fmt == "list":
        items = [str(x) for x in (raw if isinstance(raw, (list, tuple)) else [raw]) if str(x or "").strip()]
        if not items:
            return "", ""
        more = len(items) - 6
        return ", ".join(items[:6]) + (f" and {more} more" if more > 0 else ""), "text"
    if isinstance(raw, (list, tuple)):
        scalars = [x for x in raw if not isinstance(x, (dict, list, tuple)) and x not in (None, "")]
        if not scalars:
            return "", ""
        if fmt != "text":
            raw = scalars[0]
        else:
            return ", ".join(dict.fromkeys(str(x) for x in scalars)), "text"
    if raw is None or raw == "" or isinstance(raw, dict):
        return "", ""
    if fmt == "time":
        text = _iso_or_text(raw)
        return (text, "time") if text else ("", "")
    if isinstance(raw, bool) and fmt == "text":
        return ("Yes" if raw else "No"), "text"
    text = str(_DETAIL_FORMATTERS.get(fmt, _fmt_text)(raw) or "").strip()
    if fmt == "text" and re.fullmatch(r"[a-z0-9]+(?:_[a-z0-9]+)+", text):
        # Enum-like values (e.g. "not_reported") read better as words.
        text = text.replace("_", " ").capitalize()
    return (text, "text") if text and text.lower() != "not reported" else ("", "")


def _section_rows(fields: tuple, facts: dict) -> list[dict]:
    """Rows for one section from neutral facts: [{label, value, format, key}]."""
    rows: list[dict] = []
    for label, key, fmt in fields:
        value, hint = _detail_value(facts.get(key), fmt)
        if value:
            rows.append({"label": label, "value": value, "format": hint, "key": key})
    return rows


def curated_details(kind: str, facts: dict | None = None) -> list[dict]:
    """The labelled "More information" sections for a Device Finder result, from NEUTRAL facts.

    ``kind`` is ``infrastructure``, ``wired_client`` or a wireless/NAC client. Only labelled facts are
    returned (never identifiers such as org/site/map ids); empty sections are omitted."""
    facts = facts or {}
    sections: list[dict] = []

    def add(title: str, rows: list[dict]) -> None:
        if rows:
            sections.append({"title": title, "rows": rows})

    if kind == "infrastructure":
        add("Device", _section_rows(_SELF_FIELDS, facts))
        add("Upstream connection", _section_rows(_UPSTREAM_FIELDS, facts))
        return sections
    wired = kind == "wired_client"
    add("About this client", _section_rows(_ABOUT_FIELDS, facts))
    add("Connection quality", _section_rows(_WIRED_QUALITY_FIELDS if wired else _WIRELESS_QUALITY_FIELDS, facts))
    if wired:
        add("Switch port", _section_rows(_PORT_FIELDS, facts))
    add("Access (802.1X / NAC)", _section_rows(_ACCESS_FIELDS, facts))
    add("Seen before", _section_rows(_HISTORY_FIELDS, facts))
    add("Switch" if wired else "Access point", _section_rows(_ATTACHED_FIELDS, facts))
    if not wired:
        add("Path upstream", _section_rows(_UPSTREAM_FIELDS, facts))
    return sections


# ---- Mist adapter: Mist record fields → neutral fact keys ---------------------------------------------
# The only place in the "More information" path that knows Mist field names. Each neutral key lists the
# Mist fields to try, in order, across the records passed for that group.
_MIST_CLIENT_FIELDS: dict[str, tuple[str, ...]] = {
    "manufacturer": ("manufacture", "manufacturer", "mfg"),
    "family": ("family",),
    "model": ("model", "last_model"),
    "os": ("os", "last_os"),
    "os_version": ("os_version",),
    "ipv6": ("ip6",),
    "random_mac": ("random_mac",),
    "guest": ("is_guest", "guest"),
    "first_seen": ("first_seen",),
    "connected_since": ("assoc_time", "connected_time"),
    "uptime": ("uptime",),
    "idle": ("idle_time",),
    "snr": ("snr",),
    "proto": ("proto", "protocol"),
    "key_mgmt": ("key_mgmt",),
    "tx_rate": ("tx_rate",),
    "rx_rate": ("rx_rate",),
    "tx_bytes": ("tx_bytes",),
    "rx_bytes": ("rx_bytes",),
    "tx_retries": ("tx_retries",),
    "rx_retries": ("rx_retries",),
    "dual_band": ("dual_band",),
    "locating_aps": ("num_locating_aps",),
}
_MIST_PORT_FIELDS: dict[str, tuple[str, ...]] = {
    "link": ("up",),
    "speed": ("speed",),
    "duplex": ("full_duplex",),
    "poe_on": ("poe_on",),
    "poe_mode": ("poe_mode",),
    "power_draw": ("power_draw", "poe_watts"),
    "port_usage": ("port_usage",),
    "port_mode": ("port_mode",),
    "stp_state": ("stp_state",),
    "mac_count": ("mac_count",),
    "rx_errors": ("rx_errors",),
    "tx_errors": ("tx_errors",),
    "port_tx_bytes": ("tx_bytes",),
    "port_rx_bytes": ("rx_bytes",),
    "last_flapped": ("last_flapped",),
    "xcvr": ("xcvr_model", "xcvr_part_number"),
    "lldp_name": ("neighbor_system_name",),
    "lldp_port": ("neighbor_port_desc",),
}
_MIST_ACCESS_FIELDS: dict[str, tuple[str, ...]] = {
    "auth_method": ("method", "auth_type"),
    "auth_state": ("state", "status", "last_status"),
    "nac_rule": ("nac_rule", "nacrule_name"),
    "nac_rule_matched": ("nacrule_matched",),
    "username": ("idp_username", "username"),
    "idp_role": ("idp_role",),
    "psk_name": ("psk_name", "last_psk_name"),
    "cert_cn": ("cert_cn",),
    "cert_issuer": ("cert_issuer",),
    "cert_expiry": ("cert_expiry",),
    "mdm_compliance": ("mdm_compliance",),
    "mdm_provider": ("mdm_provider",),
    "vlan": ("vlan",),
    "nas_vendor": ("nas_vendor", "last_nas_vendor"),
}
_MIST_DEVICE_FIELDS: dict[str, tuple[str, ...]] = {
    "attached_name": ("name", "hostname"),
    "attached_type": ("type",),
    "attached_model": ("model",),
    "attached_serial": ("serial",),
    "attached_firmware": ("version",),
    "attached_mac": ("mac",),
    "attached_ip": ("ip", "ip_address"),
    "attached_status": ("status",),
    "attached_uptime": ("uptime",),
    "attached_last_seen": ("last_seen",),
    "attached_clients": ("num_clients",),
    "attached_hw_rev": ("hw_rev",),
}


def _present(value: Any) -> bool:
    if value is None or value == "" or isinstance(value, dict):
        return False
    if isinstance(value, (list, tuple)):
        return any(not isinstance(x, (dict, list, tuple)) and x not in (None, "") for x in value)
    return True


def _map_fields(mapping: dict[str, tuple[str, ...]], *records: Any) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, names in mapping.items():
        for record in records:
            if not isinstance(record, dict):
                continue
            value = next((record.get(n) for n in names if _present(record.get(n))), None)
            if value is not None:
                out[key] = value
                break
    return out


def _norm_fact(value: Any) -> str:
    text = str(value or "").strip().lower()
    mac = re.sub(r"[^0-9a-f]", "", text)
    return mac if len(mac) == 12 and re.fullmatch(r"[0-9a-f:\-. ]+", text) else re.sub(r"\s+", " ", text)


def _scalars(value: Any) -> list[str]:
    items = value if isinstance(value, (list, tuple)) else [value]
    return [str(x).strip() for x in items if not isinstance(x, (dict, list, tuple)) and str(x or "").strip()]


def _others(values: list[str], current: list[str]) -> list[str]:
    now = {_norm_fact(v) for v in current if v}
    seen: dict[str, str] = {}
    for v in values:
        n = _norm_fact(v)
        if n and n not in now and n not in seen:
            seen[n] = v
    return list(seen.values())


def _mist_history_facts(history: dict, current: dict, names: dict[str, str]) -> dict[str, list[str]]:
    """Values Mist remembers for this client other than the current ones (newest first, as Mist lists them)."""

    def name_of(mac: str) -> str:
        return names.get(clean_mac(mac)) or display_mac(mac)

    aps_now = [current.get("ap_mac", "")] + [m for m, n in names.items() if n and n == current.get("ap_name")]
    ports = []
    for entry in history.get("device_mac_port") or []:
        if isinstance(entry, dict) and entry.get("device_mac") and entry.get("port_id"):
            ports.append(f"{name_of(str(entry['device_mac']))} {entry['port_id']}")
    facts = {
        "hostname_history": _others(
            _scalars(history.get("hostname")) + _scalars(history.get("last_hostname")), [current.get("hostname", "")]
        ),
        "ip_history": _others(_scalars(history.get("ip")) + _scalars(history.get("last_ip")), [current.get("ip", "")]),
        "username_history": _others(_scalars(history.get("username")), [current.get("username", "")]),
        "ssid_history": _others(_scalars(history.get("ssid")), [current.get("ssid", "")]),
        "vlan_history": _others(_scalars(history.get("vlan")), [current.get("vlan", "")]),
        "ap_history": [name_of(m) for m in _others(_scalars(history.get("ap")), aps_now)],
        "port_history": _others(ports, [f"{current.get('switch_name', '')} {current.get('port_id', '')}".strip()]),
    }
    return {k: v for k, v in facts.items() if v}


def _mist_upstream_facts(device: dict) -> dict[str, Any]:
    """How a Mist access point (or switch) itself is connected: LLDP neighbour, PoE draw, gateway."""
    lldp = device.get("lldp_stat") if isinstance(device.get("lldp_stat"), dict) else {}
    if not lldp and isinstance(device.get("lldp_stats"), list):
        lldp = next((x for x in device["lldp_stats"] if isinstance(x, dict)), {})
    ip_stat = device.get("ip_stat") if isinstance(device.get("ip_stat"), dict) else {}
    facts = {
        "upstream_switch": lldp.get("system_name"),
        "upstream_port": lldp.get("port_desc") or lldp.get("port_id"),
        "upstream_power": lldp.get("power_draw"),
        "upstream_gateway": ip_stat.get("gateway"),
    }
    return {k: v for k, v in facts.items() if _present(v)}


def mist_detail_facts(
    *,
    client: dict | None = None,
    attached: dict | None = None,
    port: dict | None = None,
    access: tuple[dict, ...] | list[dict] = (),
    history: dict | None = None,
    device_names: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Mist adapter: Mist client / NAC / port / device records → neutral facts for :func:`curated_details`.

    ``client`` is the merged client record plus the resolved current values (hostname, ip, username, ssid,
    vlan, ap_name / ap_mac or switch_name / port_id) used to leave current values out of the history."""
    client = client or {}
    attached = dict(attached or {})
    facts: dict[str, Any] = {}
    facts.update(_map_fields(_MIST_CLIENT_FIELDS, client))
    facts.update(_map_fields(_MIST_PORT_FIELDS, port or {}))
    facts.update(_map_fields(_MIST_ACCESS_FIELDS, *access))
    if attached.get("type"):
        attached["type"] = _DEVICE_TYPE_LABELS.get(str(attached["type"]).lower(), str(attached["type"]).title())
    facts.update(_map_fields(_MIST_DEVICE_FIELDS, attached))
    facts.update(_mist_upstream_facts(attached))
    facts.update(_mist_history_facts(history or {}, client, device_names or {}))
    return facts


def _device_names(client: MistClient, history: dict) -> dict[str, str]:
    """MAC → device name for the access points / switches in a client's history (cached directory)."""
    wanted = {clean_mac(x) for x in _scalars(history.get("ap"))}
    for entry in history.get("device_mac_port") or []:
        if isinstance(entry, dict):
            wanted.add(clean_mac(entry.get("device_mac")))
    wanted.discard("")
    if not wanted:
        return {}
    try:
        directory = client.device_directory()
    except Exception:  # noqa: BLE001 - names are optional; MACs are shown instead
        return {}
    return {m: str((directory.get(m) or {}).get("name") or "") for m in wanted if (directory.get(m) or {}).get("name")}


def _contains_any(payload: Any, needles: list[str]) -> bool:
    try:
        text = json.dumps(payload, default=str).lower()
    except Exception:
        text = str(payload).lower()
    return any(n and n.lower() in text for n in needles)


def _match_device_stats(client: MistClient, mac: str, device_type: str | None = None) -> dict:
    types = [device_type] if device_type in {"ap", "switch", "gateway", "router"} else ["all"]
    for dtype in types:
        try:
            # Ask Mist for this MAC only instead of downloading every device's stats.
            for row in client.list_org_device_stats(dtype or "all", mac=mac):
                if clean_mac(row.get("mac")) == mac:
                    return row
        except MistApiError:
            pass
    return {}


def _match_inventory(client: MistClient, mac: str, site_id: str | None = None) -> dict:
    matched: dict = {}
    try:
        rows = client.search_org_inventory(site_id=site_id, mac=mac, limit=10)
        if rows:
            matched = dict(rows[0])
    except MistApiError:
        pass

    # VC member MACs are not always represented by the same device identifier used by
    # switch port statistics. Inventory exposes vc_mac, so retain the member hit but
    # promote the result to the VC anchor when one exists.
    try:
        inventory = client.list_org_inventory(device_type="switch", vc=True, unassigned=False, site_id=site_id)
        if not matched:
            for row in inventory:
                if clean_mac(row.get("mac")) == mac or clean_mac(row.get("vc_mac")) == mac:
                    matched = dict(row)
                    break
        vc_mac = clean_mac(matched.get("vc_mac"))
        member_mac = clean_mac(matched.get("mac"))
        if vc_mac and member_mac and vc_mac != member_mac:
            anchor = next((row for row in inventory if clean_mac(row.get("mac")) == vc_mac), None)
            if anchor:
                promoted = dict(matched)
                promoted.update(anchor)
                promoted["member_mac"] = member_mac
                promoted["vc_mac"] = vc_mac
                matched = promoted
    except MistApiError:
        pass
    return matched


def _switch_mac_candidates(original_mac: str, *records: dict) -> list[str]:
    values: list[str] = []
    for value in [original_mac]:
        cleaned = clean_mac(value)
        if cleaned and cleaned not in values:
            values.append(cleaned)
    for record in records:
        if not isinstance(record, dict):
            continue
        for key in ("mac", "vc_mac", "device_mac", "switch_mac"):
            raw = record.get(key)
            if isinstance(raw, (list, tuple)):
                candidates = raw
            else:
                candidates = [raw]
            for value in candidates:
                cleaned = clean_mac(value)
                if cleaned and cleaned not in values:
                    values.append(cleaned)
    return values


def _pick_port(
    rows: Any, port_id: str, candidate_macs: list[str] | None = None, *, require_mac_match: bool = False
) -> dict:
    if not isinstance(rows, list) or not rows:
        return {}
    exact_port = [row for row in rows if isinstance(row, dict) and str(_first_scalar(row, "port_id")) == port_id]
    pool = exact_port or [row for row in rows if isinstance(row, dict)]
    if candidate_macs:
        wanted = {clean_mac(x) for x in candidate_macs if clean_mac(x)}
        matched = [row for row in pool if clean_mac(_first_scalar(row, "mac", "device_mac")) in wanted]
        if matched:
            pool = matched
        elif require_mac_match:
            return {}
    return dict(pool[0]) if pool else {}


def _active_alarms(client: MistClient, *macs: str) -> list[dict]:
    try:
        rows = client.search_org_alarms()
    except MistApiError:
        return []
    needles = [clean_mac(x) for x in macs if clean_mac(x)]
    matched = []
    for row in rows:
        if not _contains_any(row, needles):
            continue
        status = str(_first(row, "status", "state")).lower()
        if (
            row.get("resolved") is True
            or row.get("resolved_time")
            or row.get("cleared_time")
            or status in {"resolved", "closed", "cleared"}
        ):
            continue
        matched.append(row)
    matched.sort(key=lambda x: _as_epoch(_first(x, "timestamp", "last_seen")), reverse=True)
    return matched[:25]


_SEVERITY_LEVEL = {
    "critical": "critical",
    "major": "critical",
    "error": "critical",
    "warn": "warning",
    "warning": "warning",
    "minor": "warning",
}


def _conditions(client: MistClient, alarms: list[dict], sites: dict[str, str]) -> list[dict]:
    """Open alarms as readable "where" records for Device Finder's Requires attention list (v0.10.24).

    ``{key, title, severity (critical|warning|info), detail, fix, site, devices: [{name, mac, type}],
    ports, since, last_seen, count, source}``; never raises (labels are optional)."""
    if not alarms:
        return []
    try:
        directory = client.device_directory() or {}
    except Exception:  # noqa: BLE001
        directory = {}
    try:
        definitions = {str(d.get("key") or ""): d for d in client.list_alarm_definitions() if isinstance(d, dict)}
    except Exception:  # noqa: BLE001
        definitions = {}
    try:
        from app.services.audit_people import source_labels

        source = source_labels().get("mist") or "Juniper Mist"
    except Exception:  # noqa: BLE001
        source = "Juniper Mist"
    out: list[dict] = []
    for row in alarms:
        if not isinstance(row, dict):
            continue
        atype = str(_first(row, "type", "key") or "condition")
        definition = definitions.get(atype) or {}
        devices: list[dict] = []
        for field, dtype in (("switches", "switch"), ("aps", "ap"), ("gateways", "gateway")):
            for mac in _scalars(row.get(field)):
                m = clean_mac(mac)
                if not m:
                    continue
                entry = directory.get(m) or {}
                devices.append({"name": str(entry.get("name") or display_mac(m)), "mac": display_mac(m), "type": dtype})
        hostnames = [h for h in _scalars(row.get("hostnames")) if h not in {d["name"] for d in devices}]
        devices.extend({"name": h, "mac": "", "type": ""} for h in hostnames[:5])
        severity = _SEVERITY_LEVEL.get(str(row.get("severity") or definition.get("severity") or "").lower(), "info")
        reasons = [r for r in _scalars(row.get("reasons")) if r]
        out.append(
            {
                "key": str(row.get("id") or f"{atype}|{row.get('timestamp')}"),
                "type": atype,
                "title": str(definition.get("display") or atype.replace("_", " ").capitalize()),
                "severity": severity,
                "detail": "; ".join(reasons[:3]) or str(row.get("note") or row.get("text") or ""),
                "fix": str(row.get("suggestion") or row.get("recommendation") or definition.get("suggestion") or ""),
                "site": sites.get(str(row.get("site_id") or ""), "") if row.get("site_id") else "Organization",
                "devices": devices[:8],
                "ports": _scalars(row.get("port_ids") or row.get("ports"))[:8],
                "since": _iso_or_text(_first(row, "timestamp")),
                "last_seen": _iso_or_text(_first(row, "last_seen", "timestamp")),
                "count": int(row.get("count") or 1),
                "source": source,
            }
        )
    return out


def _nac_context(client: MistClient, mac: str, site_id: str | None) -> tuple[list[dict], list[dict], str | None]:
    clients: list[dict] = []
    events: list[dict] = []
    errors: list[str] = []
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = {
            pool.submit(client.search_org_nac_clients, site_id=site_id, mac=mac, limit=20): "clients",
            pool.submit(
                client.search_org_nac_client_events, site_id=site_id, mac=mac, duration="1d", limit=50
            ): "events",
        }
        for future in as_completed(futures):
            try:
                rows = future.result()
                if futures[future] == "clients":
                    clients = rows if isinstance(rows, list) else []
                else:
                    events = rows if isinstance(rows, list) else []
            except MistApiError as exc:
                errors.append(str(exc))
    return clients, events, "; ".join(errors) or None


def _troubleshoot_context(client: MistClient, mac: str, site_id: str | None) -> dict:
    try:
        return {"available": True, "data": client.troubleshoot(mac, site_id=site_id), "error": ""}
    except MistApiError as exc:
        return {"available": False, "data": {}, "error": str(exc)}


def _simulation_detail(kind: str, mac: str, site_id: str | None) -> dict:
    if kind == "infrastructure":
        return {
            "mode": "simulation",
            "kind": kind,
            "identity": {
                "title": "NW-DEMO-EX4400-FL2",
                "mac": "02:8a:e8:f6:75:09",
                "ip": "10.10.20.12",
                "username": "",
                "hostname": "NW-DEMO-EX4400-FL2",
                "site": "Example Medical Center",
                "site_id": "00000000-0000-4000-8000-000000000001",
            },
            "path": [
                {"label": "Site", "value": "Example Medical Center", "state": "ok"},
                {"label": "Switch", "value": "NW-DEMO-EX4400-FL2", "state": "ok"},
            ],
            "connection": {"type": "Switch", "status": "Connected", "last_seen": "Now"},
            "authentication": {},
            "device": {
                "name": "NW-DEMO-EX4400-FL2",
                "mac": "02:8a:e8:f6:75:09",
                "model": "EX4400-48MP",
                "serial": "SIM-VC-FL2",
                "version": "24.4R1",
                "status": "Connected",
            },
            "port": {},
            "ports_summary": {"total": 48, "up": 31, "down": 17, "poe_on": 22},
            "alarms": [],
            "nac_events": [],
            "troubleshoot": {
                "available": True,
                "data": {
                    "summary": "Switch is connected and no active Marvis root-cause issue is detected in preview data."
                },
                "error": "",
            },
            "raw_sources": [
                "inventory",
                "device stats",
                "port stats",
                "Mist alarms",
                "Marvis troubleshoot (when licensed)",
            ],
        }
    if kind == "wireless_client":
        return {
            "mode": "simulation",
            "kind": kind,
            "identity": {
                "title": "JSMITH-IPHONE",
                "mac": "02:0c:41:f4:a0:e1",
                "ip": "10.44.20.81",
                "username": "jsmith@example.org",
                "hostname": "JSMITH-IPHONE",
                "site": "Example Surgery Center",
                "site_id": "sim-clinic",
            },
            "path": [
                {"label": "Site", "value": "Example Surgery Center", "state": "ok"},
                {"label": "Access Point", "value": "DEMO-AP-01", "state": "ok"},
                {"label": "SSID", "value": "CORP", "state": "ok"},
                {"label": "VLAN", "value": "210", "state": "ok"},
            ],
            "connection": {
                "type": "Wireless",
                "status": "Connected",
                "ap": "DEMO-AP-01",
                "ap_mac": "02:26:41:b3:4d:5f",
                "ssid": "CORP",
                "band": "5 GHz",
                "channel": 149,
                "rssi": -58,
                "vlan": "210",
                "last_seen": "Now",
            },
            "authentication": {
                "method": "802.1X / EAP-TLS",
                "state": "Authenticated",
                "username": "jsmith@example.org",
                "nac_rule": "Corporate Managed Devices",
            },
            "device": {"name": "DEMO-AP-01", "model": "AP64", "version": "0.14.29633", "status": "Connected"},
            "port": {},
            "alarms": [],
            "nac_events": [
                {
                    "type": "NAC_CLIENT_PERMITTED",
                    "timestamp": "2026-10-05T19:21:00-04:00",
                    "text": "Client permitted by Corporate Managed Devices",
                }
            ],
            "troubleshoot": {
                "available": True,
                "data": {"summary": "Client is currently healthy. No active root-cause issue detected."},
                "error": "",
            },
            "raw_sources": [
                "wireless client stats",
                "NAC client context",
                "AP inventory/stats",
                "Mist alarms",
                "Marvis troubleshoot (when licensed)",
            ],
        }
    return {
        "mode": "simulation",
        "kind": "wired_client",
        "identity": {
            "title": "CAMERA-102",
            "mac": "02:ae:3f:9f:20:8a",
            "ip": "10.20.30.55",
            "username": "",
            "hostname": "CAMERA-102",
            "site": "Remote Campus",
            "site_id": "sim-remote",
        },
        "path": [
            {"label": "Site", "value": "Remote Campus", "state": "ok"},
            {"label": "Switch", "value": "DEMO-SW-03", "state": "ok"},
            {"label": "Port", "value": "ge-0/0/18", "state": "ok"},
            {"label": "VLAN", "value": "120", "state": "ok"},
        ],
        "connection": {
            "type": "Wired",
            "status": "Connected",
            "switch": "DEMO-SW-03",
            "switch_mac": "02:40:11:87:0f:36",
            "port_id": "ge-0/0/18",
            "vlan": "120",
            "speed": "1 Gbps",
            "last_seen": "Now",
        },
        "authentication": {"method": "MAB", "state": "Authenticated", "username": "", "nac_rule": "Camera / IoT"},
        "device": {
            "name": "DEMO-SW-03",
            "mac": "02:40:11:87:0f:36",
            "model": "EX4400-48MP",
            "version": "24.4R1",
            "status": "Connected",
        },
        "port": {
            "port_id": "ge-0/0/18",
            "up": True,
            "speed": 1000,
            "full_duplex": True,
            "poe_on": True,
            "poe_mode": "802.3at",
            "poe_watts": 14.8,
            "neighbor_system_name": "CAMERA-102",
            "neighbor_port_desc": "eth0",
        },
        "alarms": [],
        "nac_events": [],
        "troubleshoot": {
            "available": True,
            "data": {
                "summary": "Wired client is reachable through DEMO-SW-03 ge-0/0/18. No active Mist issue detected."
            },
            "error": "",
        },
        "raw_sources": [
            "wired client stats",
            "switch port stats",
            "NAC client context",
            "switch inventory/stats",
            "Mist alarms",
        ],
    }


def detective_troubleshoot(mac: str, site_id: str | None = None) -> dict:
    client = get_mist_client()
    mac = clean_mac(mac)
    if len(mac) != 12:
        raise ValueError("A 12-character client or device MAC is required")
    if not client.configured:
        # Mist is not connected: this is illustrative sample output, never a real health verdict.
        return {
            "available": False,
            "sample": True,
            "mode": "sample",
            "data": {
                "results": [
                    {
                        "category": "Sample data",
                        "reason": "Mist not connected",
                        "text": "Sample Marvis output. Connect Mist in Settings to run a real troubleshoot.",
                    }
                ]
            },
            "error": "",
        }
    return _troubleshoot_context(client, mac, site_id)


def detective_detail(kind: str, mac: str, site_id: str | None = None, *, fresh: bool = False) -> dict:
    client = get_mist_client()
    mac = clean_mac(mac)
    if len(mac) != 12:
        raise ValueError("A 12-character client or device MAC is required")
    if not client.configured:
        data = _simulation_detail(kind, mac, site_id)
        connection = data.get("connection") or {}
        data["details"] = curated_details(
            data.get("kind", kind),
            mist_detail_facts(
                client={
                    **(data.get("identity") or {}),
                    **{k: v for k, v in connection.items() if k not in {"ap", "ap_mac", "switch", "switch_mac"}},
                    "ap_name": connection.get("ap", ""),
                    "ap_mac": connection.get("ap_mac", ""),
                },
                attached=data.get("device") or {},
                port={**(data.get("port") or {}), "switch_name": connection.get("switch", "")},
                access=(data.get("authentication") or {},),
            ),
        )
        # Match live behavior: Marvis is optional enrichment and loads after core detail.
        data["troubleshoot"] = {"available": False, "pending": True, "data": {}, "error": ""}
        return data
    if fresh:
        client.clear_cache_matching(
            "/clients/",
            "/wired_clients/",
            "/nac_clients/",
            "/stats/clients/",
            "/stats/ports/",
            "/inventory/search",
            "/stats/devices",
            "/alarms/search",
        )

    sites = _site_map(client)
    result: dict[str, Any] = {"mode": "live", "kind": kind, "raw_sources": []}

    if kind in {"wireless_client", "wired_client", "nac_client"}:
        wired = kind == "wired_client"
        primary_rows: list[dict] = []
        if wired:
            try:
                primary_rows = client.search_org_wired_clients(site_id=site_id, mac=mac, limit=20)
            except MistApiError:
                primary_rows = []
        else:
            try:
                primary_rows = client.search_org_wireless_clients(site_id=site_id, mac=mac, limit=20)
            except MistApiError:
                primary_rows = []
            if not primary_rows and kind == "nac_client":
                try:
                    nac_guess = client.search_org_nac_clients(site_id=site_id, mac=mac, limit=5)
                    if nac_guess and str(nac_guess[0].get("type") or "").lower() == "wired":
                        wired = True
                        primary_rows = client.search_org_wired_clients(site_id=site_id, mac=mac, limit=20)
                except MistApiError:
                    pass

        primary = max(primary_rows, key=lambda x: _as_epoch(_first(x, "last_seen", "timestamp")), default={})
        resolved_site_id = str(site_id or _first(primary, "site_id"))
        site_name = sites.get(resolved_site_id, resolved_site_id or "Unknown site")
        stats = {}
        if resolved_site_id:
            try:
                stats = client.get_site_client_stats(resolved_site_id, mac, wired=wired, fresh=fresh)
                result["raw_sources"].append("site client stats")
            except MistApiError:
                stats = {}
        merged = {**primary, **stats}
        if wired:
            # Site client stats is the most current source when it reports a complete
            # attachment. If it does not, use the explicit historical device_mac_port
            # relationship from wired-client search so switch and port stay paired.
            current_attachment = _wired_attachment(stats)
            if current_attachment.get("device_mac") and current_attachment.get("port_id"):
                attachment = current_attachment
            else:
                attachment = _wired_attachment(primary, stats)
            device_mac = str(attachment.get("device_mac") or "")
            port_id = str(attachment.get("port_id") or "")
        else:
            attachment = {}
            device_mac = clean_mac(_first_scalar(merged, "ap_mac", "ap"))
            port_id = ""
        device_type = "switch" if wired else "ap"

        # Once the attachment is known, the remaining enrichment calls are independent.
        # Run them concurrently so opening a match is not blocked by serial API latency.
        tasks: dict[str, Any] = {
            "nac": lambda: _nac_context(client, mac, resolved_site_id or None),
            "alarms": lambda: _active_alarms(client, mac, device_mac),
        }
        if device_mac:
            tasks["inventory"] = lambda: _match_inventory(client, device_mac, resolved_site_id or None)
            tasks["device_stats"] = lambda: _match_device_stats(client, device_mac, device_type)
        if wired and device_mac and port_id:
            tasks["org_port"] = lambda: client.search_org_ports(
                device_type="switch", mac=device_mac, port_id=port_id, limit=20
            )
            if resolved_site_id:
                tasks["site_port"] = lambda: client.search_site_ports(
                    resolved_site_id, device_type="switch", mac=device_mac, port_id=port_id, limit=20
                )

        fetched: dict[str, Any] = {}
        fetch_errors: dict[str, str] = {}
        with ThreadPoolExecutor(max_workers=min(6, max(1, len(tasks)))) as pool:
            future_map = {pool.submit(fn): name for name, fn in tasks.items()}
            for future in as_completed(future_map):
                name = future_map[future]
                try:
                    fetched[name] = future.result()
                except Exception as exc:
                    fetched[name] = None
                    fetch_errors[name] = str(exc)

        inv = fetched.get("inventory") if isinstance(fetched.get("inventory"), dict) else {}
        dev_stats = fetched.get("device_stats") if isinstance(fetched.get("device_stats"), dict) else {}
        device = {**inv, **dev_stats}
        nac_clients, nac_events, nac_error = (
            fetched.get("nac") if isinstance(fetched.get("nac"), tuple) else ([], [], None)
        )
        if nac_clients:
            result["raw_sources"].append("NAC client context")
        nac = max(nac_clients, key=lambda x: _as_epoch(_first(x, "last_seen", "timestamp")), default={})
        alarms = fetched.get("alarms") if isinstance(fetched.get("alarms"), list) else []
        if alarms:
            result["raw_sources"].append("Mist alarms")

        port: dict = {}
        port_source = ""
        candidate_macs = _switch_mac_candidates(device_mac, inv, dev_stats) if wired else [device_mac]
        resolved_device_mac = candidate_macs[0] if candidate_macs else device_mac
        # Prefer the VC anchor/device identifier for display and subsequent telemetry
        # queries when inventory promoted a physical member MAC to its vc_mac.
        inventory_mac = clean_mac(inv.get("mac")) if isinstance(inv, dict) else ""
        if inventory_mac:
            resolved_device_mac = inventory_mac

        if wired and device_mac and port_id:
            for source_name in ("org_port", "site_port"):
                rows = fetched.get(source_name)
                port = _pick_port(rows, port_id, candidate_macs)
                if port:
                    port_source = "organization port stats" if source_name == "org_port" else "site port stats"
                    break
            if not port:
                port = _embedded_port(dev_stats, port_id)
                if port:
                    port_source = "embedded switch stats"

            # If the client referenced a physical VC member, the first query may have
            # used a MAC that is not the device identifier accepted by port stats.
            # Retry only the additional VC/device candidates, and fetch the switch's
            # direct site stats (which contains the same port objects) as a final exact
            # source. A site-wide port_id-only search is used only when rows can be
            # matched back to a known candidate MAC.
            if not port:
                secondary: dict[str, Any] = {}
                for idx, candidate in enumerate(candidate_macs):
                    if not candidate or candidate == device_mac:
                        continue
                    secondary[f"org_port_{idx}"] = lambda candidate=candidate: client.search_org_ports(
                        device_type="switch", mac=candidate, port_id=port_id, limit=20
                    )
                    if resolved_site_id:
                        secondary[f"site_port_{idx}"] = lambda candidate=candidate: client.search_site_ports(
                            resolved_site_id, device_type="switch", mac=candidate, port_id=port_id, limit=20
                        )
                if resolved_site_id:
                    secondary["site_port_by_id"] = lambda: client.search_site_ports(
                        resolved_site_id, device_type="switch", port_id=port_id, limit=100
                    )
                device_id = str(_first_scalar(inv, "id", "device_id")) if isinstance(inv, dict) else ""
                if resolved_site_id and device_id:
                    secondary["direct_device_stats"] = lambda: client.get_site_device_stats(
                        resolved_site_id, device_id, fresh=fresh
                    )

                secondary_results: dict[str, Any] = {}
                if secondary:
                    with ThreadPoolExecutor(max_workers=min(6, len(secondary))) as pool:
                        future_map = {pool.submit(fn): name for name, fn in secondary.items()}
                        for future in as_completed(future_map):
                            name = future_map[future]
                            try:
                                secondary_results[name] = future.result()
                            except Exception as exc:
                                secondary_results[name] = None
                                fetch_errors[name] = str(exc)

                for name, rows in secondary_results.items():
                    if name.startswith("org_port_") or name.startswith("site_port_"):
                        if name == "site_port_by_id":
                            continue
                        port = _pick_port(rows, port_id, candidate_macs)
                        if port:
                            port_source = (
                                "VC-aware organization port stats"
                                if name.startswith("org_port_")
                                else "VC-aware site port stats"
                            )
                            break
                if not port:
                    port = _pick_port(
                        secondary_results.get("site_port_by_id"), port_id, candidate_macs, require_mac_match=True
                    )
                    if port:
                        port_source = "site port stats (resolved device identity)"
                direct_stats = secondary_results.get("direct_device_stats")
                if isinstance(direct_stats, dict) and direct_stats:
                    # Use direct device stats for the device card too; it is more precise
                    # than an organization-wide scan when a VC anchor ID is known.
                    dev_stats = {**dev_stats, **direct_stats}
                    device = {**inv, **dev_stats}
                    direct_port = _embedded_port(direct_stats, port_id)
                    if not port and direct_port:
                        port = direct_port
                        port_source = "direct switch stats"

            if port:
                result["raw_sources"].append(port_source)

        hostname = str(_first_scalar(merged, "dhcp_hostname", "hostname", default=_first_scalar(nac, "hostname")))
        username = str(
            _first_scalar(merged, "username", "last_username", default=_first_scalar(nac, "username", "last_username"))
        )
        ip = (
            str(attachment.get("ip") or _first_scalar(merged, "ip", "ip_address"))
            if wired
            else str(_first_scalar(merged, "ip", "ip_address"))
        )
        title = hostname or username or display_mac(mac)
        device_name = str(_first_scalar(device, "name", "hostname", default=("Switch" if wired else "Access Point")))
        device_status_raw = _first_scalar(device, "status", default="")
        connected = _first_scalar(device, "connected", default=None)
        device_status = (
            "Connected"
            if connected is True
            else "Disconnected"
            if connected is False
            else str(device_status_raw or "Unknown").title()
        )
        if wired and attachment.get("vlan") not in (None, ""):
            vlan = str(attachment.get("vlan"))
        else:
            vlan = str(_first_scalar(merged, "vlan", "vlan_id", default=_first_scalar(nac, "vlan", "ingress_vlan")))
        ssid = str(_first_scalar(merged, "ssid"))
        auth_method = str(_first_scalar(merged, "auth_method", default=_first_scalar(nac, "auth_type")))
        auth_state = str(_first_scalar(merged, "auth_state", default=_first_scalar(nac, "status")))
        nac_rule = str(_first_scalar(nac, "nacrule_name"))

        path = [{"label": "Site", "value": site_name, "state": "ok" if resolved_site_id else "unknown"}]
        path.append(
            {
                "label": "Switch" if wired else "Access Point",
                "value": device_name or display_mac(device_mac),
                "state": "ok" if device_mac else "unknown",
            }
        )
        if wired:
            path.append({"label": "Port", "value": port_id or "Unknown", "state": "ok" if port_id else "unknown"})
        else:
            path.append({"label": "SSID", "value": ssid or "Unknown", "state": "ok" if ssid else "unknown"})
        path.append({"label": "VLAN", "value": vlan or "Unknown", "state": "ok" if vlan else "unknown"})

        connection = {
            "type": "Wired" if wired else "Wireless",
            "status": str(_first(merged, "status", "auth_state", default="Seen by Mist")).replace("_", " ").title(),
            "switch" if wired else "ap": device_name,
            "switch_mac" if wired else "ap_mac": display_mac(resolved_device_mac if wired else device_mac),
            "port_id": port_id if wired else "",
            "ssid": ssid if not wired else "",
            "vlan": vlan,
            "ip": ip,
            "band": str(_first_scalar(merged, "band")),
            "channel": _first_scalar(merged, "channel"),
            "rssi": _first_scalar(merged, "rssi"),
            "last_seen": _iso_or_text(_first_scalar(merged, "last_seen", "timestamp")),
        }
        port_lookup = {
            "reported": bool(port),
            "port_id": port_id,
            "switch": device_name,
            "switch_mac": display_mac(resolved_device_mac if wired else device_mac),
            "source": port_source,
            "attempted": [
                "organization port stats",
                "site port stats",
                "VC/device identity resolution",
                "direct switch stats",
            ]
            if wired and port_id
            else [],
            "errors": [
                message for key, message in fetch_errors.items() if "port" in key or key == "direct_device_stats"
            ],
            "message": ""
            if port
            else (
                "Mist identified the wired attachment, but no current telemetry row matched the resolved switch and port. "
                "The client attachment and switch identity were resolved correctly; port telemetry may be outside Mist's current/last-hour statistics window."
            ),
        }
        result.update(
            {
                "identity": {
                    "title": title,
                    "mac": display_mac(mac),
                    "ip": ip,
                    "username": username,
                    "hostname": hostname,
                    "site": site_name,
                    "site_id": resolved_site_id,
                },
                "path": path,
                "connection": connection,
                "authentication": {
                    "method": auth_method or "Not reported",
                    "state": auth_state or "Not reported",
                    "username": username,
                    "nac_rule": nac_rule,
                    "nac_error": nac_error or "",
                },
                "device": {
                    "name": device_name,
                    "mac": display_mac(resolved_device_mac if wired else device_mac),
                    "model": str(_first_scalar(device, "model")),
                    "serial": str(_first_scalar(device, "serial")),
                    "version": str(_first_scalar(device, "version")),
                    "status": device_status,
                },
                "port": port,
                "details": curated_details(
                    "wired_client" if wired else "wireless_client",
                    mist_detail_facts(
                        client={
                            # NAC knows OS/manufacturer for some clients Mist's client stats do not profile.
                            **{k: nac.get(k) for k in ("os", "family", "model", "mfg", "random_mac") if nac.get(k)},
                            **merged,
                            "hostname": hostname,
                            "username": username,
                            "ip": ip,
                            "vlan": vlan,
                            "ap_name": "" if wired else device_name,
                            "ap_mac": "" if wired else device_mac,
                            "ssid": ssid,
                            "switch_name": device_name if wired else "",
                            "port_id": port_id,
                        },
                        history=primary,
                        device_names=_device_names(client, primary),
                        attached={
                            **device,
                            "name": device_name,
                            "mac": resolved_device_mac if wired else device_mac,
                            "status": device_status,
                        },
                        port={**port, "switch_name": device_name, "port_id": port_id} if wired else {},
                        access=(
                            {
                                "method": auth_method,
                                "state": auth_state,
                                "nac_rule": nac_rule,
                            },
                            nac,
                            merged,  # shared-key (PSK) name lives on the client record
                        ),
                    ),
                ),
                "port_lookup": port_lookup,
                "alarms": alarms,
                "conditions": _conditions(client, alarms, sites),
                "nac_events": nac_events[:25],
                "troubleshoot": {"available": False, "pending": True, "data": {}, "error": ""},
            }
        )
        return result

    # Infrastructure device detail. Inventory and device stats are independent.
    with ThreadPoolExecutor(max_workers=2) as pool:
        f_inv = pool.submit(_match_inventory, client, mac, site_id)
        f_stats = pool.submit(_match_device_stats, client, mac, None)
        inv = f_inv.result()
        stats = f_stats.result()
    device = {**inv, **stats}
    device_type = str(_first(device, "type", "device_type", default="device")).lower()
    resolved_site_id = str(site_id or _first(device, "site_id"))
    site_name = sites.get(resolved_site_id, resolved_site_id or "Unassigned")
    with ThreadPoolExecutor(max_workers=3) as pool:
        f_alarms = pool.submit(_active_alarms, client, mac)
        f_changes = pool.submit(_device_changes, mac)
        if device_type in {"switch", "gateway"}:
            f_ports = pool.submit(client.search_org_ports, device_type=device_type, mac=mac, limit=100)
        else:
            f_ports = None
        alarms = f_alarms.result()
        try:
            ports = f_ports.result() if f_ports else []
        except Exception:
            ports = []
        recent_changes = f_changes.result()
    if ports:
        result["raw_sources"].append("port stats")
    result["raw_sources"].extend(["inventory", "device stats"])
    title = str(_first(device, "name", "hostname", "serial", default=display_mac(mac)))
    connected = _first(device, "connected", default=None)
    status = (
        "Connected"
        if connected is True
        else "Disconnected"
        if connected is False
        else str(_first(device, "status", default="Unknown")).title()
    )
    path = [
        {"label": "Site", "value": site_name, "state": "ok" if resolved_site_id else "unknown"},
        {"label": device_type.title() if device_type else "Device", "value": title, "state": "ok"},
    ]
    result.update(
        {
            "identity": {
                "title": title,
                "mac": display_mac(mac),
                "ip": str(_first(device, "ip", "ip_address")),
                "username": "",
                "hostname": str(_first(device, "hostname", "name")),
                "site": site_name,
                "site_id": resolved_site_id,
            },
            "path": path,
            "connection": {
                "type": device_type.title(),
                "status": status,
                "last_seen": _iso_or_text(_first(device, "last_seen", "timestamp", "last_disconnected")),
            },
            "authentication": {},
            "device": {
                "name": title,
                "mac": display_mac(mac),
                "model": str(_first(device, "model")),
                "serial": str(_first(device, "serial")),
                "version": str(_first(device, "version")),
                "status": status,
            },
            "port": {},
            "details": curated_details(
                "infrastructure", mist_detail_facts(attached={**device, "name": title, "mac": mac, "status": status})
            ),
            "ports_summary": {
                "total": len(ports),
                "up": sum(1 for p in ports if p.get("up") is True),
                "down": sum(1 for p in ports if p.get("up") is False),
                "poe_on": sum(1 for p in ports if p.get("poe_on") is True),
                "sample": ports[:12],
            },
            "alarms": alarms,
            "conditions": _conditions(client, alarms, sites),
            "recent_changes": recent_changes,
            "nac_events": [],
            "troubleshoot": {"available": False, "pending": True, "data": {}, "error": ""},
        }
    )
    return result


def _device_changes(mac: str, limit: int = 10) -> list[dict]:
    """Recent audit entries (last 7 days, newest first) that touched this device, from every connected
    audit source, with who made them (vendor-neutral, app/services/audit_people.py). Never raises."""
    try:
        from app.integrations.domain import normalize_mac, stable_key
        from app.services import audit_people

        bare = normalize_mac(mac)
        if not bare:
            return []
        key = stable_key("mac", bare)
        audit = audit_people.collect("7d", device_key=key)  # filtered at the source, memoised 60 s
        out = []
        for e in audit["entries"]:
            if key not in (e.get("device_keys") or []):
                continue
            a = audit["actors"].get(e.get("actor_ref") or "", {})
            out.append(
                {
                    "time": e.get("time"),
                    "timestamp": e.get("timestamp"),
                    "action": e.get("verb"),
                    "what": e.get("what"),
                    "summary": e.get("summary"),
                    "source_label": e.get("source_label"),
                    "changes": [
                        {"label": c.get("field"), "before": c.get("before"), "after": c.get("after")}
                        for c in (e.get("changes") or [])[:20]
                    ],
                    "actor": {
                        "name": a.get("name") or e.get("actor_name") or "System",
                        "email": a.get("email") or e.get("actor_email") or "",
                        "kind_label": a.get("kind_label", ""),
                        "roles": a.get("role_lines") or [],
                        "changes_24h": a.get("changes_24h", 0),
                        "changes_7d": a.get("changes_7d", 0),
                    },
                }
            )
            if len(out) >= limit:
                break
        return out
    except Exception:  # noqa: BLE001 - optional enrichment
        return []
