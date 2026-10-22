from __future__ import annotations

from copy import deepcopy
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
import json

from fastapi import APIRouter, HTTPException, Query

from app.core.auth import STACKING_WRITE, require
from app.modules.system.presence import holds_exit
from app.core.config import AUDIT_ROOT
from app.core.file_utils import write_private_text
from app.core.security import redact_sensitive
from app.data.sample_data import SITES, VCS
from app.services import chassis_service
from app.services.mist_client import MistApiError, get_mist_client

router = APIRouter(prefix="/api/v1", tags=["virtual-chassis"])


def _clean_mac(value) -> str:
    return str(value or "").lower().replace(":", "").replace("-", "")


def _normalize_role(value) -> str:
    """Normalize Mist/Junos VC role vocabulary without losing intent."""
    role = str(value or "").strip().lower().replace("_", "-")
    aliases = {
        "primary": "master",
        "primary-routing-engine": "master",
        "master": "master",
        "secondary": "backup",
        "backup-routing-engine": "backup",
        "backup": "backup",
        "routingengine": "routing-engine",
        "routing-engine": "routing-engine",
        "re": "routing-engine",
        "line-card": "linecard",
        "linecard": "linecard",
    }
    return aliases.get(role, role or "linecard")


def _canonicalize_mist_roles(members: list[dict]) -> list[dict]:
    """Convert Junos `routing-engine` roles to Mist's documented write vocabulary.

    Mist maps both `master` and `backup` to Junos `routing-engine` for
    preprovisioned VC configuration.  Some device reads therefore expose the Junos
    role while the Mist device-config write API expects master/backup/linecard.
    """
    rows = [dict(m) for m in members]
    for row in rows:
        row["vc_role"] = _normalize_role(row.get("vc_role"))
    routing = sorted(
        [r for r in rows if r.get("vc_role") == "routing-engine"],
        key=lambda r: int(r.get("member_id", 999)),
    )
    has_master = any(r.get("vc_role") == "master" for r in rows)
    has_backup = any(r.get("vc_role") == "backup" for r in rows)
    if not has_master and routing:
        routing.pop(0)["vc_role"] = "master"
        has_master = True
    if not has_backup and routing:
        routing.pop(0)["vc_role"] = "backup"
    return rows


def _identity_mode(device_mac: str, members: list[dict]) -> str:
    member0 = next((m for m in members if m.get("member_id") == 0), None)
    if member0 and device_mac and _clean_mac(device_mac) == _clean_mac(member0.get("mac")):
        return "Legacy FPC0-based ID"
    return "Virtual Device ID"


def _members_from_payload(payload: dict) -> list[dict]:
    if not isinstance(payload, dict):
        return []
    vc = payload.get("virtual_chassis")
    if isinstance(vc, dict) and isinstance(vc.get("members"), list):
        return vc["members"]
    if isinstance(payload.get("members"), list):
        return payload["members"]
    if isinstance(payload.get("member"), list):
        return payload["member"]
    return []


def _member_index(raw: dict, fallback: int = 999) -> int:
    for key in ("member_id", "member", "_idx", "fpc", "slot"):
        if raw.get(key) is None:
            continue
        try:
            return int(raw.get(key))
        except (TypeError, ValueError):
            continue
    return fallback


def _merge_member_sources(config_members: list[dict], live_members: list[dict]) -> list[dict]:
    """Merge write-safe VC config with Mist's live VC topology/stats view.

    The config list carries the member MAC/member_id needed for writes.  The live
    /vc endpoint carries operational member metadata such as _idx, serial, model,
    vc_state and hardware health.  Mist's live member objects do not always include
    the member MAC, so member index is the primary merge key after MAC.
    """
    live_by_mac = {_clean_mac(x.get("mac")): x for x in live_members if _clean_mac(x.get("mac"))}
    live_by_index = {_member_index(x): x for x in live_members if _member_index(x) != 999}
    merged: list[dict] = []
    for pos, cfg in enumerate(config_members):
        mac = _clean_mac(cfg.get("mac"))
        idx = _member_index(cfg, pos)
        live = live_by_mac.get(mac) or live_by_index.get(idx) or {}
        row = dict(live)
        # Configuration values normally win, but Junos may expose the configured
        # control-plane role as `routing-engine` while Mist's live VC status tells us
        # whether that member is currently master or backup.  Preserve the more
        # specific live Mist role so the editor does not reject a valid VC.
        live_role = _normalize_role(live.get("vc_role") or live.get("role"))
        cfg_role = _normalize_role(cfg.get("vc_role") or cfg.get("role"))
        for key, value in cfg.items():
            if value in (None, "", [], {}):
                continue
            if key in {"vc_role", "role"} and cfg_role == "routing-engine" and live_role in {"master", "backup"}:
                continue
            row[key] = value
        if cfg_role == "routing-engine" and live_role in {"master", "backup"}:
            row["configured_vc_role"] = "routing-engine"
            row["vc_role"] = live_role
        row["member_id"] = idx
        if mac:
            row["mac"] = mac
        merged.append(row)
    return merged


def _normalize_members(
    raw_members: list[dict],
    inventory_by_mac: dict[str, dict],
    stats_by_mac: dict[str, dict],
    fallback_model: str = "",
    vc_firmware: str = "",
) -> list[dict]:
    members = []
    for pos, raw in enumerate(raw_members):
        mac = _clean_mac(raw.get("mac"))
        if not mac:
            continue
        inv = inventory_by_mac.get(mac, {})
        stat = stats_by_mac.get(mac, {})
        member_id = _member_index(raw, pos)
        explicit_version = (
            raw.get("version")
            or raw.get("fw_version")
            or raw.get("firmware_version")
            or stat.get("version")
            or stat.get("fw_version")
            or inv.get("version")
        )
        version = explicit_version or vc_firmware or ""
        if "connected" in raw:
            connected = raw.get("connected")
        elif str(raw.get("vc_state") or "").lower() in {"present", "online", "connected", "master", "backup"}:
            connected = True
        elif str(raw.get("vc_state") or "").lower() in {"absent", "offline", "disconnected"}:
            connected = False
        elif "connected" in inv:
            connected = inv.get("connected")
        else:
            connected = stat.get("connected")
        members.append(
            {
                "mac": mac,
                "vc_role": _normalize_role(raw.get("vc_role") or raw.get("role") or "linecard"),
                "member_id": member_id,
                "vc_ports": list(raw.get("vc_ports") or []),
                "serial": raw.get("serial")
                or raw.get("serial_number")
                or inv.get("serial")
                or inv.get("serial_number")
                or stat.get("serial")
                or "—",
                "model": raw.get("model") or inv.get("model") or stat.get("model") or fallback_model or "Switch",
                "version": version,
                "version_scope": "member" if explicit_version else ("vc" if vc_firmware else "unknown"),
                "connected": connected,
                "vc_state": raw.get("vc_state") or "",
            }
        )
    members.sort(key=lambda x: x.get("member_id", 999))
    return members


def _live_sites() -> list[dict]:
    client = get_mist_client()
    rows = [{"id": s.get("id"), "name": s.get("name") or s.get("id")} for s in client.list_sites() if s.get("id")]
    return sorted(rows, key=lambda s: str(s["name"]).casefold())


def _discover_vc_groups(inventory: list[dict], site_id: str | None) -> dict[str, list[dict]]:
    groups: dict[str, list[dict]] = {}
    for item in inventory:
        if str(item.get("type") or "").lower() != "switch":
            continue
        sid = str(item.get("site_id") or "")
        if site_id and site_id != "all" and sid != site_id:
            continue
        vc_mac = _clean_mac(item.get("vc_mac"))
        mac = _clean_mac(item.get("mac"))
        if not vc_mac or not mac:
            continue
        groups.setdefault(vc_mac, []).append(item)
    return groups


def _resolve_vc_anchor(
    client, vc_mac: str, group: list[dict], site_devices_cache: dict[str, list[dict]]
) -> tuple[dict, str]:
    # Current inventory normally includes the VC anchor itself (mac == vc_mac), including virtual 020003... identities.
    anchor = next((x for x in group if _clean_mac(x.get("mac")) == vc_mac and x.get("id")), None)
    site_id = str((anchor or group[0]).get("site_id") or "")
    if anchor:
        return anchor, site_id

    # Prefer the already-fetched site switch configuration before issuing another
    # API request.  `dict.setdefault(..., api_call())` would still evaluate the API
    # call even when the cache key exists, so use an explicit cache check here.
    if site_id:
        devices = site_devices_cache.get(site_id)
        if devices is None:
            try:
                devices = client.list_site_devices(site_id, "switch")
            except MistApiError:
                devices = []
            site_devices_cache[site_id] = devices
        anchor = next(
            (x for x in devices if _clean_mac(x.get("mac")) == vc_mac or _clean_mac(x.get("vc_mac")) == vc_mac), None
        )
        if anchor and anchor.get("id"):
            return anchor, site_id

    # Current Mist OpenAPI exposes vc_mac on inventory/search.  Use that as the
    # final identity lookup rather than relying on the older inventory query form.
    try:
        rows = client.search_org_inventory(device_type="switch", site_id=site_id or None, vc_mac=vc_mac, limit=20)
        anchor = next(
            (
                x
                for x in rows
                if (_clean_mac(x.get("mac")) == vc_mac or _clean_mac(x.get("vc_mac")) == vc_mac) and x.get("id")
            ),
            None,
        )
        if anchor:
            return anchor, str(anchor.get("site_id") or site_id)
    except MistApiError:
        pass
    return {}, site_id


def _fast_vc_summaries(site_id: str) -> list[dict]:
    """Return fast VC cards for one selected site.

    This path intentionally avoids the org-wide /stats/devices endpoint. Real
    diagnostics from the user's environment showed that call averaging >4s and
    reaching ~9s. Site selection only needs inventory + one site device-config
    list to discover chassis, names, member count and configured roles. Live VC
    topology/stats are fetched only when Manage VC opens.
    """
    client = get_mist_client()
    requested_site = str(site_id or "").strip()
    if not requested_site or requested_site == "all":
        return []

    # These are the two lightest authoritative sources that give us both physical
    # VC membership and logical device/config identity. Run them concurrently.
    with ThreadPoolExecutor(max_workers=2, thread_name_prefix="vc-summary") as pool:
        inv_future = pool.submit(
            client.list_org_inventory,
            device_type="switch",
            vc=True,
            unassigned=False,
            site_id=requested_site,
        )
        cfg_future = pool.submit(client.list_site_devices, requested_site, "switch")
        inventory = inv_future.result()
        devices = cfg_future.result()

    groups = _discover_vc_groups(inventory, requested_site)
    inv_by_mac = {_clean_mac(x.get("mac")): x for x in inventory if x.get("mac")}
    inventory_by_id: dict[str, list[dict]] = {}
    for item in inventory:
        iid = str(item.get("id") or item.get("device_id") or "")
        if iid:
            inventory_by_id.setdefault(iid, []).append(item)

    summaries: list[dict] = []
    seen_device_ids: set[str] = set()
    seen_vc_macs: set[str] = set()

    # Prefer the site's single device-config list for names and configured member
    # order/roles. This is one request for the site, not one request per VC.
    for dev in devices:
        vc_cfg = dev.get("virtual_chassis")
        if not isinstance(vc_cfg, dict) or not isinstance(vc_cfg.get("members"), list) or not vc_cfg.get("members"):
            continue
        device_id = str(dev.get("id") or "")
        if not device_id:
            continue
        inv_rows = inventory_by_id.get(device_id, [])
        inv_anchor = next((x for x in inv_rows if x.get("id")), None)
        vc_mac = _clean_mac(
            (inv_anchor or {}).get("vc_mac") or dev.get("vc_mac") or (inv_anchor or {}).get("mac") or dev.get("mac")
        )
        group = groups.get(vc_mac, [])
        if not group and inv_rows:
            # Some clouds expose the logical ID on every physical VC inventory row.
            group = inv_rows
        members = _normalize_members(
            vc_cfg.get("members") or [],
            inv_by_mac,
            {},
            str(dev.get("model") or (inv_anchor or {}).get("model") or "Switch"),
            str(dev.get("version") or ""),
        )
        logical_mac = _clean_mac(dev.get("mac") or (inv_anchor or {}).get("mac") or vc_mac)
        connected = (inv_anchor or {}).get("connected")
        if connected is None and group:
            vals = [x.get("connected") for x in group if "connected" in x]
            if vals:
                connected = any(v is True for v in vals)
        status = (
            "Connected"
            if connected is True
            else "Disconnected"
            if connected is False
            else str((inv_anchor or {}).get("status") or "Ready").title()
        )
        summaries.append(
            {
                "device_id": device_id,
                "site_id": requested_site,
                "vc_mac": vc_mac or logical_mac,
                "name": dev.get("name")
                or (inv_anchor or {}).get("name")
                or (inv_anchor or {}).get("hostname")
                or f"VC {vc_mac or logical_mac}",
                "model": dev.get("model")
                or (inv_anchor or {}).get("model")
                or (group[0].get("model") if group else "Switch"),
                "status": status,
                "version": dev.get("version") or "",
                "serial": (inv_anchor or {}).get("serial") or dev.get("serial") or "",
                "preprovisioned": bool(vc_cfg.get("preprovisioned", True)),
                "identity_mode": _identity_mode(logical_mac, members),
                "members": members,
                "member_count": len(members) or len(group),
                "source": "Mist inventory + site VC config summary",
            }
        )
        seen_device_ids.add(device_id)
        if vc_mac:
            seen_vc_macs.add(vc_mac)

    # Inventory fallback for a VC that is present in Mist inventory but is not in
    # the site config list. Keep the card usable; Manage VC will fetch/verify the
    # authoritative detail for the selected device.
    for vc_mac, group in groups.items():
        if vc_mac in seen_vc_macs:
            continue
        anchor = next(
            (x for x in group if _clean_mac(x.get("mac")) == vc_mac and (x.get("id") or x.get("device_id"))), None
        )
        if not anchor:
            anchor = next((x for x in group if x.get("id") or x.get("device_id")), None)
        if not anchor:
            continue
        device_id = str(anchor.get("id") or anchor.get("device_id") or "")
        if not device_id or device_id in seen_device_ids:
            continue
        physical = []
        seen_macs: set[str] = set()
        for idx, item in enumerate(sorted(group, key=lambda x: str(x.get("serial") or x.get("mac") or ""))):
            mac = _clean_mac(item.get("mac"))
            if not mac or mac in seen_macs:
                continue
            seen_macs.add(mac)
            physical.append(
                {
                    "mac": mac,
                    "vc_role": _normalize_role(item.get("vc_role") or item.get("role") or "linecard"),
                    "member_id": int(item.get("member_id", idx)),
                    "vc_ports": [],
                    "serial": item.get("serial") or "—",
                    "model": item.get("model") or anchor.get("model") or "Switch",
                    "version": "",
                    "version_scope": "unknown",
                    "connected": item.get("connected"),
                    "vc_state": "",
                }
            )
        connected = anchor.get("connected")
        status = (
            "Connected"
            if connected is True
            else "Disconnected"
            if connected is False
            else str(anchor.get("status") or "Ready").title()
        )
        summaries.append(
            {
                "device_id": device_id,
                "site_id": requested_site,
                "vc_mac": vc_mac,
                "name": anchor.get("name") or anchor.get("hostname") or f"VC {vc_mac}",
                "model": anchor.get("model") or (physical[0].get("model") if physical else "Switch"),
                "status": status,
                "version": "",
                "serial": anchor.get("serial") or "",
                "preprovisioned": True,
                "identity_mode": "Identity loads on open",
                "members": physical,
                "member_count": len(physical),
                "source": "Mist VC inventory summary",
            }
        )

    return sorted(summaries, key=lambda x: x["name"].lower())


def _live_vc_detail(site_id: str, device_id: str) -> dict:
    """Fetch authoritative detail for one VC only, with independent reads in parallel."""
    client = get_mist_client()
    with ThreadPoolExecutor(max_workers=4, thread_name_prefix="vc-detail") as pool:
        config_f = pool.submit(client.get_site_device, site_id, device_id)
        live_f = pool.submit(client.get_site_virtual_chassis, site_id, device_id)
        stat_f = pool.submit(client.get_site_device_stats, site_id, device_id)
        inv_f = pool.submit(
            client.list_org_inventory,
            device_type="switch",
            vc=True,
            unassigned=False,
            site_id=site_id,
        )
        config = config_f.result()
        live_vc = live_f.result()
        stat = stat_f.result()
        inventory = inv_f.result()

    vc_mac = _clean_mac(
        live_vc.get("vc_mac")
        or config.get("vc_mac")
        or stat.get("vc_mac")
        or live_vc.get("mac")
        or config.get("mac")
        or stat.get("mac")
    )
    groups = _discover_vc_groups(inventory, site_id)
    group = groups.get(vc_mac, [])
    if not group and vc_mac:
        group = [x for x in inventory if _clean_mac(x.get("mac")) == vc_mac or _clean_mac(x.get("vc_mac")) == vc_mac]
    inv_by_mac = {_clean_mac(i.get("mac")): i for i in inventory if i.get("mac")}
    stats_by_mac: dict[str, dict] = {}
    if stat.get("mac"):
        stats_by_mac[_clean_mac(stat.get("mac"))] = stat

    config_members = _members_from_payload(config)
    live_members = _members_from_payload(live_vc)
    raw_members = _merge_member_sources(config_members, live_members) if config_members else []
    if not raw_members:
        live_by_index = {_member_index(x): x for x in live_members if _member_index(x) != 999}
        raw_members = []
        for idx, item in enumerate(sorted(group, key=lambda x: str(x.get("serial") or x.get("mac") or ""))):
            row = dict(live_by_index.get(idx, {}))
            row.update(
                {
                    "mac": item.get("mac"),
                    "member_id": item.get("member_id", idx),
                    "vc_role": row.get("vc_role") or item.get("vc_role") or "linecard",
                }
            )
            raw_members.append(row)

    model = str(
        live_vc.get("model")
        or stat.get("model")
        or config.get("model")
        or (group[0].get("model") if group else "Switch")
    )
    vc_firmware = str(
        live_vc.get("version")
        or live_vc.get("fw_version")
        or stat.get("version")
        or stat.get("fw_version")
        or config.get("version")
        or ""
    )
    members = _normalize_members(raw_members, inv_by_mac, stats_by_mac, model, vc_firmware)
    logical_mac = _clean_mac(live_vc.get("mac") or config.get("mac") or stat.get("mac") or vc_mac)
    connected = live_vc.get("connected") if "connected" in live_vc else stat.get("connected")
    if connected is None:
        connected = str(live_vc.get("status") or "").lower() == "connected" if live_vc.get("status") else None
    status = (
        "Connected"
        if connected is True
        else "Disconnected"
        if connected is False
        else str(live_vc.get("status") or stat.get("status") or "Unknown").title()
    )
    vc_cfg = config.get("virtual_chassis") if isinstance(config.get("virtual_chassis"), dict) else {}
    return {
        "device_id": device_id,
        "site_id": site_id,
        "vc_mac": vc_mac or logical_mac,
        "name": config.get("name") or live_vc.get("name") or stat.get("name") or f"VC {vc_mac or logical_mac}",
        "model": model,
        "status": status,
        "version": vc_firmware,
        "serial": live_vc.get("serial") or stat.get("serial") or config.get("serial") or "",
        "preprovisioned": bool(vc_cfg.get("preprovisioned", live_vc.get("preprovisioned", True))),
        "identity_mode": _identity_mode(logical_mac, members),
        "members": members,
        "member_count": len(members),
        "source": "Mist device config + live VC topology/stats",
    }


def _live_vcs(site_id: str | None, *, include_live: bool = True, only_device_id: str | None = None) -> list[dict]:
    client = get_mist_client()
    requested_site = str(site_id or "").strip()
    if requested_site == "all":
        requested_site = ""

    # Site selection used to perform organization-wide stats plus serial config/live
    # lookups for every chassis.  Pull the site-scoped sources together first, then
    # fetch independent VC status documents concurrently.
    if requested_site:
        with ThreadPoolExecutor(max_workers=3, thread_name_prefix="vc-site") as pool:
            inv_future = pool.submit(
                client.list_org_inventory, device_type="switch", vc=True, unassigned=False, site_id=requested_site
            )
            stats_future = pool.submit(client.list_org_device_stats, "switch", site_id=requested_site)
            devices_future = pool.submit(client.list_site_devices, requested_site, "switch")
            inventory = inv_future.result()
            stats = stats_future.result()
            site_devices_cache: dict[str, list[dict]] = {requested_site: devices_future.result()}
    else:
        # v0.10.40: the org switch statistics (the slowest read, ~5 s) run alongside the inventory and the
        # per-site device reads instead of after the inventory.
        with ThreadPoolExecutor(max_workers=1, thread_name_prefix="vc-stats") as stats_pool:
            stats_future = stats_pool.submit(client.list_org_device_stats, "switch")
            inventory = client.list_org_inventory(device_type="switch", vc=True, unassigned=True)
            site_devices_cache = {}
            candidate_sites = sorted({str(x.get("site_id") or "") for x in inventory if x.get("site_id")})
            if candidate_sites:
                with ThreadPoolExecutor(max_workers=min(6, len(candidate_sites)), thread_name_prefix="vc-sites") as pool:
                    futs = {pool.submit(client.list_site_devices, sid, "switch"): sid for sid in candidate_sites}
                    for fut in as_completed(futs):
                        sid = futs[fut]
                        try:
                            site_devices_cache[sid] = fut.result()
                        except MistApiError:
                            site_devices_cache[sid] = []
            stats = stats_future.result()

    inv_by_mac = {_clean_mac(i.get("mac")): i for i in inventory if i.get("mac")}
    stats_by_mac = {_clean_mac(s.get("mac")): s for s in stats if s.get("mac")}
    groups = _discover_vc_groups(inventory, requested_site or None)
    descriptors: dict[tuple[str, str], dict] = {}

    # Site device configuration is the fastest authoritative source for member
    # MAC/member_id/role and avoids one GET per chassis.
    for sid, devices in site_devices_cache.items():
        for dev in devices:
            vc_cfg = dev.get("virtual_chassis")
            if not isinstance(vc_cfg, dict) or not isinstance(vc_cfg.get("members"), list) or not vc_cfg.get("members"):
                continue
            device_id = str(dev.get("id") or "")
            if not device_id:
                continue
            dmac = _clean_mac(dev.get("mac"))
            vc_mac = _clean_mac(dev.get("vc_mac")) or dmac
            # Inventory is more reliable for virtual VC identity when available.
            inv_anchor = next((x for x in inventory if str(x.get("id") or "") == device_id), None)
            if inv_anchor:
                vc_mac = _clean_mac(inv_anchor.get("vc_mac")) or _clean_mac(inv_anchor.get("mac")) or vc_mac
            descriptors[(sid, device_id)] = {
                "sid": sid,
                "device_id": device_id,
                "vc_mac": vc_mac,
                "anchor": inv_anchor or dev,
                "config": dev,
                "group": groups.get(vc_mac, []),
            }

    # Add inventory-discovered VCs that were not exposed by list-site-devices.
    for vc_mac, group in groups.items():
        anchor, sid = _resolve_vc_anchor(client, vc_mac, group, site_devices_cache)
        if requested_site and sid != requested_site:
            continue
        device_id = str(anchor.get("id") or anchor.get("device_id") or "")
        if not sid or not device_id or (sid, device_id) in descriptors:
            continue
        config = next((d for d in site_devices_cache.get(sid, []) if str(d.get("id") or "") == device_id), {})
        descriptors[(sid, device_id)] = {
            "sid": sid,
            "device_id": device_id,
            "vc_mac": vc_mac,
            "anchor": anchor,
            "config": config,
            "group": group,
        }

    if only_device_id:
        descriptors = {key: d for key, d in descriptors.items() if str(d.get("device_id") or "") == str(only_device_id)}

    # The /vc endpoint is a combined topology + stats view.  Site cards do not need
    # that expensive per-chassis payload, so the list route skips it and Manage VC
    # enriches only the selected chassis.  When enrichment is requested, independent
    # VC calls remain concurrent for callers that request more than one.
    live_by_key: dict[tuple[str, str], dict] = {}
    if include_live and descriptors:
        with ThreadPoolExecutor(max_workers=min(8, len(descriptors)), thread_name_prefix="vc-live") as pool:
            futs = {
                pool.submit(client.get_site_virtual_chassis, d["sid"], d["device_id"]): key
                for key, d in descriptors.items()
            }
            for fut in as_completed(futs):
                key = futs[fut]
                try:
                    live_by_key[key] = fut.result()
                except MistApiError:
                    live_by_key[key] = {}

    result: list[dict] = []
    for key, desc in descriptors.items():
        sid = desc["sid"]
        device_id = desc["device_id"]
        vc_mac = desc["vc_mac"]
        anchor = desc["anchor"] or {}
        group = desc["group"] or []
        config = desc["config"] or {}
        live_vc = live_by_key.get(key, {})

        # In rare cases the site device list may not contain the logical anchor;
        # retrieve just that one config rather than doing this for every VC.
        if not config:
            try:
                config = client.get_site_device(sid, device_id)
            except MistApiError:
                config = {}

        config_members = _members_from_payload(config)
        live_members = _members_from_payload(live_vc)
        raw_members = _merge_member_sources(config_members, live_members) if config_members else []
        if not raw_members:
            # Inventory grouping remains a last-resort discovery path.  Merge live
            # member-by-index metadata where possible, but do not invent identities.
            raw_members = []
            sorted_group = sorted(group, key=lambda x: str(x.get("serial") or x.get("mac")))
            live_by_index = {_member_index(x): x for x in live_members if _member_index(x) != 999}
            for idx, item in enumerate(sorted_group):
                row = dict(live_by_index.get(idx, {}))
                row.update(
                    {
                        "mac": item.get("mac"),
                        "member_id": item.get("member_id", idx),
                        "vc_role": item.get("vc_role")
                        or row.get("vc_role")
                        or ("master" if _clean_mac(item.get("mac")) == vc_mac else "linecard"),
                    }
                )
                raw_members.append(row)

        stat = stats_by_mac.get(vc_mac, {})
        if not stat:
            stat = next((x for x in stats if str(x.get("id") or "") == device_id), {})
        model = str(
            live_vc.get("model")
            or anchor.get("model")
            or (group[0].get("model") if group else "")
            or config.get("model")
            or "Switch"
        )
        vc_firmware = str(
            live_vc.get("version")
            or live_vc.get("fw_version")
            or stat.get("version")
            or stat.get("fw_version")
            or config.get("version")
            or ""
        )
        members = _normalize_members(raw_members, inv_by_mac, stats_by_mac, model, vc_firmware)
        connected = anchor.get("connected") if "connected" in anchor else stat.get("connected")
        if connected is None:
            connected = str(live_vc.get("status") or "").lower() == "connected" if live_vc.get("status") else None
        status = (
            "Connected"
            if connected is True
            else "Disconnected"
            if connected is False
            else str(stat.get("status") or live_vc.get("status") or anchor.get("status") or "Unknown").title()
        )
        vc_cfg = config.get("virtual_chassis") if isinstance(config.get("virtual_chassis"), dict) else {}
        preprovisioned = bool(vc_cfg.get("preprovisioned", live_vc.get("preprovisioned", True)))
        logical_mac = _clean_mac(anchor.get("mac") or config.get("mac") or live_vc.get("mac") or vc_mac)
        result.append(
            {
                "device_id": device_id,
                "site_id": sid,
                "vc_mac": vc_mac or logical_mac,
                "name": config.get("name")
                or live_vc.get("name")
                or anchor.get("name")
                or anchor.get("hostname")
                or f"VC {vc_mac or logical_mac}",
                "model": model,
                "status": status,
                "version": vc_firmware,
                "serial": live_vc.get("serial") or anchor.get("serial") or config.get("serial") or "",
                "preprovisioned": preprovisioned,
                "identity_mode": _identity_mode(logical_mac, members),
                "members": members,
                "source": "Mist site switch config + VC topology/stats"
                if include_live
                else "Mist site switch config + inventory/stats",
            }
        )

    if requested_site:
        result = [vc for vc in result if str(vc.get("site_id") or "") == requested_site]
    return sorted(result, key=lambda x: (x["site_id"], x["name"].lower()))


def _validate_members(members: list[dict]) -> list[dict]:
    """Return VC safety checks with explicit blocker/warning severity.

    Only malformed structure is a hard blocker. Mist/Junos role vocabulary,
    control-plane layout, inventory representation, and legacy identity changes
    are reviewed as warnings because Mist can legitimately represent those states
    differently and the Mist write API remains the final authority.
    """
    ids = [m.get("member_id") for m in members]
    macs = [_clean_mac(m.get("mac")) for m in members]
    roles = [_normalize_role(m.get("vc_role")) for m in members]
    allowed_roles = {"master", "backup", "routing-engine", "linecard"}
    control_roles = [r for r in roles if r in {"master", "backup", "routing-engine"}]
    expected_control = 1 if len(members) == 1 else 2

    return [
        {
            "label": "Virtual Chassis has at least one member",
            "ok": len(members) > 0,
            "level": "blocker",
        },
        {
            "label": "Member MAC addresses are valid and unique",
            "ok": bool(macs)
            and len(macs) == len(set(macs))
            and all(len(m) == 12 and all(c in "0123456789abcdef" for c in m) for m in macs),
            "level": "blocker",
        },
        {
            "label": "Member IDs are unique",
            "ok": len(ids) == len(set(ids)),
            "level": "blocker",
        },
        {
            "label": "All member IDs are non-negative integers",
            "ok": all(isinstance(i, int) and not isinstance(i, bool) and i >= 0 for i in ids),
            "level": "blocker",
        },
        {
            "label": f"Recommended: {expected_control} Routing Engine member{'s' if expected_control != 1 else ''} configured",
            "ok": len(control_roles) == expected_control,
            "level": "warning",
        },
        {
            "label": "Recommended: Master/Backup assignments are not duplicated",
            "ok": roles.count("master") <= 1 and roles.count("backup") <= 1,
            "level": "warning",
        },
        {
            "label": "Roles can be normalized to Mist Master/Backup/Linecard",
            "ok": all(r in allowed_roles for r in roles),
            "level": "warning",
        },
    ]


def _sample(value):
    """Deep-copy built-in demo data and flag every item so it is never shown as live."""
    data = deepcopy(value)
    items = data if isinstance(data, list) else [data]
    for item in items:
        if isinstance(item, dict):
            item["sample"] = True
            item["mode"] = "sample"
    return data


def _blocking_checks_failed(checks: list[dict]) -> bool:
    return any((c.get("level") or "blocker") == "blocker" and not c.get("ok") for c in checks)


def _redact_vc_audit(payload: dict) -> dict:
    """Generic audit redaction plus the config-snapshot redaction (OSPF/WEP keys, md5, …)."""
    try:
        from app.modules.config_backup.engine import redact_config
        from app.services.backup_service import _fingerprint_key

        payload = redact_config(payload, _fingerprint_key())
    except Exception:  # noqa: BLE001 - fall back to the generic redaction below
        pass
    return redact_sensitive(payload)


def _audit_write(name: str, payload: dict) -> Path:
    root = AUDIT_ROOT
    root.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    path = root / f"{stamp}_{name}.json"
    write_private_text(path, json.dumps(_redact_vc_audit(payload), indent=2, default=str))
    return path


def _member_id(member: dict) -> int:
    """member_id as int; malformed values raise a 400 instead of an unhandled 500."""
    value = member.get("member_id")
    if isinstance(value, bool):
        raise HTTPException(status_code=400, detail="VC member_id must be an integer")
    try:
        return int(value)
    except (TypeError, ValueError):
        raise HTTPException(status_code=400, detail=f"VC member_id must be an integer (got {value!r})") from None


def _member_signature(members: list[dict]) -> list[tuple]:
    """Exact (member_id, mac, role) set with master and backup kept distinct.

    Some Mist reads report Junos ``routing-engine`` for both control members;
    those are first mapped to master/backup by the same rule used for writes, so
    two reads of the same VC always produce the same signature.
    """
    rows = _canonicalize_mist_roles([m for m in members if isinstance(m, dict)])
    return sorted((_member_id(m), _clean_mac(m.get("mac")), _normalize_role(m.get("vc_role"))) for m in rows)


def _role_class_signature(members: list[dict]) -> list[tuple]:
    """(member_id, mac, role class): master/backup/routing-engine collapse to one class."""
    rows = []
    for m in members:
        if not isinstance(m, dict):
            continue
        role = _normalize_role(m.get("vc_role"))
        rows.append(
            (
                _member_id(m),
                _clean_mac(m.get("mac")),
                "routing-engine" if role in {"master", "backup", "routing-engine"} else role,
            )
        )
    return sorted(rows)


def _vc_unchanged_since_load(before_members: list[dict], original_members: list[dict]) -> bool:
    """Concurrency guard. Exact master/backup comparison when both sides state them
    explicitly; when either side only says ``routing-engine`` (config vs live views
    after a switchover), compare membership and role class so a legitimate edit is
    not refused forever."""
    if _roles_ambiguous(before_members) or _roles_ambiguous(original_members):
        return _role_class_signature(before_members) == _role_class_signature(original_members)
    return _member_signature(before_members) == _member_signature(original_members)


def _roles_ambiguous(members: list[dict]) -> bool:
    """True when a read only says 'routing-engine', so master vs backup cannot be confirmed."""
    return any(_normalize_role(m.get("vc_role")) == "routing-engine" for m in members if isinstance(m, dict))


@router.get("/sites")
def sites(refresh: bool = Query(False)):
    client = get_mist_client()
    if not client.configured:
        return _sample(SITES)
    if refresh:
        client.clear_cache_matching("/sites?", "/inventory", "/stats/devices")  # this page's reads only
    try:
        return _live_sites()
    except MistApiError:
        if client.settings.fallback_to_simulation:
            return _sample(SITES)
        raise


@router.get("/virtual-chassis")
def virtual_chassis(site_id: str = Query("all"), refresh: bool = Query(False)):
    client = get_mist_client()
    if not client.configured:
        if site_id == "all":
            return _sample([vc for values in VCS.values() for vc in values])
        return _sample(VCS.get(site_id, []))
    if refresh:
        # Refresh only the VC discovery sources instead of flushing dashboard,
        # Detective, alarm and other unrelated caches.
        client.clear_cache_matching(
            f"/api/v1/sites/{site_id}/devices",
            f"/api/v1/orgs/{client.settings.org_id}/inventory",
        )
    try:
        if site_id and site_id != "all":
            return _fast_vc_summaries(site_id)
        return _live_vcs(site_id, include_live=False)
    except MistApiError as exc:
        if client.settings.fallback_to_simulation:
            return _sample(VCS.get(site_id, []))
        raise HTTPException(status_code=exc.status_code or 502, detail=str(exc)) from exc


@router.get("/virtual-chassis/detail")
def virtual_chassis_detail(site_id: str = Query(...), device_id: str = Query(...), refresh: bool = Query(False)):
    client = get_mist_client()
    if not client.configured:
        match = next((x for x in VCS.get(site_id, []) if str(x.get("device_id")) == str(device_id)), None)
        if not match:
            raise HTTPException(status_code=404, detail="Virtual Chassis not found")
        return _sample(match)
    if refresh:
        client.clear_cache_matching(
            f"/api/v1/sites/{site_id}/devices/{device_id}",
            f"/api/v1/sites/{site_id}/devices/{device_id}/vc",
        )
    try:
        detail = _live_vc_detail(site_id, device_id)
        if not detail.get("members"):
            raise HTTPException(status_code=404, detail="Virtual Chassis not found at the selected site")
        return detail
    except MistApiError as exc:
        if client.settings.fallback_to_simulation:
            match = next((x for x in VCS.get(site_id, []) if str(x.get("device_id")) == str(device_id)), None)
            if match:
                return _sample(match)
        raise HTTPException(status_code=exc.status_code or 502, detail=str(exc)) from exc


def _sample_site_names() -> dict[str, str]:
    return {s["id"]: s["name"] for s in SITES}


def _sample_overview(site_id: str) -> dict:
    vcs = [vc for values in VCS.values() for vc in values]
    stats, events = chassis_service.sample_stats_from_vcs(vcs)
    result = chassis_service.build_overview(stats, [], events, site_id=site_id or None, site_names=_sample_site_names())
    result["sample"] = True
    return result


@router.get("/virtual-chassis/overview")
def virtual_chassis_overview(site_id: str = Query(""), refresh: bool = Query(False)):
    """Every stack in the org (or one site) ranked worst first, with plain-English issues. Read-only."""
    site_id = "" if site_id == "all" else str(site_id or "")
    client = get_mist_client()
    if not client.configured:
        return _sample_overview(site_id)
    if refresh:
        client.clear_cache_matching("/stats/devices", "/devices/events/search", "/alarms/search")
    try:
        try:
            names = client.site_name_map()
        except MistApiError:
            names = {}
        return chassis_service.collect_overview(client, site_id or None, names)
    except MistApiError as exc:
        if client.settings.fallback_to_simulation:
            return _sample_overview(site_id)
        raise HTTPException(status_code=exc.status_code or 502, detail=str(exc)) from exc


@router.get("/virtual-chassis/health")
def virtual_chassis_health(site_id: str = Query(...), device_id: str = Query(...), refresh: bool = Query(False)):
    """Rich read-only health report for one stack (members, VC links, topology, environment, events)."""
    client = get_mist_client()

    def sample():
        match = next((x for x in VCS.get(site_id, []) if str(x.get("device_id")) == str(device_id)), None)
        if not match:
            raise HTTPException(status_code=404, detail="Virtual Chassis not found")
        stats, events = chassis_service.sample_stats_from_vcs([match])
        row = chassis_service.assess_stack(stats[0], events=events, site_name=_sample_site_names().get(site_id, ""))
        row["sample"] = True
        row["warnings"] = []
        return row

    if not client.configured:
        return sample()
    if refresh:
        from app.services.mist_client import _path_id

        try:
            site_id, device_id = _path_id(site_id, "site ID"), _path_id(device_id, "device ID")
        except MistApiError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        client.clear_cache_matching(
            f"/api/v1/sites/{site_id}/stats/devices/{device_id}",
            f"/api/v1/sites/{site_id}/devices/{device_id}",
            f"/api/v1/sites/{site_id}/devices/events/search",
        )
    try:
        try:
            site_name = client.site_name_map().get(site_id, "")
        except MistApiError:
            site_name = ""
        return chassis_service.collect_stack(client, site_id, device_id, site_name)
    except MistApiError as exc:
        if client.settings.fallback_to_simulation:
            return sample()
        raise HTTPException(status_code=exc.status_code or 502, detail=str(exc)) from exc


@router.post("/virtual-chassis/preview")
def preview(payload: dict):
    members = payload.get("members", [])
    original_members = payload.get("original_members") or []
    identity_mode = str(payload.get("identity_mode") or "")
    checks = _validate_members(members)
    client = get_mist_client()
    site_id = str(payload.get("site_id") or "")

    if client.configured and site_id:
        try:
            # Advisory only: physical VC inventory representation varies by
            # platform/cloud, and a missing member MAC here must not falsely block
            # a legitimate preprovisioned VC change.
            inventory = client.list_org_inventory(device_type="switch", unassigned=False, site_id=site_id)
            inv_macs = {_clean_mac(x.get("mac")) for x in inventory if x.get("mac")}
            proposed = [_clean_mac(m.get("mac")) for m in members]
            found = sum(1 for mac in proposed if mac in inv_macs)
            checks.append(
                {
                    "label": f"Inventory cross-check: {found} of {len(proposed)} proposed member MACs found in the site inventory",
                    "ok": found == len(proposed),
                    "level": "warning",
                }
            )
        except MistApiError:
            checks.append(
                {
                    "label": "Inventory cross-check unavailable; Mist will validate the submitted configuration",
                    "ok": False,
                    "level": "warning",
                }
            )

    legacy_identity_change = False
    if identity_mode.startswith("Legacy") and original_members and not _blocking_checks_failed(checks):
        old0 = next((m for m in original_members if str(m.get("member_id")) == "0"), None)
        new0 = next((m for m in members if str(m.get("member_id")) == "0"), None)
        legacy_identity_change = bool(old0 and new0 and _clean_mac(old0.get("mac")) != _clean_mac(new0.get("mac")))
        checks.append(
            {
                "label": "High risk: member 0 changes on a legacy FPC0-based VC and may change the Mist device identity",
                "ok": not legacy_identity_change,
                "level": "warning",
            }
        )

    blocked = _blocking_checks_failed(checks)
    return {
        "valid": not blocked,
        "checks": checks,
        "write_enabled": bool(client.configured and not blocked),
        "has_warnings": any(c.get("level") == "warning" and not c.get("ok") for c in checks),
        "legacy_identity_change": legacy_identity_change,
        "mode": "live" if client.configured else "simulation",
    }


@router.post("/virtual-chassis/apply")
@holds_exit
def apply_changes(payload: dict):
    require(STACKING_WRITE)  # v0.10.22: per-person permission (desktop: always granted)
    client = get_mist_client()
    if not client.configured:
        raise HTTPException(status_code=400, detail="Mist is not configured")
    if payload.get("confirmed") is not True:
        raise HTTPException(status_code=400, detail="Explicit confirmation is required before applying a VC change")

    site_id = str(payload.get("site_id") or "")
    device_id = str(payload.get("device_id") or "")
    members = payload.get("members") or []
    preprovisioned = payload.get("preprovisioned")
    original_members = payload.get("original_members")
    if not site_id or not device_id:
        raise HTTPException(status_code=400, detail="site_id and device_id are required")
    if not isinstance(preprovisioned, bool):
        # Never guess: silently converting a non-preprovisioned VC changes how Mist manages it.
        raise HTTPException(status_code=400, detail="preprovisioned must be sent explicitly as true or false")
    if not isinstance(original_members, list) or not original_members:
        # Needed for the concurrency guard; without it a stale editor could overwrite newer Mist changes.
        raise HTTPException(status_code=400, detail="original_members (the VC as loaded in the editor) is required")
    if not isinstance(members, list) or not all(isinstance(m, dict) for m in members):
        raise HTTPException(status_code=400, detail="members must be a list of member objects")

    checks = _validate_members(members)
    if _blocking_checks_failed(checks):
        raise HTTPException(status_code=400, detail={"message": "VC structural validation failed", "checks": checks})

    audit_path: Path | None = None
    audit_record: dict = {}
    try:
        # Do not hard-block on an inventory cross-check. Mist can preprovision VC
        # members and can represent physical VC inventory differently by platform.
        # The authoritative device update below is the final API validation.
        before = client.get_site_device(site_id, device_id, fresh=True)
        before_members = _members_from_payload(before)
        before_by_mac = {_clean_mac(m.get("mac")): m for m in before_members if isinstance(m, dict)}
        # Concurrency guard: do not overwrite a VC that changed in Mist after the editor loaded.
        if before_members and not _vc_unchanged_since_load(before_members, original_members):
            raise HTTPException(
                status_code=409,
                detail="The Virtual Chassis changed in Mist after this editor was loaded. Refresh VC Data and review the new state before applying.",
            )

        # Legacy FPC0 member-0 movement is a high-risk warning shown in Preview,
        # not a synthetic backend rejection. The user explicitly reviews the diff,
        # checks the confirmation box, and confirms again before this write.
        desired = []
        write_members = _canonicalize_mist_roles(members)
        for member in write_members:
            mac = _clean_mac(member.get("mac"))
            entry = {
                "mac": mac,
                "member_id": _member_id(member),
                "vc_role": _normalize_role(member.get("vc_role")),
            }
            # Preserve configured VC ports. The editor does not change VC ports, and a
            # full virtual_chassis PUT without them would remove explicit VC-port config,
            # so fall back to the ports currently configured for this member MAC.
            vc_ports = (
                member.get("vc_ports") if "vc_ports" in member else (before_by_mac.get(mac) or {}).get("vc_ports")
            )
            if vc_ports:
                entry["vc_ports"] = list(vc_ports)
            desired.append(entry)
        request_body = {"virtual_chassis": {"preprovisioned": preprovisioned, "members": desired}}

        # Persist the pre-change evidence before issuing the network write.
        audit_record = {
            "tool": "Virtual Chassis Control Center",
            "started_at": datetime.now(timezone.utc).isoformat(),
            "status": "pending",
            "site_id": site_id,
            "device_id": device_id,
            "before": before,
            "request": request_body,
        }
        audit_path = _audit_write("virtual_chassis_change", audit_record)
        try:  # Config Backups safety snapshot; never blocks the confirmed change.
            from app.services import backup_service

            safety = backup_service.snapshot_before_change(site_id, device_id, "Chassis Manager: member change")
            audit_record["pre_change_snapshot"] = {
                k: safety.get(k) for k in ("ok", "snapshot", "skipped", "error") if k in safety
            }
        except Exception as exc:  # noqa: BLE001
            audit_record["pre_change_snapshot"] = {"ok": False, "error": type(exc).__name__}

        response = client.update_site_device(site_id, device_id, request_body)
        after = client.get_site_device(site_id, device_id, fresh=True)
        after_members = _members_from_payload(after)
        matches = bool(after_members) and _member_signature(after_members) == _member_signature(desired)
        roles_unconfirmed = matches and _roles_ambiguous(after_members)
        verified = matches and not roles_unconfirmed
        status = (
            "verified"
            if verified
            else "accepted_roles_unconfirmed"
            if roles_unconfirmed
            else "accepted_verification_pending"
        )
        audit_record.update(
            {
                "completed_at": datetime.now(timezone.utc).isoformat(),
                "status": status,
                "mist_response": response,
                "after": after,
                "verification": {"config_matches_requested": matches, "master_backup_confirmed": verified},
            }
        )
        write_private_text(audit_path, json.dumps(_redact_vc_audit(audit_record), indent=2, default=str))
        return {
            "ok": True,
            "verified": verified,
            "status": status,
            "audit_file": audit_path.name,
            "response": response,
            "after": after,
        }
    except HTTPException:
        raise
    except MistApiError as exc:
        if audit_path is not None:
            audit_record.update(
                {
                    "completed_at": datetime.now(timezone.utc).isoformat(),
                    "status": "failed",
                    "error": str(exc),
                }
            )
            write_private_text(audit_path, json.dumps(_redact_vc_audit(audit_record), indent=2, default=str))
        raise HTTPException(status_code=exc.status_code or 502, detail=str(exc)) from exc
