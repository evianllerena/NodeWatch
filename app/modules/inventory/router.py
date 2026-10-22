from copy import deepcopy

from fastapi import APIRouter, HTTPException, Query

from app.data.sample_data import INVENTORY
from app.services.mist_client import MistApiError, get_mist_client

router = APIRouter(prefix="/api/v1", tags=["inventory"])


def _clean(value) -> str:
    return str(value or "").lower().replace(":", "").replace("-", "")


def _normalise_inventory(items: list[dict], sites: list[dict], stats: list[dict]) -> list[dict]:
    site_names = {str(s.get("id")): str(s.get("name") or s.get("id")) for s in sites}
    stats_by_mac = {_clean(s.get("mac")): s for s in stats if s.get("mac")}
    rows = []
    for item in items:
        dtype = str(item.get("type") or item.get("device_type") or "").lower()
        model = str(item.get("model") or "")
        if dtype and dtype != "switch":
            continue
        if not dtype and model and not model.upper().startswith(("EX", "QFX")):
            continue
        mac = _clean(item.get("mac"))
        sid = str(item.get("site_id") or "")
        stat = stats_by_mac.get(mac, {})
        assigned = bool(sid)
        connected = item.get("connected") if "connected" in item else stat.get("connected")
        status_text = str(item.get("status") or stat.get("status") or "").lower()
        if connected is None and status_text:
            if status_text in {"connected", "online", "up"}:
                connected = True
            elif status_text in {"disconnected", "offline", "down"}:
                connected = False
        if not assigned:
            status = "Unassigned"
        elif connected is False:
            status = "Assigned / Down"
        elif connected is True:
            status = "Assigned / Connected"
        else:
            status = "Assigned"
        rows.append(
            {
                "id": item.get("id"),
                "mac": mac,
                "serial": item.get("serial") or item.get("serial_number") or "—",
                "model": model or stat.get("model") or "Unknown",
                "status": status,
                "connected": connected,
                "site": site_names.get(sid, sid or "Unassigned"),
                "site_id": sid or None,
                "vc_mac": _clean(item.get("vc_mac")),
                "in_virtual_chassis": bool(item.get("vc_mac")),
                "name": item.get("name") or item.get("hostname") or "",
            }
        )
    return sorted(rows, key=lambda x: (x["site"], x["model"], x["serial"]))


def _sample(rows):
    """Built-in demo inventory, flagged per row so it is never presented as live data."""
    data = deepcopy(rows)
    for row in data if isinstance(data, list) else []:
        if isinstance(row, dict):
            row["sample"] = True
            row["mode"] = "sample"
    return data


@router.get("/inventory")
def inventory(refresh: bool = Query(False), site_id: str | None = Query(None)):
    client = get_mist_client()
    if not client.configured:
        return _sample(INVENTORY)
    if refresh:
        client.clear_cache_matching("/inventory", "/stats/devices", "/sites?")  # this page's reads only
    try:
        from concurrent.futures import ThreadPoolExecutor

        with ThreadPoolExecutor(max_workers=3, thread_name_prefix="inventory") as pool:
            f_inventory = pool.submit(
                client.list_org_inventory,
                device_type="switch",
                vc=True,
                unassigned=not bool(site_id),
                site_id=site_id or None,
            )
            f_sites = pool.submit(client.list_sites)
            f_status = pool.submit(
                client.search_org_inventory, device_type="switch", site_id=site_id or None, limit=50_000
            )
            base_inventory = f_inventory.result()
            sites = f_sites.result()
            status_rows = f_status.result()
        rows = _normalise_inventory(base_inventory, sites, status_rows)
        if site_id:
            rows = [row for row in rows if str(row.get("site_id") or "") == str(site_id)]
        return rows
    except MistApiError as exc:
        if client.settings.fallback_to_simulation:
            return _sample(INVENTORY)
        raise HTTPException(status_code=exc.status_code or 502, detail=str(exc)) from exc
