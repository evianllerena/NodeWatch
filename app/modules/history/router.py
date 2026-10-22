from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import json
import re
from typing import Any

from fastapi import APIRouter, Query

from app.core.config import AUDIT_ROOT
from app.core.security import redact_sensitive
from app.modules.history.activity import (
    diff_changes,
    display_value,
    field_rows,
    format_mac,
    humanize_key,
    to_epoch,
)
from app.services import audit_people
from app.services.mist_client import get_mist_client

router = APIRouter(prefix="/api/v1", tags=["history"])


def _epoch(value: Any) -> float:
    return to_epoch(value) or 0.0


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).astimezone().isoformat() if ts else ""


_STAMP = re.compile(r"^(\d{8}T\d{6})(\d{0,6})Z")
_TOOL_LABELS = {
    "port-operations": "Port Toolkit",
    "config-backup": "Config Backup",
}
_STATUS_LABELS = {
    "verified": "Verified",
    "accepted_roles_unconfirmed": "Accepted · roles not yet confirmed",
    "accepted_verification_pending": "Accepted · verification pending",
    "pending": "Pending",
    "failed": "Failed",
}


def _file_epoch(name: str) -> float:
    m = _STAMP.match(name)
    if not m:
        return 0.0
    try:
        dt = datetime.strptime(m.group(1), "%Y%m%dT%H%M%S").replace(tzinfo=timezone.utc)
        return dt.timestamp() + (int(m.group(2).ljust(6, "0")) / 1e6 if m.group(2) else 0)
    except ValueError:
        return 0.0


def _verified(payload: dict) -> bool | None:
    if isinstance(payload.get("verified"), bool):
        return payload["verified"]
    status = str(payload.get("status") or "").lower()
    if status == "verified":
        return True
    if status == "failed" or payload.get("error"):
        return False
    verification = payload.get("verification")
    if isinstance(verification, dict) and verification:
        return all(bool(v) for v in verification.values())
    return None


def _device_name(payload: dict, devices: dict[str, dict]) -> str:
    for source in (payload.get("after"), payload.get("before")):
        if isinstance(source, dict):
            for candidate in (source, source.get("switch")):
                if isinstance(candidate, dict) and candidate.get("name"):
                    return str(candidate["name"])
    device_id = str(payload.get("device_id") or "")
    entry = devices.get(device_id) or {}
    if entry.get("name"):
        return entry["name"]
    mac = device_id[-12:] if len(device_id) >= 12 else ""
    return format_mac(mac) if re.fullmatch(r"[0-9a-f]{12}", mac) else ""


def _normalize_local(name: str, payload: dict, site_names: dict[str, str], devices: dict[str, dict]) -> dict:
    payload = payload if isinstance(payload, dict) else {}
    ts = _epoch(payload.get("completed_at") or payload.get("timestamp") or payload.get("started_at")) or _file_epoch(
        name
    )
    tool = str(payload.get("tool") or "NodeWatch")
    tool = _TOOL_LABELS.get(tool, tool)
    action = humanize_key(payload.get("action") or "")
    site_id = str(payload.get("site_id") or "")
    site = site_names.get(site_id, "")
    device = _device_name(payload, devices)
    target_bits = [b for b in (device, f"port {payload['port_id']}" if payload.get("port_id") else "", site) if b]
    if not target_bits and payload.get("snapshot"):
        target_bits.append(f"snapshot {payload['snapshot']}")
    verified = _verified(payload)
    status = str(payload.get("status") or "")
    result_rows: list[dict] = []
    if status:
        result_rows.append(
            {"label": "Status", "value": _STATUS_LABELS.get(status, humanize_key(status)), "kind": "text"}
        )
    if verified is not None:
        result_rows.append({"label": "Verified", "value": "Yes" if verified else "No", "kind": "text"})
    if payload.get("error"):
        result_rows.append({"label": "Error", "value": display_value(str(payload["error"])), "kind": "text"})
    for key in ("verification", "response", "remaining_differences", "protected_override"):
        if key in payload and payload[key] not in (None, "", [], {}):
            for row in field_rows({key: payload[key]}, limit=40):
                result_rows.append(row)
    for key in ("started_at", "completed_at"):
        t = _epoch(payload.get(key))
        if t:
            result_rows.append({"label": humanize_key(key), "value": int(t * 1000), "kind": "time"})
    request_rows = field_rows(payload.get("request"), limit=80) if payload.get("request") not in (None, "") else []
    return {
        "file": name,
        "timestamp": ts,
        "time": _iso(ts),
        "tool": tool,
        "action": action,
        "site_id": site_id,
        "site": site,
        "device_id": str(payload.get("device_id") or ""),
        "device": device,
        "target": " · ".join(target_bits) or "—",
        "verified": verified,
        "status": _STATUS_LABELS.get(status, humanize_key(status)) if status else "",
        "request": request_rows,
        "result": result_rows,
        "changes": diff_changes(payload.get("before"), payload.get("after")),
    }


def _local_history(site_names: dict[str, str] | None = None, devices: dict[str, dict] | None = None) -> list[dict]:
    audit_dir = AUDIT_ROOT
    if not audit_dir.exists():
        return []
    rows = []
    for path in sorted(audit_dir.glob("*.json"), reverse=True)[:250]:
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        rows.append(_normalize_local(path.name, redact_sensitive(payload), site_names or {}, devices or {}))
    return rows


@router.get("/history")
def history(refresh: bool = Query(False), duration: str = Query("7d")):
    """Audit activity from every connected source (vendor-neutral, see app/services/audit_people.py) plus
    NodeWatch's own local change records.

    ``audit_entries`` [entry], ``actors`` {actor_ref: actor}, ``sources`` [{id, label}] (v0.10.24)."""
    client = get_mist_client()
    if refresh:
        client.clear_cache_matching("/logs/search", "/sites?", "/inventory", "/admins", "/apitokens")
        audit_people.clear_cache()
    site_names: dict[str, str] = {}
    devices: dict[str, dict] = {}
    # v0.10.40: the audit sources and the two name lookups are independent: read them together.
    with ThreadPoolExecutor(max_workers=3, thread_name_prefix="history") as pool:
        f_audit = pool.submit(audit_people.collect, duration)
        f_sites = pool.submit(client.site_name_map) if client.configured else None
        need_devices = client.configured and AUDIT_ROOT.exists() and next(AUDIT_ROOT.glob("*.json"), None) is not None
        f_devices = pool.submit(client.device_directory) if need_devices else None
        audit = f_audit.result()
        site_names = f_sites.result() if f_sites else {}
        devices = f_devices.result() if f_devices else {}
    return {
        "audit_entries": audit["entries"],
        "actors": audit["actors"],
        "sources": audit["sources"],
        "local_changes": _local_history(site_names, devices),
        "errors": audit["errors"],
        "duration": duration,
    }
