from copy import deepcopy
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import JSONResponse

from app.data.sample_data import NOC_DASHBOARD
from app.services import attention_service
from app.services.dashboard_service import build_live_dashboard
from app.services.local_state import local_state
from app.services.mist_client import MistApiError, get_mist_client
from app.services.triage.base import ReadOnlyError, StoreUnavailableError
from app.services.triage.manager import MANAGER as TRIAGE

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])


def _simulation_dashboard(mode: str, errors: list[str] | None = None) -> dict:
    data = deepcopy(NOC_DASHBOARD)
    dismissed = local_state.dismissed()
    active = [x for x in data.get("attention", []) if x.get("dismiss_key") not in dismissed]
    data["attention"] = active
    data["dismissed"] = [
        v for k, v in dismissed.items() if any(x.get("dismiss_key") == k for x in NOC_DASHBOARD.get("attention", []))
    ]
    summary = data.setdefault("summary", {})
    summary["critical"] = sum(1 for x in active if x.get("severity") == "critical")
    summary["warning"] = sum(1 for x in active if x.get("severity") == "warning")
    summary["open_issues"] = len(active)
    summary["unresolved_total"] = len(active)
    summary["acknowledged"] = sum(1 for x in active if x.get("acked"))
    summary["needs_attention"] = sum(1 for x in active if not x.get("acked"))
    summary["dismissed"] = len(data["dismissed"])
    data["mode"] = mode
    data["errors"] = errors or []
    alerts = attention_service.alerts_from_legacy(NOC_DASHBOARD.get("attention", []))
    attention_service.remember(alerts, [], preview=True)  # sample data: in-memory triage only
    data["incidents"] = attention_service.payload()
    counts = data["incidents"]["counts"]
    summary.update(
        critical=counts["critical"],
        warning=counts["warning"],
        open_issues=counts["open"],
        unresolved_total=counts["open"],
        acknowledged=counts["acknowledged"],
        needs_attention=counts["new"],
        dismissed=counts["suppressed"],
    )
    return data


def _compact(data: dict) -> dict:
    """HTTP response: incidents instead of the full per-alert list (members are paged on demand)."""
    out = dict(data)
    out["attention"] = []
    return out


# What the Command Center reads from Mist (cleared by its Refresh button; v0.10.40).
DASHBOARD_READS = (
    "/alarms/search",
    "/stats/sites",
    "/inventory/search",
    "/inventory?",
    "/stats/devices",
    "/sites?",
    "/alarm_defs",
    "/devices/events/search",  # also brings the event buffer up to date
)


@router.get("")
def dashboard(refresh: bool = Query(False)):
    client = get_mist_client()
    if refresh:
        # v0.10.40: Refresh re-reads what this page shows; other pages keep their warm reads.
        client.clear_cache_matching(*DASHBOARD_READS)
    if not client.configured:
        data = _simulation_dashboard("simulation", client.settings.validate())
        data["configuration_required"] = True
        return data
    try:
        return _compact(build_live_dashboard(client, legacy_details=False))
    except MistApiError as exc:
        if not client.settings.fallback_to_simulation:
            raise HTTPException(status_code=exc.status_code or 502, detail=str(exc)) from exc
        return _simulation_dashboard("simulation-fallback", [str(exc)])


# --------------------------------------------------------------------------- incidents (v0.10.16)


def _ensure_alerts() -> None:
    """After a backend restart the incident cache is empty: rebuild it once."""
    if attention_service.cached_alerts():
        return
    client = get_mist_client()
    if client.configured:
        try:
            build_live_dashboard(client, legacy_details=False)
        except MistApiError as exc:
            raise HTTPException(status_code=exc.status_code or 502, detail=str(exc)) from exc
    else:
        _simulation_dashboard("simulation")


@router.get("/incidents")
def incidents():
    _ensure_alerts()
    return attention_service.payload()


@router.get("/incidents/{incident_id}")
def incident(incident_id: str, offset: int = Query(0, ge=0), limit: int = Query(50, ge=1, le=500), state: str = ""):
    _ensure_alerts()
    detail = attention_service.incident_detail(incident_id, offset=offset, limit=limit, state=state)
    if detail is None:
        raise HTTPException(status_code=404, detail="This incident is no longer open — it may have resolved.")
    return detail


@router.post("/triage")
def triage(payload: dict):
    _ensure_alerts()
    try:
        return attention_service.triage(payload or {})
    except attention_service.ConflictError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ReadOnlyError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except StoreUnavailableError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/triage/undo")
def triage_undo(payload: dict):
    try:
        return attention_service.undo(str((payload or {}).get("token") or ""))
    except ReadOnlyError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


# --------------------------------------------------------------------------- team triage (v0.10.18)


def _store_errors(fn, *args):
    try:
        return fn(*args)
    except ReadOnlyError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except StoreUnavailableError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/triage/store")
def triage_store():
    """Settings › Team triage: available stores (from their manifests), the active one and its status."""
    return TRIAGE.describe()


@router.post("/triage/store")
def triage_store_save(payload: dict):
    """Choose the store (``backend``, ``settings``, ``display_name``, ``copy_local``)."""
    return _store_errors(TRIAGE.save, payload or {})


@router.post("/triage/store/test")
def triage_store_test(payload: dict):
    """Probe a store without switching to it (shared folder: write, read back and delete a probe file)."""
    return _store_errors(TRIAGE.test, payload or {})


@router.get("/triage/status")
def triage_status():
    return TRIAGE.status()


@router.post("/triage/sync")
def triage_sync():
    backend = TRIAGE.backend()
    backend.sync(force=True)
    return TRIAGE.status()


@router.get("/triage/actors")
def triage_actors():
    return {"actors": TRIAGE.actors(), "me": TRIAGE.actor()}


@router.get("/triage/export")
def triage_export():
    data = TRIAGE.export()
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    return JSONResponse(
        data, headers={"Content-Disposition": f'attachment; filename="nodewatch-triage-history-{stamp}.json"'}
    )


@router.get("/suppressed")
def suppressed(kind: str = "", offset: int = Query(0, ge=0), limit: int = Query(200, ge=1, le=1000)):
    _ensure_alerts()
    return attention_service.suppressed(kind=kind, offset=offset, limit=limit)


@router.post("/mutes")
def add_mute(payload: dict):
    try:
        return attention_service.add_mute(payload or {})
    except ReadOnlyError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/mutes/{rule_id}/remove")
def remove_mute(rule_id: str):
    try:
        return attention_service.remove_mute(rule_id)
    except ReadOnlyError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/dismiss")
def dismiss_condition(payload: dict):
    key = str(payload.get("key") or "").strip()
    if not key:
        raise HTTPException(status_code=400, detail="Dismiss key is required")
    record = {
        "key": key,
        "title": str(payload.get("title") or "Condition"),
        "type": str(payload.get("type") or ""),
        "device": str(payload.get("device") or ""),
        "site": str(payload.get("site") or ""),
        "dismissed_at": datetime.now(timezone.utc).isoformat(),
    }
    local_state.dismiss(key, record)
    return {"ok": True, "record": record}


@router.post("/dismiss/bulk")
def dismiss_conditions_bulk(payload: dict):
    items = payload.get("items") or []
    if not isinstance(items, list) or not items:
        raise HTTPException(status_code=400, detail="At least one condition is required")
    if len(items) > 1000:
        raise HTTPException(status_code=400, detail="Bulk dismiss is limited to 1000 conditions per request")
    records = []
    now = datetime.now(timezone.utc).isoformat()
    for item in items:
        if not isinstance(item, dict):
            continue
        key = str(item.get("key") or "").strip()
        if not key:
            continue
        records.append(
            {
                "key": key,
                "title": str(item.get("title") or "Condition"),
                "type": str(item.get("type") or ""),
                "device": str(item.get("device") or ""),
                "site": str(item.get("site") or ""),
                "dismissed_at": now,
            }
        )
    if not records:
        raise HTTPException(status_code=400, detail="No valid condition records were supplied")
    count = local_state.dismiss_many(records)
    return {"ok": True, "dismissed": count}


@router.post("/dismiss/restore-all")
def restore_all_conditions():
    count = local_state.restore_all()
    return {"ok": True, "restored": count}


@router.post("/dismiss/{key:path}/restore")
def restore_condition(key: str):
    local_state.restore(key)
    return {"ok": True, "key": key}


@router.post("/disconnects/dismiss")
def dismiss_disconnect(payload: dict):
    key = str(payload.get("key") or "").strip()
    if not key:
        raise HTTPException(status_code=400, detail="Disconnect key is required")
    record = {
        "key": key,
        "device": str(payload.get("device") or "Known-down device"),
        "device_type": str(payload.get("device_type") or "device"),
        "mac": str(payload.get("mac") or ""),
        "site": str(payload.get("site") or ""),
        "dismissed_at": datetime.now(timezone.utc).isoformat(),
        "note": str(payload.get("note") or "Known down / intentionally suppressed by engineer")[:300],
    }
    local_state.dismiss_disconnect(key, record)
    return {"ok": True, "record": record}


@router.post("/disconnects/dismiss/bulk")
def dismiss_disconnects_bulk(payload: dict):
    items = payload.get("items") or []
    if not isinstance(items, list) or not items:
        raise HTTPException(status_code=400, detail="At least one disconnect is required")
    if len(items) > 500:
        raise HTTPException(status_code=400, detail="Bulk dismiss is limited to 500 disconnects per request")
    records = []
    now = datetime.now(timezone.utc).isoformat()
    for item in items:
        if not isinstance(item, dict):
            continue
        key = str(item.get("key") or "").strip()
        if not key:
            continue
        records.append(
            {
                "key": key,
                "device": str(item.get("device") or "Known-down device"),
                "device_type": str(item.get("device_type") or "device"),
                "mac": str(item.get("mac") or ""),
                "site": str(item.get("site") or ""),
                "dismissed_at": now,
                "note": str(item.get("note") or "Known down / intentionally suppressed by engineer")[:300],
            }
        )
    if not records:
        raise HTTPException(status_code=400, detail="No valid disconnect records were supplied")
    count = local_state.dismiss_disconnects(records)
    return {"ok": True, "dismissed": count}


@router.post("/disconnects/dismiss/restore-all")
def restore_all_disconnects():
    count = local_state.restore_all_disconnects()
    return {"ok": True, "restored": count}


@router.post("/disconnects/dismiss/{key:path}/restore")
def restore_disconnect(key: str):
    local_state.restore_disconnect(key)
    return {"ok": True, "key": key}
