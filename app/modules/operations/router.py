from fastapi import APIRouter, Body, HTTPException, Query

from app.services.mist_client import MistApiError, get_mist_client
from app.services.operations_service import (
    PortActionError,
    execute_port_action,
    get_switch_ports,
    list_switches,
    port_overview,
    port_profiles,
    preview_port_action,
)

router = APIRouter(prefix="/api/v1/operations", tags=["operations"])


@router.get("/sites")
def sites():
    client = get_mist_client()
    try:
        rows = [{"id": x.get("id"), "name": x.get("name") or x.get("id")} for x in client.list_sites()]
    except MistApiError as exc:
        raise HTTPException(status_code=exc.status_code or 502, detail=str(exc)) from exc
    return sorted(rows, key=lambda x: str(x.get("name") or "").casefold())


@router.get("/overview")
def overview(site_id: str = Query(""), fresh: bool = False):
    """Most important port problems org-wide (no site) or for one site, ranked by severity."""
    try:
        return port_overview(site_id or None, fresh=fresh)
    except MistApiError as exc:
        raise HTTPException(status_code=exc.status_code or 502, detail=str(exc)) from exc


@router.get("/switches")
def switches(site_id: str = Query(...)):
    try:
        return list_switches(site_id)
    except MistApiError as exc:
        raise HTTPException(status_code=exc.status_code or 502, detail=str(exc)) from exc


@router.get("/ports")
def ports(site_id: str = Query(...), device_id: str = Query(...), fresh: bool = False):
    try:
        return get_switch_ports(site_id, device_id, fresh=fresh)
    except MistApiError as exc:
        raise HTTPException(status_code=exc.status_code or 502, detail=str(exc)) from exc


@router.get("/port-profiles")
def profiles(site_id: str = Query(...), device_id: str = Query(...)):
    try:
        return port_profiles(site_id, device_id)
    except MistApiError as exc:
        raise HTTPException(status_code=exc.status_code or 502, detail=str(exc)) from exc


@router.post("/preview")
def preview(payload: dict = Body(...)):
    try:
        return preview_port_action(
            str(payload.get("site_id") or ""),
            str(payload.get("device_id") or ""),
            str(payload.get("port_id") or ""),
            str(payload.get("action") or ""),
            payload.get("payload") or {},
        )
    except MistApiError as exc:
        raise HTTPException(status_code=exc.status_code or 502, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/execute")
def execute(payload: dict = Body(...)):
    try:
        return execute_port_action(
            str(payload.get("site_id") or ""),
            str(payload.get("device_id") or ""),
            str(payload.get("port_id") or ""),
            str(payload.get("action") or ""),
            # Strict boolean: "yes", 1 or any other truthy value is not a confirmation.
            confirmed=payload.get("confirmed") is True,
            payload=payload.get("payload") or {},
        )
    except MistApiError as exc:
        raise HTTPException(status_code=exc.status_code or 502, detail=str(exc)) from exc
    except PortActionError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
