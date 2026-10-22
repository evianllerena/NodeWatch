from fastapi import APIRouter, Body, HTTPException, Query
from fastapi.responses import FileResponse

from app.services.siem_service import (
    display_events,
    export_events,
    forward_once,
    get_forwarder_config,
    save_forwarder_config,
)

router = APIRouter(prefix="/api/v1/siem", tags=["siem"])


@router.get("/preview")
def preview(limit: int = Query(200, ge=1, le=1000)):
    return {"events": display_events(limit)}


@router.post("/export")
def export(fmt: str = Query("jsonl"), limit: int = Query(1000, ge=1, le=5000)):
    if fmt not in {"jsonl", "cef"}:
        raise HTTPException(status_code=400, detail="fmt must be jsonl or cef")
    path = export_events(fmt, limit)
    return FileResponse(path, filename=path.name, media_type="text/plain")


@router.get("/forwarder")
def forwarder_status():
    return get_forwarder_config()


@router.post("/forwarder")
def forwarder_save(payload: dict = Body(...)):
    try:
        return save_forwarder_config(payload)
    except (ValueError, RuntimeError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/forwarder/test")
def forwarder_test():
    try:
        return forward_once(force_sample=True)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@router.post("/forwarder/diagnose")
def forwarder_diagnose():
    from app.services.siem_service import diagnose_hec

    return diagnose_hec()


@router.post("/forwarder/run")
def forwarder_run():
    try:
        return forward_once()
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
