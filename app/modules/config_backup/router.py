from __future__ import annotations

import json

from fastapi import APIRouter, Body, HTTPException, Query, Request
from fastapi.responses import Response
from starlette.concurrency import run_in_threadpool

from app.core.security import redact_text
from app.services import backup_service as svc

router = APIRouter(prefix="/api/v1/config-backup", tags=["config-backup"])


def _fail(exc: Exception) -> HTTPException:
    status = getattr(exc, "status_code", None)
    if isinstance(exc, FileNotFoundError) or isinstance(exc, KeyError):
        status = 404
    code = status if isinstance(status, int) and 400 <= status < 600 else 400
    detail = exc.args[0] if isinstance(exc, KeyError) and exc.args else str(exc)
    return HTTPException(status_code=code, detail=redact_text(detail)[:500])


def _download(data: bytes, filename: str, media: str) -> Response:
    return Response(
        content=data,
        media_type=media,
        headers={"Content-Disposition": f'attachment; filename="{filename}"', "Cache-Control": "no-store"},
    )


# ------------------------------------------------------------------ landing / timeline


@router.get("/overview")
def overview(site_id: str = Query(""), refresh: bool = Query(False), full: bool = Query(False)):
    try:
        return svc.overview(site_id or None, refresh=refresh, full=full)
    except Exception as exc:
        raise _fail(exc) from exc


@router.get("/snapshots")
def snapshots(site_id: str = Query("")):
    return {"snapshots": svc.list_snapshots(site_id=site_id or None), "schedule": svc.schedule_info()}


@router.post("/snapshot")
def snapshot(payload: dict = Body(...)):
    """Take a snapshot now. No site → whole org; a site → org templates + that site."""
    try:
        site_id = str(payload.get("site_id") or "").strip()
        device_id = str(payload.get("device_id") or "").strip()
        label = str(payload.get("label") or "")
        if device_id:
            return svc.create_snapshot(site_id, device_id)
        meta = svc.create_full_snapshot([site_id] if site_id else None, org=True, trigger="manual", label=label)
        return {"ok": True, "snapshot": meta["id"], "meta": meta, "device_count": meta["device_count"]}
    except Exception as exc:
        raise _fail(exc) from exc


@router.post("/snapshots/pin")
def pin(payload: dict = Body(...)):
    try:
        return svc.set_pinned(str(payload.get("snapshot_id") or ""), payload.get("pinned") is True)
    except Exception as exc:
        raise _fail(exc) from exc


@router.post("/snapshots/delete")
def delete(payload: dict = Body(...)):
    if payload.get("confirmed") is not True:
        raise HTTPException(status_code=400, detail="Explicit confirmation is required")
    try:
        return svc.delete_snapshot(str(payload.get("snapshot_id") or ""))
    except Exception as exc:
        raise _fail(exc) from exc


@router.get("/compare")
def compare(a: str = Query(...), b: str = Query("live"), site_id: str = Query("")):
    try:
        return svc.compare(a, b, site_id or None)
    except Exception as exc:
        raise _fail(exc) from exc


@router.get("/template-drift")
def template_drift(site_id: str = Query(""), snapshot_id: str = Query("")):
    try:
        return svc.template_drift(site_id or None, snapshot_id or None)
    except Exception as exc:
        raise _fail(exc) from exc


# ------------------------------------------------------------------ objects / export / import


@router.get("/object")
def get_object(snapshot_id: str = Query(...), key: str = Query(...), download: bool = Query(False)):
    try:
        obj = svc.get_object(snapshot_id, key)
    except Exception as exc:
        raise _fail(exc) from exc
    if download:
        name = svc._safe_name(f"{obj.get('kind')}-{obj.get('name')}")
        body = json.dumps(obj.get("data"), indent=2, default=str).encode("utf-8")
        return _download(body, f"{name}.json", "application/json")
    return obj


@router.get("/export")
def export(snapshot_id: str = Query(...), fmt: str = Query("zip")):
    try:
        data, name, media = svc.export_snapshot(snapshot_id, "json" if fmt == "json" else "zip")
    except Exception as exc:
        raise _fail(exc) from exc
    return _download(data, name, media)


@router.post("/import")
async def import_snapshot(request: Request, filename: str = Query("")):
    raw = await request.body()
    try:
        # Parsing/validating an import (up to 50 MB) is CPU and disk work: keep it off the event loop
        # so the rest of the app keeps answering meanwhile.
        return await run_in_threadpool(svc.import_snapshot, raw, filename)
    except Exception as exc:
        raise _fail(exc) from exc


# ------------------------------------------------------------------ policy


@router.get("/policy")
def policy():
    return {**svc.get_policy(), "schedule": svc.schedule_info()}


@router.post("/policy")
def policy_save(payload: dict = Body(...)):
    try:
        return svc.save_policy(payload)
    except Exception as exc:
        raise _fail(exc) from exc


# ------------------------------------------------------------------ restore (Mist write)


@router.post("/restore-preview")
def preview(payload: dict = Body(...)):
    try:
        return svc.restore_object_preview(
            str(payload.get("snapshot_id") or ""),
            str(payload.get("key") or "") or None,
            str(payload.get("device_id") or "") or None,
        )
    except Exception as exc:
        raise _fail(exc) from exc


@router.post("/restore")
def do_restore(payload: dict = Body(...)):
    try:
        return svc.restore_object(
            str(payload.get("snapshot_id") or ""),
            str(payload.get("key") or "") or None,
            str(payload.get("device_id") or "") or None,
            confirmed=payload.get("confirmed") is True,
        )
    except Exception as exc:
        raise _fail(exc) from exc




