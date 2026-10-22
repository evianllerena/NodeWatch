from fastapi import APIRouter, Body, HTTPException, Query

from app.services.alerting_service import build_alert_feed, get_alerting_config, poll_and_notify, save_alerting_config

router = APIRouter(prefix="/api/v1/alerting", tags=["alerting"])


@router.get("/feed")
def feed(refresh: bool = Query(False)):
    return build_alert_feed(fresh=refresh)


@router.get("/config")
def config():
    return get_alerting_config()


@router.post("/config")
def save_config(payload: dict = Body(...)):
    try:
        return save_alerting_config(payload)
    except (ValueError, RuntimeError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/test")
def test_webhook():
    try:
        return poll_and_notify(force_test=True)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
