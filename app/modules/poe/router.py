from fastapi import APIRouter, HTTPException, Query

from app.services.mist_client import MistApiError
from app.services.poe_service import poe_overview, poe_summary

router = APIRouter(prefix="/api/v1/poe", tags=["poe"])


@router.get("/summary")
def summary(site_id: str = Query(...), device_id: str = Query(...), fresh: bool = Query(False)):
    """One switch's PoE state. Cached reads (Mist refreshes these statistics about once a minute) unless
    ``fresh`` (the page's Refresh now) asks Mist directly (v0.10.40: every 30 s cycle used to)."""
    try:
        return poe_summary(site_id, device_id, fresh=fresh)
    except MistApiError as exc:
        raise HTTPException(
            status_code=exc.status_code or 502, detail=f"Mist could not return PoE data for this switch: {exc}"
        ) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/overview")
def overview(site_id: str = Query(""), fresh: bool = Query(False)):
    """Org-wide (no site) or site-wide PoE risk overview used when no switch is selected."""
    try:
        return poe_overview(site_id or None, fresh=fresh)
    except MistApiError as exc:
        raise HTTPException(
            status_code=exc.status_code or 502, detail=f"Mist could not return the PoE overview: {exc}"
        ) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
