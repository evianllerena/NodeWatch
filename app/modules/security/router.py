"""Security Operations API (v0.10.30) and the legacy posture findings.

Everything under ``/api/v1/security/soc*`` is built by :mod:`app.services.soc` from vendor-neutral
records. ``sample=true`` answers from clearly labelled sample data (preview before a source is connected).
Case changes are local triage notes (state, owner, notes) and never reach a vendor system.
"""

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from app.core.security import redact_text
from app.services.security_service import posture
from app.services.soc import service as soc

router = APIRouter(prefix="/api/v1/security", tags=["security"])

WINDOW = "^(1h|6h|24h|3d|7d)$"


@router.get("/posture")
def get_posture(site_id: str | None = Query(None)):
    try:
        return posture(site_id or None)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=redact_text(exc)) from exc


@router.get("/soc")
def get_soc(
    window: str = Query("24h", pattern=WINDOW),
    site: str = Query("", max_length=200),
    sample: bool = Query(False),
):
    return soc.soc(window, site, sample)


@router.get("/soc/cases/{case_id}")
def get_case(case_id: str, window: str = Query("7d", pattern=WINDOW), sample: bool = Query(False)):
    found = soc.case_detail(case_id[:20], window, sample)
    if found is None:
        raise HTTPException(status_code=404, detail="This case is not in the selected window any more.")
    return found


class CaseUpdate(BaseModel):
    state: str | None = Field(None, max_length=20)
    owner: str | None = Field(None, max_length=120)
    note: str | None = Field(None, max_length=2000)


@router.post("/soc/cases/{case_id}")
def post_case(case_id: str, body: CaseUpdate):
    try:
        return soc.update_case(case_id[:20], state=body.state, owner=body.owner, note=body.note)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/soc/events")
def get_events(
    window: str = Query("24h", pattern=WINDOW),
    sample: bool = Query(False),
    q: str = Query("", max_length=200),
    kind: str = Query("", max_length=40),
    outcome: str = Query("", max_length=40),
    severity: str = Query("", max_length=40),
    direction: str = Query("", max_length=40),
    country: str = Query("", max_length=4),
    site: str = Query("", max_length=200),
    source: str = Query("", max_length=80),
    reach: int | None = Query(None, ge=1, le=5),
    through: bool = Query(False),
    signature: str = Query("", max_length=200),
    key: str = Query("", max_length=80),
    cve: str = Query("", max_length=40),
    limit: int = Query(200, ge=1, le=1000),
    offset: int = Query(0, ge=0, le=100000),
):
    return soc.events(
        window,
        sample=sample,
        q=q,
        reach=reach,
        through=through,
        signature=signature,
        key=key,
        cve=cve,
        limit=limit,
        offset=offset,
        kind=kind,
        outcome=outcome,
        severity=severity,
        direction=direction,
        country=country,
        site=site,
        source=source,
    )


@router.get("/soc/vulnerabilities")
def get_vulnerabilities(window: str = Query("7d", pattern=WINDOW), sample: bool = Query(False)):
    return soc.vulnerabilities(window, sample)


@router.post("/soc/refresh")
def post_refresh():
    return soc.refresh()
