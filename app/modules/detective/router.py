from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query

from app.data.sample_data import SITES
from app.integrations.base import IntegrationError
from app.integrations.providers.traffic import get_traffic_sessions_provider
from app.services.detective_service import detective_troubleshoot
from app.services.mist_client import MistApiError, get_mist_client
from app.services.unified_device_service import (
    detective_field_catalog,
    unified_detective_detail,
    unified_search_detective,
)

router = APIRouter(prefix="/api/detective", tags=["detective"])


@router.get("/sites")
def sites():
    client = get_mist_client()
    if not client.configured:
        return SITES
    try:
        rows = [
            {"id": str(x.get("id") or ""), "name": str(x.get("name") or x.get("id") or "Unnamed site")}
            for x in client.list_sites()
        ]
        return sorted(rows, key=lambda x: x["name"].casefold())
    except MistApiError as exc:
        raise HTTPException(status_code=exc.status_code or 502, detail=str(exc)) from exc


@router.get("/fields")
def fields():
    return detective_field_catalog()


@router.get("/search")
def search(q: str = Query("", max_length=200), site_id: str | None = Query(None)):
    q = (q or "").strip()
    if len(q) < 2 and not site_id:
        raise HTTPException(status_code=400, detail="Select a site or enter at least two search characters")
    try:
        return unified_search_detective(q, site_id=site_id or None)
    except MistApiError as exc:
        raise HTTPException(status_code=exc.status_code or 502, detail=str(exc)) from exc
    except IntegrationError as exc:
        raise HTTPException(status_code=exc.status_code or 502, detail=str(exc)) from exc


@router.get("/detail")
def detail(
    kind: str = Query(...),
    mac: str = Query(...),
    site_id: str | None = Query(None),
    refresh: bool = Query(False),
):
    allowed = {"wireless_client", "wired_client", "nac_client", "infrastructure", "endpoint"}
    if kind not in allowed:
        raise HTTPException(status_code=400, detail=f"Unsupported Detective result type: {kind}")
    try:
        return unified_detective_detail(kind, mac, site_id=site_id or None, fresh=refresh)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except MistApiError as exc:
        raise HTTPException(status_code=exc.status_code or 502, detail=str(exc)) from exc
    except IntegrationError as exc:
        raise HTTPException(status_code=exc.status_code or 502, detail=str(exc)) from exc


@router.get("/troubleshoot")
def troubleshoot(
    mac: str = Query(...),
    site_id: str | None = Query(None),
):
    try:
        return detective_troubleshoot(mac, site_id=site_id or None)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except MistApiError as exc:
        raise HTTPException(status_code=exc.status_code or 502, detail=str(exc)) from exc


@router.get("/traffic")
def traffic(
    ip: str = Query(..., max_length=64),
    window: str = Query("1h", pattern="^(15m|1h|6h|24h)$"),
    limit: int = Query(300, ge=1, le=1000),
    cursor: str | None = Query(None, max_length=256),
    refresh: bool = Query(False),
    since_ms: int | None = Query(None, ge=0),
):
    """Provider-neutral Traffic & Sessions API backed by the explicitly approved SLS adapter.

    ``since_ms`` (live mode) returns only logs newer than about three minutes before that time."""
    provider = get_traffic_sessions_provider()
    try:
        return provider.search_by_ip(ip, window=window, limit=limit, cursor=cursor, fresh=refresh, since_ms=since_ms)
    except IntegrationError as exc:
        states = {
            "SLS_NOT_CONFIGURED": (
                False,
                "not_configured",
                "Not configured",
                "Strata Logging Service is not configured and verified.",
            ),
            "CAPABILITY_UNAVAILABLE": (
                False,
                "not_configured",
                "Not configured",
                "Strata Logging Service is not configured and verified for Traffic & Sessions.",
            ),
            "SLS_TOKEN_EXCHANGE_FAILED": (
                True,
                "authentication_failed",
                "Authentication failed",
                "Strata Logging Service token exchange failed.",
            ),
            "SLS_AUTHENTICATION_FAILED": (
                True,
                "authentication_failed",
                "Authentication failed",
                "Strata Logging Service authentication failed.",
            ),
            "SLS_PERMISSION_DENIED": (
                True,
                "permission_denied",
                "Permission denied",
                "The configured SLS identity cannot read firewall traffic logs.",
            ),
            "SLS_RATE_LIMITED": (
                True,
                "rate_limited",
                "Rate limited",
                "Strata Logging Service rate limit reached; retry shortly.",
            ),
            "CIRCUIT_OPEN": (
                True,
                "circuit_open",
                "Circuit open",
                "Traffic queries are temporarily paused after repeated provider failures.",
            ),
            "SLS_QUERY_TIMEOUT": (
                True,
                "query_timeout",
                "Query timed out",
                "The Strata traffic query did not complete before the timeout.",
            ),
            "OPERATION_TIMEOUT": (
                True,
                "query_timeout",
                "Query timed out",
                "The traffic query exceeded NodeWatch's timeout budget.",
            ),
            "SLS_PROVIDER_UNAVAILABLE": (
                True,
                "service_unavailable",
                "Service unavailable",
                "Strata Logging Service authentication is temporarily unavailable.",
            ),
            "SLS_QUERY_UNAVAILABLE": (
                True,
                "service_unavailable",
                "Service unavailable",
                "Strata Logging Service traffic querying is temporarily unavailable.",
            ),
            "SLS_CONFIGURATION_ERROR": (
                False,
                "configuration_invalid",
                "Configuration invalid",
                "The SLS credential configuration is invalid.",
            ),
            "SLS_INVALID_PROVIDER_RESPONSE": (
                True,
                "configuration_invalid",
                "Configuration invalid",
                "Strata Logging Service returned an unexpected endpoint or response.",
            ),
        }
        if exc.code in states:
            configured, status, label, message = states[exc.code]
            return {
                "schema_version": "1.0",
                "available": False,
                "configured": configured,
                "provider": "strata_logging_service",
                "source": "strata_logging_service",
                "provider_authority": "strata_logging_service",
                "status": status,
                "sessions": [],
                "count": 0,
                "client_ip": ip,
                "window": window,
                "error_code": exc.code,
                "message": message,
                "status_label": label,
            }
        raise HTTPException(status_code=exc.status_code or 502, detail=str(exc)) from exc
