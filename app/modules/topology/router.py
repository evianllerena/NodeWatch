"""Topology API (v0.10.16–18): org map, the vendor-neutral site graph, change baseline, live health, path trace.

Everything is read-only towards the network; the only write is the local change baseline.
"""

from __future__ import annotations

import time
from typing import Any

from fastapi import APIRouter, HTTPException, Path, Query
from pydantic import BaseModel, Field

from app.services.path_trace_service import PROTOCOLS, trace
from app.services import topology_search
from app.services import topology_snapshot_service as snapshots
from app.services.topology_health_service import topology_health
from app.services.topology_org_service import org_view
from app.services.topology_overview import trim
from app.services.topology_service import graph_for, list_sites, node_detail, site_routes, topology_view

_META = ("version", "built_at", "age_s", "stale", "refreshing", "partial", "refresh_error", "generated_at")


def _unchanged(result: dict[str, Any], since: str) -> dict[str, Any] | None:
    """Cheap poll answer: the client already has this version."""
    if since and result.get("version") == since:
        return {"unchanged": True, **{k: result.get(k) for k in _META}}
    return None


def _wants_l3(layers: str) -> bool:
    return "l3" in {x.strip().lower() for x in str(layers or "").split(",")}


router = APIRouter(prefix="/api/v1/topology", tags=["topology"])


@router.get("")
def topology(
    site: str = Query("", max_length=200),
    fresh: bool = Query(False),
    layers: str = Query("", max_length=100),
    since: str = Query("", max_length=64),
    view: str = Query("", max_length=20),
):
    """Nodes, links, layers, per-source status and data gaps for one site (or everything).

    Answers instantly from the last build (``stale``/``refreshing``/``built_at``) while a rebuild runs in
    the background; ``fresh=true`` (the Refresh button) starts a rebuild. Poll until ``refreshing`` is false.
    ``layers`` (comma list, default physical,overlay): add ``l3`` to read routed devices' interface and
    route tables (layer-3 links) — slower, built and cached separately. ``since=<version>`` answers
    ``{"unchanged": true, version, …}`` when the map has not changed.
    """
    try:
        result = topology_view(site or None, fresh=fresh, l3=_wants_l3(layers))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    same = _unchanged(result, since)
    if same:
        return same
    if view == "overview":
        result = trim(result)
    if result.get("partial"):
        return {
            **result,
            "changes": {
                "total": 0,
                "new_nodes": [],
                "missing_nodes": [],
                "new_links": [],
                "missing_links": [],
                "baseline_at": None,
            },
        }
    return {**result, "changes": snapshots.changes(result)}


@router.get("/org")
def org(
    thresholds: str = Query("", max_length=2000),
    fresh: bool = Query(False),
    since: str = Query("", max_length=64),
):
    """Organization map: sites as nodes, WAN / SD-WAN tunnels between sites with health."""
    try:
        result = org_view(fresh=fresh, thresholds=thresholds)
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    same = _unchanged(result, since)
    if same:
        return same
    try:  # v0.10.37: what the organisation views say (types, overlays, coverage, attention) — never fatal
        from app.services.topology_org_insights import insights

        result = {**result, "insights": insights(result)}
    except Exception as exc:  # noqa: BLE001
        import logging

        logging.getLogger("nodewatch.topology").info("topology: org insights skipped: %s", exc)
    return result


@router.get("/node/{node_id}")
def node(node_id: str = Path(..., min_length=1, max_length=64), site: str = Query("", max_length=200)):
    """One node of a site map in full (records, evidence, members, seen-by) with every link touching it,
    its neighbors' names and its WAN circuits — for the detail panel of the light ``view=overview`` map."""
    try:
        out = node_detail(site or None, node_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if out is None:
        raise HTTPException(status_code=404, detail="That device is not on this map (rebuilt since?)")
    return out


@router.get("/routes")
def routes(site: str = Query("", max_length=200), node: str = Query("", max_length=64)):
    """Routing tables of the site's routed devices (Topology › Routing panel, v0.10.32). Read-only."""
    try:
        return site_routes(site or None, node)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/search")
def search(q: str = Query("", max_length=200), limit: int = Query(50, ge=1, le=500)):
    """Organisation-wide device search (names, member names/serials, IPs, MACs, serials, models) from the
    cached index — never waits for a source. ``building: true`` while no index exists yet."""
    return topology_search.search(q, limit)


@router.get("/site-map")
def site_map():
    """Canonical sites, every connector site's mapping (+ suggestion, confidence), unassigned devices."""
    return topology_search.site_map_view()


class HaPartner(BaseModel):
    name: str = Field("", max_length=200)
    state: str = Field("passive", max_length=40)


class SiteMapUpdate(BaseModel):
    mappings: dict[str, str] = Field(default_factory=dict)
    device_sites: dict[str, str] = Field(default_factory=dict)
    # v0.10.27: {unit record key "source:key" or node id: {"name", "state"} | null to remove}
    ha_partners: dict[str, HaPartner | None] = Field(default_factory=dict)


@router.put("/site-map")
def put_site_map(body: SiteMapUpdate):
    """Merge mappings: ``{connector site key: canonical site key}`` and ``{device record key ("source:key")
    : canonical site key}``; an empty value removes the user's mapping (back to automatic). Mapping a
    connector site to its own key keeps it a separate site. Every map is rebuilt in the background."""
    if len(body.mappings) + len(body.device_sites) + len(body.ha_partners) > 5000:
        raise HTTPException(status_code=400, detail="Too many mappings in one request")
    for k, v in list(body.mappings.items()) + list(body.device_sites.items()):
        if len(k) > 300 or len(v) > 300:
            raise HTTPException(status_code=400, detail="Mapping keys and values are at most 300 characters")
    if any(len(k) > 300 for k in body.ha_partners):
        raise HTTPException(status_code=400, detail="HA partner keys are at most 300 characters")
    partners = {k: (v.model_dump() if v is not None else None) for k, v in body.ha_partners.items()}
    return topology_search.update_site_map(body.mappings, body.device_sites, partners)


class BaselineRequest(BaseModel):
    site: str = Field("", max_length=200)


@router.post("/baseline")
def baseline(body: BaselineRequest):
    """Accept the current map of a site as the baseline later maps are compared with (local file only)."""
    try:
        result = graph_for(body.site or None)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if result.get("partial"):
        raise HTTPException(status_code=409, detail="The map is still being built — accept it once it is complete.")
    return snapshots.accept(result)


@router.get("/sites")
def sites():
    """Sites from every connected inventory source (the Topology site picker)."""
    return list_sites()


@router.get("/health")
def health(
    site: str = Query("", max_length=200),
    thresholds: str = Query("", max_length=2000),
    fresh: bool = Query(False),
):
    """Live per-device / per-link health for the map (raw readings cached 25 s; thresholds per request)."""
    try:
        return topology_health(site or None, thresholds=thresholds, fresh=fresh)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


class TraceRequest(BaseModel):
    src: str = Field(..., min_length=1, max_length=253)
    dst: str = Field(..., min_length=1, max_length=253)
    dst_port: int | None = Field(None, ge=1, le=65535)
    protocol: str = Field("tcp", max_length=8)
    site: str = Field("", max_length=200)
    thresholds: dict[str, Any] | None = None


@router.post("/trace")
def trace_path(body: TraceRequest):
    """Read-only path trace src → dst: hops (L2 → L3 → policy → overlay), gaps and a verdict."""
    if body.protocol.lower() not in PROTOCOLS:
        raise HTTPException(status_code=400, detail=f"protocol must be one of {', '.join(PROTOCOLS)}")
    try:
        return trace(
            body.src,
            body.dst,
            body.dst_port,
            body.protocol,
            site=body.site or None,
            thresholds=body.thresholds,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


# --------------------------------------------------------------------------- report (v0.10.36)
class ReportRequest(BaseModel):
    scope: str = Field("org", max_length=10)
    site: str = Field("", max_length=200)
    sites: list[str] = Field(default_factory=list, max_length=500)
    sections: list[str] = Field(default_factory=list, max_length=20)
    skip_empty: bool = True
    mask: bool = False
    audience: str = Field("engineer", max_length=20)


@router.post("/report")
def report_start(body: ReportRequest):
    """Start building the topology report (read-only) in the background; poll GET /report/{id}."""
    from app.services import topology_report

    try:
        return topology_report.start(**body.model_dump())
    except topology_report.TooManyJobs as exc:
        raise HTTPException(status_code=429, detail=str(exc)) from exc


@router.get("/report/{job_id}")
def report_status(job_id: str = Path(..., min_length=8, max_length=32, pattern=r"^[0-9a-f]+$")):
    from app.services import topology_report

    try:
        return topology_report.status(job_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Unknown or expired report") from exc


@router.get("/report/{job_id}/data.zip")
def report_data(job_id: str = Path(..., min_length=8, max_length=32, pattern=r"^[0-9a-f]+$")):
    from fastapi.responses import Response

    from app.services import topology_report

    try:
        data = topology_report.data_zip(job_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Unknown or unfinished report") from exc
    stamp = time.strftime("%Y%m%d-%H%M", time.localtime())
    return Response(
        content=data,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="NodeWatch-Topology-{stamp}.zip"'},
    )


class SiteTypeRequest(BaseModel):
    site: str = Field(..., min_length=1, max_length=200)
    type: str = Field("", max_length=20)


@router.put("/site-type")
def put_site_type(body: SiteTypeRequest):
    """Set (or clear, with an empty type) what kind of site this is: hub, large, branch, small, standalone,
    onramp, empty, staging (v0.10.37). Local file only; overrides the detected type."""
    from app.services.topology_org_insights import set_user_type

    try:
        return {"site_types": set_user_type(body.site, body.type)}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
