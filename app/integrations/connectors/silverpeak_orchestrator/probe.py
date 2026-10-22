"""Capability probe for the Orchestrator connector (Settings › Connections › Test, v0.10.18).

One cheap read per capability, run in parallel by :func:`app.integrations.connectors.sdk.run_probes`
within the Test's 20 s budget. Reads only: GETs and the documented read-query POSTs the connector is
already allowed to send (:data:`READ_QUERY_POSTS`). Per-appliance reads use ONE appliance (a normal
one when there is one), so the probe costs the same for 5 appliances or 500.

The point is to tell the person with the API key exactly what it can and cannot read: with a
Read-Only (``net_read``) key every check below should pass. The alarm and statistics checks are
POST requests; whether Orchestrator allows those for a Read-Only key is not yet confirmed on a live
system, so a refusal there is explained as "only a Read-Write key unlocks it" rather than guessed.
"""

from __future__ import annotations

import time
from typing import Any

from app.integrations.connectors.sdk import Probe, ProbeContext, ProbeSkipped
from app.integrations.contracts import ALERTS, HEALTH, INTERFACES, INVENTORY, ROUTES, TUNNELS, WAN_CIRCUITS

READ = (
    "A Read-Only (net_read) key is enough for this plain read; if it is refused, Orchestrator limits what "
    "this key may see (role or appliance access) — a higher permission is not the fix"
)
QUERY = (
    "Read-Only (net_read) should allow it — it is a documented read query sent as POST. If your "
    "Orchestrator refuses it for Read-Only keys, only a Read-Write key unlocks it (NodeWatch still only reads)"
)


def plan(c: Any) -> list[Probe]:
    """The probe plan for a :class:`SilverPeakOrchestratorConnector` instance ``c``."""
    from app.integrations.connectors import silverpeak_orchestrator as sp

    def appliances(ctx: ProbeContext) -> list[dict]:
        return ctx.once("appliances", c._appliances, "the appliance list")

    def first(ctx: ProbeContext) -> dict:
        rows = appliances(ctx)
        if not rows:
            raise ProbeSkipped("Orchestrator lists no appliances for this key")
        return next((r for r in rows if sp._int(r.get("state")) == 1), rows[0])

    def name(row: dict) -> str:
        return sp._text(row.get("hostName")) or c._ne_pk(row)

    def get(path: str, what: str, **params: Any) -> Any:
        return c.call(lambda: c.http().get(path, **params), what)

    # ---- INVENTORY ----------------------------------------------------------------------------
    def inventory(ctx: ProbeContext) -> tuple[int, str]:
        rows = appliances(ctx)
        sites = {c._site_of(r) for r in rows if c._site_of(r)}
        down = sum(1 for r in rows if sp._int(r.get("state")) == 2)
        text = f"{len(rows)} appliances in {len(sites)} sites" + (f" ({down} unreachable)" if down else "")
        return len(rows), text

    def ha_pairs(ctx: ProbeContext) -> tuple[int, str]:
        data = get("/appliance/haPeerMeta", "read HA pairs")
        count = len(data) if isinstance(data, (dict, list)) else 0
        return count, f"{count} appliances in HA pairs"

    def regions(ctx: ProbeContext) -> tuple[int, str]:
        data = get("/regions/appliances", "read regions")
        rows = data if isinstance(data, list) else ([data] if isinstance(data, dict) and "nePk" in data else [])
        if isinstance(data, dict) and "nePk" not in data:
            rows = [v for v in data.values() if isinstance(v, dict)]
        names = {sp._text(r.get("regionName")) for r in rows if isinstance(r, dict) and sp._text(r.get("regionName"))}
        return len(names), f"{len(names)} regions"

    # ---- one appliance ------------------------------------------------------------------------
    def interfaces(ctx: ProbeContext) -> tuple[int, str]:
        row = first(ctx)
        data = get("/interfaceState", "read interface state", nePk=c._ne_pk(row), cached="true")
        info = data.get("ifInfo") if isinstance(data, dict) else None
        count = len(info) if isinstance(info, list) else 0
        return count, f"{count} interfaces on {name(row)}"

    def deployment(ctx: ProbeContext) -> tuple[int, str]:
        row = first(ctx)
        data = get("/deployment", "read WAN deployment", nePk=c._ne_pk(row))
        count = len(c._deployment_ips(data))
        return count, f"{count} WAN addresses with bandwidth on {name(row)}"

    def labels(ctx: ProbeContext) -> tuple[int, str]:
        data = get("/gms/interfaceLabels", "read interface labels", type="wan")
        if isinstance(data, dict) and isinstance(data.get("wan"), dict):
            data = data["wan"]
        count = len(data) if isinstance(data, dict) else 0
        return count, f"{count} WAN labels"

    def routes(ctx: ProbeContext) -> tuple[int, str]:
        row = first(ctx)
        data = get("/subnets/all", "read routes", nePk=c._ne_pk(row), cached="true")
        segments = data.get("subnets") if isinstance(data, dict) else None
        if isinstance(segments, dict) and "entries" in segments:
            segments = {"0": {"subnets": segments}}
        count = 0
        for seg in (segments or {}).values() if isinstance(segments, dict) else ():
            table = seg.get("subnets") if isinstance(seg, dict) else None
            entries = table.get("entries") if isinstance(table, dict) else None
            count += len(entries) if isinstance(entries, list) else 0
        return count, f"{count} routes on {name(row)}"

    # ---- fleet-wide lists ---------------------------------------------------------------------
    def tunnels(kind: str, label: str) -> Any:
        def run(ctx: ProbeContext) -> tuple[int, str]:
            appliances(ctx)  # same prerequisite as the real read
            rows = c._all_tunnels(c.http(), kind)  # same read (and large-fabric fallback) as the real one
            up = sum(1 for t in rows if sp.tunnel_state(t.get("operStatus"), t.get("adminStatus")) == "up")
            return len(rows), f"{len(rows)} {label} tunnels ({up} up)"

        return run

    def alarms(ctx: ProbeContext) -> tuple[int, str]:
        appliances(ctx)
        count = len(c.list_alerts())
        return count, f"{count} active alarms"

    # ---- statistics (one appliance, last 5 minutes) -------------------------------------------
    def memory(ctx: ProbeContext) -> str:
        row = first(ctx)
        end = int(time.time())
        answer = c.call(
            lambda: c._query(
                c.http(),
                "/stats/timeseries/memory",
                params={"startTime": end - 300, "endTime": end},
                body={"nePks": [c._ne_pk(row)]},
            ),
            "query memory statistics",
        )
        pct = c._memory([answer]).get(c._ne_pk(row))
        return (
            f"Memory statistics readable ({name(row)}: {pct}% used)"
            if pct is not None
            else "Memory statistics readable"
        )

    def flows(ctx: ProbeContext) -> str:
        row = first(ctx)
        answer = c.call(
            lambda: c._query(c.http(), "/stats/aggregate/flow/active", params={}, body={"nePks": [c._ne_pk(row)]}),
            "query active flows",
        )
        count = c._flows([answer]).get(c._ne_pk(row))
        return (
            f"Flow statistics readable ({name(row)}: {count} active flows)"
            if count is not None
            else "Flow statistics readable"
        )

    return [
        Probe(INVENTORY, "List appliances (GET /appliance)", inventory, "appliances", READ),
        Probe(
            INVENTORY, "HA pairs (GET /appliance/haPeerMeta)", ha_pairs, "appliances in HA pairs", READ, optional=True
        ),
        Probe(INVENTORY, "Regions (GET /regions/appliances)", regions, "regions", READ, optional=True),
        Probe(
            INTERFACES,
            "Interfaces of one appliance (GET /interfaceState)",
            interfaces,
            "interfaces",
            READ,
            sample=False,
        ),
        Probe(INTERFACES, "WAN/LAN label names (GET /gms/interfaceLabels)", labels, "WAN labels", READ, optional=True),
        Probe(ROUTES, "Routes of one appliance (GET /subnets/all)", routes, "routes", READ, sample=False),
        Probe(
            TUNNELS,
            "Underlay tunnels (GET /tunnels2/physical)",
            tunnels("physical", "underlay"),
            "underlay tunnels",
            READ,
        ),
        Probe(
            TUNNELS,
            "Overlay tunnels (GET /tunnels2/bonded?children=false)",
            tunnels("bonded", "overlay"),
            "overlay tunnels",
            READ,
        ),
        Probe(
            WAN_CIRCUITS,
            "WAN bandwidth and next hops of one appliance (GET /deployment)",
            deployment,
            "WAN addresses",
            READ,
            sample=False,
            optional=True,
        ),
        Probe(ALERTS, "Active alarms (POST /alarm/appliance query)", alarms, "active alarms", QUERY),
        Probe(HEALTH, "Memory statistics (POST /stats/timeseries/memory query)", memory, "", QUERY),
        Probe(HEALTH, "Flow statistics (POST /stats/aggregate/flow/active query)", flows, "", QUERY),
    ]
