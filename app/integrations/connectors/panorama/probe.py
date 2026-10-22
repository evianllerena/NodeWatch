"""Capability probe for the Panorama connector (Settings › Connections › Test, v0.10.18).

Panorama-level commands once, then each firewall-level command against ONE connected firewall
(``target=<serial>``), so the Test costs the same for 3 firewalls or 300. Read-only: every command
goes through the client's read-only guard (``<show>`` operational commands only).

All of these need the same admin-role right — XML API › Operational Requests — so a refusal on one
firewall command but not another usually means the firewall is not reachable from Panorama, not a
missing permission; the probe says which.
"""

from __future__ import annotations

from typing import Any

from app.integrations.connectors.sdk import Probe, ProbeContext, ProbeSkipped
from app.integrations.contracts import (
    ALERTS,
    ARP_TABLE,
    HEALTH,
    INTERFACES,
    INVENTORY,
    NEIGHBORS,
    POLICY_LOOKUP,
    ROUTES,
    SECURITY_EVENTS,
    TUNNELS,
)

OPS = "Admin role › XML API › Operational Requests"
LOGS = "Admin role › XML API › Log"


def plan(c: Any) -> list[Probe]:
    """The probe plan for a :class:`PanoramaConnector` instance ``c``."""
    from app.integrations.connectors.panorama import reader as R
    from app.integrations.connectors.panorama.client import entries

    def fleet(ctx: ProbeContext) -> list[Any]:
        return ctx.once("fleet", lambda: c.call(c._fleet, "list managed firewalls"), "the firewall list")

    def first(ctx: ProbeContext) -> Any:
        connected = [fw for fw in fleet(ctx) if fw.connected]
        if not connected:
            raise ProbeSkipped("no firewall is connected to Panorama right now")
        return connected[0]

    def op(fw: Any, cmd: str, what: str) -> Any:
        return c.call(lambda: c.pan().op(cmd, target=fw.serial, cache=False), f"{what} on {fw.name}")

    def inventory(ctx: ProbeContext) -> tuple[int, str]:
        rows = fleet(ctx)
        connected = sum(1 for fw in rows if fw.connected)
        groups = {fw.device_group for fw in rows if fw.device_group}
        return len(rows), f"{len(rows)} firewalls ({connected} connected) in {len(groups)} device groups"

    def device_groups(ctx: ProbeContext) -> tuple[int, str]:
        result = c.call(lambda: c.pan().op(R.CMD_DEVICE_GROUPS, cache=False), "list device groups")
        count = len(entries(result.find("devicegroups"))) if result is not None else 0
        return count, f"{count} device groups"

    def interfaces(ctx: ProbeContext) -> tuple[int, str]:
        fw = first(ctx)
        count = len(c.list_interfaces(fw.key))
        return count, f"{count} interfaces on {fw.name}"

    def arp(ctx: ProbeContext) -> tuple[int, str]:
        fw = first(ctx)
        count = len(c.list_arp(fw.key))
        return count, f"{count} ARP entries on {fw.name}"

    def routes(ctx: ProbeContext) -> tuple[int, str]:
        fw = first(ctx)
        count = len(c.list_routes(fw.key))
        return count, f"{count} routes on {fw.name}"

    def lldp(ctx: ProbeContext) -> str:
        fw = first(ctx)
        op(fw, R.CMD_LLDP, "read LLDP neighbors")
        return f"LLDP readable on {fw.name} (empty unless LLDP is enabled on its interfaces)"

    def vpn(ctx: ProbeContext) -> tuple[int, str]:
        fw = first(ctx)
        count = len(c.call(lambda: c._tunnels_of(fw), f"read IPsec flows on {fw.name}"))
        return count, f"{count} IPsec tunnels on {fw.name}"

    def resources(ctx: ProbeContext) -> str:
        fw = first(ctx)
        op(fw, R.CMD_RESOURCES, "read system resources")
        return f"CPU and memory readable on {fw.name}"

    def ha(ctx: ProbeContext) -> str:
        rows = fleet(ctx)
        pair = next((fw for fw in rows if fw.connected and fw.ha_state), None)
        if pair is None:
            return "Derived from the firewall list (no connected HA pair to check)"
        op(pair, R.CMD_HA_STATE, "read HA state")
        return f"HA state readable on {pair.name}"

    def threats(ctx: ProbeContext) -> tuple[int, str]:
        import time as _time

        count = len(c.list_security_events(since=_time.time() - 3600, limit=20))
        return count, f"{count} threat detections in the last hour (up to 20 read)"

    return [
        Probe(INVENTORY, "Managed firewalls (show devices all)", inventory, "firewalls", OPS),
        Probe(INVENTORY, "Device groups (show devicegroups)", device_groups, "device groups", OPS, optional=True),
        Probe(
            INTERFACES, "Interfaces of one firewall (show interface all)", interfaces, "interfaces", OPS, sample=False
        ),
        Probe(ARP_TABLE, "ARP of one firewall (show arp)", arp, "ARP entries", OPS, sample=False),
        Probe(ROUTES, "Routes of one firewall (show routing route)", routes, "routes", OPS, sample=False),
        Probe(NEIGHBORS, "LLDP of one firewall (show lldp neighbors)", lldp, "", OPS),
        Probe(TUNNELS, "IPsec of one firewall (show vpn flow)", vpn, "IPsec tunnels", OPS, sample=False),
        Probe(HEALTH, "Resources of one firewall (show system resources)", resources, "", OPS),
        Probe(ALERTS, "HA state (show high-availability state)", ha, "", OPS),
        Probe(SECURITY_EVENTS, "Threat log of the last hour (log query)", threats, "detections", LOGS),
        Probe(
            POLICY_LOOKUP,
            "Security policy match",
            _policy_not_run,
        ),
    ]


def _policy_not_run(_ctx: ProbeContext) -> Any:
    raise ProbeSkipped("Not run by the test (an on-demand query); it needs the same Operational Requests right")
