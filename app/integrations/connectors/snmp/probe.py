"""Capability probe for the SNMPv3 connector (Settings › Connections › Test, v0.10.18).

Against the FIRST target only: the system group (GET), then the first few rows (GETBULK, at most 5)
of the one table each capability needs, falling back to the older table where the connector does.
GET/GETBULK only — the transport has no SET.

SNMP never says "permission denied": an object outside the user's view simply is not there. So an
empty table is reported as "empty" — either the device does not keep that table or the SNMPv3 view
excludes it — with the MIB to add to the view.
"""

from __future__ import annotations

from typing import Any

from app.integrations.connectors.sdk import Probe, ProbeContext, ProbeEmpty
from app.integrations.contracts import ARP_TABLE, HEALTH, INTERFACES, INVENTORY, MAC_TABLE, NEIGHBORS, ROUTES

ROWS = 5
VIEW = "the SNMPv3 user's read view must include {mib} (simplest: OID 1, the whole tree)"


def plan(c: Any) -> list[Probe]:
    """The probe plan for an :class:`SnmpConnector` instance ``c``."""
    from app.integrations.connectors.snmp import mibs
    from app.integrations.connectors.snmp.targets import resolve

    def target(ctx: ProbeContext) -> tuple[Any, str, str]:
        def build() -> tuple[Any, str, str]:
            hosts = c._targets()
            return c.snmp(), hosts[0], resolve(hosts[0])

        return ctx.once("target", lambda: c.call(build, "prepare SNMP"), "the first target")

    def system(ctx: ProbeContext) -> tuple[int, str]:
        transport, host, address = target(ctx)
        data = c.call(lambda: transport.fetch(address, get=mibs.SYSTEM_GETS), f"read the system group of {host}")
        facts = mibs.parse_system(data)
        if not facts["name"] and not facts["description"]:
            raise ProbeEmpty(f"{host} answered without the system group — " + VIEW.format(mib="SNMPv2-MIB system"))
        more = len(c._targets()) - 1
        text = (facts["name"] or host) + (f" (+{more} more targets not probed)" if more > 0 else "")
        return 1, text

    def table(stages: tuple[tuple[str, ...], ...], noun: str, mib: str) -> Any:
        def run(ctx: ProbeContext) -> tuple[int, str]:
            transport, host, address = target(ctx)
            for walks in stages:
                root = walks[0]
                data = c.call(
                    lambda r=root: transport.fetch(address, walk=(r,), max_rows=ROWS), f"read {noun} on {host}"
                )
                rows = [oid for oid in data if oid.startswith(root + ".")]
                if rows:
                    shown = f"{len(rows)}+" if len(rows) >= ROWS else str(len(rows))
                    return len(rows), f"{shown} {noun} on {host}"
            raise ProbeEmpty(f"No {noun} on {host}: the device does not keep this table, or " + VIEW.format(mib=mib))

        return run

    return [
        Probe(INVENTORY, "System group (sysName, sysDescr …)", system, "device", VIEW.format(mib="SNMPv2-MIB system")),
        Probe(
            INTERFACES,
            "Interface table (IF-MIB ifDescr)",
            table(((mibs.IF_DESCR,),), "interfaces", "IF-MIB"),
            "interfaces",
            VIEW.format(mib="IF-MIB"),
            sample=False,
        ),
        Probe(
            NEIGHBORS,
            "LLDP neighbors (LLDP-MIB lldpRemTable, CDP fallback)",
            table(((mibs.LLDP_REM_SYS_NAME,), (mibs.CDP_DEVICE_ID,)), "LLDP/CDP neighbors", "LLDP-MIB"),
            "LLDP/CDP neighbors",
            VIEW.format(mib="LLDP-MIB (1.0.8802)"),
            sample=False,
        ),
        Probe(
            ARP_TABLE,
            "ARP (IP-MIB ipNetToPhysical / ipNetToMedia)",
            table(mibs.ARP_WALKS, "ARP entries", "IP-MIB"),
            "ARP entries",
            VIEW.format(mib="IP-MIB"),
            sample=False,
        ),
        Probe(
            MAC_TABLE,
            "MAC table (Q-BRIDGE-MIB / BRIDGE-MIB)",
            table(mibs.FDB_WALKS, "MAC entries", "BRIDGE-MIB and Q-BRIDGE-MIB"),
            "MAC entries",
            VIEW.format(mib="BRIDGE-MIB and Q-BRIDGE-MIB"),
            sample=False,
        ),
        Probe(
            ROUTES,
            "Routes (IP-FORWARD-MIB, RFC 1213 fallback)",
            table(mibs.ROUTE_WALKS, "routes", "IP-FORWARD-MIB"),
            "routes",
            VIEW.format(mib="IP-FORWARD-MIB"),
            sample=False,
        ),
        Probe(
            HEALTH,
            "CPU load (HOST-RESOURCES-MIB hrProcessorLoad)",
            table(((mibs.HR_PROCESSOR_LOAD,),), "CPU readings", "HOST-RESOURCES-MIB"),
            "",
            VIEW.format(mib="HOST-RESOURCES-MIB"),
        ),
    ]
