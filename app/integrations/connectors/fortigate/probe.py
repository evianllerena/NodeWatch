"""Capability probe for the FortiGate connector (Settings › Connections › Test, v0.10.18).

One GET per capability (the same endpoints the connector reads), in parallel, read-only. The
admin-profile group each FortiOS monitor endpoint checks differs between releases, so the
``needs`` hints name the profile areas as documented in the GUI and are labelled as likely.
"""

from __future__ import annotations

from typing import Any

from app.integrations.connectors.sdk import Probe, ProbeContext
from app.integrations.contracts import ARP_TABLE, INTERFACES, INVENTORY, NEIGHBORS, ROUTES, TUNNELS

SYSTEM = "Admin profile: Read on System"
NETWORK = "Admin profile: Read on Network (likely; some releases check System)"
ROUTER = "Admin profile: Read on Network › Router (likely)"
VPN = "Admin profile: Read on VPN (likely)"


def plan(c: Any) -> list[Probe]:
    """The probe plan for a :class:`FortiGateConnector` instance ``c``."""

    def system(ctx: ProbeContext) -> dict:
        return ctx.once("system", c._system, "the system status")

    def status(ctx: ProbeContext) -> tuple[int, str]:
        s = system(ctx)
        name = s.get("hostname") or "FortiGate"
        version = f" · FortiOS {s['version']}" if s.get("version") else ""
        return 1, f"{name}{version}"

    def ha(ctx: ProbeContext) -> tuple[int, str]:
        system(ctx)
        peers = c._get("/api/v2/monitor/system/ha-peer", "read HA peers") or []
        count = len(peers) if isinstance(peers, list) else 0
        return count, f"{count} HA members" if count > 1 else "Standalone (no HA peer)"

    def interfaces(ctx: ProbeContext) -> tuple[int, str]:
        system(ctx)
        live = c._get("/api/v2/monitor/system/interface", "read interfaces") or {}
        return len(live), f"{len(live)} interfaces"

    def interface_config(ctx: ProbeContext) -> tuple[int, str]:
        rows = c._get("/api/v2/cmdb/system/interface", "read interface configuration") or []
        return len(rows), f"{len(rows)} configured interfaces"

    def table(path: str, what: str, noun: str) -> Any:
        def run(ctx: ProbeContext) -> tuple[int, str]:
            system(ctx)
            rows = c._get(path, what) or []
            count = len(rows) if isinstance(rows, (list, dict)) else 0
            return count, f"{count} {noun}"

        return run

    return [
        Probe(INVENTORY, "System status (GET monitor/system/status)", status, "FortiGate", SYSTEM),
        Probe(INVENTORY, "HA peers (GET monitor/system/ha-peer)", ha, "HA members", SYSTEM, optional=True),
        Probe(INTERFACES, "Interfaces (GET monitor/system/interface)", interfaces, "interfaces", NETWORK),
        Probe(
            INTERFACES,
            "Interface settings (GET cmdb/system/interface)",
            interface_config,
            "configured interfaces",
            NETWORK,
            optional=True,
            sample=False,
        ),
        Probe(
            NEIGHBORS,
            "LLDP neighbors (GET monitor/network/lldp/neighbors)",
            table("/api/v2/monitor/network/lldp/neighbors", "read LLDP neighbors", "LLDP neighbors"),
            "LLDP neighbors",
            NETWORK,
        ),
        Probe(
            ARP_TABLE,
            "ARP table (GET monitor/network/arp)",
            table("/api/v2/monitor/network/arp", "read ARP table", "ARP entries"),
            "ARP entries",
            NETWORK,
            sample=False,
        ),
        Probe(
            ROUTES,
            "Routing table (GET monitor/router/ipv4)",
            table("/api/v2/monitor/router/ipv4", "read routing table", "routes"),
            "routes",
            ROUTER,
            sample=False,
        ),
        Probe(
            TUNNELS,
            "IPsec tunnels (GET monitor/vpn/ipsec)",
            table("/api/v2/monitor/vpn/ipsec", "read IPsec tunnels", "IPsec tunnels"),
            "IPsec tunnels",
            VPN,
        ),
    ]
