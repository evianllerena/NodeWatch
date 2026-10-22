"""Capability contracts every NodeWatch connector can implement (v0.10.16).

A connector (one vendor product: Juniper Mist, Palo Alto Strata, Silver Peak Orchestrator,
FortiGate, Cisco Catalyst Center …) implements only the capabilities its API offers. Features ask
the registry for *capabilities*, never for vendors:

    for source in sources(ALERTS):          # Mist, FortiGate, Silver Peak … whatever is connected
        alerts += source.list_alerts(site_key=None)

So a company running Cisco + Fortinet gets Command Center, Topology, etc. as soon as those
connectors exist — no feature code changes. See docs/CONNECTORS.md for how to add one.

Methods return the vendor-neutral records from :mod:`app.integrations.domain`. They must:
* raise :class:`app.integrations.base.IntegrationError` (not vendor exceptions) on failure,
* never return secrets, and never return raw payloads,
* be read-only unless the capability name ends in ``.write`` (writes also need the confirmed/audited
  path of the feature that calls them).
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

from app.integrations.domain import (
    Alert,
    Device,
    Event,
    Interface,
    L2Entry,
    L3Entry,
    Neighbor,
    Route,
    Site,
    Tunnel,
    Circuit,
    Actor,
    AuditEntry,
    EndpointLocation,
    PolicyMatch,
    SecurityEvent,
    Exposure,
    SecurityIncident,
)

# Capability names (stable strings; also used in connector manifests and the settings UI).
INVENTORY = "inventory"  # sites + devices
INTERFACES = "interfaces"  # interface/port state
ALERTS = "alerts"  # open conditions
ALERTS_ACK = "alerts.ack.write"  # acknowledge in the vendor system
EVENTS = "events"  # recent device events
NEIGHBORS = "topology.neighbors"  # LLDP/CDP or vendor peer tables
MAC_TABLE = "topology.mac_table"
ARP_TABLE = "topology.arp"
ROUTES = "topology.routes"
TUNNELS = "topology.tunnels"  # IPsec / SD-WAN overlays
ENDPOINT_LOCATE = "topology.endpoint_locate"  # find where an IP/MAC is attached (v0.10.17)
POLICY_LOOKUP = "security.policy_lookup"  # firewall "would this flow be allowed" (v0.10.17)
HEALTH = "health.metrics"  # live device/interface/tunnel health: CPU, memory, errors, utilization (v0.10.17)
TRAFFIC_LOGS = "traffic.logs"  # firewall session/traffic logs (existing Traffic & Sessions)
AUDIT_LOG = "audit.log"  # who changed what, when (v0.10.24)
DIRECTORY_ADMINS = "directory.admins"  # the people and API tokens that can make changes (v0.10.24)
WAN_CIRCUITS = "wan.circuits"  # internet / MPLS / LTE circuits on WAN ports, with live quality (v0.10.24)
# v0.10.30 security operations (docs/architecture/SECURITY_DATA_PLANE.md)
SECURITY_EVENTS = "security.events"  # threat / malware / URL / DNS / IPS / wireless-intrusion detections
SECURITY_EXPOSURES = "security.exposures"  # known weaknesses (CVEs, end of support) on assets
SECURITY_INCIDENTS = "security.incidents"  # incidents a security platform already correlated

ALL_CAPABILITIES = (
    ENDPOINT_LOCATE,
    POLICY_LOOKUP,
    HEALTH,
    INVENTORY,
    INTERFACES,
    ALERTS,
    ALERTS_ACK,
    EVENTS,
    NEIGHBORS,
    MAC_TABLE,
    ARP_TABLE,
    ROUTES,
    TUNNELS,
    TRAFFIC_LOGS,
    WAN_CIRCUITS,
    AUDIT_LOG,
    DIRECTORY_ADMINS,
    SECURITY_EVENTS,
    SECURITY_EXPOSURES,
    SECURITY_INCIDENTS,
)

CAPABILITY_LABELS = {
    ENDPOINT_LOCATE: "Find endpoints",
    POLICY_LOOKUP: "Security policy lookup",
    HEALTH: "Live health",
    INVENTORY: "Sites & devices",
    INTERFACES: "Interfaces & ports",
    ALERTS: "Alerts",
    ALERTS_ACK: "Acknowledge alerts",
    EVENTS: "Device events",
    NEIGHBORS: "LLDP/CDP neighbors",
    MAC_TABLE: "MAC tables",
    ARP_TABLE: "ARP tables",
    ROUTES: "Routing tables",
    TUNNELS: "VPN / SD-WAN tunnels",
    TRAFFIC_LOGS: "Traffic logs",
    WAN_CIRCUITS: "WAN circuits",
    AUDIT_LOG: "Change history",
    DIRECTORY_ADMINS: "Administrators",
    SECURITY_EVENTS: "Security detections",
    SECURITY_EXPOSURES: "Vulnerabilities & exposures",
    SECURITY_INCIDENTS: "Security incidents",
}


@runtime_checkable
class InventorySource(Protocol):
    def list_sites(self) -> list[Site]: ...

    def list_devices(self, site_key: str | None = None) -> list[Device]: ...


@runtime_checkable
class InterfaceSource(Protocol):
    def list_interfaces(self, device_key: str) -> list[Interface]: ...


@runtime_checkable
class AlertSource(Protocol):
    def list_alerts(self, site_key: str | None = None) -> list[Alert]: ...


@runtime_checkable
class AlertAcknowledger(Protocol):
    def acknowledge_alert(self, alert: Alert, note: str = "") -> dict[str, Any]: ...


@runtime_checkable
class EventSource(Protocol):
    def list_events(self, site_key: str | None = None, *, hours: int = 24) -> list[Event]: ...


@runtime_checkable
class NeighborSource(Protocol):
    def list_neighbors(self, site_key: str | None = None) -> list[Neighbor]: ...


@runtime_checkable
class MacTableSource(Protocol):
    def list_mac_table(self, device_key: str) -> list[L2Entry]: ...


@runtime_checkable
class ArpSource(Protocol):
    def list_arp(self, device_key: str | None = None) -> list[L3Entry]: ...


@runtime_checkable
class RouteSource(Protocol):
    def list_routes(self, device_key: str) -> list[Route]: ...


@runtime_checkable
class TunnelSource(Protocol):
    def list_tunnels(self, site_key: str | None = None) -> list[Tunnel]: ...


@runtime_checkable
class TrafficLogSource(Protocol):
    """Firewall traffic/session logs for one IP (returns the Traffic & Sessions payload, schema 1.0)."""

    def search_traffic(self, ip: str, *, window: str = "1h", limit: int = 300) -> dict[str, Any]: ...


@runtime_checkable
class CircuitSource(Protocol):
    """WAN circuits of the devices at one site (None = all), as :class:`Circuit` records."""

    def list_circuits(self, site_key: str | None = None) -> list[Circuit]: ...


@runtime_checkable
class AuditLogSource(Protocol):
    """Changes recorded by the management system in the last ``hours`` (newest first)."""

    def list_audit(self, site_key: str | None = None, *, hours: int = 168) -> list[AuditEntry]: ...


@runtime_checkable
class AdminDirectory(Protocol):
    """People and API tokens that can change the network (never token secrets)."""

    def list_actors(self) -> list[Actor]: ...


@runtime_checkable
class SecurityEventSource(Protocol):
    """Security detections between ``since`` and ``until`` (epoch seconds, None = now), newest first, at most
    ``limit``. Read-only and bounded: a source pages internally and stops at ``limit``. Records are
    :class:`SecurityEvent` (never raw log rows)."""

    def list_security_events(
        self, *, since: float, until: float | None = None, limit: int = 2000
    ) -> list[SecurityEvent]: ...


@runtime_checkable
class ExposureSource(Protocol):
    """Known weaknesses on assets (site_key None = all), as :class:`Exposure` records."""

    def list_exposures(self, site_key: str | None = None) -> list[Exposure]: ...


@runtime_checkable
class SecurityIncidentSource(Protocol):
    """Incidents the platform correlated in the last ``hours`` (newest first)."""

    def list_security_incidents(self, *, hours: int = 168) -> list[SecurityIncident]: ...


# Which protocol a connector must satisfy to claim each capability (checked by the conformance tests).
@runtime_checkable
class EndpointLocator(Protocol):
    def locate_endpoint(self, *, ip: str = "", mac: str = "") -> list[EndpointLocation]: ...


@runtime_checkable
class PolicyLookup(Protocol):
    def policy_lookup(
        self,
        device_key: str,
        *,
        src_ip: str,
        dst_ip: str,
        dst_port: int | None = None,
        protocol: str = "tcp",
        application: str = "",
    ) -> list[PolicyMatch]: ...


@runtime_checkable
class HealthSource(Protocol):
    """Device records with cpu/memory/sessions/ha filled, interfaces with rates/errors, tunnels with latency/loss."""

    def list_health(self, site_key: str | None = None) -> dict[str, list[Any]]:
        """Return {"devices": [Device], "interfaces": [Interface], "tunnels": [Tunnel]} (any may be empty)."""
        ...


CAPABILITY_PROTOCOLS: dict[str, type] = {
    ENDPOINT_LOCATE: EndpointLocator,
    POLICY_LOOKUP: PolicyLookup,
    HEALTH: HealthSource,
    INVENTORY: InventorySource,
    INTERFACES: InterfaceSource,
    ALERTS: AlertSource,
    ALERTS_ACK: AlertAcknowledger,
    EVENTS: EventSource,
    NEIGHBORS: NeighborSource,
    MAC_TABLE: MacTableSource,
    ARP_TABLE: ArpSource,
    ROUTES: RouteSource,
    TUNNELS: TunnelSource,
    TRAFFIC_LOGS: TrafficLogSource,
    WAN_CIRCUITS: CircuitSource,
    AUDIT_LOG: AuditLogSource,
    DIRECTORY_ADMINS: AdminDirectory,
    SECURITY_EVENTS: SecurityEventSource,
    SECURITY_EXPOSURES: ExposureSource,
    SECURITY_INCIDENTS: SecurityIncidentSource,
}
