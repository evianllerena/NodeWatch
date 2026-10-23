"""Juniper Mist connector: wraps NodeWatch's proven Mist client in the vendor-neutral contracts.

Each capability lives in its own module (alerts.py, inventory.py, topology.py) as a mixin that
declares the capability names it implements; the manifest is the union of them.
"""

from __future__ import annotations

from app.integrations.connectors.mist.alerts import MistAlerts
from app.integrations.connectors.mist.audit import MistAudit
from app.integrations.connectors.mist.inventory import MistInventory
from app.integrations.connectors.mist.security import MistSecurity
from app.integrations.connectors.mist.topology import MistTopology
from app.integrations.connectors.sdk import Connector, ConnectorManifest, ConnectorSetup, SetupIssue, SetupStep
from app.services.mist_client import get_mist_client

_MIXINS = (MistAlerts, MistInventory, MistTopology, MistAudit, MistSecurity)

SETUP = ConnectorSetup(
    summary="Juniper Mist switches, access points and WAN edges: inventory, ports, alerts, events and LLDP.",
    prerequisites=(
        "A Mist organization and an account that may create organization API tokens",
        "Your Organization ID (Organization › Settings)",
        "The API host of your Mist cloud (api.mist.com, api.eu.mist.com, api.gc1.mist.com …)",
    ),
    steps=(
        SetupStep(
            "Create an organization API token",
            "Mist portal › Organization › Settings › API Token › Create Token. Name: nodewatch. Access level: "
            "Observer is enough for monitoring; only NodeWatch's change tools (Port Toolkit, Chassis Manager) "
            "need a level that may write — every change is confirmed and audited.",
            link="https://www.juniper.net/documentation/us/en/software/mist/api/http/getting-started/how-to-get-started",
            copy="nodewatch",
        ),
        SetupStep("Copy the token and the Organization ID", "The token is shown once. Keep both for the next step."),
        SetupStep(
            "Enter them in Mist Connection",
            "Settings & Support › Mist Connection: API host, Organization ID and token, then Test Connection "
            "and Save & Connect.",
            copy="Settings & Support › Mist Connection",
        ),
    ),
    permissions="An organization API token. Observer (read-only) is enough for monitoring; NodeWatch's change "
    "tools need a token that may write, and every change is explicitly confirmed and audited.",
    verify="Lists the organization's sites (one call).",
    troubleshooting=(
        SetupIssue("HTTP 401", "The token was revoked or mistyped. Create a new token."),
        SetupIssue("HTTP 403 or 404", "The token belongs to another organization, or the Organization ID is wrong."),
        SetupIssue("Cannot reach the host", "Use the API host of your Mist cloud region, not the portal address."),
        SetupIssue("HTTP 429", "Mist allows 5,000 API calls per hour per token; wait, or use a dedicated token."),
    ),
    data_you_get=(
        "Sites, switches, access points and WAN edges with state and firmware",
        "Switch ports and their state",
        "Alarms and recent device events (Command Center)",
        "LLDP neighbors (links in Topology)",
        "Wireless-security conditions (rogue APs, honeypot SSIDs) in Security Operations",
    ),
    estimated_minutes=5,
    uncertain=("Token access-level names can differ slightly between Mist portal releases.",),
)

MANIFEST = ConnectorManifest(
    connector_id="mist",
    vendor="Juniper",
    product="Mist Cloud",
    category="network_management",
    capabilities=tuple(dict.fromkeys(c for m in _MIXINS for c in m.CAPABILITIES)),
    description="Switches, access points and WAN edges managed by Juniper Mist.",
    docs_url="https://www.juniper.net/documentation/us/en/software/mist/api/http/getting-started/how-to-get-started",
    managed_elsewhere=True,  # API token and org are set on Settings › Mist Connection
    settings_location="Settings & Support › Mist Connection",
    setup=SETUP,
)


class MistConnector(MistAlerts, MistInventory, MistTopology, MistAudit, MistSecurity, Connector):
    manifest = MANIFEST

    @property
    def client(self):
        return get_mist_client()

    @property
    def configured(self) -> bool:
        return bool(self.client.configured)

    @property
    def enabled(self) -> bool:
        return self.configured

    def warm_up(self) -> None:
        """Start-up prefetch (runs in its own thread; does nothing when Mist is not configured)."""
        from app.services.mist_client import warm_up

        warm_up()

    def test_connection(self) -> dict:
        if not self.configured:
            return {"ok": False, "provider": "mist", "configured": False}
        sites = self.call(self.client.list_sites, "list sites")
        return {"ok": True, "provider": "mist", "configured": True, "detail": f"{len(sites)} sites"}


CONNECTOR = MistConnector
