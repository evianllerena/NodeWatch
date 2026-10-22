"""Palo Alto Networks Strata Cloud Manager connector (wraps NodeWatch's existing, proven providers).

What it declares — only what the existing code really does today:

* ``security.events`` (v0.10.30) — threat-log detections and blocked web requests from the same Log
  Viewer API, translated to vendor-neutral :class:`SecurityEvent` records (``threats.py``).

* ``traffic.logs`` — firewall traffic/session logs per IP, via the Traffic & Sessions framework
  (``providers/traffic.py``) on top of Strata Logging Service / SCM Log Viewer
  (``POST {query_host}/api/sase/v3.0/resource/query/logviewer``, ``providers/strata_logging.py``).

* ``inventory`` (v0.10.17, preview) — firewalls onboarded to Strata Cloud Manager
  (``GET /config/setup/v1/devices``) grouped by folder, plus Prisma Access remote networks as sites
  (``GET /config/deployment/v1/remote-networks``), with the same Common Services OAuth service
  account — see ``inventory.py`` for citations and what is assumed.

What it deliberately does NOT declare:

* interfaces/routes/alerts — SCM offers them only as asynchronous POST job/search APIs
  (``/operations/v1/jobs/…``, ``/incidents/v1/search``), not added yet. Panorama-managed firewalls'
  live data comes from the ``panorama`` connector.
* any write — ``writer.py`` documents the future candidate edit → ``config-versions/candidate:push``
  flow; nothing is implemented.
* Device Security (``providers/palo_alto_device_security.py``) is IoT endpoint intelligence, not a
  firewall list, and stays a separate integration.

Credentials (Common Services OAuth client) and the log query host stay on
Settings › Security & Logging Integrations (``managed_elsewhere``).
"""

from __future__ import annotations

from typing import Any

from app.integrations.connectors.paloalto_scm.inventory import ScmInventory
from app.integrations.connectors.paloalto_scm.threats import ScmThreats
from app.integrations.connectors.sdk import Connector, ConnectorManifest, ConnectorSetup, SetupIssue, SetupStep
from app.integrations.contracts import INTERFACES, INVENTORY, SECURITY_EVENTS, TRAFFIC_LOGS

SETUP = ConnectorSetup(
    summary="Firewall traffic and session logs, plus SCM-onboarded firewalls and Prisma Access remote networks.",
    prerequisites=(
        "A Strata Cloud Manager tenant (with Strata Logging Service for traffic logs)",
        "Access to Common Services › Identity & Access to create a service account",
        "The tenant's TSG ID (Tenant Service Group)",
    ),
    steps=(
        SetupStep(
            "Create a service account",
            "Common Services › Identity & Access › Add Identity › Service Account. Name: nodewatch-readonly. "
            "Copy the Client ID and Client Secret — the secret is shown once.",
            link="https://pan.dev/scm/docs/service-accounts/",
            copy="nodewatch-readonly",
        ),
        SetupStep(
            "Give it a read-only role",
            "Assign a read-only role on the tenant, for example View Only Administrator, so it can read "
            "configuration and logs but change nothing.",
        ),
        SetupStep(
            "Enter it in Security & Logging Integrations",
            "Settings & Support › Security & Logging Integrations: Client ID, TSG ID and Client Secret, then Verify.",
            copy="Settings & Support › Security & Logging Integrations",
        ),
    ),
    permissions="A Common Services service account with a read-only role on the tenant (for example View Only "
    "Administrator). NodeWatch only queries logs and lists devices.",
    verify="Runs one small traffic-log query (sample rows) through the Log Viewer API.",
    troubleshooting=(
        SetupIssue("Token request fails", "Client ID, secret or TSG ID is wrong, or the service account was deleted."),
        SetupIssue(
            "Logs work but inventory reports a permission error",
            "The role cannot read configuration. Use a role such as View Only Administrator.",
        ),
        SetupIssue("No traffic rows", "The firewalls do not forward traffic logs to Strata Logging Service."),
    ),
    data_you_get=(
        "Traffic and session logs per IP (Device Finder › Traffic & Sessions)",
        "Firewalls onboarded to Strata Cloud Manager, by folder (preview)",
        "Prisma Access remote networks as sites (preview)",
        "Threat detections and blocked web requests for Security Operations (exploits, malware, callouts, "
        "scans, attacking countries)",
    ),
    estimated_minutes=10,
    uncertain=("The minimum role for Log Viewer queries can differ per tenant; Verify reports what is refused.",),
)

MANIFEST = ConnectorManifest(
    connector_id="paloalto_scm",
    vendor="Palo Alto Networks",
    product="Strata Cloud Manager",
    category="logging",
    capabilities=(TRAFFIC_LOGS, INVENTORY, INTERFACES, SECURITY_EVENTS),
    description=(
        "Firewall traffic and session logs from Strata Logging Service (SCM Log Viewer), and the firewalls "
        "and Prisma Access remote networks onboarded to Strata Cloud Manager (inventory: preview). "
        "Endpoint intelligence (IoT Security) is configured on the same page."
    ),
    docs_url="https://pan.dev/scm/api/",
    managed_elsewhere=True,
    settings_location="Settings & Support › Security & Logging Integrations",
    setup=SETUP,
)


def _traffic_provider():
    from app.integrations.providers.traffic import get_traffic_sessions_provider

    return get_traffic_sessions_provider()


def _strata_provider():
    from app.integrations.providers.strata_logging import get_strata_logging_provider

    return get_strata_logging_provider()


from app.integrations.connectors.paloalto_scm.inventory import DEVICES_PATH  # noqa: E402


from app.integrations.base import IntegrationError  # noqa: E402


class PaloAltoScmConnector(ScmThreats, ScmInventory, Connector):
    manifest = MANIFEST

    def __init__(self) -> None:
        super().__init__()
        self.config_transport = None  # test seam for the SCM config APIs (inventory)

    def reset_state(self) -> None:
        super().reset_state()
        self.clear_inventory_cache()

    # Seams for the fixture harness: the proven providers this connector wraps.
    def traffic_provider(self):
        return _traffic_provider()

    def strata_provider(self):
        return _strata_provider()

    @property
    def configured(self) -> bool:
        try:
            return bool(self.traffic_provider().configured)
        except Exception:  # noqa: BLE001
            return False

    @property
    def enabled(self) -> bool:
        return self.configured

    # v0.10.23: the firewall inventory added in v0.10.17 reuses the Traffic & Sessions service
    # account and switched itself on without asking. It now has its own switch (Settings ›
    # Connections › Strata Cloud Manager), stored as ``inventory_enabled`` in connectors.json.
    # Unset keeps the behaviour existing installs have had since v0.10.17 (on).
    inventory_switch = True

    @property
    def inventory_enabled(self) -> bool:
        value = self._saved().get("inventory_enabled")
        return True if value is None else bool(value)

    def list_sites(self):  # type: ignore[override]
        return super().list_sites() if self.inventory_enabled else []

    def list_devices(self, site_key: str | None = None):  # type: ignore[override]
        return super().list_devices(site_key) if self.inventory_enabled else []

    def secret_values(self) -> list[str]:
        from app.integrations.config import get_palo_alto_credentials

        creds = get_palo_alto_credentials()
        return [v for v in (creds.get("client_secret"), creds.get("client_id")) if v]

    # ---- TRAFFIC_LOGS -------------------------------------------------------------------------
    def search_traffic(self, ip: str, *, window: str = "1h", limit: int = 300) -> dict[str, Any]:
        provider = self.traffic_provider()
        return self.call(lambda: provider.search_by_ip(ip, window=window, limit=limit), "search traffic logs")

    def test_connection(self) -> dict[str, Any]:
        if not self.configured:
            return {
                "ok": False,
                "provider": self.provider_id,
                "configured": False,
                "detail": f"Set up and verify on {MANIFEST.settings_location}.",
            }
        if getattr(self, "config_transport", None) is None and self.transport is None:
            # v0.10.23: Re-test signs in and reads one firewall record (a few seconds). It used to run
            # a full Log Viewer query (7-45 s), which could not finish inside the test's time limit.
            try:
                http = self.call(self.config_http, "sign in to Strata Cloud Manager")
                self.call(lambda: http.get(DEVICES_PATH, limit=1, offset=0), "read firewall inventory")
                detail = "Signed in; firewall inventory readable."
            except IntegrationError as exc:
                if exc.code != "PERMISSION_DENIED":
                    raise
                detail = "Signed in; this service account may not read the firewall inventory."
            return {"ok": True, "provider": self.provider_id, "configured": True, "detail": detail}
        result = self.call(lambda: self.strata_provider().test_connection(), "verify traffic log query")
        return {
            "ok": bool(result.get("ok")),
            "provider": self.provider_id,
            "configured": True,
            "detail": f"Traffic log query answered ({result.get('sample_count', 0)} sample rows).",
        }


CONNECTOR = PaloAltoScmConnector
