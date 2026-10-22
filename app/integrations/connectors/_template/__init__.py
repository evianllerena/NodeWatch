"""TEMPLATE connector — copy this folder to add a vendor. (Ignored by discovery: the name starts with "_".)

1. Copy ``_template/`` to ``<your_connector_id>/`` (letters, digits, underscores: ``cisco_meraki``).
2. Fill in MANIFEST: vendor, product, category, the settings fields the user types in, and ONLY the
   capabilities you really implement. Start with ``maturity="preview"``. Fill in SETUP — the guide the
   "Add connection" wizard shows (how to create a least-privilege account or key, what Test checks).
3. Implement each capability method below (delete the ones you do not support, and remove them from
   ``capabilities``). Return records from ``app.integrations.domain`` — never raw vendor payloads.
4. Record real (scrubbed) API answers in ``fixtures/`` and wire them up in ``fixtures.py``.
5. Run ``pytest tests/test_connectors_contract.py`` — it runs against every connector automatically.
6. Optional: override ``probe_plan()`` for a cheaper, vendor-specific permission check (see
   silverpeak_orchestrator/probe.py); the default probes each capability's own read method.
7. Restart NodeWatch: the connector appears in Settings › Connections › Add connection.
   ``python tools/new_connector.py <id> --vendor … --product … --category …`` does steps 1, 4 and the
   test file for you. See docs/CONNECTORS.md › "Add a new vendor in 6 steps".

Rules (enforced by the contract tests):
* read-only; every network call through ``self.http()`` inside ``self.call(...)`` so failures become
  ``IntegrationError`` and secrets are scrubbed from messages;
* device keys from ``device_key(mac=..., serial=...)`` so other vendors' records about the same box
  correlate; MACs through ``normalize_mac``; severities/roles/states from the domain vocabularies;
* the same real-world thing gets the same ``key`` on every call;
* no company-specific values in code — everything per-install comes from settings.

Cite the vendor documentation for every endpoint you call, next to the call.
"""

from __future__ import annotations

from typing import Any

from app.integrations.base import IntegrationError
from app.integrations.connectors.sdk import (
    Connector,
    ConnectorManifest,
    ConnectorSetup,
    HttpJsonClient,
    SettingField,
    SetupIssue,
    SetupStep,
    device_key as make_device_key,
    epoch_seconds,
    site_key as make_site_key,
)
from app.integrations.contracts import (  # noqa: F401 - keep the ones you implement
    ALERTS,
    ARP_TABLE,
    EVENTS,
    INTERFACES,
    INVENTORY,
    MAC_TABLE,
    NEIGHBORS,
    ROUTES,
    TUNNELS,
)
from app.integrations.domain import (  # noqa: F401
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
    normalize_mac,
    stable_key,
)

CONNECTOR_ID = "example_vendor"  # ← must equal the folder name

# The "Add connection" guide. Plain words for the person connecting the product. Replace every TODO
# (a connector cannot be promoted to maturity="stable" while its guide still contains one).
SETUP = ConnectorSetup(
    summary="TODO: one line — what NodeWatch gets from this product.",
    prerequisites=(
        "TODO: product version and how it is reached (HTTPS from this PC)",
        "TODO: who can create the read-only account or key",
    ),
    steps=(
        SetupStep(
            "TODO: Create a read-only role",
            "TODO: menu path and the exact read-only permissions to tick.",
            link="https://developer.example.com/api",
            copy="nodewatch-readonly",
        ),
        SetupStep("TODO: Create the API token", "TODO: where the token is shown and that it is shown once."),
    ),
    permissions="TODO: the least-privilege role or key, and what NodeWatch never needs.",
    verify="TODO: what Test reads (one call) and what each capability probe reads.",
    troubleshooting=(SetupIssue("Authenticated: fail (HTTP 401)", "TODO: what usually causes it and the fix."),),
    data_you_get=("TODO: each capability in plain words",),
    estimated_minutes=10,
)

MANIFEST = ConnectorManifest(
    connector_id=CONNECTOR_ID,
    vendor="Example Networks",
    product="Example Controller",
    category="network_management",  # network_management | firewall | sdwan | logging | siem | other
    capabilities=(INVENTORY, INTERFACES, ALERTS),  # ← only what you implement below
    settings=(
        SettingField("base_url", "Controller URL", "url", required=True, placeholder="https://controller.example.com"),
        SettingField(
            "api_token",
            "API token",
            "secret",
            required=True,
            help="Read-only token. Stored in Windows Credential Manager.",
        ),
        SettingField("verify_tls", "Verify TLS certificate", "boolean", default=True),
        SettingField("ca_file", "Private CA certificate (optional)", "text", placeholder=r"C:\certs\ca.pem"),
        SettingField("timeout", "Request timeout (seconds)", "number", default=20),
    ),
    description="One sentence: what NodeWatch gets from this product.",
    docs_url="https://developer.example.com/api",
    maturity="preview",
    setup=SETUP,
)

# Map the vendor's words onto the NodeWatch vocabularies (see app/integrations/domain.py).
STATUS = {"online": "up", "offline": "down", "alerting": "degraded"}
SEVERITY = {"critical": "critical", "high": "major", "medium": "warning", "low": "info"}
ROLE = {"switch": "switch", "ap": "wireless_ap", "firewall": "firewall", "appliance": "sdwan_edge"}


def _text(value: Any) -> str:
    return "" if value is None else str(value).strip()


class ExampleConnector(Connector):
    manifest = MANIFEST

    @property
    def configured(self) -> bool:
        s = self.settings()
        return bool(s.get("base_url") and s.get("api_token"))

    def build_http(self) -> HttpJsonClient:
        s = self.settings()
        token = self.secret("api_token")
        if not s.get("base_url") or not token:
            raise IntegrationError("URL and API token are required", code="NOT_CONFIGURED")
        return HttpJsonClient(
            _text(s["base_url"]),
            headers={"Authorization": f"Bearer {token}"},  # ← the vendor's auth header
            product=MANIFEST.product,
            verify_tls=bool(s.get("verify_tls", True)),
            ca_file=_text(s.get("ca_file")),
            timeout=float(s.get("timeout") or 20),
            secrets=(token,),
        )

    def _devices_raw(self) -> list[dict]:
        # GET /api/v1/devices  ← cite the vendor doc page here
        return self.call(lambda: self.http().get("/api/v1/devices"), "list devices") or []

    # ---- INVENTORY: list_sites() + list_devices(site_key) ------------------------------------
    def list_sites(self) -> list[Site]:
        # GET /api/v1/sites
        rows = self.call(lambda: self.http().get("/api/v1/sites"), "list sites") or []
        return [
            Site(
                key=make_site_key(CONNECTOR_ID, r["id"]),
                source=CONNECTOR_ID,
                name=_text(r.get("name")),
                native_id=_text(r["id"]),
            )
            for r in rows
            if isinstance(r, dict) and r.get("id")
        ]

    def list_devices(self, site_key: str | None = None) -> list[Device]:
        out = []
        for r in self._devices_raw():
            skey = make_site_key(CONNECTOR_ID, r.get("site_id")) if r.get("site_id") else ""
            if site_key and skey != site_key:
                continue
            out.append(
                Device(
                    key=make_device_key(
                        mac=r.get("mac"), serial=r.get("serial"), source=CONNECTOR_ID, native_id=r.get("id")
                    ),
                    source=CONNECTOR_ID,
                    name=_text(r.get("name")) or _text(r.get("serial")),
                    role=ROLE.get(_text(r.get("type")).lower(), "unknown"),
                    native_id=_text(r.get("id")),
                    site_key=skey,
                    vendor_name=MANIFEST.vendor,
                    model=_text(r.get("model")),
                    serial=_text(r.get("serial")),
                    mac=normalize_mac(r.get("mac")),
                    mgmt_ip=_text(r.get("ip")),
                    os_version=_text(r.get("firmware")),
                    status=STATUS.get(_text(r.get("status")).lower(), "unknown"),
                    last_seen=epoch_seconds(r.get("last_seen")),
                )
            )
        return out

    # ---- INTERFACES: list_interfaces(device_key) -------------------------------------------------
    def list_interfaces(self, device_key: str) -> list[Interface]:
        raw = next(
            (
                r
                for r in self._devices_raw()
                if make_device_key(mac=r.get("mac"), serial=r.get("serial"), source=CONNECTOR_ID, native_id=r.get("id"))
                == device_key
            ),
            None,
        )
        if raw is None:
            return []
        # GET /api/v1/devices/{id}/ports
        ports = self.call(lambda: self.http().get(f"/api/v1/devices/{raw['id']}/ports"), "read ports") or []
        return [
            Interface(
                key=stable_key(device_key, p.get("name")),
                source=CONNECTOR_ID,
                device_key=device_key,
                name=_text(p.get("name")),
                kind="physical",  # physical | lag | vlan | loopback | tunnel | mgmt | logical
                admin_up=p.get("enabled"),
                oper_up=_text(p.get("status")).lower() == "connected",
                speed_mbps=p.get("speed_mbps"),
                mac=normalize_mac(p.get("mac")),
            )
            for p in ports
            if isinstance(p, dict) and p.get("name")
        ]

    # ---- ALERTS: list_alerts(site_key) ---------------------------------------------------------
    def list_alerts(self, site_key: str | None = None) -> list[Alert]:
        # GET /api/v1/alerts?state=open
        rows = self.call(lambda: self.http().get("/api/v1/alerts", state="open"), "read alerts") or []
        out = []
        for a in rows:
            if not isinstance(a, dict):
                continue
            dkey = make_device_key(
                mac=a.get("device_mac"),
                serial=a.get("device_serial"),
                source=CONNECTOR_ID,
                native_id=a.get("device_id"),
            )
            out.append(
                Alert(
                    # Same condition on the same thing → same key on every refresh (no timestamps!).
                    key=stable_key(CONNECTOR_ID, a.get("type"), dkey, a.get("port")),
                    source=CONNECTOR_ID,
                    type=f"{CONNECTOR_ID}.{_text(a.get('type'))}",
                    category="connectivity",  # connectivity | hardware | switching | routing | security | system | performance
                    severity=SEVERITY.get(_text(a.get("severity")).lower(), "info"),
                    title=_text(a.get("title")) or _text(a.get("type")),
                    detail=_text(a.get("message")),
                    device_key=dkey,
                    first_seen=epoch_seconds(a.get("started_at")),
                    native_id=_text(a.get("id")),
                )
            )
        return out

    # ---- other capabilities: add the method, add the capability to MANIFEST ---------------------
    # EVENTS     def list_events(self, site_key=None, *, hours=24) -> list[Event]
    # NEIGHBORS  def list_neighbors(self, site_key=None) -> list[Neighbor]        (LLDP/CDP)
    # MAC_TABLE  def list_mac_table(self, device_key) -> list[L2Entry]
    # ARP_TABLE  def list_arp(self, device_key=None) -> list[L3Entry]
    # ROUTES     def list_routes(self, device_key) -> list[Route]
    # TUNNELS    def list_tunnels(self, site_key=None) -> list[Tunnel]           (IPsec / SD-WAN)
    # WAN_CIRCUITS def list_circuits(self, site_key=None) -> list[Circuit]       (internet / MPLS / LTE on WAN ports, v0.10.24)

    def test_connection(self) -> dict[str, Any]:
        """ONE cheap authenticated call."""
        if not self.configured:
            return {"ok": False, "provider": CONNECTOR_ID, "configured": False}
        # GET /api/v1/whoami
        me = self.call(lambda: self.http().get("/api/v1/whoami"), "check the API token") or {}
        return {
            "ok": True,
            "provider": CONNECTOR_ID,
            "configured": True,
            "detail": _text(me.get("org_name")) or "Connected",
        }


CONNECTOR = ExampleConnector
