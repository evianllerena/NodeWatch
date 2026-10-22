"""Palo Alto Networks Panorama connector (PAN-OS XML API) — PREVIEW.

One Panorama connection covers every firewall it manages: Panorama lists the fleet, and each
firewall-level command is sent to Panorama with ``target=<serial>``. Built from the PAN-OS and
Panorama API guide and Palo Alto's own SDK parsers (see ``reader.py`` for the command list with
citations); not yet validated against a live Panorama, hence ``maturity="preview"``.

Package layout (built for a future change module):

* ``client.py`` — transport only: X-PAN-KEY auth, GET ``/api/``, safe XML parsing, PAN-OS error codes,
  job polling, short cache, and a hard read-only guard.
* ``reader.py`` — the read capabilities (inventory, interfaces, ARP, routes, LLDP, IPsec, alerts,
  health, security policy lookup) as NodeWatch domain records.
* ``writer.py`` — design-only stub for candidate edit → validate → commit → commit-all with
  confirmation, audit and rollback. Not implemented; every method refuses.

Authentication: an API key generated on Panorama for a dedicated admin whose role allows only the
XML API "Operational Requests" permission (see docs/CONNECTORS.md › Palo Alto). The key is sent as the
``X-PAN-KEY`` header, never in the URL, and stored in Windows Credential Manager.
"""

from __future__ import annotations

from typing import Any

from app.integrations.base import IntegrationError
from app.integrations.connectors.panorama.client import PanoramaClient, PanXmlTransport, text
from app.integrations.connectors.panorama.reader import CMD_SYSTEM_INFO, CONNECTOR_ID, PanoramaReader
from app.integrations.connectors.sdk import (
    Connector,
    ConnectorManifest,
    ConnectorSetup,
    SettingField,
    SetupIssue,
    SetupStep,
)
from app.integrations.connectors.panorama.threats import PanoramaThreats
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

SETUP = ConnectorSetup(
    summary="Every firewall Panorama manages — inventory, HA, interfaces, routes, ARP, LLDP, IPsec, health "
    "and policy lookup — through one read-only key.",
    prerequisites=(
        "Panorama reachable over HTTPS (443) from this PC",
        "A Panorama superuser who may create admin roles and administrators and commit to Panorama",
        "curl (built into Windows 10 and 11) to generate the API key once",
        "Only if Panorama uses an internal certificate: your company root CA as a PEM file",
    ),
    steps=(
        SetupStep(
            "Create a read-only admin role",
            "Panorama › Admin Roles › Add. Name: nodewatch-readonly. Role: Panorama. XML API tab: enable only "
            "Operational Requests; disable Report, Log, Configuration, Commit, User-ID Agent, Export and "
            "Import. REST API tab: disable everything. Command Line: None. Web UI: disable everything.",
            link="https://docs.paloaltonetworks.com/ngfw/help/11-1/panorama-web-interface/panorama-admin-roles",
            copy="nodewatch-readonly",
        ),
        SetupStep(
            "Create the administrator",
            "Panorama › Administrators › Add. Name: nodewatch-ro. Administrator Type: Custom Panorama Admin. "
            "Profile: nodewatch-readonly. Give it a long random password (only used once, in the next step).",
            link="https://docs.paloaltonetworks.com/ngfw/help/11-1/panorama-web-interface/panorama-administrators",
            copy="nodewatch-ro",
        ),
        SetupStep("Commit", "Commit › Commit to Panorama, so the new role and administrator are active."),
        SetupStep(
            "Generate the API key",
            "Run this on any PC that can reach Panorama (replace the address and password). The password "
            "goes in the request body, not the URL. Copy the text between <key> and </key>.",
            link="https://docs.paloaltonetworks.com/pan-os/10-0/pan-os-panorama-api/get-started-with-the-pan-os-xml-api/get-your-api-key",
            copy='curl -X POST "https://panorama.example.com/api/?type=keygen" '
            '--data-urlencode "user=nodewatch-ro" --data-urlencode "password=<password>"',
        ),
        SetupStep(
            "Optional: key lifetime",
            "To rotate keys automatically: Panorama › Setup › Management › Authentication Settings › API Key "
            "Lifetime. Generating a new key or changing the password also invalidates the old key.",
        ),
    ),
    permissions="A dedicated Panorama administrator (Custom Panorama Admin) whose admin role allows only "
    "XML API › Operational Requests — no Configuration, Commit, Log, Report, Import/Export or User-ID rights, "
    "no REST API, no CLI, no Web UI. NodeWatch also refuses, before sending, any command other than <show> "
    "and the read-only policy-match <test>.",
    verify="Reads Panorama's system info, then the managed firewalls and device groups, and through Panorama "
    "(target=serial) one connected firewall's interfaces, ARP, routes, LLDP, IPsec flows, system resources "
    "and HA state. Policy lookup is not run. Nothing is changed. At most 20 s.",
    troubleshooting=(
        SetupIssue(
            "Authenticated: fail (Forbidden / invalid credentials)",
            "The key was invalidated (a new key was generated or the password changed), or the role has no "
            "XML API access. Generate a new key.",
        ),
        SetupIssue(
            "Firewall reads refused (Unauthorized)",
            "The admin role is missing XML API › Operational Requests, or the administrator is a Device Group "
            "and Template admin without that firewall's device group. Use Custom Panorama Admin.",
        ),
        SetupIssue(
            "0 firewalls, or firewall checks skipped",
            "No firewall is connected to Panorama (Panorama › Managed Devices › Summary), or the 'Device "
            "groups' filter in the form matches none.",
        ),
        SetupIssue(
            "Firewall reads time out",
            "That firewall answers Panorama slowly or is disconnecting. Lower 'Parallel firewall queries' and "
            "check its connection in Panorama.",
        ),
        SetupIssue(
            "TLS certificate: fail",
            "Panorama uses a certificate from your company CA. Export the root CA as PEM and set 'Private CA "
            "certificate'. Do not turn verification off.",
        ),
    ),
    data_you_get=(
        "Every managed firewall: model, serial, PAN-OS version, management IP, HA state and peer, device group",
        "Interfaces with security zones and virtual routers",
        "Routing tables (legacy and Advanced Routing Engine) and ARP tables",
        "LLDP neighbors (when LLDP is enabled on the firewall)",
        "IPsec tunnels with their state",
        "Live health: data-plane CPU, memory, sessions",
        "Alerts: firewall disconnected, policy out of sync, HA problems",
        "Policy lookup in the Topology path trace: would this flow be allowed",
        "Threat detections and blocked web requests in Security Operations (from the logs Panorama keeps)",
    ),
    estimated_minutes=15,
    uncertain=(
        "The Advanced Routing answer, 'show vpn flow' element names, session-info fields and the "
        "resource-monitor shape. Missing elements leave fields empty.",
    ),
)

MANIFEST = ConnectorManifest(
    connector_id=CONNECTOR_ID,
    vendor="Palo Alto Networks",
    product="Panorama",
    category="firewall",
    capabilities=(
        INVENTORY,
        INTERFACES,
        ALERTS,
        NEIGHBORS,
        ARP_TABLE,
        ROUTES,
        TUNNELS,
        HEALTH,
        POLICY_LOOKUP,
        SECURITY_EVENTS,
    ),
    settings=(
        SettingField(
            "base_url",
            "Panorama URL",
            "url",
            required=True,
            placeholder="https://panorama.example.com",
            help="The address you open Panorama at. HTTPS only. Firewalls are reached through Panorama.",
            origin_only=True,
        ),
        SettingField(
            "api_key",
            "API key",
            "secret",
            required=True,
            help="Key of a Panorama admin whose role allows only XML API › Operational Requests "
            "(see the Connectors guide). Sent as the X-PAN-KEY header; stored in Windows Credential Manager.",
        ),
        SettingField(
            "verify_tls",
            "Verify TLS certificate",
            "boolean",
            default=True,
            help="Keep on. Use a CA file for a private certificate.",
        ),
        SettingField(
            "ca_file",
            "Private CA certificate (optional)",
            "text",
            placeholder=r"C:\certs\company-root-ca.pem",
            help="PEM file that signed Panorama's certificate, instead of turning verification off.",
        ),
        SettingField(
            "device_groups",
            "Device groups (optional)",
            "text",
            placeholder="DG-Branches, DG-HQ",
            help="Comma-separated. Leave blank for every firewall Panorama manages.",
        ),
        SettingField(
            "site_map",
            "Device group → site (optional)",
            "text",
            placeholder="DG-HQ=Headquarters; DG-Branch-01=Branch 01",
            help="By default each device group is one site. Map several groups to one site name here.",
        ),
        SettingField(
            "max_workers",
            "Parallel firewall queries",
            "number",
            default=4,
            help="How many firewalls are queried at once through Panorama (1–16).",
        ),
        SettingField(
            "max_firewalls",
            "Firewall limit per refresh",
            "number",
            default=100,
            help="Safety cap on per-firewall commands in one refresh.",
        ),
        SettingField("timeout", "Request timeout (seconds)", "number", default=20),
    ),
    description=(
        "Every firewall Panorama manages: inventory, HA, interfaces and zones, routes, ARP, LLDP, IPsec "
        "tunnels, health and security policy lookup. Read-only."
    ),
    docs_url="https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-panorama-api",
    maturity="preview",
    setup=SETUP,
)


class PanoramaConnector(PanoramaThreats, PanoramaReader, Connector):
    manifest = MANIFEST

    def __init__(self) -> None:
        super().__init__()
        self._client: PanoramaClient | None = None
        self._client_for: Any = None

    def reset_state(self) -> None:
        super().reset_state()
        self._client = None
        self._client_for = None

    @property
    def configured(self) -> bool:
        s = self.settings()
        return bool(s.get("base_url") and s.get("api_key"))

    def build_http(self) -> PanXmlTransport:
        s = self.settings()
        key = self.secret("api_key")
        if not s.get("base_url") or not key:
            raise IntegrationError("Panorama URL and API key are required", code="NOT_CONFIGURED")
        return PanXmlTransport(
            str(s.get("base_url")),
            api_key=key,
            product=MANIFEST.product,
            verify_tls=bool(s.get("verify_tls", True)),
            ca_file=str(s.get("ca_file") or "").strip(),
            timeout=float(s.get("timeout") or 20),
            secrets=(key,),
        )

    def pan(self) -> PanoramaClient:
        """The read-only XML API client (kept between calls so its short cache is shared)."""
        if self._client is None or (self.transport is not None and self._client_for is not self.transport):
            self._client = PanoramaClient(self.http(), product=MANIFEST.product)
            self._client_for = self.transport
        return self._client

    def probe_plan(self) -> list[Any]:
        """Settings › Connections › Test: one firewall per command (see probe.py)."""
        from app.integrations.connectors.panorama.probe import plan

        return plan(self)

    def test_connection(self) -> dict[str, Any]:
        if not self.configured:
            return {
                "ok": False,
                "provider": CONNECTOR_ID,
                "configured": False,
                "detail": "Enter the Panorama URL and API key.",
            }
        result = self.call(lambda: self.pan().op(CMD_SYSTEM_INFO, cache=False), "read Panorama system info")
        name = text(result, "system/hostname")
        version = text(result, "system/sw-version")
        model = text(result, "system/model")
        detail = " · ".join(x for x in (name, model, f"PAN-OS {version}" if version else "") if x)
        return {"ok": True, "provider": CONNECTOR_ID, "configured": True, "detail": detail or "Panorama answered"}


CONNECTOR = PanoramaConnector
