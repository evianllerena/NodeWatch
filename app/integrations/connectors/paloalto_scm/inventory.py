"""INVENTORY for Strata Cloud Manager: firewalls and Prisma Access remote-network sites.

Uses the Common Services OAuth service account NodeWatch already stores for Traffic & Sessions
(Client ID + Client Secret + TSG ID; token from ``https://auth.apps.paloaltonetworks.com/oauth2/access_token``
with ``scope=tsg_id:<TSG>``). The token is sent as ``Authorization: Bearer`` to the fixed SCM API host
``https://api.strata.paloaltonetworks.com`` only.

Endpoints (pan.dev OpenAPI specs, PaloAltoNetworks/pan.dev ``openapi-specs/scm``):

* ``GET /config/setup/v1/devices`` — "List devices" (operationId ListDevices,
  https://pan.dev/scm/api/config/ngfw/setup/list-devices/; spec ``config/ngfw/setup/config-setup_R3.yaml``,
  server ``https://api.strata.paloaltonetworks.com/config/setup/v1``). Answer ``{data: [device], limit,
  offset, total}``; device fields: id, name, display_name, folder, hostname, ip_address, mac_address,
  family, model, software_version, uptime, ha_state, ha_peer_serial, ha_peer_state, is_connected,
  connected_since, labels.                                                     → firewalls (Device)
* ``GET /config/deployment/v1/remote-networks?folder=Remote Networks`` — "List remote networks"
  (operationId ListRemoteNetworks, spec ``config/sase/deployment/deployment-services_R3.yaml``). Fields
  used: id, name, region, spn_name, subnets. (The answer can also hold BGP peering secrets; NodeWatch
  never copies them.) Only answers on tenants with Prisma Access; anything else is skipped.
                                                                               → Prisma Access sites

Which firewalls appear: those onboarded to Strata Cloud Manager (cloud-managed NGFWs, and Panorama-
managed firewalls only if the tenant has onboarded them to SCM). Firewalls that only Panorama knows
come from the ``panorama`` connector; both key devices by serial number, so the same firewall seen by
both merges in Topology.

Assumed (preview, needs a live tenant): ``name`` carries the firewall serial number (SCM device
operations take serials ``^[0-9]{14,15}$``, see ``config/ngfw-operations/operations-R2-2026.yaml``) —
used as the serial only when it looks like one, otherwise the device is keyed by its MAC/UUID.

Not used (documented, but POST — read-only queries that the connector contract does not allow yet):
``POST /operations/v1/jobs/route-table|device-interfaces`` + ``GET /operations/v1/device/jobs/{id}``
(async route/interface tables per serial) and ``POST /incidents/v1/search`` (incidents → alerts).
"""

from __future__ import annotations

import re
import threading
import time
from typing import Any

from app.integrations.base import IntegrationError
from app.integrations.connectors.panorama.reader import parse_uptime
from app.integrations.connectors.sdk import HttpJsonClient
from app.integrations.connectors.sdk import device_key as make_device_key
from app.integrations.connectors.sdk import site_key as make_site_key
from app.integrations.contracts import INVENTORY
from app.integrations.domain import Device, Site, normalize_mac

SCM_API_HOST = "https://api.strata.paloaltonetworks.com"  # == config.PA_DS_API_HOST (approved destination)
DEVICES_PATH = "/config/setup/v1/devices"
REMOTE_NETWORKS_PATH = "/config/deployment/v1/remote-networks"
PAGE = 200
MAX_ITEMS = 5000
CACHE_SECONDS = 60.0
_SERIAL = re.compile(r"^[0-9A-Za-z]{12,16}$")


def _text(value: Any) -> str:
    return "" if value is None else str(value).strip()


def _page(payload: Any) -> tuple[list[dict], int | None]:
    if isinstance(payload, dict):
        rows = [r for r in payload.get("data") or [] if isinstance(r, dict)]
        total = payload.get("total")
        return rows, int(total) if isinstance(total, (int, float)) else None
    if isinstance(payload, list):
        return [r for r in payload if isinstance(r, dict)], None
    return [], None


class ScmInventory:
    """Capability mixin (needs ``self.call``, ``self.config_http()`` and ``self.manifest``)."""

    CAPABILITIES = (INVENTORY,)
    SOURCE = "paloalto_scm"

    def _inventory_state(self) -> dict[str, Any]:
        state = self.__dict__.get("_scm_inventory")
        if state is None:
            state = {"lock": threading.Lock(), "cache": None}
            self.__dict__["_scm_inventory"] = state
        return state

    def clear_inventory_cache(self) -> None:
        self._inventory_state()["cache"] = None
        finder = self.__dict__.get("_log_finder_obj")
        if finder is not None:
            finder.clear()

    def config_http(self) -> Any:
        """HTTP client for the SCM config APIs (the fake transport in tests)."""
        fake = getattr(self, "config_transport", None)
        if fake is not None:
            return fake
        from app.integrations.config import get_palo_alto_credentials, get_strata_logging_config
        from app.integrations.providers.strata_logging_auth import StrataLoggingAuthAdapter

        creds = get_palo_alto_credentials()
        config = get_strata_logging_config()
        adapter = StrataLoggingAuthAdapter(
            type(config)(enabled=True, request_timeout=config.request_timeout), creds
        )  # same token the Traffic & Sessions provider uses (TOKEN_MANAGER cache key is shared)
        token = adapter.authorize(force=bool(getattr(self, "_force_token", False))).access_token
        return HttpJsonClient(
            SCM_API_HOST,
            headers={"Authorization": f"Bearer {token}"},
            product="Strata Cloud Manager",
            timeout=float(config.request_timeout or 30),
            secrets=(token, creds.get("client_secret", ""), creds.get("client_id", "")),
        )

    def _list_all(self, http: Any, path: str, **params: Any) -> list[dict]:
        rows: list[dict] = []
        offset = 0
        while offset < MAX_ITEMS:
            batch, total = _page(http.get(path, limit=PAGE, offset=offset, **params))
            rows.extend(batch)
            offset += len(batch)
            if not batch or len(batch) < PAGE or (total is not None and offset >= total):
                break
        return rows

    def _inventory(self) -> dict[str, list[dict]]:
        state = self._inventory_state()
        with state["lock"]:
            hit = state["cache"]
            if hit and time.monotonic() - hit[0] < CACHE_SECONDS:
                return hit[1]
            http = self.config_http()
            try:
                devices = self._list_all(http, DEVICES_PATH)
            except IntegrationError as exc:
                if exc.code != "AUTHENTICATION_FAILED" or getattr(self, "config_transport", None) is not None:
                    raise
                # v0.10.23: a revoked/rotated token is fetched again once instead of failing until
                # the cached one expires (up to 15 minutes).
                self._force_token = True
                try:
                    http = self.config_http()
                finally:
                    self._force_token = False
                devices = self._list_all(http, DEVICES_PATH)
            try:
                remote = self._list_all(http, REMOTE_NETWORKS_PATH, folder="Remote Networks")
            except IntegrationError:
                remote = []  # no Prisma Access on this tenant, or the role cannot read deployment config
            data = {"devices": devices, "remote_networks": remote}
            state["cache"] = (time.monotonic(), data)
            return data

    # ---- records --------------------------------------------------------------------------------
    def _site_for_folder(self, folder: str) -> tuple[str, str]:
        return (make_site_key(self.SOURCE, f"folder:{folder.lower()}"), folder) if folder else ("", "")

    def list_sites(self) -> list[Site]:
        def build() -> list[Site]:
            data = self._inventory()
            sites: dict[str, Site] = {}
            for d in data["devices"]:
                key, name = self._site_for_folder(_text(d.get("folder")))
                if key and key not in sites:
                    sites[key] = Site(
                        key=key,
                        source=self.SOURCE,
                        name=name,
                        native_id=name,
                        kind="container",
                        vendor={"kind": "folder"},
                    )
            for r in data["remote_networks"]:
                name = _text(r.get("name"))
                if not name:
                    continue
                key = make_site_key(self.SOURCE, f"remote-network:{_text(r.get('id')) or name}")
                sites[key] = Site(
                    key=key,
                    source=self.SOURCE,
                    kind="remote_network",
                    name=name,
                    native_id=_text(r.get("id")) or name,
                    vendor={
                        k: v
                        for k, v in {
                            "kind": "prisma_access_remote_network",
                            "region": _text(r.get("region")),
                            "spn": _text(r.get("spn_name")),
                            "subnets": [_text(s) for s in r.get("subnets") or [] if _text(s)][:50],
                        }.items()
                        if v
                    },
                )
            if any(d.role == "cloud_gateway" for d in self._log_devices(set())):  # v0.10.27
                from app.integrations.connectors.paloalto_scm.logs import cloud_site

                cs = cloud_site(self.SOURCE)
                sites[cs.key] = cs
            return sorted(sites.values(), key=lambda s: s.name.lower())

        return self.call(build, "list Strata Cloud Manager folders and remote networks")

    def _device(self, d: dict[str, Any]) -> Device:
        name = _text(d.get("name"))
        serial = name if _SERIAL.match(name) else ""
        mac = normalize_mac(d.get("mac_address"))
        skey, sname = self._site_for_folder(_text(d.get("folder")))
        peer = _text(d.get("ha_peer_serial"))
        connected = d.get("is_connected")
        ha_state = _text(d.get("ha_state")).lower()
        return Device(
            # Serial first so the same firewall reported by Panorama gets the same key.
            key=make_device_key(serial=serial, source=self.SOURCE, native_id=_text(d.get("id")) or name)
            if serial
            else make_device_key(mac=mac, source=self.SOURCE, native_id=_text(d.get("id")) or name),
            source=self.SOURCE,
            name=_text(d.get("hostname")) or _text(d.get("display_name")) or name,
            role="firewall",
            aliases=[x for x in dict.fromkeys(_text(d.get(k)) for k in ("display_name", "hostname", "name")) if x],
            labels=[_text(x) for x in d.get("labels") or [] if _text(x)],
            native_id=_text(d.get("id")),
            site_key=skey,
            site_name=sname,
            vendor_name="Palo Alto Networks",
            model=_text(d.get("model")),
            serial=serial,
            mac=mac,
            mgmt_ip=_text(d.get("ip_address")),
            os_version=f"PAN-OS {_text(d.get('software_version'))}" if _text(d.get("software_version")) else "",
            status="up" if connected is True else "down" if connected is False else "unknown",
            uptime_s=parse_uptime(_text(d.get("uptime"))) if connected is True else None,
            ha_state=ha_state,
            members=[
                {"serial": serial, "role": ha_state or "ha-member"},
                {"serial": peer, "role": _text(d.get("ha_peer_state")).lower() or "ha-peer"},
            ]
            if peer
            else [],
            vendor={
                k: v
                for k, v in {
                    "folder": _text(d.get("folder")),
                    "family": _text(d.get("family")),
                    "labels": [_text(x) for x in d.get("labels") or [] if _text(x)],
                    "uptime": _text(d.get("uptime")),
                    "connected_since": _text(d.get("connected_since")),
                    "display_name": _text(d.get("display_name")),
                }.items()
                if v
            },
        )

    def list_devices(self, site_key: str | None = None) -> list[Device]:
        def build() -> list[Device]:
            out = [self._device(d) for d in self._inventory()["devices"] if _text(d.get("name") or d.get("id"))]
            out += self._log_devices({d.serial for d in out if d.serial})
            return [d for d in out if not site_key or d.site_key == site_key]

        return self.call(build, "list Strata Cloud Manager devices")

    # ---- firewalls seen in traffic logs (v0.10.25, see logs.py) ---------------------------------------
    def _log_finder(self) -> Any:
        from app.integrations.connectors.paloalto_scm.logs import LogFirewalls

        finder = self.__dict__.get("_log_finder_obj")
        if finder is None:
            finder = self.__dict__["_log_finder_obj"] = LogFirewalls(getattr(self, "log_state_dir", None))
        return finder

    def _log_devices(self, known_serials: set[str]) -> list[Device]:
        """Firewalls Strata Logging Service sees that the SCM device list does not: from the last background
        discovery (never queried on this thread; the first call returns [] and starts one)."""
        from app.integrations.connectors.paloalto_scm import logs

        seam = getattr(self, "log_sampler", None)  # fixture harness: run the discovery inline
        finder = self._log_finder()
        if seam is not None:
            if finder.due():
                finder.refresh(seam, background=False, system_sampler=getattr(self, "log_system_sampler", None))
        elif finder.due():
            try:
                provider = self.strata_provider()
                sampler = logs.provider_sampler(provider)
                system = logs.SystemSampler(provider) if sampler is not None else None
            except Exception:  # noqa: BLE001 - logging not configured: nothing to discover
                sampler = system = None
            if sampler is not None:
                finder.refresh(sampler, pool=logs.provider_pool(), system_sampler=system)
        found = [f for f in finder.found() if str(f.get("serial") or "") not in known_serials]
        return logs.to_devices(found, self.SOURCE)

    # ---- INTERFACES (v0.10.27): the ports a log-discovered device logged traffic on ------------------------
    def list_interfaces(self, device_key: str) -> list[Any]:
        from app.integrations.connectors.paloalto_scm import logs

        def build() -> list[Any]:
            for f in self._log_finder().found():
                serial = str(f.get("serial") or "")
                if serial and make_device_key(serial=serial, source=self.SOURCE, native_id=serial) == device_key:
                    return logs.to_interfaces(f, device_key, self.SOURCE)
            return []

        return self.call(build, "list ports seen in traffic logs")
