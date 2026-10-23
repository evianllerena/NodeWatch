"""Generic SNMPv3 (read-only) connector — PREVIEW.

For network devices that have no usable API. Vendor APIs stay the primary source; this connector
fills gaps with what every managed switch/router/firewall exposes through standard MIBs:

* INVENTORY   SNMPv2-MIB system group, ENTITY-MIB chassis serial/model, LLDP-MIB local chassis ID
* INTERFACES  IF-MIB ifTable/ifXTable, IP-MIB ipAddrTable/ipAddressTable, IEEE8023-LAG-MIB
* NEIGHBORS   LLDP-MIB lldpRemTable/lldpRemManAddrTable (+ CISCO-CDP-MIB cdpCacheTable when present)
* ARP_TABLE   IP-MIB ipNetToPhysicalTable, fallback ipNetToMediaTable
* MAC_TABLE   Q-BRIDGE-MIB dot1qTpFdbTable (+ dot1qVlanFdbId), fallback BRIDGE-MIB dot1dTpFdbTable;
              bridge port → ifIndex via dot1dBasePortIfIndex
* ROUTES      IP-FORWARD-MIB inetCidrRouteTable, fallback ipCidrRouteTable, then RFC 1213 ipRouteTable
* HEALTH      HOST-RESOURCES-MIB hrProcessorLoad / hrStorage (RAM); interface errors; rx/tx rates from
              two ifHC*Octets samples taken on consecutive refreshes

Security model:
* SNMPv3 USM only (no v1/v2c community strings, which travel in clear text). authPriv is required;
  authNoPriv needs an explicit "insecure" toggle. MD5 and DES are not offered.
* Read-only: the transport has GET and GETBULK only — there is no SET code path.
* Passphrases live in the secure credential store (Windows Credential Manager or the macOS Keychain) (SDK secret fields), are never logged, and are
  scrubbed from every error. Changing the targets in the test form requires typing them again.
* Targets: explicit hosts, or private ranges no larger than /24 (≤ 256 hosts in total); multicast,
  broadcast, link-local and reserved addresses are refused (see ``targets.py``).
* Bounded load: at most 8 hosts polled in parallel, per-host and total time limits, 60 s cache.
"""

from __future__ import annotations

import concurrent.futures
import ipaddress
import threading
import time
from typing import Any, Callable

from app.integrations.base import IntegrationError
from app.integrations.connectors.sdk import (
    Connector,
    ConnectorManifest,
    ConnectorSetup,
    SettingField,
    SetupIssue,
    SetupStep,
    device_key as make_device_key,
    site_key as make_site_key,
)
from app.integrations.connectors.snmp import mibs
from app.integrations.connectors.snmp.targets import parse_targets, resolve
from app.integrations.connectors.snmp.transport import (
    AUTH_PROTOCOLS,
    PRIV_PROTOCOLS,
    PysnmpTransport,
    SnmpCredentials,
)
from app.integrations.contracts import ARP_TABLE, HEALTH, INTERFACES, INVENTORY, MAC_TABLE, NEIGHBORS, ROUTES
from app.integrations.domain import Device, Interface, L2Entry, L3Entry, Neighbor, Route, Site, stable_key

CONNECTOR_ID = "snmp"
NO_PRIVACY = "None — authNoPriv (insecure)"

SETUP = ConnectorSetup(
    summary="Read-only SNMPv3 for devices without a usable API: system, interfaces, LLDP/CDP, ARP, MAC and "
    "routing tables, CPU/memory.",
    prerequisites=(
        "Devices with SNMPv3 enabled, reachable on UDP 161 from this PC",
        "Admin access on each device (or its template) to add an SNMPv3 user and view",
        "The device addresses: IPs, host names or private ranges up to /24 (at most 256 hosts)",
    ),
    steps=(
        SetupStep(
            "Create a read-only view",
            "On each device create an SNMP view that includes OID 1 (everything), or at least SNMPv2-MIB "
            "system, IF-MIB, IP-MIB, IP-FORWARD-MIB, LLDP-MIB, BRIDGE-MIB/Q-BRIDGE-MIB and HOST-RESOURCES-MIB. "
            "Give the group read access to it and no write view.",
        ),
        SetupStep(
            "Create the SNMPv3 user",
            "User nodewatch-ro, security level authPriv, authentication SHA-256 (or SHA-1 on old devices), "
            "privacy AES-128. Use two different passphrases of at least 8 characters. Platform examples "
            "(Junos, Cisco IOS, FortiOS, PAN-OS, Net-SNMP) are in docs/CONNECTORS.md › SNMPv3.",
            copy="snmp-server user nodewatch-ro NW-RO v3 auth sha <auth-passphrase> priv aes 128 <priv-passphrase>",
        ),
        SetupStep(
            "Allow only this PC",
            "Restrict SNMP to this PC's address with the platform's ACL or trusted-host setting.",
        ),
        SetupStep(
            "List the targets",
            "In the next step enter the devices to poll, and pick the same protocols you configured. Changing "
            "the targets later requires typing the passphrases again.",
        ),
    ),
    permissions="An SNMPv3 user with authPriv (SHA-2 + AES) in a group that has a read view only — no write "
    "or notify view. NodeWatch has no SET code path; SNMPv1/v2c communities are not offered.",
    verify="Reads the system group of the first target, then the first few rows of each table NodeWatch uses "
    "from that target: interfaces, LLDP/CDP, ARP, bridge (MAC), routes and CPU. An empty table means the "
    "device does not keep it or the view excludes it. At most 20 s.",
    troubleshooting=(
        SetupIssue(
            "Reachable: fail (no response / timeout)",
            "UDP 161 is blocked, the ACL does not allow this PC, or the user name or protocols do not match "
            "(SNMPv3 often stays silent instead of answering with an error).",
        ),
        SetupIssue(
            "Authenticated: fail (wrong digest / decryption error)",
            "A passphrase or protocol differs from the device. On Cisco 'aes 256' choose 'AES-256 (Cisco key "
            "extension)'.",
        ),
        SetupIssue(
            "A table is 'empty'",
            "Add that MIB (or OID 1) to the user's read view; some devices do not keep every table (for "
            "example no MAC table on a router).",
        ),
        SetupIssue(
            "Only the first target was tested",
            "The Test checks one target to stay fast. Targets that do not answer later are listed under the "
            "connection's last error.",
        ),
    ),
    data_you_get=(
        "Each device: name, model, serial, vendor, software, uptime, role",
        "Interfaces with state, speed, addresses, errors and aggregate members",
        "LLDP/CDP neighbors (links in Topology)",
        "ARP, MAC and routing tables (path trace)",
        "Live health: CPU, memory and interface bit rates",
    ),
    estimated_minutes=15,
)

MANIFEST = ConnectorManifest(
    connector_id=CONNECTOR_ID,
    vendor="Standard MIBs",
    product="SNMPv3 (read-only)",
    category="network_management",
    capabilities=(INVENTORY, INTERFACES, NEIGHBORS, ARP_TABLE, MAC_TABLE, ROUTES, HEALTH),
    settings=(
        SettingField(
            "targets",
            "Devices to poll",
            "text",
            required=True,
            placeholder="10.0.10.1, 10.0.20.0/28, sw1.example.com",
            help=(
                "IP addresses, host names or private ranges up to /24, separated by commas. At most 256 hosts. "
                "Use this for devices without a usable API; API connectors stay the primary source."
            ),
            address=True,
        ),
        SettingField("username", "SNMPv3 user", "text", required=True, placeholder="nodewatch-ro"),
        SettingField(
            "auth_protocol",
            "Authentication protocol",
            "select",
            default="SHA-256",
            options=AUTH_PROTOCOLS,
            help="Must match the device. MD5 is not offered.",
            security=True,
        ),
        SettingField(
            "auth_passphrase",
            "Authentication passphrase",
            "secret",
            required=True,
            help="At least 8 characters. Stored in the secure credential store (Windows Credential Manager or the macOS Keychain).",
        ),
        SettingField(
            "privacy_protocol",
            "Privacy (encryption) protocol",
            "select",
            default="AES-128",
            options=(*PRIV_PROTOCOLS, NO_PRIVACY),
            help="AES-256 follows the common (Blumenthal) key extension; pick the Cisco variant for Cisco IOS/NX-OS aes 256.",
            security=True,
        ),
        SettingField(
            "privacy_passphrase",
            "Privacy passphrase",
            "secret",
            help="At least 8 characters. Required unless privacy is off. Stored in the secure credential store (Windows Credential Manager or the macOS Keychain).",
        ),
        SettingField(
            "allow_no_privacy",
            "Allow authNoPriv — INSECURE: SNMP answers travel unencrypted",
            "boolean",
            default=False,
            help="Leave off. Only for devices that cannot encrypt SNMPv3; also choose 'None' as privacy protocol.",
            security=True,
        ),
        SettingField(
            "context",
            "SNMPv3 context (optional)",
            "text",
            placeholder="",
            help="Leave blank unless the device needs one.",
        ),
        SettingField("port", "UDP port", "number", default=161, security=True),
        SettingField("timeout", "Timeout per request (seconds)", "number", default=3),
        SettingField("retries", "Retries per request", "number", default=1),
        SettingField(
            "site_name",
            "Site name (optional)",
            "text",
            placeholder="Branch 12",
            help="Groups these devices with a site in NodeWatch.",
        ),
    ),
    description="Read-only SNMPv3 for devices without an API: system, interfaces, LLDP/CDP, ARP, MAC and routing tables, CPU/memory.",
    docs_url="https://datatracker.ietf.org/doc/html/rfc3414",
    maturity="preview",
    setup=SETUP,
)

CACHE_TTL = 60.0  # seconds a host's answer is reused (also for "did not answer")
MAX_PARALLEL = 8
HOST_BUDGET = 60.0  # one host's whole pass
TOTAL_BUDGET = 120.0  # one poll across all hosts
MIN_PASSPHRASE = 8  # RFC 3414 §11.2

# Which objects each kind of question needs. "stages" are tried in order; with first_nonempty the
# later stages are fallbacks fetched only when the earlier ones returned nothing.
GROUPS: dict[str, dict[str, Any]] = {
    "system": {"get": mibs.SYSTEM_GETS, "stages": (mibs.ENTITY_WALKS,)},
    "interfaces": {"stages": (mibs.INTERFACE_WALKS,)},
    "neighbors": {"stages": (mibs.NEIGHBOR_WALKS,)},
    "arp": {"stages": mibs.ARP_WALKS, "first_nonempty": True},
    "fdb": {"stages": mibs.FDB_WALKS, "first_nonempty": True},
    "routes": {"stages": (mibs.ROUTE_WALKS[0], mibs.ROUTE_WALKS[1] + mibs.ROUTE_WALKS[2]), "first_nonempty": True},
    "health": {"stages": (mibs.HEALTH_WALKS,)},
}
MAX_ROWS = {"routes": 20000, "fdb": 20000, "arp": 20000}


def _text(value: Any) -> str:
    return "" if value is None else str(value).strip()


def guess_role(system: dict[str, Any]) -> tuple[str, str, str]:
    """(role, vendor name, model) from sysDescr/sysName + LLDP/sysServices capabilities."""
    caps = list(dict.fromkeys(system.get("lldp_caps", []) + mibs.sys_services_caps(system.get("services"))))
    try:  # the topology engine's fingerprint table (data only; read-only import)
        from app.services.topology_fingerprints import fingerprint  # noqa: PLC0415

        fp = fingerprint(system.get("description", ""), system.get("name", ""), caps)
    except Exception:  # noqa: BLE001 - the table is optional for this connector
        fp = {"role": "unknown", "vendor_name": "", "model": ""}
    role = fp.get("role") or "unknown"
    if role == "unknown":
        if "router" in caps and "bridge" not in caps:
            role = "router"
        elif "bridge" in caps:
            role = "switch"
        elif "router" in caps:
            role = "router"
    return role, fp.get("vendor_name") or "", fp.get("model") or ""


class SnmpConnector(Connector):
    manifest = MANIFEST

    def __init__(self) -> None:
        super().__init__()
        self._lock = threading.Lock()
        self._cache: dict[tuple[str, str], tuple[float, Any]] = {}
        self._hosts_by_key: dict[str, str] = {}
        self._counters: dict[str, tuple[float, int | None, int | None]] = {}
        self.last_errors: dict[str, str] = {}
        self._inflight: set[tuple[str, str]] = set()  # (host, group) polls still running
        self._slots = threading.BoundedSemaphore(MAX_PARALLEL)  # connector-wide host concurrency
        self._generation = 0  # bumped by reset_state so late answers from old settings are not cached

    def reset_state(self) -> None:
        super().reset_state()
        with self._lock:
            self._generation += 1
            self._cache.clear()
            self._hosts_by_key.clear()
            self._counters.clear()
            self.last_errors = {}

    # ---- settings ---------------------------------------------------------------------------------
    @property
    def configured(self) -> bool:
        s = self.settings()
        return bool(_text(s.get("targets")) and _text(s.get("username")) and s.get("auth_passphrase"))

    @staticmethod
    def validate_settings(values: dict[str, Any]) -> None:
        """Called by the SDK before saving/testing the form. Raises ValueError with a readable message."""
        if _text(values.get("targets")):
            parse_targets(values.get("targets"))
        if values.get("privacy_protocol") == NO_PRIVACY and not values.get("allow_no_privacy"):
            raise ValueError("Privacy 'None' needs the insecure authNoPriv toggle; prefer AES")
        port = values.get("port")
        if port not in (None, "") and not (1 <= float(port) <= 65535 and float(port).is_integer()):
            raise ValueError("UDP port must be 1-65535")

    def _targets(self) -> list[str]:
        try:
            return parse_targets(self.settings().get("targets"))
        except ValueError as exc:
            raise IntegrationError(str(exc), code="CONFIGURATION_ERROR") from None

    def credentials(self) -> SnmpCredentials:
        s = self.settings()
        user = _text(s.get("username"))
        auth = self.secret("auth_passphrase")
        if not user or not auth:
            raise IntegrationError("SNMPv3 user and authentication passphrase are required", code="NOT_CONFIGURED")
        if len(auth) < MIN_PASSPHRASE:
            raise IntegrationError(
                "The authentication passphrase must have at least 8 characters", code="CONFIGURATION_ERROR"
            )
        auth_protocol = _text(s.get("auth_protocol")) or "SHA-256"
        if auth_protocol not in AUTH_PROTOCOLS:
            raise IntegrationError("Unsupported authentication protocol", code="CONFIGURATION_ERROR")
        priv_protocol = _text(s.get("privacy_protocol")) or "AES-128"
        priv = self.secret("privacy_passphrase")
        if priv_protocol == NO_PRIVACY:
            if not s.get("allow_no_privacy"):
                raise IntegrationError(
                    "Privacy 'None' (authNoPriv) needs the explicit insecure toggle", code="CONFIGURATION_ERROR"
                )
            priv_protocol, priv = "", ""
        elif priv_protocol not in PRIV_PROTOCOLS:
            raise IntegrationError("Unsupported privacy protocol", code="CONFIGURATION_ERROR")
        elif not priv:
            raise IntegrationError(
                "Enter the privacy passphrase (SNMPv3 authPriv is required unless the insecure authNoPriv toggle is on)",
                code="NOT_CONFIGURED",
            )
        elif len(priv) < MIN_PASSPHRASE:
            raise IntegrationError("The privacy passphrase must have at least 8 characters", code="CONFIGURATION_ERROR")
        return SnmpCredentials(
            username=user,
            auth_protocol=auth_protocol,
            auth_passphrase=auth,
            priv_protocol=priv_protocol,
            priv_passphrase=priv,
            context=_text(s.get("context")),
        )

    def snmp(self) -> Any:
        """The SNMP transport (the fixture transport in tests)."""
        if self.transport is not None:
            return self.transport
        s = self.settings()

        def number(key: str, default: float, low: float, high: float) -> float:
            try:
                return max(low, min(float(s.get(key) if s.get(key) not in (None, "") else default), high))
            except (TypeError, ValueError):
                return default

        return PysnmpTransport(
            self.credentials(),
            port=int(number("port", 161, 1, 65535)),
            timeout=number("timeout", 3, 1, 30),
            retries=int(number("retries", 1, 0, 5)),
            host_budget=HOST_BUDGET,
        )

    def _site(self) -> tuple[str, str]:
        name = _text(self.settings().get("site_name"))
        return (make_site_key(CONNECTOR_ID, name), name) if name else ("", "")

    # ---- polling ----------------------------------------------------------------------------------
    def _fetch_group(self, transport: Any, host: str, group: str, deadline: float) -> dict[str, Any]:
        """All fetches for one host and group, within ONE per-host deadline (not one per fetch)."""
        spec = GROUPS[group]
        address = resolve(host)
        data: dict[str, Any] = {}
        gets = spec.get("get", ())
        for stage_no, walks in enumerate(spec["stages"]):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise IntegrationError(
                    f"SNMP: {host} did not finish within {HOST_BUDGET:.0f} s", code="PROVIDER_UNAVAILABLE"
                )
            answer = transport.fetch(
                address,
                get=gets if stage_no == 0 else (),
                walk=walks,
                max_rows=MAX_ROWS.get(group, 10000),
                timeout=remaining,
            )
            data.update(answer)
            if spec.get("first_nonempty") and any(oid.startswith(walks[0] + ".") for oid in answer):
                break  # the preferred table answered; skip the fallbacks
        if group == "system" and not any(oid in data for oid in gets):
            raise IntegrationError(f"SNMP: {host} answered without the system group (check the SNMPv3 view)")
        return data

    def _poll_one(self, transport: Any, host: str, group: str, poll_deadline: float, generation: int) -> Any:
        """Worker: one host. Holds a slot of the connector-wide limit, caches its own result (also when
        the poll that started it has already given up) and always clears the in-flight mark."""
        try:
            while not self._slots.acquire(timeout=0.5):
                if time.monotonic() >= poll_deadline:
                    raise _NotStarted()
            try:
                if time.monotonic() >= poll_deadline:
                    raise _NotStarted()
                try:
                    value: Any = self._fetch_group(transport, host, group, time.monotonic() + HOST_BUDGET)
                except IntegrationError as exc:
                    if exc.code == "DEPENDENCY_MISSING":
                        raise
                    value = self.redact(exc)
                except ValueError as exc:  # unresolvable / unpollable host name
                    value = self.redact(exc)
                except Exception as exc:  # noqa: BLE001 - one host must not hide the others
                    value = type(exc).__name__
                with self._lock:
                    if generation == self._generation:  # settings unchanged since this poll started
                        self._cache[(host, group)] = (time.monotonic(), value)
                return value
            finally:
                self._slots.release()
        finally:
            with self._lock:
                self._inflight.discard((host, group))

    def _poll(self, hosts: list[str], group: str) -> dict[str, dict[str, Any]]:
        """{host: data} for the hosts that answered; per-host failures go to ``last_errors``.

        At most MAX_PARALLEL hosts are polled at once across overlapping polls; a host whose previous
        poll is still running (it outlived the 120 s limit) is reported as "still polling", not polled
        again.
        """
        now = time.monotonic()
        results: dict[str, dict[str, Any]] = {}
        errors: dict[str, str] = {}
        todo = []
        with self._lock:
            for host in hosts:
                cached = self._cache.get((host, group))
                if cached and now - cached[0] < CACHE_TTL:
                    if isinstance(cached[1], dict):
                        results[host] = cached[1]
                    else:
                        errors[host] = str(cached[1])
                elif (host, group) in self._inflight:
                    errors[host] = "still polling (the previous poll of this target has not finished)"
                else:
                    self._inflight.add((host, group))
                    todo.append(host)
        if todo:
            try:
                transport = self.snmp()
            except Exception:
                with self._lock:
                    self._inflight.difference_update((h, group) for h in todo)
                raise
            deadline = time.monotonic() + TOTAL_BUDGET
            generation = self._generation
            futures: dict[concurrent.futures.Future, str] = {}
            pool = concurrent.futures.ThreadPoolExecutor(
                max_workers=min(MAX_PARALLEL, len(todo)), thread_name_prefix="nodewatch-snmp"
            )
            try:
                for host in todo:
                    futures[pool.submit(self._poll_one, transport, host, group, deadline, generation)] = host
                done, pending = concurrent.futures.wait(futures, timeout=TOTAL_BUDGET)
                for future in done:
                    host = futures[future]
                    try:
                        value = future.result()
                    except _NotStarted:
                        errors[host] = f"not polled within the {TOTAL_BUDGET:.0f} s limit"
                        continue
                    if isinstance(value, dict):
                        results[host] = value
                    else:
                        errors[host] = str(value)
                for future in pending:
                    errors[futures[future]] = f"not polled within the {TOTAL_BUDGET:.0f} s limit"
            finally:
                pool.shutdown(wait=False, cancel_futures=True)
                with self._lock:  # cancelled before they started: never ran, so not in flight
                    for future, host in futures.items():
                        if future.cancelled():
                            self._inflight.discard((host, group))
        with self._lock:
            for host in hosts:
                if host in errors:
                    self.last_errors[host] = errors[host]
                elif host in results:
                    self.last_errors.pop(host, None)
        if hosts and not results:
            first = next(iter(errors.values()), "no answer")
            more = f" (and {len(errors) - 1} more)" if len(errors) > 1 else ""
            raise IntegrationError(f"SNMP: no target answered — {first}{more}", code="PROVIDER_UNAVAILABLE")
        return results

    def _run(self, fn: Callable[[], Any], what: str) -> Any:
        result = self.call(fn, what)
        if self.last_errors:
            failed = sorted(self.last_errors.items())
            summary = "; ".join(f"{h}: {e}" for h, e in failed[:3])
            self._health.last_error = self.redact(f"{len(failed)} target(s) did not answer — {summary}")[:500]
        return result

    # ---- identity ---------------------------------------------------------------------------------
    def _identity(self, host: str, data: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        """Device key: LLDP chassis MAC, else chassis serial, else bridge base MAC, else the target."""
        system = mibs.parse_system(data)
        if system["lldp_mac"]:
            key = make_device_key(mac=system["lldp_mac"])
        elif system["serial"]:
            key = make_device_key(serial=system["serial"])
        elif system["bridge_mac"]:
            key = make_device_key(mac=system["bridge_mac"])
        else:
            key = make_device_key(source=CONNECTOR_ID, native_id=host)
        return key, system

    def _systems(self) -> dict[str, tuple[str, dict[str, Any]]]:
        """{host: (device key, system facts)} for every answering target, de-duplicated by key."""
        polled = self._poll(self._targets(), "system")
        out: dict[str, tuple[str, dict[str, Any]]] = {}
        seen: set[str] = set()
        for host in self._targets():
            if host not in polled:
                continue
            key, system = self._identity(host, polled[host])
            if key in seen:
                continue  # the same box reached through two addresses
            seen.add(key)
            out[host] = (key, system)
        with self._lock:
            self._hosts_by_key.update({key: host for host, (key, _s) in out.items()})
        return out

    def _host_for(self, device_key: str) -> str:
        with self._lock:
            host = self._hosts_by_key.get(device_key)
        if host:
            return host
        for h, (key, _s) in self._systems().items():
            if key == device_key:
                return h
        return ""

    def _hosts(self, device_key: str | None) -> list[tuple[str, str]]:
        """[(host, device key)] for one device or all answering devices."""
        if device_key:
            host = self._host_for(device_key)
            return [(host, device_key)] if host else []
        return [(h, key) for h, (key, _s) in self._systems().items()]

    def _names(self, host: str) -> dict[str, str]:
        data = self._poll([host], "interfaces").get(host, {})
        return mibs.if_names(data)

    def _device(self, host: str, key: str, system: dict[str, Any]) -> Device:
        skey, sname = self._site()
        role, fp_vendor, fp_model = guess_role(system)
        mgmt = host if _is_ip(host) else ""
        vendor_name = system["manufacturer"] or mibs.enterprise_vendor(system["object_id"]) or fp_vendor
        if vendor_name == "Example (documentation)":
            vendor_name = system["manufacturer"] or fp_vendor or vendor_name
        return Device(
            key=key,
            source=CONNECTOR_ID,
            name=system["name"] or host,
            role=role,
            native_id=host,
            site_key=skey,
            site_name=sname,
            vendor_name=vendor_name,
            model=system["model"] or fp_model,
            serial=system["serial"],
            mac=system["lldp_mac"] or system["bridge_mac"],
            mgmt_ip=mgmt,
            os_version=system["software"] or mibs.os_version_from_descr(system["description"]),
            status="up",  # it answered SNMP just now
            uptime_s=system["uptime_s"],
            members=system["members"],
            vendor={
                k: v
                for k, v in {
                    "snmp_target": host,
                    "sys_object_id": system["object_id"],
                    "sys_descr": system["description"][:300],
                    "location": system["location"],
                }.items()
                if v
            },
        )

    # ---- INVENTORY --------------------------------------------------------------------------------
    def list_sites(self) -> list[Site]:
        key, name = self._site()
        return [Site(key=key, source=CONNECTOR_ID, name=name, native_id=name)] if key else []

    def list_devices(self, site_key: str | None = None) -> list[Device]:
        skey, _ = self._site()
        if site_key and site_key != skey:
            return []
        systems = self._run(self._systems, "poll SNMP targets")
        return [self._device(host, key, system) for host, (key, system) in systems.items()]

    # ---- INTERFACES -------------------------------------------------------------------------------
    def _interfaces(self, host: str, key: str) -> list[Interface]:
        data = self._poll([host], "interfaces").get(host, {})
        rows = mibs.parse_interfaces(data)
        names = [r["name"] for r in rows]
        out = []
        for r in rows:
            unique = names.count(r["name"]) == 1
            out.append(
                Interface(
                    key=stable_key(key, r["name"] if unique else f"{r['name']}#{r['index']}"),
                    source=CONNECTOR_ID,
                    device_key=key,
                    name=r["name"],
                    kind=r["kind"],
                    role="mgmt" if r["kind"] == "mgmt" else "",
                    admin_up=r["admin_up"],
                    oper_up=r["oper_up"],
                    speed_mbps=r["speed_mbps"] or None,
                    mac=r["mac"],
                    ips=r["ips"],
                    lag_parent=r["lag_parent"],
                    description=r["alias"],
                    rx_errors=r["rx_errors"],
                    tx_errors=r["tx_errors"],
                    vendor={
                        "ifIndex": int(r["index"]) if r["index"].isdigit() else r["index"],
                        "if_type": r["if_type"],
                    },
                )
            )
        return out

    def list_interfaces(self, device_key: str) -> list[Interface]:
        host = self._run(lambda: self._host_for(device_key), "find SNMP device") if device_key else ""
        if not host:
            return []
        return self._run(lambda: self._interfaces(host, device_key), "read interfaces")

    # ---- NEIGHBORS --------------------------------------------------------------------------------
    def list_neighbors(self, site_key: str | None = None) -> list[Neighbor]:
        skey, _ = self._site()
        if site_key and site_key != skey:
            return []

        def collect() -> list[Neighbor]:
            out = []
            hosts = self._hosts(None)
            data = self._poll([h for h, _k in hosts], "neighbors")
            for host, key in hosts:
                if host not in data:
                    continue
                ifaces = {i.name: i for i in self._interfaces(host, key)}
                for n in mibs.parse_neighbors(data[host], self._names(host)):
                    local = ifaces.get(n["local_port"])
                    out.append(
                        Neighbor(
                            source=CONNECTOR_ID,
                            device_key=key,
                            local_interface=n["local_port"],
                            remote_name=n["remote_name"],
                            remote_interface=n["remote_port"],
                            remote_mac=n["remote_mac"],
                            remote_mgmt_ip=n["remote_mgmt_ip"],
                            remote_description=n["remote_description"],
                            remote_capabilities=n["remote_caps"],
                            protocol=n["protocol"],
                            local_lag=local.lag_parent if local else "",
                            local_up=local.oper_up if local else None,
                            speed_mbps=local.speed_mbps if local else None,
                        )
                    )
            return out

        return self._run(collect, "read LLDP/CDP neighbors")

    # ---- ARP / MAC / routes -----------------------------------------------------------------------
    def _table(self, device_key: str | None, group: str, build: Callable[[str, str, dict, dict], list]) -> list:
        def collect() -> list:
            hosts = self._hosts(device_key)
            if not hosts:
                return []
            data = self._poll([h for h, _k in hosts], group)
            out = []
            for host, key in hosts:
                if host in data:
                    out.extend(build(host, key, data[host], self._names(host)))
            return out

        return self._run(collect, f"read {group} table")

    def list_arp(self, device_key: str | None = None) -> list[L3Entry]:
        return self._table(
            device_key,
            "arp",
            lambda host, key, data, names: [
                L3Entry(source=CONNECTOR_ID, device_key=key, ip=r["ip"], mac=r["mac"], interface=r["interface"])
                for r in mibs.parse_arp(data, names)
            ],
        )

    def list_mac_table(self, device_key: str) -> list[L2Entry]:
        if not device_key:
            return []
        return self._table(
            device_key,
            "fdb",
            lambda host, key, data, names: [
                L2Entry(source=CONNECTOR_ID, device_key=key, mac=r["mac"], interface=r["interface"], vlan=r["vlan"])
                for r in mibs.parse_fdb(data, names)
            ],
        )

    def list_routes(self, device_key: str) -> list[Route]:
        if not device_key:
            return []
        return self._table(
            device_key,
            "routes",
            lambda host, key, data, names: [
                Route(
                    source=CONNECTOR_ID,
                    device_key=key,
                    prefix=r["prefix"],
                    next_hop=r["next_hop"],
                    interface=r["interface"],
                    protocol="blackhole" if r["blackhole"] else r["protocol"],
                )
                for r in mibs.parse_routes(data, names)
            ],
        )

    # ---- HEALTH -----------------------------------------------------------------------------------
    def list_health(self, site_key: str | None = None) -> dict[str, list[Any]]:
        skey, _ = self._site()
        if site_key and site_key != skey:
            return {"devices": [], "interfaces": [], "tunnels": []}

        def collect() -> dict[str, list[Any]]:
            systems = self._systems()
            health = self._poll(list(systems), "health")
            devices, interfaces = [], []
            for host, (key, system) in systems.items():
                device = self._device(host, key, system)
                facts = mibs.parse_health(health.get(host, {}))
                device.cpu_pct, device.memory_pct = facts["cpu_pct"], facts["memory_pct"]
                devices.append(device)
                interfaces.extend(self._rated(host, key))
            return {"devices": devices, "interfaces": interfaces, "tunnels": []}

        return self._run(collect, "read SNMP health")

    def _rated(self, host: str, key: str) -> list[Interface]:
        """Interfaces with errors, plus rx/tx bps when an earlier sample of the HC counters exists."""
        data = self._poll([host], "interfaces").get(host, {})
        sampled_at = self._sample_time(host)
        rows = {r["name"]: r for r in mibs.parse_interfaces(data)}
        out = []
        for iface in self._interfaces(host, key):
            row = rows.get(iface.name) or {}
            counter_key = f"{key}|{iface.key}"
            previous = self._counters.get(counter_key)
            hc_in, hc_out = row.get("hc_in"), row.get("hc_out")
            if previous and sampled_at > previous[0]:
                elapsed = sampled_at - previous[0]
                iface.rx_bps = _rate(previous[1], hc_in, elapsed)
                iface.tx_bps = _rate(previous[2], hc_out, elapsed)
                busiest = max((v for v in (iface.rx_bps, iface.tx_bps) if v is not None), default=None)
                if busiest is not None and iface.speed_mbps:
                    iface.utilization_pct = round(min(100.0, 100.0 * busiest / (iface.speed_mbps * 1e6)), 1)
            if not previous or sampled_at > previous[0]:
                with self._lock:
                    self._counters[counter_key] = (sampled_at, hc_in, hc_out)
            out.append(iface)
        return out

    def _sample_time(self, host: str) -> float:
        with self._lock:
            cached = self._cache.get((host, "interfaces"))
        return cached[0] if cached else time.monotonic()

    # ---- capability probe (Settings › Connections › Test; see probe.py) ------------------------------
    def probe_plan(self) -> list[Any]:
        from app.integrations.connectors.snmp.probe import plan

        return plan(self)

    # ---- connection test --------------------------------------------------------------------------
    def test_connection(self) -> dict[str, Any]:
        if not self.configured:
            return {
                "ok": False,
                "provider": CONNECTOR_ID,
                "configured": False,
                "detail": "Enter the devices to poll, the SNMPv3 user and its passphrases.",
            }

        def probe() -> dict[str, Any]:
            hosts = self._targets()
            host = hosts[0]
            data = self.snmp().fetch(resolve(host), get=mibs.SYSTEM_GETS)
            system = mibs.parse_system(data)
            if not system["name"] and not system["description"]:
                raise IntegrationError(f"SNMP: {host} answered without the system group (check the SNMPv3 view)")
            first_line = system["description"].splitlines()[0][:80] if system["description"] else ""
            more = f" · {len(hosts) - 1} more target(s) not tested" if len(hosts) > 1 else ""
            return {
                "ok": True,
                "provider": CONNECTOR_ID,
                "configured": True,
                "detail": " · ".join(x for x in (system["name"] or host, first_line) if x) + more,
            }

        def guarded() -> dict[str, Any]:
            try:
                return probe()
            except ValueError as exc:  # unresolvable/unpollable host name
                raise IntegrationError(f"SNMP: {exc}", code="CONFIGURATION_ERROR") from None

        return self.call(guarded, "test SNMP connection")


class _NotStarted(Exception):
    """A queued host poll that never started before the poll's deadline."""


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _rate(before: int | None, after: int | None, elapsed: float) -> float | None:
    if before is None or after is None or elapsed <= 0:
        return None
    delta = after - before
    if delta < 0:
        delta += 2**64  # 64-bit counter wrapped (a reset looks the same; capped below)
        if delta > 2**63:
            return None
    return round(delta * 8 / elapsed, 1)


CONNECTOR = SnmpConnector
