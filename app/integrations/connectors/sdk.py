"""NodeWatch connector SDK (v0.10.16): the one place a vendor plugs in.

A connector is a package under ``app/integrations/connectors/<connector_id>/`` that exposes:

* ``MANIFEST`` — a :class:`ConnectorManifest`: who it is, what it can do, and which settings fields the
  user fills in (the Settings page draws the connection form from this; secrets go to the secure
  credential store automatically: Windows Credential Manager or the macOS Keychain).
* ``CONNECTOR`` — a :class:`Connector` subclass implementing the capability methods it declares
  (see :mod:`app.integrations.contracts`).

Nothing else in NodeWatch needs to change: connectors are discovered at start-up, show up under
Settings › Connections, and every feature that uses a capability starts using the new source.

Contract tests in ``tests/test_connectors_contract.py`` run against every discovered connector.
"""

from __future__ import annotations

import contextvars
import functools
import importlib
import inspect
import json
import logging
import pkgutil
import re
import socket
import ssl
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlparse
from urllib.request import HTTPRedirectHandler, Request

from app.core.config import DATA_ROOT
from app.core.file_utils import locked_json_update
from app.integrations import api_timing
from app.integrations.base import IntegrationError, ProviderAdapter, ProviderDescriptor, ProviderHealth, refused_text, registry
from app.core.security import redact_text
from app.core.version import APP_VERSION
from app.integrations.contracts import ALL_CAPABILITIES, CAPABILITY_LABELS, CAPABILITY_PROTOCOLS
from app.integrations.domain import _Record, normalize_mac, stable_key
from app.integrations.secrets import SecretStore

log = logging.getLogger("nodewatch.connectors")

CONNECTORS_FILE = DATA_ROOT / "connectors.json"
SECRETS = SecretStore(DATA_ROOT)
CATEGORIES = (
    "network_management",  # cloud/on-prem controller for switches/APs (Mist, Meraki, Catalyst Center)
    "firewall",  # Palo Alto, FortiGate, Check Point
    "sdwan",  # Silver Peak/Aruba EdgeConnect, Fortinet SD-WAN, Cisco SD-WAN
    "logging",  # log lakes: Strata Logging Service, FortiAnalyzer
    "siem",  # outbound destinations
    "other",
)
CATEGORY_LABELS = {
    "network_management": "Network management",
    "firewall": "Firewall",
    "sdwan": "SD-WAN",
    "logging": "Logging",
    "siem": "SIEM",
    "other": "Other",
}
# v0.10.18: where each kind of data shows up in NodeWatch (Add connection › Done). Tool ids are the
# app/core/registry.py ids that openTool() understands.
CAPABILITY_FEATURES: dict[str, tuple[tuple[str, str, str], ...]] = {
    "inventory": (("topology", "Topology", "devices and sites on the map"),),
    "interfaces": (("topology", "Topology", "link state and the path trace"),),
    "alerts": (
        ("dashboard", "Command Center", "Requires Attention"),
        ("topology", "Topology", "health colours"),
    ),
    "events": (("dashboard", "Command Center", "recent device events"),),
    "topology.neighbors": (("topology", "Topology", "cabling between devices (LLDP/CDP)"),),
    "topology.mac_table": (("topology", "Topology", "path trace: where a MAC is attached"),),
    "topology.arp": (("topology", "Topology", "path trace: IP → MAC"),),
    "topology.routes": (("topology", "Topology", "path trace: next hops"),),
    "topology.tunnels": (("topology", "Topology", "VPN / SD-WAN tunnels and their state"),),
    "topology.endpoint_locate": (("topology", "Topology", "path trace: find an endpoint"),),
    "security.policy_lookup": (("topology", "Topology", "path trace: would the firewall allow it"),),
    "health.metrics": (("topology", "Topology", "live health: CPU, memory, latency, loss"),),
    "traffic.logs": (("detective", "Device Finder", "Traffic & Sessions"),),
    "wan.circuits": (("topology", "Topology", "internet circuits: carrier, bandwidth, quality"),),
    "audit.log": (("history", "Activity Log", "who changed what, when"),),
    "directory.admins": (("history", "Activity Log", "names, roles and sign-in details of who made a change"),),
    "security.events": (("security", "Security Operations", "threats, attackers, countries and incidents"),),
    "security.exposures": (("security", "Security Operations", "vulnerabilities on your devices"),),
    "security.incidents": (("security", "Security Operations", "incidents your security platform raised"),),
}
FIELD_TYPES = ("text", "url", "secret", "number", "boolean", "select")
MATURITY_LEVELS = ("stable", "preview")


@dataclass(frozen=True)
class SettingField:
    """One input on the connector's connection form."""

    key: str
    label: str
    type: str = "text"
    required: bool = False
    placeholder: str = ""
    help: str = ""
    default: Any = None
    options: tuple[str, ...] = ()  # for "select"
    # v0.10.17: a non-URL field naming where credentials are sent (e.g. SNMP targets). Like a URL
    # field, changing it in the test form means saved secrets are not reused until typed again.
    address: bool = False
    # v0.10.18: a setting that protects where/how the secret travels (TLS verification, CA file, port,
    # SNMPv3 protocols …). Changing it in the test form means saved secrets are not reused until typed
    # again — like an address change. Keys in SECURITY_KEYS are treated this way even when unflagged.
    security: bool = False
    # v0.10.19: for "url" fields whose API always lives at the server root (Orchestrator, Panorama,
    # FortiGate): a pasted page address such as https://host/9.4/webclient/html/swagger/index.html#/
    # is reduced to https://host (path, query and fragment dropped) instead of being rejected.
    origin_only: bool = False


def url_origin(text: str) -> str:
    """https://host[:port] of a URL (no path, query or fragment); '' when it has no host."""
    parsed = urlparse(str(text or "").strip())
    if not parsed.hostname:
        return ""
    port = f":{parsed.port}" if parsed.port else ""
    return f"{parsed.scheme}://{parsed.hostname}{port}"


SECURITY_KEYS = frozenset({"verify_tls", "ca_file", "port"})


def _security_field(f: "SettingField") -> bool:
    return f.security or f.key in SECURITY_KEYS


def _norm(f: "SettingField", value: Any) -> Any:
    """Comparable form of a setting value (so '20' and 20.0, or ' x ' and 'x', compare equal)."""
    if value is None or value == "":
        value = f.default
    if f.type == "boolean":
        return bool(value)
    if f.type == "number":
        try:
            return float(value)
        except (TypeError, ValueError):
            return None
    return str(value if value is not None else "").strip()


@dataclass(frozen=True)
class SetupStep:
    """One numbered step of a connector's "Before you start" guide (v0.10.18)."""

    title: str
    detail: str
    link: str = ""  # optional https:// page with the vendor's own instructions
    copy: str = ""  # optional value the user may copy (a key name, a command, a menu path)


@dataclass(frozen=True)
class SetupIssue:
    """A known problem and its fix, shown under "Troubleshooting"."""

    symptom: str
    fix: str


@dataclass(frozen=True)
class ConnectorSetup:
    """Setup guide drawn by Settings › Connections › Add connection (v0.10.18).

    Plain words for the person connecting the product: what they get, what they need, how to create a
    least-privilege account or key, what the Test checks and what to do when it fails.
    """

    summary: str  # one line: what you get
    prerequisites: tuple[str, ...] = ()
    steps: tuple[SetupStep, ...] = ()
    permissions: str = ""  # the least-privilege role/key to create
    verify: str = ""  # what "Test" checks
    troubleshooting: tuple[SetupIssue, ...] = ()
    data_you_get: tuple[str, ...] = ()  # capabilities in plain words
    estimated_minutes: int = 10
    uncertain: tuple[str, ...] = ()  # not yet confirmed on a live system — shown labelled as such

    def problems(self) -> list[str]:
        """Structural checks (also run by ConnectorManifest.validate when a guide is present)."""
        errors = []
        summary = (self.summary or "").strip()
        if not summary or "\n" in summary or len(summary) > 160:
            errors.append("setup.summary must be one line of at most 160 characters")
        if not self.steps:
            errors.append("setup.steps needs at least one step")
        for i, step in enumerate(self.steps, 1):
            if not isinstance(step, SetupStep) or not step.title.strip() or not step.detail.strip():
                errors.append(f"setup.steps[{i}] needs a title and a detail")
            elif step.link and not step.link.startswith("https://"):
                errors.append(f"setup.steps[{i}].link must be an https:// URL")
        if not (self.permissions or "").strip():
            errors.append("setup.permissions must describe the least-privilege account or key")
        if not (self.verify or "").strip():
            errors.append("setup.verify must say what the Test checks")
        if not self.data_you_get or not all(str(x).strip() for x in self.data_you_get):
            errors.append("setup.data_you_get must list what NodeWatch reads, in plain words")
        if not all(isinstance(t, SetupIssue) and t.symptom.strip() and t.fix.strip() for t in self.troubleshooting):
            errors.append("setup.troubleshooting entries need a symptom and a fix")
        if not all(str(p).strip() for p in self.prerequisites):
            errors.append("setup.prerequisites must not contain blank entries")
        if not isinstance(self.estimated_minutes, int) or not 1 <= self.estimated_minutes <= 120:
            errors.append("setup.estimated_minutes must be 1-120")
        return errors


@dataclass(frozen=True)
class ConnectorManifest:
    connector_id: str  # "mist", "fortigate", "silverpeak_orchestrator"
    vendor: str  # "Juniper", "Fortinet", "HPE Aruba (Silver Peak)"
    product: str  # "Mist Cloud", "FortiGate (FortiOS REST API)"
    category: str
    capabilities: tuple[str, ...]
    settings: tuple[SettingField, ...] = ()
    description: str = ""
    docs_url: str = ""
    maturity: str = "stable"  # stable | preview (built from public docs, not yet validated on a live system)
    version: str = "1"
    managed_elsewhere: bool = False  # settings live in an older dedicated page (Mist, Palo Alto)
    settings_location: str = ""  # managed_elsewhere only: the Settings section that configures it
    setup: ConnectorSetup | None = None  # v0.10.18: the "Add connection" guide (required by the contract tests)

    def validate(self) -> list[str]:
        errors = []
        if not self.connector_id or not self.connector_id.replace("_", "").isalnum():
            errors.append("connector_id must be letters, digits and underscores")
        if self.category not in CATEGORIES:
            errors.append(f"unknown category {self.category!r}")
        unknown = [c for c in self.capabilities if c not in ALL_CAPABILITIES]
        if unknown:
            errors.append(f"unknown capabilities {unknown}")
        for f in self.settings:
            if f.type not in FIELD_TYPES:
                errors.append(f"setting {f.key}: unknown type {f.type!r}")
        keys = [f.key for f in self.settings]
        if len(keys) != len(set(keys)) or "enabled" in keys:
            errors.append("setting keys must be unique and must not be 'enabled'")
        if self.maturity not in MATURITY_LEVELS:
            errors.append("maturity must be stable or preview")
        if not self.vendor or not self.product:
            errors.append("vendor and product are required")
        if self.setup is not None:
            if not isinstance(self.setup, ConnectorSetup):
                errors.append("setup must be a ConnectorSetup")
            else:
                errors.extend(self.setup.problems())
        return errors

    def setup_problems(self) -> list[str]:
        """What is missing from the setup guide (the contract tests require a complete one).

        A connector without a guide still loads (third-party packages keep working); the Add connection
        wizard then shows the form only. ``stable`` connectors must not carry template placeholders.
        """
        if self.setup is None:
            return ["MANIFEST.setup is missing (see _template/__init__.py)"]
        problems = [p for p in self.validate() if p.startswith("setup")]
        if self.maturity == "stable":
            blob = json.dumps(asdict(self.setup))
            if "TODO" in blob:
                problems.append("a stable connector's setup guide must not contain TODO placeholders")
        return problems

    def public_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["settings"] = [asdict(s) for s in self.settings]
        return d


def _secret_ref(connection_id: str, key: str) -> str:
    """Credential-store name; the first connection's id is the connector id, so its name never changed."""
    return f"NodeWatch:Connector:{connection_id}:{key}"


# Record methods whose results are stamped with the connection that produced them (v0.10.47, N1).
_RECORD_METHOD_PREFIXES = ("list_", "search_", "get_", "locate_", "lookup_", "query_")


def _stamp(record: Any, connection_id: str, tenant: Callable[[], str]) -> None:
    if not isinstance(record, _Record):
        return
    if hasattr(record, "connection_id") and not record.connection_id:
        record.connection_id = connection_id
    if hasattr(record, "tenant_id") and not record.tenant_id:
        record.tenant_id = tenant()


def _stamp_records_of(connector: "Connector") -> None:
    """Wrap the instance's record-returning methods so every record carries connection_id (and tenant_id).

    Only empty fields are filled, nothing else in a record changes, and non-record results pass through.
    The tenant is asked once per result (settings can change while NodeWatch runs)."""

    def tenant_once() -> Callable[[], str]:
        cache: dict[str, str] = {}

        def tenant() -> str:
            if "t" not in cache:
                try:
                    cache["t"] = str(connector.tenant_id() or "")
                except Exception:  # noqa: BLE001 - a tenant label must never fail a read
                    cache["t"] = ""
            return cache["t"]

        return tenant

    for name in dir(type(connector)):
        if not name.startswith(_RECORD_METHOD_PREFIXES):
            continue
        attr = getattr(type(connector), name, None)
        if not inspect.isfunction(attr):
            continue
        bound = getattr(connector, name)

        def wrapped(*args: Any, __fn: Callable[..., Any] = bound, **kwargs: Any) -> Any:
            result = __fn(*args, **kwargs)
            cid, tenant = connector.connection_id, tenant_once()
            if isinstance(result, _Record):
                _stamp(result, cid, tenant)
            elif isinstance(result, (list, tuple)):
                for item in result:
                    _stamp(item, cid, tenant)
            return result

        functools.update_wrapper(wrapped, bound)
        setattr(connector, name, wrapped)


# --------------------------------------------------------------------------- capability probes (v0.10.18)

PROBE_BUDGET_S = 40.0  # v0.10.23 (was 20 s): the whole Test (connection check + every probe) finishes within this
PROBE_HTTP_TIMEOUT_S = (
    15.0  # v0.10.23 (was 8 s; a slow DNS answer alone took 12 s): one probe request never waits longer than this
)
PROBE_WORKERS = 4
PROBE_STATUSES = ("ok", "denied", "empty", "unsupported", "error", "timeout", "skipped")


class ProbeSkipped(Exception):
    """Raised inside a probe that cannot run (no device to read from, a prerequisite failed …)."""


@dataclass(frozen=True)
class Probe:
    """One cheap, read-only check of a claimed capability (``run(ctx)`` → count, text or (count, text))."""

    capability: str
    check: str  # what is read, in plain words: "List appliances"
    run: Callable[["ProbeContext"], Any]
    noun: str = ""  # what the count counts: "appliances"
    needs: str = ""  # the permission that allows this read (shown when it is refused)
    optional: bool = False  # enrichment: a refusal leaves details empty but the capability works
    sample: bool = True  # include the count in the "Found" summary (False for one-device reads)


class ProbeContext:
    """Shared, lock-protected memo for probes running in parallel (e.g. the device list)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._locks: dict[str, threading.Lock] = {}
        self._values: dict[str, tuple[bool, Any]] = {}

    def once(self, name: str, fn: Callable[[], Any], what: str = "") -> Any:
        """Run ``fn`` once; later callers reuse its answer. When it failed, the first caller gets the
        real error and every later caller a ProbeSkipped (the failure is reported once, not N times)."""
        with self._lock:
            lock = self._locks.setdefault(name, threading.Lock())
        with lock:
            if name in self._values:
                ok, value = self._values[name]
                if ok:
                    return value
                raise ProbeSkipped(f"needs {what or name}, which could not be read")
            try:
                value = fn()
            except Exception:
                self._values[name] = (False, None)
                raise
            self._values[name] = (True, value)
            return value


class ProbeEmpty(Exception):
    """Raised by a probe whose read was answered with nothing where something was expected (e.g. an
    SNMPv3 view that excludes a table): reported as "empty" — possibly a permission/view limit."""


def _probe_status(exc: BaseException) -> str:
    if isinstance(exc, ProbeSkipped):
        return "skipped"
    if isinstance(exc, ProbeEmpty):
        return "empty"
    if isinstance(exc, IntegrationError):
        if exc.code in ("PERMISSION_DENIED", "AUTHENTICATION_FAILED") or exc.status_code in (401, 403):
            return "denied"
        if exc.code in ("NOT_FOUND", "UNSUPPORTED") or exc.status_code in (404, 405, 501):
            return "unsupported"
        if "timed out" in str(exc).lower() or "timeout" in str(exc).lower():
            return "timeout"
    if isinstance(exc, TimeoutError):
        return "timeout"
    return "error"


def _run_probe(connector: "Connector", probe: Probe, ctx: ProbeContext) -> dict[str, Any]:
    started = time.monotonic()
    row: dict[str, Any] = {
        "capability": probe.capability,
        "label": CAPABILITY_LABELS.get(probe.capability, probe.capability),
        "check": probe.check,
        "noun": probe.noun,
        "needs": probe.needs,
        "optional": probe.optional,
        "sample": probe.sample,
        "count": None,
        "detail": "",
    }
    try:
        value = probe.run(ctx)
        count: Any = None
        text = ""
        if isinstance(value, str):
            text = value
        elif isinstance(value, tuple):
            count, text = value[0], str(value[1] or "") if len(value) > 1 else ""
        else:
            count = value
        if isinstance(count, bool) or not isinstance(count, (int, float)):
            count = None
        row["count"] = int(count) if count is not None else None
        row["status"] = "ok"  # an empty answer is still a permitted read; the count says so
        default = f"{row['count']} {probe.noun}".strip() if row["count"] is not None else "Readable"
        row["detail"] = connector.redact(text or default)[:300]
    except Exception as exc:  # noqa: BLE001 - every failure becomes a row, never a crash
        row["status"] = _probe_status(exc)
        known = isinstance(exc, (IntegrationError, ProbeSkipped, ProbeEmpty))
        row["detail"] = connector.redact(exc)[:300] if known else type(exc).__name__
    row["ms"] = int((time.monotonic() - started) * 1000)
    return row


def _not_exercised(_ctx: ProbeContext) -> Any:
    raise ProbeSkipped(
        "Not run by the test: it is an on-demand query (or a write) that uses the same access as the reads"
    )


_STATUS_RANK = {"denied": 6, "error": 5, "timeout": 4, "empty": 3, "unsupported": 2, "skipped": 1, "ok": 0}


def run_probes(
    connector: "Connector", *, budget_s: float = PROBE_BUDGET_S, futures_out: list | None = None
) -> dict[str, Any]:
    """Run ``connector.probe_plan()`` in parallel within ``budget_s``: per-capability ok/denied/error.

    Read-only by construction (probes call the connector's read methods only) and bounded: whatever
    has not finished when the budget runs out is reported as "timeout" and not waited for.
    """
    started = time.monotonic()
    budget_s = max(1.0, min(float(budget_s), 60.0))
    try:
        plan = [p for p in connector.probe_plan() if isinstance(p, Probe)]
    except Exception as exc:  # noqa: BLE001
        return {"checks": [], "capabilities": [], "error": connector.redact(exc)[:300], "elapsed_ms": 0}
    ctx = ProbeContext()
    rows: list[dict[str, Any] | None] = [None] * len(plan)
    if plan:
        from concurrent.futures import ThreadPoolExecutor, wait

        pool = ThreadPoolExecutor(max_workers=min(PROBE_WORKERS, len(plan)), thread_name_prefix="nw-probe")
        try:
            futures = {pool.submit(_run_probe, connector, p, ctx): i for i, p in enumerate(plan)}
            if futures_out is not None:
                futures_out.extend(futures)
            done, _pending = wait(futures, timeout=budget_s)
            for future, i in futures.items():
                if future in done:
                    rows[i] = future.result()
        finally:
            pool.shutdown(wait=False, cancel_futures=True)
    checks: list[dict[str, Any]] = []
    for i, p in enumerate(plan):
        row = rows[i]
        if row is None:
            row = {
                "capability": p.capability,
                "label": CAPABILITY_LABELS.get(p.capability, p.capability),
                "check": p.check,
                "noun": p.noun,
                "needs": p.needs,
                "optional": p.optional,
                "sample": p.sample,
                "count": None,
                "status": "timeout",
                "detail": f"Not finished within the {budget_s:.0f} s test limit",
                "ms": int(budget_s * 1000),
            }
        checks.append(row)
    capabilities = []
    for cap in connector.manifest.capabilities:
        mine = [c for c in checks if c["capability"] == cap]
        required = [c for c in mine if not c["optional"]] or mine
        if not mine:
            status, detail = "skipped", "Not checked by the test"
        else:
            worst = max(required, key=lambda c: _STATUS_RANK.get(c["status"], 5))
            status = worst["status"]
            extras = [c for c in mine if c["optional"] and c["status"] != "ok"]
            if status == "ok" and extras:
                status = "partial"
            detail = (
                worst["detail"]
                if status not in ("ok", "partial")
                else "; ".join(c["detail"] for c in required if c["status"] == "ok" and c["detail"])
            )
            if status == "partial":
                detail += "".join(f" · {c['check']}: {c['status']}" for c in extras)
        capabilities.append(
            {"capability": cap, "label": CAPABILITY_LABELS.get(cap, cap), "status": status, "detail": detail}
        )
    blocked = [c for c in checks if c["status"] in ("denied", "empty")]
    if blocked:

        def what(c: dict[str, Any]) -> str:
            # optional checks are details of a capability that otherwise works: name the detail itself
            return c["check"].split(" (")[0] if c["optional"] else c["label"]

        labels = list(dict.fromkeys(what(c) for c in blocked))
        items: dict[str, list[str]] = {}
        for c in blocked:
            items.setdefault(c["needs"] or "a broader read permission", [])
            if what(c) not in items[c["needs"] or "a broader read permission"]:
                items[c["needs"] or "a broader read permission"].append(what(c))
        unlock = {
            "more_needed": True,
            "text": "More permission would unlock: " + ", ".join(labels) + ".",
            "capabilities": labels,
            "items": [{"unlocks": ", ".join(v), "needs": k} for k, v in items.items()],
        }
    else:
        unlock = {
            "more_needed": False,
            "text": "Nothing more is needed. NodeWatch only reads, and this account can read everything NodeWatch uses."
            if checks and all(c["status"] in ("ok", "skipped") for c in checks)
            else "No read was refused. Checks that failed for other reasons are listed above.",
            "capabilities": [],
            "items": [],
        }
    sample = []
    for c in checks:
        if c["status"] == "ok" and c["count"] is not None and c["noun"] and c["sample"] and not c["optional"]:
            text = c["detail"] or f"{c['count']} {c['noun']}"
            if text not in sample:
                sample.append(text)
    return {
        "checks": checks,
        "capabilities": capabilities,
        "unlock": unlock,
        "sample": " · ".join(sample[:4]),
        "elapsed_ms": int((time.monotonic() - started) * 1000),
        "budget_s": budget_s,
    }


class Connector(ProviderAdapter):
    """Base class for connectors. Subclasses set ``manifest`` and implement capability methods."""

    manifest: ConnectorManifest

    def __init__(self) -> None:
        self.descriptor = ProviderDescriptor(
            self.manifest.connector_id,
            f"{self.manifest.vendor} {self.manifest.product}".strip(),
            tuple(self.manifest.capabilities),
            read_only=not any(c.endswith(".write") for c in self.manifest.capabilities),
            vendor=self.manifest.vendor,
            adapter_version=self.manifest.version,
        )
        self._health = ProviderHealth()
        # Test seams (contract tests / fixture harnesses): a fake transport and in-memory settings.
        self.transport: Any = None
        self.settings_override: dict[str, Any] | None = None
        self.secret_override: dict[str, str] | None = None
        # v0.10.47 (N1): which connection of this connector the instance is. The first connection's id is
        # the connector id, so its settings, credentials and keys are exactly what they were before.
        self.connection_id: str = self.manifest.connector_id
        self.connection_label: str = ""
        _stamp_records_of(self)

    @property
    def is_first_connection(self) -> bool:
        return self.connection_id == self.manifest.connector_id

    def tenant_id(self) -> str:
        """The org / TSG / VDOM this connection reads, when the vendor has one (override; "" = none)."""
        return ""

    # ---- settings -----------------------------------------------------------------------------
    def _saved(self) -> dict[str, Any]:
        if self.settings_override is not None:
            return self.settings_override
        return load_connector_settings().get(self.connection_id, {})

    def settings(self) -> dict[str, Any]:
        """Saved non-secret settings merged over defaults; secrets as booleans (present/absent)."""
        saved = self._saved()
        out: dict[str, Any] = {}
        for f in self.manifest.settings:
            if f.type == "secret":
                out[f.key] = bool(self.secret(f.key))
            else:
                out[f.key] = saved.get(f.key, f.default)
        out["enabled"] = bool(saved.get("enabled", False))
        return out

    def secret(self, key: str) -> str:
        """A saved secret value — use only to authenticate; never return, log or put it in an error."""
        if self.secret_override is not None:
            return str(self.secret_override.get(key) or "")
        return SECRETS.get(_secret_ref(self.connection_id, key))

    def secret_values(self) -> list[str]:
        return [v for v in (self.secret(f.key) for f in self.manifest.settings if f.type == "secret") if v]

    def redact(self, text: Any) -> str:
        return redact_text(text, *self.secret_values())

    @property
    def enabled(self) -> bool:
        return bool(self._saved().get("enabled", False))

    @property
    def configured(self) -> bool:
        s = self.settings()
        return all(s.get(f.key) not in (None, "", False) for f in self.manifest.settings if f.required)

    def health_state(self) -> ProviderHealth:
        self._health.configured = self.configured
        if not self.configured:
            self._health.state = "disabled"
        return self._health

    def reset_state(self) -> None:
        """Forget connection results and cached vendor data (called after the settings change)."""
        self._health = ProviderHealth()

    @staticmethod
    def validate_settings(values: dict[str, Any]) -> None:
        """Connector-specific form checks (v0.10.17). Raise ValueError with a readable message."""

    def test_connection(self) -> dict[str, Any]:
        """Override with one cheap authenticated call."""
        return {"ok": self.configured, "provider": self.provider_id, "configured": self.configured}

    # ---- capability probes (v0.10.18) ---------------------------------------------------------------
    def probe_plan(self) -> list[Probe]:
        """The cheapest read per claimed capability. Override for a smarter, vendor-specific plan.

        Default: the capability's own read method, scoped to ONE device where the method takes one.
        Never a write: write capabilities and query-style capabilities (policy lookup, endpoint
        locate, traffic logs) are listed as "not checked" instead of being exercised.
        """
        from app.integrations import contracts as C

        caps = self.manifest.capabilities
        plan: list[Probe] = []

        def devices(ctx: ProbeContext) -> list[Any]:
            return ctx.once("devices", lambda: list(self.list_devices()), "the device list")

        def first(ctx: ProbeContext) -> str:
            found = devices(ctx)
            if not found:
                raise ProbeSkipped("no device to read from")
            return found[0].key

        if C.INVENTORY in caps:
            plan.append(Probe(C.INVENTORY, "List devices", lambda ctx: len(devices(ctx)), "devices"))
        if C.INTERFACES in caps:
            plan.append(
                Probe(
                    C.INTERFACES,
                    "Interfaces of one device",
                    lambda ctx: len(self.list_interfaces(first(ctx))),
                    "interfaces",
                    sample=False,
                )
            )
        if C.ALERTS in caps:
            plan.append(Probe(C.ALERTS, "Open alerts", lambda ctx: len(self.list_alerts()), "open alerts"))
        if C.EVENTS in caps:
            plan.append(
                Probe(C.EVENTS, "Events of the last hour", lambda ctx: len(self.list_events(hours=1)), "events")
            )
        if C.NEIGHBORS in caps:
            plan.append(Probe(C.NEIGHBORS, "LLDP/CDP neighbors", lambda ctx: len(self.list_neighbors()), "neighbors"))
        if C.MAC_TABLE in caps:
            plan.append(
                Probe(
                    C.MAC_TABLE,
                    "MAC table of one device",
                    lambda ctx: len(self.list_mac_table(first(ctx))),
                    "MAC entries",
                    sample=False,
                )
            )
        if C.ARP_TABLE in caps:
            plan.append(
                Probe(
                    C.ARP_TABLE,
                    "ARP table of one device",
                    lambda ctx: len(self.list_arp(first(ctx))),
                    "ARP entries",
                    sample=False,
                )
            )
        if C.ROUTES in caps:
            plan.append(
                Probe(
                    C.ROUTES,
                    "Routes of one device",
                    lambda ctx: len(self.list_routes(first(ctx))),
                    "routes",
                    sample=False,
                )
            )
        if C.TUNNELS in caps:
            plan.append(Probe(C.TUNNELS, "Tunnels", lambda ctx: len(self.list_tunnels()), "tunnels"))
        if C.WAN_CIRCUITS in caps:
            plan.append(Probe(C.WAN_CIRCUITS, "WAN circuits", lambda ctx: len(self.list_circuits()), "circuits"))
        if C.HEALTH in caps:
            plan.append(
                Probe(
                    C.HEALTH,
                    "Live health",
                    lambda ctx: len((self.list_health() or {}).get("devices") or []),
                    "devices with live health",
                )
            )
        if C.SECURITY_EVENTS in caps:  # v0.10.30: one small, bounded read of the last hour
            plan.append(
                Probe(
                    C.SECURITY_EVENTS,
                    "Security detections of the last hour",
                    lambda ctx: len(self.list_security_events(since=time.time() - 3600, limit=50)),
                    "detections",
                )
            )
        if C.SECURITY_EXPOSURES in caps:
            plan.append(
                Probe(C.SECURITY_EXPOSURES, "Exposures", lambda ctx: len(self.list_exposures()), "exposures")
            )
        if C.SECURITY_INCIDENTS in caps:
            plan.append(
                Probe(
                    C.SECURITY_INCIDENTS,
                    "Incidents of the last day",
                    lambda ctx: len(self.list_security_incidents(hours=24)),
                    "incidents",
                )
            )
        for cap in (C.POLICY_LOOKUP, C.ENDPOINT_LOCATE, C.TRAFFIC_LOGS, C.ALERTS_ACK):
            if cap in caps:
                plan.append(Probe(cap, "Not exercised by the test", _not_exercised))
        return plan

    def probe_capabilities(self, *, budget_s: float = PROBE_BUDGET_S) -> dict[str, Any]:
        """Per-capability ok / denied / error report within ``budget_s`` (read-only)."""
        return run_probes(self, budget_s=budget_s)

    # ---- helpers for subclasses ----------------------------------------------------------------
    def call(self, fn: Callable[[], Any], what: str) -> Any:
        """Run a vendor call, record health and turn any failure into IntegrationError."""
        try:
            result = fn()
        except IntegrationError as exc:
            message = self.redact(exc)
            self._health.mark_error(message, status_code=exc.status_code)
            if message != str(exc):
                raise IntegrationError(message, code=exc.code, status_code=exc.status_code) from None
            raise
        except Exception as exc:  # noqa: BLE001 - vendor/client exceptions are normalized here
            status = getattr(exc, "status_code", None)
            detail = self.redact(exc)
            self._health.mark_error(f"{what}: {detail}", status_code=status)
            raise IntegrationError(f"{self.manifest.product}: {what} failed ({detail})", status_code=status) from None
        self._health.mark_success()
        return result

    def http(self) -> "HttpJsonClient":
        """The HTTP client for this connector (the fake transport in tests). Override ``build_http``."""
        if self.transport is not None:
            return self.transport
        return self.build_http()

    def build_http(self) -> "HttpJsonClient":
        raise IntegrationError(f"{self.manifest.product} does not use the shared HTTP client", code="UNSUPPORTED")


# --------------------------------------------------------------------------- shared helpers


def _scoped(source: str, connection_id: str) -> tuple[str, ...]:
    """Key parts for a connector's own ids: unchanged for its first connection (connection_id empty or the
    connector id), so keys stored before v0.10.47 still match; other connections get keys of their own."""
    return (source,) if not connection_id or connection_id == source else (source, connection_id)


def device_key(*, mac: Any = "", serial: Any = "", source: str = "", native_id: Any = "", connection_id: str = "") -> str:
    """The vendor-neutral device key every connector should use.

    Same box → same key, whichever vendor or connection reports it: base MAC first, then serial number,
    and only when neither is known a key scoped to the reporting connection.
    """
    bare = normalize_mac(mac)
    if bare:
        return stable_key("mac", bare)
    if str(serial or "").strip():
        return stable_key("serial", str(serial).strip())
    return stable_key(*_scoped(source, connection_id), native_id)


def site_key(source: str, native_id: Any, connection_id: str = "") -> str:
    """Site key scoped to the connection (sites are not shared between vendors or between connections)."""
    return stable_key("site", *_scoped(source, connection_id), native_id)


def epoch_seconds(value: Any) -> float | None:
    """Vendor timestamp (s, ms or µs epoch) → epoch seconds; None when missing/invalid."""
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    if number <= 0:
        return None
    while number > 1e11:  # ms / µs
        number /= 1000.0
    return number


_SIGN_IN_HINTS = ("login", "signin", "sign-in", "sso", "saml", "oauth", "auth", "portal")


def _redirect_message(where: str, status: int, headers: Any, base_url: str) -> str:
    """Explain a refused redirect: where it pointed (no query) and what that usually means."""
    location = ""
    try:
        location = str((headers or {}).get("Location") or "")
    except Exception:  # noqa: BLE001
        location = ""
    target = urlparse(location)
    base = urlparse(base_url)
    shown = f"{target.scheme + '://' if target.scheme else ''}{target.hostname or ''}{target.path or ''}".strip() or "?"
    text = f"{where} was redirected (HTTP {status}) to {shown}"
    lowered = (target.path or "").lower() + (target.hostname or "").lower()
    if any(h in lowered for h in _SIGN_IN_HINTS):
        return (
            text + ": the server sent NodeWatch to its sign-in page, which means the API key was not accepted. "
            "Check the key is enabled and not expired, that it was copied completely, and that the URL is just "
            "the server address (for example https://orchestrator.example.com)."
        )
    if target.hostname and base.hostname and target.hostname.lower() != base.hostname.lower():
        return (
            text + ": the server points to a different address. Use that address as the URL if it is the same system."
        )
    return text + ": check that the URL is just the server address (no page path)."


class _NoRedirect(HTTPRedirectHandler):
    """Never follow a redirect: it would carry the API token to another URL."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


def validate_https_url(value: Any, label: str = "Base URL") -> str:
    text = str(value or "").strip().rstrip("/")
    parsed = urlparse(text)
    if parsed.scheme != "https" or not parsed.hostname:
        raise IntegrationError(f"{label} must be an https:// URL", code="CONFIGURATION_ERROR")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise IntegrationError(
            f"{label} must not contain credentials, a query or a fragment", code="CONFIGURATION_ERROR"
        )
    return text


MAX_RESPONSE_BYTES = 20 * 1024 * 1024  # one API answer; anything bigger is a misconfiguration or abuse

_HTTP_CODES = {401: "AUTHENTICATION_FAILED", 403: "PERMISSION_DENIED", 404: "NOT_FOUND", 429: "RATE_LIMITED"}


_OPENERS: dict[tuple[bool, str], Any] = {}
_OPENERS_LOCK = threading.Lock()


from app.core.http_pool import ResponseTooLarge  # noqa: E402


def _shared_opener(verify_tls: bool, ca_file: str) -> Any:
    """Pooled keep-alive opener for one TLS setting (see HttpJsonClient.__init__)."""
    from app.core.http_pool import KeepAliveOpener

    key = (verify_tls, ca_file)
    with _OPENERS_LOCK:
        opener = _OPENERS.get(key)
        if opener is None:
            context = ssl.create_default_context(cafile=ca_file or None)
            if not verify_tls:  # explicit per-connection user choice; shown as a warning in Settings
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
            opener = _OPENERS[key] = KeepAliveOpener(context=context, retry_unsafe=False)
        return opener


class HttpJsonClient:
    """Small read-only JSON-over-HTTPS client for connectors (urllib, no extra dependencies).

    * https only; TLS certificates verified by default (``ca_file`` trusts a private CA instead of
      turning verification off);
    * timeouts on every call; redirects never followed (they would carry the token);
    * every failure is an :class:`IntegrationError` whose text never contains the secrets passed in.
    """

    def __init__(
        self,
        base_url: str,
        *,
        headers: dict[str, str],
        product: str,
        verify_tls: bool = True,
        ca_file: str = "",
        timeout: float = 20.0,
        secrets: tuple[str, ...] | list[str] = (),
        max_bytes: int = MAX_RESPONSE_BYTES,
    ) -> None:
        self.base_url = validate_https_url(base_url)
        self.max_bytes = max(1024, int(max_bytes))
        self.product = product
        self.timeout = max(3.0, min(float(timeout or 20.0), 120.0))
        self._secrets = tuple(s for s in secrets if s)
        self._headers = {"Accept": "application/json", "User-Agent": f"NodeWatch/{APP_VERSION}", **headers}
        # v0.10.23: one pooled keep-alive opener per TLS setting, shared by every client of the
        # process. Connector clients are short-lived (built per call), so a per-client urllib
        # opener paid DNS + TCP + TLS (and a CA-store load) on every request. The pooled opener
        # never follows redirects (3xx is raised as HTTPError, handled below exactly as before),
        # asks for gzip and honours the system proxy settings like urllib does.
        self._opener = _shared_opener(bool(verify_tls), ca_file or "")

    def _fail(self, message: str, *, code: str = "PROVIDER_ERROR", status: int | None = None) -> IntegrationError:
        return IntegrationError(
            redact_text(f"{self.product}: {message}", *self._secrets), code=code, status_code=status
        )

    def request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        body: Any = None,
        timeout: float | None = None,
    ) -> Any:
        """One call. A name-resolution failure (nothing was sent) is retried once on a new lookup."""
        try:
            return self._request_once(method, path, params=params, body=body, timeout=timeout)
        except IntegrationError as exc:
            if getattr(exc, "dns_failure", False):
                time.sleep(0.5)
                return self._request_once(method, path, params=params, body=body, timeout=timeout)
            raise

    def _request_once(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        body: Any = None,
        timeout: float | None = None,
    ) -> Any:
        query = {k: v for k, v in (params or {}).items() if v is not None and v != ""}
        url = self.base_url + path + (("&" if "?" in path else "?") + urlencode(query) if query else "")
        data = json.dumps(body).encode("utf-8") if body is not None else None
        headers = dict(self._headers)
        if data is not None:
            headers["Content-Type"] = "application/json"
        req = Request(url, data=data, method=method.upper(), headers=headers)
        where = f"{method.upper()} {path.split('?', 1)[0]}"
        started = time.perf_counter()
        ok = False
        try:
            limit = max(3.0, min(float(timeout), 300.0)) if timeout else self.timeout
            with self._opener.open(req, timeout=limit, max_bytes=self.max_bytes) as resp:
                body_bytes = resp.read(self.max_bytes + 1)
            ok = True
            if len(body_bytes) > self.max_bytes:
                ok = False  # counted as a failed call in Support diagnostics (v0.10.23)
                raise self._fail(
                    f"{where} answered more than {self.max_bytes // (1024 * 1024)} MB; narrow the request or check the URL",
                    code="RESPONSE_TOO_LARGE",
                )
            raw = body_bytes.decode("utf-8", errors="replace")
        except IntegrationError:
            raise
        except HTTPError as exc:
            try:
                excerpt = " ".join(exc.read(4096).decode("utf-8", errors="replace").split())[:200]
            except Exception:  # noqa: BLE001
                excerpt = ""
            status = int(exc.code)
            if 300 <= status < 400:
                raise self._fail(_redirect_message(where, status, exc.headers, self.base_url), status=status) from None
            text = f"{where} → HTTP {status}" + (f": {excerpt}" if excerpt else "")
            if status == 403 and method.upper() != "GET":  # v0.10.46: the system's answer for this account, now
                # (reads keep their per-connector setup hints: a refused read is often a wrong scope or URL)
                text = f"{text}. {refused_text(self.product)}"
            raise self._fail(text, code=_HTTP_CODES.get(status, "PROVIDER_ERROR"), status=status) from None
        except ResponseTooLarge:
            raise self._fail(
                f"{where} answered more than {self.max_bytes // (1024 * 1024)} MB; narrow the request or check the URL",
                code="RESPONSE_TOO_LARGE",
            ) from None
        except URLError as exc:
            err = self._fail(
                f"cannot reach {urlparse(self.base_url).hostname} ({exc.reason})", code="PROVIDER_UNAVAILABLE"
            )
            err.dns_failure = isinstance(exc.reason, socket.gaierror)
            raise err from None
        except (TimeoutError, OSError) as exc:
            raise self._fail(f"{where} failed ({exc})", code="PROVIDER_UNAVAILABLE") from None
        finally:  # per-connector timing for Support diagnostics (endpoint template only, v0.10.21)
            api_timing.note(self.product, method, path, (time.perf_counter() - started) * 1000, ok)
        if not raw.strip():
            return None
        try:
            return json.loads(raw)
        except ValueError:
            raise self._fail(f"{where} did not return JSON") from None

    def get(self, path: str, **params: Any) -> Any:
        return self.request("GET", path, params=params)


class FixtureTransport:
    """Fake :class:`HttpJsonClient` for tests: answers from recorded JSON, never touches the network.

    ``routes`` maps ``"GET /path"`` (query string ignored) to a payload, an Exception to raise, or a
    callable ``(params, body) -> payload`` for answers that depend on the query (e.g. per device).
    Every call is recorded in ``calls`` as ``(method, path, params, body)``.
    """

    def __init__(self, routes: dict[str, Any]) -> None:
        self.routes = dict(routes)
        self.calls: list[tuple[str, str, dict[str, Any], Any]] = []

    def request(
        self, method: str, path: str, *, params: dict[str, Any] | None = None, body: Any = None, timeout: Any = None
    ) -> Any:
        self.calls.append((method.upper(), path, dict(params or {}), body))
        key = f"{method.upper()} {path.split('?', 1)[0]}"
        if key not in self.routes:
            raise IntegrationError(f"fixture: no recorded answer for {key}", code="NOT_FOUND", status_code=404)
        value = self.routes[key]
        if callable(value):
            value = value(dict(params or {}), body)
        if isinstance(value, Exception):
            raise value
        return json.loads(json.dumps(value))  # a fresh copy each call, like a real API

    def get(self, path: str, **params: Any) -> Any:
        return self.request("GET", path, params=params)


# --------------------------------------------------------------------------- settings storage


def load_fixture(package_file: str, name: str) -> Any:
    """Read ``fixtures/<name>`` next to a connector's module (fixture harnesses and tests)."""
    from pathlib import Path

    return json.loads((Path(package_file).parent / "fixtures" / name).read_text(encoding="utf-8"))


_SETTINGS_CACHE: dict[str, Any] = {"sig": None, "data": {}}
_SETTINGS_LOCK = threading.Lock()


def _forget_settings_cache() -> None:
    with _SETTINGS_LOCK:
        _SETTINGS_CACHE.update(sig=None)


def load_connector_settings() -> dict[str, dict[str, Any]]:
    """connectors.json, re-read only when the file changed (v0.10.23).

    It is read on almost every vendor call; a file that is briefly locked or half-written (Windows
    antivirus, a save in progress) now yields the last good copy instead of "no connections",
    which made a configured connection look "not configured" for that moment.
    """
    try:
        st = CONNECTORS_FILE.stat()
        sig = (st.st_mtime_ns, st.st_size)
    except FileNotFoundError:
        with _SETTINGS_LOCK:
            _SETTINGS_CACHE.update(sig=None, data={})
        return {}
    except OSError:
        sig = None
    with _SETTINGS_LOCK:
        if sig is not None and sig == _SETTINGS_CACHE["sig"]:
            return json.loads(json.dumps(_SETTINGS_CACHE["data"]))
    for attempt in range(3):
        try:
            data = json.loads(CONNECTORS_FILE.read_text(encoding="utf-8"))
            data = data if isinstance(data, dict) else {}
            with _SETTINGS_LOCK:
                _SETTINGS_CACHE.update(sig=sig, data=data)
            return json.loads(json.dumps(data))
        except (OSError, ValueError):
            time.sleep(0.05 * (attempt + 1))
    with _SETTINGS_LOCK:
        return json.loads(json.dumps(_SETTINGS_CACHE["data"]))


def clean_connector_settings(
    connector: Connector, values: dict[str, Any]
) -> tuple[dict[str, Any], dict[str, str], list[str]]:
    """Validate a connection form → (non-secret values, new secrets, secrets to clear). Raises ValueError."""
    manifest = connector.manifest
    clean: dict[str, Any] = {"enabled": bool(values.get("enabled", False))}
    new_secrets: dict[str, str] = {}
    cleared: list[str] = []
    for f in manifest.settings:
        raw = values.get(f.key)
        if f.type == "secret":
            if isinstance(raw, str) and raw.strip():
                if len(raw.strip()) > 4096:
                    raise ValueError(f"{f.label} is too long")
                new_secrets[f.key] = raw.strip()
            elif values.get(f"clear_{f.key}"):
                cleared.append(f.key)
            if (
                f.required
                and clean["enabled"]
                and not new_secrets.get(f.key)
                and (f.key in cleared or not connector.secret(f.key))
            ):
                raise ValueError(f"{f.label} is required")
            continue
        if f.type == "boolean":
            clean[f.key] = bool(raw if raw is not None else f.default)
        elif f.type == "number":
            try:
                clean[f.key] = float(raw) if raw not in (None, "") else f.default
            except (TypeError, ValueError) as exc:
                raise ValueError(f"{f.label} must be a number") from exc
        elif f.type == "select":
            if raw not in (None, "") and str(raw) not in f.options:
                raise ValueError(f"{f.label} must be one of {', '.join(f.options)}")
            clean[f.key] = str(raw) if raw not in (None, "") else f.default
        else:
            text = str(raw or "").strip()
            if f.type == "url" and text:
                if f.origin_only and "@" not in urlparse(text).netloc:
                    text = url_origin(text) or text
                parsed = urlparse(text)
                if parsed.scheme != "https" or not parsed.hostname:
                    raise ValueError(f"{f.label} must start with https://")
                if parsed.username or parsed.password or parsed.query or parsed.fragment:
                    raise ValueError(f"{f.label} must not contain credentials, a query or a fragment")
                text = text.rstrip("/")
            if len(text) > 500:
                raise ValueError(f"{f.label} is too long")
            clean[f.key] = text
        if f.required and clean.get(f.key) in (None, ""):
            raise ValueError(f"{f.label} is required")
    connector.validate_settings(clean)
    return clean, new_secrets, cleared


def save_connector_settings(connector_id: str, values: dict[str, Any], connection_id: str = "") -> dict[str, Any]:
    """Validate and save a connection's form. Secret fields go to the secure credential store; blank keeps them.

    ``connection_id`` names one connection of the connector (default: its first, whose id is the connector id)."""
    connector = get_connector(connection_id or connector_id)
    if connector is None:
        raise ValueError(f"Unknown connector {connector_id}")
    manifest = connector.manifest
    if manifest.managed_elsewhere:
        raise ValueError(f"{manifest.product} is configured on its own settings page")
    clean, new_secrets, cleared = clean_connector_settings(connector, values)
    labels = {f.key: f.label for f in manifest.settings}
    connection_id = connector.connection_id
    for key, value in new_secrets.items():
        SECRETS.put(_secret_ref(connection_id, key), value, username=f"NodeWatch {manifest.product} {labels[key]}")
    for key in cleared:
        SECRETS.delete(_secret_ref(connection_id, key))

    def apply(current: Any) -> dict[str, Any]:
        data = current if isinstance(current, dict) else {}
        data[connection_id] = clean
        return data

    locked_json_update(CONNECTORS_FILE, apply)

    _forget_settings_cache()
    connector.reset_state()  # new settings: forget the previous connection result and cached data
    _invalidate_maps()
    return connector.settings()


def _host(value: Any) -> str:
    parsed = urlparse(str(value or "").strip())
    return f"{(parsed.hostname or '').lower()}:{parsed.port or ''}"


def _addresses(value: Any) -> set[str]:
    """An address field's entries, order/case/separator-insensitive (SNMP target lists)."""
    return {part for part in str(value or "").lower().replace(",", " ").replace(";", " ").split() if part}


def candidate_connector(connector_id: str, values: dict[str, Any]) -> Connector:
    """A throw-away instance using unsaved form values (blank secrets fall back to the saved ones).

    A saved secret is only reused for the host it was saved for: if any URL field now points
    somewhere else, the secret must be typed again (otherwise editing the URL would send the saved
    token to an arbitrary server). The same holds when a security setting changed (v0.10.18: TLS
    verification, CA file, port, SNMPv3 protocols — ``SettingField.security`` / ``SECURITY_KEYS``):
    otherwise the saved secret could be sent with weaker protection than it was saved for.
    """
    connector = get_connector(connector_id)
    if connector is None:
        raise ValueError(f"Unknown connector {connector_id}")
    if connector.manifest.managed_elsewhere:
        return connector
    clean, new_secrets, cleared = clean_connector_settings(connector, {**values, "enabled": True})
    saved = connector.settings()
    host_changed = any(
        f.type == "url" and clean.get(f.key) and _host(clean.get(f.key)) != _host(saved.get(f.key))
        for f in connector.manifest.settings
    ) or any(
        f.address and clean.get(f.key) and _addresses(clean.get(f.key)) != _addresses(saved.get(f.key))
        for f in connector.manifest.settings
    )
    security_changed = [
        f.label
        for f in connector.manifest.settings
        if f.type != "secret" and _security_field(f) and _norm(f, clean.get(f.key)) != _norm(f, saved.get(f.key))
    ]
    secret_fields = [f for f in connector.manifest.settings if f.type == "secret"]
    if host_changed or security_changed:
        missing = [f.label for f in secret_fields if not new_secrets.get(f.key) and connector.secret(f.key)]
        if missing:
            if host_changed:
                raise ValueError(
                    f"The address changed, so the saved {', '.join(missing)} is not sent to it. "
                    f"Enter the {', '.join(missing)} again to test this address."
                )
            raise ValueError(
                f"A security setting changed ({', '.join(security_changed)}), so the saved "
                f"{', '.join(missing)} is not used with it. Enter the {', '.join(missing)} again to test."
            )
        host_changed = True  # never fall back to a saved secret under changed settings
    candidate = type(connector)()
    candidate.connection_id = connector.connection_id
    candidate.settings_override = clean
    candidate.secret_override = {
        f.key: new_secrets.get(f.key) or ("" if f.key in cleared or host_changed else connector.secret(f.key))
        for f in secret_fields
    }
    return candidate


def saved_clone(connector_id: str) -> Connector:
    """A throw-away instance with the SAVED settings (Re-test without touching the live instance's
    caches). Externally managed connectors are returned as they are."""
    connector = get_connector(connector_id)
    if connector is None:
        raise ValueError(f"Unknown connector {connector_id}")
    if connector.manifest.managed_elsewhere:
        return connector
    clone = type(connector)()
    clone.connection_id = connector.connection_id
    clone.settings_override = {**connector._saved(), "enabled": True}
    clone.secret_override = {f.key: connector.secret(f.key) for f in connector.manifest.settings if f.type == "secret"}
    clone.transport = connector.transport  # test seam only (None in the app)
    return clone


def set_connector_enabled(connector_id: str, enabled: bool) -> dict[str, Any]:
    """Switch a saved connection on or off without re-entering the form."""
    connector = get_connector(connector_id)
    if connector is None:
        raise ValueError(f"Unknown connector {connector_id}")
    if connector.manifest.managed_elsewhere and getattr(connector, "inventory_switch", False):
        # v0.10.23: connectors set up elsewhere may still offer an inventory on/off switch here.
        def apply_inventory(current: Any) -> dict[str, Any]:
            data = current if isinstance(current, dict) else {}
            row = data.get(connector_id) if isinstance(data.get(connector_id), dict) else {}
            data[connector_id] = {**row, "inventory_enabled": bool(enabled)}
            return data

        locked_json_update(CONNECTORS_FILE, apply_inventory)

        _forget_settings_cache()
        connector.reset_state()
        _invalidate_maps()
        return connector.settings()
    if connector.manifest.managed_elsewhere:
        raise ValueError(f"{connector.manifest.product} is switched on and off on its own settings page")
    if enabled and not connector.configured:
        raise ValueError("Fill in and save the connection first")

    connection_id = connector.connection_id

    def apply(current: Any) -> dict[str, Any]:
        data = current if isinstance(current, dict) else {}
        row = data.get(connection_id) if isinstance(data.get(connection_id), dict) else {}
        data[connection_id] = {**row, "enabled": bool(enabled)}
        return data

    locked_json_update(CONNECTORS_FILE, apply)

    _forget_settings_cache()
    connector.reset_state()
    _invalidate_maps()
    return connector.settings()


def _invalidate_maps() -> None:
    """v0.10.23: rebuild the topology maps after a connection changes (they kept serving the
    graph built with the old settings until its own refresh)."""
    for module in ("app.services.topology_service", "app.services.topology_org_service"):
        try:
            mod = importlib.import_module(module)
            clear = getattr(mod, "clear_cache", None)
            if callable(clear):
                clear()
        except Exception as exc:  # noqa: BLE001 - never block a settings save
            log.info("Could not reset %s after a connection change: %s", module, type(exc).__name__)


_TLS_WORDS = ("certificate", "ssl", "tls", "handshake")


class TestInProgress(Exception):
    """A Test of this connector is still running (or its timed-out reads have not finished yet)."""


_TESTS_LOCK = threading.Lock()
_TESTS_RUNNING: set[str] = set()


def _release_when_done(key: str, futures: list) -> None:
    """Free the connector's test slot once every worker of that test has really finished, so repeated
    Test clicks can never pile up threads that outlived the 20 s budget."""
    pending = [f for f in futures if not f.done()]
    if not pending:
        with _TESTS_LOCK:
            _TESTS_RUNNING.discard(key)
        return
    remaining = {"n": len(pending)}
    lock = threading.Lock()

    def one_done(_f: Any) -> None:
        with lock:
            remaining["n"] -= 1
            last = remaining["n"] == 0
        if last:
            with _TESTS_LOCK:
                _TESTS_RUNNING.discard(key)

    for f in pending:
        f.add_done_callback(one_done)


def test_running(connector_id: str) -> bool:
    with _TESTS_LOCK:
        return connector_id in _TESTS_RUNNING


def connection_report(
    target: Connector, *, probe: bool = True, budget_s: float | None = None, guard: str | None = None
) -> dict[str, Any]:
    """The Add-connection Test: one connection check, then (when it passed) the capability probes.

    Returns a checklist (reachable, TLS, authenticated, permissions, found) plus per-capability
    results — all text redacted, no secret values, bounded to ``budget_s`` in total. ``target`` is a
    throw-away instance (unsaved form values or :func:`saved_clone`), so the live connector's caches
    and health are untouched; the caller decides what to record.
    """

    if guard:
        with _TESTS_LOCK:
            if guard in _TESTS_RUNNING:
                raise TestInProgress(
                    f"A test of {target.manifest.product} is still running. Wait for it to finish, then try again."
                )
            _TESTS_RUNNING.add(guard)
    workers: list = []
    try:
        return _connection_report(
            target, probe=probe, budget_s=PROBE_BUDGET_S if budget_s is None else budget_s, workers=workers
        )
    finally:
        if guard:
            _release_when_done(guard, workers)


def _connection_report(target: Connector, *, probe: bool, budget_s: float, workers: list) -> dict[str, Any]:
    from concurrent.futures import ThreadPoolExecutor
    from concurrent.futures import TimeoutError as FutureTimeout

    started = time.monotonic()
    budget_s = max(2.0, min(float(budget_s), 60.0))
    if target.settings_override is not None and target.settings_override.get("timeout") not in (None, ""):
        try:
            target.settings_override["timeout"] = min(float(target.settings_override["timeout"]), PROBE_HTTP_TIMEOUT_S)
        except (TypeError, ValueError):
            target.settings_override["timeout"] = PROBE_HTTP_TIMEOUT_S
    manifest = target.manifest
    has_url = any(f.type == "url" for f in manifest.settings)
    result: dict[str, Any] = {}
    error: IntegrationError | None = None
    other: str = ""
    pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="nw-test")
    try:
        future = pool.submit(target.test_connection)
        workers.append(future)
        try:
            result = future.result(timeout=min(budget_s * 0.6, PROBE_HTTP_TIMEOUT_S + 15))
        except FutureTimeout:
            error = IntegrationError(
                f"{manifest.product} did not answer within {min(budget_s * 0.6, PROBE_HTTP_TIMEOUT_S + 15):.0f} s",
                code="PROVIDER_UNAVAILABLE",
            )
        except IntegrationError as exc:
            error = exc
        except Exception as exc:  # noqa: BLE001
            other = type(exc).__name__
    finally:
        pool.shutdown(wait=False, cancel_futures=True)
    ok = bool(result.get("ok")) and error is None and not other
    message = target.redact(error) if error is not None else (f"Unexpected {other}" if other else "")
    if not ok and not message:
        message = target.redact(result.get("detail") or "Not configured")
    low = message.lower()
    code = error.code if error is not None else ""
    status = error.status_code if error is not None else None

    checks: list[dict[str, Any]] = []

    def add(cid: str, label: str, state: str, detail: str) -> None:
        checks.append({"id": cid, "label": label, "status": state, "detail": detail})

    tls_failed = error is not None and any(w in low for w in _TLS_WORDS)
    unreachable = code in ("PROVIDER_UNAVAILABLE", "CONFIGURATION_ERROR", "NOT_CONFIGURED") and not tls_failed
    auth_failed = code in ("AUTHENTICATION_FAILED", "PERMISSION_DENIED") or status in (401, 403)
    if not result.get("configured", True) and error is None and not other:
        unreachable = True
    settings = target.settings() if not manifest.managed_elsewhere else {}

    if unreachable:
        add("reachable", "Reachable", "fail", message)
    else:
        add("reachable", "Reachable", "pass", "Answered" if not ok else "Answered over the network")
    if not has_url:
        add(
            "tls",
            "Encrypted connection",
            "skip",
            f"Checked on {manifest.settings_location}"
            if manifest.managed_elsewhere
            else "Not HTTPS: this connection type uses its own encryption",
        )
    elif unreachable:
        add("tls", "TLS certificate", "skip", "Not checked")
    elif tls_failed:
        add(
            "tls",
            "TLS certificate",
            "fail",
            message + " — point 'Private CA certificate' at the CA that signed the certificate",
        )
    elif settings.get("verify_tls") is False:
        add("tls", "TLS certificate", "warn", "Certificate checks are off for this connection")
    else:
        ca = " with your private CA" if str(settings.get("ca_file") or "").strip() else ""
        add("tls", "TLS certificate", "pass", f"Certificate verified{ca}")
    if unreachable or tls_failed:
        add("auth", "Authenticated", "skip", "Not checked")
    elif auth_failed:
        add("auth", "Authenticated", "fail", message)
    elif not ok:
        add("auth", "Authenticated", "fail", message)
    else:
        add("auth", "Authenticated", "pass", target.redact(result.get("detail") or "Accepted"))

    probes: dict[str, Any] = {}
    if ok and probe and not manifest.managed_elsewhere:
        remaining = budget_s - (time.monotonic() - started)
        probes = run_probes(target, budget_s=max(1.0, remaining), futures_out=workers)
        caps = probes.get("capabilities") or []
        bad = [c for c in caps if c["status"] in ("denied", "empty")]
        failed = [c for c in caps if c["status"] in ("error", "timeout")]
        if not caps:
            add("permissions", "Permissions sufficient", "skip", "No capability checks for this connector")
        elif bad:
            state = "fail" if len(bad) == len([c for c in caps if c["status"] != "skipped"]) else "warn"
            add(
                "permissions",
                "Permissions sufficient",
                state,
                "Refused: " + ", ".join(c["label"] for c in bad),
            )
        elif failed:
            add(
                "permissions",
                "Permissions sufficient",
                "warn",
                "Some reads failed: " + ", ".join(c["label"] for c in failed),
            )
        else:
            partial = [c["label"] for c in caps if c["status"] == "partial"]
            add(
                "permissions",
                "Permissions sufficient",
                "pass",
                "Every capability is readable" + (f" (some details missing: {', '.join(partial)})" if partial else ""),
            )
        sample = probes.get("sample") or ""
        add("found", "Found", "pass" if sample else "warn", sample or "Nothing found yet")
    elif ok and manifest.managed_elsewhere:
        add("permissions", "Permissions sufficient", "skip", f"Managed on {manifest.settings_location}")
        add("found", "Found", "pass", target.redact(result.get("detail") or ""))
    else:
        add("permissions", "Permissions sufficient", "skip", "Not checked")
        add("found", "Found", "skip", "Not checked")
    return {
        "ok": ok,
        "detail": target.redact(result.get("detail") or "") if ok else "",
        "error": "" if ok else message,
        "status_code": status,
        "code": code,
        "checks": checks,
        "capabilities": probes.get("capabilities", []),
        "probes": probes.get("checks", []),
        "unlock": probes.get("unlock"),
        "sample": probes.get("sample", ""),
        "elapsed_ms": int((time.monotonic() - started) * 1000),
        "budget_s": budget_s,
    }


def remove_connector_settings(connector_id: str) -> None:
    connector = get_connector(connector_id)
    if connector is None or connector.manifest.managed_elsewhere:
        raise ValueError(f"Unknown or externally managed connector {connector_id}")
    connection_id = connector.connection_id
    for f in connector.manifest.settings:
        if f.type == "secret":
            SECRETS.delete(_secret_ref(connection_id, f.key))

    def apply(current: Any) -> dict[str, Any]:
        data = current if isinstance(current, dict) else {}
        data.pop(connection_id, None)
        return data

    locked_json_update(CONNECTORS_FILE, apply)

    _forget_settings_cache()
    connector.reset_state()
    _invalidate_maps()


# --------------------------------------------------------------------------- discovery & lookup

_LOCK = threading.Lock()
_CONNECTORS: dict[str, Connector] = {}
_FAILED: dict[str, str] = {}
_DISCOVERED = False


def _load_one(package: str, name: str) -> Connector:
    """Import, validate and instantiate one connector package. Raises ValueError/Exception on any problem."""
    module = importlib.import_module(f"{package}.{name}")
    manifest = getattr(module, "MANIFEST", None)
    cls = getattr(module, "CONNECTOR", None)
    if not isinstance(manifest, ConnectorManifest):
        raise ValueError("MANIFEST is missing or is not a ConnectorManifest")
    if not isinstance(cls, type) or not issubclass(cls, Connector):
        raise ValueError("CONNECTOR is missing or is not a Connector subclass")
    problems = manifest.validate()
    if problems:
        raise ValueError("; ".join(problems))
    if getattr(getattr(cls, "manifest", None), "connector_id", None) != manifest.connector_id:
        raise ValueError("CONNECTOR.manifest does not match MANIFEST")
    instance = cls()
    missing = [
        c
        for c in manifest.capabilities
        if c in CAPABILITY_PROTOCOLS and not isinstance(instance, CAPABILITY_PROTOCOLS[c])
    ]
    if missing:
        raise ValueError(f"claims {missing} without implementing them")
    return instance


# v0.10.22: only these connector packages are imported. Importing runs a package's top-level
# code inside the process that holds every credential, so an unexpected folder dropped into
# app/integrations/connectors/ must never be executed just because it exists.
# tools/new_connector.py reminds you to add new packages here.
SHIPPED_CONNECTORS = frozenset({"fortigate", "mist", "paloalto_scm", "panorama", "silverpeak_orchestrator", "snmp"})


def discover() -> dict[str, Connector]:
    """Import every package under app/integrations/connectors that exposes MANIFEST + CONNECTOR.

    A connector that fails to import, validate or start is logged, skipped and listed in
    :data:`_FAILED` (shown as a "failed to load" card) — it never stops the others from loading.
    """
    global _DISCOVERED
    with _LOCK:
        if _DISCOVERED:
            return _CONNECTORS
        from app.integrations import connectors as pkg

        try:
            # v0.10.50: the allow-list says what loads. Listing the folder only finds packages dropped in beside them,
            # which are reported and never imported. (A compiled build has no package folders to list.)
            for info in pkgutil.iter_modules(pkg.__path__):
                if info.ispkg and not info.name.startswith("_") and info.name not in SHIPPED_CONNECTORS:
                    log.warning("Connector package %s is not on the allow-list; not imported", info.name)
                    _FAILED[info.name] = "Not loaded: package is not on NodeWatch's connector allow-list"
            for name in sorted(SHIPPED_CONNECTORS):
                try:
                    instance = _load_one(pkg.__name__, name)
                    connector_id = instance.manifest.connector_id
                    if connector_id in _CONNECTORS:
                        raise ValueError(f"duplicate connector_id {connector_id!r} (already used by another package)")
                    _CONNECTORS[connector_id] = instance
                    if registry.descriptor(connector_id) is None:
                        registry.register(instance.descriptor, lambda inst=instance: inst)
                except Exception as exc:  # noqa: BLE001 - one broken connector must not take NodeWatch down
                    log.exception("Connector %s failed to load", name)
                    _FAILED[name] = f"{type(exc).__name__}: {redact_text(exc)}"[:300]
            _load_extra_connections()
        finally:
            _DISCOVERED = True
        return _CONNECTORS


# --------------------------------------------------------------------------- more connections (v0.10.47, N1)
# A connector's first connection is the connector itself (connection id = connector id). Further connections
# of the same connector (a second Mist org, another FortiGate) are listed in connectors.json under
# "_connections" as {connection_id: {"connector": connector_id, "label": text}} and each gets its own
# instance, settings row and credential-store entries, named by its connection id.
CONNECTIONS_KEY = "_connections"
_CONNECTION_ID_RE = re.compile(r"^[a-z0-9_]+-[0-9]{1,4}$")


def _new_connection(base: Connector, connection_id: str, label: str) -> Connector:
    instance = type(base)()
    instance.connection_id = connection_id
    instance.connection_label = label
    return instance


def _load_extra_connections() -> None:
    """Create the instances of saved extra connections (caller holds _LOCK, after the connectors loaded)."""
    rows = load_connector_settings().get(CONNECTIONS_KEY)
    for connection_id, row in (rows.items() if isinstance(rows, dict) else []):
        base = _CONNECTORS.get(str((row or {}).get("connector") or ""))
        if base is None or not _CONNECTION_ID_RE.match(str(connection_id)) or connection_id in _CONNECTORS:
            continue
        if base.manifest.managed_elsewhere:
            continue  # configured on its own page; more connections of it come with that page (N2)
        try:
            _CONNECTORS[connection_id] = _new_connection(base, connection_id, str(row.get("label") or "")[:80])
        except Exception as exc:  # noqa: BLE001 - one broken connection must not stop the others
            log.warning("Connection %s failed to load: %s", connection_id, redact_text(exc))


def connections_of(connector_id: str) -> list[Connector]:
    """Every connection of a connector, its first one first."""
    return sorted((c for c in discover().values() if c.manifest.connector_id == connector_id),
                  key=lambda c: (not c.is_first_connection, c.connection_id))


def add_connection(connector_id: str, label: str = "") -> Connector:
    """Add another (empty, disabled) connection of a connector; fill it in like the first one."""
    base = get_connector(connector_id)
    if base is None or not base.is_first_connection:
        raise ValueError(f"Unknown connector {connector_id}")
    if base.manifest.managed_elsewhere:
        raise ValueError(f"{base.manifest.product} is configured on its own settings page")
    label = " ".join(str(label or "").split())[:80]
    with _LOCK:
        taken = {c for c in _CONNECTORS}
        number = next(n for n in range(2, 10_000) if f"{connector_id}-{n}" not in taken)
        connection_id = f"{connector_id}-{number}"

        def apply(current: Any) -> dict[str, Any]:
            data = current if isinstance(current, dict) else {}
            rows = data.get(CONNECTIONS_KEY) if isinstance(data.get(CONNECTIONS_KEY), dict) else {}
            rows[connection_id] = {"connector": connector_id, "label": label}
            data[CONNECTIONS_KEY] = rows
            return data

        locked_json_update(CONNECTORS_FILE, apply)
        _forget_settings_cache()
        _CONNECTORS[connection_id] = _new_connection(base, connection_id, label)
    return _CONNECTORS[connection_id]


def remove_connection(connection_id: str) -> None:
    """Delete an extra connection: its settings, its credentials and its entry. The first one is cleared
    with remove_connector_settings instead (the connector itself stays)."""
    connection = get_connector(connection_id)
    if connection is None or connection.is_first_connection:
        raise ValueError(f"Unknown connection {connection_id}")
    remove_connector_settings(connection_id)

    def apply(current: Any) -> dict[str, Any]:
        data = current if isinstance(current, dict) else {}
        rows = data.get(CONNECTIONS_KEY) if isinstance(data.get(CONNECTIONS_KEY), dict) else {}
        rows.pop(connection_id, None)
        data[CONNECTIONS_KEY] = rows
        return data

    locked_json_update(CONNECTORS_FILE, apply)
    _forget_settings_cache()
    with _LOCK:
        _CONNECTORS.pop(connection_id, None)


def load_failures() -> dict[str, str]:
    """{package name: reason} for connectors that could not be loaded."""
    discover()
    return dict(_FAILED)


def get_connector(connector_id: str) -> Connector | None:
    return discover().get(connector_id)


def all_connectors() -> list[Connector]:
    return sorted(
        discover().values(),
        key=lambda c: (c.manifest.category, c.manifest.connector_id, not c.is_first_connection, c.connection_id),
    )


def tls_verification_off() -> list[str]:
    """Enabled connections whose user turned certificate checks off (for the persistent banner, v0.10.22)."""
    names = []
    for c in all_connectors():
        if c.manifest.managed_elsewhere or not any(f.key == "verify_tls" for f in c.manifest.settings):
            continue
        try:
            if c.enabled and c.settings().get("verify_tls") is False:
                names.append(c.manifest.product or c.manifest.connector_id)
        except Exception:  # noqa: BLE001 - a broken connector must not break /api/status
            continue
    return names


# Optional connector hooks (v0.10.45). Features look a hook up with ``hook()`` instead of probing for
# vendor methods with getattr/hasattr, so every optional entry point a connector may offer is listed here.
OPTIONAL_HOOKS: dict[str, str] = {
    "list_device_facts": "NEIGHBORS: (site) -> per-device port, PoE, client and floor facts from statistics already read",
    "list_topology_devices": "NEIGHBORS: (site) -> devices a neighbor source can describe when no inventory covers them",
    "acknowledge_alert": "ALERTS: (alert, note) -> {ok, acked, failed}; acknowledges the alert in the source",
    "warm_up": "start-up: () -> None; must return at once (start a thread) and do nothing when not configured",
}


def hook(connector: Any, name: str) -> Callable[..., Any] | None:
    """The connector's optional ``name`` hook (one of OPTIONAL_HOOKS), or None when it does not offer it."""
    if name not in OPTIONAL_HOOKS:
        raise KeyError(f"unknown connector hook {name!r}")
    fn = getattr(connector, name, None)
    return fn if callable(fn) else None


def warm_up_all() -> None:
    """Start-up: let every connector that offers ``warm_up`` prefetch what the first pages read. Never raises."""
    for c in all_connectors():
        fn = hook(c, "warm_up")
        if fn is None:
            continue
        try:
            fn()
        except Exception:  # noqa: BLE001 - one connector never stops the others
            log.warning("warm-up of %s failed", c.manifest.connector_id, exc_info=True)


def sources(capability: str, *, include_disabled: bool = False) -> list[Connector]:
    """Connected connectors offering ``capability`` — what features iterate over."""
    out = []
    for c in all_connectors():
        if capability not in c.manifest.capabilities:
            continue
        if not include_disabled and not (c.configured and (c.enabled or c.manifest.managed_elsewhere)):
            continue
        out.append(c)
    return out


def gather(capability: str, method: str, *args: Any, **kwargs: Any) -> tuple[list[Any], list[dict[str, Any]]]:
    """Call ``method`` on every source of ``capability``; return (records, [{source, error}]).

    One failing vendor never hides the others' data: its error is reported next to the results.
    """
    records: list[Any] = []
    errors: list[dict[str, Any]] = []
    srcs = sources(capability)

    def run(c: Connector) -> tuple[list[Any], dict[str, Any] | None]:
        started = time.monotonic()
        try:
            return list(getattr(c, method)(*args, **kwargs) or []), None
        except IntegrationError as exc:
            return [], {"source": c.provider_id, "product": c.manifest.product, "error": str(exc)}
        except Exception as exc:  # noqa: BLE001
            log.exception("Connector %s.%s failed", c.provider_id, method)
            return [], {"source": c.provider_id, "product": c.manifest.product, "error": type(exc).__name__}
        finally:
            log.debug("%s.%s took %.2fs", c.provider_id, method, time.monotonic() - started)

    # v0.10.23: vendors are asked at the same time (was one after another, each with its own
    # timeout), so a page waits for the slowest source instead of the sum of all of them.
    # Each task runs in a copy of the caller's context (request principal, etc.). Order of the
    # merged records stays the source order.
    if len(srcs) <= 1:
        outcomes = [run(c) for c in srcs]
    else:
        with ThreadPoolExecutor(max_workers=len(srcs), thread_name_prefix="gather") as pool:
            futures = [pool.submit(contextvars.copy_context().run, run, c) for c in srcs]
            outcomes = [f.result() for f in futures]
    for rows, error in outcomes:
        records.extend(rows)
        if error:
            errors.append(error)
    return records, errors


def connector_state(c: Connector) -> dict[str, str]:
    """connected | ready | disabled | not_configured | error, with a short label for the UI."""
    configured = c.configured
    enabled = c.enabled or (c.manifest.managed_elsewhere and configured)
    health = c.health_state()
    if not configured:
        return {"state": "not_configured", "label": "Not configured"}
    if not enabled:
        return {"state": "disabled", "label": "Disabled"}
    if health.last_error and health.state != "healthy":
        if health.intermittent:
            return {"state": "connected", "label": "Connected · last call failed"}
        return {"state": "error", "label": "Error"}
    if health.state == "healthy":
        return {"state": "connected", "label": "Connected"}
    return {"state": "ready", "label": "Configured"}


_HEAL_LOCK = threading.Lock()
_HEAL_LAST: dict[str, float] = {}
HEAL_INTERVAL_S = 60.0


def heal_in_background(c: Connector) -> None:
    """v0.10.23: a connection shown as Error re-checks itself (at most once a minute) when the
    Connections page is opened, so a recovered network clears the card without Edit + Save."""
    if c.manifest.managed_elsewhere or not c.configured or not c.enabled:
        return
    now = time.monotonic()
    with _HEAL_LOCK:
        if now - _HEAL_LAST.get(c.provider_id, -1e9) < HEAL_INTERVAL_S:
            return
        _HEAL_LAST[c.provider_id] = now

    def run() -> None:
        try:
            result = c.test_connection()
            if result.get("ok"):
                c._health.mark_success()
                mark_verified_here(c.provider_id)
            else:
                log.info("Background check of %s did not pass: %s", c.provider_id, str(result.get("error") or result.get("message") or "")[:200])
        except Exception as exc:  # noqa: BLE001 - background check only
            log.info("Background re-check of %s failed: %s", c.provider_id, type(exc).__name__)

    threading.Thread(target=run, name=f"heal-{c.provider_id}", daemon=True).start()


def verify_all_in_background() -> int:
    """v0.10.35: at start-up every configured, enabled connector checks its connection by itself, so
    Settings shows "Connected" (or the real error) without a manual Re-test. Health lives in memory,
    so before this a fresh start showed "Configured" until the first real read or a Re-test."""
    started = 0
    for c in all_connectors():
        try:
            if c.manifest.managed_elsewhere or not c.configured or not c.enabled:
                continue
            if c.health_state().state == "healthy":
                continue
            heal_in_background(c)
            started += 1
        except Exception as exc:  # noqa: BLE001 - one broken connector must not stop the others
            log.info("Start-up check of %s skipped: %s", getattr(c, "provider_id", "?"), type(exc).__name__)
    if started:
        log.info("Checking %d connection(s) in the background", started)
    return started


# v0.10.32: a Preview connector that has worked on this install is shown as Stable. Preview means "built
# from the vendor's documentation, not yet validated on a live system"; once it has answered here (a passing
# test or real reads) it is validated on this network, so the badge no longer says Preview. Kept on disk so a
# restart (health is in memory) does not bring the Preview badge back.
_VERIFIED_FILE = DATA_ROOT / "state" / "connectors-verified.json"
_verified_cache: dict[str, str] | None = None
_verified_lock = threading.Lock()


def verified_here() -> dict[str, str]:
    global _verified_cache
    with _verified_lock:
        if _verified_cache is None:
            try:
                raw = json.loads(_VERIFIED_FILE.read_text(encoding="utf-8"))
                _verified_cache = {str(k): str(v) for k, v in raw.items()} if isinstance(raw, dict) else {}
            except (OSError, ValueError):
                _verified_cache = {}
        return dict(_verified_cache)


def mark_verified_here(connector_id: str) -> None:
    global _verified_cache
    if connector_id in verified_here():
        return
    stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    def update(current: Any) -> Any:
        data = dict(current) if isinstance(current, dict) else {}
        data.setdefault(connector_id, stamp)
        return data

    try:
        _VERIFIED_FILE.parent.mkdir(parents=True, exist_ok=True)
        saved = locked_json_update(_VERIFIED_FILE, update, default={})
        with _verified_lock:
            _verified_cache = {str(k): str(v) for k, v in (saved or {}).items()}
    except OSError as exc:
        log.info("Could not record that %s works here: %s", connector_id, exc)


def catalog() -> list[dict[str, Any]]:
    """Every connector with its manifest, state and capabilities (Settings › Connections)."""
    rows = []
    verified = verified_here()
    for c in all_connectors():
        try:
            health = c.health_state()
            state = connector_state(c)
            if state.get("state") in {"error", "ready"}:
                heal_in_background(c)
            configured = c.configured
            enabled = c.enabled or (c.manifest.managed_elsewhere and configured)
            values = c.settings() if not c.manifest.managed_elsewhere else {}
        except Exception as exc:  # noqa: BLE001 - one broken connector must not hide the others
            log.warning("Connector %s state unavailable: %s", c.provider_id, type(exc).__name__)
            health, state, configured, enabled, values = (
                ProviderHealth(state="degraded", last_error="State unavailable"),
                {"state": "error", "label": "Error"},
                False,
                False,
                {},
            )
        rows.append(
            {
                **c.manifest.public_dict(),
                # Connection identity (v0.10.56, N1): connector_id is the vendor code; connection_id addresses one
                # connection of it (equal to connector_id for the first one, so single-connection rows are unchanged).
                "connection_id": c.connection_id,
                "connection_label": c.connection_label,
                "is_first_connection": c.is_first_connection,
                "category_label": CATEGORY_LABELS.get(c.manifest.category, c.manifest.category),
                "capability_labels": {cap: CAPABILITY_LABELS.get(cap, cap) for cap in c.manifest.capabilities},
                "configured": configured,
                "enabled": enabled,
                "values": values,
                "health": health.public_dict,
                "inventory_switch": bool(getattr(c, "inventory_switch", False)),
                "inventory_enabled": bool(getattr(c, "inventory_enabled", True)),
                "features": {
                    cap: [
                        {"tool": t, "label": label, "what": what} for t, label, what in CAPABILITY_FEATURES.get(cap, ())
                    ]
                    for cap in c.manifest.capabilities
                },
                **state,
            }
        )
        row = rows[-1]
        if row.get("state") == "connected" and health.state == "healthy" and c.provider_id not in verified:
            mark_verified_here(c.provider_id)
            verified = verified_here()
        row["verified_here"] = verified.get(c.provider_id, "")
        # The badge to show: Stable when validated by its authors or working on this network.
        row["maturity_shown"] = "stable" if (row.get("maturity") == "stable" or row["verified_here"]) else row.get("maturity", "")
    for name, reason in sorted(load_failures().items()):
        rows.append(
            {
                "connector_id": f"failed_{name}",  # never collides with a loaded connector's id
                "package": name,
                "vendor": "",
                "product": name,
                "category": "other",
                "category_label": CATEGORY_LABELS["other"],
                "capabilities": [],
                "capability_labels": {},
                "settings": [],
                "description": "This connector could not be loaded, so NodeWatch is not using it.",
                "docs_url": "",
                "maturity": "",
                "managed_elsewhere": True,
                "settings_location": "",
                "configured": False,
                "enabled": False,
                "values": {},
                "health": ProviderHealth(state="failed", last_error=reason).public_dict,
                "load_error": reason,
                "setup": None,
                "features": {},
                "state": "load_failed",
                "label": "Failed to load",
            }
        )
    return rows


def available_capabilities() -> dict[str, Any]:
    """Which capabilities at least one connected source offers (the UI hides the rest)."""
    out: dict[str, Any] = {}
    for cap in ALL_CAPABILITIES:
        names = [c.provider_id for c in sources(cap)]
        out[cap] = {"available": bool(names), "sources": names, "label": CAPABILITY_LABELS.get(cap, cap)}
    return out


def reset_for_tests() -> None:
    global _DISCOVERED
    with _LOCK:
        _CONNECTORS.clear()
        _FAILED.clear()
        _DISCOVERED = False
