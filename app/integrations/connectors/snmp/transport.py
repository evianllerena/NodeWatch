"""SNMP transports for the generic SNMP connector: the real one (pysnmp) and a fixture one for tests.

Both implement :class:`SnmpTransport`, so the connector logic and the contract tests never need a
network. Read-only by construction: the only operations are GET and GETBULK (walk). There is no
SET code path anywhere in this package.

The real transport imports ``pysnmp`` lazily: NodeWatch starts and the connector is listed even
when the library is missing; polling then fails with a clear "SNMP support component missing" error.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import ipaddress
import json
import threading
import time
import warnings
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol, Sequence, runtime_checkable

from app.integrations.base import IntegrationError
from app.integrations.connectors.snmp.mibs import oid_key

AUTH_PROTOCOLS = ("SHA-256", "SHA-384", "SHA-512", "SHA-1 (legacy)")
PRIV_PROTOCOLS = ("AES-128", "AES-256", "AES-256 (Cisco key extension)")
MISSING_COMPONENT = (
    "SNMP support component missing: the 'pysnmp' package (and 'cryptography' for AES privacy) is not "
    "installed in NodeWatch's runtime. Update NodeWatch with a build that includes it."
)


@dataclass(frozen=True)
class SnmpCredentials:
    """SNMPv3 USM credentials. ``repr`` never shows the passphrases."""

    username: str
    auth_protocol: str = "SHA-256"
    auth_passphrase: str = field(default="", repr=False)
    priv_protocol: str = "AES-128"  # "" = authNoPriv (only with the explicit insecure toggle)
    priv_passphrase: str = field(default="", repr=False)
    context: str = ""

    @property
    def secrets(self) -> tuple[str, ...]:
        return tuple(s for s in (self.auth_passphrase, self.priv_passphrase) if s)

    @property
    def security_level(self) -> str:
        return "authPriv" if self.priv_protocol else "authNoPriv"


@runtime_checkable
class SnmpTransport(Protocol):
    """What the connector needs from SNMP: one read pass against one host.

    ``fetch`` GETs the ``get`` scalars (absent objects are simply missing from the answer) and walks
    every subtree in ``walk`` with GETBULK (at most ``max_rows`` objects per subtree), finishing within
    ``timeout`` seconds when given (the rest of the host's deadline). It returns one
    flat ``{oid: value}`` dict (OIDs without a leading dot; value model in ``mibs``) and records the
    call in ``calls`` as ``("GET", "snmp://<host>", {"get": n, "walk": [...]}, None)`` — every SNMP
    read PDU (Get/GetBulk) is a read, so the connector contract's "only reads" check applies as is.
    Failures raise :class:`IntegrationError` without credentials in the message.
    """

    calls: list[tuple[str, str, dict[str, Any], Any]]

    def fetch(
        self,
        host: str,
        *,
        get: Sequence[str] = (),
        walk: Sequence[str] = (),
        max_rows: int = 10000,
        timeout: float | None = None,
    ) -> dict[str, Any]: ...


# --------------------------------------------------------------------------- fixture transport


def decode_fixture_value(value: Any) -> Any:
    """Fixture JSON → value model: ints stay ints; "hex:…" → bytes; "ip:…"/"oid:…" → str; text → bytes."""
    if isinstance(value, bool) or value is None:
        raise ValueError("fixture values must be ints or strings")
    if isinstance(value, int):
        return value
    text = str(value)
    if text.startswith("hex:"):
        return bytes.fromhex(text[4:].replace(":", "").replace(" ", ""))
    if text.startswith("ip:") or text.startswith("oid:"):
        return text.split(":", 1)[1]
    return text.encode("utf-8")


def load_snmp_fixture(path: str | Path) -> dict[str, Any]:
    """Read an snmpwalk-style fixture: {"oids": {"1.3.6.1.2.1.1.5.0": "name", …}}."""
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    return {oid.strip("."): decode_fixture_value(v) for oid, v in raw["oids"].items()}


class FixtureSnmpTransport:
    """Serves GET/walks from recorded agent data per host. Never touches the network.

    ``hosts`` maps host → {oid: value} (or an Exception to raise for that host). Unknown hosts time
    out, like a silent address in a range would.
    """

    def __init__(self, hosts: dict[str, Any], *, delay: float = 0.0) -> None:
        self.hosts = dict(hosts)
        self.delay = delay
        self.gate: threading.Event | None = None
        self.calls: list[tuple[str, str, dict[str, Any], Any]] = []
        self._lock = threading.Lock()
        self.active = 0
        self.max_active = 0

    def fetch(
        self,
        host: str,
        *,
        get: Sequence[str] = (),
        walk: Sequence[str] = (),
        max_rows: int = 10000,
        timeout: float | None = None,
    ) -> dict[str, Any]:
        with self._lock:
            self.calls.append(
                ("GET", f"snmp://{host}", {"get": len(get), "walk": list(walk), "timeout": timeout}, None)
            )
            self.active += 1
            self.max_active = max(self.max_active, self.active)
        try:
            if self.delay:
                time.sleep(self.delay)
            if self.gate is not None:  # tests: hold the "agent" until released
                self.gate.wait(30)
            data = self.hosts.get(host)
            if data is None:
                raise IntegrationError(f"SNMP: no response from {host} (timeout)", code="PROVIDER_UNAVAILABLE")
            if isinstance(data, Exception):
                raise data
            out = {oid: data[oid] for oid in get if oid in data}
            for root in walk:
                prefix = root + "."
                rows = sorted((oid for oid in data if oid.startswith(prefix)), key=oid_key)[:max_rows]
                out.update({oid: data[oid] for oid in rows})
            return out
        finally:
            with self._lock:
                self.active -= 1


# --------------------------------------------------------------------------- pysnmp transport


def _load_pysnmp(need_privacy: bool) -> Any:
    # pysnmp 7.1 still builds AES-CFB from cryptography's primitives module, which warns about the
    # move to "decrepit" on every process start; the pinned cryptography release still provides it.
    warnings.filterwarnings("ignore", message=r"CFB has been moved", module=r"pysnmp\.")
    try:
        from pysnmp.hlapi.v3arch import asyncio as hl  # noqa: PLC0415 - lazy: optional component
    except Exception:  # noqa: BLE001 - ImportError or a broken install
        raise IntegrationError(MISSING_COMPONENT, code="DEPENDENCY_MISSING") from None
    if need_privacy:
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher  # noqa: F401, PLC0415
        except Exception:  # noqa: BLE001
            raise IntegrationError(MISSING_COMPONENT, code="DEPENDENCY_MISSING") from None
    return hl


def pysnmp_available() -> bool:
    try:
        _load_pysnmp(True)
    except IntegrationError:
        return False
    return True


_AUTH_ERRORS = {
    "UnknownUserName": "the SNMPv3 user is unknown to the device",
    "WrongDigest": "authentication failed (wrong auth passphrase or auth protocol)",
    "AuthenticationError": "authentication failed (wrong auth passphrase or auth protocol)",
    "DecryptionError": "decryption failed (wrong privacy passphrase or privacy protocol)",
    "UnsupportedSecurityLevel": "the device does not accept this security level for the user",
    "NotInTimeWindow": "the device rejected the request time window; retry",
}


class PysnmpTransport:
    """SNMPv3 over UDP with pysnmp's asyncio API (one short-lived engine per host pass)."""

    def __init__(
        self,
        credentials: SnmpCredentials,
        *,
        port: int = 161,
        timeout: float = 3.0,
        retries: int = 1,
        max_repetitions: int = 25,
        host_budget: float = 60.0,
    ) -> None:
        self.credentials = credentials
        self.port = port
        self.timeout = timeout
        self.retries = retries
        self.max_repetitions = max_repetitions
        self.host_budget = host_budget
        self.calls: list[tuple[str, str, dict[str, Any], Any]] = []
        self._lock = threading.Lock()

    def _fail(self, message: str, code: str = "PROVIDER_ERROR") -> IntegrationError:
        from app.core.security import redact_text  # noqa: PLC0415

        return IntegrationError(redact_text(f"SNMP: {message}", *self.credentials.secrets), code=code)

    def fetch(
        self,
        host: str,
        *,
        get: Sequence[str] = (),
        walk: Sequence[str] = (),
        max_rows: int = 10000,
        timeout: float | None = None,
    ) -> dict[str, Any]:
        with self._lock:
            self.calls.append(("GET", f"snmp://{host}", {"get": len(get), "walk": list(walk)}, None))
        hl = _load_pysnmp(bool(self.credentials.priv_protocol))
        coro = self._fetch(hl, host, tuple(get), tuple(walk), max_rows)
        try:
            budget = self.host_budget if timeout is None else max(0.1, min(self.host_budget, timeout))
            return _run(asyncio.wait_for(coro, budget))
        except IntegrationError:
            raise
        except (asyncio.TimeoutError, TimeoutError):
            raise self._fail(f"{host} did not finish within its time limit", "PROVIDER_UNAVAILABLE") from None
        except Exception as exc:  # noqa: BLE001 - library errors become IntegrationError
            raise self._fail(f"{host}: {type(exc).__name__}: {exc}") from None

    # -- internals ---------------------------------------------------------------------------------
    def _auth(self, hl: Any) -> Any:
        c = self.credentials
        auth = {
            "SHA-256": hl.usmHMAC192SHA256AuthProtocol,
            "SHA-384": hl.usmHMAC256SHA384AuthProtocol,
            "SHA-512": hl.usmHMAC384SHA512AuthProtocol,
            "SHA-1 (legacy)": hl.usmHMACSHAAuthProtocol,
        }.get(c.auth_protocol)
        if auth is None:
            raise self._fail("unsupported auth protocol", "CONFIGURATION_ERROR")
        if not c.priv_protocol:
            return hl.UsmUserData(c.username, authKey=c.auth_passphrase, authProtocol=auth)
        priv = {
            "AES-128": hl.usmAesCfb128Protocol,
            "AES-256": hl.usmAesBlumenthalCfb256Protocol,
            "AES-256 (Cisco key extension)": hl.usmAesCfb256Protocol,
        }.get(c.priv_protocol)
        if priv is None:
            raise self._fail("unsupported privacy protocol", "CONFIGURATION_ERROR")
        return hl.UsmUserData(
            c.username, authKey=c.auth_passphrase, privKey=c.priv_passphrase, authProtocol=auth, privProtocol=priv
        )

    def _check(self, host: str, error_indication: Any) -> None:
        if not error_indication:
            return
        name = type(error_indication).__name__
        if name in _AUTH_ERRORS:
            raise self._fail(f"{host}: {_AUTH_ERRORS[name]}", "AUTHENTICATION_FAILED")
        if name == "RequestTimedOut":
            raise self._fail(
                f"no response from {host} (timeout; check address, port, ACLs and SNMPv3 user)", "PROVIDER_UNAVAILABLE"
            )
        raise self._fail(f"{host}: {error_indication}", "PROVIDER_ERROR")

    async def _fetch(self, hl: Any, host: str, get: tuple[str, ...], walk: tuple[str, ...], max_rows: int) -> dict:
        engine = hl.SnmpEngine()
        try:
            target_cls = hl.Udp6TransportTarget if ipaddress.ip_address(host).version == 6 else hl.UdpTransportTarget
            target = await target_cls.create((host, self.port), timeout=self.timeout, retries=self.retries)
            auth = self._auth(hl)
            context = hl.ContextData(contextName=self.credentials.context.encode("utf-8"))
            out: dict[str, Any] = {}
            for chunk in [get[i : i + 10] for i in range(0, len(get), 10)]:
                err, status, _index, var_binds = await hl.get_cmd(
                    engine,
                    auth,
                    target,
                    context,
                    *[hl.ObjectType(hl.ObjectIdentity(o)) for o in chunk],
                    lookupMib=False,
                )
                self._check(host, err)
                if status:
                    continue  # an error-status on a GET of scalars: treat the chunk as absent
                for name, value in var_binds:
                    converted = _convert(value)
                    if converted is not _ABSENT:
                        out[_oid(name)] = converted
            for root in walk:
                out.update(await self._walk(hl, engine, auth, target, context, host, root, max_rows))
            return out
        finally:
            try:
                engine.close_dispatcher()
                await asyncio.sleep(0)  # let the dispatcher's cancelled timer task finish before the loop closes
            except Exception:  # noqa: BLE001
                pass

    async def _walk(self, hl, engine, auth, target, context, host, root, max_rows) -> dict[str, Any]:  # noqa: ANN001
        prefix = root + "."
        rows: dict[str, Any] = {}
        current, last = root, oid_key(root)
        while len(rows) < max_rows:
            err, status, _index, var_binds = await hl.bulk_cmd(
                engine,
                auth,
                target,
                context,
                0,
                self.max_repetitions,
                hl.ObjectType(hl.ObjectIdentity(current)),
                lookupMib=False,
            )
            self._check(host, err)
            if status or not var_binds:
                break
            done = False
            for name, value in var_binds:
                oid = _oid(name)
                key = oid_key(oid)
                converted = _convert(value)
                if not oid.startswith(prefix) or converted is _ABSENT or key <= last:
                    done = True  # left the subtree, end of MIB, or a non-increasing OID (broken agent)
                    break
                rows[oid] = converted
                current, last = oid, key
                if len(rows) >= max_rows:
                    break
            if done:
                break
        return rows


_ABSENT = object()


def _oid(name: Any) -> str:
    try:
        return ".".join(str(x) for x in tuple(name))
    except TypeError:
        return str(name).strip(".")


def _convert(value: Any) -> Any:
    """pysnmp/pyasn1 value → connector value model (see ``mibs``)."""
    kind = type(value).__name__
    if kind in ("NoSuchObject", "NoSuchInstance", "EndOfMibView", "Null"):
        return _ABSENT
    if kind == "IpAddress":
        return str(ipaddress.IPv4Address(bytes(value.asOctets())))
    if kind == "ObjectIdentifier" or kind == "ObjectName":
        return ".".join(str(x) for x in tuple(value))
    if hasattr(value, "asOctets"):
        return bytes(value.asOctets())
    try:
        return int(value)
    except (TypeError, ValueError):
        return str(value)


_THREADS = concurrent.futures.ThreadPoolExecutor(max_workers=8, thread_name_prefix="nodewatch-snmp-loop")


def _run(coro: Any) -> Any:
    """Run a coroutine from sync code, also when the calling thread already runs an event loop."""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    return _THREADS.submit(asyncio.run, coro).result()
