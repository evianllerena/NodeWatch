"""PAN-OS XML API transport for Panorama (and, through ``target=<serial>``, its managed firewalls).

This module is the *transport* layer only: build requests, send them, parse and check the XML
answer, poll asynchronous jobs, cache briefly. It knows nothing about NodeWatch records — that is
``reader.py`` (read capabilities today) and, later, ``writer.py`` (the change module).

Official references (PAN-OS and Panorama API guide, docs.paloaltonetworks.com):

* API key in the ``X-PAN-KEY`` HTTP header ("API Authentication and Security";
  https://docs.paloaltonetworks.com/pan-os/11-0/pan-os-panorama-api/about-the-pan-os-xml-api/structure-of-a-pan-os-xml-api-request/api-authentication-and-security
  — "Use the custom HTTP header, X-PAN-KEY: <key>"). NodeWatch never puts the key in the URL.
* Request shape ``/api/?type=op&cmd=<xml>`` and ``target=<serial>`` to run a command on a managed
  firewall through Panorama ("Query a Firewall from Panorama (API)";
  https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-panorama-api/pan-os-xml-api-use-cases/query-a-firewall-from-panorama-api).
* Error answers ``<response status="error" code="N">`` and their codes ("PAN-OS XML API Error Codes";
  https://docs.paloaltonetworks.com/pan-os/10-2/pan-os-panorama-api/get-started-with-the-pan-os-xml-api/pan-os-xml-api-error-codes).
* Log queries are asynchronous: ``type=log`` returns a job id, ``type=log&action=get&job-id=N`` returns
  the job and, when ``FIN``, the logs ("Retrieve Logs (API)" in the same guide).

READ-ONLY BY CONSTRUCTION: :func:`assert_read_only` rejects every request that could change a
device before it is sent — ``type=config`` with any action other than ``get``/``show``,
``type=commit``, ``import``, ``user-id``, and operational commands other than ``<show>`` and the two
read-only ``<test>`` lookups. The future change module must use its own, separately reviewed client
(see ``writer.py``); it must not loosen this guard.
"""

from __future__ import annotations

import re
import threading
import time
import xml.etree.ElementTree as ET
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlparse
from urllib.request import Request

from app.core.version import APP_VERSION
from app.integrations import api_timing
from app.integrations.base import IntegrationError
from app.integrations.connectors.sdk import MAX_RESPONSE_BYTES, HttpJsonClient

API_PATH = "/api/"

# Operational commands NodeWatch may send: <show>…</show>, and these read-only <test> lookups.
READ_ONLY_TESTS = frozenset({"security-policy-match", "nat-policy-match"})
READ_ONLY_CONFIG_ACTIONS = frozenset({"get", "show"})
READ_ONLY_LOG_ACTIONS = frozenset({"", "get"})  # submit a query / fetch its job (no "finish")
ALLOWED_TYPES = frozenset({"op", "config", "log", "version"})

# https://docs.paloaltonetworks.com/pan-os/10-2/pan-os-panorama-api/get-started-with-the-pan-os-xml-api/pan-os-xml-api-error-codes
PAN_ERROR_CODES = {
    "400": ("Bad request", "PROVIDER_ERROR"),
    "403": ("Forbidden (invalid API key or insufficient admin rights)", "AUTHENTICATION_FAILED"),
    "1": ("Unknown command", "UNSUPPORTED"),
    "6": ("Bad XPath", "PROVIDER_ERROR"),
    "7": ("Object not present", "NOT_FOUND"),
    "12": ("Invalid object", "PROVIDER_ERROR"),
    "13": ("Object not found", "NOT_FOUND"),
    "14": ("Operation not possible", "PROVIDER_ERROR"),
    "15": ("Operation denied", "PERMISSION_DENIED"),
    "16": ("Unauthorized (the admin role lacks this XML API permission)", "PERMISSION_DENIED"),
    "17": ("Invalid command", "UNSUPPORTED"),
    "18": ("Malformed command", "PROVIDER_ERROR"),
    "22": ("Session timed out", "AUTHENTICATION_FAILED"),
}

_UNSAFE_XML = re.compile(rb"<!\s*(DOCTYPE|ENTITY)", re.IGNORECASE)


class ReadOnlyViolation(IntegrationError):
    """A request that could change Panorama or a firewall was refused before it was sent."""

    def __init__(self, message: str) -> None:
        super().__init__(message, code="READ_ONLY", status_code=None)


class PanApiError(IntegrationError):
    """``<response status="error">``: carries the PAN-OS error code (``pan_code``)."""

    def __init__(self, message: str, *, pan_code: str = "", code: str = "PROVIDER_ERROR") -> None:
        super().__init__(message, code=code, status_code=None)
        self.pan_code = pan_code


# --------------------------------------------------------------------------- safe XML


def parse_xml(data: str | bytes, *, what: str = "Panorama answer") -> ET.Element:
    """Parse untrusted XML: no DTDs, no entities (blocks XXE and entity-expansion bombs), bounded size."""
    raw = data.encode("utf-8") if isinstance(data, str) else bytes(data or b"")
    if len(raw) > MAX_RESPONSE_BYTES:
        raise IntegrationError(f"{what} is too large", code="RESPONSE_TOO_LARGE")
    # The DOCTYPE/ENTITY guard below reads ASCII. Refuse multi-byte encodings outright so it
    # can never be bypassed by a UTF-16/32 body (v0.10.22, defence in depth: the transport
    # also decodes as UTF-8 first).
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff") or raw[:4] in (b"\x00\x00\xfe\xff", b"\xff\xfe\x00\x00") or b"\x00" in raw:
        raise IntegrationError(f"{what} is not UTF-8 XML; refused", code="PROVIDER_ERROR")
    if _UNSAFE_XML.search(raw):
        raise IntegrationError(f"{what} contains a DOCTYPE/ENTITY declaration; refused", code="PROVIDER_ERROR")
    try:
        return ET.fromstring(raw)
    except ET.ParseError as exc:
        raise IntegrationError(f"{what} is not valid XML ({exc})", code="PROVIDER_ERROR") from None


def text(node: ET.Element | None, path: str = "") -> str:
    """Stripped text of ``node`` (or of ``node.find(path)``); '' when absent."""
    if node is None:
        return ""
    target = node.find(path) if path else node
    if target is None or target.text is None:
        return ""
    return target.text.strip()


def entries(node: ET.Element | None, path: str = "entry") -> list[ET.Element]:
    return [] if node is None else list(node.findall(path))


def op_root(cmd: str) -> ET.Element:
    try:
        return parse_xml(cmd, what="operational command")
    except IntegrationError:
        raise ReadOnlyViolation("NodeWatch only sends well-formed XML operational commands") from None


def assert_read_only(params: dict[str, Any]) -> None:
    """Refuse anything that is not a pure read. Raises :class:`ReadOnlyViolation`."""
    kind = str(params.get("type") or "").strip().lower()
    if kind not in ALLOWED_TYPES:
        raise ReadOnlyViolation(f"type={kind or '(none)'} is not allowed: NodeWatch's Panorama connection is read-only")
    if kind == "config":
        action = str(params.get("action") or "").strip().lower()
        if action not in READ_ONLY_CONFIG_ACTIONS:
            raise ReadOnlyViolation(f"type=config&action={action or '(none)'} would change configuration; refused")
    elif kind == "log":
        action = str(params.get("action") or "").strip().lower()
        if action not in READ_ONLY_LOG_ACTIONS:
            raise ReadOnlyViolation(f"type=log&action={action} is not a read; refused")
    elif kind == "op":
        root = op_root(str(params.get("cmd") or ""))
        tag = root.tag.lower()
        if tag == "show":
            return
        children = list(root)
        if tag == "test" and len(children) == 1 and children[0].tag.lower() in READ_ONLY_TESTS:
            return
        raise ReadOnlyViolation(f"operational command <{root.tag}> is not a read-only show/test; refused")


# --------------------------------------------------------------------------- transport


class PanXmlTransport(HttpJsonClient):
    """HTTPS transport for ``/api/``: same safety rules as :class:`HttpJsonClient` (https only, TLS
    verified unless the user turned it off, private CA file, timeouts, no redirects, size cap, secrets
    scrubbed from errors) but returns the raw XML text instead of JSON."""

    def __init__(self, base_url: str, *, api_key: str, **kwargs: Any) -> None:
        super().__init__(base_url, headers={"X-PAN-KEY": api_key, "Accept": "application/xml"}, **kwargs)

    def request(self, method: str, path: str, *, params: dict[str, Any] | None = None, body: Any = None) -> Any:
        if body is not None or method.upper() != "GET":
            raise ReadOnlyViolation("the Panorama read client only sends GET requests")
        assert_read_only(params or {})  # second line of defence; PanoramaClient checks first
        query = {k: v for k, v in (params or {}).items() if v is not None and v != ""}
        url = self.base_url + path + ("?" + urlencode(query) if query else "")
        headers = {**self._headers, "User-Agent": f"NodeWatch/{APP_VERSION}"}
        req = Request(url, method="GET", headers=headers)
        where = f"type={query.get('type', '')}"
        started, ok = time.perf_counter(), False
        try:
            with self._opener.open(req, timeout=self.timeout) as resp:
                body_bytes = resp.read(self.max_bytes + 1)
            ok = True
        except HTTPError as exc:
            status = int(exc.code)
            if 300 <= status < 400:
                raise self._fail(
                    f"{where} was redirected (HTTP {status}); check the Panorama URL", status=status
                ) from None
            code = {401: "AUTHENTICATION_FAILED", 403: "AUTHENTICATION_FAILED", 429: "RATE_LIMITED"}.get(
                status, "PROVIDER_ERROR"
            )
            hint = " — check the API key and the admin role's XML API permissions" if status in (401, 403) else ""
            raise self._fail(f"{where} → HTTP {status}{hint}", code=code, status=status) from None
        except URLError as exc:
            raise self._fail(
                f"cannot reach {urlparse(self.base_url).hostname} ({exc.reason})", code="PROVIDER_UNAVAILABLE"
            ) from None
        except (TimeoutError, OSError) as exc:
            raise self._fail(f"{where} failed ({exc})", code="PROVIDER_UNAVAILABLE") from None
        finally:  # Support diagnostics timing like every other connector (v0.10.22; request type only)
            api_timing.note(self.product, "GET", f"{path}:{query.get('type', '')}", (time.perf_counter() - started) * 1000, ok)
        if len(body_bytes) > self.max_bytes:
            raise self._fail(
                f"{where} answered more than {self.max_bytes // (1024 * 1024)} MB", code="RESPONSE_TOO_LARGE"
            )
        return body_bytes.decode("utf-8", errors="replace")


# --------------------------------------------------------------------------- client


class PanoramaClient:
    """Read-only PAN-OS XML API client: op/show/get with optional ``target`` serial, error parsing,
    job polling and a short cache. ``transport`` is a :class:`PanXmlTransport` (or the fixture fake)."""

    def __init__(
        self,
        transport: Any,
        *,
        cache_seconds: float = 30.0,
        product: str = "Panorama",
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.transport = transport
        self.cache_seconds = max(0.0, float(cache_seconds))
        self.product = product
        self._sleep = sleep
        self._cache: dict[tuple, tuple[float, ET.Element]] = {}
        self._lock = threading.Lock()

    # ---- core ---------------------------------------------------------------------------------
    def request(self, params: dict[str, Any], *, cache: bool = True) -> ET.Element:
        """Send one read request; return the ``<response>`` element (status checked)."""
        assert_read_only(params)
        key = tuple(sorted((k, str(v)) for k, v in params.items() if v not in (None, "")))
        now = time.monotonic()
        if cache and self.cache_seconds:
            with self._lock:
                hit = self._cache.get(key)
                if hit and now - hit[0] < self.cache_seconds:
                    return hit[1]
        raw = self.transport.request("GET", API_PATH, params={k: v for k, v in params.items() if v not in (None, "")})
        root = parse_xml(raw if isinstance(raw, (str, bytes)) else str(raw or ""), what=f"{self.product} answer")
        self.check(root, params)
        if cache and self.cache_seconds:
            with self._lock:
                if len(self._cache) > 512:
                    self._cache.clear()
                self._cache[key] = (now, root)
        return root

    def check(self, root: ET.Element, params: dict[str, Any]) -> None:
        if root.tag != "response":
            raise PanApiError(f"{self.product}: unexpected answer <{root.tag}>")
        if (root.get("status") or "").lower() == "success":
            return
        pan_code = root.get("code") or ""
        name, code = PAN_ERROR_CODES.get(pan_code, ("error", "PROVIDER_ERROR"))
        lines = [t.strip() for t in root.itertext() if t and t.strip()]
        detail = " ".join(" ".join(lines).split())[:240]
        where = "on firewall " + str(params["target"]) if params.get("target") else ""
        message = f"{self.product}: {name}" + (f" (code {pan_code})" if pan_code else "")
        message += f" {where}".rstrip() + (f": {detail}" if detail else "")
        raise PanApiError(message, pan_code=pan_code, code=code)

    def clear_cache(self) -> None:
        with self._lock:
            self._cache.clear()

    # ---- reads --------------------------------------------------------------------------------
    def op(self, cmd: str, *, target: str = "", vsys: str = "", cache: bool = True) -> ET.Element:
        """Run an operational ``<show>``/read-only ``<test>`` command; returns ``<result>`` (maybe empty)."""
        root = self.request({"type": "op", "cmd": cmd, "target": target, "vsys": vsys}, cache=cache)
        result = root.find("result")
        return result if result is not None else ET.Element("result")

    def config_get(self, xpath: str, *, running: bool = False, target: str = "") -> ET.Element:
        """Read candidate (``get``) or running (``show``) configuration at ``xpath``."""
        root = self.request(
            {"type": "config", "action": "show" if running else "get", "xpath": xpath, "target": target}
        )
        result = root.find("result")
        return result if result is not None else ET.Element("result")

    def log_query(
        self,
        log_type: str,
        query: str = "",
        *,
        nlogs: int = 50,
        skip: int = 0,
        target: str = "",
        timeout_s: float = 20.0,
        interval_s: float = 1.0,
    ) -> list[ET.Element]:
        """Asynchronous log query: submit, then poll ``action=get`` until the job is FIN (bounded)."""
        submitted = self.request(
            {
                "type": "log",
                "log-type": log_type,
                "query": query,
                "nlogs": max(1, min(int(nlogs), 500)),
                "target": target,
                **({"skip": int(skip)} if skip else {}),
            },
            cache=False,
        )
        job_id = text(submitted, "result/job")
        if not job_id:
            raise PanApiError(f"{self.product}: log query did not return a job id")
        deadline = time.monotonic() + max(1.0, timeout_s)
        while True:
            answer = self.request({"type": "log", "action": "get", "job-id": job_id, "target": target}, cache=False)
            status = text(answer, "result/job/status").upper()
            if status == "FIN":
                return entries(answer.find("result/log/logs"))
            if time.monotonic() >= deadline:
                raise PanApiError(
                    f"{self.product}: log query job {job_id} did not finish in {timeout_s:.0f} s", code="TIMEOUT"
                )
            self._sleep(interval_s)

    # ---- writes: deliberately absent ----------------------------------------------------------
    def set_config(self, *_: Any, **__: Any) -> None:
        raise ReadOnlyViolation("configuration changes are not implemented (see panorama/writer.py)")

    edit_config = delete_config = set_config

    def commit(self, *_: Any, **__: Any) -> None:
        raise ReadOnlyViolation("commit / commit-all are not implemented (see panorama/writer.py)")

    commit_all = commit
