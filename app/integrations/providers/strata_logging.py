"""Strata Logging Service provider for Traffic & Sessions.

NodeWatch 0.10.7 queries firewall traffic logs through the Strata Cloud Manager
Log Viewer API, the same API the SCM web console uses:

    POST https://<region>.api.prismaaccess.com/api/sase/v3.0/resource/query/logviewer/firewall_traffic
    Authorization: Bearer <Common Services OAuth token, scope tsg_id:<TSG>>
    Prisma-Tenant: <TSG ID>[:<sub-tenant ID>]

Request body (captured from SCM Log Viewer)::

    {"filter": {"rules": [{"property": "event_time", "operator": "between",
                           "values": [<start µs>, <end µs>]}, ...]},
     "orderBy": {"properties": [{"property": "time_generated",
                                 "sort": {"sequence": 1, "order": "desc"}}]},
     "pagination": {"page_size": N, "page_number": P},
     "count": N}

Response: ``{"header": {"dataCount": n, "status": {"subCode": 200}, ...}, "data": [...]}``.

Earlier releases called ``/logging-service/v1/queries`` on api.strata.paloaltonetworks.com.
That is the retired Logging Service v1 API; it does not accept Common Services tokens,
which is why every query returned HTTP 403 "Access denied".

This API is what the SCM console uses but Palo Alto does not publish it as a
supported public API, so field names may change. Everything is read-only.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import secrets
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request

from app.core.security import redact_text
from app.core.version import APP_VERSION
from app.integrations.base import IntegrationError, ProviderAdapter, ProviderDescriptor, ProviderHealth, registry
from app.integrations.config import (
    SLS_LOGVIEWER_PATH,
    SLS_TENANT_PATTERN,
    StrataLoggingConfig,
    get_strata_logging_config,
    get_strata_logging_credentials,
    normalize_sls_query_host,
)
from app.integrations.diagnostics import record_integration_event
from app.integrations.models import CURRENT_SCHEMA_VERSION, CanonicalRecord, ProvenanceValue
from app.integrations.query import NodeWatchQuery, QueryResult
from app.integrations.resilience import RetryPolicy
from app.integrations.providers.sls_http import KeepAliveOpener
from app.integrations.providers.strata_logging_auth import StrataLoggingAuthAdapter, json_body
from app.core.file_utils import write_private_text

PROVIDER_ID = "strata_logging_service"
DESCRIPTOR = ProviderDescriptor(
    PROVIDER_ID,
    "Strata Logging Service",
    ("traffic.sessions", "traffic.raw", "logs.query"),
    read_only=True,
    vendor="palo_alto",
    adapter_version="4",
    query_capabilities=("traffic.sessions",),
)

TRAFFIC_DATASET = "firewall_traffic"
# Other Log Viewer resources observed in SCM. Not queried yet; kept so future
# features use the same names.
FUTURE_SLS_DATASETS = (
    "firewall_threat",
    "firewall_url",
    "firewall_file_data",
    "firewall_advanced_dns_security",
    "sdwan_traffic",
)
SYSTEM_DATASET = "firewall_system"  # v0.10.27: HA events and log sources that write no traffic (read-only)
# v0.10.28: Palo Alto does not publish the Log Viewer name of the system log; these are the names it is
# tried under (the first that answers is remembered). All are read-only queries.
SYSTEM_DATASETS = ("log_system", "common_system", "firewall_system", "system")
# v0.10.30 (Security Operations): threat and URL logs, under every name the Log Viewer may use for them
# (tried in order, the first that answers is remembered by the connector). Read-only queries.
THREAT_DATASETS = ("firewall_threat", "log_threat", "threat")
URL_DATASETS = ("firewall_url", "log_url")
_ALLOWED_DATASETS = frozenset(
    (TRAFFIC_DATASET, *SYSTEM_DATASETS, *FUTURE_SLS_DATASETS, *THREAT_DATASETS, *URL_DATASETS)
)
_MAX_PAGE_SIZE = 1000
_CURSOR_TTL_SECONDS = 300.0
_PROVIDER_DETAIL_LIMIT = 300
# Log Viewer queries for one lookup run side by side on this shared pool (no per-call pool set-up).
_QUERY_POOL = ThreadPoolExecutor(max_workers=6, thread_name_prefix="nodewatch-sls")
# Whether Log Viewer accepts a nested OR rule (source OR destination) in one query. Palo Alto does not
# document this API, so NodeWatch checks it against the two-query answer once before relying on it.
OR_UNKNOWN, OR_SUPPORTED, OR_UNSUPPORTED = "unknown", "supported", "unsupported"


def _query_error_code(http_status: int) -> str:
    if http_status == 400:
        return "SLS_QUERY_INVALID"
    if http_status == 401:
        return "SLS_AUTHENTICATION_FAILED"
    if http_status == 403:
        return "SLS_PERMISSION_DENIED"
    if http_status == 404:
        return "SLS_QUERY_ENDPOINT_NOT_FOUND"
    if http_status == 429:
        return "SLS_RATE_LIMITED"
    if 500 <= http_status <= 599:
        return "SLS_QUERY_UNAVAILABLE"
    return "SLS_QUERY_FAILED"


def _http_guidance(http_status: int, *, query_host: str, tenant: str) -> str:
    """Explain what Palo Alto's answer means without guessing at a single cause."""
    if http_status == 403:
        return (
            f" Palo Alto refused the log query for Prisma-Tenant {tenant} on {query_host}."
            " The OAuth token itself was accepted. Check that: (1) the TSG ID is the tenant"
            " shown in Strata Cloud Manager; (2) the service account has a role in that TSG"
            " that can open Log Viewer; (3) the log query host matches your region (shown in"
            " the Log Viewer request URL in your browser's developer tools)."
        )
    if http_status == 404:
        return f" {query_host} does not serve the Log Viewer API. Check the log query host / region."
    if http_status == 401:
        return " The OAuth token was rejected for log queries. Re-check the Client ID, Client Secret and TSG ID."
    return ""


def _value(raw: Any) -> Any:
    """Log Viewer wraps many fields as {"id": n, "value": "..."} or {"value": ..., "hex": ...}."""
    if isinstance(raw, dict):
        return raw.get("value")
    return raw


def _number(value: Any) -> int | None:
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return None


def _epoch_or_iso(value: Any) -> str:
    """Accept seconds, milliseconds or microseconds since epoch, or a string."""
    if value in (None, ""):
        return ""
    if isinstance(value, (int, float)) or (isinstance(value, str) and value.isdigit()):
        try:
            number = float(value)
            while number > 10_000_000_000:
                number /= 1000.0
            return datetime.fromtimestamp(number, tz=timezone.utc).isoformat()
        except (ValueError, OSError, OverflowError):
            return ""
    return str(value)


# Every field Palo Alto returns is passed to the UI (as ``fields``) so any of them can be shown as a
# column. Values are flattened to text; nested objects become "a.b" keys; long values are clipped.
_MAX_FIELDS = 150
_MAX_FIELD_LEN = 300
_TIME_FIELDS = {"time_generated", "receive_time", "event_time", "session_start_time", "start_time", "log_time"}


def _flatten_fields(raw: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}

    def put(key: str, value: Any) -> None:
        if len(out) >= _MAX_FIELDS or value in (None, "", [], {}):
            return
        if key in _TIME_FIELDS or key.endswith("_time") and isinstance(value, (int, float, str)):
            iso = _epoch_or_iso(value)
            if iso and iso[:2] in ("19", "20"):
                out[key] = iso
                return
        if isinstance(value, bool):
            out[key] = "yes" if value else "no"
        elif isinstance(value, (int, float)):
            out[key] = value
        elif isinstance(value, list):
            text = ", ".join(str(_value(v)) for v in value if _value(v) not in (None, ""))
            if text:
                out[key] = text[:_MAX_FIELD_LEN]
        else:
            out[key] = str(value)[:_MAX_FIELD_LEN]

    for key, value in raw.items():
        if isinstance(value, dict):
            if "value" in value:
                put(key, value.get("value"))
            else:
                for sub, inner in value.items():
                    put(f"{key}.{sub}", _value(inner) if not isinstance(inner, dict) else None)
        else:
            put(key, value)
    return out


def _to_microseconds(moment: datetime) -> int:
    return int(moment.timestamp() * 1_000_000)


@dataclass
class _CursorState:
    signature: str
    page_number: int
    start: datetime
    end: datetime
    expires_at: float
    or_mode: str = ""


class StrataLoggingProvider(ProviderAdapter):
    descriptor = DESCRIPTOR

    def __init__(
        self,
        config: StrataLoggingConfig | None = None,
        credentials: dict[str, str] | None = None,
        *,
        opener=None,
    ) -> None:
        self.config = config or get_strata_logging_config()
        self.credentials = credentials or get_strata_logging_credentials()
        # Keep-alive + gzip HTTPS client (sls_http); tests inject their own opener.
        self._opener = opener or KeepAliveOpener()
        self._auth = StrataLoggingAuthAdapter(self.config, self.credentials, opener=self._opener)
        self._health = ProviderHealth(configured=self.configured)
        self._cursor_lock = threading.RLock()
        self._cursor_states: dict[str, _CursorState] = {}
        self._or_mode = _remembered_or_mode(self._or_memory_key())
        self._or_probe_inconclusive = 0
        self._or_probe_5xx = 0

    # ------------------------------------------------------------------ state

    @property
    def configured(self) -> bool:
        return bool(
            self.config.enabled
            and self.config.verified
            and not self.config.validate()
            and self._auth.credentials_present
        )

    def capabilities(self) -> tuple[str, ...]:
        # Capabilities become active only after a verified live traffic query.
        return self.descriptor.capabilities if self.configured else ()

    def health_state(self) -> ProviderHealth:
        if not self.configured:
            self._health.state = "disabled"
            self._health.configured = False
        elif self._health.state == "disabled":
            self._health.state = "configured"
            self._health.configured = True
        return self._health

    def cache_policy(self, capability: str) -> tuple[str, float | None]:
        if capability == "traffic.sessions":
            return ("hot", float(self.config.cache_seconds))
        return super().cache_policy(capability)

    def retry_policy(self) -> RetryPolicy:
        # A traffic query may legitimately take most of query_timeout; the overall
        # budget must exceed it or slow-but-successful queries would be abandoned.
        budget = float(self.config.query_timeout + self.config.request_timeout)
        return RetryPolicy(attempts=2, timeout_budget_seconds=budget)

    @property
    def query_host(self) -> str:
        host = normalize_sls_query_host(self.config.query_host)
        if not host:
            raise IntegrationError(
                "Log query host is not an approved Prisma Access API host", code="SLS_CONFIGURATION_ERROR"
            )
        return host

    @property
    def tenant(self) -> str:
        tenant = (self.config.tenant_header or self.credentials.get("tsg_id") or "").strip()
        if not SLS_TENANT_PATTERN.match(tenant):
            raise IntegrationError(
                "The TSG ID (or Prisma-Tenant override) must be numeric", code="SLS_CONFIGURATION_ERROR"
            )
        return tenant

    # ------------------------------------------------------------------- auth

    def _authorize(self, *, force: bool = False):
        try:
            context = self._auth.authorize(force=force)
        except IntegrationError as exc:
            state = {
                "SLS_NOT_CONFIGURED": "not_configured",
                "SLS_TOKEN_EXCHANGE_FAILED": "authentication_failed",
                "SLS_PERMISSION_DENIED": "permission_denied",
                "SLS_RATE_LIMITED": "rate_limited",
                "SLS_CONFIGURATION_ERROR": "configuration_invalid",
                "SLS_INVALID_PROVIDER_RESPONSE": "configuration_invalid",
                "SLS_PROVIDER_UNAVAILABLE": "unavailable",
            }.get(exc.code, "degraded")
            self._health.mark_error(str(exc), status_code=exc.status_code, state=state)
            raise
        self._health.mark_success()
        return context

    # ------------------------------------------------------------------- HTTP

    def _post_logviewer(
        self,
        dataset: str,
        body: dict[str, Any],
        *,
        retry_auth: bool = True,
        timings: list[dict[str, Any]] | None = None,
        probe: bool = False,
    ) -> dict[str, Any]:
        if dataset not in _ALLOWED_DATASETS:
            raise IntegrationError(f"Unsupported log dataset: {dataset}", code="INVALID_QUERY")
        context = self._authorize()
        host = self.query_host
        tenant = self.tenant
        path = f"{SLS_LOGVIEWER_PATH}/{dataset}"
        req = Request(
            host + path,
            data=json.dumps(body).encode("utf-8"),
            method="POST",
            headers={
                "Authorization": f"Bearer {context.access_token}",
                "Prisma-Tenant": tenant,
                "Accept": "application/json",
                "Content-Type": "application/json",
                "User-Agent": f"NodeWatch/{APP_VERSION}",
            },
        )
        meta = {"phase": "or_probe" if probe else "query", "http_method": "POST", "path": path, "host": host}
        record_integration_event(provider=PROVIDER_ID, operation="SLS_QUERY_STARTED", ok=True, metadata=meta)
        started = time.perf_counter()
        try:
            # Log queries can run long server-side; use the query timeout, not the short request timeout.
            timeout = max(self.config.request_timeout, self.config.query_timeout)
            with self._opener.open(req, timeout=timeout) as resp:
                status_code = int(getattr(resp, "status", 200) or 200)
                wire = dict(getattr(resp, "timing", None) or {})
                received = time.perf_counter()
                payload = json_body(resp)
                parse_ms = int((time.perf_counter() - received) * 1000)
        except HTTPError as exc:
            duration_ms = int((time.perf_counter() - started) * 1000)
            provider_detail = self._error_detail(exc)
            record_integration_event(
                provider=PROVIDER_ID,
                operation=f"SLS_QUERY_HTTP_{exc.code}",
                ok=False,
                duration_ms=duration_ms,
                status_code=exc.code,
                error=provider_detail or f"HTTP {exc.code}",
                metadata=meta,
            )
            if exc.code == 401 and retry_auth:
                self._auth.invalidate()
                self._authorize(force=True)
                return self._post_logviewer(dataset, body, retry_auth=False, timings=timings, probe=probe)
            guidance = _http_guidance(exc.code, query_host=host, tenant=tenant)
            detail_suffix = f" Provider response: {provider_detail}" if provider_detail else ""
            if probe:
                # An experimental single-query form was refused: not a provider health problem.
                raise IntegrationError(
                    f"Log query HTTP {exc.code} from {host}{path}.{detail_suffix}",
                    code=_query_error_code(exc.code),
                    status_code=exc.code,
                ) from exc
            state = {401: "authentication_failed", 403: "permission_denied", 429: "rate_limited"}.get(
                exc.code, "degraded"
            )
            self._health.mark_error(provider_detail or f"HTTP {exc.code}", status_code=exc.code, state=state)
            raise IntegrationError(
                f"Log query HTTP {exc.code} from {host}{path}.{guidance}{detail_suffix}",
                code=_query_error_code(exc.code),
                status_code=exc.code,
            ) from exc
        except (URLError, TimeoutError, OSError) as exc:
            duration_ms = int((time.perf_counter() - started) * 1000)
            reason = getattr(exc, "reason", None) or exc
            record_integration_event(
                provider=PROVIDER_ID,
                operation="SLS_QUERY_NETWORK_FAILED",
                ok=False,
                duration_ms=duration_ms,
                error=f"Network error: {reason}",
                metadata=meta,
            )
            self._health.mark_error(str(reason), state="unavailable")
            code = (
                "SLS_QUERY_TIMEOUT"
                if isinstance(exc, TimeoutError) or "timed out" in str(reason)
                else "SLS_QUERY_UNAVAILABLE"
            )
            raise IntegrationError(f"Unable to reach the log query host {host}: {reason}", code=code) from exc

        duration_ms = int((time.perf_counter() - started) * 1000)
        timing = {
            "total_ms": duration_ms,
            "parse_ms": parse_ms,
            "rows": len(payload.get("data") or []) if isinstance(payload, dict) else 0,
            **{k: wire[k] for k in ("connect_ms", "wait_ms", "download_ms", "bytes", "wire_bytes") if k in wire},
        }
        if "reused_connection" in wire:
            timing["reused_connection"] = bool(wire["reused_connection"])
        if timings is not None:
            timings.append(timing)
        record_integration_event(
            provider=PROVIDER_ID,
            operation=f"SLS_QUERY_HTTP_{status_code}",
            ok=200 <= status_code < 300,
            duration_ms=duration_ms,
            status_code=status_code,
            metadata={**meta, **{k: v for k, v in timing.items() if k != "total_ms"}},
        )
        if not isinstance(payload, dict) or not isinstance(payload.get("data", []), list):
            raise IntegrationError(
                "Log Viewer API returned an unexpected response shape", code="SLS_INVALID_PROVIDER_RESPONSE"
            )
        header = payload.get("header") if isinstance(payload.get("header"), dict) else {}
        sub_code = (
            _number((header.get("status") or {}).get("subCode")) if isinstance(header.get("status"), dict) else None
        )
        if sub_code is not None and not (200 <= sub_code < 300):
            message = redact_text(str((header.get("status") or {}).get("message") or ""))[:_PROVIDER_DETAIL_LIMIT]
            raise IntegrationError(
                f"Log Viewer API reported status {sub_code}{': ' + message if message else ''}",
                code=_query_error_code(sub_code),
                status_code=sub_code,
            )
        self._health.mark_success()
        return payload

    @staticmethod
    def _error_detail(exc: HTTPError) -> str:
        try:
            raw = exc.read().decode("utf-8", errors="replace")
        except Exception:
            return ""
        detail: Any = raw
        try:
            parsed = json.loads(raw) if raw.strip() else {}
            if isinstance(parsed, dict):
                detail = (
                    parsed.get("detail")
                    or parsed.get("message")
                    or parsed.get("msg")
                    or parsed.get("error_description")
                    or parsed.get("error")
                    or raw
                )
        except ValueError:
            pass
        text = " ".join(redact_text(str(detail or "")).split())
        return text[:_PROVIDER_DETAIL_LIMIT]

    # ------------------------------------------------------------ query build

    @staticmethod
    def _query_range(query: NodeWatchQuery) -> tuple[datetime, datetime]:
        if query.start_time and query.end_time:
            try:
                start = datetime.fromisoformat(query.start_time.replace("Z", "+00:00")).astimezone(timezone.utc)
                end = datetime.fromisoformat(query.end_time.replace("Z", "+00:00")).astimezone(timezone.utc)
            except ValueError as exc:
                raise IntegrationError("Invalid traffic query time range", code="INVALID_QUERY") from exc
        else:
            end = datetime.now(timezone.utc)
            start = end - timedelta(minutes=15)
        if start >= end:
            raise IntegrationError("Traffic query start time must be before end time", code="INVALID_QUERY")
        return start, end

    @staticmethod
    def _ip_from_filters(query: NodeWatchQuery) -> str | None:
        ip: str | None = None
        for item in query.filters:
            if item.field == "source_or_destination.ip" and item.operator == "eq":
                try:
                    ip = str(ipaddress.ip_address(str(item.value).strip()))
                except ValueError as exc:
                    raise IntegrationError("Traffic query requires a valid IP address", code="INVALID_QUERY") from exc
            else:
                raise IntegrationError(
                    f"Unsupported Strata traffic filter: {item.field}/{item.operator}", code="INVALID_QUERY"
                )
        return ip

    @staticmethod
    def _build_body(
        start: datetime,
        end: datetime,
        *,
        page_size: int,
        page_number: int,
        ip_rule: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        rules: list[dict[str, Any]] = [
            {
                "property": "event_time",
                "operator": "between",
                "values": [_to_microseconds(start), _to_microseconds(end)],
            }
        ]
        if ip_rule:
            rules.append(ip_rule)
        size = max(1, min(int(page_size), _MAX_PAGE_SIZE))
        flt: dict[str, Any] = {"rules": rules}
        if ip_rule and "rules" in ip_rule:
            flt = {"operator": "AND", "rules": rules}  # nested OR group (see _or_rule)
        return {
            "filter": flt,
            "orderBy": {"properties": [{"property": "time_generated", "sort": {"sequence": 1, "order": "desc"}}]},
            "pagination": {"page_size": size, "page_number": max(1, int(page_number))},
            "count": size,
        }

    @staticmethod
    def _ip_rules(ip: str) -> list[dict[str, Any]]:
        prefix = 32 if ipaddress.ip_address(ip).version == 4 else 128
        cidr = f"{ip}/{prefix}"
        return [
            {"property": "source_ip.value", "operator": "ip_match_cidr", "values": [cidr]},
            {"property": "dest_ip.value", "operator": "ip_match_cidr", "values": [cidr]},
        ]

    @classmethod
    def _or_rule(cls, ip: str) -> dict[str, Any]:
        """One rule group matching source OR destination (Insights query-language nesting)."""
        return {"operator": "OR", "rules": cls._ip_rules(ip)}

    # ------------------------------------------------------------- pagination

    def _prune_cursors(self) -> None:
        now = time.monotonic()
        with self._cursor_lock:
            for token, state in list(self._cursor_states.items()):
                if state.expires_at <= now:
                    self._cursor_states.pop(token, None)

    def _store_cursor(self, signature: str, page_number: int, start: datetime, end: datetime, or_mode: str = "") -> str:
        self._prune_cursors()
        token = secrets.token_urlsafe(24)
        with self._cursor_lock:
            self._cursor_states[token] = _CursorState(
                signature, page_number, start, end, time.monotonic() + _CURSOR_TTL_SECONDS, or_mode
            )
        return token

    def _peek_cursor(self, token: str, signature: str) -> _CursorState:
        """Look up a cursor without consuming it, so a retried request can reuse it."""
        self._prune_cursors()
        with self._cursor_lock:
            state = self._cursor_states.get(str(token or ""))
        if not state or state.signature != signature:
            raise IntegrationError("Traffic pagination cursor is invalid or expired", code="INVALID_CURSOR")
        return state

    def _drop_cursor(self, token: str) -> None:
        with self._cursor_lock:
            self._cursor_states.pop(str(token or ""), None)

    # -------------------------------------------------------------- normalize

    def _normalize(self, raw: dict[str, Any]) -> CanonicalRecord:
        source_map: dict[str, str] = {}

        def take(canonical: str, *names: str, transform=None):
            value = None
            source_name = ""
            for name in names:
                if name in raw and raw[name] not in (None, ""):
                    candidate = _value(raw[name])
                    if candidate in (None, ""):
                        continue
                    source_name = name
                    value = candidate
                    break
            if transform is not None:
                value = transform(value)
            if value not in (None, ""):
                source_map[canonical] = source_name
            return value

        source = take("source", "source_ip", "src")
        destination = take("destination", "dest_ip", "dst")
        observed = (
            take("receive_time", "time_generated", "log_time", "receive_time_epoch", transform=_epoch_or_iso)
            or datetime.now(timezone.utc).isoformat()
        )
        sequence = raw.get("sequence_no")
        if sequence not in (None, ""):
            record_id = f"seq:{sequence}"
        else:
            record_id = hashlib.sha256(
                json.dumps(raw, sort_keys=True, default=str, separators=(",", ":")).encode()
            ).hexdigest()

        traffic = {
            "rule": take("rule", "rule_matched", "rule"),
            "rule_uuid": take("rule_uuid", "rule_matched_uuid"),
            "application": take("application", "app", "application"),
            "application_category": take("application_category", "app_category"),
            "application_subcategory": take("application_subcategory", "app_sub_category"),
            "application_risk": take("application_risk", "risk_of_app", transform=_number),
            "action": take("action", "action"),
            "type": take("type", "sub_type", "subtype", "log_subtype"),
            "decrypted": take(
                "decrypted",
                "is_decrypted",
                "decrypted",
                "flags_decrypted",
                transform=lambda v: (
                    None if v in (None, "") else ("yes" if str(v).lower() in ("1", "true", "yes") else "no")
                ),
            ),
            "source": source,
            "destination": destination,
            "source_port": take("source_port", "source_port", transform=_number),
            "destination_port": take("destination_port", "dest_port", transform=_number),
            "protocol": take("protocol", "protocol"),
            "from_zone": take("from_zone", "from_zone"),
            "to_zone": take("to_zone", "to_zone"),
            "source_user": take("source_user", "source_user"),
            "destination_user": take("destination_user", "dest_user"),
            "bytes_total": take("bytes_total", "bytes_total", transform=_number),
            "bytes_sent": take("bytes_sent", "bytes_sent", transform=_number),
            "bytes_received": take("bytes_received", "bytes_received", transform=_number),
            "packets_total": take("packets_total", "packets_total", "packets", transform=_number),
            "packets_sent": take("packets_sent", "packets_sent", transform=_number),
            "packets_received": take("packets_received", "packets_received", transform=_number),
            "session_id": take("session_id", "session_id"),
            "session_start_time": take("session_start_time", "session_start_time", transform=_epoch_or_iso),
            "elapsed_time": take("elapsed_time", "total_time_elapsed", "elapsed_time", transform=_number),
            "session_end_reason": take("session_end_reason", "session_end_reason"),
            "nat_source": take("nat_source", "nat_source"),
            "nat_destination": take("nat_destination", "nat_dest"),
            "nat_source_port": take("nat_source_port", "nat_source_port", transform=_number),
            "nat_destination_port": take("nat_destination_port", "nat_dest_port", transform=_number),
            "firewall": take("firewall", "log_source_name"),
            "firewall_serial": take("firewall_serial", "log_source_id"),
            "vsys": take("vsys", "vsys"),
            "url_category": take("url_category", "url_category"),
            "inbound_interface": take("inbound_interface", "inbound_if"),
            "outbound_interface": take("outbound_interface", "outbound_if"),
            "receive_time": observed,
        }
        traffic = {key: value for key, value in traffic.items() if value not in (None, "")}
        fields = _flatten_fields(raw)
        provenance = {
            f"traffic.{key}": [
                ProvenanceValue(
                    value,
                    PROVIDER_ID,
                    observed_at=observed,
                    dataset="firewall.traffic",
                    source_field=source_map.get(key, ""),
                    schema_version=CURRENT_SCHEMA_VERSION,
                )
            ]
            for key, value in traffic.items()
        }
        return CanonicalRecord(
            event_type="network.session",
            provider_id=PROVIDER_ID,
            observed_at=observed,
            record_id=record_id,
            entity_id=str(source or destination or ""),
            data={
                "traffic": {**traffic, "fields": fields},
                "dataset": "firewall.traffic",
                "summary": f"{traffic.get('action', 'session')} {source or '?'} → {destination or '?'}",
            },
            provenance=provenance,
            raw=raw,
        )

    # ------------------------------------------------------------------ query

    @staticmethod
    def _row_key(row: dict[str, Any]) -> str:
        return (
            str(row.get("sequence_no") or "")
            or hashlib.sha256(json.dumps(row, sort_keys=True, default=str).encode()).hexdigest()
        )

    @staticmethod
    def _newest(row: dict[str, Any]) -> float:
        value = _value(row.get("time_generated"))
        number = _number(value)
        if number is not None:
            return float(number)
        iso = _epoch_or_iso(value)
        try:
            return datetime.fromisoformat(iso.replace("Z", "+00:00")).timestamp() * 1_000_000
        except ValueError:
            return 0.0

    @staticmethod
    def _row_matches_ip(row: dict[str, Any], ip: str) -> bool:
        for name in ("source_ip", "dest_ip", "src", "dst"):
            value = _value(row.get(name))
            if value in (None, ""):
                continue
            try:
                if str(ipaddress.ip_address(str(value).strip())) == ip:
                    return True
            except ValueError:
                continue
        return False

    def _merge_split(self, payloads: list[dict[str, Any]], page_size: int) -> tuple[list[dict[str, Any]], bool]:
        merged: dict[str, dict[str, Any]] = {}
        has_more = False
        for payload in payloads:
            rows = [row for row in payload.get("data") or [] if isinstance(row, dict)]
            has_more = has_more or len(rows) >= page_size
            for row in rows:
                merged.setdefault(self._row_key(row), row)
        return sorted(merged.values(), key=self._newest, reverse=True), has_more

    @property
    def or_mode(self) -> str:
        return self._or_mode

    def _or_memory_key(self) -> str:
        return f"{getattr(self.config, 'query_host', '')}|{getattr(self.config, 'tenant_header', '')}"

    def _set_or_mode(self, mode: str, reason: str) -> None:
        if self._or_mode == mode:
            return
        self._or_mode = mode
        _remember_or_mode(self._or_memory_key(), mode)
        record_integration_event(
            provider=PROVIDER_ID,
            operation=f"SLS_OR_QUERY_{mode.upper()}",
            ok=mode == OR_SUPPORTED,
            error="" if mode == OR_SUPPORTED else reason,
            metadata={"phase": "or_probe", "or_query": mode},
        )

    def _fetch_page(
        self,
        start: datetime,
        end: datetime,
        *,
        ip: str | None,
        page_size: int,
        page_number: int,
        timings: list[dict[str, Any]] | None = None,
        or_mode: str | None = None,
    ) -> tuple[list[dict[str, Any]], bool]:
        """Return (rows, has_more). An IP lookup matches source OR destination.

        Log Viewer was first used with an AND-only rule list, so an IP lookup ran one query
        for the source side and one for the destination side, in parallel, merged newest-first.
        v0.10.15 also tries one query with a nested OR group. Because the API is not documented,
        the first lookup runs both forms side by side and uses the single query only after its
        answer matched the two-query answer; any later answer with a row for another IP
        switches back to two queries for good.
        """
        if not ip:
            payload = self._post_logviewer(
                TRAFFIC_DATASET,
                self._build_body(start, end, page_size=page_size, page_number=page_number),
                timings=timings,
            )
            rows = [row for row in payload.get("data") or [] if isinstance(row, dict)]
            return rows, len(rows) >= page_size

        mode = or_mode or self._or_mode
        if mode == OR_SUPPORTED:
            body = self._build_body(start, end, page_size=page_size, page_number=page_number, ip_rule=self._or_rule(ip))
            try:
                payload = self._post_logviewer(TRAFFIC_DATASET, body, timings=timings, probe=True)
            except IntegrationError as exc:
                if exc.code != "SLS_QUERY_INVALID":
                    raise
                self._set_or_mode(OR_UNSUPPORTED, f"single OR query refused: {exc}")
            else:
                rows = [row for row in payload.get("data") or [] if isinstance(row, dict)]
                if all(self._row_matches_ip(row, ip) for row in rows):
                    return sorted(rows, key=self._newest, reverse=True), len(rows) >= page_size
                self._set_or_mode(OR_UNSUPPORTED, "single OR query returned rows for other IP addresses")
            # fall through to the two-query form

        bodies = [
            self._build_body(start, end, page_size=page_size, page_number=page_number, ip_rule=rule)
            for rule in self._ip_rules(ip)
        ]
        probe_future = None
        if mode == OR_UNKNOWN and page_number == 1 and self._or_probe_inconclusive < 5:
            probe_body = self._build_body(
                start, end, page_size=page_size, page_number=page_number, ip_rule=self._or_rule(ip)
            )
            probe_future = _QUERY_POOL.submit(self._post_logviewer, TRAFFIC_DATASET, probe_body, probe=True)
        futures = [_QUERY_POOL.submit(self._post_logviewer, TRAFFIC_DATASET, body, timings=timings) for body in bodies]
        payloads = [future.result() for future in futures]
        ordered, has_more = self._merge_split(payloads, page_size)
        if probe_future is not None:
            self._judge_or_probe(probe_future, ordered, ip, page_size)
        return ordered, has_more

    def _judge_or_probe(self, future, split_rows: list[dict[str, Any]], ip: str, page_size: int) -> None:  # noqa: ANN001
        try:
            payload = future.result(timeout=max(1.0, float(self.config.query_timeout)))
        except IntegrationError as exc:
            if exc.code == "SLS_QUERY_INVALID":
                self._set_or_mode(OR_UNSUPPORTED, f"single OR query refused: {exc}")
            elif (exc.status_code or 0) >= 500:
                # v0.10.23: this tenant answered HTTP 500 to every probe in the field (17 of 17,
                # up to 36 s each, alongside real lookups): two in a row settle it.
                self._or_probe_5xx += 1
                self._or_probe_inconclusive += 1
                if self._or_probe_5xx >= 2:
                    self._set_or_mode(OR_UNSUPPORTED, f"single OR query failed twice with HTTP {exc.status_code}")
            else:
                self._or_probe_inconclusive += 1
            return
        except Exception:  # noqa: BLE001 - a probe must never fail the real lookup
            self._or_probe_inconclusive += 1
            return
        rows = [row for row in payload.get("data") or [] if isinstance(row, dict)]
        if not all(self._row_matches_ip(row, ip) for row in rows):
            self._set_or_mode(OR_UNSUPPORTED, "single OR query returned rows for other IP addresses")
            return
        expected = [self._row_key(row) for row in split_rows[:page_size]]
        if not expected:
            self._or_probe_inconclusive += 1  # nothing to compare against yet
            return
        got = {self._row_key(row) for row in rows}
        overlap = len(got.intersection(expected)) / len(expected)
        # Rows sharing the boundary timestamp may differ when the page is full; otherwise exact.
        threshold = 0.9 if len(expected) >= page_size else 1.0
        if overlap >= threshold:
            self._set_or_mode(OR_SUPPORTED, "")
        else:
            self._set_or_mode(OR_UNSUPPORTED, f"single OR query matched {overlap:.0%} of the two-query answer")

    def query(self, query: NodeWatchQuery) -> QueryResult:
        if query.capability != "traffic.sessions":
            raise IntegrationError("Unsupported Strata capability", code="CAPABILITY_UNAVAILABLE")
        if not self.configured:
            raise IntegrationError("Strata Logging Service is not enabled and verified", code="SLS_NOT_CONFIGURED")
        started = time.perf_counter()
        ip = self._ip_from_filters(query)
        page_size = max(1, min(int(query.page_size or 100), _MAX_PAGE_SIZE))
        # The cursor pins the original time range: the UI recomputes "last hour" on
        # every call, and later pages must continue the same result set.
        signature = hashlib.sha256(json.dumps([ip, page_size]).encode()).hexdigest()
        or_mode = None
        if query.cursor:
            state = self._peek_cursor(query.cursor, signature)
            start, end, page_number = state.start, state.end, state.page_number
            or_mode = state.or_mode or None  # later pages keep the form page 1 used
        else:
            start, end = self._query_range(query)
            page_number = 1
            or_mode = self._or_mode if self._or_mode != OR_UNKNOWN else None
        page_mode = or_mode or self._or_mode
        timings: list[dict[str, Any]] = []
        raw_rows, has_more = self._fetch_page(
            start, end, ip=ip, page_size=page_size, page_number=page_number, timings=timings, or_mode=or_mode
        )
        fetched = time.perf_counter()
        if query.cursor:
            self._drop_cursor(query.cursor)  # only after the page was fetched successfully
        records: list[CanonicalRecord] = []
        for raw in raw_rows:
            record = self._normalize(raw)
            records.append(record)
        # A page fetched with the single query continues with it; a two-query page continues split.
        used_or = page_mode == OR_SUPPORTED and self._or_mode == OR_SUPPORTED
        next_cursor = (
            self._store_cursor(signature, page_number + 1, start, end, OR_SUPPORTED if used_or else OR_UNSUPPORTED)
            if has_more
            else None
        )
        result = QueryResult(
            records=records,
            provider_id=PROVIDER_ID,
            cursor=query.cursor,
            next_cursor=next_cursor,
            has_more=bool(next_cursor),
            total=None,
            retrieved_count=len(records),
        )
        result.timing = {  # type: ignore[attr-defined]
            "queries": len(timings),
            "single_or_query": used_or,
            "or_query": self._or_mode,
            "palo_alto_ms": max((t.get("total_ms", 0) for t in timings), default=0),
            "wait_ms": max((t.get("wait_ms", 0) for t in timings), default=0),
            "download_ms": max((t.get("download_ms", 0) for t in timings), default=0),
            "connect_ms": max((t.get("connect_ms", 0) for t in timings), default=0),
            "parse_ms": sum(t.get("parse_ms", 0) for t in timings),
            "bytes": sum(t.get("bytes", 0) for t in timings),
            "wire_bytes": sum(t.get("wire_bytes", 0) for t in timings),
            "reused_connections": sum(1 for t in timings if t.get("reused_connection")),
            "fetch_ms": int((fetched - started) * 1000),
            "normalize_ms": int((time.perf_counter() - fetched) * 1000),
        }
        return result

    def test_connection(self) -> dict[str, Any]:
        """OAuth + one real read-only firewall_traffic query (1 row, last 15 minutes)."""
        started = time.perf_counter()
        try:
            self._authorize(force=True)
            end = datetime.now(timezone.utc)
            start = end - timedelta(minutes=15)
            rows, _ = self._fetch_page(start, end, ip=None, page_size=1, page_number=1)
            duration_ms = int((time.perf_counter() - started) * 1000)
            record_integration_event(
                provider=PROVIDER_ID,
                operation="SLS_QUERY_SUCCESS",
                ok=True,
                duration_ms=duration_ms,
                status_code=200,
                metadata={"phase": "verification", "sample_count": len(rows)},
            )
            return {
                "ok": True,
                "reachable": True,
                "authorized": True,
                "traffic_query_authorized": True,
                "sample_count": len(rows),
                "read_only": True,
                "api_host": self.query_host,
                "tsg_id_present": bool(self.credentials.get("tsg_id")),
                "diagnostic_code": "SLS_TRAFFIC_QUERY_OK",
                "capability": "traffic.sessions",
            }
        except IntegrationError as exc:
            duration_ms = int((time.perf_counter() - started) * 1000)
            record_integration_event(
                provider=PROVIDER_ID,
                operation="SLS_QUERY_FAILED",
                ok=False,
                duration_ms=duration_ms,
                status_code=exc.status_code,
                error=f"{exc.code}: {exc}",
                metadata={"phase": "verification"},
            )
            raise

    def diagnostics(self) -> dict[str, Any]:
        try:
            host = self.query_host
        except IntegrationError:
            host = ""
        return {
            "provider": PROVIDER_ID,
            "configured": self.configured,
            "verified": bool(self.config.verified),
            "verified_at": self.config.verified_at,
            "query_api": "scm_logviewer",
            "query_host": host,
            "tenant_override_set": bool(self.config.tenant_header),
            "auth": self._auth.safe_status(),
            "active_capabilities": list(self.capabilities()),
            "declared_capabilities": list(self.descriptor.capabilities),
            "future_dataset_hooks": list(FUTURE_SLS_DATASETS),
            "single_or_query": self._or_mode,
            "http_pool": dict(getattr(self._opener, "stats", {}) or {}),
            "health": self.health_state().public_dict,
        }


_provider: StrataLoggingProvider | None = None
_provider_lock = threading.Lock()


def get_strata_logging_provider(*, reset: bool = False) -> StrataLoggingProvider:
    global _provider
    with _provider_lock:
        if reset or _provider is None:
            _provider = StrataLoggingProvider()
        return _provider


registry.register(DESCRIPTOR, get_strata_logging_provider)


# v0.10.23: the single-OR-query decision survives restarts and settings saves (it was re-probed
# after every start, costing up to 36 s per probe). Keyed by query host + tenant override.
def _or_memory_file():
    from app.core.config import DATA_ROOT

    return DATA_ROOT / "state" / "sls_or_mode.json"


def _remembered_or_mode(key: str) -> str:
    try:
        data = json.loads(_or_memory_file().read_text(encoding="utf-8"))
        mode = data.get(key) if isinstance(data, dict) else None
        return mode if mode in (OR_SUPPORTED, OR_UNSUPPORTED) else OR_UNKNOWN
    except (OSError, ValueError):
        return OR_UNKNOWN


def _remember_or_mode(key: str, mode: str) -> None:
    try:
        path = _or_memory_file()
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            data = data if isinstance(data, dict) else {}
        except (OSError, ValueError):
            data = {}
        if mode in (OR_SUPPORTED, OR_UNSUPPORTED):
            data[key] = mode
        else:
            data.pop(key, None)
        write_private_text(path, json.dumps(data))  # atomic, owner-only (v0.10.40)
    except OSError:
        pass
