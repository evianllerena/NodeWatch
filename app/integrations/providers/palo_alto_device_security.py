from __future__ import annotations

from app.core.version import APP_VERSION

import base64
import json
import ssl
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener

from app.core.config import DIAGNOSTICS_ROOT
from app.core.file_utils import append_jsonl_rotating
from app.core.security import redact_text
from app.integrations.auth import TOKEN_MANAGER
from app.integrations.base import IntegrationError, ProviderAdapter, ProviderDescriptor, ProviderHealth, registry
from app.integrations.rate_limit import REQUEST_LIMITER, retry_after_seconds
from app.integrations.config import (
    PA_DS_API_HOST,
    PA_DS_AUTH_HOST,
    PaloAltoDeviceSecurityConfig,
    get_palo_alto_config,
    get_palo_alto_credentials,
    validate_palo_alto_credentials,
)


class _NoCredentialRedirect(HTTPRedirectHandler):
    """Do not follow redirects carrying authentication headers to another request."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


PROVIDER_ID = "palo_alto_device_security"
CAPABILITIES = (
    "device_by_ip",
    "device_by_mac",
    "device_identity",
    "device_risk",
    "device_classification",
    "device.by_ip",
    "device.by_mac",
    "device.identity",
    "device.risk",
    "device.classification",
)
DESCRIPTOR = ProviderDescriptor(
    PROVIDER_ID, "Palo Alto Device Security", CAPABILITIES, read_only=True, vendor="palo_alto"
)


_CACHE_MAX_ENTRIES = 2048


@dataclass
class CacheEntry:
    expires_at: float
    value: Any


class PaloAltoDeviceSecurityProvider(ProviderAdapter):
    descriptor = DESCRIPTOR

    def __init__(self, config: PaloAltoDeviceSecurityConfig | None = None, credentials: dict[str, str] | None = None):
        self.config = config or get_palo_alto_config()
        self.credentials = credentials or get_palo_alto_credentials()
        self.health = ProviderHealth(configured=self.config.enabled)
        self._cache: dict[str, CacheEntry] = {}
        self._timing_log: Path = DIAGNOSTICS_ROOT / "integration_api_timing.jsonl"
        # Authentication headers are never allowed to follow HTTP redirects.  The
        # approved API endpoints are expected to answer directly.
        self._opener = build_opener(HTTPSHandler(context=self._context()), _NoCredentialRedirect())

    @property
    def configured(self) -> bool:
        return (
            self.config.enabled and not self.config.validate() and not validate_palo_alto_credentials(self.credentials)
        )

    def health_state(self) -> ProviderHealth:
        self.health.configured = self.configured
        if not self.configured and self.health.state == "disabled":
            return self.health
        if self.configured and self.health.state == "disabled":
            self.health.state = "unknown"
        return self.health

    def _context(self):
        # This integration intentionally does not expose a TLS bypass.
        return ssl.create_default_context()

    @property
    def _token_key(self) -> str:
        return f"{PROVIDER_ID}:{self.config.instance_id}:{self.credentials.get('client_id', '')}:{self.credentials.get('tsg_id', '')}"

    def _record_timing(
        self,
        *,
        operation: str,
        duration_ms: int,
        status_code: int | None,
        ok: bool,
        cache_hit: bool = False,
        error: str = "",
    ) -> None:
        try:
            record: dict[str, Any] = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "provider": PROVIDER_ID,
                "operation": operation,
                "duration_ms": duration_ms,
                "status_code": status_code,
                "ok": ok,
                "cache_hit": cache_hit,
            }
            if error:
                record["error"] = redact_text(error, self.credentials.get("client_secret", ""))[:500]
            append_jsonl_rotating(self._timing_log, record)
        except Exception:
            pass

    @staticmethod
    def _decode_json(raw: str) -> Any:
        if not raw:
            return None
        value = json.loads(raw)
        # Device detail can be represented as a JSON-encoded string by some clients.
        # Accept that shape without normalizing key case (Palo Alto exposes both
        # `source` and `Source` as distinct fields).
        if isinstance(value, str):
            stripped = value.strip()
            if stripped.startswith("{") or stripped.startswith("["):
                value = json.loads(stripped)
        return value

    def _fetch_token(self) -> tuple[str, int]:
        errors = self.config.validate() + validate_palo_alto_credentials(self.credentials)
        if errors:
            raise IntegrationError("; ".join(errors), code="CONFIGURATION_ERROR")
        client_id = self.credentials["client_id"]
        client_secret = self.credentials["client_secret"]
        tsg_id = self.credentials["tsg_id"]
        basic = base64.b64encode(f"{client_id}:{client_secret}".encode("ascii")).decode("ascii")
        body = urlencode({"grant_type": "client_credentials", "scope": f"tsg_id:{tsg_id}"}).encode("ascii")
        req = Request(
            f"{PA_DS_AUTH_HOST}/oauth2/access_token",
            data=body,
            method="POST",
            headers={
                "Authorization": f"Basic {basic}",
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
                "User-Agent": f"NodeWatch/{APP_VERSION}",
            },
        )
        try:
            REQUEST_LIMITER.wait(f"{PROVIDER_ID}:auth", min_interval_seconds=0.10)
            with self._opener.open(req, timeout=self.config.request_timeout) as resp:
                try:
                    payload = self._decode_json(resp.read().decode("utf-8")) or {}
                except ValueError as exc:
                    raise IntegrationError(
                        "Palo Alto authentication returned invalid JSON", code="AUTHENTICATION_FAILED"
                    ) from exc
                token = str(payload.get("access_token") or "") if isinstance(payload, dict) else ""
                # Without expires_in the token used to be cached for 1 s, which (with the 90 s refresh
                # margin) meant a new token on every call. Assume 900 s like the Strata Logging
                # client (v0.10.22); a 401 still invalidates it early.
                try:
                    expires = int(payload.get("expires_in") or 900) if isinstance(payload, dict) else 900
                except (TypeError, ValueError):
                    expires = 900
                if not token:
                    raise IntegrationError(
                        "Palo Alto authentication returned no access token", code="AUTHENTICATION_FAILED"
                    )
                return token, expires
        except HTTPError as exc:
            try:
                raw = exc.read().decode("utf-8")
                payload = self._decode_json(raw)
                message = (
                    payload.get("error_description") or payload.get("message") or payload.get("error") or raw
                    if isinstance(payload, dict)
                    else raw
                )
            except Exception:
                message = str(exc)
            raise IntegrationError(
                f"Palo Alto authentication HTTP {exc.code}: {redact_text(message, client_secret)}",
                code="AUTHENTICATION_FAILED",
                status_code=exc.code,
            ) from exc
        except URLError as exc:
            raise IntegrationError(
                f"Unable to reach Palo Alto authentication service: {exc.reason}", code="PROVIDER_UNAVAILABLE"
            ) from exc
        except (TimeoutError, OSError) as exc:
            raise IntegrationError(
                f"Palo Alto authentication request failed: {exc}", code="PROVIDER_UNAVAILABLE"
            ) from exc

    def _token(self) -> str:
        return TOKEN_MANAGER.get(self._token_key, self._fetch_token, refresh_margin_seconds=90)

    def _request(
        self,
        path: str,
        params: dict[str, Any],
        *,
        operation: str,
        cache: bool = True,
        retry_auth: bool = True,
        retry_rate: bool = True,
    ) -> Any:
        if not self.configured:
            raise IntegrationError("Device intelligence integration is not configured", code="NOT_CONFIGURED")
        query = {k: v for k, v in params.items() if v is not None and v != ""}
        cache_key = f"{path}?" + urlencode(sorted((str(k), str(v)) for k, v in query.items()))
        now = time.time()
        if cache:
            hit = self._cache.get(cache_key)
            if hit and hit.expires_at <= now:
                self._cache.pop(cache_key, None)
                hit = None
            if hit:
                self._record_timing(operation=operation, duration_ms=0, status_code=200, ok=True, cache_hit=True)
                return hit.value

        started = time.perf_counter()
        token = self._token()
        url = f"{PA_DS_API_HOST}{path}"
        if query:
            url += "?" + urlencode(query)
        req = Request(
            url,
            method="GET",
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/json",
                "User-Agent": f"NodeWatch/{APP_VERSION}",
            },
        )
        status_code: int | None = None
        try:
            REQUEST_LIMITER.wait(f"{PROVIDER_ID}:api", min_interval_seconds=0.05)
            with self._opener.open(req, timeout=self.config.request_timeout) as resp:
                status_code = getattr(resp, "status", None) or resp.getcode()
                payload = self._decode_json(resp.read().decode("utf-8"))
        except HTTPError as exc:
            duration_ms = int((time.perf_counter() - started) * 1000)
            try:
                raw = exc.read().decode("utf-8")
                body = self._decode_json(raw)
                message = (
                    body.get("message") or body.get("detail") or body.get("error") or raw
                    if isinstance(body, dict)
                    else raw
                )
            except Exception:
                message = str(exc)
            if exc.code == 401 and retry_auth:
                TOKEN_MANAGER.invalidate(self._token_key)
                return self._request(
                    path, params, operation=operation, cache=cache, retry_auth=False, retry_rate=retry_rate
                )
            if exc.code == 429 and retry_rate:
                delay = retry_after_seconds(exc.headers, maximum=5.0)
                if delay is not None:
                    time.sleep(delay)
                    return self._request(
                        path, params, operation=operation, cache=cache, retry_auth=retry_auth, retry_rate=False
                    )
            if exc.code == 401:
                code = "AUTHENTICATION_FAILED"
            elif exc.code == 403:
                code = "PERMISSION_DENIED"
            elif exc.code == 404:
                code = "NOT_FOUND"
            elif exc.code == 429:
                code = "RATE_LIMITED"
            else:
                code = "PROVIDER_ERROR"
            self._record_timing(
                operation=operation, duration_ms=duration_ms, status_code=exc.code, ok=False, error=str(message)
            )
            self.health.mark_error(
                redact_text(message, token, self.credentials.get("client_secret", "")),
                status_code=exc.code,
                state="authentication_failed" if exc.code == 401 else "degraded",
            )
            raise IntegrationError(
                f"Device intelligence HTTP {exc.code}: {redact_text(message, token, self.credentials.get('client_secret', ''))}",
                code=code,
                status_code=exc.code,
            ) from exc
        except URLError as exc:
            duration_ms = int((time.perf_counter() - started) * 1000)
            self._record_timing(
                operation=operation, duration_ms=duration_ms, status_code=None, ok=False, error=str(exc.reason)
            )
            self.health.mark_error(str(exc.reason), state="unavailable")
            raise IntegrationError(
                f"Unable to reach device intelligence service: {exc.reason}", code="PROVIDER_UNAVAILABLE"
            ) from exc
        except json.JSONDecodeError as exc:
            duration_ms = int((time.perf_counter() - started) * 1000)
            self._record_timing(
                operation=operation, duration_ms=duration_ms, status_code=status_code, ok=False, error="invalid JSON"
            )
            raise IntegrationError(
                "Device intelligence service returned invalid JSON", code="PROVIDER_ERROR", status_code=status_code
            ) from exc

        duration_ms = int((time.perf_counter() - started) * 1000)
        self._record_timing(operation=operation, duration_ms=duration_ms, status_code=status_code, ok=True)
        self.health.mark_success()
        if cache and isinstance(payload, (dict, list)):
            self._cache[cache_key] = CacheEntry(now + self.config.cache_seconds, payload)
            # Bounded: lookups are keyed by IP/MAC, so the cache would otherwise grow forever.
            if len(self._cache) > _CACHE_MAX_ENTRIES:
                for key in [k for k, v in self._cache.items() if v.expires_at <= now] or list(self._cache)[
                    : len(self._cache) - _CACHE_MAX_ENTRIES
                ]:
                    self._cache.pop(key, None)
        return payload

    @staticmethod
    def _normalize_device(payload: Any) -> dict[str, Any]:
        if not payload:
            return {}
        device: dict[str, Any] = {}
        if isinstance(payload, dict):
            if isinstance(payload.get("devices"), list):
                device = payload["devices"][0] if payload["devices"] else {}
            elif isinstance(payload.get("devices"), dict) and isinstance(payload["devices"].get("hits"), list):
                hits = payload["devices"]["hits"]
                device = hits[0] if hits else {}
            else:
                device = payload
        if not isinstance(device, dict):
            return {}

        def exact(*names: str, default: Any = "") -> Any:
            for name in names:
                if name in device and device[name] not in (None, ""):
                    return device[name]
            return default

        mac = str(exact("MAC", "mac_address", "deviceid") or "").strip().lower()
        result: dict[str, Any] = {
            "hostname": exact("hostname"),
            "ip": exact("ip_address"),
            "mac": mac,
            "vendor": exact("vendor"),
            "model": exact("model"),
            "serial": exact("Serial_Number"),
            "category": exact("category"),
            "profile": exact("profile"),
            "profile_type": exact("profile_type"),
            "profile_vertical": exact("profile_vertical"),
            "os": exact("os_group"),
            "firmware": exact("os/firmware_version", "os_ver", "firmwareVer"),
            "vlan": exact("vlan"),
            "subnet": exact("subnet"),
            "zone": exact("zone"),
            "internet_access": exact("internet_access"),
            "confidence": exact("confidence_score"),
            "risk_level": exact("risk_level"),
            "risk_score": exact("risk_score"),
            "endpoint_protection": exact("endpoint_protection"),
            "status": exact("Status"),
            "first_seen": exact("first_seen_date"),
            "last_activity": exact("last_activity"),
            "critical_alerts": exact("number_of_critical_alerts", default=0),
            "warning_alerts": exact("number_of_warning_alerts", default=0),
            "caution_alerts": exact("number_of_caution_alerts", default=0),
            "info_alerts": exact("number_of_info_alerts", default=0),
            "username": exact("AD_Username"),
            "domain": exact("AD_Domain"),
            "auth_method": exact("Authentication_Method"),
            "eap_method": exact("EAP_Method"),
            "nac_profile": exact("NAC_profile"),
            "nac_state": exact("NAC_Auth_State"),
        }
        return {k: v for k, v in result.items() if v not in (None, "")}

    def lookup_by_ip(self, ip: str, *, fresh: bool = False) -> dict[str, Any]:
        if fresh:
            self.clear_cache()
        payload = self._request("/iot/pub/v1/device/ip", {"ip": ip}, operation="lookup_by_ip", cache=not fresh)
        return self._normalize_device(payload)

    def lookup_by_mac(self, mac: str, *, fresh: bool = False) -> dict[str, Any]:
        if fresh:
            self.clear_cache()
        payload = self._request("/iot/pub/v1/device", {"deviceid": mac}, operation="lookup_by_mac", cache=not fresh)
        return self._normalize_device(payload)

    _PROBE_ENDPOINT = "/iot/pub/v1/device/list"

    def _probe_excerpt(self, raw: str, token: str = "") -> str:
        text = " ".join(str(raw or "").split())
        text = redact_text(text, token, self.credentials.get("client_secret", ""))
        return text[:200] + ("…" if len(text) > 200 else "")

    def test_connection(self) -> dict[str, Any]:
        """Strictly verify sign-in and a real IoT Security read.

        Nothing cached is trusted: the OAuth token and the response cache are dropped
        first, a fresh token is requested, and ``GET /iot/pub/v1/device/list`` must
        answer HTTP 2xx with JSON that is either a list or an object containing a
        ``devices`` list (empty is fine). Any ``_errors``/``error``/``errors``,
        ``success: false`` or a missing device list is a failure. Failures raise
        :class:`IntegrationError` naming the stage ("oauth" or "api") and HTTP status.
        """
        endpoint = self._PROBE_ENDPOINT
        tsg = str(self.credentials.get("tsg_id") or "")
        tsg_suffix = tsg[-4:]
        TOKEN_MANAGER.invalidate(self._token_key)
        self.clear_cache()

        # Stage 1: OAuth (always a fresh token).
        try:
            token = self._token()
        except IntegrationError as exc:
            status = exc.status_code
            raise IntegrationError(
                f"Sign-in failed (stage: oauth, POST /oauth2/access_token → "
                f"{f'HTTP {status}' if status else 'no HTTP response'}): {exc}",
                code=exc.code or "AUTHENTICATION_FAILED",
                status_code=status or 502,
            ) from exc

        # Stage 2: a real, uncached IoT Security API read.
        def fail(status: int | None, reason: str, raw: str = "", request_id: str = "") -> IntegrationError:
            parts = [
                f"IoT Security API check failed (stage: api, GET {endpoint} → "
                f"{f'HTTP {status}' if status else 'no HTTP response'}): {reason}"
            ]
            excerpt = self._probe_excerpt(raw, token)
            if excerpt:
                parts.append(f"Response: {excerpt}")
            if request_id:
                parts.append(f"Request ID: {request_id}")
            code = {401: "AUTHENTICATION_FAILED", 403: "PERMISSION_DENIED", 429: "RATE_LIMITED"}.get(
                status or 0, "PROVIDER_ERROR"
            )
            self.health.mark_error(reason, status_code=status, state="degraded")
            # A 2xx answer that is not a valid device list is still a failed check;
            # report it as a gateway error rather than echoing the misleading 200.
            http_status = status if status and status >= 400 else 502
            return IntegrationError(". ".join(parts), code=code, status_code=http_status)

        url = f"{PA_DS_API_HOST}{endpoint}?" + urlencode({"detail": "false", "pagelength": 1})
        req = Request(
            url,
            method="GET",
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/json",
                "User-Agent": f"NodeWatch/{APP_VERSION}",
            },
        )
        started = time.perf_counter()
        status: int | None = None
        raw = ""
        header_request_id = ""
        try:
            REQUEST_LIMITER.wait(f"{PROVIDER_ID}:api", min_interval_seconds=0.05)
            with self._opener.open(req, timeout=self.config.request_timeout) as resp:
                status = getattr(resp, "status", None) or resp.getcode()
                headers = getattr(resp, "headers", None)
                if headers is not None:
                    header_request_id = str(headers.get("x-request-id") or headers.get("X-Request-Id") or "")
                raw = resp.read().decode("utf-8", errors="replace")
        except HTTPError as exc:
            try:
                raw = exc.read().decode("utf-8", errors="replace")
            except Exception:
                raw = ""
            request_id = ""
            try:
                body = json.loads(raw) if raw else None
                if isinstance(body, dict):
                    request_id = str(body.get("_request_id") or "")
            except ValueError:
                pass
            if exc.code == 401:
                TOKEN_MANAGER.invalidate(self._token_key)
            self._record_timing(
                operation="health_probe",
                duration_ms=int((time.perf_counter() - started) * 1000),
                status_code=exc.code,
                ok=False,
                error=raw[:300],
            )
            raise fail(exc.code, "the API rejected the request", raw, request_id) from exc
        except URLError as exc:
            raise fail(None, f"unable to reach the API ({exc.reason})") from exc
        except (TimeoutError, OSError) as exc:
            raise fail(None, f"request failed ({exc})") from exc

        self._record_timing(
            operation="health_probe",
            duration_ms=int((time.perf_counter() - started) * 1000),
            status_code=status,
            ok=bool(status and 200 <= status < 300),
        )
        if not status or not 200 <= status < 300:
            raise fail(status, "unexpected HTTP status", raw, header_request_id)
        try:
            payload = self._decode_json(raw)
        except ValueError as exc:
            raise fail(status, "the response was not JSON", raw, header_request_id) from exc

        request_id = header_request_id
        devices: list | None = None
        total: int | None = None
        if isinstance(payload, list):
            devices = payload
        elif isinstance(payload, dict):
            request_id = str(payload.get("_request_id") or request_id)
            api_errors = payload.get("_errors") or payload.get("errors") or payload.get("error")
            if api_errors or payload.get("success") is False:
                raise fail(status, "the API reported an error", raw, request_id)
            if isinstance(payload.get("devices"), list):
                devices = payload["devices"]
            for key in ("total", "count", "total_count"):
                if key in payload:
                    try:
                        total = int(payload[key])
                    except (TypeError, ValueError):
                        total = None
                    break
        if devices is None:
            raise fail(status, "the response did not contain a device list", raw, request_id)

        self.health.mark_success()
        return {
            "ok": True,
            "reachable": True,
            "authorized": True,
            "stage": "api",
            "status_code": status,
            "endpoint": endpoint,
            "tsg_suffix": tsg_suffix,
            "devices_returned": len(devices),
            "total": total,
            "request_id": request_id,
        }

    def clear_cache(self) -> None:
        self._cache.clear()


_provider_singleton: PaloAltoDeviceSecurityProvider | None = None


def get_palo_alto_device_security_provider(*, reset: bool = False) -> PaloAltoDeviceSecurityProvider:
    global _provider_singleton
    if reset or _provider_singleton is None:
        _provider_singleton = PaloAltoDeviceSecurityProvider()
    return _provider_singleton


registry.register(DESCRIPTOR, get_palo_alto_device_security_provider)
