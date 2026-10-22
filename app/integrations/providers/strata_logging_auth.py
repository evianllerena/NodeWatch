from __future__ import annotations

import base64
import json
import ssl
import time
from dataclasses import dataclass
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener

from app.core.version import APP_VERSION
from app.integrations.auth import TOKEN_MANAGER
from app.integrations.base import IntegrationError
from app.integrations.diagnostics import record_integration_event
from app.integrations.config import PA_DS_AUTH_HOST, StrataLoggingConfig, validate_palo_alto_credentials


@dataclass(frozen=True)
class SlsAuthContext:
    access_token: str
    tsg_id: str
    expires_at_monotonic: float


class ApprovedSlsRedirectHandler(HTTPRedirectHandler):
    """Never forward OAuth or bearer credentials through HTTP redirects."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


def json_body(resp) -> Any:  # noqa: ANN001
    raw = resp.read().decode("utf-8", errors="replace")
    if not raw.strip():
        return {}
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise IntegrationError(
            "Strata Logging Service returned invalid JSON",
            code="SLS_INVALID_PROVIDER_RESPONSE",
        ) from exc


def _auth_http_code(http_status: int) -> str:
    if http_status in {400, 401}:
        return "SLS_TOKEN_EXCHANGE_FAILED"
    if http_status == 403:
        return "SLS_PERMISSION_DENIED"
    if http_status == 429:
        return "SLS_RATE_LIMITED"
    if 500 <= http_status <= 599:
        return "SLS_PROVIDER_UNAVAILABLE"
    return "SLS_TOKEN_EXCHANGE_FAILED"


class StrataLoggingAuthAdapter:
    """Authenticate SLS with the same Common Services OAuth service account used by SCM.

    Required credential set: Client ID + Client Secret + TSG ID.  NodeWatch does not
    use the Cortex XSOAR Registration ID / Encryption Key flow for this provider.
    """

    def __init__(self, config: StrataLoggingConfig, credentials: dict[str, str], *, opener=None) -> None:
        self.config = config
        self.credentials = credentials
        context = ssl.create_default_context()
        self._opener = opener or build_opener(ApprovedSlsRedirectHandler(), HTTPSHandler(context=context))
        self._context: SlsAuthContext | None = None

    @property
    def credentials_present(self) -> bool:
        return not validate_palo_alto_credentials(self.credentials)

    @property
    def configured(self) -> bool:
        return bool(self.config.enabled and not self.config.validate() and self.credentials_present)

    @property
    def _token_key(self) -> str:
        return f"strata_logging_service:common_services:{self.credentials.get('client_id', '')}:{self.credentials.get('tsg_id', '')}"

    def invalidate(self) -> None:
        TOKEN_MANAGER.invalidate(self._token_key)
        self._context = None

    def _fetch_token(self) -> tuple[str, int]:
        started = time.perf_counter()
        record_integration_event(
            provider="strata_logging_service",
            operation="SLS_OAUTH_STARTED",
            ok=True,
            metadata={"phase": "oauth"},
        )
        client_id = self.credentials["client_id"]
        client_secret = self.credentials["client_secret"]
        tsg_id = self.credentials["tsg_id"]
        basic = base64.b64encode(f"{client_id}:{client_secret}".encode("utf-8")).decode("ascii")
        data = urlencode({"grant_type": "client_credentials", "scope": f"tsg_id:{tsg_id}"}).encode("ascii")
        req = Request(
            PA_DS_AUTH_HOST + "/oauth2/access_token",
            data=data,
            method="POST",
            headers={
                "Authorization": f"Basic {basic}",
                "Accept": "application/json",
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": f"NodeWatch/{APP_VERSION}",
            },
        )
        try:
            with self._opener.open(req, timeout=self.config.request_timeout) as resp:
                status_code = int(getattr(resp, "status", 200) or 200)
                body = json_body(resp)
        except HTTPError as exc:
            duration_ms = int((time.perf_counter() - started) * 1000)
            record_integration_event(
                provider="strata_logging_service",
                operation="SLS_OAUTH_FAILED",
                ok=False,
                duration_ms=duration_ms,
                status_code=exc.code,
                error=f"Common Services OAuth HTTP {exc.code}",
                metadata={"phase": "oauth"},
            )
            raise IntegrationError(
                f"Palo Alto Common Services OAuth HTTP {exc.code}",
                code=_auth_http_code(exc.code),
                status_code=exc.code,
            ) from exc
        except URLError as exc:
            duration_ms = int((time.perf_counter() - started) * 1000)
            record_integration_event(
                provider="strata_logging_service",
                operation="SLS_OAUTH_FAILED",
                ok=False,
                duration_ms=duration_ms,
                error=f"OAuth network error: {exc.reason}",
                metadata={"phase": "oauth"},
            )
            raise IntegrationError(
                f"Unable to reach Palo Alto Common Services OAuth: {exc.reason}",
                code="SLS_PROVIDER_UNAVAILABLE",
            ) from exc
        if not isinstance(body, dict) or not body.get("access_token"):
            duration_ms = int((time.perf_counter() - started) * 1000)
            record_integration_event(
                provider="strata_logging_service",
                operation="SLS_OAUTH_FAILED",
                ok=False,
                duration_ms=duration_ms,
                status_code=status_code,
                error="OAuth response did not include an access token",
                metadata={"phase": "oauth"},
            )
            raise IntegrationError(
                "Palo Alto Common Services OAuth succeeded without an access token",
                code="SLS_INVALID_PROVIDER_RESPONSE",
            )
        try:
            ttl = int(body.get("expires_in") or 900)
        except (TypeError, ValueError):
            ttl = 900
        duration_ms = int((time.perf_counter() - started) * 1000)
        record_integration_event(
            provider="strata_logging_service",
            operation="SLS_OAUTH_SUCCESS",
            ok=True,
            duration_ms=duration_ms,
            status_code=status_code,
            metadata={"phase": "oauth"},
        )
        return str(body["access_token"]), max(60, ttl)

    def authorize(self, *, force: bool = False) -> SlsAuthContext:
        if not self.configured:
            raise IntegrationError(
                "Strata Logging Service requires the Palo Alto Common Services Client ID, Client Secret, and TSG ID",
                code="SLS_NOT_CONFIGURED",
            )
        if force:
            TOKEN_MANAGER.invalidate(self._token_key)
            self._context = None
        token = TOKEN_MANAGER.get(self._token_key, self._fetch_token, refresh_margin_seconds=90)
        self._context = SlsAuthContext(
            access_token=token,
            tsg_id=self.credentials["tsg_id"],
            expires_at_monotonic=time.monotonic() + 120,
        )
        return self._context

    def safe_status(self) -> dict[str, Any]:
        context = self._context
        return {
            "auth_mode": "common_services_oauth",
            "credentials_present": self.credentials_present,
            "token_cached": bool(context and time.monotonic() < context.expires_at_monotonic),
            "auth_host": PA_DS_AUTH_HOST,
            "tsg_id_present": bool(self.credentials.get("tsg_id")),
        }


def verify_common_services_oauth(credentials: dict[str, str], *, opener=None) -> None:
    """Prove the shared Common Services credentials can obtain a token (no API call).

    Used when the Palo Alto credentials are saved without enabling Device
    Intelligence, so a tenant that only uses Traffic & Sessions can still store
    verified credentials.
    """
    errors = validate_palo_alto_credentials(credentials)
    if errors:
        raise IntegrationError("; ".join(errors), code="SLS_NOT_CONFIGURED", status_code=400)
    adapter = StrataLoggingAuthAdapter(StrataLoggingConfig(enabled=True), credentials, opener=opener)
    adapter.authorize(force=True)
