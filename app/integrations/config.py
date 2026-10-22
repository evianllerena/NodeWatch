from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from typing import Any
from urllib.parse import urlparse

from app.core.config import DATA_ROOT
from app.core.file_utils import locked_json_update
from app.integrations.secrets import SecretStore

INTEGRATIONS_FILE = DATA_ROOT / "integrations.json"
PA_DS_CREDENTIAL_REF = "NodeWatch:Integration:PaloAltoDeviceSecurity:OAuthClientCredentials"
PA_DS_API_HOST = "https://api.strata.paloaltonetworks.com"
PA_DS_AUTH_HOST = "https://auth.apps.paloaltonetworks.com"
SLS_CREDENTIAL_REF = (
    "NodeWatch:Integration:StrataLoggingService:SCMRegistration"  # legacy v0.10.2 secret target; deleted on save/reset
)
SLS_AUTH_HOST = PA_DS_AUTH_HOST
SLS_AUTH_PATH = "/oauth2/access_token"
SLS_AUTH_MODE = "common_services_oauth"
# v4 (NodeWatch 0.10.7) moved Traffic & Sessions from the retired
# ``/logging-service/v1/queries`` API to the Strata Cloud Manager Log Viewer API.
# Older saved configs must be re-verified once against the new endpoint.
SLS_CONFIG_VERSION = 4

# Strata Cloud Manager's Log Viewer queries the regional Prisma Access API host
# (observed: https://pa-us01.api.prismaaccess.com for US tenants). The bearer
# token may only ever be sent to a host under this approved suffix.
SLS_DEFAULT_QUERY_HOST = "https://pa-us01.api.prismaaccess.com"
SLS_QUERY_HOST_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.api\.prismaaccess\.com$")
SLS_DEFAULT_QUERY_TIMEOUT = 90
SLS_LOGVIEWER_PATH = "/api/sase/v3.0/resource/query/logviewer"
# Prisma-Tenant header value: "<TSG ID>" or "<TSG ID>:<sub-tenant/customer ID>".
SLS_TENANT_PATTERN = re.compile(r"^[0-9]{1,20}(?::[0-9]{1,20})?$")


def normalize_sls_query_host(value: str) -> str:
    """Return ``https://<host>`` for an approved Prisma Access API host, else ``""``."""
    raw = str(value or "").strip().lower().rstrip("/")
    if not raw:
        return SLS_DEFAULT_QUERY_HOST
    if "://" not in raw:
        raw = "https://" + raw
    parsed = urlparse(raw)
    host = parsed.hostname or ""
    if (
        parsed.scheme != "https"
        or parsed.port not in (None, 443)
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
        or parsed.username
        or parsed.password
        or not SLS_QUERY_HOST_PATTERN.match(host)
    ):
        return ""
    return f"https://{host}"


@dataclass(frozen=True)
class StrataLoggingConfig:
    enabled: bool = False
    verified: bool = False
    verified_at: str = ""
    auth_mode: str = SLS_AUTH_MODE
    config_version: int = SLS_CONFIG_VERSION
    auth_host: str = SLS_AUTH_HOST
    verify_tls: bool = True
    request_timeout: int = 30
    # Log Viewer answered a 1-row verification in ~33 s on a real tenant; leave headroom.
    query_timeout: int = SLS_DEFAULT_QUERY_TIMEOUT
    cache_seconds: int = 30
    query_host: str = SLS_DEFAULT_QUERY_HOST
    tenant_header: str = ""  # blank = use the TSG ID from the Common Services credentials

    def validate(self) -> list[str]:
        errors: list[str] = []
        if not self.query_host or normalize_sls_query_host(self.query_host) != self.query_host:
            errors.append(
                "Log query host must be a Prisma Access API host such as https://pa-us01.api.prismaaccess.com"
            )
        if self.tenant_header and not SLS_TENANT_PATTERN.match(self.tenant_header):
            errors.append("Prisma-Tenant override must look like <TSG ID> or <TSG ID>:<sub-tenant ID>")
        parsed = urlparse(self.auth_host)
        expected = urlparse(SLS_AUTH_HOST)
        if parsed.scheme != "https" or parsed.hostname != expected.hostname:
            errors.append("Strata Logging Service authentication host is not an approved NodeWatch destination")
        if parsed.path not in ("", "/") or parsed.query or parsed.fragment or parsed.username or parsed.password:
            errors.append("Strata Logging Service authentication host must contain only the approved HTTPS host")
        if self.auth_mode != SLS_AUTH_MODE:
            errors.append("Strata Logging Service authentication mode is not supported")
        if self.config_version != SLS_CONFIG_VERSION:
            errors.append("Strata Logging Service configuration version is not supported")
        if not self.verify_tls:
            errors.append("Strata Logging Service requires TLS certificate verification")
        if self.request_timeout < 3 or self.request_timeout > 120:
            errors.append("Strata Logging Service request timeout must be between 3 and 120 seconds")
        if self.query_timeout < 5 or self.query_timeout > 180:
            errors.append("Strata Logging Service query timeout must be between 5 and 180 seconds")
        if self.cache_seconds < 5 or self.cache_seconds > 300:
            errors.append("Strata Logging Service cache duration must be between 5 and 300 seconds")
        return errors

    @property
    def public_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class PaloAltoDeviceSecurityConfig:
    enabled: bool = False
    api_host: str = PA_DS_API_HOST
    auth_host: str = PA_DS_AUTH_HOST
    verify_tls: bool = True
    request_timeout: int = 20
    cache_seconds: int = 300
    instance_id: str = "primary"

    def validate(self) -> list[str]:
        errors: list[str] = []
        for label, value, expected in (
            ("Device Security API host", self.api_host, PA_DS_API_HOST),
            ("Palo Alto authentication host", self.auth_host, PA_DS_AUTH_HOST),
        ):
            parsed = urlparse(value)
            if parsed.scheme != "https" or parsed.hostname != urlparse(expected).hostname:
                errors.append(f"{label} is not an approved NodeWatch destination")
            if parsed.path not in ("", "/") or parsed.query or parsed.fragment or parsed.username or parsed.password:
                errors.append(f"{label} must contain only the approved HTTPS host")
        if not self.verify_tls:
            errors.append("Palo Alto integration requires TLS certificate verification")
        if self.request_timeout < 3 or self.request_timeout > 120:
            errors.append("Palo Alto request timeout must be between 3 and 120 seconds")
        return errors

    @property
    def public_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        return payload


def _update_section(name: str, value: dict[str, Any] | None) -> None:
    """Set (or remove, when ``value`` is None) one section of integrations.json under a file lock."""

    def apply(current: Any) -> dict[str, Any] | None:
        root = dict(current) if isinstance(current, dict) else {}
        if value is None:
            root.pop(name, None)
        else:
            root[name] = value
        return root or None

    DATA_ROOT.mkdir(parents=True, exist_ok=True)
    locked_json_update(INTEGRATIONS_FILE, apply, default={})


def _upgrade_query_timeout(value: Any) -> int:
    # 45 was the pre-v0.10.7 default and was saved with every config; treat it as
    # "not chosen" so existing installs get the longer Log Viewer default.
    timeout = _coerce_int(value, SLS_DEFAULT_QUERY_TIMEOUT, 5, 180)
    return SLS_DEFAULT_QUERY_TIMEOUT if timeout == 45 else timeout


def _load_payload() -> dict[str, Any]:
    if not INTEGRATIONS_FILE.exists():
        return {}
    try:
        value = json.loads(INTEGRATIONS_FILE.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except Exception:
        return {}


def _coerce_int(value: Any, default: int, minimum: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return max(minimum, min(maximum, parsed))


def get_palo_alto_config() -> PaloAltoDeviceSecurityConfig:
    root = _load_payload()
    payload = root.get("palo_alto_device_security") if isinstance(root.get("palo_alto_device_security"), dict) else {}
    return PaloAltoDeviceSecurityConfig(
        enabled=bool(payload.get("enabled", False)),
        api_host=PA_DS_API_HOST,
        auth_host=PA_DS_AUTH_HOST,
        verify_tls=True,
        request_timeout=_coerce_int(payload.get("request_timeout"), 20, 3, 120),
        cache_seconds=_coerce_int(payload.get("cache_seconds"), 300, 30, 1800),
        instance_id=str(payload.get("instance_id") or "primary")[:64],
    )


def get_palo_alto_credentials() -> dict[str, str]:
    store = SecretStore(DATA_ROOT)
    payload = store.get_json(PA_DS_CREDENTIAL_REF)
    return {
        "client_id": str(payload.get("client_id") or "").strip(),
        "client_secret": str(payload.get("client_secret") or "").strip(),
        "tsg_id": str(payload.get("tsg_id") or "").strip(),
    }


def merge_palo_alto_credentials(*, client_id: str = "", client_secret: str = "", tsg_id: str = "") -> dict[str, str]:
    current = get_palo_alto_credentials()
    return {
        "client_id": (client_id or current.get("client_id") or "").strip(),
        "client_secret": (client_secret or current.get("client_secret") or "").strip(),
        "tsg_id": (tsg_id or current.get("tsg_id") or "").strip(),
    }


def validate_palo_alto_credentials(credentials: dict[str, str]) -> list[str]:
    errors: list[str] = []
    if not credentials.get("client_id"):
        errors.append("Palo Alto Client ID is missing")
    if not credentials.get("client_secret"):
        errors.append("Palo Alto Client Secret is missing")
    if not credentials.get("tsg_id"):
        errors.append("Palo Alto TSG ID is missing")
    return errors


def save_palo_alto_config(config: PaloAltoDeviceSecurityConfig, credentials: dict[str, str]) -> None:
    validation = config.validate() + validate_palo_alto_credentials(credentials)
    if validation:
        raise ValueError("; ".join(validation))
    _update_section(
        "palo_alto_device_security",
        {
            "enabled": bool(config.enabled),
            "request_timeout": int(config.request_timeout),
            "cache_seconds": int(config.cache_seconds),
            "instance_id": config.instance_id,
        },
    )
    SecretStore(DATA_ROOT).put_json(
        PA_DS_CREDENTIAL_REF,
        credentials,
        username="NodeWatch Palo Alto Device Security OAuth",
    )


def set_palo_alto_enabled(enabled: bool) -> PaloAltoDeviceSecurityConfig:
    current = get_palo_alto_config()
    _update_section(
        "palo_alto_device_security",
        {
            "enabled": bool(enabled),
            "request_timeout": current.request_timeout,
            "cache_seconds": current.cache_seconds,
            "instance_id": current.instance_id,
        },
    )
    return get_palo_alto_config()


def reset_palo_alto_config() -> bool:
    """Reset Device Security. Returns True when the shared credentials were removed too.

    v0.10.23: the Palo Alto service account is shared with Traffic & Sessions and the Strata Cloud
    Manager firewall inventory. Resetting Device Security used to delete it for all of them,
    silently switching those off; it is now kept while Traffic & Sessions is enabled.
    """
    _update_section("palo_alto_device_security", None)
    if get_strata_logging_config().enabled:
        return False
    SecretStore(DATA_ROOT).delete(PA_DS_CREDENTIAL_REF)
    return True


def get_strata_logging_config() -> StrataLoggingConfig:
    root = _load_payload()
    payload = root.get("strata_logging_service") if isinstance(root.get("strata_logging_service"), dict) else {}
    # v0.10.1 had the same secure credential target but no persisted verification
    # marker. Preserve credentials/settings while requiring one real read-only
    # traffic query after upgrade before the capability becomes active.
    stored_version = _coerce_int(payload.get("config_version"), SLS_CONFIG_VERSION, 0, 1000)
    # A verification made against an older query API says nothing about the
    # current one: keep the saved settings but require one new live check.
    upgraded = stored_version < SLS_CONFIG_VERSION
    query_host = normalize_sls_query_host(str(payload.get("query_host") or "")) or SLS_DEFAULT_QUERY_HOST
    tenant_header = str(payload.get("tenant_header") or "").strip()
    if tenant_header and not SLS_TENANT_PATTERN.match(tenant_header):
        tenant_header = ""
    return StrataLoggingConfig(
        enabled=bool(payload.get("enabled", False)),
        verified=False if upgraded else bool(payload.get("verified", False)),
        verified_at="" if upgraded else str(payload.get("verified_at") or "")[:80],
        auth_mode=SLS_AUTH_MODE,
        config_version=SLS_CONFIG_VERSION,
        auth_host=SLS_AUTH_HOST,
        verify_tls=True,
        request_timeout=_coerce_int(payload.get("request_timeout"), 30, 3, 120),
        # v0.10.23: a value saved by the user (marker below) is used as is; only old saves that
        # never chose a timeout get the newer default.
        query_timeout=_coerce_int(payload.get("query_timeout"), SLS_DEFAULT_QUERY_TIMEOUT, 5, 180)
        if payload.get("query_timeout_user_set")
        else _upgrade_query_timeout(payload.get("query_timeout")),
        cache_seconds=_coerce_int(payload.get("cache_seconds"), 30, 5, 300),
        query_host=query_host,
        tenant_header=tenant_header,
    )


def get_strata_logging_credentials() -> dict[str, str]:
    # SLS REST queries use the same Common Services OAuth service account as SCM.
    return get_palo_alto_credentials()


def validate_strata_logging_credentials(credentials: dict[str, str]) -> list[str]:
    return validate_palo_alto_credentials(credentials)


def save_strata_logging_config(
    config: StrataLoggingConfig, credentials: dict[str, str], *, require_credentials: bool = True
) -> None:
    # Disabling must always be possible, even after the shared credentials were removed.
    validation = config.validate() + (validate_strata_logging_credentials(credentials) if require_credentials else [])
    if validation:
        raise ValueError("; ".join(validation))
    _update_section(
        "strata_logging_service",
        {
            "config_version": SLS_CONFIG_VERSION,
            "auth_mode": SLS_AUTH_MODE,
            "enabled": bool(config.enabled),
            "verified": bool(config.verified),
            "verified_at": str(config.verified_at or "")[:80],
            "request_timeout": int(config.request_timeout),
            "query_timeout": int(config.query_timeout),
            # v0.10.23: a timeout saved from the form is the user's choice and is never rewritten.
            "query_timeout_user_set": int(config.query_timeout) != SLS_DEFAULT_QUERY_TIMEOUT,
            "cache_seconds": int(config.cache_seconds),
            "query_host": config.query_host,
            "tenant_header": config.tenant_header,
        },
    )
    # Remove obsolete XSOAR-style SLS secrets from v0.10.2 if they were ever stored.
    SecretStore(DATA_ROOT).delete(SLS_CREDENTIAL_REF)


def reset_strata_logging_config() -> None:
    _update_section("strata_logging_service", None)
    SecretStore(DATA_ROOT).delete(SLS_CREDENTIAL_REF)
