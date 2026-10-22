from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Body, HTTPException

from app.integrations import registry
from app.integrations.base import IntegrationError
from app.integrations.diagnostics import record_integration_event
from app.integrations.vendor import VENDORS
from app.integrations.config import (
    PaloAltoDeviceSecurityConfig,
    get_palo_alto_config,
    get_palo_alto_credentials,
    merge_palo_alto_credentials,
    reset_palo_alto_config,
    save_palo_alto_config,
    set_palo_alto_enabled,
    validate_palo_alto_credentials,
    StrataLoggingConfig,
    get_strata_logging_config,
    get_strata_logging_credentials,
    SLS_TENANT_PATTERN,
    normalize_sls_query_host,
    reset_strata_logging_config,
    save_strata_logging_config,
    validate_strata_logging_credentials,
)
from app.integrations.providers.palo_alto_device_security import (
    PaloAltoDeviceSecurityProvider,
    get_palo_alto_device_security_provider,
)
from app.integrations.auth import TOKEN_MANAGER
from app.integrations.providers.traffic import APPROVED_TRAFFIC_PROVIDER_ID, get_traffic_sessions_provider
from app.integrations.providers.strata_logging import StrataLoggingProvider, get_strata_logging_provider
from app.integrations.providers.strata_logging_auth import verify_common_services_oauth
from app.integrations.query import invalidate_query_cache

router = APIRouter(prefix="/api/integrations", tags=["integrations"])


def _public_sls_state() -> dict:
    cfg = get_strata_logging_config()
    creds = get_strata_logging_credentials()
    provider = get_strata_logging_provider()
    credential_complete = not validate_strata_logging_credentials(creds)
    if not credential_complete:
        status = "not_configured"
        label = "Common Services credentials required"
    elif cfg.enabled and not cfg.verified:
        status = "verification_required"
        label = "Verification required"
    elif not cfg.enabled:
        status = "configured_disabled" if cfg.verified else "verification_required"
        label = "Verified · Disabled" if cfg.verified else "Ready to verify"
    elif provider.configured:
        status = "connected"
        label = "Connected"
    else:
        status = "configuration_invalid"
        label = "Configuration invalid"
    return {
        "id": "strata_logging_service",
        "enabled": cfg.enabled,
        "configured": provider.configured,
        "verified": cfg.verified,
        "verified_at": cfg.verified_at,
        "auth_mode": cfg.auth_mode,
        "config_version": cfg.config_version,
        "query_api": "scm_logviewer",
        "query_host": cfg.query_host,
        "tenant_header": cfg.tenant_header,
        "status": status,
        "status_label": label,
        "provider_authority": APPROVED_TRAFFIC_PROVIDER_ID,
        "credential_source": "Palo Alto Common Services",
        "client_id_present": bool(creds.get("client_id")),
        "client_secret_present": bool(creds.get("client_secret")),
        "tsg_id_present": bool(creds.get("tsg_id")),
        "credential_store": "Windows Credential Manager",
        "read_only": True,
        "health": provider.health_state().public_dict,
        "capabilities": list(provider.capabilities()),
        "declared_capabilities": list(provider.descriptor.capabilities),
    }


def _sls_settings_from_payload(payload: dict, current: StrataLoggingConfig) -> tuple[str, str]:
    """Return (query_host, tenant_header) from the request, falling back to saved values."""
    if "query_host" in payload:
        query_host = normalize_sls_query_host(str(payload.get("query_host") or ""))
        if not query_host:
            raise HTTPException(
                status_code=400,
                detail="Log query host must be a Prisma Access API host such as https://pa-us01.api.prismaaccess.com",
            )
    else:
        query_host = current.query_host
    tenant_header = str(payload.get("tenant_header", current.tenant_header) or "").strip()
    if tenant_header and not SLS_TENANT_PATTERN.match(tenant_header):
        raise HTTPException(
            status_code=400, detail="Prisma-Tenant override must look like <TSG ID> or <TSG ID>:<sub-tenant ID>"
        )
    return query_host, tenant_header


def _sls_candidate(payload: dict) -> tuple[StrataLoggingConfig, dict[str, str]]:
    """Config used for a live verification. Marked enabled+verified only so the probe can run."""
    current = get_strata_logging_config()
    query_host, tenant_header = _sls_settings_from_payload(payload, current)
    cfg = StrataLoggingConfig(
        enabled=True,
        verified=True,
        verified_at=current.verified_at,
        request_timeout=current.request_timeout,
        query_timeout=current.query_timeout,
        cache_seconds=current.cache_seconds,
        query_host=query_host,
        tenant_header=tenant_header,
    )
    return cfg, get_strata_logging_credentials()


def _sls_event(operation: str, *, ok: bool, status_code: int | None = None, error: str = "", **metadata) -> None:
    record_integration_event(
        provider="strata_logging_service",
        operation=operation,
        ok=ok,
        status_code=status_code,
        error=error,
        metadata=metadata,
    )


def _sls_verify_and_save(payload: dict, *, enable: bool, failure_prefix: str) -> dict:
    """Run one live log query with the candidate settings; persist only on success."""
    cfg, creds = _sls_candidate(payload)
    errors = cfg.validate() + validate_strata_logging_credentials(creds)
    if errors:
        message = "; ".join(errors)
        _sls_event(
            "SLS_ENABLE_FAILED" if enable else "SLS_TEST_FAILED",
            ok=False,
            status_code=400,
            error=message,
            phase="configuration" if enable else "verification",
            enabled=enable,
        )
        raise HTTPException(status_code=400, detail=message)
    try:
        probe = StrataLoggingProvider(config=cfg, credentials=creds).test_connection()
    except IntegrationError as exc:
        _sls_event(
            "SLS_ENABLE_FAILED" if enable else "SLS_TEST_FAILED",
            ok=False,
            status_code=exc.status_code or 502,
            error=f"{exc.code}: {exc}",
            phase="configuration" if enable else "verification",
            enabled=enable,
        )
        raise HTTPException(status_code=exc.status_code or 502, detail=f"{failure_prefix}: {exc.code}: {exc}") from exc
    verified_at = datetime.now(timezone.utc).isoformat()
    persisted = StrataLoggingConfig(
        enabled=enable,
        verified=True,
        verified_at=verified_at,
        request_timeout=cfg.request_timeout,
        query_timeout=cfg.query_timeout,
        cache_seconds=cfg.cache_seconds,
        query_host=cfg.query_host,
        tenant_header=cfg.tenant_header,
    )
    try:
        save_strata_logging_config(persisted, creds)
        get_strata_logging_provider(reset=True)
        invalidate_query_cache()
    except Exception as exc:
        _sls_event(
            "SLS_ENABLE_FAILED" if enable else "SLS_TEST_FAILED",
            ok=False,
            status_code=500,
            error=f"Persistence failure: {type(exc).__name__}",
            phase="configuration",
            enabled=enable,
        )
        raise HTTPException(
            status_code=500, detail=f"Unable to save Strata Logging Service integration: {exc}"
        ) from exc
    sample_count = int(probe.get("sample_count") or 0)
    _sls_event(
        "SLS_VERIFICATION_SAVED",
        ok=True,
        status_code=200,
        phase="configuration",
        enabled=enable,
        verified=True,
        sample_count=sample_count,
    )
    return {
        **probe,
        "ok": True,
        "integration": _public_sls_state(),
        "sample_count": sample_count,
        "provider_authority": APPROVED_TRAFFIC_PROVIDER_ID,
    }


def _refresh_after_credential_change() -> None:
    """Traffic & Sessions shares the Palo Alto credentials; drop stale copies everywhere."""
    TOKEN_MANAGER.clear()
    get_palo_alto_device_security_provider(reset=True)
    get_strata_logging_provider(reset=True)
    invalidate_query_cache()
    # v0.10.23: the Strata Cloud Manager firewall inventory uses the same account; drop its cached
    # inventory and connection state too (it kept using the old account for up to a minute).
    try:
        from app.integrations.connectors import sdk

        scm = sdk.get_connector("paloalto_scm")
        if scm is not None:
            scm.reset_state()
    except Exception:  # noqa: BLE001 - never block a credential save
        pass


def _public_pa_state() -> dict:
    cfg = get_palo_alto_config()
    creds = get_palo_alto_credentials()
    return {
        "id": "palo_alto_device_security",
        "enabled": cfg.enabled,
        "configured": not cfg.validate() and not validate_palo_alto_credentials(creds),
        "client_id_present": bool(creds.get("client_id")),
        "client_secret_present": bool(creds.get("client_secret")),
        "tsg_id_present": bool(creds.get("tsg_id")),
        "credential_store": "Windows Credential Manager",
        "read_only": True,
        "capabilities": list(
            registry.descriptor("palo_alto_device_security").capabilities
            if registry.descriptor("palo_alto_device_security")
            else ()
        ),
    }


def _candidate(payload: dict) -> tuple[PaloAltoDeviceSecurityConfig, dict[str, str]]:
    current = get_palo_alto_config()
    credentials = merge_palo_alto_credentials(
        client_id=str(payload.get("client_id") or ""),
        client_secret=str(payload.get("client_secret") or ""),
        tsg_id=str(payload.get("tsg_id") or ""),
    )
    config = PaloAltoDeviceSecurityConfig(
        enabled=True,  # test candidate must be active even before persistence
        request_timeout=current.request_timeout,
        cache_seconds=current.cache_seconds,
        instance_id=current.instance_id,
    )
    return config, credentials


@router.get("")
def integrations():
    return {
        "providers": registry.descriptors(),
        "vendors": VENDORS.catalog(),
        "palo_alto_device_security": _public_pa_state(),
        "strata_logging_service": _public_sls_state(),
        "traffic_sessions": {
            "enabled": get_traffic_sessions_provider().configured,
            "configured": get_traffic_sessions_provider().configured,
            "status": "ready" if get_traffic_sessions_provider().configured else _public_sls_state()["status"],
            "read_only": True,
            "provider": APPROVED_TRAFFIC_PROVIDER_ID,
            "provider_authority": APPROVED_TRAFFIC_PROVIDER_ID,
        },
    }


@router.post("/palo-alto-device-security/test")
def test_palo_alto_device_security(payload: dict = Body(...)):
    config, credentials = _candidate(payload)
    validation = config.validate() + validate_palo_alto_credentials(credentials)
    if validation:
        raise HTTPException(status_code=400, detail="; ".join(validation))
    try:
        result = PaloAltoDeviceSecurityProvider(config=config, credentials=credentials).test_connection()
        return {**result, "read_only": True}
    except IntegrationError as exc:
        raise HTTPException(status_code=exc.status_code or 502, detail=str(exc)) from exc


@router.post("/palo-alto-device-security/save")
def save_palo_alto_device_security(payload: dict = Body(...)):
    config, credentials = _candidate(payload)
    validation = config.validate() + validate_palo_alto_credentials(credentials)
    if validation:
        raise HTTPException(status_code=400, detail="; ".join(validation))

    requested_enabled = bool(payload.get("enabled", True))
    try:
        if requested_enabled:
            # Device Intelligence on: prove the IoT API itself answers.
            PaloAltoDeviceSecurityProvider(config=config, credentials=credentials).test_connection()
        else:
            # Device Intelligence off (e.g. tenant only uses Traffic & Sessions):
            # still prove the shared Common Services credentials can obtain a token.
            verify_common_services_oauth(credentials)
    except IntegrationError as exc:
        raise HTTPException(status_code=exc.status_code or 502, detail=f"Nothing was saved: {exc}") from exc

    persisted = PaloAltoDeviceSecurityConfig(
        enabled=requested_enabled,
        request_timeout=config.request_timeout,
        cache_seconds=config.cache_seconds,
        instance_id=config.instance_id,
    )
    try:
        save_palo_alto_config(persisted, credentials)
        _refresh_after_credential_change()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Unable to save integration securely: {exc}") from exc
    return {"ok": True, "integration": _public_pa_state()}


@router.post("/palo-alto-device-security/enable")
def enable_palo_alto_device_security(payload: dict = Body(...)):
    enabled = bool(payload.get("enabled", True))
    if enabled:
        credentials = get_palo_alto_credentials()
        validation = get_palo_alto_config().validate() + validate_palo_alto_credentials(credentials)
        if validation:
            raise HTTPException(status_code=400, detail="; ".join(validation))
    set_palo_alto_enabled(enabled)
    _refresh_after_credential_change()
    return {"ok": True, "integration": _public_pa_state()}


@router.post("/palo-alto-device-security/reset")
def reset_palo_alto_device_security():
    try:
        removed = reset_palo_alto_config()
        _refresh_after_credential_change()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Unable to reset integration: {exc}") from exc
    note = (
        ""
        if removed
        else "Device Security was reset. The Palo Alto service account was kept because Traffic & Sessions "
        "(and the Strata Cloud Manager firewall inventory) still use it."
    )
    return {"ok": True, "credentials_kept": not removed, "note": note, "integration": _public_pa_state()}


@router.post("/strata-logging/ui-event")
def strata_logging_ui_event(payload: dict = Body(...)):
    event = str(payload.get("event") or "").strip().upper()[:80]
    allowed = {
        "SLS_UI_ENABLE_CLICKED",
        "SLS_UI_DISABLE_CLICKED",
        "SLS_UI_VERIFY_CLICKED",
        "SLS_UI_RESET_CLICKED",
    }
    if event not in allowed:
        raise HTTPException(status_code=400, detail="Unsupported SLS UI diagnostic event")
    record_integration_event(
        provider="strata_logging_service",
        operation=event,
        ok=True,
        metadata={"phase": "ui", "enabled": bool(payload.get("enabled", False))},
    )
    return {"ok": True}


@router.post("/strata-logging/test")
def test_strata_logging(payload: dict = Body(...)):
    """Verify with a live query without enabling. A success is remembered (Verified · Disabled)."""
    _sls_event("SLS_TEST_STARTED", ok=True, phase="verification")
    current = get_strata_logging_config()
    return _sls_verify_and_save(payload, enable=current.enabled, failure_prefix="Verification failed")


@router.post("/strata-logging/enable")
def enable_strata_logging(payload: dict = Body(...)):
    enabled = bool(payload.get("enabled", True))
    _sls_event(
        "SLS_ENABLE_REQUESTED" if enabled else "SLS_DISABLE_REQUESTED", ok=True, phase="configuration", enabled=enabled
    )
    if enabled:
        # Verification runs before anything is persisted; failure leaves the saved state unchanged.
        return _sls_verify_and_save(payload, enable=True, failure_prefix="Integration was not enabled")

    current = get_strata_logging_config()
    query_host, tenant_header = _sls_settings_from_payload(payload, current)
    persisted = StrataLoggingConfig(
        enabled=False,
        verified=current.verified and query_host == current.query_host and tenant_header == current.tenant_header,
        verified_at=current.verified_at,
        request_timeout=current.request_timeout,
        query_timeout=current.query_timeout,
        cache_seconds=current.cache_seconds,
        query_host=query_host,
        tenant_header=tenant_header,
    )
    try:
        save_strata_logging_config(persisted, get_strata_logging_credentials(), require_credentials=False)
        get_strata_logging_provider(reset=True)
        invalidate_query_cache()
    except Exception as exc:
        _sls_event(
            "SLS_DISABLE_FAILED",
            ok=False,
            status_code=500,
            error=f"Persistence failure: {type(exc).__name__}",
            phase="configuration",
            enabled=False,
        )
        raise HTTPException(
            status_code=500, detail=f"Unable to update Strata Logging Service integration: {exc}"
        ) from exc
    _sls_event(
        "SLS_DISABLED_SAVED",
        ok=True,
        status_code=200,
        phase="configuration",
        enabled=False,
        verified=persisted.verified,
    )
    return {"ok": True, "integration": _public_sls_state(), "sample_count": None}


@router.post("/strata-logging/reset")
def reset_strata_logging():
    _sls_event("SLS_RESET_REQUESTED", ok=True, phase="configuration")
    try:
        reset_strata_logging_config()
        get_strata_logging_provider(reset=True)
        invalidate_query_cache()
    except Exception as exc:
        _sls_event(
            "SLS_RESET_FAILED",
            ok=False,
            status_code=500,
            error=f"Reset failure: {type(exc).__name__}",
            phase="configuration",
        )
        raise HTTPException(
            status_code=500, detail=f"Unable to reset Strata Logging Service integration: {exc}"
        ) from exc
    _sls_event("SLS_RESET_SAVED", ok=True, status_code=200, phase="configuration", enabled=False, verified=False)
    return {"ok": True, "integration": _public_sls_state()}
