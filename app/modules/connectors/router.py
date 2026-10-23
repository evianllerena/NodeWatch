"""Settings › Connections API (v0.10.16).

GET    /api/v1/connectors               catalog: every discovered connector, its state and form fields
GET    /api/v1/connectors/capabilities  which capabilities at least one connected source offers
POST   /api/v1/connectors/{id}          save the connection form (secrets → secure credential store)
POST   /api/v1/connectors/{id}/test     one cheap read-only call (with the unsaved form when given);
                                        with {"probe": true} the Add-connection checklist: reachable, TLS,
                                        authenticated, per-capability permission probes, what was found
                                        (v0.10.18, read-only, at most 20 s)
POST   /api/v1/connectors/{id}/enabled  switch a saved connection on/off (v0.10.18)
DELETE /api/v1/connectors/{id}          forget the saved settings and secrets

Never returns secret values (secret fields come back as true/false).
"""

from __future__ import annotations

import time
from typing import Any

from fastapi import APIRouter, Body, HTTPException

from app.integrations.base import IntegrationError
from app.integrations.connectors import sdk
from app.integrations.contracts import CAPABILITY_LABELS
from app.integrations.diagnostics import record_integration_event

router = APIRouter(prefix="/api/v1/connectors", tags=["connectors"])


def _row(connector_id: str) -> dict[str, Any]:
    return next((r for r in sdk.catalog() if r["connector_id"] == connector_id), {})


def _connector(connector_id: str) -> sdk.Connector:
    connector = sdk.get_connector(connector_id)
    if connector is None:
        raise HTTPException(status_code=404, detail="Unknown connector")
    return connector


@router.get("")
def list_connectors() -> dict[str, Any]:
    return {
        "connectors": sdk.catalog(),
        "categories": sdk.CATEGORY_LABELS,
        "capability_labels": CAPABILITY_LABELS,
        "capability_features": {
            cap: [{"tool": t, "label": label, "what": what} for t, label, what in places]
            for cap, places in sdk.CAPABILITY_FEATURES.items()
        },
        "probe_budget_s": sdk.PROBE_BUDGET_S,
    }


@router.get("/capabilities")
def capabilities() -> dict[str, Any]:
    return {"capabilities": sdk.available_capabilities()}


@router.post("/{connector_id}")
def save_connector(connector_id: str, payload: dict = Body(default_factory=dict)) -> dict[str, Any]:
    connector = _connector(connector_id)
    if connector.manifest.managed_elsewhere:
        raise HTTPException(
            status_code=409, detail=f"Configure {connector.manifest.product} on {connector.manifest.settings_location}"
        )
    values = payload.get("values") if isinstance(payload.get("values"), dict) else payload
    values = {**values, "enabled": bool(payload.get("enabled", values.get("enabled", False)))}
    try:
        sdk.save_connector_settings(connector_id, values)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=connector.redact(exc)) from None
    record_integration_event(
        provider=connector_id, operation="CONNECTOR_SETTINGS_SAVED", ok=True, metadata={"enabled": values["enabled"]}
    )
    return {"ok": True, "connector": _row(connector_id)}


def _report(connector_id: str, connector: sdk.Connector, values: dict[str, Any] | None) -> dict[str, Any]:
    """The Add-connection Test (checklist + capability probes) on a throw-away instance."""
    started = time.perf_counter()
    try:
        target = sdk.candidate_connector(connector_id, values) if values is not None else sdk.saved_clone(connector_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=connector.redact(exc)) from None
    try:
        report = sdk.connection_report(target, guard=connector_id)
    except sdk.TestInProgress as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from None
    ok = bool(report["ok"])
    if values is None and not connector.manifest.managed_elsewhere:
        # Re-test of the saved connection: the result is the connection's health.
        if ok:
            connector._health.mark_success()
        else:
            connector._health.mark_error(report["error"], status_code=report.get("status_code"))
    record_integration_event(
        provider=connector_id,
        operation="CONNECTOR_TEST_OK" if ok else "CONNECTOR_TEST_FAILED",
        ok=ok,
        duration_ms=int((time.perf_counter() - started) * 1000),
        status_code=report.get("status_code"),
        error="" if ok else report["error"],
    )
    return {**report, "connector": _row(connector_id)}


@router.post("/{connector_id}/test")
def test_connector(connector_id: str, payload: dict = Body(default_factory=dict)) -> dict[str, Any]:
    connector = _connector(connector_id)
    values = payload.get("values") if isinstance(payload.get("values"), dict) else None
    if payload.get("probe"):
        return _report(connector_id, connector, values)
    started = time.perf_counter()
    try:
        target = sdk.candidate_connector(connector_id, values) if values is not None else connector
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=connector.redact(exc)) from None
    try:
        result = target.test_connection()
    except IntegrationError as exc:
        message = target.redact(exc)
        record_integration_event(
            provider=connector_id,
            operation="CONNECTOR_TEST_FAILED",
            ok=False,
            duration_ms=int((time.perf_counter() - started) * 1000),
            status_code=exc.status_code,
            error=message,
        )
        if target is connector:
            connector._health.mark_error(message, status_code=exc.status_code)
        return {"ok": False, "error": message, "status_code": exc.status_code, "connector": _row(connector_id)}
    except Exception as exc:  # noqa: BLE001 - never leak a stack trace or secret to the page
        record_integration_event(
            provider=connector_id, operation="CONNECTOR_TEST_FAILED", ok=False, error=type(exc).__name__
        )
        return {"ok": False, "error": f"Unexpected {type(exc).__name__}", "connector": _row(connector_id)}
    ok = bool(result.get("ok"))
    if target is connector and ok:
        connector._health.mark_success()
    record_integration_event(
        provider=connector_id,
        operation="CONNECTOR_TEST_OK" if ok else "CONNECTOR_TEST_FAILED",
        ok=ok,
        duration_ms=int((time.perf_counter() - started) * 1000),
    )
    return {
        "ok": ok,
        "detail": target.redact(result.get("detail") or ""),
        "error": "" if ok else target.redact(result.get("detail") or "Not configured"),
        "connector": _row(connector_id),
    }


@router.post("/{connector_id}/enabled")
def set_enabled(connector_id: str, payload: dict = Body(default_factory=dict)) -> dict[str, Any]:
    connector = _connector(connector_id)
    enabled = bool(payload.get("enabled"))
    try:
        sdk.set_connector_enabled(connector_id, enabled)
    except ValueError as exc:
        raise HTTPException(status_code=409 if connector.manifest.managed_elsewhere else 400, detail=str(exc)) from None
    record_integration_event(
        provider=connector_id, operation="CONNECTOR_ENABLED" if enabled else "CONNECTOR_DISABLED", ok=True
    )
    return {"ok": True, "connector": _row(connector_id)}


@router.delete("/{connector_id}")
def reset_connector(connector_id: str) -> dict[str, Any]:
    _connector(connector_id)
    try:
        sdk.remove_connector_settings(connector_id)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from None
    record_integration_event(provider=connector_id, operation="CONNECTOR_SETTINGS_RESET", ok=True)
    return {"ok": True, "connector": _row(connector_id)}
