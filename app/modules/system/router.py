from __future__ import annotations

import json
import logging
import os
import subprocess
import sys

from fastapi import APIRouter, Body, HTTPException, Query, Request

from app.core.config import DATA_ROOT, STATE_ROOT, get_settings, reset_settings, save_settings
from app.core import credential_store
from app.core.credential_store import load_secret
from app.core.registry import get_tools
from app.core.security import identity_proof, launch_proof
from app.core.version import APP_BUILD, APP_VERSION
from app.services.mist_client import MistApiError, MistClient, get_mist_client, reset_mist_client

DIAGNOSTIC_EXPORTS_KEPT = 5
log = logging.getLogger("nodewatch.system")
router = APIRouter(prefix="/api", tags=["system"])


@router.get("/modules")
def modules():
    return get_tools()


@router.get("/settings")
def settings():
    current = get_settings()
    return {
        **current.public_dict,
        "configured": current.configured and not current.validate(),
        "configuration_errors": current.validate(),
        "credential_store": credential_store.store_label(),
    }


def _candidate_from_payload(payload: dict) -> tuple[str, str, str, bool]:
    current = get_settings()
    api_host = str(payload.get("api_host") or current.api_host or "https://api.mist.com").strip().rstrip("/")
    org_id = str(payload.get("org_id") or current.org_id or "").strip()
    token = str(payload.get("token") or current.token or "").strip()
    verify_tls = bool(payload.get("verify_tls", current.verify_tls))
    return api_host, org_id, token, verify_tls


@router.post("/settings/test")
def test_settings(payload: dict = Body(...)):
    api_host, org_id, token, verify_tls = _candidate_from_payload(payload)
    from app.core.config import Settings

    candidate = Settings(api_host=api_host, org_id=org_id, token=token, verify_tls=verify_tls)
    validation = candidate.validate()
    if validation:
        raise HTTPException(status_code=400, detail="; ".join(validation))
    client = MistClient(candidate)
    try:
        org = client.get_org()
        sites = client.list_sites()
        return {
            "ok": True,
            "organization": org.get("name") or org_id,
            "site_count": len(sites),
            "api_host": candidate.safe_api_host,
        }
    except MistApiError as exc:
        raise HTTPException(status_code=exc.status_code or 502, detail=str(exc)) from exc


@router.post("/settings/save")
def save_app_settings(payload: dict = Body(...)):
    api_host, org_id, token, verify_tls = _candidate_from_payload(payload)
    from app.core.config import Settings

    candidate = Settings(api_host=api_host, org_id=org_id, token=token, verify_tls=verify_tls)
    validation = candidate.validate()
    if validation:
        raise HTTPException(status_code=400, detail="; ".join(validation))

    # Never persist a connection that has not been verified.
    try:
        test_client = MistClient(candidate)
        org = test_client.get_org()
        sites = test_client.list_sites()
    except MistApiError as exc:
        raise HTTPException(status_code=exc.status_code or 502, detail=str(exc)) from exc

    try:
        saved = save_settings(api_host=api_host, org_id=org_id, token=token, verify_tls=verify_tls)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Unable to save application settings: {exc}") from exc

    current = get_mist_client().settings
    unchanged = (current.api_host, current.org_id, current.token, current.verify_tls) == (
        saved.api_host,
        saved.org_id,
        saved.token,
        saved.verify_tls,
    )
    if unchanged:
        # Same connection saved again (v0.10.24): keep the warm client - its caches and the device-event
        # buffer - instead of re-downloading the whole organisation and a day of events.
        get_mist_client().settings = saved
    else:
        reset_mist_client(saved)
    if not verify_tls:
        log.warning("Mist TLS certificate verification was DISABLED by the user")
    return {
        "ok": True,
        "organization": org.get("name") or org_id,
        "site_count": len(sites),
        "settings": saved.public_dict,
    }


@router.post("/settings/reset")
def reset_app_settings():
    try:
        reset_settings()
        reset_mist_client()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Unable to reset application settings: {exc}") from exc
    return {"ok": True}


@router.post("/settings/open-data-folder")
def open_data_folder():
    DATA_ROOT.mkdir(parents=True, exist_ok=True)
    try:
        if os.name == "nt":
            os.startfile(str(DATA_ROOT))  # type: ignore[attr-defined]
        elif sys.platform == "darwin":
            # Finder; the path is an argument (never a shell string).
            subprocess.run(["/usr/bin/open", str(DATA_ROOT)], check=True, timeout=10)
        else:
            return {
                "ok": False,
                "path": str(DATA_ROOT),
                "message": "Open-folder action is available on Windows and macOS.",
            }
        return {"ok": True, "path": str(DATA_ROOT)}
    except (OSError, subprocess.SubprocessError) as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


def _tls_verification_off(client) -> list[str]:
    """Every connection sending credentials without certificate checks (persistent banner, v0.10.22)."""
    names = [] if client.settings.verify_tls else ["Mist"]
    try:
        from app.integrations.connectors.sdk import tls_verification_off

        names += tls_verification_off()
    except Exception:  # noqa: BLE001
        pass
    try:
        from app.services.siem_service import get_forwarder_config

        cfg = get_forwarder_config()
        if cfg.get("enabled") and cfg.get("provider") == "splunk_hec" and cfg.get("verify_tls") is False:
            names.append("Splunk HEC")
    except Exception:  # noqa: BLE001
        pass
    return names


def _source_states(client) -> tuple[list[str], list[str]]:
    """(working, failing) product names of every configured and enabled source, from
    ``sdk.connector_state`` (connected / ready vs error). Mist counts when it is configured."""
    working: list[str] = []
    failing: list[str] = []
    try:
        from app.integrations.connectors import sdk

        for c in sdk.all_connectors():
            m = c.manifest
            try:
                state = sdk.connector_state(c).get("state")
            except Exception:  # noqa: BLE001 - one broken connector must not break the status line
                state = "error"
            label = f"{m.vendor} {m.product}".strip()
            if state in {"connected", "ready"} and label not in working:
                working.append(label)
            elif state == "error" and label not in failing:
                failing.append(label)
    except Exception:  # noqa: BLE001 - the status line must always answer
        if client.configured:
            working.append("Juniper Mist")
    return working, failing


def _connected_products(client) -> list[str]:
    return _source_states(client)[0]


def _probe_answer(request: Request) -> dict:
    """The launcher's handshake (v0.10.33): version, build, pid, port and the two proofs only. It never waits for
    the Mist client, settings or credentials, so a slow start-up of anything else cannot fail the handshake.
    v0.10.44: it no longer says whether a vendor is configured or TLS checks are off; that needs the request token."""
    own_port = int(os.environ.get("NODEWATCH_ACTIVE_PORT") or 0) or None
    result: dict = {"version": APP_VERSION, "build": APP_BUILD, "pid": os.getpid(), "port": own_port, "read_only": False}
    try:
        from app.launcher import startup_answered

        startup_answered()
    except Exception:  # noqa: BLE001 - diagnostics only
        pass
    launch_challenge = request.query_params.get("launch_challenge")
    if launch_challenge and own_port:
        proof = launch_proof(os.environ.get("NODEWATCH_LAUNCH_NONCE") or "", launch_challenge, own_port)
        if proof:
            result["launch_proof"] = proof
    challenge = request.query_params.get("challenge")
    if challenge and own_port:
        proof = identity_proof(STATE_ROOT, challenge, own_port)
        if proof:
            result["identity_proof"] = proof
    return result


@router.get("/status")
def status(request: Request, test: bool = Query(False), probe: bool = Query(False), quick: bool = Query(False)):
    if probe:
        return _probe_answer(request)
    client = get_mist_client()
    validation = client.settings.validate()
    result = {
        "mode": "live" if client.configured else "setup-required",
        "read_only": False,
        "mist_connected": False,
        "configured": client.configured,
        "org_scope": "Single organization",
        "api_host": client.settings.safe_api_host,
        "version": APP_VERSION,
        "build": APP_BUILD,
        "pid": os.getpid(),
        "port": int(os.environ.get("NODEWATCH_ACTIVE_PORT") or 0) or None,
        "configuration_errors": validation,
        "tls_verification_disabled": not client.settings.verify_tls,
    }
    # Not on the token-free probe: it reads connector settings and the Splunk configuration.
    result["tls_verification_off"] = _tls_verification_off(client)
    # v0.10.24: NodeWatch is usable with any connected source, not only Mist. ``configured`` keeps
    # meaning "Mist is configured" (Mist-only pages use it); start-up and the header use these.
    products, failing = _source_states(client)
    result["connected_products"] = products
    result["failing_products"] = failing
    result["any_source_configured"] = bool(client.configured or products or failing)
    # Ordinary status requests avoid contacting Mist when setup is incomplete.
    if not client.configured:
        return result
    result["mist_api_usage"] = client.api_usage()  # calls/hour vs Mist's 5,000 limit; "warning" when high
    if quick and not test:
        # Start-up (v0.10.24): the page only needs to know whether Mist is configured to pick its first
        # page; it no longer waits on a Mist round trip (up to the DNS timeout on a cold start). The live
        # check follows separately and shares the dashboard's organisation read.
        result["mist_connected"] = None
        return result
    try:
        # The connection test reads the organisation fresh from Mist. It used to clear every cached
        # read first, so start-up and each "Refresh NOC" re-downloaded the whole org (v0.10.23).
        org = client.get_org(fresh=test)
        result["mist_connected"] = True
        result["organization"] = org.get("name") or client.settings.org_id
    except MistApiError as exc:
        result["connection_error"] = str(exc)
    return result


@router.post("/support/diagnostics")
def export_diagnostics():
    import json
    import platform
    import zipfile
    from datetime import datetime, timezone

    from fastapi.responses import FileResponse

    from app.core.config import DIAGNOSTICS_ROOT, LOG_ROOT
    from app.core.file_utils import flush_async_jsonl
    from app.core.security import contains_secret_material, redact_text
    from app.integrations.config import (
        get_palo_alto_credentials,
        get_strata_logging_config,
        get_strata_logging_credentials,
    )
    from app.integrations.providers.strata_logging import get_strata_logging_provider

    flush_async_jsonl()  # API timing lines are written in the background: include the latest
    export_root = DATA_ROOT / "exports"
    export_root.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = export_root / f"NodeWatch-Diagnostics-{stamp}.zip"
    current = get_settings()

    # Diagnostic packages are an external trust boundary. Gather credential values only
    # so they can be removed from text before export; the values themselves are never
    # written to the package. Failure to read an optional secret must never make the
    # support export expose or depend on it.
    known_secrets: list[str] = []
    for value in (current.token,):
        if value:
            known_secrets.append(str(value))
    try:
        pa_credentials = get_palo_alto_credentials()
        for key in ("client_secret",):
            value = str(pa_credentials.get(key) or "")
            if value:
                known_secrets.append(value)
    except Exception:  # noqa: BLE001 - no Palo Alto secret to redact
        pass
    try:
        sls_credentials = get_strata_logging_credentials()
        value = str(sls_credentials.get("client_secret") or "")
        if value and value not in known_secrets:
            known_secrets.append(value)
    except Exception:
        sls_credentials = {}
    for target in ("NodeWatch:SplunkHecToken", "NodeWatch:AlertWebhookUrl"):
        try:
            value = load_secret(DATA_ROOT, target)
            if value:
                known_secrets.append(value)
        except Exception:  # noqa: BLE001 - no stored secret to redact
            pass

    summary = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "app_version": APP_VERSION,
        "app_build": APP_BUILD,
        "platform": platform.platform(),
        "python": platform.python_version(),
        "configured": current.configured,
        "api_host": current.safe_api_host,
        "process_id": os.getpid(),
        "active_port": int(os.environ.get("NODEWATCH_ACTIVE_PORT") or 0)
        or None,
        "credentials_included": False,
        "raw_binary_logs_included": False,
        "note": "Text diagnostics are sanitized before export. Credentials, tokens, request bodies, configuration snapshots, and binary logs are excluded.",
    }
    summary["mist_api_usage"] = get_mist_client().api_usage()  # per-endpoint calls in the last hour
    try:  # per-connector HTTP timing (calls, total ms, slowest endpoint) — endpoint templates only
        from app.integrations import api_timing

        summary["integration_api_timing"] = api_timing.summary()
        from app.main import in_flight

        summary["page_requests_in_progress"] = in_flight()
    except Exception as exc:  # noqa: BLE001
        summary["integration_api_timing"] = {"diagnostic_status": "unavailable", "error_type": type(exc).__name__}
    try:  # Event Relay / SIEM forwarding: settings shape, delivery status, last connection check (no token)
        from urllib.parse import urlparse as _urlparse

        from app.services import siem_service

        fwd = siem_service.get_forwarder_config()
        url = _urlparse(str(fwd.get("splunk_url") or ""))
        summary["siem_forwarder"] = {
            "provider": fwd.get("provider"),
            "enabled": bool(fwd.get("enabled")),
            "interval_seconds": fwd.get("interval_seconds"),
            "splunk_endpoint": f"{url.scheme}://{url.hostname}{f':{url.port}' if url.port else ''}{url.path}"
            if url.hostname
            else "",
            "verify_tls": bool(fwd.get("verify_tls", True)),
            "proxy_configured": bool(fwd.get("proxy_url")),
            "token_present": bool(fwd.get("token_present")),
            "index_set": bool(fwd.get("splunk_index")),
            "syslog_target_set": bool(fwd.get("syslog_host")),
            "status": fwd.get("status") or {},
            "last_diagnose": siem_service.last_diagnose(),
        }
    except Exception as exc:  # noqa: BLE001
        summary["siem_forwarder"] = {"diagnostic_status": "unavailable", "error_type": type(exc).__name__}
    try:
        sls_cfg = get_strata_logging_config()
        sls_provider = get_strata_logging_provider()
        sls_diag = sls_provider.diagnostics()
        summary["strata_logging_service"] = {
            "enabled": sls_cfg.enabled,
            "verified": sls_cfg.verified,
            "verified_at": sls_cfg.verified_at,
            "auth_mode": sls_cfg.auth_mode,
            "credential_source": "Palo Alto Common Services",
            "client_id_present": bool(sls_credentials.get("client_id")),
            "client_secret_present": bool(sls_credentials.get("client_secret")),
            "tsg_id_present": bool(sls_credentials.get("tsg_id")),
            "active_capabilities": sls_diag.get("active_capabilities") or [],
            "declared_capabilities": sls_diag.get("declared_capabilities") or [],
            "health": sls_diag.get("health") or {},
            "query_api": sls_diag.get("query_api") or "",
            "query_host": sls_diag.get("query_host") or "",
            "tenant_override_set": bool(sls_diag.get("tenant_override_set")),
            "tsg_id_present_in_auth": bool((sls_diag.get("auth") or {}).get("tsg_id_present")),
        }
    except Exception as exc:
        summary["strata_logging_service"] = {"diagnostic_status": "unavailable", "error_type": type(exc).__name__}

    # Surface the most recent sanitized SLS workflow stages directly in the
    # support summary. The underlying JSONL is also included, but this makes it
    # immediately obvious whether the click reached UI wiring, OAuth, the query
    # endpoint, and persistence. No credentials, request bodies, or tokens are
    # recorded by the integration diagnostic writer.
    try:
        timing_path = DIAGNOSTICS_ROOT / "integration_api_timing.jsonl"
        sls_trace: list[dict] = []
        if timing_path.exists():
            for line in timing_path.read_text(encoding="utf-8", errors="replace").splitlines()[-300:]:
                try:
                    row = json.loads(line)
                except Exception:
                    continue
                if row.get("provider") != "strata_logging_service":
                    continue
                operation = str(row.get("operation") or "")
                if not operation.startswith("SLS_"):
                    continue
                sls_trace.append(
                    {
                        "timestamp": row.get("timestamp"),
                        "operation": operation,
                        "ok": bool(row.get("ok")),
                        "status_code": row.get("status_code"),
                        "duration_ms": row.get("duration_ms"),
                        "error": row.get("error", ""),
                        "meta": row.get("meta", {}),
                    }
                )
        summary["strata_logging_service"]["recent_trace"] = sls_trace[-30:]
    except Exception:  # noqa: BLE001 - the export leaves out a trace it cannot read
        pass

    # v0.10.30: Security Operations — counts and source health only (never detection content), and which
    # Log Viewer names answered for threat / URL logs (field names seen are in the application log).
    try:
        from app.services.soc import service as soc_service

        summary["security_operations"] = soc_service.diagnostics()
    except Exception as exc:  # noqa: BLE001
        summary["security_operations"] = {"diagnostic_status": "unavailable", "error_type": type(exc).__name__}
    try:
        from app.integrations.connectors import sdk as _sdk

        scm = _sdk.get_connector("paloalto_scm")
        if scm is not None and isinstance(summary.get("strata_logging_service"), dict):
            summary["strata_logging_service"]["security_logs"] = scm.security_log_status()
    except Exception:  # noqa: BLE001
        pass

    skipped: list[str] = []
    included = 0
    with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        # The summary includes provider error text, so it gets the same known-secret
        # scrub as every other file in the package.
        zf.writestr("support_summary.json", redact_text(json.dumps(summary, indent=2), *known_secrets))
        for root, prefix in ((DIAGNOSTICS_ROOT, "diagnostics"), (LOG_ROOT, "logs")):
            if not root.exists():
                continue
            for path in root.rglob("*"):
                if not path.is_file():
                    continue
                relative_name = f"{prefix}/{path.relative_to(root)}"
                try:
                    size = path.stat().st_size
                except OSError:
                    skipped.append(f"{relative_name}: unable to inspect")
                    continue
                tail_only = False
                if size > 10_000_000:
                    if not path.name.endswith(".log"):
                        skipped.append(f"{relative_name}: larger than 10 MB")
                        continue
                    tail_only = True  # v0.10.41: a big log contributes its most recent 5 MB
                try:
                    if tail_only:
                        with path.open("rb") as fh:
                            fh.seek(-5_000_000, 2)
                            raw = fh.read()
                        raw = raw[raw.find(b"\n") + 1 :]
                    else:
                        raw = path.read_bytes()
                    try:
                        text = raw.decode("utf-8")
                    except UnicodeDecodeError:
                        if not path.name.endswith((".log", ".txt")):
                            raise
                        if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):  # UTF-16 (written by PowerShell)
                            text = raw.decode("utf-16", errors="replace")
                        elif b"\x00" in raw:
                            raise
                        else:
                            text = None
                        if text is None:
                            # v0.10.41: a log written in the Windows code page (application.log before
                            # this release) is still text: include it instead of skipping it.
                            text = raw.decode("cp1252", errors="replace")
                except (OSError, UnicodeDecodeError):
                    # Do not copy opaque/binary artifacts into a support package where
                    # the central secret scrubber cannot inspect their contents.
                    skipped.append(f"{relative_name}: non-UTF-8/binary content")
                    continue

                sanitized = redact_text(text, *known_secrets)
                if contains_secret_material(sanitized, *known_secrets):
                    skipped.append(f"{relative_name}: sensitive material remained after sanitization")
                    continue
                zf.writestr(relative_name, sanitized)
                included += 1

        zf.writestr(
            "sanitization_report.json",
            json.dumps(
                {
                    "sanitized_text_files_included": included,
                    "files_skipped": skipped,
                    "credentials_included": False,
                },
                indent=2,
            ),
        )

    # Keep only the newest few exports on disk; each one is a copy of the logs.
    for old in sorted(export_root.glob("NodeWatch-Diagnostics-*.zip"), reverse=True)[DIAGNOSTIC_EXPORTS_KEPT:]:
        try:
            old.unlink()
        except OSError:
            pass
    return FileResponse(out, filename=out.name, media_type="application/zip")


# --- Exit NodeWatch (v0.10.12) -------------------------------------------------
# The native launcher exits once the browser is open, so the backend process
# (NodeWatchBackend.exe, or python.exe on the fallback path) keeps running until
# the user stops it. POST /api/system/exit answers first and stops the backend
# shortly afterwards. Like every /api/ route it requires the per-launch request
# token (enforced in app.main.local_security).
EXIT_DELAY_SECONDS = 0.5
EXIT_FORCE_AFTER_SECONDS = 10.0


def _stop_backend_process() -> None:
    """Ask uvicorn to shut down cleanly; hard-exit if that is unavailable or stalls."""
    import threading

    try:
        import importlib

        # importlib returns sys.modules["app.launcher"], which app/launcher.py points
        # at itself when it runs as ``python -m app.launcher``.
        clean = importlib.import_module("app.launcher").request_shutdown()
    except Exception:
        log.exception("Clean backend shutdown request failed")
        clean = False
    if not clean:
        log.info("No uvicorn server handle; exiting backend process directly")
        logging.shutdown()
        os._exit(0)
    # Background services or a lingering browser connection must not keep the
    # process alive after the user asked to exit.
    backstop = threading.Timer(EXIT_FORCE_AFTER_SECONDS, os._exit, args=(0,))
    backstop.daemon = True
    backstop.start()


# Tests replace this with a recorder so the test process is never stopped.
_shutdown_hook = _stop_backend_process


def _schedule_exit() -> None:
    import threading

    hook = _shutdown_hook
    timer = threading.Timer(EXIT_DELAY_SECONDS, hook)
    timer.daemon = True
    timer.start()


@router.post("/system/presence")
async def presence_heartbeat(payload: dict = Body(default={})):
    """The page's "I am still open" heartbeat (and its "is NodeWatch still running?" check).

    v0.10.41: answered on the server's event loop, not in the worker-thread pool, so it is answered at
    once even when every worker is busy with slow vendor reads (it used to queue behind them, and a page
    that could not get an answer in time said "NodeWatch has stopped" while NodeWatch was running).
    The work is a dictionary update and a cached preference read."""
    from app.modules.system.presence import TRACKER, keep_running_preference, watchdog_enabled

    tabs = TRACKER.heartbeat(str(payload.get("tab") or ""), str(payload.get("state") or "visible"))
    report = payload.get("report")
    if isinstance(report, dict):
        # The page could not reach NodeWatch for a while and has now reached it again: say why, for support.
        log.warning(
            "Page lost contact with NodeWatch for %s s (%s); attempts: %s",
            str(report.get("seconds") or "?")[:12],
            str(report.get("trigger") or "?")[:40],
            str(report.get("attempts") or "")[:400],
        )
    return {"ok": True, "tabs": tabs, "auto_exit": watchdog_enabled() and not keep_running_preference()}


@router.get("/system/keep-running")
def keep_running_get():
    """Settings › "Keep NodeWatch running when its window is closed" (default off)."""
    from app.modules.system.presence import keep_running_preference, watchdog_enabled

    return {"keep_running": keep_running_preference(max_age=0), "auto_exit_available": watchdog_enabled()}


@router.post("/system/keep-running")
def keep_running_set(payload: dict = Body(...)):
    from app.modules.system.presence import set_keep_running_preference

    value = payload.get("keep_running")
    if not isinstance(value, bool):
        raise HTTPException(status_code=400, detail="keep_running must be true or false")
    return {"keep_running": set_keep_running_preference(value)}


@router.post("/system/presence/bye")
def presence_bye(payload: dict = Body(default={})):
    from app.modules.system.presence import TRACKER

    return {"ok": True, "tabs": TRACKER.bye(str(payload.get("tab") or ""))}


@router.post("/system/exit")
def exit_backend():
    log.info("Exit requested from the NodeWatch UI; stopping backend pid=%s", os.getpid())
    _schedule_exit()
    return {"ok": True, "stopping": True, "pid": os.getpid()}
