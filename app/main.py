from __future__ import annotations

import logging
import threading
import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.exception_handlers import http_exception_handler
from fastapi.templating import Jinja2Templates
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.trustedhost import TrustedHostMiddleware

from app.core import dns_cache

dns_cache.install()  # v0.10.23: last-good DNS answers survive the resolver timeouts seen in the field

from app.core.auth import PermissionDenied, bind_principal, get_auth_provider, unbind_principal
from app.core.deployment import get_deployment
from app.core.security import WRITE_REQUEST_TOKEN, redact_sensitive, redact_text
from app.modules.system.presence import TRACKER as PRESENCE
from app.core.version import APP_BUILD, APP_VERSION
from app.ui.preferences import page_context
from app.modules.ai_engineer.router import router as ai_engineer_router
from app.modules.alerting.router import router as alerting_router
from app.modules.config_backup.router import router as config_backup_router
from app.modules.dashboard.router import router as dashboard_router
from app.modules.detective.router import router as detective_router
from app.modules.history.router import router as history_router
from app.modules.inventory.router import router as inventory_router
from app.modules.integrations.router import router as integrations_router
from app.modules.connectors.router import router as connectors_router
from app.modules.operations.router import router as operations_router
from app.modules.poe.router import router as poe_router
from app.modules.security.router import router as security_router
from app.modules.siem.router import router as siem_router
from app.modules.system.router import router as system_router
from app.modules.validator.router import router as validator_router
from app.modules.ui.router import router as ui_router
from app.modules.virtual_chassis.router import router as vc_router
from app.modules.topology.router import router as topology_router
from app.services.alerting_service import start_alerting_monitor, stop_alerting_monitor
from app.services.siem_service import start_siem_forwarder, stop_siem_forwarder
from app.services.backup_service import start_backup_scheduler, stop_backup_scheduler

from app.integrations import api_timing

BASE_DIR = Path(__file__).resolve().parent
MAX_API_BODY_BYTES = 2 * 1024 * 1024
MAX_IMPORT_BODY_BYTES = 50 * 1024 * 1024  # matches backup_service.MAX_IMPORT_BYTES
UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def _startup_work() -> None:
    """Everything start-up used to do before the server answered (v0.10.33: in the background).

    Loading the connectors and starting the background services ran inside the ASGI lifespan, so uvicorn
    did not accept a single connection until all of it had finished. When any of it was slow (a vendor
    connector, a credential read, the network) the launcher's 40 s handshake expired first and NodeWatch
    reported "backend startup failed before secure verification completed". Nothing here is needed to
    answer the handshake; pages that need the connectors wait for them (discover() holds a lock)."""
    log = logging.getLogger("nodewatch")
    started = time.monotonic()
    steps = []

    def step(name, fn):
        t = time.monotonic()
        try:
            fn()
        except Exception:  # noqa: BLE001 - one failing service must not stop the others
            log.exception("Start-up step %s failed", name)
        steps.append(f"{name} {round((time.monotonic() - t) * 1000)} ms")

    from app.integrations.connectors.sdk import discover as discover_connectors
    from app.modules.system import router as system_module
    from app.modules.system.presence import start_watchdog

    step("connectors", discover_connectors)
    from app.integrations.connectors.sdk import verify_all_in_background, warm_up_all as warm_up_connectors

    step("connection checks", verify_all_in_background)
    step("connector warm-up", warm_up_connectors)
    step("event relay", start_siem_forwarder)
    step("alerting", start_alerting_monitor)
    step("backups", start_backup_scheduler)
    # Close the backend when the last NodeWatch tab closes (no "Exit NodeWatch" click needed).
    step("presence", lambda: start_watchdog(lambda: system_module._shutdown_hook()))
    log.info("Background start-up finished in %d ms (%s)", round((time.monotonic() - started) * 1000), "; ".join(steps))


def stop_soc_collector() -> None:
    """Stop the SOC collector thread if a page started it (it starts on first use, not at start-up)."""
    import sys

    soc = sys.modules.get("app.services.soc.service")  # never imported just to stop it
    if soc is not None:
        soc.COLLECTOR.stop()


@asynccontextmanager
async def lifespan(_: FastAPI):
    # v0.10.23: routes are plain functions run in AnyIO's worker threads (40 by default). Pages make
    # several calls at once and vendor reads can wait on slow networks, so allow more in flight
    # instead of queueing page requests behind them.
    try:
        import anyio.to_thread

        anyio.to_thread.current_default_thread_limiter().total_tokens = 100
    except Exception:  # noqa: BLE001 - keep the default
        pass
    threading.Thread(target=_startup_work, name="nodewatch-startup", daemon=True).start()
    try:
        yield
    finally:
        stop_alerting_monitor()
        stop_siem_forwarder()
        stop_backup_scheduler()
        stop_soc_collector()


# NodeWatch is a loopback desktop application, not a general-purpose API server.
# Interactive API documentation is disabled in distributed builds.
app = FastAPI(
    title="NodeWatch",
    version=APP_VERSION,
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
    lifespan=lifespan,
)
DEPLOYMENT = get_deployment()  # desktop today; any other mode refuses to start (app/core/deployment.py)
AUTH_PROVIDER = get_auth_provider()
app.add_middleware(TrustedHostMiddleware, allowed_hosts=list(DEPLOYMENT.allowed_hosts))
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
templates = Jinja2Templates(directory=BASE_DIR / "templates")


def _redact_detail(value):
    """Scrub credential patterns from every error detail (strings, nested dicts and lists)."""
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, dict):
        # Key-based first ({"password": "x"} → redacted whatever the value looks like), then patterns.
        return {key: _redact_detail(item) for key, item in redact_sensitive(value).items()}
    if isinstance(value, (list, tuple)):
        return [_redact_detail(item) for item in value]
    return value


@app.exception_handler(PermissionDenied)
async def _permission_denied_handler(request: Request, exc: PermissionDenied):
    return JSONResponse({"detail": str(exc)}, status_code=403)


@app.exception_handler(StarletteHTTPException)
async def _redacting_http_exception_handler(request: Request, exc: StarletteHTTPException):
    # v0.10.22: many routers return str(exc) from vendor/client errors as the detail. Redact
    # centrally so no route can echo a token, secret or credential-bearing URL to the page.
    exc.detail = _redact_detail(exc.detail)
    return await http_exception_handler(request, exc)


def _secure(response, path: str):
    """Security headers on every response, including the middleware's own early refusals."""
    response.headers["X-NodeWatch-Version"] = APP_VERSION
    response.headers["X-NodeWatch-Build"] = APP_BUILD
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(self), geolocation=(), payment=(), usb=()"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self'; "
        "img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; "
        "frame-ancestors 'none'; form-action 'self'"
    )
    if path.startswith("/static/") and not path.endswith(".json"):
        # v0.10.23: every static URL carries ?v=<build> (index.html; the build, not the version, since pilot builds
        # share version 0.10.42), so a new release always
        # fetches fresh files; within one version the webview may keep them instead of
        # re-downloading and re-parsing ~1.3 MB of JS/CSS on every launch and reload.
        response.headers["Cache-Control"] = "private, max-age=604800, immutable"
    elif path == "/" or path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
    return response


# v0.10.41: page requests in progress, so a pile-up (every worker busy, pages waiting) is visible in
# application.log and the diagnostics export instead of only as a page that stops answering.
_IN_FLIGHT: dict[str, int] = {}
_IN_FLIGHT_WARN = 60
_in_flight_warned_at = 0.0


def _in_flight_key(method: str, path: str) -> str:
    return api_timing.endpoint(method, path)[:80] if path.startswith("/api/") else "(page)"


def _in_flight_begin(method: str, path: str) -> None:
    global _in_flight_warned_at
    key = _in_flight_key(method, path)
    _IN_FLIGHT[key] = _IN_FLIGHT.get(key, 0) + 1
    total = sum(_IN_FLIGHT.values())
    if total >= _IN_FLIGHT_WARN and time.monotonic() - _in_flight_warned_at > 300:
        _in_flight_warned_at = time.monotonic()
        top = sorted(_IN_FLIGHT.items(), key=lambda kv: -kv[1])[:6]
        logging.getLogger("nodewatch").warning("%d page requests in progress at once: %s", total, top)


def _in_flight_end(method: str, path: str) -> None:
    key = _in_flight_key(method, path)
    n = _IN_FLIGHT.get(key, 0) - 1
    if n > 0:
        _IN_FLIGHT[key] = n
    else:
        _IN_FLIGHT.pop(key, None)


def in_flight() -> dict:
    return {"total": sum(_IN_FLIGHT.values()), "by_endpoint": dict(sorted(_IN_FLIGHT.items(), key=lambda kv: -kv[1])[:10])}


@app.middleware("http")
async def local_security(request: Request, call_next):
    path = str(request.scope.get("path") or "")

    # Who is asking (desktop mode: loopback + same-origin + per-launch token, see app/core/auth.py).
    auth = AUTH_PROVIDER.authenticate(request, path)
    if not auth.ok:
        return _secure(JSONResponse({"detail": auth.detail}, status_code=auth.status), path)
    request.state.principal = auth.principal

    if path.startswith("/api/") and request.method.upper() in UNSAFE_METHODS:
        # A whole-org snapshot export can be tens of MB; only its import endpoint accepts that much.
        limit = MAX_IMPORT_BODY_BYTES if path == "/api/v1/config-backup/import" else MAX_API_BODY_BYTES
        content_length = request.headers.get("content-length")
        if content_length:
            try:
                if int(content_length) > limit:
                    return _secure(JSONResponse({"detail": "Request body is too large"}, status_code=413), path)
            except ValueError:
                return _secure(JSONResponse({"detail": "Invalid Content-Length"}, status_code=400), path)

        # Enforce the limit on the bytes actually received as well, so a client
        # cannot bypass the check by omitting or falsifying Content-Length.
        body = await request.body()
        if len(body) > limit:
            return _secure(JSONResponse({"detail": "Request body is too large"}, status_code=413), path)

    # A change in flight (e.g. a confirmed Mist write) holds off the close-with-last-tab exit.
    tracked = path.startswith("/api/") and request.method.upper() in UNSAFE_METHODS and "/presence" not in path
    if tracked:
        PRESENCE.begin_request()
    principal_token = bind_principal(auth.principal)  # visible to the route and its services
    started = time.perf_counter()
    _in_flight_begin(request.method, path)
    try:
        response = await call_next(request)
    finally:
        _in_flight_end(request.method, path)
        unbind_principal(principal_token)
        if tracked:
            PRESENCE.end_request()
    if path.startswith("/api/"):
        # v0.10.40: how long each page request took, for Support diagnostics ("NodeWatch API" in
        # integration_api_timing) and the browser's network panel (Server-Timing). Route templates only.
        ms = (time.perf_counter() - started) * 1000
        response.headers["Server-Timing"] = f"app;dur={ms:.0f}"
        if "/presence" not in path:
            route = request.scope.get("route")
            api_timing.note("NodeWatch API", request.method, getattr(route, "path", None) or path, ms,
                            response.status_code < 500)
    return _secure(response, path)


for router in (
    system_router,
    dashboard_router,
    detective_router,
    operations_router,
    vc_router,
    topology_router,
    validator_router,
    config_backup_router,
    poe_router,
    alerting_router,
    security_router,
    siem_router,
    ai_engineer_router,
    inventory_router,
    integrations_router,
    connectors_router,
    history_router,
    ui_router,
):
    # Phase 1: every state-changing route checks its permission (desktop: always granted).
    app.include_router(router)


@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    return templates.TemplateResponse(
        request,
        "index.html",
        {
            "app_version": APP_VERSION,
            "app_build": APP_BUILD,
            "write_request_token": WRITE_REQUEST_TOKEN,
            **page_context(),
        },
    )
