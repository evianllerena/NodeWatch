from __future__ import annotations

import hmac
import json
import logging
import os
import secrets
import socket
import sys
import threading
import time
import urllib.request
import webbrowser

import uvicorn

from app.core.config import DATA_ROOT, LOG_ROOT, STATE_ROOT
from app.core.credential_store import migrate_known_credentials
from app.core.deployment import DeploymentError, get_deployment
from app.core.security import identity_proof
from app.core.version import APP_BUILD, APP_VERSION

HOST = "127.0.0.1"  # desktop deployment (app/core/deployment.py); checked in main()
PORTS = range(8765, 8796)

# The running uvicorn server, so POST /api/system/exit can stop it cleanly.
_SERVER: uvicorn.Server | None = None


def request_shutdown() -> bool:
    """Ask the running uvicorn server to exit. False when no server is running here."""
    server = _SERVER
    if server is None:
        return False
    logging.getLogger("nodewatch").info("Backend shutdown requested; stopping uvicorn")
    server.should_exit = True
    return True


def _status(port: int, challenge: str = "") -> dict | None:
    url = f"http://{HOST}:{port}/api/status?probe=true"
    if challenge:
        url += f"&challenge={challenge}"
    try:
        with urllib.request.urlopen(url, timeout=0.35) as response:
            return json.loads(response.read().decode("utf-8"))
    except Exception:
        return None


def _is_genuine_exact_backend(port: int) -> bool:
    """Same version/build AND proves the per-install key (not just any lookalike)."""
    challenge = secrets.token_hex(32)
    status = _status(port, challenge)
    if not status or status.get("version") != APP_VERSION or status.get("build") != APP_BUILD:
        return False
    if status.get("port") != port:
        return False
    expected = identity_proof(STATE_ROOT, challenge, port) or ""
    return bool(expected) and hmac.compare_digest(str(status.get("identity_proof") or ""), expected)


# v0.10.33: if the launcher's handshake is not answered within 25 s, every thread's stack is written to
# logs/startup-trace.txt, so a start-up that hangs says where (cancelled by the first handshake answer).
_TRACE_FILE = None
_ANSWERED = threading.Event()


def _arm_startup_trace() -> None:
    global _TRACE_FILE
    try:
        import faulthandler

        _TRACE_FILE = open(LOG_ROOT / "startup-trace.txt", "w", encoding="utf-8")  # noqa: SIM115 - kept open
        _TRACE_FILE.write(f"NodeWatch v{APP_VERSION} ({APP_BUILD}) start-up trace, written only if the handshake hangs\n")
        _TRACE_FILE.flush()
        faulthandler.dump_traceback_later(25, repeat=False, file=_TRACE_FILE)
    except Exception:  # noqa: BLE001 - diagnostics only
        _TRACE_FILE = None


def startup_answered() -> None:
    """Called by the first handshake answer: start-up worked, no trace is needed."""
    if _ANSWERED.is_set():
        return
    _ANSWERED.set()
    try:
        import faulthandler

        faulthandler.cancel_dump_traceback_later()
        logging.getLogger("nodewatch").info("Launcher handshake answered")
    except Exception:  # noqa: BLE001
        pass


def _reserve_port() -> tuple[int, socket.socket]:
    """Bind the listening socket now and hand it to uvicorn (no check-then-bind race)."""
    for port in PORTS:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            if os.name == "nt":
                # Refuse to share the port with another process.
                sock.setsockopt(socket.SOL_SOCKET, getattr(socket, "SO_EXCLUSIVEADDRUSE", 0xFFFFFFFB), 1)
            sock.bind((HOST, port))
            sock.listen(128)
            return port, sock
        except OSError:
            sock.close()
            continue
    raise RuntimeError("No free local port is available for NodeWatch (8765-8795).")


def _open_when_ready(port: int) -> None:
    if os.environ.get("NODEWATCH_EXTERNAL_LAUNCHER") == "1" or os.environ.get("MNT_EXTERNAL_LAUNCHER") == "1":
        return
    for _ in range(100):
        if _is_genuine_exact_backend(port):
            webbrowser.open(f"http://{HOST}:{port}/")
            return
        time.sleep(0.1)


def main() -> int:
    LOG_ROOT.mkdir(parents=True, exist_ok=True)
    # v0.10.41: UTF-8 (it was the Windows code page, so the diagnostics export skipped the log) and
    # rotated at 10 MB, three files kept (it grew without limit).
    from logging.handlers import RotatingFileHandler

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        handlers=[RotatingFileHandler(LOG_ROOT / "application.log", maxBytes=10_000_000, backupCount=3, encoding="utf-8")],
    )
    log = logging.getLogger("nodewatch")
    try:
        deployment = get_deployment()
    except DeploymentError as exc:  # e.g. NODEWATCH_DEPLOYMENT_MODE=server: fail closed, and say why
        log.error("%s", exc)
        raise SystemExit(str(exc)) from exc
    if deployment.bind_host != HOST:
        log.error("Unsupported bind address %r for the desktop launcher", deployment.bind_host)
        raise SystemExit(f"Unsupported bind address {deployment.bind_host!r} for the desktop launcher")
    log.info("Python backend bootstrap: executable=%s version=%s", sys.executable, sys.version.replace("\n", " "))
    log.info("Backend data root: %s", DATA_ROOT)

    external_launch = (
        os.environ.get("NODEWATCH_EXTERNAL_LAUNCHER") == "1" or os.environ.get("MNT_EXTERNAL_LAUNCHER") == "1"
    )
    launch_nonce = os.environ.get("NODEWATCH_LAUNCH_NONCE", "").strip()

    # Migrate known Credential Manager targets before services start. Migration
    # is copy/verify/delete and retains legacy values if a write fails.
    try:
        migrate_known_credentials(DATA_ROOT)
    except Exception:
        log.exception("Credential migration check failed")

    # Direct Python launches may reuse an exact running build. A native launcher
    # launch with a fresh nonce MUST create its own backend so a stale exact-build
    # process can never satisfy the launcher handoff.
    if not (external_launch and launch_nonce):
        for port in PORTS:
            if _is_genuine_exact_backend(port):
                if not external_launch:
                    webbrowser.open(f"http://{HOST}:{port}/")
                return 0

    try:
        port, listen_socket = _reserve_port()
    except Exception as exc:
        log.exception("Unable to find local port")
        raise SystemExit(str(exc)) from exc

    os.environ["NODEWATCH_ACTIVE_PORT"] = str(port)
    threading.Thread(target=_open_when_ready, args=(port,), daemon=True).start()
    log.info("Starting NodeWatch v%s (%s) on %s:%s", APP_VERSION, APP_BUILD, HOST, port)
    if external_launch and sys.platform == "win32":
        from app.core import app_window

        window = app_window.register()
        if window:
            log.info("App window: %s", window)
    # This line is intentionally emitted before uvicorn.run so a launcher-side
    # timeout can distinguish Python bootstrap/import failures from bind/startup failures.
    log.info("Backend entering uvicorn.run")
    _arm_startup_trace()
    config = uvicorn.Config(
        "app.main:app",
        host=HOST,
        port=port,
        log_level="warning",
        access_log=False,
        reload=False,
        proxy_headers=False,
        server_header=False,
        date_header=False,
        timeout_keep_alive=5,
        # v0.10.41: above this many open connections uvicorn answers 503 to everything, including the
        # page's heartbeat; 100 could be reached by a page left open for hours against slow sources.
        limit_concurrency=400,
    )
    global _SERVER
    _SERVER = uvicorn.Server(config)
    try:
        _SERVER.run(sockets=[listen_socket])
    finally:
        _SERVER = None
    log.info("NodeWatch backend stopped")
    return 0


if __name__ == "__main__":
    # Started as ``python -m app.launcher``: make ``import app.launcher`` (used by
    # POST /api/system/exit) return this module so it sees the running server.
    sys.modules.setdefault("app.launcher", sys.modules[__name__])
    raise SystemExit(main())
