"""Who is making a request, and what they may do (v0.10.22 plumbing).

Desktop mode (the only mode today) keeps NodeWatch's existing rules exactly:

* loopback clients only;
* ``Sec-Fetch-Site`` must be same-origin (or absent / ``none``) on ``/api/``;
* every ``/api/`` request carries the per-launch ``X-NodeWatch-Request`` token, except the
  launcher's ``GET /api/status?probe=true``;
* the person at the keyboard is :data:`LOCAL_USER`, who holds every permission.

What is new is the shape: requests are checked by an :class:`AuthProvider` that returns a
:class:`Principal`, the principal is available to any code via :func:`current_principal`, and
every production write calls :func:`require` with a named permission. A future server mode adds
a provider (for example OpenID Connect sign-in with Microsoft Entra ID) and maps roles to these
permissions; feature code does not change. See docs/architecture/DEPLOYMENT_MODES.md.
"""

from __future__ import annotations

import contextvars
import getpass
import hmac
import ipaddress
from dataclasses import dataclass, field

from app.core.deployment import DESKTOP, get_deployment
from app.core.security import WRITE_REQUEST_TOKEN

# --------------------------------------------------------------------------- permissions
# One name per kind of production change (the Operate/Govern write features) plus the local
# triage actions. Server mode will grant subsets by role (viewer / operator / admin).
PORTS_WRITE = "ports.write"  # Port Toolkit: bounce, cable test, port profile
STACKING_WRITE = "stacking.write"  # Virtual Chassis membership / roles
CONFIG_RESTORE = "config.restore"  # Config Backups: restore to the live network
ALERTS_ACK = "alerts.ack.write"  # acknowledge alarms in the vendor system
TRIAGE = "alerts.triage"  # local / team triage (ack, snooze, dismiss, assign, note)
SETTINGS_ADMIN = "settings.admin"  # connections, credentials, policies

ALL_PERMISSIONS = frozenset({PORTS_WRITE, STACKING_WRITE, CONFIG_RESTORE, ALERTS_ACK, TRIAGE, SETTINGS_ADMIN})


@dataclass(frozen=True)
class Principal:
    id: str
    display: str
    kind: str  # "local-user" today; "user" / "service" in server mode
    permissions: frozenset = field(default_factory=frozenset)

    def can(self, permission: str) -> bool:
        return permission in self.permissions


def _local_name() -> str:
    try:
        return getpass.getuser() or "local user"
    except Exception:  # noqa: BLE001
        return "local user"


LOCAL_USER = Principal(id="local", display=_local_name(), kind="local-user", permissions=ALL_PERMISSIONS)

_CURRENT: contextvars.ContextVar[Principal | None] = contextvars.ContextVar("nodewatch_principal", default=None)


def current_principal() -> Principal | None:
    """The principal of the request being handled. Outside a request (scheduler, scripts) desktop
    mode answers LOCAL_USER; a multi-user mode answers None, so nothing runs without a person."""
    p = _CURRENT.get()
    if p is None and _deployment_mode() == DESKTOP:
        return LOCAL_USER
    return p


_MODE: str | None = None


def _deployment_mode() -> str:
    """Decided once per process (like app.main): a later environment change cannot alter it."""
    global _MODE
    if _MODE is None:
        _MODE = get_deployment().mode
    return _MODE


def bind_principal(principal: Principal | None) -> contextvars.Token:
    return _CURRENT.set(principal)


def unbind_principal(token: contextvars.Token) -> None:
    _CURRENT.reset(token)


class PermissionDenied(Exception):
    """Not a PermissionError on purpose: some routes map PermissionError to HTTP 400."""

    status_code = 403


def require(permission: str) -> Principal:
    """Raise PermissionDenied unless the current principal holds ``permission``."""
    p = current_principal()
    if p is None or not p.can(permission):
        raise PermissionDenied(f"You do not have permission for this change ({permission}).")
    return p


# --------------------------------------------------------------------------- providers


@dataclass(frozen=True)
class AuthResult:
    principal: Principal | None
    status: int = 200
    detail: str = ""

    @property
    def ok(self) -> bool:
        return self.principal is not None


class LocalTokenAuth:
    """Desktop mode: the rules NodeWatch has always applied, unchanged."""

    name = "local-token"

    @staticmethod
    def is_loopback(request) -> bool:
        client = request.client
        if not client or not client.host:
            return True
        try:
            return ipaddress.ip_address(client.host).is_loopback
        except ValueError:
            # Starlette TestClient identifies itself as "testclient". Keep this non-network
            # sentinel for automated QA only.
            return client.host == "testclient"

    @staticmethod
    def token_exempt(request, path: str) -> bool:
        """Only the launcher's readiness/identity probe may skip the per-launch token.

        ``/api/status?probe=true`` returns version/build/port and the launch handshake only;
        it never contacts Mist or returns organisation data.
        """
        return path == "/api/status" and request.query_params.get("probe") == "true"

    def authenticate(self, request, path: str) -> AuthResult:
        if not self.is_loopback(request):
            return AuthResult(None, 403, "NodeWatch accepts local loopback requests only")
        if path.startswith("/api/") and not self.token_exempt(request, path):
            # Browser-origin check first, then the per-launch unpredictable token. Required for
            # reads too: several GET endpoints return device configs, backups, audit records and
            # diagnostics. (A program running as the same user can read the token from the page
            # like the browser does; see docs/SECURITY_MODEL.md.)
            fetch_site = (request.headers.get("sec-fetch-site") or "").lower()
            if fetch_site and fetch_site not in {"same-origin", "none"}:
                return AuthResult(None, 403, "Cross-site request blocked")
            supplied = request.headers.get("x-nodewatch-request") or ""
            if not supplied or not hmac.compare_digest(supplied, WRITE_REQUEST_TOKEN):
                return AuthResult(None, 403, "Missing or invalid NodeWatch request token")
        return AuthResult(LOCAL_USER)


def get_auth_provider():
    provider = get_deployment().auth_provider
    if provider == LocalTokenAuth.name:
        return LocalTokenAuth()
    raise RuntimeError(f"Authentication provider {provider!r} is not available in this version")
