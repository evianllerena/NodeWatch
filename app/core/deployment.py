"""How this NodeWatch is deployed (v0.10.22 plumbing for future team/hosted modes).

Today the only supported mode is ``desktop``: one Windows user, the backend bound to 127.0.0.1,
the per-launch request token as "authentication". Every place that depends on that assumption
reads it from here instead of hard-coding it, so a future ``server`` mode (team server on the LAN,
or hosted) changes this module and the auth provider, not the whole application.

Selecting any other mode fails closed: NodeWatch refuses to start rather than run a
multi-user deployment without real sign-in, HTTPS and per-user permissions.
See docs/architecture/DEPLOYMENT_MODES.md for what a server mode still needs.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

DESKTOP = "desktop"
SERVER = "server"  # planned: team server (LAN/VPN) or hosted; not available yet
KNOWN_MODES = (DESKTOP, SERVER)


class DeploymentError(RuntimeError):
    """The requested deployment mode cannot run in this version."""


@dataclass(frozen=True)
class Deployment:
    mode: str
    bind_host: str  # interface the backend listens on
    allowed_hosts: tuple[str, ...]  # Host headers accepted (TrustedHostMiddleware)
    auth_provider: str  # see app.core.auth.get_auth_provider
    multi_user: bool  # several people share one backend (per-user identity everywhere)
    loopback_only: bool  # refuse any client that is not on this machine


_DESKTOP = Deployment(
    mode=DESKTOP,
    bind_host="127.0.0.1",
    allowed_hosts=("127.0.0.1", "localhost"),
    auth_provider="local-token",
    multi_user=False,
    loopback_only=True,
)


def requested_mode() -> str:
    return (os.environ.get("NODEWATCH_DEPLOYMENT_MODE") or DESKTOP).strip().lower() or DESKTOP


def get_deployment() -> Deployment:
    mode = requested_mode()
    if mode == DESKTOP:
        return _DESKTOP
    if mode == SERVER:
        raise DeploymentError(
            "NODEWATCH_DEPLOYMENT_MODE=server is planned but not available in this version: a shared NodeWatch "
            "needs sign-in (SSO), HTTPS and per-user permissions first (docs/architecture/DEPLOYMENT_MODES.md). "
            "Unset NODEWATCH_DEPLOYMENT_MODE to run the desktop app."
        )
    raise DeploymentError(f"Unknown NODEWATCH_DEPLOYMENT_MODE {mode!r}; expected one of {', '.join(KNOWN_MODES)}")
