"""Who is acting: Windows user name + machine name, plus an optional display name from Settings.

NodeWatch has no accounts of its own; the Windows sign-in is the identity. It is good enough to tell
teammates apart on a shared triage folder, and it is not an authentication mechanism (see
docs/TEAM_TRIAGE.md › Trust).
"""

from __future__ import annotations

import getpass
import os
import socket

from app.services.triage.events import clean_text, safe_name


def windows_user() -> str:
    # v0.10.22: the signed-in account (os.getlogin = GetUserNameW on Windows) comes first. The
    # %USERNAME% variable is only a fallback: anyone can start NodeWatch with USERNAME=alice, and
    # shared folders now check that a log file's owner is the user its name claims.
    for getter in (os.getlogin, lambda: os.environ.get("USERNAME"), getpass.getuser):
        try:
            name = getter()
        except Exception:  # noqa: BLE001 - os.getlogin fails without a controlling terminal
            name = ""
        if name:
            return safe_name(name)
    return "unknown"


def machine_name() -> str:
    for getter in (lambda: os.environ.get("COMPUTERNAME"), socket.gethostname):
        try:
            name = getter()
        except Exception:  # noqa: BLE001
            name = ""
        if name:
            return safe_name(name.split(".")[0])
    return "unknown"


def current_actor(display_name: str = "") -> dict:
    user = windows_user()
    return {"user": user, "display": clean_text(display_name, 80) or user, "machine": machine_name()}


def is_me(name: str, actor: dict) -> bool:
    """True when an assignee text names this user (user name or display name, case-insensitive)."""
    n = str(name or "").strip().lower()
    return bool(n) and n in {str(actor.get("user", "")).lower(), str(actor.get("display", "")).lower()}
