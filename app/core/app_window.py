"""NodeWatch's own window on Windows (v0.10.39).

The native launcher opens the app window with the program registered under the App Paths name ``nwhost.exe``
(it used to look for ``msedge.exe`` first). This module registers that name, for the current user only, to
``app\\bin\\NodeWatchApp.exe``: NodeWatch's own window program (source: tools/nwwindow). It is called before the
backend answers the launcher's handshake, so the launcher finds it when it opens the window.

Set NODEWATCH_BROWSER_WINDOW=1 to keep the Edge app window instead: the name is then pointed at Edge (or
removed, in which case the launcher uses Chrome or the default browser).
"""
from __future__ import annotations

import logging
import os
import sys
from pathlib import Path

log = logging.getLogger(__name__)

APP_PATHS = r"Software\Microsoft\Windows\CurrentVersion\App Paths\nwhost.exe"
WINDOW_EXE = Path(__file__).resolve().parents[1] / "bin" / "NodeWatchApp.exe"


def _edge() -> str:
    import winreg

    for root in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
        try:
            with winreg.OpenKey(root, r"Software\Microsoft\Windows\CurrentVersion\App Paths\msedge.exe") as k:
                value = str(winreg.QueryValueEx(k, "")[0]).strip('"')
                if value and Path(value).is_file():
                    return value
        except OSError:
            continue
    for env in ("ProgramFiles(x86)", "ProgramFiles", "LOCALAPPDATA"):
        base = os.environ.get(env)
        if base:
            p = Path(base) / "Microsoft" / "Edge" / "Application" / "msedge.exe"
            if p.is_file():
                return str(p)
    return ""


def _set(target: str) -> None:
    import winreg

    with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, APP_PATHS, 0, winreg.KEY_SET_VALUE | winreg.KEY_QUERY_VALUE) as k:
        try:
            current = str(winreg.QueryValueEx(k, "")[0])
        except OSError:
            current = ""
        if current != target:
            winreg.SetValueEx(k, "", 0, winreg.REG_SZ, target)
            winreg.SetValueEx(k, "Path", 0, winreg.REG_SZ, str(Path(target).parent))


def _remove() -> None:
    import winreg

    try:
        winreg.DeleteKey(winreg.HKEY_CURRENT_USER, APP_PATHS)
    except OSError:
        pass


def register() -> str:
    """Point the launcher's app-window name at the right program. Returns what it now opens (for the log)."""
    if sys.platform != "win32":
        return ""
    try:
        if os.environ.get("NODEWATCH_BROWSER_WINDOW") == "1" or not WINDOW_EXE.is_file():
            edge = _edge()
            if edge:
                _set(edge)
                return edge
            _remove()
            return "browser"
        _set(str(WINDOW_EXE))
        return str(WINDOW_EXE)
    except Exception:  # never in the way of start-up: the launcher still falls back to a browser
        log.exception("Could not register the NodeWatch window")
        return ""
