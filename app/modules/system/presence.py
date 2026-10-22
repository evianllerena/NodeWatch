"""Close NodeWatch when its last browser tab closes (v0.10.15).

Every open NodeWatch tab sends a heartbeat (``POST /api/system/presence``) and says goodbye when
it is closed (``pagehide`` → ``POST /api/system/presence/bye`` with ``keepalive``). The watchdog
stops the backend when:

* the last tab said goodbye and none came back within ``BYE_GRACE_SECONDS`` (a reload or a
  navigation sends a new heartbeat well inside that window), or
* no tab has been heard from for ``STALE_SECONDS`` while it was visible (browser killed or
  crashed). A tab that said it went to the background (hidden) or is being frozen (Edge
  "sleeping tabs", Chrome Memory Saver) can stay silent for ``HIDDEN_STALE_SECONDS`` instead,
  because browsers stop its timers completely, or
* no tab ever connected within ``FIRST_CONTACT_SECONDS`` of start-up (the browser never opened).

A computer that sleeps stops every timer, NodeWatch's included: when the watchdog notices a jump
in wall-clock time it treats it as sleep and restarts the countdown instead of exiting.

``NODEWATCH_KEEP_RUNNING=1`` disables the watchdog (development and tests). The user can do the same
with Settings › "Keep NodeWatch running when its window is closed" (v0.10.24, ``keep_running`` in
ui.json, see :func:`keep_running_preference`): the watchdog then never stops the backend by itself.

v0.10.24 is more forgiving: the goodbye grace is 60 s (was 15 s), and a tab that said goodbye but then
sends a real heartbeat again (visible, or any heartbeat a few seconds after its goodbye - e.g. a
goodbye sent while a window was only being minimised or the page restored itself) counts as open again.
"""

from __future__ import annotations

import functools
import logging
import os
import threading
import time
from collections.abc import Callable

log = logging.getLogger("nodewatch.presence")

BYE_GRACE_SECONDS = 60.0
# A closing tab can send its last "hidden" heartbeat just after its goodbye; anything later than this,
# or any "visible" heartbeat, is a tab that is really still there.
REVIVE_AFTER_BYE_SECONDS = 3.0
# v0.10.35: silence alone is a weak signal (a PC in modern standby keeps NodeWatch running but freezes
# the browser, so heartbeats stop without any goodbye; that stopped NodeWatch overnight in 0.10.34).
# While the NodeWatch app window is known to be open, silence never stops the backend - only an explicit
# goodbye or the window closing do. Without that knowledge (a normal browser tab) the limits are long.
STALE_SECONDS = 1800.0
HIDDEN_STALE_SECONDS = 24 * 3600.0
FIRST_CONTACT_SECONDS = 600.0
TICK_SECONDS = 5.0
SLEEP_JUMP_SECONDS = 60.0
MAX_TABS = 64


class PresenceTracker:
    def __init__(self, clock: Callable[[], float] = time.time):
        self._clock = clock
        self._lock = threading.Lock()
        self._tabs: dict[str, float] = {}
        self._started = clock()
        self._ever_seen = False
        self._last_bye: float | None = None
        self._last_tick = clock()
        self._hidden: set[str] = set()
        # Tabs that said goodbye. A closing tab often sends its "hidden" heartbeat and its goodbye at
        # the same moment; if the heartbeat arrives second it must not bring the closed tab back.
        self._closed: dict[str, float] = {}
        self._busy = 0

    def heartbeat(self, tab_id: str, state: str = "visible") -> int:
        tab = str(tab_id or "")[:64]
        if not tab:
            return len(self._tabs)
        with self._lock:
            now = self._clock()
            closed_at = self._closed.get(tab)
            if closed_at is not None:
                if state in {"hidden", "frozen"} and now - closed_at < REVIVE_AFTER_BYE_SECONDS:
                    return len(self._tabs)  # the closing tab's own last heartbeat, racing its goodbye
                self._closed.pop(tab, None)
                log.info("Tab %s is back after its goodbye (%s, %.0f s later); ignoring the goodbye", tab[:8], state, now - closed_at)
            if tab not in self._tabs and len(self._tabs) >= MAX_TABS:
                oldest = min(self._tabs, key=self._tabs.get)
                self._tabs.pop(oldest, None)
            self._tabs[tab] = now
            if state in {"hidden", "frozen"}:
                self._hidden.add(tab)
            else:
                self._hidden.discard(tab)
            self._ever_seen = True
            self._last_bye = None
            return len(self._tabs)

    def bye(self, tab_id: str) -> int:
        with self._lock:
            tab = str(tab_id or "")[:64]
            self._tabs.pop(tab, None)
            self._hidden.discard(tab)
            if tab:
                now = self._clock()
                self._closed[tab] = now
                if len(self._closed) > 4 * MAX_TABS:
                    for old in sorted(self._closed, key=self._closed.get)[: len(self._closed) - 2 * MAX_TABS]:
                        self._closed.pop(old, None)
            if not self._tabs:
                self._last_bye = self._clock()
            log.info(
                "Tab %s said goodbye; %d tab(s) still open%s",
                tab[:8] or "?",
                len(self._tabs),
                "" if self._tabs else f" - NodeWatch stops in {int(BYE_GRACE_SECONDS)} s unless a tab returns",
            )
            return len(self._tabs)

    def browser_closed(self) -> None:
        """The NodeWatch app window's browser exited (v0.10.22, see AppWindowWatch). Its tabs' goodbye
        messages can be lost when the whole browser shuts down, so forget the tabs now. The grace is
        35 s rather than 15 s so a NodeWatch tab in a normal browser (heartbeat every 30 s) can still
        show it is open."""
        with self._lock:
            open_tabs = len(self._tabs)
            self._tabs.clear()
            self._hidden.clear()
            self._last_bye = self._clock()
        log.info("App window closed with %d tab(s) registered; stopping in %d s unless a tab returns",
                 open_tabs, int(BYE_GRACE_SECONDS))

    def begin_request(self) -> None:
        with self._lock:
            self._busy += 1

    def end_request(self) -> None:
        with self._lock:
            self._busy = max(0, self._busy - 1)

    def snapshot(self) -> dict:
        with self._lock:
            now = self._clock()
            return {
                "tabs": len(self._tabs),
                "ever_seen": self._ever_seen,
                "hidden_tabs": len(self._hidden),
                "seconds_since_bye": None if self._last_bye is None else round(now - self._last_bye, 1),
            }

    def should_exit(self, *, window_open: bool = False) -> str:
        """Reason to stop the backend now, or "" to keep running. Call every TICK_SECONDS.

        ``window_open``: the NodeWatch app window's browser is running (its profile lock exists). Then
        quiet tabs are kept as open however long they are silent."""
        with self._lock:
            now = self._clock()
            gap = now - self._last_tick
            self._last_tick = now
            if window_open:
                for tab in self._tabs:
                    self._tabs[tab] = now
            if gap > SLEEP_JUMP_SECONDS:
                # The PC slept (or the process was suspended): give every tab a fresh chance.
                for tab in self._tabs:
                    self._tabs[tab] = now
                if self._last_bye is not None:
                    self._last_bye = now
                if not self._ever_seen:
                    self._started = now
                return ""
            for tab, seen in list(self._tabs.items()):
                limit = HIDDEN_STALE_SECONDS if tab in self._hidden else STALE_SECONDS
                if now - seen > limit:
                    self._tabs.pop(tab, None)
                    self._hidden.discard(tab)
                    if not self._tabs:
                        self._last_bye = seen + limit
            if self._tabs or self._busy:
                return ""
            if not self._ever_seen:
                return "no browser tab connected" if now - self._started > FIRST_CONTACT_SECONDS else ""
            if self._last_bye is not None and now - self._last_bye >= BYE_GRACE_SECONDS:
                return f"last NodeWatch tab closed {int(now - self._last_bye)} s ago, no tab came back (0 tabs open)"
            return ""


TRACKER = PresenceTracker()


def holds_exit(fn):
    """Keep the backend alive while ``fn`` runs (v0.10.22).

    The HTTP middleware already counts in-flight write requests, but that count ends when the
    request task ends; if the browser disconnects mid-change, the synchronous handler can still be
    writing to the vendor and verifying. Production write entry points use this decorator so the
    close-with-last-tab exit waits for the change itself, not just for the request.
    """

    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        TRACKER.begin_request()
        try:
            return fn(*args, **kwargs)
        finally:
            TRACKER.end_request()

    return wrapper
_WATCHDOG: threading.Thread | None = None


def watchdog_enabled() -> bool:
    return os.environ.get("NODEWATCH_KEEP_RUNNING", "").strip() not in {"1", "true", "yes"}


_KEEP_RUNNING_CACHE: dict = {"at": 0.0, "value": False}


def keep_running_preference(*, max_age: float = 10.0) -> bool:
    """Settings › "Keep NodeWatch running when its window is closed" (ui.json ``keep_running``, default off)."""
    now = time.monotonic()
    if now - _KEEP_RUNNING_CACHE["at"] < max_age:
        return bool(_KEEP_RUNNING_CACHE["value"])
    value = False
    try:
        from app.core.file_utils import read_json
        from app.ui.preferences import UI_FILE

        data = read_json(UI_FILE, {}) if UI_FILE.exists() else {}
        value = bool(isinstance(data, dict) and data.get("keep_running") is True)
    except Exception:  # noqa: BLE001 - unreadable preferences keep the default behaviour
        value = bool(_KEEP_RUNNING_CACHE["value"])
    _KEEP_RUNNING_CACHE.update(at=now, value=value)
    return value


def set_keep_running_preference(enabled: bool) -> bool:
    from app.core.config import DATA_ROOT
    from app.core.file_utils import locked_json_update
    from app.ui.preferences import UI_FILE

    def apply(cur):
        data = dict(cur) if isinstance(cur, dict) else {}
        data["keep_running"] = bool(enabled)
        return data

    DATA_ROOT.mkdir(parents=True, exist_ok=True)
    locked_json_update(UI_FILE, apply, default={})
    _KEEP_RUNNING_CACHE.update(at=time.monotonic(), value=bool(enabled))
    log.info("Keep NodeWatch running when its window is closed: %s", "on" if enabled else "off")
    return bool(enabled)


class AppWindowWatch:
    """Notices when the NodeWatch app window closes, even if its goodbye message was lost.

    The native launcher opens NodeWatch in Edge/Chrome app mode with a private profile in
    <data>\\app-window. Chromium keeps a "lockfile" in that folder while it runs (deleted on exit); on
    macOS it is the "SingletonLock" symlink instead (it points nowhere, so it is tested with lexists).
    Once the file has been seen and is then gone for two ticks, the window is closed. If the file is
    never seen (default-browser fallback, another browser), this does nothing.
    """

    def __init__(self, profile_dir) -> None:
        from pathlib import Path

        self.lockfile = Path(profile_dir) / ("lockfile" if os.name == "nt" else "SingletonLock")
        self.seen = False
        self.missing = 0

    @property
    def open(self) -> bool:
        """The window's browser is running right now (lock seen and not missing)."""
        return self.seen and self.missing == 0

    def closed(self) -> bool:
        try:
            present = os.path.lexists(self.lockfile)
        except OSError:
            return False
        if present:
            self.seen, self.missing = True, 0
            return False
        if not self.seen:
            return False
        self.missing += 1
        if self.missing >= 2:
            self.seen, self.missing = False, 0
            return True
        return False


def start_watchdog(stop: Callable[[], None]) -> bool:
    """Run the presence watchdog in the background; ``stop`` shuts the backend down."""
    global _WATCHDOG
    if not watchdog_enabled() or (_WATCHDOG and _WATCHDOG.is_alive()):
        return False

    try:
        from app.core.config import DATA_ROOT

        window = AppWindowWatch(DATA_ROOT / "app-window")
    except Exception:  # noqa: BLE001 - the backstop is optional
        window = None

    def loop() -> None:
        last_kept = ""
        while True:
            time.sleep(TICK_SECONDS)
            try:
                if window is not None and window.closed():
                    log.info("NodeWatch app window closed")
                    TRACKER.browser_closed()
                reason = TRACKER.should_exit(window_open=bool(window is not None and window.open))
            except Exception:  # noqa: BLE001 - the watchdog must never die or stop NodeWatch by mistake
                log.exception("Presence check failed; NodeWatch keeps running")
                continue
            if reason and keep_running_preference():
                if reason != last_kept:
                    log.info("Not stopping NodeWatch (%s): the keep-running setting is on", reason)
                    last_kept = reason
                continue
            if reason:
                log.info("Stopping NodeWatch: %s", reason)
                stop()
                return

    _WATCHDOG = threading.Thread(target=loop, name="nodewatch-presence", daemon=True)
    _WATCHDOG.start()
    return True
