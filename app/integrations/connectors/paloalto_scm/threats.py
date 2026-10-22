"""Strata Cloud Manager / Strata Logging Service → ``security.events`` (v0.10.30).

Reads threat and URL logs through the Log Viewer API the Traffic & Sessions provider already uses (same
service account, same query host, read-only POSTs); each row becomes a vendor-neutral :class:`SecurityEvent`
through the shared PAN-OS vocabulary in :mod:`app.integrations.connectors.panos_logs`.

Dataset names: Palo Alto does not publish the Log Viewer names of the threat and URL logs. Like the system
log (v0.10.28), each candidate is tried and the first that answers is remembered; refusals are remembered for
24 hours with the service's own error text (diagnostics). Field names are tolerant (several spellings per
value) and the set of field names seen is written to the application log once per start, so a diagnostics
file shows what this tenant really returns.

Cost: one bounded series of pages (≤ ``MAX_PAGES`` × 1000 rows) per call; the Security Operations service
calls it in the background with a moving window, never on a page request.
"""

from __future__ import annotations

import json
import logging
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.integrations.connectors.panos_logs import to_event
from app.integrations.contracts import SECURITY_EVENTS
from app.integrations.domain import SecurityEvent
from app.integrations.providers.strata_logging import THREAT_DATASETS, URL_DATASETS
from app.core.file_utils import write_private_text

log = logging.getLogger("nodewatch.connectors.paloalto_scm")

STATE_NAME = "scm_security_logs.json"
REFUSED_RETRY_S = 24 * 3600.0
PAGE_SIZE = 1000
MAX_PAGES = 5
# URL logs record every web request; only the ones a policy blocked or warned on are security events.
URL_BLOCK_ACTIONS = ("block-url", "block-continue", "block-override", "override-lockout", "continue", "override")


class _SecurityLogState:
    """Which dataset name answers for threat / URL logs (remembered), refusals with their text (24 h)."""

    def __init__(self, state_dir: Path | None = None) -> None:
        self._lock = threading.Lock()
        self._state_dir = state_dir
        self._data: dict[str, Any] | None = None
        self.fields_logged: set[str] = set()

    def _path(self) -> Path:
        if self._state_dir is not None:
            return self._state_dir / STATE_NAME
        from app.core.config import STATE_ROOT

        return STATE_ROOT / STATE_NAME

    def load(self) -> dict[str, Any]:
        with self._lock:
            if self._data is None:
                try:
                    raw = json.loads(self._path().read_text(encoding="utf-8"))
                    self._data = raw if isinstance(raw, dict) else {}
                except (OSError, ValueError):
                    self._data = {}
            return dict(self._data)

    def save(self, data: dict[str, Any]) -> None:
        with self._lock:
            self._data = dict(data)
        p = self._path()
        try:
            p.parent.mkdir(parents=True, exist_ok=True)
            write_private_text(p, json.dumps(data, separators=(",", ":"), default=str))  # atomic, owner-only (v0.10.40)
        except OSError as exc:
            log.info("SCM security log state not saved: %s", exc)

    def clear(self) -> None:
        with self._lock:
            self._data = {}


def _dt(epoch: float) -> datetime:
    return datetime.fromtimestamp(epoch, tz=timezone.utc)


class ScmThreats:
    """Mixin for the Strata Cloud Manager connector: the ``security.events`` capability."""

    CAPABILITIES = (SECURITY_EVENTS,)

    def _security_state(self) -> _SecurityLogState:
        st = getattr(self, "_sec_state", None)
        if st is None:
            st = self._sec_state = _SecurityLogState(getattr(self, "security_state_dir", None))
        return st

    def security_log_status(self) -> dict[str, Any]:
        """For diagnostics: which names answered, which were refused and why."""
        return self._security_state().load()

    def _query_dataset(
        self, kind: str, names: tuple[str, ...], since: float, until: float, limit: int, extra_rules: list | None
    ) -> list[dict[str, Any]]:
        provider = self.strata_provider()
        post = getattr(provider, "_post_logviewer", None)
        build = getattr(provider, "_build_body", None)
        if not callable(post) or not callable(build):
            return []
        state = self._security_state()
        data = state.load()
        mem = dict(data.get(kind) or {})
        now = time.time()
        if mem.get("refused_at") and now - float(mem["refused_at"]) < REFUSED_RETRY_S and not mem.get("dataset"):
            return []  # every name was refused recently; asked again after 24 h
        order = list(names)
        if mem.get("dataset") in order:
            order.remove(mem["dataset"])
            order.insert(0, mem["dataset"])
        rows: list[dict[str, Any]] = []
        refusals: list[str] = []
        start, end = _dt(since), _dt(until)
        pages = max(1, min(MAX_PAGES, -(-limit // PAGE_SIZE)))
        for dataset in order:
            got: list[dict[str, Any]] = []
            try:
                for page in range(1, pages + 1):
                    body = build(start, end, page_size=min(PAGE_SIZE, limit), page_number=page)
                    if extra_rules:
                        body["filter"]["rules"].extend(extra_rules)
                    # The first page of an unproven name is a probe (a refusal is not a provider failure).
                    payload = post(dataset, body, probe=(page == 1 and mem.get("dataset") != dataset))
                    batch = [r for r in (payload.get("data") or []) if isinstance(r, dict)]
                    got += batch
                    if len(batch) < min(PAGE_SIZE, limit) or len(got) >= limit:
                        break
            except Exception as exc:  # noqa: BLE001
                status = getattr(exc, "status_code", None)
                if status in (400, 403, 404, 422) and not got:
                    refusals.append(f"{dataset}: HTTP {status} {str(exc)[:200]}")
                    continue
                if got:
                    rows = got  # a later page failed: keep what arrived
                    break
                raise
            rows = got
            if mem.get("dataset") != dataset:
                log.info("Log Viewer %s log answers as %s: %d rows", kind, dataset, len(rows))
            mem.update(dataset=dataset, refused_at=None, refusals=[], answered_at=now)
            break
        else:
            mem.update(dataset="", refused_at=now, refusals=refusals[-6:])
            log.info("Log Viewer refuses every %s log name tried: %s", kind, "; ".join(refusals)[:600])
        data[kind] = mem
        state.save(data)
        if rows and kind not in state.fields_logged:
            state.fields_logged.add(kind)
            names_seen = sorted({k for r in rows[:200] for k in r})
            log.info("Log Viewer %s log fields (%d): %s", kind, len(names_seen), ", ".join(names_seen)[:2000])
        return rows[:limit]

    def list_security_events(self, *, since: float, until: float | None = None, limit: int = 2000) -> list[SecurityEvent]:
        """Threat-log detections (exploits, malware, spyware/C2, scans, floods, data) and blocked web requests
        between ``since`` and ``until``, newest first, at most ``limit``."""
        if not self.configured:
            return []
        until = float(until or time.time())
        since = float(since)
        if since >= until:
            return []
        limit = max(1, min(int(limit or 2000), MAX_PAGES * PAGE_SIZE))
        threat_rows = self.call(
            lambda: self._query_dataset("threat", THREAT_DATASETS, since, until, limit, None),
            "read threat logs",
        )
        url_rows: list[dict[str, Any]] = []
        try:
            url_rows = self._query_dataset(
                "url",
                URL_DATASETS,
                since,
                until,
                min(limit, PAGE_SIZE),
                [{"property": "action", "operator": "in", "values": list(URL_BLOCK_ACTIONS)}],
            )
        except Exception as exc:  # noqa: BLE001 - blocked-web events are a bonus; threats still count
            log.info("URL log read skipped: %s", self.redact(exc)[:200])
        out: list[SecurityEvent] = []
        seen: set[str] = set()
        for rows, kind in ((threat_rows, "threat"), (url_rows, "url")):
            for r in rows:
                ev = to_event(r, self.provider_id, kind)
                if ev is None or ev.key in seen:
                    continue
                if kind == "url" and ev.outcome == "allowed":
                    continue
                seen.add(ev.key)
                out.append(ev)
        out.sort(key=lambda e: -e.timestamp)
        return out[:limit]
