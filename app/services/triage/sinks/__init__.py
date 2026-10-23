"""Triage sinks: outbound integrations told about triage events made on this PC (v0.10.18).

None ship yet. A ticketing / chat integration (Jira, ServiceNow, Microsoft Teams, Slack …) plugs in
like this::

    # app/services/triage/sinks/servicenow.py
    class ServiceNowSink:
        sink_id = "servicenow"

        def on_event(self, event: dict) -> None:
            if event["action"] == "assign":       # e.g. open / update an incident ticket
                OUTBOX.put(event)                  # never block the user's click: queue, send in a thread

    SINK = ServiceNowSink()

and is registered at start-up with :func:`register` (or discovered from this package by its ``SINK``
attribute — :func:`discover`). Rules a sink must follow:

* Only locally authored events are dispatched (each PC tells the outside world about its own clicks),
  so ten NodeWatch PCs reading one shared folder create one ticket, not ten.
* Be idempotent by ``event["id"]`` (a retry must not create a second ticket).
* Credentials (API tokens) live in Windows Credential Manager via ``app.integrations.secrets`` and are
  configured like a connector, never inside triage events or triage settings.
* Writing to an external system is a write: show what will be sent, require confirmation for
  anything that changes a vendor system, and audit it (``AuditService``), as for "Acknowledge in Mist".
* A failing sink is logged and skipped; it never fails the triage action.
"""

from __future__ import annotations

import importlib
import logging
import threading

from app.services.triage.base import TriageSink

log = logging.getLogger("nodewatch.triage.sinks")
_LOCK = threading.RLock()
_SINKS: dict[str, TriageSink] = {}
_DISCOVERED = False
# Allow-list (pilot P1): only these modules are imported; a file dropped into the folder is ignored.
SHIPPED_SINKS = ("builtin",)


def register(sink: TriageSink) -> None:
    if not isinstance(sink, TriageSink) or not str(getattr(sink, "sink_id", "")):
        raise TypeError("a sink needs a sink_id and on_event(event)")
    with _LOCK:
        _SINKS[sink.sink_id] = sink


def unregister(sink_id: str) -> None:
    with _LOCK:
        _SINKS.pop(sink_id, None)


def discover() -> None:
    """Register the shipped sink modules (``SHIPPED_SINKS``) that expose ``SINK``."""
    global _DISCOVERED
    with _LOCK:
        if _DISCOVERED:
            return
        _DISCOVERED = True
        for name in SHIPPED_SINKS:
            try:
                module = importlib.import_module(f"{__name__}.{name}")
                sink = getattr(module, "SINK", None)
                if sink is not None:
                    register(sink)
            except Exception:  # noqa: BLE001
                log.exception("Triage sink %s failed to load", name)


def registered() -> list[str]:
    discover()
    with _LOCK:
        return sorted(_SINKS)


def dispatch(events: list[dict]) -> None:
    discover()
    with _LOCK:
        sinks = list(_SINKS.values())
    for sink in sinks:
        for event in events:
            try:
                sink.on_event(event)
            except Exception:  # noqa: BLE001 - a sink never breaks triage
                log.exception("Triage sink %s failed on event %s", sink.sink_id, event.get("id"))
