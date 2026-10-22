"""Juniper Mist → ``security.events`` (v0.10.30): wireless-intrusion conditions as security detections.

Mist reports rogue access points, rogue clients, honeypot SSIDs and other wireless-security conditions as
alarms. They already arrive here as vendor-neutral :class:`Alert` records with category "security"
(:mod:`alerts`); this mixin re-expresses those as :class:`SecurityEvent` records (kind "wireless",
outcome "alerted": Mist saw it, nothing blocked it), so the Security Operations Center counts them with
every other vendor's detections. No extra Mist API call is made.
"""

from __future__ import annotations

import time
from typing import Any

from app.integrations.contracts import SECURITY_EVENTS
from app.integrations.domain import SecurityEvent, stable_key

_SEVERITY = {"critical": "critical", "major": "major", "warning": "warning", "info": "info"}


class MistSecurity:
    CAPABILITIES: tuple[str, ...] = (SECURITY_EVENTS,)

    def list_security_events(self, *, since: float, until: float | None = None, limit: int = 2000) -> list[SecurityEvent]:
        until = float(until or time.time())
        alerts: list[Any] = self.list_alerts(None)  # type: ignore[attr-defined]
        out: list[SecurityEvent] = []
        for a in alerts:
            if a.category != "security":
                continue
            when = a.last_seen or a.first_seen
            if when is None or not (since <= when <= until):
                continue
            out.append(
                SecurityEvent(
                    key=stable_key("mist-sec", a.key),  # one record per condition: repeats update it
                    source=a.source,
                    timestamp=float(when),
                    kind="wireless",
                    severity=_SEVERITY.get(a.severity, "warning"),
                    outcome="alerted",
                    direction="internal",
                    name=a.title,
                    category=a.type,
                    sensor_key=a.device_key,
                    sensor_name=a.device_name,
                    site_key=a.site_key,
                    count=max(1, int(a.count or 1)),
                    native_id=a.native_id,
                    console_url=a.console_url,
                    vendor={"alert_key": a.key, "site_name": a.site_name},
                )
            )
        out.sort(key=lambda e: -e.timestamp)
        return out[: max(1, int(limit or 2000))]
