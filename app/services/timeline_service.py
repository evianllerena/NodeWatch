from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Iterable

from app.integrations.models import CanonicalRecord


@dataclass(frozen=True)
class TimelineItem:
    timestamp: str
    event_type: str
    provider_id: str
    site_id: str = ""
    entity_id: str = ""
    severity: str = ""
    summary: str = ""
    data: dict[str, Any] | None = None

    @property
    def public_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "provider_id": self.provider_id,
            "site_id": self.site_id,
            "entity_id": self.entity_id,
            "severity": self.severity,
            "summary": self.summary,
            "data": self.data or {},
        }


def _time_key(value: str) -> float:
    raw = str(value or "").replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(raw).timestamp()
    except (TypeError, ValueError, OverflowError):
        return 0.0


class TimelineService:
    def from_records(self, records: Iterable[CanonicalRecord]) -> list[TimelineItem]:
        items = []
        for record in records:
            summary = str(record.data.get("summary") or record.data.get("message") or record.event_type)
            items.append(
                TimelineItem(
                    timestamp=record.observed_at,
                    event_type=record.event_type,
                    provider_id=record.provider_id,
                    site_id=record.site_id,
                    entity_id=record.entity_id,
                    severity=record.severity,
                    summary=summary,
                    data=record.data,
                )
            )
        return sorted(items, key=lambda x: _time_key(x.timestamp))


TIMELINE_SERVICE = TimelineService()
