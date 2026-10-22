from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

CURRENT_SCHEMA_VERSION = 1


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class ProvenanceValue:
    value: Any
    provider_id: str
    observed_at: str = ""
    confidence: float | None = None
    dataset: str = ""
    source_field: str = ""
    schema_version: int = CURRENT_SCHEMA_VERSION
    retrieved_at: str = field(default_factory=utc_now)

    @property
    def public_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class CanonicalRecord:
    """Versioned vendor-neutral NodeWatch record.

    ``data`` contains canonical nested fields. ``raw`` is backend-only provider data
    and must never be exposed by default through public_dict().
    """

    event_type: str
    provider_id: str
    observed_at: str = field(default_factory=utc_now)
    schema_version: int = CURRENT_SCHEMA_VERSION
    record_id: str = ""
    site_id: str = ""
    entity_id: str = ""
    severity: str = ""
    data: dict[str, Any] = field(default_factory=dict)
    provenance: dict[str, list[ProvenanceValue]] = field(default_factory=dict)
    raw: Any = None

    def public_dict(self, *, include_raw: bool = False) -> dict[str, Any]:
        result = {
            "schema_version": self.schema_version,
            "event_type": self.event_type,
            "provider_id": self.provider_id,
            "record_id": self.record_id,
            "observed_at": self.observed_at,
            "site_id": self.site_id,
            "entity_id": self.entity_id,
            "severity": self.severity,
            "data": self.data,
            "provenance": {k: [v.public_dict for v in vals] for k, vals in self.provenance.items()},
        }
        if include_raw:
            result["raw"] = self.raw
        return result
