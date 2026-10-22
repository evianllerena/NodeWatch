from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Iterable


@dataclass(frozen=True)
class Observation:
    """One provider's observation of a normalized Device Finder field.

    Provider identity and authority stay in the backend.  Device Finder consumes the
    resolved values only; this metadata exists so future providers can be added without
    turning correlation into a last-writer-wins merge.
    """

    field_id: str
    value: Any
    provider_id: str
    authority: int = 50
    observed_at: str = ""
    confidence: float | None = None


@dataclass
class CorrelationResult:
    values: dict[str, Any] = field(default_factory=dict)
    observations: dict[str, list[Observation]] = field(default_factory=dict)
    conflicts: dict[str, list[Observation]] = field(default_factory=dict)


def _present(value: Any) -> bool:
    return value is not None and value != ""


def _time_score(value: str) -> float:
    raw = str(value or "").strip()
    if not raw:
        return 0.0
    try:
        if raw.endswith("Z"):
            raw = raw[:-1] + "+00:00"
        return datetime.fromisoformat(raw).timestamp()
    except (TypeError, ValueError, OverflowError):
        return 0.0


def _confidence_score(value: float | None) -> float:
    try:
        return float(value) if value is not None else -1.0
    except (TypeError, ValueError):
        return -1.0


def _same_value(a: Any, b: Any) -> bool:
    if isinstance(a, str) or isinstance(b, str):
        return str(a).strip().lower() == str(b).strip().lower()
    return a == b


class CorrelationEngine:
    """Deterministically resolve normalized provider observations.

    Resolution order is explicit authority, then freshness, then confidence.  Ties are
    stable.  Disagreements are retained in the returned backend result for diagnostics
    and future reasoning, but normal Device Finder responses need expose only ``values``.
    """

    def resolve(self, observations: Iterable[Observation]) -> CorrelationResult:
        grouped: dict[str, list[Observation]] = {}
        for obs in observations:
            if not obs.field_id or not _present(obs.value):
                continue
            grouped.setdefault(obs.field_id, []).append(obs)

        result = CorrelationResult(observations=grouped)
        for field_id, rows in grouped.items():
            ranked = sorted(
                enumerate(rows),
                key=lambda pair: (
                    int(pair[1].authority),
                    _time_score(pair[1].observed_at),
                    _confidence_score(pair[1].confidence),
                    -pair[0],
                ),
                reverse=True,
            )
            winner = ranked[0][1]
            result.values[field_id] = winner.value
            disagreements = [row for row in rows if not _same_value(row.value, winner.value)]
            if disagreements:
                result.conflicts[field_id] = [winner, *disagreements]
        return result


CORRELATION_ENGINE = CorrelationEngine()
