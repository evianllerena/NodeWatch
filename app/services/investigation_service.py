from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.integrations.base import IntegrationError, registry
from app.integrations.query import NodeWatchQuery, QueryFilter, QUERY_ENGINE
from app.integrations.providers.traffic import APPROVED_TRAFFIC_PROVIDER_ID, resolve_traffic_window
from app.services.timeline_service import TIMELINE_SERVICE
from app.services.unified_device_service import unified_search_detective, unified_detective_detail


@dataclass
class InvestigationBundle:
    entity: dict[str, Any]
    sections: dict[str, Any] = field(default_factory=dict)
    provider_errors: list[dict[str, str]] = field(default_factory=list)

    @property
    def public_dict(self) -> dict[str, Any]:
        return {"entity": self.entity, "sections": self.sections, "provider_errors": self.provider_errors}


class InvestigationService:
    """Feature-facing API above vendor adapters."""

    def activity(self, *, ip: str, window: str = "1h", limit: int = 300) -> dict[str, Any]:
        try:
            start, end = resolve_traffic_window(window)
        except IntegrationError as exc:
            return {
                "provider_id": None,
                "records": [],
                "retrieved_count": 0,
                "has_more": False,
                "error": {"code": exc.code, "message": str(exc)},
            }
        query = NodeWatchQuery(
            event_type="network.session",
            capability="traffic.sessions",
            filters=(QueryFilter("source_or_destination.ip", "eq", ip),),
            start_time=start.isoformat(),
            end_time=end.isoformat(),
            page_size=limit,
        )
        try:
            result = QUERY_ENGINE.execute(query, provider_id=APPROVED_TRAFFIC_PROVIDER_ID)
            payload = result.public_dict
            payload["timeline"] = [
                x.public_dict
                for x in TIMELINE_SERVICE.from_records([r for r in result.records if hasattr(r, "event_type")])
            ]
            return payload
        except IntegrationError as exc:
            return {
                "provider_id": None,
                "records": [],
                "retrieved_count": 0,
                "has_more": False,
                "error": {"code": exc.code, "message": str(exc)},
            }

    def device(self, *, target: str, site_id: str | None = None) -> dict[str, Any]:
        result = unified_search_detective(target, site_id=site_id)
        rows = result.get("results") or []
        if not rows:
            return {"entity": {"target": target}, "sections": {}, "provider_errors": [], "found": False}
        top = rows[0]
        detail = unified_detective_detail(
            top.get("kind") or "endpoint",
            top.get("mac") or "",
            site_id=top.get("site_id") or site_id,
            fresh=False,
        )
        return {
            "found": True,
            "entity": {
                "target": target,
                "kind": top.get("kind"),
                "mac": top.get("mac"),
                "site_id": top.get("site_id") or site_id or "",
            },
            "sections": {"device": detail},
            "provider_errors": [],
        }

    def capabilities(self) -> dict[str, list[str]]:
        result: dict[str, list[str]] = {}
        for row in registry.descriptors():
            provider_id = row["provider_id"]
            provider = registry.get(provider_id)
            result[provider_id] = list(provider.capabilities()) if provider is not None else []
        return result


INVESTIGATION_SERVICE = InvestigationService()
