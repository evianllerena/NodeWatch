from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Iterable
import hashlib
import json

from app.integrations.base import IntegrationError, ProviderAdapter, registry
from app.integrations.cache import CACHE
from app.integrations.resilience import execute_resilient

ALLOWED_OPERATORS = {"eq", "neq", "in", "contains", "prefix", "exists", "gt", "gte", "lt", "lte"}
MAX_PAGE_SIZE = 1000


@dataclass(frozen=True)
class QueryFilter:
    field: str
    operator: str
    value: Any = None

    def validate(self) -> None:
        if not self.field or len(self.field) > 200:
            raise ValueError("Invalid query field")
        if self.operator not in ALLOWED_OPERATORS:
            raise ValueError(f"Unsupported query operator: {self.operator}")


@dataclass(frozen=True)
class NodeWatchQuery:
    event_type: str
    capability: str
    filters: tuple[QueryFilter, ...] = ()
    start_time: str = ""
    end_time: str = ""
    fields: tuple[str, ...] = ()
    sort: str = "-observed_at"
    page_size: int = 300
    cursor: str | None = None
    fresh: bool = False

    def validate(self) -> None:
        if not self.event_type or len(self.event_type) > 120:
            raise ValueError("event_type is required")
        if not self.capability or len(self.capability) > 120:
            raise ValueError("capability is required")
        if not (1 <= int(self.page_size) <= MAX_PAGE_SIZE):
            raise ValueError(f"page_size must be between 1 and {MAX_PAGE_SIZE}")
        for item in self.filters:
            item.validate()

    @property
    def public_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["filters"] = [asdict(x) for x in self.filters]
        return data


@dataclass
class QueryResult:
    records: list[Any] = field(default_factory=list)
    provider_id: str | None = None
    cursor: str | None = None
    next_cursor: str | None = None
    has_more: bool = False
    total: int | None = None
    retrieved_count: int = 0
    warnings: list[str] = field(default_factory=list)

    @property
    def public_dict(self) -> dict[str, Any]:
        def serialize(item: Any) -> Any:
            public = getattr(item, "public_dict", None)
            if public is not None:
                return public() if callable(public) else public
            to_dict = getattr(item, "to_dict", None)
            if callable(to_dict):
                return to_dict()
            return item

        return {
            "provider_id": self.provider_id,
            "records": [serialize(x) for x in self.records],
            "cursor": self.cursor,
            "next_cursor": self.next_cursor,
            "has_more": self.has_more,
            "total": self.total,
            "retrieved_count": self.retrieved_count or len(self.records),
            "warnings": list(self.warnings),
        }


class QueryEngine:
    """Provider-neutral dispatch layer. Features express intent, adapters translate it."""

    def execute(self, query: NodeWatchQuery, *, provider_id: str | None = None) -> QueryResult:
        query.validate()
        providers: Iterable[ProviderAdapter]
        if provider_id:
            provider = registry.get(provider_id)
            if provider is None:
                raise IntegrationError(f"Unknown provider: {provider_id}", code="PROVIDER_NOT_FOUND")
            if not provider.supports_query(query.capability):
                raise IntegrationError(
                    f"Provider {provider_id} does not support {query.capability}", code="CAPABILITY_UNAVAILABLE"
                )
            # Naming a provider explicitly must not bypass its enabled/verified gate.
            if not provider.configured or query.capability not in provider.capabilities():
                raise IntegrationError(
                    f"Provider {provider_id} is not enabled and verified for {query.capability}",
                    code="CAPABILITY_UNAVAILABLE",
                )
            providers = (provider,)
        else:
            providers = registry.providers_for(query.capability, configured_only=True, query_only=True)
        providers = list(providers)
        if not providers:
            raise IntegrationError(
                f"No configured provider supports capability {query.capability}", code="CAPABILITY_UNAVAILABLE"
            )
        if len(providers) > 1 and provider_id is None:
            # Do not silently pick a vendor when multiple authoritative sources exist.
            raise IntegrationError(
                f"Multiple providers support {query.capability}; an explicit provider or aggregation policy is required",
                code="AMBIGUOUS_PROVIDER",
            )
        provider = providers[0]
        cache_payload = query.public_dict
        # ``fresh`` controls cache usage, not query identity. A manual refresh must
        # overwrite the same cache entry used by normal reads instead of creating a
        # parallel fresh-only entry.
        cache_payload["fresh"] = False
        cache_key = (
            "query:"
            + hashlib.sha256(json.dumps(cache_payload, sort_keys=True, default=str).encode("utf-8")).hexdigest()
        )
        if not query.fresh:
            cached = CACHE.get(cache_key)
            if isinstance(cached, QueryResult):
                return cached
        policy_factory = getattr(provider, "retry_policy", None)
        policy = policy_factory() if callable(policy_factory) else None
        result = execute_resilient(provider.provider_id, lambda: provider.query(query), retry=policy)
        if isinstance(result, QueryResult):
            normalized = result
        elif isinstance(result, list):
            normalized = QueryResult(records=result, provider_id=provider.provider_id, retrieved_count=len(result))
        elif isinstance(result, dict):
            normalized = QueryResult(
                records=list(result.get("records") or result.get("sessions") or []),
                provider_id=result.get("provider_id") or provider.provider_id,
                cursor=result.get("cursor"),
                next_cursor=result.get("next_cursor"),
                has_more=bool(result.get("has_more")),
                total=result.get("total"),
                retrieved_count=int(
                    result.get("retrieved_count") or len(result.get("records") or result.get("sessions") or [])
                ),
                warnings=list(result.get("warnings") or []),
            )
        else:
            raise IntegrationError("Provider returned an unsupported query result", code="INVALID_PROVIDER_RESPONSE")
        cache_tier, cache_ttl = provider.cache_policy(query.capability)
        CACHE.put(cache_key, normalized, tier=cache_tier, ttl_seconds=cache_ttl)
        return normalized


QUERY_ENGINE = QueryEngine()


def invalidate_query_cache() -> int:
    """Drop cached query results (call when a provider is enabled, disabled or reset)."""
    return CACHE.invalidate("query:")
