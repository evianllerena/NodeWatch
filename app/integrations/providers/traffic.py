from __future__ import annotations

from concurrent.futures import Future
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import threading
import time
from typing import Any

from app.integrations.base import IntegrationError, ProviderAdapter, ProviderDescriptor, ProviderHealth, registry
from app.integrations.query import NodeWatchQuery, QueryFilter, QUERY_ENGINE

PROVIDER_ID = "traffic_framework"
APPROVED_TRAFFIC_PROVIDER_ID = "strata_logging_service"
TRAFFIC_SCHEMA_VERSION = "1.0"
DESCRIPTOR = ProviderDescriptor(
    PROVIDER_ID,
    "Traffic Sessions Framework",
    ("traffic.framework",),
    read_only=True,
    vendor="nodewatch",
)
# v0.10.15: a device's answer is kept for 60 s so re-opening it (or opening it after the row was
# hovered) is instant, and identical requests that arrive while one is running share its answer.
RECENT_SECONDS = 60.0
_RECENT_MAX = 64


@dataclass(frozen=True)
class TrafficSessionQuery:
    client_ip: str
    window: str = "1h"
    limit: int = 300
    refresh: bool = False


def resolve_traffic_window(window: str, *, bucket_seconds: int = 30) -> tuple[datetime, datetime]:
    delta = {
        "15m": timedelta(minutes=15),
        "1h": timedelta(hours=1),
        "6h": timedelta(hours=6),
        "24h": timedelta(hours=24),
    }.get(window)
    if delta is None:
        raise IntegrationError("Unsupported traffic time window", code="INVALID_QUERY")
    now = datetime.now(timezone.utc)
    bucket = max(1, int(bucket_seconds))
    epoch = int(now.timestamp())
    end = datetime.fromtimestamp(epoch - (epoch % bucket), tz=timezone.utc)
    return end - delta, end


class TrafficSessionsProvider(ProviderAdapter):
    """Provider-neutral Traffic & Sessions facade.

    It dispatches through the generic query engine only when an approved vendor adapter
    advertises ``traffic.sessions``. It never chooses or embeds a vendor API itself.
    """

    descriptor = DESCRIPTOR

    def __init__(self) -> None:
        self._recent_lock = threading.Lock()
        self._recent: dict[tuple, tuple[float, dict[str, Any]]] = {}
        self._inflight: dict[tuple, Future] = {}

    def clear_recent(self) -> None:
        with self._recent_lock:
            self._recent.clear()

    def _recent_get(self, key: tuple) -> dict[str, Any] | None:
        now = time.monotonic()
        with self._recent_lock:
            hit = self._recent.get(key)
            if not hit:
                return None
            at, payload = hit
            if now - at > RECENT_SECONDS:
                self._recent.pop(key, None)
                return None
        return {**payload, "cached": True, "age_ms": int((now - at) * 1000)}

    def _recent_put(self, key: tuple, payload: dict[str, Any]) -> None:
        with self._recent_lock:
            if len(self._recent) >= _RECENT_MAX:
                oldest = min(self._recent, key=lambda k: self._recent[k][0])
                self._recent.pop(oldest, None)
            self._recent[key] = (time.monotonic(), payload)

    @property
    def configured(self) -> bool:
        provider = registry.get(APPROVED_TRAFFIC_PROVIDER_ID)
        return bool(provider and provider.configured and provider.supports_query("traffic.sessions"))

    def health_state(self) -> ProviderHealth:
        health = ProviderHealth(configured=self.configured)
        health.state = "healthy" if self.configured else "pending_provider"
        return health

    def search_by_ip(
        self,
        ip: str,
        *,
        window: str = "1h",
        limit: int = 300,
        cursor: str | None = None,
        fresh: bool = False,
        since_ms: int | None = None,
    ) -> dict[str, Any]:
        # Normal (non-live, first page) lookups: answer from the 60 s per-device cache, or join an
        # identical lookup that is already running (e.g. one started when the row was hovered).
        # The provider instance is part of the key: enabling, re-verifying or resetting Palo Alto
        # creates a new instance, so nothing cached under the old configuration is reused.
        source = id(registry.get(APPROVED_TRAFFIC_PROVIDER_ID))
        key = ("lookup", source, ip, window, int(limit)) if not since_ms and not cursor else None
        if not self.configured:
            self.clear_recent()  # disabled or reset: never answer from an earlier configuration
            key = None
        if key is None:
            return self._search(ip, window=window, limit=limit, cursor=cursor, fresh=fresh, since_ms=since_ms)
        if not fresh:
            recent = self._recent_get(key)
            if recent is not None:
                return recent
        with self._recent_lock:
            running = self._inflight.get(key)
            owner = running is None
            if owner:
                running = Future()
                self._inflight[key] = running
        if not owner:
            return {**running.result(), "joined": True}
        try:
            payload = self._search(ip, window=window, limit=limit, cursor=cursor, fresh=fresh, since_ms=since_ms)
        except BaseException as exc:
            running.set_exception(exc)
            raise
        finally:
            with self._recent_lock:
                self._inflight.pop(key, None)
        if payload.get("available"):
            self._recent_put(key, payload)
        running.set_result(payload)
        return payload

    def _search(
        self,
        ip: str,
        *,
        window: str,
        limit: int,
        cursor: str | None,
        fresh: bool,
        since_ms: int | None,
    ) -> dict[str, Any]:
        # Align normal queries to the hot-cache window so repeated UI reads do not
        # generate a new provider job merely because the current microsecond changed.
        start, end = resolve_traffic_window(window)
        if since_ms:
            # Live mode: only the newest logs. Look back 3 minutes before the newest row the UI
            # already has, because Strata indexes logs 1-2 minutes after the firewall writes them.
            end = datetime.now(timezone.utc)
            since = datetime.fromtimestamp(int(since_ms) / 1000, tz=timezone.utc) - timedelta(minutes=3)
            start = max(since, end - timedelta(hours=24))
            fresh = True
        query = NodeWatchQuery(
            event_type="network.session",
            capability="traffic.sessions",
            filters=(QueryFilter("source_or_destination.ip", "eq", ip),),
            start_time=start.isoformat(),
            end_time=end.isoformat(),
            page_size=limit,
            cursor=cursor,
            fresh=fresh,
        )
        started = time.perf_counter()
        if not self.configured:
            provider = registry.get(APPROVED_TRAFFIC_PROVIDER_ID)
            return empty_traffic_response(
                client_ip=ip,
                window=window,
                message="Strata Logging Service is not configured and verified for Traffic & Sessions."
                if provider is not None
                else "The approved Traffic & Sessions provider is not installed.",
                provider=APPROVED_TRAFFIC_PROVIDER_ID,
                status="not_configured" if provider is not None else "service_unavailable",
                status_label="Not configured" if provider is not None else "Provider unavailable",
            )
        try:
            result = QUERY_ENGINE.execute(query, provider_id=APPROVED_TRAFFIC_PROVIDER_ID)
        except IntegrationError as exc:
            if exc.code == "CAPABILITY_UNAVAILABLE":
                provider = registry.get(APPROVED_TRAFFIC_PROVIDER_ID)
                if provider is not None:
                    return empty_traffic_response(
                        client_ip=ip,
                        window=window,
                        message="Strata Logging Service is not configured and verified for Traffic & Sessions.",
                        provider=APPROVED_TRAFFIC_PROVIDER_ID,
                        status="not_configured",
                        status_label="Not configured",
                    )
                return empty_traffic_response(
                    client_ip=ip,
                    window=window,
                    message="The approved Traffic & Sessions provider is not installed.",
                    provider=APPROVED_TRAFFIC_PROVIDER_ID,
                    status="service_unavailable",
                    status_label="Provider unavailable",
                )
            raise
        records = []
        for item in result.public_dict["records"]:
            traffic = ((item.get("data") or {}).get("traffic") or {}) if isinstance(item, dict) else {}
            if traffic:
                records.append(
                    {
                        **traffic,
                        "provider_id": item.get("provider_id"),
                        "record_id": item.get("record_id"),
                        # Per-field provenance stays in the backend record (it repeated every value
                        # several times and made the answer to the browser several times larger).
                    }
                )
        return {
            "schema_version": TRAFFIC_SCHEMA_VERSION,
            "available": True,
            "configured": True,
            "provider": result.provider_id,
            "source": result.provider_id,
            "provider_authority": APPROVED_TRAFFIC_PROVIDER_ID,
            "status": "data_available" if records else "no_traffic",
            "status_label": "Data available" if records else "No traffic found",
            "client_ip": ip,
            "window": window,
            "sessions": records,
            "count": len(records),
            "cursor": result.cursor,
            "next_cursor": result.next_cursor,
            "has_more": result.has_more,
            "total": result.total,
            "query_duration_ms": int((time.perf_counter() - started) * 1000),
            "timing": {
                **(getattr(result, "timing", None) or {}),
                "nodewatch_ms": int((time.perf_counter() - started) * 1000),
            },
            "cached": False,
            "message": "" if records else "No traffic sessions found for this device during the selected time range.",
        }


def empty_traffic_response(
    *,
    client_ip: str,
    window: str,
    message: str,
    provider: str | None = None,
    status: str = "not_configured",
    status_label: str = "Data source unavailable",
) -> dict[str, Any]:
    return {
        "schema_version": TRAFFIC_SCHEMA_VERSION,
        "available": False,
        "configured": False,
        "provider": provider,
        "source": provider,
        "provider_authority": APPROVED_TRAFFIC_PROVIDER_ID,
        "status": status,
        "client_ip": client_ip,
        "window": window,
        "sessions": [],
        "count": 0,
        "message": message,
        "status_label": status_label,
    }


_provider = TrafficSessionsProvider()


def get_traffic_sessions_provider() -> TrafficSessionsProvider:
    return _provider


registry.register(DESCRIPTOR, lambda: _provider)
