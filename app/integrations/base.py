from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Callable


class IntegrationError(RuntimeError):
    """Normalized provider failure used by the integration framework."""

    def __init__(self, message: str, *, code: str = "PROVIDER_UNAVAILABLE", status_code: int | None = None):
        super().__init__(message)
        self.code = code
        self.status_code = status_code


def refused_text(product: str, *, change: bool = False) -> str:
    """Plain explanation of an HTTP 403 from any connected system (v0.10.46).

    NodeWatch never decides, stores or assumes what a connection's account may do. The system answers on every
    call, so a right granted or removed there applies at once."""
    what = "this change" if change else "this request"
    return (
        f"{product} refused {what}: the account this connection signs in with is not allowed to do it. "
        f"Its rights are set in {product}, and NodeWatch follows them as they are at the moment of each call."
    )


@dataclass(frozen=True)
class ProviderDescriptor:
    provider_id: str
    display_name: str
    capabilities: tuple[str, ...]
    read_only: bool = True
    vendor: str = ""
    adapter_version: str = "1"
    query_capabilities: tuple[str, ...] = ()

    def supports(self, capability: str) -> bool:
        return capability in self.capabilities

    def supports_query(self, capability: str) -> bool:
        return capability in self.query_capabilities

    @property
    def public_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ProviderHealth:
    state: str = "disabled"
    configured: bool = False
    last_success: str = ""
    last_error: str = ""
    status_code: int | None = None
    consecutive_failures: int = 0

    def mark_success(self) -> None:
        self.state = "healthy"
        self.configured = True
        self.last_success = datetime.now(timezone.utc).isoformat()
        self.last_error = ""
        self.status_code = 200
        self.consecutive_failures = 0

    last_error_at: str = ""

    def mark_error(self, message: str, *, status_code: int | None = None, state: str = "degraded") -> None:
        self.state = state
        self.last_error = str(message or "")[:500]
        self.last_error_at = datetime.now(timezone.utc).isoformat()
        self.status_code = status_code
        self.consecutive_failures += 1

    def seconds_since_success(self) -> float | None:
        if not self.last_success:
            return None
        try:
            return (datetime.now(timezone.utc) - datetime.fromisoformat(self.last_success)).total_seconds()
        except ValueError:
            return None

    @property
    def intermittent(self) -> bool:
        """v0.10.23: a sporadic failure (DNS hiccup, one timeout) between successful calls.

        The connection is shown as connected with a note instead of "Error" - before, the last
        call's result alone decided the badge, so one failed lookup left the card red until the
        connection was edited and saved again.
        """
        since = self.seconds_since_success()
        return since is not None and since < 600 and self.consecutive_failures < 3

    @property
    def public_dict(self) -> dict[str, Any]:
        return asdict(self)


class ProviderAdapter(ABC):
    """Stable contract for every external NodeWatch data provider.

    UI and feature modules must consume NodeWatch service/query interfaces rather than
    vendor APIs directly. Adapters own authentication, capability declaration,
    translation and provider-specific health details.
    """

    descriptor: ProviderDescriptor

    @property
    @abstractmethod
    def configured(self) -> bool:
        raise NotImplementedError

    @property
    def provider_id(self) -> str:
        return self.descriptor.provider_id

    def capabilities(self) -> tuple[str, ...]:
        return self.descriptor.capabilities

    def supports(self, capability: str) -> bool:
        return self.descriptor.supports(capability)

    def supports_query(self, capability: str) -> bool:
        return self.descriptor.supports_query(capability)

    def health_state(self) -> ProviderHealth:
        state = ProviderHealth(configured=self.configured)
        state.state = "unknown" if self.configured else "disabled"
        return state

    def test_connection(self) -> dict[str, Any]:
        return {"ok": self.configured, "provider": self.provider_id, "configured": self.configured}

    def diagnostics(self) -> dict[str, Any]:
        return {
            "provider": self.provider_id,
            "configured": self.configured,
            "capabilities": list(self.capabilities()),
            "health": self.health_state().public_dict,
        }

    def cache_policy(self, capability: str) -> tuple[str, float | None]:
        """Return the central cache tier and optional TTL for a query capability."""
        return ("hot", None)

    def query(self, query: Any) -> Any:
        raise IntegrationError(
            f"Provider {self.provider_id} does not implement the generic query operation",
            code="UNSUPPORTED_QUERY",
        )


class ProviderRegistry:
    """Lazy validated provider registry.

    Factories are intentionally lazy and network-free at import time. New vendors are
    registered here, while feature modules discover providers by capability.
    """

    def __init__(self) -> None:
        self._factories: dict[str, Callable[[], ProviderAdapter]] = {}
        self._descriptors: dict[str, ProviderDescriptor] = {}

    def register(self, descriptor: ProviderDescriptor, factory: Callable[[], ProviderAdapter]) -> None:
        provider_id = str(descriptor.provider_id or "").strip()
        if not provider_id:
            raise ValueError("provider_id cannot be empty")
        if provider_id in self._descriptors and self._descriptors[provider_id] != descriptor:
            raise ValueError(f"Conflicting provider registration: {provider_id}")
        self._descriptors[provider_id] = descriptor
        self._factories[provider_id] = factory

    def descriptor(self, provider_id: str) -> ProviderDescriptor | None:
        return self._descriptors.get(provider_id)

    def get(self, provider_id: str) -> ProviderAdapter | None:
        factory = self._factories.get(provider_id)
        if not factory:
            return None
        instance = factory()
        if not isinstance(instance, ProviderAdapter):
            raise TypeError(f"Provider factory {provider_id} did not return ProviderAdapter")
        return instance

    def descriptors(self) -> list[dict[str, Any]]:
        return [x.public_dict for x in sorted(self._descriptors.values(), key=lambda d: d.provider_id)]

    def providers_for(
        self, capability: str, *, configured_only: bool = False, query_only: bool = False
    ) -> list[ProviderAdapter]:
        out: list[ProviderAdapter] = []
        for descriptor in self._descriptors.values():
            if query_only and not descriptor.supports_query(capability):
                continue
            if not query_only and not descriptor.supports(capability):
                continue
            provider = self.get(descriptor.provider_id)
            if provider is None or (configured_only and not provider.configured):
                continue
            out.append(provider)
        return out


registry = ProviderRegistry()
