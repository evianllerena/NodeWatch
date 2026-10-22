from __future__ import annotations

import random
import threading
import time
from dataclasses import dataclass
from typing import Callable, TypeVar

from app.integrations.base import IntegrationError
from app.integrations.rate_limit import REQUEST_LIMITER

T = TypeVar("T")


@dataclass(frozen=True)
class RetryPolicy:
    attempts: int = 2
    base_delay_seconds: float = 0.25
    max_delay_seconds: float = 2.0
    min_interval_seconds: float = 0.05
    timeout_budget_seconds: float = 30.0


class CircuitBreaker:
    def __init__(self, *, failure_threshold: int = 5, reset_seconds: float = 60.0) -> None:
        self.failure_threshold = max(1, failure_threshold)
        self.reset_seconds = max(1.0, reset_seconds)
        self._state: dict[str, tuple[int, float]] = {}
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        with self._lock:
            failures, opened_at = self._state.get(key, (0, 0.0))
            if failures < self.failure_threshold:
                return True
            if time.monotonic() - opened_at >= self.reset_seconds:
                self._state[key] = (0, 0.0)
                return True
            return False

    def success(self, key: str) -> None:
        with self._lock:
            self._state.pop(key, None)

    def failure(self, key: str) -> None:
        with self._lock:
            failures, opened_at = self._state.get(key, (0, 0.0))
            failures += 1
            if failures >= self.failure_threshold and not opened_at:
                opened_at = time.monotonic()
            self._state[key] = (failures, opened_at)


CIRCUIT_BREAKER = CircuitBreaker()


# Errors that retrying cannot fix (bad credentials, permissions, configuration,
# invalid input) or that already consumed the whole time budget.
NON_RETRYABLE_CODES = frozenset(
    {
        "AUTHENTICATION_FAILED",
        "PERMISSION_DENIED",
        "CONFIGURATION_ERROR",
        "NOT_CONFIGURED",
        "INVALID_QUERY",
        "INVALID_CURSOR",
        "OPERATION_TIMEOUT",
        "CAPABILITY_UNAVAILABLE",
        "SLS_NOT_CONFIGURED",
        "SLS_TOKEN_EXCHANGE_FAILED",
        "SLS_AUTHENTICATION_FAILED",
        "SLS_PERMISSION_DENIED",
        "SLS_CONFIGURATION_ERROR",
        "SLS_INVALID_PROVIDER_RESPONSE",
        "SLS_QUERY_INVALID",
        "SLS_QUERY_ENDPOINT_NOT_FOUND",
        "SLS_QUERY_TIMEOUT",
    }
)


def execute_resilient(provider_id: str, operation: Callable[[], T], *, retry: RetryPolicy | None = None) -> T:
    """Run ``operation`` with spacing, bounded retries and a circuit breaker.

    The time budget limits *starting another attempt*; a result that arrives is
    always returned, even if the attempt was slow. (Earlier versions discarded a
    successful result that exceeded the budget and then retried it.)
    """
    policy = retry or RetryPolicy()
    if not CIRCUIT_BREAKER.allow(provider_id):
        raise IntegrationError(f"Provider circuit is temporarily open: {provider_id}", code="CIRCUIT_OPEN")
    last: Exception | None = None
    started_total = time.monotonic()
    attempts = max(1, policy.attempts)
    for attempt in range(attempts):
        try:
            REQUEST_LIMITER.wait(provider_id, min_interval_seconds=policy.min_interval_seconds)
            result = operation()
            CIRCUIT_BREAKER.success(provider_id)
            return result
        except IntegrationError as exc:
            last = exc
            if exc.code in NON_RETRYABLE_CODES:
                # Configuration/permission problems say nothing about provider
                # health, so they do not trip the circuit breaker.
                break
        except Exception as exc:  # adapter boundary: normalize unexpected transport failures
            last = exc
        CIRCUIT_BREAKER.failure(provider_id)
        if attempt + 1 >= attempts:
            break
        delay = min(policy.max_delay_seconds, policy.base_delay_seconds * (2**attempt))
        if time.monotonic() - started_total + delay >= policy.timeout_budget_seconds:
            break
        time.sleep(delay + random.uniform(0, delay * 0.1))
    if isinstance(last, IntegrationError):
        raise last
    raise IntegrationError(str(last or "Provider operation failed"), code="PROVIDER_UNAVAILABLE") from last
