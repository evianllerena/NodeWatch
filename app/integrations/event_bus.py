from __future__ import annotations

import threading
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable


@dataclass(frozen=True)
class NodeWatchEvent:
    event_type: str
    payload: dict[str, Any]
    provider_id: str = "nodewatch"
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class EventBus:
    def __init__(self, *, history_limit: int = 2000) -> None:
        self._subscribers: dict[str, list[Callable[[NodeWatchEvent], None]]] = defaultdict(list)
        self._history: deque[NodeWatchEvent] = deque(maxlen=history_limit)
        self._lock = threading.RLock()

    def subscribe(self, event_type: str, callback: Callable[[NodeWatchEvent], None]) -> Callable[[], None]:
        with self._lock:
            self._subscribers[event_type].append(callback)

        def unsubscribe() -> None:
            with self._lock:
                callbacks = self._subscribers.get(event_type, [])
                if callback in callbacks:
                    callbacks.remove(callback)

        return unsubscribe

    def publish(self, event: NodeWatchEvent) -> list[str]:
        with self._lock:
            self._history.append(event)
            callbacks = list(self._subscribers.get(event.event_type, [])) + list(self._subscribers.get("*", []))
        errors: list[str] = []
        for callback in callbacks:
            try:
                callback(event)
            except Exception as exc:
                errors.append(str(exc)[:300])
        return errors

    def recent(self, *, limit: int = 100, event_type: str | None = None) -> list[NodeWatchEvent]:
        with self._lock:
            rows = list(self._history)
        if event_type:
            rows = [x for x in rows if x.event_type == event_type]
        return rows[-max(1, min(limit, 1000)) :]


EVENT_BUS = EventBus()
