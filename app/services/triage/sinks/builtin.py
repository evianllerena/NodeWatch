"""Reference sinks: a no-op (registered, shows the shape) and a recorder for tests."""

from __future__ import annotations

import threading


class NullSink:
    sink_id = "null"

    def on_event(self, event: dict) -> None:
        return None


class RecordingSink:
    """Keeps the last events it was given (tests; a template for a queueing sink)."""

    def __init__(self, sink_id: str = "recording", keep: int = 1000) -> None:
        self.sink_id = sink_id
        self.keep = keep
        self.events: list[dict] = []
        self._lock = threading.Lock()

    def on_event(self, event: dict) -> None:
        with self._lock:
            if any(e["id"] == event["id"] for e in self.events):
                return  # idempotent by event id
            self.events.append(event)
            del self.events[: -self.keep]


SINK = NullSink()
