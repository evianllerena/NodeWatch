"""Shared time helper."""

from __future__ import annotations

from typing import Any


def epoch_seconds(value: Any) -> float:
    """A numeric timestamp in seconds (milliseconds are recognised); 0.0 when missing or not a number."""
    if value in (None, ""):
        return 0.0
    try:
        n = float(value)
        if n > 1e12:
            n /= 1000.0
        return n
    except (TypeError, ValueError):
        return 0.0
