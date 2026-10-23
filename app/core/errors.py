"""Shared exception types."""

from __future__ import annotations


class NotConfiguredError(RuntimeError):
    """A feature was asked to act before the user configured it (a 4xx, not a 502 from the destination)."""
