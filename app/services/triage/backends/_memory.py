"""In-memory store for preview / sample data: never written anywhere, never offered in Settings."""

from __future__ import annotations

from pathlib import Path

from app.services.triage.base import BackendManifest, BaseBackend

MANIFEST = BackendManifest(backend_id="memory", label="Preview (in memory)", description="Sample data only.")


class MemoryBackend(BaseBackend):
    manifest = MANIFEST

    def __init__(self, settings=None, *, state_dir: Path | None = None, actor: dict) -> None:
        super().__init__(settings, state_dir=state_dir or Path("."), actor=actor)

    def append_many(self, events: list[dict]) -> None:
        self.ingest([(None, e) for e in events])

    def append_many_imported(self, events: list[dict]) -> int:
        return self.ingest([(None, e) for e in events])

    def health(self) -> dict:
        return {**super().health(), "mode": "preview"}
