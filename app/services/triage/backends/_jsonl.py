"""Shared base for stores made of JSON-lines event logs in a folder (local and shared folder)."""

from __future__ import annotations

from pathlib import Path

from app.services.triage.base import BaseBackend, ReadOnlyError
from app.services.triage.events import writer_id
from app.services.triage.logfiles import FolderReader, LogFullError, SegmentedWriter, encode


class JsonlFolderBackend(BaseBackend):
    def _open_logs(self, folder: Path, segment_state: Path, *, verify_owner: bool = False) -> None:
        """``verify_owner``: shared folders only — bind each log file to its Windows owner (v0.10.22)."""
        self.log_folder = Path(folder)
        self.writer_name = writer_id(self.actor)
        self.writer = SegmentedWriter(self.log_folder, self.writer_name, state_file=segment_state, verify_owner=verify_owner)
        self.reader = FolderReader(self.log_folder, verify_owner=verify_owner)

    def _write_lines(self, events: list[dict]) -> None:
        try:
            self.writer.append([encode(e) for e in events])
        except LogFullError as exc:
            raise ReadOnlyError(str(exc)) from exc

    def _read(self, *, check_writer: bool) -> int:
        items = self.reader.read_new()
        return self.ingest([(w if check_writer else None, raw, loc) for w, raw, loc in items])

    def _rewind(self, loc: tuple) -> None:
        self.reader.rewind(*loc)

    def mine(self, event: dict) -> bool:
        return writer_id(event["actor"]) == self.writer_name

    def health(self) -> dict:
        h = super().health()
        st = self.reader.stats
        h.update(
            skipped_lines=st.skipped,
            oversized_files=list(st.oversized_files),
            ignored_files=st.ignored_files,
            ignored_writers=st.ignored_writers,
            foreign_files=st.foreign_files,
            unverified_files=st.unverified_files,
            ignored_segments=st.ignored_segments,
            backlog=st.backlog,
        )
        return h
