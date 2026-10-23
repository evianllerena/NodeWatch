"""``local`` — triage kept on this PC only (the default; what every NodeWatch before v0.10.18 did).

Data (in the NodeWatch data folder, ``state/``):

* ``attention_state.events/<machine>-<user>.0001.jsonl`` — the append-only event log (the truth).
* ``attention_state.json`` — a snapshot of the folded state in the pre-v0.10.18 shape (``alerts`` /
  ``mutes`` + ``"format": 2``), rewritten after each change. Older NodeWatch versions can still read it.
* ``attention_state.v1-backup.json`` — the original pre-v0.10.18 file, kept untouched by the migration.

Migration: on first start, every record of an old ``attention_state.json`` becomes one event with the
record's own timestamp and fields (acknowledged → ``ack``, snoozed → ``snooze`` with ``until`` /
``until_change`` / ``duration``, dismissed → ``dismiss`` with its reason, each mute rule → ``mute``),
authored by the current Windows user and flagged ``migrated``. Nothing is lost: the original file is
copied to the backup first, and migration never runs again once the event log has events.
"""

from __future__ import annotations

import json
import shutil
import time
import uuid
from pathlib import Path

from app.core.file_utils import write_private_text
from app.services.triage.store import legacy_via
from app.services.triage.backends._jsonl import JsonlFolderBackend
from app.services.triage.base import BackendManifest
from app.services.triage.events import DURATIONS, EventError, validate_event

SNAPSHOT_FORMAT = 2

MANIFEST = BackendManifest(
    backend_id="local",
    label="Only this PC",
    description="Acknowledgements, snoozes, dismissals, mutes, notes and assignments are kept on this PC. "
    "Teammates do not see them (except acknowledgements written to the source, such as Mist).",
    shared=False,
    order=10,
)


def _via(by: str) -> str:
    by = str(by or "")
    if via := legacy_via(by):
        return via
    if by.startswith("NodeWatch"):
        return "NodeWatch"
    return by[:60]


class LocalBackend(JsonlFolderBackend):
    manifest = MANIFEST

    def __init__(self, settings=None, *, state_dir: Path, actor: dict, legacy_path: Path | None = None) -> None:
        super().__init__(settings, state_dir=state_dir, actor=actor)
        self.legacy_path = Path(legacy_path) if legacy_path else self.state_dir / "attention_state.json"
        self.backup_path = self.legacy_path.with_name(self.legacy_path.stem + ".v1-backup.json")
        self.legacy_path.parent.mkdir(parents=True, exist_ok=True)
        self._open_logs(
            self.legacy_path.with_name(self.legacy_path.stem + ".events"),
            self.legacy_path.with_name(self.legacy_path.stem + ".segment.json"),
        )
        self._read(check_writer=False)
        self.migrated = self._migrate()
        self.last_sync = time.time()

    # ------------------------------------------------------------------ migration
    def _migrate(self) -> int:
        if self.fold.events:
            return 0
        try:
            data = json.loads(self.legacy_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return 0
        if not isinstance(data, dict) or data.get("format") == SNAPSHOT_FORMAT:
            return 0
        if not self.backup_path.exists():
            shutil.copy2(self.legacy_path, self.backup_path)
        events = []
        now = time.time()
        for key, rec in (data.get("alerts") or {}).items():
            ev = self._legacy_record_event(str(key), rec, now)
            if ev:
                events.append(ev)
        for rid, rule in (data.get("mutes") or {}).items():
            ev = self._legacy_mute_event(str(rid), rule, now)
            if ev:
                events.append(ev)
        if events:
            self.append_many(events)
        else:
            self._write_snapshot()
        return len(events)

    def _base(self, ts, now: float) -> dict:
        try:
            ts = float(ts)
        except (TypeError, ValueError):
            ts = now
        if not (0 < ts <= now):
            ts = now
        return {"id": uuid.uuid4().hex, "ts": ts, "seq": self.next_seq(), "actor": self.actor, "version": 1}

    def _legacy_record_event(self, key: str, rec, now: float) -> dict | None:
        if not isinstance(rec, dict):
            return None
        state = rec.get("state")
        fields: dict = {"migrated": True}
        if state == "acknowledged":
            action = "ack"
            fields["via"] = _via(rec.get("by"))
        elif state == "snoozed":
            action = "snooze"
            fields.update(
                until=rec.get("until") or None,
                until_change=str(rec.get("until_change") or "")[:64],
                duration=rec.get("duration") if rec.get("duration") in DURATIONS else "",
            )
        elif state == "dismissed":
            action = "dismiss"
            fields["reason"] = str(rec.get("reason") or "Dismissed")[:200]
        else:
            return None
        context = {
            k: str(rec.get(k) or "")[:200]
            for k in ("title", "type", "source", "site_name", "device_name")
            if rec.get(k)
        }
        raw = {
            **self._base(rec.get("at"), now),
            "action": action,
            "target_kind": "alert",
            "target": key,
            "fields": {k: v for k, v in fields.items() if v not in (None, "")},
            "context": context,
            "source_vendor": str(rec.get("source") or "")[:40],
        }
        try:
            return validate_event(raw, now=now, strict=False)
        except EventError:
            return None

    def _legacy_mute_event(self, rid: str, rule, now: float) -> dict | None:
        if not isinstance(rule, dict):
            return None
        fields = {
            "type": str(rule.get("type") or "")[:120],
            "label": str(rule.get("label") or "")[:120],
            "source": str(rule.get("source") or "")[:40],
            "site_key": str(rule.get("site_key") or "")[:64],
            "site_name": str(rule.get("site_name") or "")[:120],
            "reason": str(rule.get("reason") or "")[:200],
            "until": rule.get("until") or None,
            "migrated": True,
        }
        raw = {
            **self._base(rule.get("created_at"), now),
            "action": "mute",
            "target_kind": "mute",
            "target": rid,
            "fields": {k: v for k, v in fields.items() if v not in (None, "")},
            "source_vendor": fields["source"],
        }
        try:
            return validate_event(raw, now=now, strict=False)
        except EventError:
            return None

    # ------------------------------------------------------------------ writing
    def append_many(self, events: list[dict]) -> None:
        if not events:
            return
        with self.lock:
            self._write_lines(events)
            self.ingest([(None, e) for e in events])
            self._write_snapshot()

    def append_many_imported(self, events: list[dict]) -> int:
        new = [e for e in events if e["id"] not in self.fold.events]
        self.append_many(new)
        return len(new)

    def _write_snapshot(self) -> None:
        snap = self.fold.snapshot()
        write_private_text(
            self.legacy_path,
            json.dumps(
                {
                    "format": SNAPSHOT_FORMAT,
                    "note": "Snapshot of the NodeWatch triage event log (attention_state.events). Do not edit.",
                    "alerts": snap["alerts"],
                    "mutes": snap["mutes"],
                },
                indent=1,
            ),
        )

    def describe(self) -> dict:
        return {**super().describe(), "location": str(self.log_folder)}

    def health(self) -> dict:
        h = super().health()
        h.update(mode="local", migrated=self.migrated, location=str(self.log_folder))
        return h


BACKEND = LocalBackend
