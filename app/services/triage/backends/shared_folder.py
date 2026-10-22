"""``shared_folder`` — team triage through a Windows file share, with no server and no file locking.

Layout of the shared folder (e.g. ``\\\\fileserver\\NodeWatch\\triage``)::

    README-NodeWatch-triage.txt         what this folder is (written once, best effort)
    logs\\<machine>~<user>.0001.jsonl     one append-only event log per user and PC
    logs\\<machine>~<user>.0002.jsonl     … next segment after 2 MB

Conflict-free by construction:

* Each NodeWatch writes **only its own** log file (one complete line per write, flush + fsync), so two
  people never write the same file and SMB oplocks / locking never come into play.
* Every NodeWatch reads **all** logs incrementally (byte offset per file) and folds them with
  last-writer-wins per alert (:mod:`app.services.triage.fold`), so all PCs converge on the same state.
* An event found in ``bob``'s file that claims to be from ``alice`` is ignored.
* Undo is a compensating event (e.g. ``restore`` after ``dismiss``), never an edit of history.

Offline: when the share cannot be reached, new events go to a local outbox (``state/triage-shared-…/
outbox.jsonl``), are shown at once, and are written to the share on the next successful sync.
Read-only: when the user may read but not write the folder, NodeWatch shows teammates' triage and
refuses new actions with a clear message (switch to "Only this PC" or ask for write access).

Privacy: the files are plain JSON. Anyone who can open the share can read who acknowledged, snoozed,
dismissed, muted, assigned or commented what, and when. They never contain tokens or passwords.
"""

from __future__ import annotations

import errno
import hashlib
import json
import os
import time
import uuid
from pathlib import Path

from app.integrations.connectors.sdk import SettingField
from app.services.triage.backends._jsonl import JsonlFolderBackend
from app.services.triage.base import BackendManifest, ReadOnlyError
from app.services.triage.events import EventError, safe_name, validate_event, writer_id, writer_matches
from app.services.triage import logfiles, ownership
from app.services.triage.logfiles import FILE_RE, encode
from app.services.triage.paths import validate_folder_path

SYNC_MIN_INTERVAL_S = 3.0
OUTBOX_MAX_EVENTS = 20_000
README = """NodeWatch shared triage folder
==============================

NodeWatch writes one append-only log per user and PC under logs\\ (<machine>~<user>.NNNN.jsonl).
Each NodeWatch only appends to its own file and reads everyone else's. Do not edit the files.

The files are plain JSON: anyone who can read this share can see who acknowledged, snoozed,
dismissed, muted, assigned or commented on which alert, and when. They never contain passwords or
API tokens. NodeWatch (v0.10.22+) reads a log file only when its Windows owner is the user named
in the file name, so creating a file under someone else's name does not work. Shares that map all
users to one account ("force user") cannot keep owners, so NodeWatch turns the check off there
(Settings shows "Identity checks: OFF"); share administrators can always forge entries. Recommended: NOC group "Modify" on "This folder only", "CREATOR OWNER" Full control on
"Subfolders and files only", no other write access, no "force user" mapping.
"""

MANIFEST = BackendManifest(
    backend_id="shared_folder",
    label="Shared folder",
    description="Everyone points NodeWatch at the same Windows file share. Each PC writes only its own "
    "append-only log there and reads everyone else's, so the team sees who acknowledged, snoozed, "
    "dismissed, assigned or commented on each incident. Works offline and catches up later.",
    settings=(
        SettingField(
            key="path",
            label="Shared folder",
            type="text",
            required=True,
            placeholder="\\\\fileserver\\NodeWatch\\triage",
            help="A UNC path or mapped drive every NOC engineer can read and write.",
            address=True,
        ),
    ),
    shared=True,
    maturity="preview",
    order=20,
)


def _offline_error(exc: OSError) -> bool:
    return not isinstance(exc, PermissionError) and getattr(exc, "errno", None) not in (errno.EACCES, errno.EPERM)


class SharedFolderBackend(JsonlFolderBackend):
    manifest = MANIFEST

    def __init__(self, settings=None, *, state_dir: Path, actor: dict) -> None:
        super().__init__(self.clean_settings(settings or {}), state_dir=state_dir, actor=actor)
        self.root = Path(self.settings["path"])
        digest = hashlib.sha1(str(self.root).lower().encode("utf-8")).hexdigest()[:12]
        self.cache_dir = self.state_dir / f"triage-shared-{digest}"
        # Owner verification starts off and is switched on by _calibrate_owner_check() once this
        # share is known to preserve file owners.
        self.owner_check = "pending"
        self._open_logs(self.root / "logs", self.cache_dir / "segment.json", verify_owner=False)
        self.outbox_path = self.cache_dir / "outbox.jsonl"
        self.mode = "unknown"  # ok | offline | read_only | error
        self.read_only = False
        self.probed = False
        self._next_sync = 0.0
        self.ingest([(None, e) for e in self._load_outbox()])
        self.sync(force=True)

    # ------------------------------------------------------------------ settings
    @classmethod
    def clean_settings(cls, values: dict) -> dict:
        return {"path": validate_folder_path((values or {}).get("path"))}

    @classmethod
    def test_settings(cls, values: dict, *, actor: dict) -> dict:
        """Write a probe file, read it back, delete it; report read-only and what is already there."""
        root = Path(cls.clean_settings(values)["path"])
        if not root.is_dir():
            return {"ok": False, "message": f"Folder not found or the share is not reachable: {root}"}
        logs = root / "logs"
        try:
            names = os.listdir(logs) if logs.is_dir() else []
        except OSError as exc:
            return {"ok": False, "message": f"Cannot list the folder: {exc.strerror or exc}"}
        writers = sorted({m.group("writer") for n in names if (m := FILE_RE.match(n))})
        probe = logs / f".probe-{writer_id(actor)}-{uuid.uuid4().hex[:8]}.tmp"
        token = uuid.uuid4().hex.encode()
        try:
            logs.mkdir(exist_ok=True)
            logfiles.append_bytes(probe, token)
            ok = probe.read_bytes() == token
        except PermissionError:
            return {
                "ok": True,
                "read_only": True,
                "writers": writers,
                "message": "You can read this folder but not write to it. NodeWatch would show your team's "
                "triage but could not save yours. Ask for Modify permission, or keep 'Only this PC'.",
            }
        except OSError as exc:
            return {"ok": False, "message": f"Could not write a test file: {exc.strerror or exc}"}
        finally:
            try:
                probe.unlink()
            except OSError:
                pass
        if not ok:
            return {"ok": False, "message": "Wrote a test file but read back something else — check the share."}
        others = [w for w in writers if not writer_matches(actor, w)]
        return {
            "ok": True,
            "read_only": False,
            "writers": writers,
            "message": "Read and write OK."
            + (
                f" {len(others)} other NodeWatch user(s) already use this folder."
                if others
                else " No one else uses it yet."
            ),
        }

    # ------------------------------------------------------------------ outbox (offline queue)
    def _load_outbox(self) -> list[dict]:
        out = []
        try:
            lines = self.outbox_path.read_bytes().splitlines()
        except OSError:
            return out
        for line in lines[-OUTBOX_MAX_EVENTS:]:
            try:
                out.append(validate_event(json.loads(line), strict=False, now=time.time() + 10**9))
            except (ValueError, EventError):
                continue
        return out

    def _queue(self, events: list[dict]) -> None:
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        if self.pending() + len(events) > OUTBOX_MAX_EVENTS:
            raise ReadOnlyError("The shared folder has been unreachable for too long; the offline queue is full.")
        logfiles.append_bytes(self.outbox_path, b"".join(encode(e) for e in events))

    def pending(self) -> int:
        try:
            return sum(1 for line in self.outbox_path.read_bytes().splitlines() if line.strip())
        except OSError:
            return 0

    def _flush_outbox(self) -> None:
        queued = self._load_outbox()
        if not queued:
            return
        self._write_lines(queued)  # may raise OSError: the outbox stays
        try:
            self.outbox_path.unlink()
        except OSError:
            pass

    # ------------------------------------------------------------------ sync
    def _calibrate_owner_check(self) -> None:
        """Decide whether this share preserves file owners (v0.10.22).

        Creates a throw-away file and reads its owner back. Only when the owner is this PC's own
        account is the owner check enforced. Shares that map everyone to one account (NAS "force
        user"), Samba unix SIDs, or owners that cannot be resolved turn the check off for this
        folder — reported as ``owner_check: unavailable`` — instead of hiding every teammate.
        """
        logs = self.log_folder
        probe = logs / f".owner-probe-{uuid.uuid4().hex}.tmp"
        try:
            logs.mkdir(exist_ok=True)
            with open(probe, "xb"):
                pass
            owner = ownership.file_owner(probe)
        except OSError:
            owner = ""  # read-only or unreachable: cannot calibrate (ensure() reports the reason)
        finally:
            try:
                probe.unlink()
            except OSError:
                pass
        if owner and safe_name(owner).lower() == safe_name(ownership.current_account()).lower():
            self.owner_check = "enforced"
        else:
            self.owner_check = "not_applicable" if owner is None else "unavailable"
        enforce = self.owner_check == "enforced"
        self.writer.verify_owner = enforce
        self.reader.verify_owner = enforce

    def _probe(self) -> None:
        if self.probed:
            return
        try:
            self._calibrate_owner_check()
            self.writer.ensure()
            self.read_only = False
            try:
                readme = self.root / "README-NodeWatch-triage.txt"
                if not readme.exists():
                    readme.write_text(README, encoding="utf-8")
            except OSError:
                pass
        except PermissionError:
            self.read_only = True
        self.probed = True

    def sync(self, force: bool = False) -> None:
        now = time.time()
        with self.lock:
            if not force and now < self._next_sync:
                return
            self._next_sync = now + SYNC_MIN_INTERVAL_S
            try:
                if not self.root.is_dir():
                    raise FileNotFoundError(errno.ENOENT, "shared folder not reachable", str(self.root))
                self._probe()
                if not self.read_only:
                    self._flush_outbox()
                self._read(check_writer=True)
                self.mode = "read_only" if self.read_only else "ok"
                self.last_sync = now
                self.last_error = ""
            except PermissionError as exc:
                if self.probed and not self.read_only:
                    self.read_only = True
                    self.mode = "read_only"
                else:
                    self.mode = "error"
                self.last_error = f"No permission: {exc.strerror or exc}"
            except OSError as exc:
                self.mode = "offline"
                self.probed = False  # probe again when the share is back
                self.last_error = f"Shared folder not reachable: {exc.strerror or exc}"

    # ------------------------------------------------------------------ writing
    @property
    def writable(self) -> bool:
        return not self.read_only

    def _read_only_error(self) -> ReadOnlyError:
        return ReadOnlyError(
            "The shared triage folder is read-only for your Windows account, so this action was not saved. "
            "Ask for Modify permission on the folder, or switch Settings › Team triage to 'Only this PC'."
        )

    def append_many(self, events: list[dict]) -> None:
        if not events:
            return
        with self.lock:
            if self.read_only:
                raise self._read_only_error()
            try:
                if self.mode == "offline" or self.pending():
                    if not self.root.is_dir():
                        raise FileNotFoundError(errno.ENOENT, "shared folder not reachable")
                    self._probe()
                    if self.read_only:
                        raise self._read_only_error()
                    self._flush_outbox()
                self._write_lines(events)
                self.mode = "ok"
            except PermissionError as exc:
                self.read_only = True
                self.mode = "read_only"
                raise self._read_only_error() from exc
            except OSError as exc:
                if not _offline_error(exc):
                    raise
                self._queue(events)
                self.mode = "offline"
                self.last_error = (
                    f"Shared folder not reachable — saved on this PC, will sync later ({exc.strerror or exc})"
                )
            self.ingest([(None, e) for e in events])

    def append_many_imported(self, events: list[dict]) -> int:
        mine = [e for e in events if self.mine(e) and e["id"] not in self.fold.events]
        self.append_many(mine)
        return len(mine)

    # ------------------------------------------------------------------ status
    def describe(self) -> dict:
        return {**super().describe(), "location": str(self.root)}

    def health(self) -> dict:
        h = super().health()
        try:
            files = len(self.reader.offsets)
        except Exception:  # noqa: BLE001
            files = 0
        h.update(
            mode=self.mode,
            location=str(self.root),
            files=files,
            read_only=self.read_only,
            owner_check=getattr(self, "owner_check", "pending"),
        )
        return h


BACKEND = SharedFolderBackend
