"""Append-only JSON-lines event logs: one writer per file, any number of readers.

File names: ``<writer>.<segment:04d>.jsonl`` where ``<writer>`` is ``<machine>~<user>``. (Pre-release
``<machine>-<user>`` names are no longer read since v0.10.22: nobody writes them, so anyone could
create one under a teammate's name.) A writer only ever appends to its own
current segment (one ``write`` of one complete line, then flush + fsync) and
starts the next segment when the current one reaches :data:`ROTATE_BYTES`. Files are never renamed or
rewritten, so readers on other PCs can keep a byte offset per file and read only what is new — this is
what makes the design safe on SMB shares without any file locking.

Readers consume complete lines only (a line still being written has no trailing newline yet), skip
lines that are too long or not valid JSON, never read more than :data:`MAX_READ_BYTES` of one file and
start again from 0 when a file got shorter (restored from backup / replaced).

Abuse limits (someone with write access to the share creating junk): a writer remembers its own
segment number on this PC and only ever moves forward one segment at a time, so a teammate creating
``alice's .0500`` cannot block Alice; readers ignore segment numbers above :data:`MAX_SEGMENTS`, read at
most :data:`MAX_FILES` files of :data:`MAX_WRITERS` writers, and at most :data:`MAX_SYNC_BYTES` /
:data:`MAX_SYNC_LINES` per sync (the rest is read on the next sync). Everything skipped is counted.

Identity (v0.10.22, shared folders): a file is read only when its Windows owner is the user its name
claims (see ownership.py); files someone created under another person's name are skipped and
counted. Writers are kept most-recently-active first, at most :data:`MAX_MACHINES_PER_USER` machines
per user, so junk files can no longer push real teammates out of the :data:`MAX_WRITERS` cap. A writer
never appends to a segment file someone else created; it moves on to the next free number.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from app.services.triage.events import MAX_LINE_BYTES, safe_name
from app.services.triage.ownership import current_account, file_owner
from app.core.file_utils import write_private_text

ROTATE_BYTES = 2 * 1024 * 1024
MAX_READ_BYTES = 8 * 1024 * 1024  # per file; a writer never makes one this big
MAX_SEGMENTS = 500  # per writer (≈ 1 GB): beyond this the writer stops and says so
MAX_FILES = 5000  # files considered per folder
MAX_WRITERS = 500  # distinct writers considered per folder (most recently active first)
MAX_MACHINES_PER_USER = 8  # writers (machines) considered per user name
MAX_SYNC_BYTES = 32 * 1024 * 1024  # read per sync; the rest next time
MAX_SYNC_LINES = 200_000
FILE_RE = re.compile(r"^(?P<writer>(?P<machine>[a-z0-9._\-]{1,64})~(?P<user>[a-z0-9._\-]{1,64}))\.(?P<seg>\d{4})\.jsonl$")


class LogFullError(OSError):
    """This writer used all its segments."""


# Seams for tests (read-only shares, unreachable servers): every byte written goes through these.
def append_bytes(path: Path, data: bytes) -> None:
    with open(path, "ab") as fh:
        fh.write(data)
        fh.flush()
        os.fsync(fh.fileno())


def touch(path: Path) -> None:
    with open(path, "ab"):
        pass


def encode(event: dict) -> bytes:
    line = json.dumps(event, separators=(",", ":"), ensure_ascii=False, sort_keys=True).encode("utf-8") + b"\n"
    if len(line) > MAX_LINE_BYTES:
        raise ValueError("event is too large")
    return line


class SegmentedWriter:
    """Appends to ``<writer>.<NNNN>.jsonl``. ``state_file`` (on this PC) remembers the segment in use."""

    def __init__(self, folder: Path, writer: str, state_file: Path | None = None, *, verify_owner: bool = False) -> None:
        self.folder = Path(folder)
        self.writer = writer
        self.state_file = Path(state_file) if state_file else None
        self.verify_owner = verify_owner
        self._segment: int | None = None
        self._size = 0

    def _foreign(self, seg: int) -> bool:
        """True when segment ``seg`` exists and was created by another account (shared folders)."""
        if not self.verify_owner:
            return False
        path = self.folder / self._name(seg)
        if not path.exists():
            return False
        owner = file_owner(path)
        if not owner:  # unknown (or an administrator's): trust our own segment counter
            return False
        return safe_name(owner).lower() != safe_name(current_account()).lower()

    def _usable(self, seg: int) -> int:
        """``seg`` or the next segment number that nobody else created first."""
        while seg < MAX_SEGMENTS and self._foreign(seg):
            seg += 1
        return seg

    def _saved_segment(self) -> int:
        if not self.state_file:
            return 1
        try:
            seg = int(json.loads(self.state_file.read_text(encoding="utf-8")).get(self.writer, 1))
        except (OSError, ValueError, TypeError, AttributeError):
            return 1
        return seg if 1 <= seg <= MAX_SEGMENTS else 1

    def _save_segment(self) -> None:
        if not self.state_file:
            return
        try:
            data = json.loads(self.state_file.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                data = {}
        except (OSError, ValueError):
            data = {}
        data[self.writer] = self._segment
        try:
            self.state_file.parent.mkdir(parents=True, exist_ok=True)
            write_private_text(self.state_file, json.dumps(data))  # atomic (v0.10.40)
        except OSError:
            pass

    def _seg_size(self, seg: int) -> int:
        try:
            return (self.folder / self._name(seg)).stat().st_size
        except OSError:
            return 0

    def _discover(self) -> None:
        """Start at the segment this PC last used and move forward only past *full* segments, one by
        one. Never jump to whatever high number exists on the share (anyone could create it)."""
        seg = self._usable(self._saved_segment())
        while seg < MAX_SEGMENTS and self._seg_size(seg) >= ROTATE_BYTES:
            seg = self._usable(seg + 1)
        self._segment = seg
        self._size = self._seg_size(seg)
        self._save_segment()

    def _name(self, seg: int) -> str:
        return f"{self.writer}.{seg:04d}.jsonl"

    @property
    def current_path(self) -> Path:
        if self._segment is None:
            self._discover()
        return self.folder / self._name(self._segment or 1)

    def ensure(self) -> Path:
        """Create the folder and our current segment (empty) — the writability probe.

        Only the last folder level is created: a missing share root must fail (offline), never be
        re-created as a local folder."""
        self.folder.mkdir(exist_ok=True)
        path = self.current_path
        touch(path)
        return path

    def append(self, lines: list[bytes]) -> None:
        if self._segment is None:
            self._discover()
        self.folder.mkdir(exist_ok=True)
        batch: list[bytes] = []
        for line in lines:
            if self._size and self._size + sum(map(len, batch)) + len(line) > ROTATE_BYTES:
                if batch:
                    self._write(batch)
                    batch = []
                if (self._segment or 1) >= MAX_SEGMENTS:
                    raise LogFullError("This user's triage log is full; archive old segments to continue")
                self._segment = self._usable((self._segment or 1) + 1)
                self._size = self._seg_size(self._segment)
                self._save_segment()
            batch.append(line)
        if batch:
            self._write(batch)

    def _write(self, batch: list[bytes]) -> None:
        data = b"".join(batch)
        append_bytes(self.folder / self._name(self._segment or 1), data)
        self._size += len(data)


@dataclass
class ReadStats:
    lines: int = 0
    skipped: int = 0  # malformed, too long or invalid events
    oversized_files: list[str] = field(default_factory=list)
    ignored_segments: int = 0  # segment number above MAX_SEGMENTS
    ignored_files: int = 0  # beyond MAX_FILES
    ignored_writers: int = 0  # beyond MAX_WRITERS or MAX_MACHINES_PER_USER
    foreign_files: int = 0  # file name claims a user who does not own the file (skipped)
    unverified_files: int = 0  # owner could not be determined (read, but identity unproven)
    backlog: bool = False  # last sync hit the per-sync byte/line budget; more is read next time


class FolderReader:
    """Incremental reader of every ``*.jsonl`` log in a folder (byte offset per file)."""

    def __init__(self, folder: Path, *, verify_owner: bool = False) -> None:
        self.folder = Path(folder)
        self.offsets: dict[str, int] = {}
        self.stats = ReadStats()
        self.verify_owner = verify_owner
        self._owners: dict[str, str | None] = {}  # file name -> owner (an owner never changes without admin rights)

    def _owner_ok(self, name: str, user: str) -> bool | None:
        """True: owner is that user · False: someone else · None: owner unknown."""
        if name not in self._owners:
            self._owners[name] = file_owner(self.folder / name)
        owner = self._owners[name]
        if not owner:
            return None
        return safe_name(owner).lower() == user

    def files(self) -> list[tuple[str, str]]:
        """[(file name, writer)] sorted, within the caps — raises OSError when the folder cannot be listed."""
        out = []
        bad_seg = foreign = unverified = 0
        recent: dict[str, float] = {}  # writer -> newest file mtime
        for entry in os.scandir(self.folder):
            m = FILE_RE.match(entry.name)
            if not m or not entry.is_file():
                continue
            if not 1 <= int(m.group("seg")) <= MAX_SEGMENTS:
                bad_seg += 1
                continue
            writer = m.group("writer")
            if self.verify_owner:
                verdict = self._owner_ok(entry.name, m.group("user"))
                if verdict is False:
                    foreign += 1
                    continue
                if verdict is None and os.name == "nt":
                    unverified += 1
            try:
                mtime = entry.stat().st_mtime
            except OSError:
                mtime = 0.0
            recent[writer] = max(recent.get(writer, 0.0), mtime)
            out.append((entry.name, writer))
        out.sort()
        # Most recently active writers first; at most MAX_MACHINES_PER_USER machines per user name,
        # so nobody can crowd real teammates out of the cap with junk names (v0.10.22).
        per_user: dict[str, int] = {}
        allowed: set[str] = set()
        for writer in sorted(recent, key=lambda w: (-recent[w], w)):
            user = writer.split("~", 1)[1]
            if per_user.get(user, 0) >= MAX_MACHINES_PER_USER or len(allowed) >= MAX_WRITERS:
                continue
            per_user[user] = per_user.get(user, 0) + 1
            allowed.add(writer)
        kept = [x for x in out if x[1] in allowed]
        self.stats.ignored_segments = bad_seg
        self.stats.foreign_files = foreign
        self.stats.unverified_files = unverified
        self.stats.ignored_writers = len(recent) - len(allowed)
        self.stats.ignored_files = max(0, len(kept) - MAX_FILES) + (len(out) - len(kept))
        return kept[:MAX_FILES]

    def rewind(self, name: str, offset: int) -> None:
        """Read ``name`` again from ``offset`` next time (events that could not be kept yet)."""
        if name in self.offsets:
            self.offsets[name] = min(self.offsets[name], offset)

    def read_new(self) -> list[tuple[str, dict, tuple[str, int]]]:
        """[(writer, raw event dict, (file, line offset))] appended since the last call (within the
        per-sync budget). Raises OSError if the folder is gone."""
        out: list[tuple[str, dict, tuple[str, int]]] = []
        try:
            names = self.files()
        except FileNotFoundError:
            return out
        budget = MAX_SYNC_BYTES
        self.stats.backlog = False
        for name, writer in names:
            if budget <= 0 or len(out) >= MAX_SYNC_LINES:
                self.stats.backlog = True
                break
            path = self.folder / name
            try:
                size = path.stat().st_size
            except OSError:
                continue
            offset = self.offsets.get(name, 0)
            if size < offset:  # replaced or truncated: read again (duplicates are ignored by id)
                offset = 0
            limit = min(size, MAX_READ_BYTES, offset + budget)
            if limit < min(size, MAX_READ_BYTES):
                self.stats.backlog = True
            if size > MAX_READ_BYTES and name not in self.stats.oversized_files:
                self.stats.oversized_files.append(name)
            if limit <= offset:
                self.offsets[name] = offset
                continue
            with open(path, "rb") as fh:
                fh.seek(offset)
                chunk = fh.read(limit - offset)
            end = chunk.rfind(b"\n")
            if end < 0:
                if len(chunk) > MAX_LINE_BYTES:  # a giant line without newline: skip past it
                    self.offsets[name] = offset + len(chunk)
                    self.stats.skipped += 1
                continue
            pos = offset
            for line in chunk[: end + 1].split(b"\n")[:-1]:
                start = pos
                pos += len(line) + 1
                if not line.strip():
                    continue
                if len(out) >= MAX_SYNC_LINES:
                    pos = start
                    self.stats.backlog = True
                    break
                self.stats.lines += 1
                if len(line) > MAX_LINE_BYTES:
                    self.stats.skipped += 1
                    continue
                try:
                    raw = json.loads(line.decode("utf-8"))
                except (UnicodeDecodeError, ValueError):
                    self.stats.skipped += 1
                    continue
                if not isinstance(raw, dict):
                    self.stats.skipped += 1
                    continue
                out.append((writer, raw, (name, start)))
            budget -= pos - offset
            self.offsets[name] = pos
        return out
