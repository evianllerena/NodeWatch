"""Shared-folder triage identity hardening (v0.10.22)."""

from __future__ import annotations

import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from tests import conftest_env  # noqa: F401

from app.services.triage import base, events, logfiles


ALICE = {"user": "alice", "display": "Alice", "machine": "hq-pc"}


class WriterNames(unittest.TestCase):
    def test_legacy_stem_refused(self):
        self.assertTrue(events.writer_matches(ALICE, "hq-pc~alice"))
        self.assertFalse(events.writer_matches(ALICE, "hq-pc-alice"))
        self.assertIsNone(logfiles.FILE_RE.match("hq-pc-alice.0001.jsonl"))
        m = logfiles.FILE_RE.match("hq-pc~alice.0001.jsonl")
        self.assertEqual((m.group("machine"), m.group("user")), ("hq-pc", "alice"))


class OwnerChecks(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.folder = Path(self.tmp.name)
        self.owners: dict[str, str] = {}

    def tearDown(self):
        self.tmp.cleanup()

    def _file(self, name: str, owner: str, age: float = 0.0):
        p = self.folder / name
        p.write_bytes(b"")
        t = time.time() - age
        os.utime(p, (t, t))
        self.owners[name] = owner

    def _owner(self, path):
        return self.owners.get(Path(path).name, "")

    def test_reader_skips_files_owned_by_someone_else(self):
        self._file("hq-pc~alice.0001.jsonl", "alice")
        self._file("evil-pc~alice.0001.jsonl", "mallory")
        with mock.patch.object(logfiles, "file_owner", self._owner):
            reader = logfiles.FolderReader(self.folder, verify_owner=True)
            names = [n for n, _ in reader.files()]
        self.assertEqual(names, ["hq-pc~alice.0001.jsonl"])
        self.assertEqual(reader.stats.foreign_files, 1)

    def test_writer_cap_is_per_user_and_by_recency(self):
        for i in range(20):
            self._file(f"junk{i:02d}~mallory.0001.jsonl", "mallory", age=0)
        self._file("hq-pc~alice.0001.jsonl", "alice", age=60)
        with mock.patch.object(logfiles, "file_owner", self._owner):
            reader = logfiles.FolderReader(self.folder, verify_owner=True)
            writers = {w for _, w in reader.files()}
        self.assertIn("hq-pc~alice", writers)
        self.assertEqual(sum(1 for w in writers if w.endswith("~mallory")), logfiles.MAX_MACHINES_PER_USER)

    def test_writer_skips_precreated_foreign_segment(self):
        self._file("hq-pc~alice.0001.jsonl", "mallory")
        with mock.patch.object(logfiles, "file_owner", self._owner), mock.patch.object(logfiles, "current_account", return_value="alice"):
            w = logfiles.SegmentedWriter(self.folder, "hq-pc~alice", verify_owner=True)
            self.assertEqual(w.current_path.name, "hq-pc~alice.0002.jsonl")

    def test_unverified_owner_still_read(self):
        self._file("hq-pc~alice.0001.jsonl", "")
        with mock.patch.object(logfiles, "file_owner", self._owner):
            reader = logfiles.FolderReader(self.folder, verify_owner=True)
            self.assertEqual(len(reader.files()), 1)


class OwnerCheckCalibration(unittest.TestCase):
    """A share that does not keep Windows owners must turn the check off, not hide everyone."""

    def _backend(self, tmp, owner_of_probe):
        from app.services.triage.backends import shared_folder

        share = Path(tmp, "share")
        share.mkdir()
        with mock.patch.object(shared_folder.ownership, "file_owner", return_value=owner_of_probe), mock.patch.object(
            shared_folder.ownership, "current_account", return_value="alice"
        ):
            b = shared_folder.SharedFolderBackend({"path": str(share)}, state_dir=Path(tmp, "state"), actor=ALICE)
        return b

    def test_force_user_share_disables_check(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch(
            "app.services.triage.backends.shared_folder.validate_folder_path", side_effect=lambda v: v
        ):
            b = self._backend(tmp, "nas-service")
            self.assertEqual(b.owner_check, "unavailable")
            self.assertFalse(b.reader.verify_owner)
            self.assertFalse(b.writer.verify_owner)
            self.assertEqual(b.health()["owner_check"], "unavailable")

    def test_owner_preserving_share_enforces_check(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch(
            "app.services.triage.backends.shared_folder.validate_folder_path", side_effect=lambda v: v
        ):
            b = self._backend(tmp, "alice")
            self.assertEqual(b.owner_check, "enforced")
            self.assertTrue(b.reader.verify_owner)


class TimeBombs(unittest.TestCase):
    def _backend(self, tmp):
        return base.BaseBackend({}, state_dir=Path(tmp), actor={"user": "bob", "display": "Bob", "machine": "pc2"})

    def test_far_future_event_refused_not_deferred(self):
        now = time.time()
        with tempfile.TemporaryDirectory() as tmp:
            b = self._backend(tmp)
            raw = events.new_event("ack", "k1", actor=ALICE, ts=now, seq=1)
            raw = dict(raw, ts=now + 2 * 3600, id="f" * 32)
            b.ingest([("hq-pc~alice", raw)], now=now)
            self.assertEqual(len(b.deferred), 0)
            self.assertEqual(b.rejected, 1)

    def test_slightly_future_event_still_deferred(self):
        now = time.time()
        with tempfile.TemporaryDirectory() as tmp:
            b = self._backend(tmp)
            raw = events.new_event("ack", "k1", actor=ALICE, ts=now, seq=1)
            raw = dict(raw, ts=now + 600, id="e" * 32)
            b.ingest([("hq-pc~alice", raw)], now=now)
            self.assertEqual(len(b.deferred), 1)


class Names(unittest.TestCase):
    def test_invisible_and_lookalike(self):
        self.assertEqual(events.clean_text("a​lice", 80), "alice")
        self.assertEqual(events.name_skeleton("Аlice"), "alice")  # Cyrillic A
        self.assertEqual(events.name_skeleton("Alicé"), "alice")

    def test_identity_prefers_signed_in_account(self):
        from app.services.triage import identity

        with mock.patch.dict(os.environ, {"USERNAME": "alice"}), mock.patch.object(identity.os, "getlogin", return_value="bob"):
            self.assertEqual(identity.windows_user(), "bob")


if __name__ == "__main__":
    unittest.main()
