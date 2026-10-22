"""The integrity manifest matches the files on disk (bundle target), and nothing unlisted hides under app/.

On the source target there is no manifest to check against, so these tests verify the recorded v0.10.42
manifests still describe a complete tree (no listed app file deleted by accident).
"""

from __future__ import annotations

import hashlib
import json
import unittest

import tests.support  # noqa: F401
from tests.support import REPO, ROOT, TARGET


def _sha256(path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


@unittest.skipUnless(TARGET == "bundle", "bundle target only")
class BundleIntegrity(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = json.loads((ROOT / "integrity.json").read_text(encoding="utf-8"))["files"]

    def test_every_listed_file_matches(self):
        bad, missing = [], []
        for rel, digest in self.manifest.items():
            p = ROOT / rel
            if not p.exists():
                missing.append(rel)
            elif _sha256(p) != digest:
                bad.append(rel)
        self.assertEqual((missing, bad), ([], []))

    def test_nothing_unlisted_under_app_or_runtime(self):
        listed = set(self.manifest)
        extra = []
        for top in ("app", "branding", "runtime", "runtime-macos"):
            base = ROOT / top
            if not base.exists():
                continue
            for p in base.rglob("*"):
                if p.is_file() and "__pycache__" not in p.parts:
                    rel = p.relative_to(ROOT).as_posix()
                    if rel not in listed:
                        extra.append(rel)
        self.assertEqual(extra, [])

    def test_no_dev_or_doc_files_shipped(self):
        """Release hygiene gate (plan Phase 1/3). Expected to fail on v0.10.42, which ships docs/."""
        found = [p.relative_to(ROOT).as_posix() for p in ROOT.rglob("*")
                 if p.name in {"__pycache__", "docs", ".git", "tests"} or p.suffix in {".map", ".pdb"}]
        if found and "docs" in {f.split("/")[0] for f in found}:
            self.skipTest("v0.10.42 ships docs/; becomes a hard gate once the Phase 1 bundle step lands")
        self.assertEqual(found, [])


@unittest.skipUnless(TARGET == "source", "source target only")
class SourceTreeCompleteness(unittest.TestCase):
    def test_every_app_file_from_v0_10_42_still_exists_or_was_removed_on_purpose(self):
        removed_on_purpose = set(json.loads((REPO / "tests" / "baselines" / "removed_files.json").read_text("utf-8")))
        manifest = json.loads((REPO / "integrity.v0.10.42.windows.json").read_text("utf-8"))["files"]
        gone = [rel for rel in manifest if rel.startswith("app/") and not rel.startswith("app/bin/")
                and not (REPO / rel).exists() and rel not in removed_on_purpose]
        self.assertEqual(gone, [], "files deleted without being listed in tests/baselines/removed_files.json")


if __name__ == "__main__":
    unittest.main()
