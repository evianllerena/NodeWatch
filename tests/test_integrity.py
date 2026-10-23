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
        """Release hygiene gate (v0.10.44: releases no longer ship docs/ or README.md). Run with python -B."""
        found = [p.relative_to(ROOT).as_posix() for p in ROOT.rglob("*")
                 if p.name in {"__pycache__", "docs", ".git", "tests", "README.md"} or p.suffix in {".map", ".pdb"}
                 or p.relative_to(ROOT).as_posix() == "branding/README.txt"]
        self.assertEqual(found, [])

    def test_compiled_packages_ship_no_source(self):
        """Phase 2: when app/core, app/integrations and app/services are compiled, none of their .py/.pyc ships."""
        from tests.support import COMPILED, COMPILED_PACKAGES

        if not COMPILED:
            self.skipTest("not a compiled build")
        left = [p.relative_to(ROOT).as_posix() for top in COMPILED_PACKAGES for p in (ROOT / "app" / top).rglob("*")
                if p.suffix in {".py", ".pyc"}] if (ROOT / "app").exists() else []
        self.assertEqual(left, [])
        self.assertEqual(len([p for top in COMPILED_PACKAGES for p in (ROOT / "app").glob(f"{top}.*") if p.suffix in {".pyd", ".so"}]), 3)

    def test_no_wrong_os_files_shipped(self):
        """v0.10.47: the macOS app carries no Windows-only files (report: Windows files in the macOS app)."""
        if (ROOT / "runtime-macos").exists():
            self.assertEqual([r for r in ("app/core/app_window.py", "branding/startup.bmp") if (ROOT / r).exists()], [])


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
