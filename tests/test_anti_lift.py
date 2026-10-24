"""Phase 3 anti-lift guard: the compiled app module refuses to run when lifted out of its install.

The guard function is tested directly with fake module paths (no compiled build needed). It is fail-open:
it refuses only a provable lift and allows on any doubt, so it can never stop a genuine NodeWatch start.
"""

from __future__ import annotations

import hashlib
import json
import os
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

import tests.support  # noqa: F401


class AntiLift(unittest.TestCase):
    def _guard(self):
        from app import _verify_not_lifted

        return _verify_not_lifted

    def test_source_checkout_is_never_lifted(self):
        self.assertIsNone(self._guard()("/some/path/app/__init__.py"))

    def test_compiled_module_without_a_manifest_refuses(self):
        with TemporaryDirectory() as tmp:
            mod = Path(tmp) / "app.cpython-312-darwin.so"
            mod.write_bytes(b"compiled")
            reason = self._guard()(str(mod))
        self.assertIsNotNone(reason)
        self.assertIn("will not run on its own", reason)

    def test_compiled_module_inside_its_install_runs(self):
        with TemporaryDirectory() as tmp:
            mod = Path(tmp) / "app.cp312-win_amd64.pyd"
            mod.write_bytes(b"the real compiled module")
            (Path(tmp) / "integrity.json").write_text(
                json.dumps({"files": {mod.name: hashlib.sha256(mod.read_bytes()).hexdigest()}}), "utf-8"
            )
            self.assertIsNone(self._guard()(str(mod)))

    def test_manifest_without_the_module_allows_fail_open(self):
        with TemporaryDirectory() as tmp:
            mod = Path(tmp) / "app.cpython-312-darwin.so"
            mod.write_bytes(b"compiled")
            (Path(tmp) / "integrity.json").write_text(json.dumps({"files": {"other": "x"}}), "utf-8")
            self.assertIsNone(self._guard()(str(mod)))

    def test_escape_hatch(self):
        with TemporaryDirectory() as tmp:
            mod = Path(tmp) / "app.cpython-312-darwin.so"
            mod.write_bytes(b"compiled")
            with mock.patch.dict(os.environ, {"NODEWATCH_ALLOW_LIFT": "1"}):
                self.assertIsNone(self._guard()(str(mod)))


if __name__ == "__main__":
    unittest.main()
