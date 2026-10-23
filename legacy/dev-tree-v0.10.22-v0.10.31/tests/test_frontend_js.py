"""Runs the Node-based frontend tests in tests/js (skipped when Node.js is not installed)."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

JS_DIR = Path(__file__).resolve().parent / "js"
NODE = shutil.which("node")


@pytest.mark.skipif(NODE is None, reason="Node.js not installed")
def test_frontend_js_suite():
    files = sorted(str(p) for p in JS_DIR.glob("*.test.cjs"))
    result = subprocess.run([NODE, "--test", *files], capture_output=True, text=True, timeout=120)
    assert result.returncode == 0, result.stdout + result.stderr


ESLINT = shutil.which("eslint")


@pytest.mark.skipif(ESLINT is None, reason="eslint not installed")
def test_frontend_lint_has_no_undefined_references():
    root = JS_DIR.parents[1]
    result = subprocess.run(
        [ESLINT, "--max-warnings", "0", "app/static"], cwd=root, capture_output=True, text=True, timeout=120
    )
    assert result.returncode == 0, result.stdout + result.stderr
