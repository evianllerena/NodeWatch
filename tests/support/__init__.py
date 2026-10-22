"""Shared test support for the NodeWatch suite.

Import this package before anything under ``app`` so the environment (data folder, target tree) is set first.
The suite uses only the standard library (``unittest``) so it runs on the bundled interpreter with no extra
installs: ``runtime\\python\\python.exe tests\\run.py --target bundle --root <_internal folder>``.
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
TARGET = os.environ.get("NODEWATCH_TEST_TARGET", "source")  # "source" | "bundle"
ROOT = Path(os.environ.get("NODEWATCH_TEST_ROOT") or REPO).resolve()  # folder that contains app/

# Every run gets its own empty data folder: tests never touch a real profile, credentials or settings.
_DATA = Path(tempfile.mkdtemp(prefix="nodewatch-test-data-"))
os.environ["NODEWATCH_DATA"] = str(_DATA)
os.environ.setdefault("NODEWATCH_EXTERNAL_LAUNCHER", "1")

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

if TARGET == "bundle":
    # Never write __pycache__ into an install: the launcher quarantines unlisted files under app/.
    sys.dont_write_bytecode = True
    os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
    # Use the bundle's own vendored packages when this OS matches the bundle (Windows: runtime/site-packages,
    # macOS: runtime-macos/site-packages-<arch>), so the run tests exactly what ships.
    import platform

    if sys.platform == "win32":
        _site = ROOT / "runtime" / "site-packages"
    elif sys.platform == "darwin":
        _site = ROOT / "runtime-macos" / f"site-packages-{'arm64' if platform.machine() == 'arm64' else 'x86_64'}"
    else:
        _site = None
    if _site is not None and _site.is_dir() and str(_site) not in sys.path:
        sys.path.insert(1, str(_site))

DATA_ROOT = _DATA


def app_dir() -> Path:
    return ROOT / "app"
