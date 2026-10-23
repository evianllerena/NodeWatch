"""Shared pytest setup: isolate NodeWatch data in a temp directory.

NodeWatch resolves its data root at import time, so the environment must be
set before any ``app.*`` module is imported.
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

_TEST_HOME = Path(tempfile.mkdtemp(prefix="nodewatch-tests-"))
os.environ["NODEWATCH_DATA"] = str(_TEST_HOME)
os.environ["LOCALAPPDATA"] = str(_TEST_HOME)

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
