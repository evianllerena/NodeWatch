"""Point NodeWatch's data folder at a temporary directory before any app module is imported."""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
os.environ.setdefault("NODEWATCH_DATA", tempfile.mkdtemp(prefix="nodewatch-test-"))
