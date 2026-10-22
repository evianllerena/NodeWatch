"""Local triage state of SOC cases (v0.10.30): state, owner, notes and history — never sent to a vendor.

Cases themselves are recomputed from detections on every read; only what a person decided is stored
(``state/security/cases.json``). A resolved or dismissed case reopens by itself when new detections arrive
(see :func:`app.services.soc.engine.build_cases`).
"""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from typing import Any

from app.integrations.domain import SECURITY_INCIDENT_STATES

FILE_NAME = "cases.json"
MAX_CASES = 2000
_lock = threading.Lock()
_cache: dict[str, Any] = {"data": None}


def _path(root: Path | None = None) -> Path:
    if root is not None:
        return root / FILE_NAME
    from app.core.config import STATE_ROOT

    return STATE_ROOT / "security" / FILE_NAME


def _read(root: Path | None) -> dict[str, dict[str, Any]]:
    try:
        raw = json.loads(_path(root).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return raw if isinstance(raw, dict) else {}


def load(root: Path | None = None) -> dict[str, dict[str, Any]]:
    if root is not None:
        return _read(root)
    with _lock:
        if _cache["data"] is None:
            _cache["data"] = _read(None)
        return dict(_cache["data"])


def update(
    case_id: str,
    *,
    state: str | None = None,
    owner: str | None = None,
    note: str | None = None,
    root: Path | None = None,
) -> dict[str, Any]:
    from app.core.auth import current_principal
    from app.core.file_utils import write_private_text

    who = getattr(current_principal(), "display", "") or "local user"
    now = time.time()
    with _lock:
        data = _read(root)
        cur = dict(data.get(case_id) or {})
        hist = list(cur.get("history") or [])
        if state is not None:
            state = str(state).strip().lower()
            if state not in SECURITY_INCIDENT_STATES:
                raise ValueError(f"Unknown case state: {state}")
            if state != cur.get("state", "new"):
                hist.append({"at": now, "by": who, "what": f"State: {cur.get('state', 'new')} → {state}"})
                cur["state"] = state
                cur["state_at"] = now
        if owner is not None:
            owner = str(owner).strip()[:120]
            if owner != cur.get("owner", ""):
                hist.append({"at": now, "by": who, "what": f"Owner: {owner or 'nobody'}"})
                cur["owner"] = owner
        if note:
            notes = list(cur.get("notes") or [])
            notes.append({"at": now, "by": who, "text": str(note).strip()[:2000]})
            cur["notes"] = notes[-50:]
        cur["history"] = hist[-50:]
        cur["updated_at"] = now
        data[case_id] = cur
        if len(data) > MAX_CASES:
            oldest = sorted(data.items(), key=lambda kv: float(kv[1].get("updated_at") or 0))
            for k, _ in oldest[: len(data) - MAX_CASES]:
                data.pop(k, None)
        write_private_text(_path(root), json.dumps(data, separators=(",", ":")))
        if root is None:
            _cache["data"] = data
        return cur
