from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from app.core.credential_store import delete_secret, load_secret, save_secret


class SecretStore:
    """Vendor-neutral wrapper around the platform secret store.

    On distributed Windows builds this is Windows Credential Manager.  Callers only
    persist opaque references in ordinary settings and never handle storage details.
    """

    def __init__(self, data_root: Path):
        self.data_root = data_root

    def get(self, ref: str) -> str:
        return load_secret(self.data_root, ref)

    def put(self, ref: str, value: str, *, username: str = "NodeWatch Integration Secret") -> None:
        save_secret(self.data_root, ref, value, username=username)

    def delete(self, ref: str) -> None:
        delete_secret(self.data_root, ref)

    def exists(self, ref: str) -> bool:
        return bool(self.get(ref))

    def get_json(self, ref: str) -> dict[str, Any]:
        raw = self.get(ref)
        if not raw:
            return {}
        try:
            value = json.loads(raw)
            return value if isinstance(value, dict) else {}
        except Exception:
            return {}

    def put_json(self, ref: str, value: dict[str, Any], *, username: str = "NodeWatch Integration Secret") -> None:
        self.put(ref, json.dumps(value, separators=(",", ":")), username=username)
