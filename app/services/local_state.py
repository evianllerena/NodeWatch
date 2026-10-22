from __future__ import annotations

import json
from pathlib import Path
from threading import Lock

from app.core.config import STATE_ROOT
from app.core.file_utils import write_private_text


class LocalState:
    def __init__(self, path: Path | None = None):
        self.path = path or (STATE_ROOT / "local_state.json")
        self._lock = Lock()

    def _load(self) -> dict:
        if not self.path.exists():
            return {"dismissed_alerts": {}, "dismissed_disconnects": {}}
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
            if not isinstance(payload, dict):
                return {"dismissed_alerts": {}, "dismissed_disconnects": {}}
            payload.setdefault("dismissed_alerts", {})
            payload.setdefault("dismissed_disconnects", {})
            return payload
        except Exception:
            return {"dismissed_alerts": {}, "dismissed_disconnects": {}}

    def _save(self, data: dict) -> None:
        write_private_text(self.path, json.dumps(data, indent=2))

    def dismissed(self) -> dict[str, dict]:
        return dict(self._load().get("dismissed_alerts", {}))

    def dismiss(self, key: str, payload: dict) -> None:
        with self._lock:
            data = self._load()
            data.setdefault("dismissed_alerts", {})[key] = payload
            self._save(data)

    def dismiss_many(self, records: list[dict]) -> int:
        with self._lock:
            data = self._load()
            bucket = data.setdefault("dismissed_alerts", {})
            count = 0
            for record in records:
                key = str(record.get("key") or "").strip()
                if not key:
                    continue
                bucket[key] = record
                count += 1
            if count:
                self._save(data)
            return count

    def restore(self, key: str) -> None:
        with self._lock:
            data = self._load()
            data.setdefault("dismissed_alerts", {}).pop(key, None)
            self._save(data)

    def restore_all(self) -> int:
        with self._lock:
            data = self._load()
            bucket = data.setdefault("dismissed_alerts", {})
            count = len(bucket)
            if count:
                data["dismissed_alerts"] = {}
                self._save(data)
            return count

    def dismissed_disconnects(self) -> dict[str, dict]:
        return dict(self._load().get("dismissed_disconnects", {}))

    def dismiss_disconnect(self, key: str, payload: dict) -> None:
        with self._lock:
            data = self._load()
            data.setdefault("dismissed_disconnects", {})[key] = payload
            self._save(data)

    def dismiss_disconnects(self, records: list[dict]) -> int:
        with self._lock:
            data = self._load()
            bucket = data.setdefault("dismissed_disconnects", {})
            count = 0
            for record in records:
                key = str(record.get("key") or "").strip()
                if not key:
                    continue
                bucket[key] = record
                count += 1
            if count:
                self._save(data)
            return count

    def restore_disconnect(self, key: str) -> None:
        with self._lock:
            data = self._load()
            data.setdefault("dismissed_disconnects", {}).pop(key, None)
            self._save(data)

    def restore_all_disconnects(self) -> int:
        with self._lock:
            data = self._load()
            bucket = data.setdefault("dismissed_disconnects", {})
            count = len(bucket)
            if count:
                data["dismissed_disconnects"] = {}
                self._save(data)
            return count


local_state = LocalState()
