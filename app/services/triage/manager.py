"""Which triage store is active on this PC, its settings, switching, testing, status and export."""

from __future__ import annotations

import json
import logging
import threading
import time
from pathlib import Path

from app.core.config import DATA_ROOT, STATE_ROOT
from app.core.file_utils import write_private_text
from app.core.version import APP_VERSION
from app.services.triage import registry
from app.services.triage.base import BaseBackend, StoreUnavailableError
from app.services.triage.events import clean_text, order_key
from app.services.triage.identity import current_actor

log = logging.getLogger("nodewatch.triage")
COPY_NOTES_DAYS = 30


class TriageManager:
    def __init__(self, settings_path: Path | None = None, state_dir: Path | None = None) -> None:
        self.settings_path = Path(settings_path or DATA_ROOT / "triage_settings.json")
        self.state_dir = Path(state_dir or STATE_ROOT)
        self._lock = threading.RLock()
        self._backend: BaseBackend | None = None
        self.error = ""

    # ------------------------------------------------------------------ settings
    def config(self) -> dict:
        try:
            data = json.loads(self.settings_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            data = {}
        if not isinstance(data, dict):
            data = {}
        settings = data.get("settings") if isinstance(data.get("settings"), dict) else {}
        return {
            "backend": str(data.get("backend") or "local"),
            "settings": {k: v for k, v in settings.items() if isinstance(v, dict)},
            "display_name": clean_text(data.get("display_name"), 80),
        }

    def _save_config(self, cfg: dict) -> None:
        write_private_text(self.settings_path, json.dumps(cfg, indent=1))

    def actor(self) -> dict:
        return current_actor(self.config()["display_name"])

    # ------------------------------------------------------------------ active store
    def _build(self, backend_id: str, settings: dict) -> BaseBackend:
        cls = registry.get(backend_id)
        if cls is None:
            raise StoreUnavailableError(f"Unknown triage store {backend_id!r}")
        if not cls.manifest.available:
            raise StoreUnavailableError(f"{cls.manifest.label} is not available yet.")
        return cls(settings, state_dir=self.state_dir, actor=self.actor())

    def backend(self) -> BaseBackend:
        with self._lock:
            if self._backend is None:
                cfg = self.config()
                try:
                    self._backend = self._build(cfg["backend"], cfg["settings"].get(cfg["backend"], {}))
                    self.error = ""
                except Exception as exc:  # noqa: BLE001 - never lose triage because a setting broke
                    log.warning("Triage store %s unusable, using this PC only: %s", cfg["backend"], exc)
                    self.error = f"{cfg['backend']}: {exc}"[:300]
                    self._backend = self._build("local", {})
            return self._backend

    def set_backend_for_tests(self, backend: BaseBackend | None) -> None:
        with self._lock:
            self._backend = backend

    # ------------------------------------------------------------------ Settings › Team triage
    def describe(self) -> dict:
        cfg = self.config()
        return {
            "active": cfg["backend"],
            "display_name": cfg["display_name"],
            "settings": cfg["settings"],
            "backends": [m.public_dict() for m in registry.manifests()],
            "load_failures": registry.load_failures(),
            "me": self.actor(),
            "status": self.status(),
        }

    def status(self) -> dict:
        b = self.backend()
        try:
            b.sync()
        except Exception as exc:  # noqa: BLE001
            b.last_error = str(exc)[:300]
        h = b.health()
        if self.error:
            h["config_error"] = self.error
        return h

    def test(self, body: dict) -> dict:
        backend_id = str((body or {}).get("backend") or "")
        cls = registry.get(backend_id)
        if cls is None:
            raise ValueError("Choose a triage store")
        if not cls.manifest.available:
            raise StoreUnavailableError(f"{cls.manifest.label} is not available yet.")
        return cls.test_settings((body or {}).get("settings") or {}, actor=self.actor())

    def save(self, body: dict) -> dict:
        """Apply Settings › Team triage. ``copy_local`` copies the current state into the new store."""
        body = body or {}
        backend_id = str(body.get("backend") or "local")
        cls = registry.get(backend_id)
        if cls is None:
            raise ValueError("Choose a triage store")
        if not cls.manifest.available:
            raise StoreUnavailableError(f"{cls.manifest.label} is not available yet.")
        settings = cls.clean_settings(body.get("settings") or {})
        display = clean_text(body.get("display_name"), 80)
        if len(str(body.get("display_name") or "").strip()) > 80:
            raise ValueError("Display name is too long (80 characters max)")
        with self._lock:
            cfg = self.config()
            cfg["display_name"] = display
            current = self.backend()
            same = cfg["backend"] == backend_id and cfg["settings"].get(backend_id, {}) == settings
            copied = 0
            if same:
                current.actor["display"] = display or current.actor["user"]
            else:
                if cls.manifest.shared:
                    probe = cls.test_settings(settings, actor=self.actor())
                    if not probe.get("ok"):
                        raise ValueError(probe.get("message") or "The store did not pass the test")
                new = cls(settings, state_dir=self.state_dir, actor=current_actor(display))
                if body.get("copy_local"):
                    copied = new.import_events(self.copy_set(current))
                self._backend = new
                self.error = ""
            cfg["backend"] = backend_id
            cfg["settings"][backend_id] = settings
            self._save_config(cfg)
        return {"ok": True, "copied": copied, **self.describe()}

    @staticmethod
    def copy_set(src: BaseBackend) -> list[dict]:
        """Events that reproduce ``src``'s current state: register winners + recent notes."""
        src.sync(force=True)
        cutoff = time.time() - COPY_NOTES_DAYS * 86400
        notes = [e for e in src.fold.all_events() if e["action"] == "note" and e["ts"] >= cutoff]
        return sorted({e["id"]: e for e in src.fold.winners() + notes}.values(), key=order_key)

    def export(self) -> dict:
        b = self.backend()
        b.sync(force=True)
        return {
            "kind": "nodewatch-triage-history",
            "nodewatch_version": APP_VERSION,
            "exported_at": time.time(),
            "store": b.describe(),
            "exported_by": self.actor(),
            "note": "Plain triage history: who did what to which alert, and when. Contains no credentials.",
            "events": b.fold.all_events(),
        }

    def actors(self) -> list[dict]:
        b = self.backend()
        with b.lock:
            seen = [dict(a) for a in b.fold.actors.values()]
        me = self.actor()
        if not any(a["user"].lower() == me["user"].lower() for a in seen):
            seen.append({"user": me["user"], "display": me["display"], "machines": [me["machine"]], "last_ts": 0})
        return sorted(seen, key=lambda a: a["display"].lower())


MANAGER = TriageManager()
