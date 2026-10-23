"""Discovery of triage store plug-ins (``app/services/triage/backends/<id>.py``).

A module is a store when it exposes ``MANIFEST`` (a valid :class:`BackendManifest` whose ``backend_id``
equals the module name) and ``BACKEND`` (a :class:`BaseBackend` subclass whose ``manifest`` is that
MANIFEST). A broken module is logged and listed in :func:`load_failures`; it never stops the others.
"""

from __future__ import annotations

import importlib
import logging
import threading

from app.core.security import redact_text
from app.services.triage.base import BackendManifest, BaseBackend

log = logging.getLogger("nodewatch.triage")
_LOCK = threading.Lock()
_BACKENDS: dict[str, type[BaseBackend]] = {}
_FAILED: dict[str, str] = {}
_DISCOVERED = False
# Allow-list (pilot P1), the same rule connectors follow (sdk.SHIPPED_CONNECTORS).
SHIPPED_BACKENDS = ("local", "nodewatch_server", "shared_folder")


def _load_one(name: str) -> type[BaseBackend]:
    module = importlib.import_module(f"app.services.triage.backends.{name}")
    manifest = getattr(module, "MANIFEST", None)
    cls = getattr(module, "BACKEND", None)
    if not isinstance(manifest, BackendManifest):
        raise ValueError("MANIFEST is missing or is not a BackendManifest")
    if not isinstance(cls, type) or not issubclass(cls, BaseBackend):
        raise ValueError("BACKEND is missing or is not a BaseBackend subclass")
    problems = manifest.validate()
    if manifest.backend_id != name:
        problems.append("backend_id must equal the module name")
    if getattr(cls, "manifest", None) is not manifest:
        problems.append("BACKEND.manifest is not MANIFEST")
    if problems:
        raise ValueError("; ".join(problems))
    return cls


def discover() -> dict[str, type[BaseBackend]]:
    global _DISCOVERED
    with _LOCK:
        if _DISCOVERED:
            return _BACKENDS
        # Only the stores NodeWatch ships are imported; a module dropped into the folder is ignored.
        for name in SHIPPED_BACKENDS:
            try:
                _BACKENDS[name] = _load_one(name)
            except Exception as exc:  # noqa: BLE001 - one broken store must not take NodeWatch down
                log.exception("Triage store %s failed to load", name)
                _FAILED[name] = f"{type(exc).__name__}: {redact_text(exc)}"[:300]
        _DISCOVERED = True
        return _BACKENDS


def get(backend_id: str) -> type[BaseBackend] | None:
    return discover().get(str(backend_id or ""))


def manifests() -> list[BackendManifest]:
    return sorted((c.manifest for c in discover().values()), key=lambda m: (m.order, m.backend_id))


def load_failures() -> dict[str, str]:
    discover()
    return dict(_FAILED)


def reset_for_tests() -> None:
    global _DISCOVERED
    with _LOCK:
        _BACKENDS.clear()
        _FAILED.clear()
        _DISCOVERED = False
