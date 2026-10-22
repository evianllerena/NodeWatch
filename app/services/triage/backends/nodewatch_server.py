"""``nodewatch_server`` — PLANNED, not implemented: one NodeWatch acting as a small team server.

Listed in Settings as "Team server (coming later)" and refused if selected. This module documents the
design so it can be built without changing anything else (the facade, fold, UI and sinks already speak
events):

Server side (a NodeWatch started with ``--team-server``, listening on HTTPS on the LAN):

* ``POST /api/v1/team/events``            body ``{"events": [<event>, …]}`` → ``{"accepted": [ids], "rejected": [...]}``
  The server validates every event with ``events.validate_event(strict=True)``, forces
  ``actor.user`` to the user the token belongs to (no impersonation), assigns a server sequence
  number and appends to its own JSON-lines log (the same format as the local store).
* ``GET  /api/v1/team/events?cursor=<n>&limit=1000`` → ``{"events": [...], "cursor": <n>}`` for
  incremental reads (long-polling optional).
* ``GET  /api/v1/team/health`` → users seen, event count, version.

Auth: a per-user bearer token issued by the server admin (``nodewatch team add-user jdoe``), stored on
each client in Windows Credential Manager (``app.integrations.secrets.SecretStore``) — never in the
triage settings JSON (the manifest validator forbids secret fields for that reason). TLS with a
certificate the clients trust; certificate pinning optional. No anonymous access.

Client side (this backend): ``append`` POSTs (queues in an outbox like ``shared_folder`` when the server
is unreachable), ``sync`` GETs from the last cursor and folds — identical semantics to the shared folder.
"""

from __future__ import annotations

from pathlib import Path

from app.integrations.connectors.sdk import SettingField
from app.services.triage.base import BackendManifest, BaseBackend, StoreUnavailableError

NOT_AVAILABLE = "Team server mode is planned for a later NodeWatch version and cannot be used yet."

MANIFEST = BackendManifest(
    backend_id="nodewatch_server",
    label="Team server (coming later)",
    description="One NodeWatch acts as a small team server; the others connect with a personal token. "
    "Planned — use a shared folder today.",
    settings=(
        SettingField(
            key="server_url",
            label="Team server address",
            type="url",
            placeholder="https://noc-pc-01.example.com:8770",
            help="Planned.",
            address=True,
        ),
    ),
    shared=True,
    maturity="planned",
    order=30,
)


class NodeWatchServerBackend(BaseBackend):
    manifest = MANIFEST

    def __init__(self, settings=None, *, state_dir: Path, actor: dict) -> None:
        raise StoreUnavailableError(NOT_AVAILABLE)

    @classmethod
    def clean_settings(cls, values: dict) -> dict:
        raise ValueError(NOT_AVAILABLE)

    @classmethod
    def test_settings(cls, values: dict, *, actor: dict) -> dict:
        return {"ok": False, "message": NOT_AVAILABLE}

    def append_many(self, events):  # pragma: no cover - never constructed
        raise StoreUnavailableError(NOT_AVAILABLE)

    def append_many_imported(self, events):  # pragma: no cover
        raise StoreUnavailableError(NOT_AVAILABLE)


BACKEND = NodeWatchServerBackend
