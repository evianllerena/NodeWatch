"""Team triage (v0.10.18): pluggable stores for acknowledge / snooze / dismiss / mute / notes / assign.

Modules:

* :mod:`.events`   — the event schema, validation and bounds (the only thing a store writes)
* :mod:`.fold`     — deterministic last-writer-wins fold of events into state
* :mod:`.base`     — ``TriageBackend`` / ``TriageSink`` protocols, ``BackendManifest``, ``BaseBackend``
* :mod:`.registry` — discovery of store plug-ins in ``backends/``
* :mod:`.backends` — ``local`` (default), ``shared_folder`` (SMB, no locking), ``nodewatch_server`` (planned)
* :mod:`.sinks`    — outbound integrations (Jira / ServiceNow / Teams / Slack would plug in here)
* :mod:`.store`    — the facade the Command Center uses (records in, events out)
* :mod:`.manager`  — active store, Settings › Team triage, switching with copy, export

See docs/TEAM_TRIAGE.md.
"""

from app.services.triage.base import (  # noqa: F401
    BackendManifest,
    BaseBackend,
    ReadOnlyError,
    StoreUnavailableError,
    TriageBackend,
    TriageSink,
    TriageStoreError,
)
