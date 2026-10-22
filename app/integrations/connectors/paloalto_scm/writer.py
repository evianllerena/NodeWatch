"""Strata Cloud Manager change module — DESIGN ONLY, NOT IMPLEMENTED.

The SCM connector is read-only: it sends only ``GET`` requests to the config APIs (``inventory.py``)
and the Log Viewer query used by Traffic & Sessions. This file fixes where a future SCM change module
goes and how it must behave, mirroring ``panorama/writer.py`` so one NodeWatch "change" feature can
drive either management plane.

SCM configuration APIs (pan.dev OpenAPI specs, ``openapi-specs/scm/config``; server
``https://api.strata.paloaltonetworks.com``):

1. Edit candidate configuration in a *folder* (or snippet): e.g. security rules
   ``POST/PUT/DELETE /config/security/v1/security-rules?folder=<folder>&position=pre`` (spec
   ``config/ngfw/security/security-services_R3.yaml``). Every object edit lands in the candidate.
2. Preview: list candidate vs running versions — ``GET /config/operations/v1/config-versions`` and
   ``GET /config/operations/v1/config-versions/candidate`` (spec ``config/ngfw/operations/config-operations_R3.yaml``)
   — shown in NodeWatch's confirm dialog; nothing is pushed without ``confirmed is True``.
3. Push: ``POST /config/operations/v1/config-versions/candidate:push`` with ``{"folder": [...],
   "description": "NodeWatch …"}`` (optionally ``admin`` to push only this service account's changes)
   → job id.
4. Poll: ``GET /config/operations/v1/jobs/{id}`` until the job and its child jobs finish; per-device
   results go to the audit entry.
5. Audit + rollback: every step through ``AuditService``; rollback by loading the previous version
   (``config-versions`` load/revert operations in the same spec) and pushing again, confirmed and audited.

Credentials: a *separate* service account with a write-capable role; the read-only account NodeWatch
stores today must keep a view-only role. Only then would the connector declare a ``.write`` capability.
"""

from __future__ import annotations

from typing import Any

from app.integrations.base import IntegrationError

PLANNED_OPERATIONS = ("candidate.edit", "config-versions.preview", "candidate:push", "jobs.poll", "rollback")


class ScmWriter:
    """Placeholder for the future SCM change module. Every method refuses."""

    implemented = False

    def __init__(self, *_: Any, **__: Any) -> None:
        pass

    def plan(self, *_: Any, **__: Any) -> Any:
        raise IntegrationError(
            "Strata Cloud Manager changes are not implemented yet (design in paloalto_scm/writer.py)", code="READ_ONLY"
        )

    preview = apply = push = rollback = plan
