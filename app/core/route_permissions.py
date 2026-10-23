"""Which permission each state-changing API route needs (pilot Phase 1).

Desktop mode grants every permission to the local user, so this changes nothing there. It exists so a
multi-user mode cannot reach a write without a permission, and so a new unsafe route cannot ship unreviewed:
a route missing from this table needs SETTINGS_ADMIN (fail closed), and the test suite fails until it is added.

``None`` means the route changes only this person's view or local session state, or only reads.
Some routes also check a permission deeper in their service (ports, stacking, restore, vendor ack); that check
stays. The classification is a proposal recorded in the pilot plan's change log for review.
"""

from __future__ import annotations

from fastapi import Request

from app.core.auth import (
    CONFIG_RESTORE,
    PORTS_WRITE,
    SETTINGS_ADMIN,
    STACKING_WRITE,
    TRIAGE,
    require,
)

UNSAFE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})

ROUTE_PERMISSIONS: dict[str, str | None] = {
    # Triage: local / team triage of alerts and cases.
    "POST /api/dashboard/disconnects/dismiss": TRIAGE,
    "POST /api/dashboard/disconnects/dismiss/bulk": TRIAGE,
    "POST /api/dashboard/disconnects/dismiss/restore-all": TRIAGE,
    "POST /api/dashboard/disconnects/dismiss/{key:path}/restore": TRIAGE,
    "POST /api/dashboard/dismiss": TRIAGE,
    "POST /api/dashboard/dismiss/bulk": TRIAGE,
    "POST /api/dashboard/dismiss/restore-all": TRIAGE,
    "POST /api/dashboard/dismiss/{key:path}/restore": TRIAGE,
    "POST /api/dashboard/mutes": TRIAGE,
    "POST /api/dashboard/mutes/{rule_id}/remove": TRIAGE,
    "POST /api/dashboard/triage": TRIAGE,
    "POST /api/dashboard/triage/sync": TRIAGE,
    "POST /api/dashboard/triage/undo": TRIAGE,
    "POST /api/v1/security/soc/cases/{case_id}": TRIAGE,
    # Settings: connections, credentials, destinations, policies, site mapping.
    "DELETE /api/v1/connectors/{connector_id}": SETTINGS_ADMIN,
    "POST /api/v1/connectors/{connector_id}": SETTINGS_ADMIN,
    "POST /api/v1/connectors/{connector_id}/enabled": SETTINGS_ADMIN,
    "POST /api/v1/connectors/{connector_id}/test": SETTINGS_ADMIN,
    "POST /api/dashboard/triage/store": SETTINGS_ADMIN,
    "POST /api/dashboard/triage/store/test": SETTINGS_ADMIN,
    "POST /api/integrations/palo-alto-device-security/enable": SETTINGS_ADMIN,
    "POST /api/integrations/palo-alto-device-security/reset": SETTINGS_ADMIN,
    "POST /api/integrations/palo-alto-device-security/save": SETTINGS_ADMIN,
    "POST /api/integrations/palo-alto-device-security/test": SETTINGS_ADMIN,
    "POST /api/integrations/strata-logging/enable": SETTINGS_ADMIN,
    "POST /api/integrations/strata-logging/reset": SETTINGS_ADMIN,
    "POST /api/integrations/strata-logging/test": SETTINGS_ADMIN,
    "POST /api/platform-overview/lock/configure": SETTINGS_ADMIN,
    "POST /api/settings/reset": SETTINGS_ADMIN,
    "POST /api/settings/save": SETTINGS_ADMIN,
    "POST /api/settings/test": SETTINGS_ADMIN,
    "POST /api/v1/alerting/config": SETTINGS_ADMIN,
    "POST /api/v1/alerting/test": SETTINGS_ADMIN,
    "POST /api/v1/config-backup/import": SETTINGS_ADMIN,
    "POST /api/v1/config-backup/policy": SETTINGS_ADMIN,
    "POST /api/v1/config-backup/snapshots/delete": SETTINGS_ADMIN,
    "POST /api/v1/siem/forwarder": SETTINGS_ADMIN,
    "POST /api/v1/siem/forwarder/diagnose": SETTINGS_ADMIN,
    "POST /api/v1/siem/forwarder/run": SETTINGS_ADMIN,
    "POST /api/v1/siem/forwarder/test": SETTINGS_ADMIN,
    "PUT /api/v1/topology/site-map": SETTINGS_ADMIN,
    "PUT /api/v1/topology/site-type": SETTINGS_ADMIN,
    # Production changes (the service also checks).
    "POST /api/v1/config-backup/restore": CONFIG_RESTORE,
    "POST /api/v1/operations/execute": PORTS_WRITE,
    "POST /api/v1/virtual-chassis/apply": STACKING_WRITE,
    # No permission: reads, previews, this person's view, or this session.
    "POST /api/integrations/strata-logging/ui-event": None,
    "POST /api/platform-overview/lock/verify": None,
    "POST /api/settings/open-data-folder": None,
    "POST /api/support/diagnostics": None,
    "POST /api/system/exit": None,
    "POST /api/system/keep-running": None,
    "POST /api/system/presence": None,
    "POST /api/system/presence/bye": None,
    "POST /api/ui/preferences": None,
    "POST /api/ui/theme": None,
    "POST /api/v1/ai-engineer/ask": None,
    "POST /api/v1/config-backup/restore-preview": None,
    "POST /api/v1/config-backup/snapshot": None,
    "POST /api/v1/config-backup/snapshots/pin": None,
    "POST /api/v1/operations/preview": None,
    "POST /api/v1/security/soc/refresh": None,
    "POST /api/v1/siem/export": None,
    "POST /api/v1/topology/baseline": None,
    "POST /api/v1/topology/report": None,
    "POST /api/v1/topology/trace": None,
    "POST /api/v1/validator/run": None,
    "POST /api/v1/virtual-chassis/preview": None,
}


def permission_for(method: str, path: str) -> str | None:
    """The permission a route needs. An unsafe route missing from the table needs SETTINGS_ADMIN."""
    method = method.upper()
    if method not in UNSAFE_METHODS:
        return None
    key = f"{method} {path}"
    return ROUTE_PERMISSIONS[key] if key in ROUTE_PERMISSIONS else SETTINGS_ADMIN


async def enforce_route_permission(request: Request) -> None:
    """Router dependency: raise PermissionDenied (403) unless the principal holds the route's permission."""
    route = request.scope.get("route")
    path = getattr(route, "path", None) or request.url.path
    permission = permission_for(request.method, path)
    if permission:
        require(permission)
