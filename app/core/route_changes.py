"""What each state-changing API route changes (v0.10.46). A review list, not a permission check.

NodeWatch does not grant, store or assume rights over the systems it connects to. A change sent through a
connection is allowed or refused by that system, for the account the connection signs in with, at the moment
of the call: a right granted or removed there applies at once, with nothing to update here. A refusal is
shown as the vendor's refusal (``app.integrations.base.refused_text``).

  connection  can send a change to a connected system (that system decides, per call)
  nodewatch   changes only NodeWatch's own saved data or settings on this PC
  none        reads, previews, tests a connection, or this window's session

The suite fails while a state-changing route is missing here, so every new one is reviewed.
"""

from __future__ import annotations

ROUTE_CHANGES: dict[str, str] = {
    # Sends a change through a connection.
    "POST /api/dashboard/triage": "connection",
    "POST /api/v1/config-backup/restore": "connection",
    "POST /api/v1/operations/execute": "connection",
    "POST /api/v1/virtual-chassis/apply": "connection",
    # NodeWatch's own data and settings.
    "DELETE /api/v1/connectors/{connector_id}": "nodewatch",
    "POST /api/dashboard/disconnects/dismiss": "nodewatch",
    "POST /api/dashboard/disconnects/dismiss/bulk": "nodewatch",
    "POST /api/dashboard/disconnects/dismiss/restore-all": "nodewatch",
    "POST /api/dashboard/disconnects/dismiss/{key:path}/restore": "nodewatch",
    "POST /api/dashboard/dismiss": "nodewatch",
    "POST /api/dashboard/dismiss/bulk": "nodewatch",
    "POST /api/dashboard/dismiss/restore-all": "nodewatch",
    "POST /api/dashboard/dismiss/{key:path}/restore": "nodewatch",
    "POST /api/dashboard/mutes": "nodewatch",
    "POST /api/dashboard/mutes/{rule_id}/remove": "nodewatch",
    "POST /api/dashboard/triage/store": "nodewatch",
    "POST /api/dashboard/triage/sync": "nodewatch",
    "POST /api/dashboard/triage/undo": "nodewatch",
    "POST /api/integrations/palo-alto-device-security/enable": "nodewatch",
    "POST /api/integrations/palo-alto-device-security/reset": "nodewatch",
    "POST /api/integrations/palo-alto-device-security/save": "nodewatch",
    "POST /api/integrations/strata-logging/enable": "nodewatch",
    "POST /api/integrations/strata-logging/reset": "nodewatch",
    "POST /api/settings/reset": "nodewatch",
    "POST /api/settings/save": "nodewatch",
    "POST /api/ui/preferences": "nodewatch",
    "POST /api/ui/theme": "nodewatch",
    "POST /api/v1/alerting/config": "nodewatch",
    "POST /api/v1/config-backup/import": "nodewatch",
    "POST /api/v1/config-backup/policy": "nodewatch",
    "POST /api/v1/config-backup/snapshot": "nodewatch",
    "POST /api/v1/config-backup/snapshots/delete": "nodewatch",
    "POST /api/v1/config-backup/snapshots/pin": "nodewatch",
    "POST /api/v1/connectors/{connector_id}": "nodewatch",
    "POST /api/v1/connectors/{connector_id}/connections": "nodewatch",
    "POST /api/v1/connectors/{connector_id}/enabled": "nodewatch",
    "POST /api/v1/security/soc/cases/{case_id}": "nodewatch",
    "POST /api/v1/siem/forwarder": "nodewatch",
    "POST /api/v1/siem/forwarder/run": "nodewatch",
    "POST /api/v1/topology/baseline": "nodewatch",
    "PUT /api/v1/topology/site-map": "nodewatch",
    "PUT /api/v1/topology/site-type": "nodewatch",
    # Reads, previews, connection tests, this session.
    "POST /api/dashboard/triage/store/test": "none",
    "POST /api/integrations/palo-alto-device-security/test": "none",
    "POST /api/integrations/strata-logging/test": "none",
    "POST /api/integrations/strata-logging/ui-event": "none",
    "POST /api/settings/open-data-folder": "none",
    "POST /api/settings/test": "none",
    "POST /api/support/diagnostics": "none",
    "POST /api/system/exit": "none",
    "POST /api/system/keep-running": "none",
    "POST /api/system/presence": "none",
    "POST /api/system/presence/bye": "none",
    "POST /api/v1/ai-engineer/ask": "none",
    "POST /api/v1/alerting/test": "none",
    "POST /api/v1/config-backup/restore-preview": "none",
    "POST /api/v1/connectors/{connector_id}/test": "none",
    "POST /api/v1/operations/preview": "none",
    "POST /api/v1/security/soc/refresh": "none",
    "POST /api/v1/siem/export": "none",
    "POST /api/v1/siem/forwarder/diagnose": "none",
    "POST /api/v1/siem/forwarder/test": "none",
    "POST /api/v1/topology/report": "none",
    "POST /api/v1/topology/trace": "none",
    "POST /api/v1/validator/run": "none",
    "POST /api/v1/virtual-chassis/preview": "none",
}
