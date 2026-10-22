from __future__ import annotations

from typing import Any

from app.services.investigation_service import INVESTIGATION_SERVICE
from app.services.mist_client import get_mist_client
from app.services.operations_service import list_switches
from app.services.poe_service import poe_summary
from app.services.security_service import posture


class OperationsAssistantDataService:
    """Single data boundary for the Operations Assistant.

    The assistant no longer owns vendor authentication or constructs vendor requests.
    Existing capabilities are exposed through this facade while new multi-vendor data
    comes from the Investigation Service. This lets provider migration happen behind
    the facade without repeatedly rewriting natural-language intent logic.
    """

    @property
    def _mist(self):
        return get_mist_client()

    # Generic/canonical data
    def device_activity(self, *, ip: str, window: str = "1h", limit: int = 100) -> dict[str, Any]:
        return INVESTIGATION_SERVICE.activity(ip=ip, window=window, limit=limit)

    def capability_map(self) -> dict[str, list[str]]:
        return INVESTIGATION_SERVICE.capabilities()

    def device_investigation(self, target: str, *, site_id: str | None = None) -> dict[str, Any]:
        return INVESTIGATION_SERVICE.device(target=target, site_id=site_id)

    # Compatibility-facing operational methods. Vendor calls remain behind this
    # boundary until corresponding canonical services are available.
    def list_sites(self):
        return self._mist.list_sites()

    def search_org_alarms(self):
        return self._mist.search_org_alarms()

    def search_org_inventory(self, **kwargs):
        return self._mist.search_org_inventory(**kwargs)

    def search_audit_logs(self, *args, **kwargs):
        return self._mist.search_audit_logs(*args, **kwargs)

    def site_security_posture(self, site_id: str | None):
        return posture(site_id)

    def site_poe_summary(self, site_id: str) -> dict[str, Any]:
        switches = list_switches(site_id, self._mist)
        total_draw = 0.0
        powered = 0
        unreadable = 0
        evidence = []
        for sw in switches[:100]:
            try:
                ps = poe_summary(site_id, sw["id"])
                total_draw += float(ps.get("draw_watts") or 0)
                powered += int(ps.get("powered_ports") or 0)
                evidence.append(
                    {
                        "type": "poe",
                        "title": sw.get("name") or sw.get("id"),
                        "detail": f"{ps.get('draw_watts', 0)} W · {ps.get('powered_ports', 0)} powered ports",
                    }
                )
            except Exception:
                unreadable += 1
        return {
            "switch_count": len(switches),
            "readable_switches": len(switches) - unreadable,
            "unreadable_switches": unreadable,
            "powered_ports": powered,
            "draw_watts": total_draw,
            "evidence": evidence,
        }


ASSISTANT_DATA = OperationsAssistantDataService()
