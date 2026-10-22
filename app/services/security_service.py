from __future__ import annotations

from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor

from app.services.mist_client import MistApiError, get_mist_client


def posture(site_id: str | None = None) -> dict:
    """Build posture from fast inventory search instead of the slow org-wide stats/devices pull."""
    c = get_mist_client()
    errors: list[str] = []
    with ThreadPoolExecutor(max_workers=4, thread_name_prefix="security-posture") as pool:
        f_alarms = pool.submit(c.search_org_alarms)
        f_inventory = pool.submit(c.search_org_inventory, site_id=site_id, limit=1000)
        f_audit = pool.submit(c.search_audit_logs, "7d")
        f_nac = pool.submit(c.search_org_nac_clients_any, status="denied", site_id=site_id, duration="1d", limit=200)
        vals = []
        for f in (f_alarms, f_inventory, f_audit, f_nac):
            try:
                vals.append(f.result())
            except MistApiError as exc:
                vals.append([])
                errors.append(str(exc))
    alarms, inventory, audit, nac = vals
    if site_id:
        alarms = [a for a in alarms if not a.get("site_id") or str(a.get("site_id")) == site_id]

    findings = []
    unresolved = [a for a in alarms if not a.get("resolved")]
    critical = [a for a in unresolved if str(a.get("severity") or "").lower() in {"critical", "major"}]
    if critical:
        findings.append(
            {
                "severity": "critical",
                "category": "Alarms",
                "title": "Critical or major unresolved alarms",
                "count": len(critical),
                "items": critical[:20],
            }
        )

    rogues = [
        a for a in unresolved if "rogue" in str(a.get("type") or a.get("type_code") or a.get("message") or "").lower()
    ]
    if rogues:
        findings.append(
            {
                "severity": "warning",
                "category": "Wireless Security",
                "title": "Rogue-related active conditions",
                "count": len(rogues),
                "items": rogues[:20],
            }
        )

    disconnected = [
        d
        for d in inventory
        if str(d.get("status") or "").lower() in {"disconnected", "down", "offline"} or d.get("connected") is False
    ]
    if disconnected:
        findings.append(
            {
                "severity": "critical",
                "category": "Availability",
                "title": "Infrastructure disconnected from Mist",
                "count": len(disconnected),
                "items": disconnected[:30],
            }
        )

    by_model = defaultdict(Counter)
    for d in inventory:
        model = str(d.get("model") or "Unknown")
        version = str(d.get("version") or "Unknown")
        by_model[model][version] += 1
    inconsistent = []
    for model, versions in by_model.items():
        real = [v for v in versions if v != "Unknown"]
        if len(real) > 1:
            inconsistent.append({"model": model, "versions": dict(versions)})
    if inconsistent:
        findings.append(
            {
                "severity": "warning",
                "category": "Firmware",
                "title": "Multiple firmware versions within the same model",
                "count": len(inconsistent),
                "items": inconsistent,
            }
        )

    if nac:
        findings.append(
            {
                "severity": "warning",
                "category": "Access Assurance",
                "title": "NAC denied clients in the last day",
                "count": len(nac),
                "items": nac[:30],
            }
        )

    changes = [
        x
        for x in audit
        if any(
            word in str(x.get("message") or x.get("activity") or "").lower()
            for word in ("update", "change", "delete", "create", "config")
        )
    ]
    if changes:
        findings.append(
            {
                "severity": "info",
                "category": "Change Activity",
                "title": "Recent configuration/admin changes",
                "count": len(changes),
                "items": changes[:30],
            }
        )

    counts = Counter(f["severity"] for f in findings)
    return {
        "site_id": site_id,
        "findings": findings,
        "summary": {
            "critical": counts["critical"],
            "warning": counts["warning"],
            "info": counts["info"],
            "active_alarms": len(unresolved),
            "disconnected_devices": len(disconnected),
            "nac_denials": len(nac),
        },
        "errors": errors,
        "device_source": "Mist inventory search",
    }
