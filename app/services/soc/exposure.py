"""Vulnerabilities & exposures (v0.10.30), from three vendor-neutral inputs:

* ``security.exposures`` — weaknesses a scanner / endpoint platform / vendor advisory service reports on assets;
* detections that name CVEs — which known vulnerabilities attackers are trying against you, and whether any
  attempt got through (see :func:`engine.cve_pressure`);
* NodeWatch's own inventory — software spread per model (the same model on several releases is the first
  thing to fix before a vulnerability is announced), and which of those devices attackers aimed at.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any

from app.integrations.contracts import SECURITY_EXPOSURES


def from_sources() -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    from app.integrations.connectors import sdk

    if not sdk.sources(SECURITY_EXPOSURES):
        return [], []
    rows, errors = sdk.gather(SECURITY_EXPOSURES, "list_exposures", None)
    return [r.to_dict() for r in rows], errors


def software(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Models with their software versions, from the last organisation read (no extra vendor call)."""
    try:
        from app.services import topology_org_service as org

        raw = org.raw_devices() or {}
    except Exception:  # noqa: BLE001
        raw = {}
    devices = list(raw.get("devices") or [])
    targeted_ips = {(e.get("target") or {}).get("ip") for e in events if int(e.get("reach") or 0) >= 2}
    groups: dict[tuple[str, str], dict[str, Any]] = defaultdict(lambda: {"versions": Counter(), "devices": 0, "role": "", "targeted": 0})
    seen: set[str] = set()
    for d in devices:
        model = str(getattr(d, "model", "") or "")
        version = str(getattr(d, "os_version", "") or "")
        if not model or not version or getattr(d, "role", "") in ("endpoint", "cloud", "unknown"):
            continue
        ident = str(getattr(d, "serial", "") or "") or f"{d.source}:{d.key}"
        if ident in seen:
            continue
        seen.add(ident)
        g = groups[(str(getattr(d, "vendor_name", "") or ""), model)]
        g["versions"][version] += 1
        g["devices"] += 1
        g["role"] = g["role"] or str(getattr(d, "role", "") or "")
        ips = {str(getattr(d, "mgmt_ip", "") or ""), *[str(x) for x in getattr(d, "addresses", None) or []]}
        if ips & targeted_ips:
            g["targeted"] += 1
    out = []
    for (vendor, model), g in groups.items():
        out.append(
            {
                "vendor": vendor,
                "model": model,
                "role": g["role"],
                "devices": g["devices"],
                "versions": [{"version": v, "count": c} for v, c in g["versions"].most_common()],
                "targeted": g["targeted"],
            }
        )
    out.sort(key=lambda r: (-(len(r["versions"]) > 1), -r["targeted"], -r["devices"]))
    return out
