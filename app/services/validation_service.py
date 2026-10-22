from __future__ import annotations

import json
import getpass
import os
import re
from datetime import datetime, timezone

from app.core.config import VALIDATION_ROOT
from app.core.file_utils import write_private_text
from app.core.security import redact_sensitive
from app.services.detective_service import clean_mac
from app.services.mist_client import MistApiError, get_mist_client

BAD_CONFIG_ALARM_MARKERS = ("CONFIG_FAILED", "CONFIGURATION_FAILED", "SW_CONFIG_FAILED", "AP_CONFIG_FAILED")
_CONNECTED_STATES = {"connected", "up", "online"}
_DISCONNECTED_STATES = {"disconnected", "down", "offline", "restarting", "upgrading"}
_ALARM_MAC_FIELDS = ("macs", "switches", "aps", "gateways", "device_mac", "mac", "devices")


def _safe_component(value: str, fallback: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]", "_", str(value or ""))
    cleaned = cleaned.strip("._")[:80]
    return cleaned or fallback


def _alarm_macs(alarm: dict) -> set[str]:
    macs: set[str] = set()
    for key in _ALARM_MAC_FIELDS:
        value = alarm.get(key)
        values = value if isinstance(value, list) else [value]
        for item in values:
            if isinstance(item, dict):
                item = item.get("mac")
            mac = clean_mac(item)
            if len(mac) == 12:
                macs.add(mac)
    return macs


def _alarm_open(alarm: dict) -> bool:
    status = str(alarm.get("status") or alarm.get("state") or "").lower()
    if status in {"resolved", "cleared", "closed"}:
        return False
    return not (alarm.get("resolved") or alarm.get("resolved_time") or alarm.get("cleared"))


def run_validation(site_id: str, device_id: str, *, expected: dict | None = None, label: str = "manual") -> dict:
    client = get_mist_client()
    checks = []
    try:
        config = client.get_site_device(site_id, device_id, fresh=True)
        stats = client.get_site_device_stats(site_id, device_id, fresh=True)
    except MistApiError as exc:
        return {
            "ok": False,
            "checks": [{"severity": "blocker", "ok": False, "label": "Mist device state readable", "detail": str(exc)}],
        }
    mac = clean_mac(config.get("mac") or stats.get("mac"))
    status = str(stats.get("status") or "").lower()
    if status in _CONNECTED_STATES and not stats.get("disconnected"):
        checks.append({"severity": "pass", "ok": True, "label": "Device connected to Mist", "detail": status})
    elif status in _DISCONNECTED_STATES or stats.get("disconnected"):
        checks.append(
            {
                "severity": "blocker",
                "ok": False,
                "label": "Device connected to Mist",
                "detail": status or "disconnected",
            }
        )
    else:
        # No status is not proof of health: report it as unknown and do not pass.
        checks.append(
            {
                "severity": "blocker",
                "ok": False,
                "label": "Device connected to Mist",
                "detail": f"Connection state unknown ({status or 'not reported'})",
            }
        )
    alarms_readable = True
    try:
        alarms = client.search_org_alarms(
            fresh=True, duration="1d", limit=2000
        )  # recent alarms are enough after a change
    except MistApiError:
        alarms = []
        alarms_readable = False
    config_fail = []
    for alarm in alarms:
        if not isinstance(alarm, dict) or not _alarm_open(alarm):
            continue
        if not mac or mac not in _alarm_macs(alarm):
            continue
        kind = str(alarm.get("type") or alarm.get("type_code") or "").lower()
        if any(marker.lower() in kind for marker in BAD_CONFIG_ALARM_MARKERS):
            config_fail.append(alarm)
    if not alarms_readable:
        checks.append(
            {
                "severity": "warning",
                "ok": False,
                "label": "No active configuration-failure alarm",
                "detail": "Alarms could not be read from Mist",
            }
        )
    else:
        checks.append(
            {
                "severity": "blocker" if config_fail else "pass",
                "ok": not config_fail,
                "label": "No active configuration-failure alarm",
                "detail": f"{len(config_fail)} open configuration-failure alarm(s) for this device",
            }
        )
    if expected:
        mismatches = []
        for key, value in expected.items():
            if config.get(key) != value:
                mismatches.append(key)
        checks.append(
            {
                "severity": "warning" if mismatches else "pass",
                "ok": not mismatches,
                "label": "Expected configuration observed",
                "detail": "Mismatch: " + ", ".join(mismatches) if mismatches else "Expected fields match",
            }
        )
    else:
        checks.append(
            {
                "severity": "info",
                "ok": True,
                "label": "Configuration re-read succeeded",
                "detail": f"Device configuration returned {len(config)} top-level fields",
            }
        )
    if config.get("virtual_chassis"):
        try:
            vc = client.get_site_virtual_chassis(site_id, device_id, fresh=True)
            state = str(vc.get("status") or vc.get("state") or "").lower()
            stable = state not in {"transition", "in_transition", "unstable", "down", "failed"}
            checks.append(
                {
                    "severity": "warning" if not stable else "pass",
                    "ok": stable,
                    "label": "Virtual Chassis operational state",
                    "detail": state or "No unstable state reported",
                }
            )
        except MistApiError as exc:
            checks.append(
                {"severity": "info", "ok": True, "label": "Virtual Chassis status", "detail": f"Not available: {exc}"}
            )
    blockers = [c for c in checks if c.get("severity") == "blocker" and not c.get("ok")]
    warnings = [c for c in checks if c.get("severity") == "warning" and not c.get("ok")]
    report = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "site_id": site_id,
        "device_id": device_id,
        "label": label,
        "actor": os.environ.get("USERNAME") or getpass.getuser() or "NodeWatch",
        "ok": not blockers,
        "checks": checks,
        "blockers": len(blockers),
        "warnings": len(warnings),
        "device": {
            "name": config.get("name") or stats.get("name"),
            "mac": mac,
            "model": config.get("model") or stats.get("model"),
            "version": stats.get("version") or config.get("version"),
        },
    }
    VALIDATION_ROOT.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    name = f"{stamp}_{_safe_component(device_id, 'device')}_{_safe_component(label, 'manual')}.json"
    root = VALIDATION_ROOT.resolve()
    path = (root / name).resolve()
    if path.parent != root:
        raise ValueError("Validation report path escaped the validation folder")
    write_private_text(path, json.dumps(redact_sensitive(report), indent=2, default=str))
    report["report_file"] = path.name
    return report


def list_reports(limit: int = 50) -> list[dict]:
    if not VALIDATION_ROOT.exists():
        return []
    rows = []
    for path in sorted(VALIDATION_ROOT.glob('*.json'), reverse=True)[:limit]:
        try:
            data = json.loads(path.read_text(encoding='utf-8'))
            rows.append(
                {
                    "file": path.name,
                    "timestamp": data.get("timestamp"),
                    "device": (data.get("device") or {}).get("name"),
                    "device_id": data.get("device_id"),
                    "site_id": data.get("site_id"),
                    "action": data.get("label"),
                    "actor": data.get("actor") or "NodeWatch",
                    "ok": data.get("ok"),
                    "warnings": data.get("warnings"),
                    "blockers": data.get("blockers"),
                }
            )
        except Exception:
            pass
    return rows
