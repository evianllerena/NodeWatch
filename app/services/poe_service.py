from __future__ import annotations

import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from app.services.mist_client import MistApiError, _path_id, get_mist_client
from app.services.operations_service import get_switch_ports

_LEGACY_BUDGET_KEYS = (
    "poe_budget",
    "poe_power_budget",
    "poe_max_power",
    "power_budget",
    "max_poe_power",
    "poe_capacity",
    "poe_capacity_watts",
    "max_power",
    "available_power",
)

NO_PORT_ROWS_NOTE = (
    "Mist reported {draw:.1f} W of chassis PoE draw but returned no per-port PoE rows for this switch. "
    "In Mist, open the switch (Switches → this switch → Ports tab) and check the PoE column; make sure PoE is "
    "enabled in the port profile (port usage) of the powered ports; and confirm the switch firmware reports PoE "
    "telemetry to Mist (upgrade Junos if the PoE column stays empty)."
)


def _num(v: Any) -> float | None:
    try:
        if v in (None, ""):
            return None
        return float(v)
    except (TypeError, ValueError):
        return None


def module_poe(stats: dict) -> list[dict]:
    """Per FPC / Virtual Chassis member PoE budget from ``stats.module_stat[i].poe``."""
    out = []
    modules = stats.get("module_stat") if isinstance(stats, dict) else None
    for idx, module in enumerate(modules if isinstance(modules, list) else []):
        if not isinstance(module, dict):
            continue
        poe = module.get("poe") if isinstance(module.get("poe"), dict) else {}
        max_power, power_draw = _num(poe.get("max_power")), _num(poe.get("power_draw"))
        if max_power is None and power_draw is None:
            continue
        fpc = module.get("fpc_idx")
        if fpc is None:
            fpc = module.get("idx", idx)
        out.append(
            {
                "fpc": fpc,
                "serial": module.get("serial") or "",
                "model": module.get("model") or "",
                "vc_role": module.get("vc_role") or "",
                "max_power": max_power,
                "power_draw": power_draw,
                "utilization_pct": round(power_draw / max_power * 100, 1)
                if max_power and power_draw is not None
                else None,
            }
        )
    return out


def _legacy_budget(stats: dict) -> float | None:
    sources = [stats] + [stats.get(k) for k in ("poe", "power", "poe_stats", "power_stats")]
    for source in sources:
        if not isinstance(source, dict):
            continue
        for key in _LEGACY_BUDGET_KEYS:
            budget = _num(source.get(key))
            if budget is not None and budget > 0:
                return budget
    return None


def is_powered(port: dict) -> bool:
    return bool(port.get("poe_on")) or (_num(port.get("poe_watts")) or 0) > 0


def poe_summary(site_id: str, device_id: str, *, fresh: bool = False) -> dict:
    data = get_switch_ports(site_id, device_id, fresh=fresh)
    stats = data.get("stats") or {}
    ports = data.get("ports") or []
    members = module_poe(stats)
    member_budget = sum(m["max_power"] or 0 for m in members)
    member_draw = sum(m["power_draw"] or 0 for m in members)
    budget = member_budget if member_budget > 0 else _legacy_budget(stats)
    powered = [p for p in ports if is_powered(p)]
    port_draw = sum(_num(p.get("poe_watts")) or 0 for p in powered)
    draw = max(port_draw, member_draw)
    utilization = (draw / budget * 100) if budget and budget > 0 else None

    explicit_port_caps = []
    for p in ports:
        raw = p.get("raw") if isinstance(p.get("raw"), dict) else {}
        for key in ("poe_max_power", "poe_max_watts", "max_power", "power_limit", "poe_power_limit"):
            cap = _num(raw.get(key))
            if cap is not None and cap > 0:
                explicit_port_caps.append(cap)
                break
    derived_budget = (
        round(sum(explicit_port_caps), 2)
        if explicit_port_caps and len(explicit_port_caps) >= len([p for p in ports if p.get("poe_on")])
        else None
    )
    derived_utilization = (draw / derived_budget * 100) if derived_budget and derived_budget > 0 else None

    risks = []
    if utilization is not None:
        if utilization >= 90:
            risks.append(
                {"severity": "critical", "title": "PoE budget above 90%", "detail": f"{utilization:.1f}% used"}
            )
        elif utilization >= 80:
            risks.append({"severity": "warning", "title": "PoE budget above 80%", "detail": f"{utilization:.1f}% used"})
    for m in members:
        pct = m["utilization_pct"]
        if pct is not None and pct >= 90 and len(members) > 1:
            risks.append(
                {
                    "severity": "warning",
                    "title": f"Member FPC {m['fpc']} PoE above 90%",
                    "detail": f"{m['power_draw']:.1f} W of {m['max_power']:.1f} W on this member",
                }
            )
    high = [p for p in powered if (_num(p.get("poe_watts")) or 0) >= 30]
    if high:
        risks.append(
            {"severity": "info", "title": "High-draw powered ports", "detail": f"{len(high)} port(s) at or above 30 W"}
        )
    if budget is None:
        detail = "Mist did not report a chassis PoE budget (module PoE statistics) for this switch."
        if derived_budget is not None:
            detail += f" NodeWatch derived a {derived_budget:.1f} W minimum from explicit per-port power limits; this is not the chassis rating."
        else:
            detail += " Current per-port draw remains authoritative and is shown below."
        risks.append({"severity": "info", "title": "PoE budget unavailable from Mist", "detail": detail})
    notes = []
    if not powered and member_draw > 0:
        notes.append(NO_PORT_ROWS_NOTE.format(draw=member_draw))
    return {
        "switch": data["switch"],
        "budget_watts": round(budget, 2) if budget is not None else None,
        "budget_source": "module_stat" if member_budget > 0 else ("switch_stats" if budget is not None else None),
        "derived_budget_watts": derived_budget,
        "draw_watts": round(draw, 2),
        "port_draw_watts": round(port_draw, 2),
        "module_draw_watts": round(member_draw, 2) if members else None,
        "utilization_pct": round(utilization, 1) if utilization is not None else None,
        "derived_utilization_pct": round(derived_utilization, 1) if derived_utilization is not None else None,
        "per_member": members,
        "powered_ports": len(powered),
        "risks": risks,
        "notes": notes,
        "warnings": list(data.get("warnings") or []),
        "ports": powered,
    }


# --------------------------------------------------------------------------- org / site overview (v0.10.15)
#
# When no switch is selected Power Guard shows where PoE needs attention across the
# organisation (or one site): switches ranked by PoE budget used, VC members near their
# budget, PSU problems that cut the budget, PoE / PSU alarms, PoE-powered APs that are
# offline or running on reduced power, and the ports drawing the most power. Everything
# comes from a handful of org-level reads that are fetched concurrently and cached.

OVERVIEW_TTL_SECONDS = 20.0
OVERVIEW_PORT_LIMIT = 10_000
CRITICAL_PCT = 90.0
WARNING_PCT = 80.0
_overview_cache: dict[str, tuple[float, dict]] = {}
_overview_lock = threading.Lock()

_PSU_OK = {"ok", "online", "present", "normal", "good", "on", "active", "absent", "empty", "not present", "n/a", ""}
_PORT_FAULT_WORDS = ("fault", "denied", "overload", "short", "error", "fail", "invalid")
_POE_ALARM_WORDS = ("poe",)
_PSU_ALARM_WORDS = ("psu", "pem", "power_supply", "power-supply", "powersupply")
_SEVERITY_RANK = {"critical": 3, "warning": 2, "info": 1, "ok": 0}


def _bare_mac(value: Any) -> str:
    return re.sub(r"[^0-9a-f]", "", str(value or "").lower())


def _text(value: Any) -> str:
    return str(value or "").strip()


def _worst(*levels: str) -> str:
    return max(levels or ("ok",), key=lambda s: _SEVERITY_RANK.get(s, 0))


def psu_problems(stats: dict) -> list[dict]:
    """PSUs that are present but not healthy (``module_stat[].psus[].status``).

    A failed PSU usually lowers the PoE budget of that member, so it is a PoE risk.
    Empty / absent slots are ignored: many switches ship with one PSU.
    """
    out = []
    modules = stats.get("module_stat") if isinstance(stats, dict) else None
    for idx, module in enumerate(modules if isinstance(modules, list) else []):
        if not isinstance(module, dict):
            continue
        fpc = module.get("fpc_idx", module.get("idx", idx))
        for psu in module.get("psus") or []:
            if not isinstance(psu, dict):
                continue
            status = _text(psu.get("status")).lower()
            if status in _PSU_OK:
                continue
            out.append({"fpc": fpc, "name": _text(psu.get("name")) or "PSU", "status": status})
    return out


def _port_fault(row: dict) -> str:
    """Return a PoE fault label when Mist reports one on a port stat row."""
    for key in ("poe_status", "poe_state", "poe_fault", "poe_oper_status", "poe_error"):
        value = row.get(key)
        if value in (None, "", False):
            continue
        text = "fault" if value is True else _text(value).lower()
        if any(word in text for word in _PORT_FAULT_WORDS):
            return text
    return ""


def _alarm_kind(alarm: dict) -> str:
    text = " ".join(_text(alarm.get(k)).lower() for k in ("type", "group", "reason", "text"))
    if any(word in text for word in _POE_ALARM_WORDS):
        return "poe"
    if any(word in text for word in _PSU_ALARM_WORDS):
        return "psu"
    return ""


def _alarm_open(alarm: dict) -> bool:
    if alarm.get("acked") is True:
        return False
    return _text(alarm.get("status")).lower() not in {"resolved", "cleared", "closed"}


def _ap_powered_by_poe(ap: dict) -> bool:
    src = _text(ap.get("power_src")).lower()
    if src:
        return "dc" not in src or "poe" in src
    return True  # Mist does not report the source while offline; APs are almost always PoE-powered


def _ap_power_constrained(ap: dict) -> str:
    if ap.get("power_constrained") is True:
        return "Power constrained"
    opmode = _text(ap.get("power_opmode")).lower()
    if opmode and "full" not in opmode and "default" not in opmode:
        return _text(ap.get("power_opmode"))
    lldp = ap.get("lldp_stat") if isinstance(ap.get("lldp_stat"), dict) else {}
    requested, allocated = _num(lldp.get("power_requested")), _num(lldp.get("power_allocated"))
    # Both are reported in the same unit (mW) by the AP's LLDP power negotiation.
    if requested and allocated is not None and 0 < allocated < requested:
        return "Switch allocated less power than requested"
    return ""


def _search_poe_ports(client: Any, site_id: str | None) -> list[dict]:
    params = {"device_type": "switch", "poe_on": "true"}
    if site_id:
        path = f"/api/v1/sites/{_path_id(site_id, 'site ID')}/stats/ports/search"
    else:
        path = f"/api/v1/orgs/{client._org}/stats/ports/search"
    return client._search(path, params, limit=OVERVIEW_PORT_LIMIT)


def _gather(client: Any, site_id: str | None) -> tuple[dict, list[str]]:
    jobs = {
        "switch stats": lambda: client.list_org_device_stats("switch", site_id=site_id),
        "AP stats": lambda: client.list_org_device_stats("ap", site_id=site_id),
        "PoE port stats": lambda: _search_poe_ports(client, site_id),
        "alarms": lambda: client.search_org_alarms(),
        "sites": lambda: client.site_name_map(),
    }
    values: dict[str, Any] = {}
    errors: list[str] = []
    with ThreadPoolExecutor(max_workers=len(jobs), thread_name_prefix="poe-overview") as pool:
        futures = {name: pool.submit(fn) for name, fn in jobs.items()}
        for name, future in futures.items():
            try:
                values[name] = future.result()
            except MistApiError as exc:
                if name == "switch stats":
                    raise
                errors.append(f"Mist could not return {name} ({exc}); that part of the overview is incomplete.")
                values[name] = None
            except Exception as exc:  # one broken source must not take the whole overview down
                errors.append(f"{name}: unexpected {type(exc).__name__}: {exc}")
                values[name] = None
    return values, errors


def build_poe_overview(client: Any, site_id: str | None = None) -> dict:
    site_id = _path_id(site_id, "site ID") if _text(site_id) else None
    values, warnings = _gather(client, site_id)
    site_names = values.get("sites") if isinstance(values.get("sites"), dict) else {}

    def in_scope(row: dict) -> bool:
        return not site_id or _text(row.get("site_id")) == site_id

    switches_raw = [s for s in values.get("switch stats") or [] if isinstance(s, dict) and in_scope(s)]
    aps_raw = [a for a in values.get("AP stats") or [] if isinstance(a, dict) and in_scope(a)]
    port_rows = [p for p in values.get("PoE port stats") or [] if isinstance(p, dict) and in_scope(p)]
    alarms = [
        a
        for a in values.get("alarms") or []
        if isinstance(a, dict) and in_scope(a) and _alarm_open(a) and _alarm_kind(a)
    ]
    if len(port_rows) >= OVERVIEW_PORT_LIMIT:
        warnings.append(f"Mist returned the maximum of {OVERVIEW_PORT_LIMIT} powered ports; port totals are partial.")

    by_mac: dict[str, dict] = {}
    switches: list[dict] = []
    for s in switches_raw:
        mac = _bare_mac(s.get("mac"))
        members = module_poe(s)
        member_budget = sum(m["max_power"] or 0 for m in members)
        member_draw = sum(m["power_draw"] or 0 for m in members)
        budget = member_budget if member_budget > 0 else _legacy_budget(s)
        row = {
            "id": _text(s.get("id")),
            "name": _text(s.get("name") or s.get("hostname")) or (mac or "Unnamed switch"),
            "mac": mac,
            "model": _text(s.get("model")),
            "site_id": _text(s.get("site_id")),
            "site_name": site_names.get(_text(s.get("site_id"))) or "",
            "status": _text(s.get("status")).lower() or "unknown",
            "budget_watts": round(budget, 1) if budget else None,
            "module_draw_watts": round(member_draw, 1) if members else None,
            "port_draw_watts": 0.0,
            "powered_ports": 0,
            "members": members,
            "hot_members": [],
            "psu_problems": psu_problems(s),
            "fault_ports": [],
            "alarms": [],
            "issues": [],
        }
        switches.append(row)
        if mac:
            by_mac[mac] = row

    # Per-port draw (only powered ports were requested).
    top_ports: list[dict] = []
    fault_ports: list[dict] = []
    for p in port_rows:
        sw = by_mac.get(_bare_mac(p.get("mac")))
        w = None
        for key in ("power_draw", "poe_usage", "poe_watts", "poe_power"):
            w = _num(p.get(key))
            if w is not None:
                break
        entry = {
            "port_id": _text(p.get("port_id")),
            "watts": round(w or 0, 1),
            "poe_mode": _text(p.get("poe_mode")),
            "poe_priority": _text(p.get("poe_priority")),
            "up": bool(p.get("up")),
            "neighbor": _text(p.get("neighbor_system_name") or p.get("neighbor_port_desc")),
            "switch_id": sw["id"] if sw else "",
            "switch_name": sw["name"] if sw else _text(p.get("mac")),
            "site_id": _text(p.get("site_id")) or (sw["site_id"] if sw else ""),
        }
        entry["site_name"] = site_names.get(entry["site_id"]) or ""
        fault = _port_fault(p)
        if sw:
            sw["powered_ports"] += 1
            sw["port_draw_watts"] += w or 0
        if fault:
            entry["fault"] = fault
            fault_ports.append(entry)
            if sw:
                sw["fault_ports"].append(entry)
        if w:
            top_ports.append(entry)
    top_ports.sort(key=lambda e: -e["watts"])

    # PoE / PSU alarms, attached to their switch when Mist names it.
    alarm_rows = []
    for a in alarms:
        macs = [_bare_mac(m) for m in (a.get("macs") or a.get("switches") or []) if m]
        if a.get("mac"):
            macs.append(_bare_mac(a.get("mac")))
        sw = next((by_mac[m] for m in macs if m in by_mac), None)
        names = a.get("hostnames") if isinstance(a.get("hostnames"), list) else []
        row = {
            "id": _text(a.get("id")),
            "kind": _alarm_kind(a),
            "type": _text(a.get("type")),
            "severity": _text(a.get("severity")).lower() or "warning",
            "count": int(_num(a.get("count")) or 1),
            "last_seen": a.get("last_seen") or a.get("timestamp"),
            "site_id": _text(a.get("site_id")),
            "switch_id": sw["id"] if sw else "",
            "switch_name": sw["name"] if sw else ", ".join(str(n) for n in names[:3]),
        }
        row["site_name"] = site_names.get(row["site_id"]) or ""
        alarm_rows.append(row)
        if sw:
            sw["alarms"].append(row)
    alarm_rows.sort(key=lambda r: str(r.get("last_seen") or ""), reverse=True)

    # Finish each switch: draw, utilisation, issues and a severity used for ranking.
    for sw in switches:
        sw["port_draw_watts"] = round(sw["port_draw_watts"], 1)
        draw = max(sw["port_draw_watts"], sw["module_draw_watts"] or 0)
        sw["draw_watts"] = round(draw, 1)
        budget = sw["budget_watts"]
        util = round(draw / budget * 100, 1) if budget else None
        sw["utilization_pct"] = util
        severity = "ok"
        issues = sw["issues"]
        if util is not None and util >= CRITICAL_PCT:
            severity = "critical"
            issues.append(f"PoE budget {util:.0f}% used")
        elif util is not None and util >= WARNING_PCT:
            severity = "warning"
            issues.append(f"PoE budget {util:.0f}% used")
        for m in sw["members"]:
            pct = m["utilization_pct"]
            if pct is not None and pct >= WARNING_PCT and len(sw["members"]) > 1:
                sw["hot_members"].append(m)
                level = "critical" if pct >= CRITICAL_PCT else "warning"
                severity = _worst(severity, level)
                # Only worth its own line when the member is hotter than the chassis as a whole.
                if util is None or util < WARNING_PCT or pct >= util + 5:
                    issues.append(f"Member FPC {m['fpc']} at {pct:.0f}%")
        if sw["psu_problems"]:
            severity = _worst(severity, "critical")
            issues.append(f"{len(sw['psu_problems'])} PSU problem(s)")
        if sw["fault_ports"]:
            severity = _worst(severity, "critical")
            issues.append(f"{len(sw['fault_ports'])} PoE fault port(s)")
        if sw["alarms"]:
            worst_alarm = "critical" if any(a["severity"] == "critical" for a in sw["alarms"]) else "warning"
            severity = _worst(severity, worst_alarm)
            issues.append(f"{len(sw['alarms'])} PoE/PSU alarm(s)")
        if sw["status"] not in ("connected", "unknown"):
            severity = _worst(severity, "warning")
            issues.append("Switch offline: last known PoE values")
        sw["severity"] = severity

    switches.sort(
        key=lambda s: (
            -_SEVERITY_RANK.get(s["severity"], 0),
            -(s["utilization_pct"] if s["utilization_pct"] is not None else -1),
            -s["draw_watts"],
            s["name"].lower(),
        )
    )

    # APs: offline PoE-powered APs and APs running on reduced PoE power.
    aps_offline: list[dict] = []
    aps_constrained: list[dict] = []
    site_ap_total: dict[str, int] = {}
    for ap in aps_raw:
        sid = _text(ap.get("site_id"))
        site_ap_total[sid] = site_ap_total.get(sid, 0) + 1
        lldp = ap.get("lldp_stat") if isinstance(ap.get("lldp_stat"), dict) else {}
        upstream = by_mac.get(_bare_mac(lldp.get("chassis_id")))
        entry = {
            "id": _text(ap.get("id")),
            "name": _text(ap.get("name")) or _text(ap.get("mac")),
            "mac": _bare_mac(ap.get("mac")),
            "model": _text(ap.get("model")),
            "site_id": sid,
            "site_name": site_names.get(sid) or "",
            "switch_id": upstream["id"] if upstream else "",
            "switch_name": upstream["name"] if upstream else _text(lldp.get("system_name")),
            "switch_port": _text(lldp.get("port_id")),
            "power_src": _text(ap.get("power_src")),
            "last_seen": ap.get("last_seen"),
        }
        status = _text(ap.get("status")).lower()
        if status and status != "connected":
            if _ap_powered_by_poe(ap):
                aps_offline.append(entry)
        else:
            reason = _ap_power_constrained(ap)
            if reason:
                aps_constrained.append({**entry, "reason": reason})

    # Site roll-up (also used for the site-scoped header).
    sites: dict[str, dict] = {}

    def site_row(sid: str) -> dict:
        if sid not in sites:
            sites[sid] = {
                "site_id": sid,
                "site_name": site_names.get(sid) or sid or "Unassigned",
                "switches": 0,
                "budget_watts": 0.0,
                "draw_watts": 0.0,
                "max_utilization_pct": None,
                "worst_switch_id": "",
                "worst_switch_name": "",
                "over_90": 0,
                "over_80": 0,
                "psu_problems": 0,
                "fault_ports": 0,
                "alarms": 0,
                "aps_total": site_ap_total.get(sid, 0),
                "aps_offline": 0,
                "aps_constrained": 0,
                "severity": "ok",
            }
        return sites[sid]

    for sw in switches:
        row = site_row(sw["site_id"])
        row["switches"] += 1
        row["budget_watts"] += sw["budget_watts"] or 0
        row["draw_watts"] += sw["draw_watts"]
        util = sw["utilization_pct"]
        if util is not None and (row["max_utilization_pct"] is None or util > row["max_utilization_pct"]):
            row["max_utilization_pct"] = util
            row["worst_switch_id"], row["worst_switch_name"] = sw["id"], sw["name"]
        if util is not None and util >= CRITICAL_PCT:
            row["over_90"] += 1
        elif util is not None and util >= WARNING_PCT:
            row["over_80"] += 1
        row["psu_problems"] += len(sw["psu_problems"])
        row["fault_ports"] += len(sw["fault_ports"])
        row["severity"] = _worst(row["severity"], sw["severity"])
        if not row["worst_switch_id"] and sw["severity"] != "ok":
            row["worst_switch_id"], row["worst_switch_name"] = sw["id"], sw["name"]
    for a in alarm_rows:
        if a["switch_id"]:
            continue  # already counted via the switch severity
        row = site_row(a["site_id"])
        row["severity"] = _worst(row["severity"], "critical" if a["severity"] == "critical" else "warning")
    for a in alarm_rows:
        site_row(a["site_id"])["alarms"] += 1
    for ap in aps_offline:
        row = site_row(ap["site_id"])
        row["aps_offline"] += 1
        row["severity"] = _worst(row["severity"], "warning")
    for ap in aps_constrained:
        row = site_row(ap["site_id"])
        row["aps_constrained"] += 1
        row["severity"] = _worst(row["severity"], "warning")
    for row in sites.values():
        row["budget_watts"] = round(row["budget_watts"], 1)
        row["draw_watts"] = round(row["draw_watts"], 1)
    site_list = sorted(
        sites.values(),
        key=lambda r: (
            -_SEVERITY_RANK.get(r["severity"], 0),
            -(r["over_90"] * 4 + r["psu_problems"] * 3 + r["fault_ports"] * 3 + r["alarms"] * 2 + r["over_80"]),
            -r["aps_offline"],
            -(r["max_utilization_pct"] if r["max_utilization_pct"] is not None else -1),
            r["site_name"].lower(),
        ),
    )

    with_budget = [s for s in switches if s["budget_watts"]]
    budget_total = sum(s["budget_watts"] for s in with_budget)
    draw_budgeted = sum(s["draw_watts"] for s in with_budget)
    totals = {
        "switches": len(switches),
        "switches_with_budget": len(with_budget),
        "budget_watts": round(budget_total, 1),
        "draw_watts": round(sum(s["draw_watts"] for s in switches), 1),
        "utilization_pct": round(draw_budgeted / budget_total * 100, 1) if budget_total else None,
        "powered_ports": sum(s["powered_ports"] for s in switches),
        "over_90": sum(
            1 for s in switches if s["utilization_pct"] is not None and s["utilization_pct"] >= CRITICAL_PCT
        ),
        "over_80": sum(
            1
            for s in switches
            if s["utilization_pct"] is not None and WARNING_PCT <= s["utilization_pct"] < CRITICAL_PCT
        ),
        "hot_members": sum(len(s["hot_members"]) for s in switches),
        "psu_problems": sum(len(s["psu_problems"]) for s in switches),
        "fault_ports": len(fault_ports),
        "poe_alarms": sum(1 for a in alarm_rows if a["kind"] == "poe"),
        "psu_alarms": sum(1 for a in alarm_rows if a["kind"] == "psu"),
        "aps_total": len(aps_raw),
        "aps_offline": len(aps_offline),
        "aps_constrained": len(aps_constrained),
        "sites_at_risk": sum(1 for r in site_list if r["severity"] in ("critical", "warning")),
    }
    aps_offline.sort(key=lambda a: (a["site_name"].lower(), a["name"].lower()))
    return {
        "scope": "site" if site_id else "org",
        "site_id": site_id or "",
        "site_name": site_names.get(site_id or "", "") if site_id else "",
        "generated_at": time.time(),
        "thresholds": {"warning_pct": WARNING_PCT, "critical_pct": CRITICAL_PCT},
        "totals": totals,
        "switches": switches,
        "sites": site_list,
        "top_ports": top_ports[:12],
        "fault_ports": fault_ports[:100],
        "alarms": alarm_rows[:100],
        "aps_offline": aps_offline[:200],
        "aps_constrained": aps_constrained[:200],
        "warnings": warnings,
    }


def poe_overview(site_id: str | None = None, client: Any = None, *, fresh: bool = False) -> dict:
    """Cached org / site PoE overview (``fresh`` bypasses NodeWatch's short overview cache)."""
    key = _text(site_id) or "*"
    now = time.monotonic()
    if not fresh:
        with _overview_lock:
            hit = _overview_cache.get(key)
        if hit and hit[0] > now:
            return hit[1]
    result = build_poe_overview(client or get_mist_client(), site_id)
    with _overview_lock:
        _overview_cache[key] = (time.monotonic() + OVERVIEW_TTL_SECONDS, result)
        if len(_overview_cache) > 64:
            _overview_cache.pop(next(iter(_overview_cache)))
    return result


def clear_overview_cache() -> None:
    with _overview_lock:
        _overview_cache.clear()
