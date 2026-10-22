"""Virtual Chassis health aggregation (NodeWatch v0.10.15).

Read-only. Turns Mist switch statistics (``module_stat[]``), the live ``/vc`` view,
the device's ``virtual_chassis`` config, device events and alarms into:

* an org- or site-wide ranked list of stacks with plain-English issues, and
* a rich per-stack report (members, VC links, topology, environment, events,
  firmware/redundancy verdicts).

Every Mist field is optional: Mist and Junos versions differ in what they report,
so the helpers below accept the documented names plus the common aliases and never
raise on a missing or malformed field.
"""

from __future__ import annotations

import re
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from app.services.mist_client import MistApiError

SEV_RANK = {"critical": 3, "warning": 2, "info": 1, "ok": 0}
SEV_WEIGHT = {"critical": 100, "warning": 10, "info": 1}
# Extra ranking weight so an offline / split stack outranks one with a single critical alarm.
CODE_WEIGHT = {"offline": 400, "split": 300, "split_brain": 300, "no_master": 300, "member_missing": 150}

_ABSENT_STATES = {"not-present", "notpresent", "not present", "absent", "inactive", "offline", "disconnected", "down"}
_PRESENT_STATES = {"present", "prsnt", "online", "connected", "up", "active"}
_BAD_HW = {
    "failed",
    "failure",
    "fail",
    "bad",
    "error",
    "down",
    "offline",
    "check",
    "not ok",
    "notok",
    "critical",
    "alarm",
    "major",
    "warning",
    "minor",
    "not-present",
    "absent",
    "missing",
}
_OK_HW = {"ok", "online", "present", "good", "normal", "up", "running", "active", "spinning", "on", "testing"}
_EVENT_KEYWORDS = (
    "VC",
    "VIRTUAL_CHASSIS",
    "RESTART",
    "REBOOT",
    "PSU",
    "PEM",
    "POWER_SUPPLY",
    "FAN",
    "TEMP",
    "HOT",
    "CHASSIS",
    "FPC",
    "CONFIG",
    "UPGRADE",
    "MASTER",
    "BACKUP",
    "ROLE",
    "SWITCHOVER",
    "DISCONNECTED",
    "CONNECTED",
)


# --------------------------------------------------------------------------- small helpers
def clean_mac(value: Any) -> str:
    return re.sub(r"[^0-9a-f]", "", str(value or "").lower())


def _num(value: Any) -> float | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        out = float(value)
    except (TypeError, ValueError):
        return None
    return out if out == out else None  # NaN guard


def _int(value: Any) -> int | None:
    n = _num(value)
    return int(n) if n is not None else None


def _list(value: Any) -> list:
    return [x for x in value if x is not None] if isinstance(value, list) else []


def _dict(value: Any) -> dict:
    return value if isinstance(value, dict) else {}


def _epoch(value: Any) -> float:
    n = _num(value)
    if not n:
        return 0.0
    return n / 1000.0 if n > 1e12 else n


def normalize_role(value: Any) -> str:
    role = str(value or "").strip().lower().replace("_", "-")
    return {
        "primary": "master",
        "master": "master",
        "secondary": "backup",
        "backup": "backup",
        "routing-engine": "routing-engine",
        "re": "routing-engine",
        "line-card": "linecard",
        "linecard": "linecard",
    }.get(role, role)


def fpc_index(raw: dict, fallback: int | None = None) -> int | None:
    for key in ("_idx", "fpc_idx", "fpc", "member_id", "member", "idx", "slot"):
        v = _int(raw.get(key))
        if v is not None and v >= 0:
            return v
    return fallback


def _hw_status(value: Any) -> str:
    """Return ok / bad / absent / unknown for a PSU / fan / temperature status string."""
    s = str(value or "").strip().lower()
    if not s:
        return "unknown"
    if s in {"absent", "not-present", "empty", "not present"}:
        return "absent"
    if s in _OK_HW:
        return "ok"
    if s in _BAD_HW or any(w in s for w in ("fail", "fault", "error", "alarm", "critical", "bad", "high")):
        return "bad"
    return "unknown"


def _cpu_util(cpu: dict) -> float | None:
    if not cpu:
        return None
    idle = _num(cpu.get("idle"))
    if idle is not None:
        return max(0.0, min(100.0, 100.0 - idle))
    parts = [_num(cpu.get(k)) for k in ("user", "system", "interrupt")]
    vals = [p for p in parts if p is not None]
    if vals:
        return max(0.0, min(100.0, sum(vals)))
    return _num(cpu.get("usage") or cpu.get("utilization"))


def _mem_util(mem: dict) -> float | None:
    if not mem:
        return None
    usage = _num(mem.get("usage") or mem.get("utilization"))
    if usage is not None:
        return usage
    total, used = _num(mem.get("total")), _num(mem.get("used"))
    if total and used is not None:
        return round(used * 100.0 / total, 1)
    return None


def _port_fpc(port_id: str) -> int | None:
    if str(port_id or "").lower().startswith("vcp-"):
        return None  # vcp-255/x/y: 255 is not a member number
    m = re.match(r"^[a-z]+-(\d+)/\d+/\d+", str(port_id or ""))
    return int(m.group(1)) if m else None


def _speed_label(value: Any) -> str:
    n = _num(value)
    if not n:
        return str(value or "")
    if n >= 1000:
        g = n / 1000
        return f"{g:g} Gbps"
    return f"{n:g} Mbps"


def _member_present(raw: dict) -> bool | None:
    state = str(raw.get("vc_state") or raw.get("state") or "").strip().lower()
    if state in _ABSENT_STATES:
        return False
    if state in _PRESENT_STATES:
        return True
    status = str(raw.get("status") or "").strip().lower()
    if status in _ABSENT_STATES:
        return False
    if status in _PRESENT_STATES:
        return True
    return None


def _links_of(raw: dict) -> list[dict]:
    """VC links/ports of one member in a common shape."""
    out: list[dict] = []
    for link in _list(raw.get("vc_links")):
        if not isinstance(link, dict):
            continue
        out.append(
            {
                "port": str(link.get("port_id") or link.get("port") or link.get("name") or ""),
                "neighbor_fpc": _int(
                    link.get("neighbor_module_idx")
                    if link.get("neighbor_module_idx") is not None
                    else link.get("neighbor_fpc")
                ),
                "neighbor_port": str(link.get("neighbor_port_id") or link.get("neighbor_port") or ""),
                "state": str(link.get("status") or link.get("state") or "up").lower(),
                "speed": link.get("speed"),
            }
        )
    for port in _list(raw.get("vc_ports")):
        if isinstance(port, str):
            continue  # configured port names; compared separately
        if not isinstance(port, dict):
            continue
        state = str(port.get("status") or port.get("state") or ("up" if port.get("up") else "")).lower()
        out.append(
            {
                "port": str(port.get("port_id") or port.get("port") or port.get("name") or port.get("interface") or ""),
                "neighbor_fpc": _int(
                    port.get("neighbor_module_idx")
                    if port.get("neighbor_module_idx") is not None
                    else port.get("neighbor_fpc", port.get("neighbor_member"))
                ),
                "neighbor_port": str(port.get("neighbor_port_id") or port.get("neighbor_port") or ""),
                "state": state or "unknown",
                "speed": port.get("speed"),
            }
        )
    return out


# --------------------------------------------------------------------------- members
def normalize_member(raw: dict, *, extra: dict | None = None, if_stat: dict | None = None) -> dict:
    """One VC member from a module_stat entry (optionally merged with the /vc member)."""
    src = dict(extra or {})
    src.update({k: v for k, v in (raw or {}).items() if v not in (None, "", [], {})})
    fpc = fpc_index(src)
    cpu = _dict(src.get("cpu_stat"))
    mem = _dict(src.get("memory_stat"))
    temps = []
    for t in _list(src.get("temperatures")):
        if not isinstance(t, dict):
            continue
        c = _num(t.get("celsius") if t.get("celsius") is not None else t.get("temperature"))
        status = _hw_status(t.get("status"))
        if c is not None and c >= 85:
            status = "bad"
        temps.append({"name": str(t.get("name") or "Sensor"), "celsius": c, "status": status, "raw": t.get("status")})
    fans = [
        {
            "name": str(f.get("name") or "Fan"),
            "status": _hw_status(f.get("status")),
            "raw": f.get("status"),
            "airflow": f.get("airflow"),
        }
        for f in _list(src.get("fans"))
        if isinstance(f, dict)
    ]
    psus = [
        {"name": str(p.get("name") or "PSU"), "status": _hw_status(p.get("status")), "raw": p.get("status")}
        for p in _list(src.get("psus"))
        if isinstance(p, dict)
    ]
    poe = _dict(src.get("poe"))
    ports_total = 0
    for pic in _list(src.get("pics")):
        for grp in _list(_dict(pic).get("port_groups")):
            ports_total += _int(_dict(grp).get("count")) or 0
    ports_up = None
    if if_stat and fpc is not None:
        seen: dict[str, bool] = {}
        for key, row in if_stat.items():
            row = _dict(row)
            pid = str(row.get("port_id") or key).split(".")[0]
            if not re.match(r"^(ge|mge|xe|et)-", pid) or _port_fpc(pid) != fpc:
                continue
            seen[pid] = seen.get(pid, False) or bool(row.get("up"))
        if seen:
            ports_up = sum(1 for v in seen.values() if v)
            ports_total = max(ports_total, len(seen))
    temps_c = [t["celsius"] for t in temps if t["celsius"] is not None]
    present = _member_present(src)
    return {
        "fpc": fpc,
        "mac": clean_mac(src.get("mac")),
        "role": normalize_role(src.get("vc_role") or src.get("role")) or "",
        "vc_state": str(src.get("vc_state") or src.get("state") or ""),
        "present": present,
        "vc_mode": str(src.get("vc_mode") or ""),
        "model": str(src.get("model") or ""),
        "serial": str(src.get("serial") or src.get("serial_number") or ""),
        "version": str(src.get("version") or src.get("os_version") or src.get("fw_version") or ""),
        "pending_version": str(src.get("pending_version") or ""),
        "backup_version": str(src.get("backup_version") or ""),
        "recovery_version": str(src.get("recovery_version") or ""),
        "boot_partition": str(src.get("boot_partition") or ""),
        "uptime": _int(src.get("uptime")),
        "last_seen": _epoch(src.get("last_seen")) or None,
        "cpu": _cpu_util(cpu),
        "memory": _mem_util(mem),
        "temperatures": temps,
        "max_temp": max(temps_c) if temps_c else None,
        "fans": fans,
        "psus": psus,
        "poe": {"max_power": _num(poe.get("max_power")), "power_draw": _num(poe.get("power_draw"))} if poe else None,
        "ports_up": ports_up,
        "ports_total": ports_total or None,
        "links": _links_of(src),
        "configured_vc_ports": [str(p) for p in _list(src.get("vc_ports")) if isinstance(p, str)],
        "errors": [str(e) for e in _list(src.get("errors"))][:5],
        "locating": bool(src.get("locating")),
    }


def is_stack(stat: dict) -> bool:
    modules = [m for m in _list(stat.get("module_stat")) if isinstance(m, dict)]
    if len(modules) >= 2:
        return True
    vc_mac = clean_mac(stat.get("vc_mac"))
    return bool(vc_mac and vc_mac != clean_mac(stat.get("mac")) and modules)


def merge_members(stat: dict, live_vc: dict | None = None, config: dict | None = None) -> list[dict]:
    """Members keyed by FPC: module_stat first, /vc member fills gaps, config adds absent members."""
    live_members = [m for m in _list(_dict(live_vc).get("members")) if isinstance(m, dict)]
    live_by_fpc = {fpc_index(m): m for m in live_members if fpc_index(m) is not None}
    live_by_mac = {clean_mac(m.get("mac")): m for m in live_members if clean_mac(m.get("mac"))}
    if_stat = _dict(stat.get("if_stat"))
    members: dict[int, dict] = {}
    for pos, mod in enumerate(m for m in _list(stat.get("module_stat")) if isinstance(m, dict)):
        idx = fpc_index(mod, pos)
        extra = live_by_mac.get(clean_mac(mod.get("mac"))) or live_by_fpc.get(idx) or {}
        row = normalize_member(mod, extra=extra, if_stat=if_stat)
        if row["fpc"] is None:
            row["fpc"] = idx
        members[row["fpc"]] = row
    for pos, live in enumerate(live_members):
        idx = fpc_index(live, pos)
        if idx in members:
            continue
        row = normalize_member(live, if_stat=if_stat)
        row["fpc"] = idx
        members[idx] = row
    # Configured (preprovisioned) members that Mist does not report at all are missing.
    cfg_members = [m for m in _list(_dict(_dict(config).get("virtual_chassis")).get("members")) if isinstance(m, dict)]
    known_macs = {m["mac"] for m in members.values() if m["mac"]}
    for pos, cfg in enumerate(cfg_members):
        mac = clean_mac(cfg.get("mac"))
        idx = fpc_index(cfg, pos)
        if (mac and mac in known_macs) or (not mac and idx in members):
            if idx in members and cfg.get("vc_ports"):
                members[idx]["configured_vc_ports"] = [str(p) for p in _list(cfg.get("vc_ports"))]
            continue
        if idx in members:
            # Same FPC reported with a different MAC: config/actual mismatch, noted by assess_stack.
            continue
        row = normalize_member({"mac": mac, "vc_role": cfg.get("vc_role"), "vc_state": "not-present"})
        row["fpc"] = idx
        row["configured_only"] = True
        members[idx] = row
    out = sorted(members.values(), key=lambda m: m["fpc"] if m["fpc"] is not None else 999)
    # Top-level CPU / memory describe the routing engine (master) when modules do not report their own.
    master = next((m for m in out if m["role"] == "master"), None)
    if master:
        if master["cpu"] is None:
            master["cpu"] = _cpu_util(_dict(stat.get("cpu_stat")))
        if master["memory"] is None:
            master["memory"] = _mem_util(_dict(stat.get("memory_stat")))
    return out


# --------------------------------------------------------------------------- links / topology
def build_links(members: list[dict], open_port_downs: list[dict] | None = None) -> list[dict]:
    """Undirected VC links (deduplicated) plus down ports from config / open events."""
    links: list[dict] = []
    seen: set[tuple] = set()
    present_fpcs = {m["fpc"] for m in members}
    for m in members:
        for link in m["links"]:
            a = (m["fpc"], link["port"])
            b = (link["neighbor_fpc"], link["neighbor_port"])
            key = tuple(sorted([a, b], key=lambda x: (x[0] if x[0] is not None else 999, str(x[1]))))
            if key in seen:
                continue
            seen.add(key)
            up = link["state"] not in {"down", "disabled", "absent", "failed"}
            links.append(
                {
                    "local_fpc": m["fpc"],
                    "local_port": link["port"],
                    "remote_fpc": link["neighbor_fpc"],
                    "remote_port": link["neighbor_port"],
                    "state": "up" if up else "down",
                    "speed": _speed_label(link.get("speed")) if link.get("speed") else "",
                    "source": "Mist VC links",
                }
            )
    used_ports = {(x["local_fpc"], x["local_port"]) for x in links} | {
        (x["remote_fpc"], x["remote_port"]) for x in links
    }
    for m in members:
        configured = m.get("configured_vc_ports") or []
        if not configured or m.get("present") is False:
            continue
        live_count = sum(1 for x in links if m["fpc"] in (x["local_fpc"], x["remote_fpc"]) and x["state"] == "up")
        # Live link port names (vcp-255/1/0) need not match configured names (et-0/1/0):
        # only the configured ports beyond the live link count are reported down.
        unmatched = [p for p in configured if (m["fpc"], p) not in used_ports]
        for port in unmatched[: max(0, len(configured) - live_count)]:
            links.append(
                {
                    "local_fpc": m["fpc"],
                    "local_port": port,
                    "remote_fpc": None,
                    "remote_port": "",
                    "state": "down",
                    "speed": "",
                    "source": "Configured VC port with no live link",
                }
            )
            used_ports.add((m["fpc"], port))
    for ev in open_port_downs or []:
        fpc = ev.get("fpc")
        port = ev.get("port") or ""
        if (fpc, port) in used_ports:
            continue
        if fpc is not None and fpc not in present_fpcs:
            continue
        links.append(
            {
                "local_fpc": fpc,
                "local_port": port,
                "remote_fpc": None,
                "remote_port": "",
                "state": "down",
                "speed": "",
                "source": "SW_VC_PORT_DOWN event with no recovery",
                "since": ev.get("timestamp"),
            }
        )
        used_ports.add((fpc, port))
    return links


def classify_topology(members: list[dict], links: list[dict]) -> dict:
    present = [m["fpc"] for m in members if m.get("present") is not False and m["fpc"] is not None]
    up = [x for x in links if x["state"] == "up" and x["local_fpc"] is not None and x["remote_fpc"] is not None]
    if len(present) <= 1:
        return {"kind": "single", "label": "Single member", "redundant": False, "components": 1}
    if not up:
        return {"kind": "unknown", "label": "Link data not reported", "redundant": None, "components": None}
    degree = {f: 0 for f in present}
    adj: dict[int, set[int]] = {f: set() for f in present}
    for x in up:
        a, b = x["local_fpc"], x["remote_fpc"]
        if a in degree and b in degree and a != b:
            degree[a] += 1
            degree[b] += 1
            adj[a].add(b)
            adj[b].add(a)
    # connected components
    comps = 0
    seen: set[int] = set()
    for f in present:
        if f in seen:
            continue
        comps += 1
        stack = [f]
        while stack:
            cur = stack.pop()
            if cur in seen:
                continue
            seen.add(cur)
            stack.extend(adj[cur] - seen)
    if comps > 1:
        return {
            "kind": "split",
            "label": f"Split into {comps} islands",
            "redundant": False,
            "components": comps,
        }
    if all(d >= 2 for d in degree.values()):
        return {"kind": "ring", "label": "Ring (redundant VC links)", "redundant": True, "components": 1}
    return {"kind": "chain", "label": "Daisy chain (no link redundancy)", "redundant": False, "components": 1}


# --------------------------------------------------------------------------- events / alarms
def event_kind(event_type: str) -> str:
    t = str(event_type or "").upper()
    if "VC" in t or "VIRTUAL_CHASSIS" in t or "MASTER" in t or "SWITCHOVER" in t:
        return "vc"
    if "RESTART" in t or "REBOOT" in t:
        return "reboot"
    if any(k in t for k in ("PSU", "PEM", "POWER_SUPPLY", "FAN", "TEMP", "HOT", "CHASSIS", "FPC")):
        return "environment"
    if "CONFIG" in t or "UPGRADE" in t:
        return "config"
    if "DISCONNECTED" in t or "CONNECTED" in t:
        return "connectivity"
    return "other"


def relevant_event(event_type: str) -> bool:
    t = str(event_type or "").upper()
    return any(k in t for k in _EVENT_KEYWORDS)


def friendly_event(event_type: str) -> str:
    t = str(event_type or "").upper()
    names = {
        "SW_VC_PORT_DOWN": "VC port went down",
        "SW_VC_PORT_UP": "VC port came up",
        "SW_VC_IN_TRANSITION": "Stack in transition",
        "SW_VC_STABLE": "Stack stable",
        "SW_RESTARTED": "Switch restarted",
        "SW_CONFIG_FAILED": "Configuration failed",
        "SW_CONFIGURED": "Configuration applied",
        "SW_DISCONNECTED": "Switch disconnected",
        "SW_CONNECTED": "Switch connected",
    }
    if t in names:
        return names[t]
    words = t.replace("SW_", "").replace("_", " ").strip().lower()
    return words[:1].upper() + words[1:] if words else "Event"


def _event_macs(ev: dict) -> set[str]:
    macs = {clean_mac(ev.get(k)) for k in ("mac", "device_mac", "vc_mac", "member_mac")}
    for key in ("macs", "switches"):
        for v in _list(ev.get(key)):
            if isinstance(v, str):
                macs.add(clean_mac(v))
    macs.discard("")
    return macs


def stack_events(
    events: list[dict], macs: set[str], device_id: str = "", fpc_by_mac: dict[str, int] | None = None
) -> list[dict]:
    out = []
    for ev in events:
        if not isinstance(ev, dict):
            continue
        if not (_event_macs(ev) & macs or (device_id and str(ev.get("device_id") or "") == device_id)):
            continue
        etype = str(ev.get("type") or ev.get("event_type") or "")
        if not relevant_event(etype):
            continue
        port = str(ev.get("port_id") or ev.get("port") or "")
        fpc = _int(ev.get("fpc") if ev.get("fpc") is not None else ev.get("member"))
        if fpc is None and port:
            fpc = _port_fpc(port)
        if fpc is None and fpc_by_mac:
            fpc = next((fpc_by_mac[x] for x in _event_macs(ev) if x in fpc_by_mac), None)
        if fpc is None:
            m = re.search(r"\b(?:fpc|member)\s*(\d+)", str(ev.get("text") or ""), re.IGNORECASE)
            fpc = int(m.group(1)) if m else None
        out.append(
            {
                "timestamp": _epoch(ev.get("timestamp")),
                "type": etype,
                "label": friendly_event(etype),
                "kind": event_kind(etype),
                "fpc": fpc,
                "port": port,
                "text": str(ev.get("text") or ev.get("reason") or "")[:300],
            }
        )
    out.sort(key=lambda e: e["timestamp"], reverse=True)
    return out


def open_vc_port_downs(events: list[dict]) -> list[dict]:
    """SW_VC_PORT_DOWN events with no later SW_VC_PORT_UP for the same member/port."""
    latest: dict[tuple, dict] = {}
    for ev in sorted(events, key=lambda e: e["timestamp"]):
        t = ev["type"].upper()
        if t not in {"SW_VC_PORT_DOWN", "SW_VC_PORT_UP"}:
            continue
        latest[(ev.get("fpc"), ev.get("port"))] = ev
    return [ev for ev in latest.values() if ev["type"].upper() == "SW_VC_PORT_DOWN"]


def alarm_open(row: dict) -> bool:
    status = str(row.get("status") or row.get("state") or "").lower()
    if status in {"resolved", "clear", "cleared", "closed", "inactive"}:
        return False
    return not _epoch(row.get("resolved_time"))


def stack_alarms(alarms: list[dict], macs: set[str], name: str, site_id: str) -> list[dict]:
    out = []
    lname = name.strip().lower()
    for a in alarms:
        if not isinstance(a, dict) or not alarm_open(a):
            continue
        if site_id and a.get("site_id") and str(a.get("site_id")) != site_id:
            continue
        amacs = _event_macs(a)
        hostnames = {str(h).strip().lower() for h in _list(a.get("hostnames")) if isinstance(h, str)}
        if not (amacs & macs or (lname and lname in hostnames)):
            continue
        atype = str(a.get("type") or "")
        out.append(
            {
                "type": atype,
                "label": friendly_event(atype),
                "severity": str(a.get("severity") or "warn").lower(),
                "timestamp": _epoch(a.get("timestamp") or a.get("last_seen")),
                "count": _int(a.get("count")) or 1,
                "acked": bool(a.get("acked")),
            }
        )
    out.sort(key=lambda x: x["timestamp"], reverse=True)
    return out


# --------------------------------------------------------------------------- assessment
def _fmt_age(seconds: float | int | None) -> str:
    if seconds is None:
        return "unknown"
    s = int(seconds)
    if s < 3600:
        return f"{max(1, s // 60)} min"
    if s < 86400:
        return f"{s // 3600} h"
    return f"{s // 86400} d"


def assess_stack(
    stat: dict,
    *,
    live_vc: dict | None = None,
    config: dict | None = None,
    events: list[dict] | None = None,
    alarms: list[dict] | None = None,
    site_name: str = "",
    now: float | None = None,
) -> dict:
    """Full health picture of one stack. ``events``/``alarms`` are the raw Mist rows."""
    now = now or time.time()
    stat = _dict(stat)
    members = merge_members(stat, live_vc, config)
    macs = {m["mac"] for m in members if m["mac"]} | {clean_mac(stat.get("mac")), clean_mac(stat.get("vc_mac"))}
    macs.discard("")
    name = str(
        stat.get("name") or stat.get("hostname") or _dict(config).get("name") or f"VC {clean_mac(stat.get('mac'))}"
    )
    site_id = str(stat.get("site_id") or "")
    device_id = str(stat.get("id") or stat.get("device_id") or "")
    fpc_by_mac = {m["mac"]: m["fpc"] for m in members if m["mac"] and m["fpc"] is not None}
    evs = stack_events(events or [], macs, device_id, fpc_by_mac)
    open_downs = open_vc_port_downs(evs)
    links = build_links(members, open_downs)
    topology = classify_topology(members, links)
    alarm_rows = stack_alarms(alarms or [], macs, name, site_id)

    issues: list[dict] = []

    def add(sev: str, code: str, text: str, fpc: int | None = None) -> None:
        issues.append({"severity": sev, "code": code, "text": text, "fpc": fpc})

    status = str(stat.get("status") or "").lower()
    offline = status in {"disconnected", "offline", "down"} or stat.get("connected") is False
    if offline:
        seen = _epoch(stat.get("last_seen"))
        add(
            "critical",
            "offline",
            f"Stack is offline in Mist{f' (last seen {_fmt_age(now - seen)} ago)' if seen else ''}.",
        )
    elif status in {"restarting", "upgrading"}:
        add("warning", "transition", f"Stack is {status}.")

    present = [m for m in members if m["present"] is not False]
    missing = [m for m in members if m["present"] is False]
    for m in missing:
        why = "configured but never joined" if m.get("configured_only") else (m["vc_state"] or "not present")
        add("critical", "member_missing", f"FPC {m['fpc']} is not present ({why}).", m["fpc"])

    masters = [m for m in present if m["role"] == "master"]
    backups = [m for m in present if m["role"] == "backup"]
    if len(members) >= 2 and not masters:
        add("critical", "no_master", "No member reports the master routing-engine role.")
    if len(masters) > 1:
        add(
            "critical",
            "split_brain",
            "More than one master reported (FPC "
            + ", ".join(str(m["fpc"]) for m in masters)
            + "): possible split stack.",
        )
    if len(members) >= 2 and masters and not backups:
        add(
            "warning",
            "no_backup",
            f"No backup routing engine. If FPC {masters[0]['fpc']} fails the stack goes down.",
        )

    down_links = [x for x in links if x["state"] == "down"]
    for x in down_links:
        add("warning", "vcp_down", f"VC port {x['local_port'] or '?'} on FPC {x['local_fpc']} is down.", x["local_fpc"])
    if topology["kind"] == "split":
        add("critical", "split", f"VC links leave the stack {topology['label'].lower()}.")
    elif topology["kind"] == "chain" and len(present) >= 3:
        add("info", "chain", "Stack is cabled as a daisy chain: one more VC link failure will split it.")

    versions = sorted({m["version"] for m in present if m["version"]})
    if len(versions) > 1 or stat.get("fw_versions_outofsync") is True:
        detail = ", ".join(
            f"{v} on FPC " + "/".join(str(m["fpc"]) for m in present if m["version"] == v) for v in versions
        )
        add("warning", "mixed_firmware", f"Members run different firmware ({detail or 'Mist reports out of sync'}).")
    pending = [m for m in present if m["pending_version"] and m["pending_version"] != m["version"]]
    if pending:
        add(
            "info",
            "pending_upgrade",
            "Firmware staged but not active on FPC " + ", ".join(str(m["fpc"]) for m in pending) + ".",
        )

    for m in present:
        for p in m["psus"]:
            if p["status"] == "bad":
                add("critical", "psu", f"FPC {m['fpc']} {p['name']} reports {p['raw'] or 'a fault'}.", m["fpc"])
        bad_fans = [f for f in m["fans"] if f["status"] == "bad"]
        if bad_fans:
            add(
                "warning",
                "fan",
                f"FPC {m['fpc']} fan fault: " + ", ".join(f"{f['name']} ({f['raw']})" for f in bad_fans) + ".",
                m["fpc"],
            )
        hot = [t for t in m["temperatures"] if t["status"] == "bad" or (t["celsius"] or 0) >= 70]
        if hot:
            t = max(hot, key=lambda x: x["celsius"] or 0)
            sev = "critical" if (t["celsius"] or 0) >= 85 or t["status"] == "bad" else "warning"
            add(
                sev,
                "temperature",
                f"FPC {m['fpc']} {t['name']} at {t['celsius']:g} °C."
                if t["celsius"] is not None
                else f"FPC {m['fpc']} {t['name']} temperature alarm.",
                m["fpc"],
            )
        if m["cpu"] is not None and m["cpu"] >= 85:
            add("warning", "cpu", f"FPC {m['fpc']} CPU at {m['cpu']:.0f}%.", m["fpc"])
        if m["memory"] is not None and m["memory"] >= 85:
            add("warning", "memory", f"FPC {m['fpc']} memory at {m['memory']:.0f}%.", m["fpc"])
        if m["uptime"] is not None and m["uptime"] < 86400 and not offline:
            add("warning", "recent_reboot", f"FPC {m['fpc']} rebooted {_fmt_age(m['uptime'])} ago.", m["fpc"])
        poe = m["poe"] or {}
        if poe.get("max_power") and poe.get("power_draw") is not None and poe["power_draw"] >= 0.9 * poe["max_power"]:
            add(
                "info",
                "poe_budget",
                f"FPC {m['fpc']} PoE at {poe['power_draw'] / poe['max_power'] * 100:.0f}% of budget.",
                m["fpc"],
            )

    # Preprovisioned config vs what is physically in the stack.
    vc_cfg = _dict(_dict(config).get("virtual_chassis"))
    cfg_members = [x for x in _list(vc_cfg.get("members")) if isinstance(x, dict)]
    preprovisioned = vc_cfg.get("preprovisioned")
    if cfg_members:
        cfg_macs = {clean_mac(x.get("mac")) for x in cfg_members if clean_mac(x.get("mac"))}
        live_macs = {m["mac"] for m in members if m["mac"] and not m.get("configured_only")}
        extra = sorted(live_macs - cfg_macs) if live_macs else []
        if extra:
            add("warning", "config_mismatch", f"{len(extra)} member(s) in the stack are not in the VC configuration.")
        for cfg in cfg_members:
            idx = fpc_index(cfg)
            mac = clean_mac(cfg.get("mac"))
            live = next((m for m in members if m["fpc"] == idx and not m.get("configured_only")), None)
            if live and mac and live["mac"] and live["mac"] != mac:
                add(
                    "warning",
                    "config_mismatch",
                    f"FPC {idx} is configured as {mac} but {live['mac']} is installed.",
                    idx,
                )
            cfg_role = normalize_role(cfg.get("vc_role"))
            if live and cfg_role in {"master", "backup", "linecard"} and live["role"] and live["role"] != cfg_role:
                if cfg_role in {"master", "backup"} and live["role"] in {"master", "backup"}:
                    add(
                        "info",
                        "role_swapped",
                        f"FPC {idx} is configured as {cfg_role} but is currently {live['role']} (after a switchover).",
                        idx,
                    )
                else:
                    add(
                        "warning",
                        "role_mismatch",
                        f"FPC {idx} is configured as {cfg_role} but runs as {live['role']}.",
                        idx,
                    )

    config_status = str(stat.get("config_status") or "").lower()
    if config_status in {"failed", "error"}:
        add("critical", "config_failed", "Mist reports the last configuration push failed.")
    elif config_status in {"pending", "in_progress"}:
        add("info", "config_pending", "A configuration push is pending.")
    else:
        cfg_events = [e for e in evs if e["kind"] == "config"]
        if cfg_events and "FAIL" in cfg_events[0]["type"].upper():
            add("warning", "config_failed", f"Most recent configuration event: {cfg_events[0]['label'].lower()}.")

    reboots = [e for e in evs if e["kind"] == "reboot"]
    switchovers = [
        e
        for e in evs
        if any(k in e["type"].upper() for k in ("MASTER", "SWITCHOVER", "ROLE_CHANGE", "ROLE_CHANGED", "IN_TRANSITION"))
    ]
    if switchovers:
        add(
            "warning", "switchover", f"{len(switchovers)} master change / stack transition event(s) in the last 7 days."
        )
    if reboots and not any(i["code"] == "recent_reboot" for i in issues):
        add("info", "reboots_7d", f"{len(reboots)} restart event(s) in the last 7 days.")
    for a in alarm_rows[:5]:
        sev = "critical" if a["severity"] in {"critical", "major"} else "warning"
        add(sev if not a["acked"] else "info", "alarm", f"Open alarm: {a['label']}.")

    score = sum(SEV_WEIGHT.get(i["severity"], 0) + CODE_WEIGHT.get(i["code"], 0) for i in issues)
    worst = max((SEV_RANK[i["severity"]] for i in issues), default=0)
    severity = {3: "critical", 2: "warning", 1: "info", 0: "ok"}[worst]
    issues.sort(key=lambda i: -SEV_RANK[i["severity"]])

    verdicts = _verdicts(members, present, masters, backups, versions, topology, down_links, offline)
    env_bad = sum(1 for i in issues if i["code"] in {"psu", "fan", "temperature"})
    return {
        "device_id": device_id,
        "site_id": site_id,
        "site_name": site_name,
        "name": name,
        "model": str(stat.get("model") or (members[0]["model"] if members else "")),
        "mac": clean_mac(stat.get("mac")),
        "vc_mac": clean_mac(stat.get("vc_mac")),
        "status": status or "unknown",
        "ip": str(stat.get("ip") or _dict(stat.get("ip_stat")).get("ip") or ""),
        "version": str(stat.get("version") or ""),
        "uptime": _int(stat.get("uptime")),
        "last_seen": _epoch(stat.get("last_seen")) or None,
        "preprovisioned": preprovisioned if isinstance(preprovisioned, bool) else None,
        "member_count": len(members),
        "present_count": len(present),
        "master_fpc": masters[0]["fpc"] if masters else None,
        "backup_fpc": backups[0]["fpc"] if backups else None,
        "versions": versions,
        "members": members,
        "links": links,
        "topology": topology,
        "events": evs[:80],
        "alarms": alarm_rows,
        "issues": issues,
        "severity": severity,
        "score": score,
        "verdicts": verdicts,
        "counts": {
            "members_missing": len(missing),
            "vcp_down": len(down_links),
            "no_backup": int(any(i["code"] == "no_backup" for i in issues)),
            "mixed_firmware": int(any(i["code"] == "mixed_firmware" for i in issues)),
            "offline": int(offline),
            "env_alarms": env_bad,
            "recent_reboots": max(len(reboots), sum(1 for i in issues if i["code"] == "recent_reboot")),
            "switchovers": len(switchovers),
            "config_issues": sum(1 for i in issues if i["code"].startswith("config") or i["code"] == "role_mismatch"),
            "alarms": len(alarm_rows),
        },
    }


def _verdicts(members, present, masters, backups, versions, topology, down_links, offline) -> list[dict]:
    out = []
    if offline:
        out.append(
            {
                "topic": "Reachability",
                "level": "critical",
                "text": "Mist cannot reach this stack. The data below is the last report Mist received.",
            }
        )
    if len(members) <= 1:
        out.append(
            {
                "topic": "Redundancy",
                "level": "info",
                "text": "Single-member chassis: there is no control-plane redundancy to evaluate.",
            }
        )
    elif not masters:
        out.append(
            {
                "topic": "Redundancy",
                "level": "critical",
                "text": "No master routing engine is reported. The stack may be re-electing or split.",
            }
        )
    elif not backups:
        out.append(
            {
                "topic": "Redundancy",
                "level": "warning",
                "text": f"No backup routing engine — if FPC {masters[0]['fpc']} fails the stack goes down.",
            }
        )
    else:
        out.append(
            {
                "topic": "Redundancy",
                "level": "ok",
                "text": f"Master FPC {masters[0]['fpc']} with backup FPC {backups[0]['fpc']}: the stack survives the loss of either routing engine.",
            }
        )
    if not versions:
        out.append({"topic": "Firmware", "level": "info", "text": "Members did not report firmware versions."})
    elif len(versions) == 1:
        out.append({"topic": "Firmware", "level": "ok", "text": f"All present members run {versions[0]}."})
    else:
        majority = max(versions, key=lambda v: sum(1 for m in present if m["version"] == v))
        odd = [m for m in present if m["version"] and m["version"] != majority]
        out.append(
            {
                "topic": "Firmware",
                "level": "warning",
                "text": "Mixed firmware: "
                + ", ".join(f"FPC {m['fpc']} runs {m['version']}" for m in odd)
                + f" while the rest run {majority}. Members on different releases can drop out of the stack or fail to rejoin after a reboot.",
            }
        )
    kind = topology["kind"]
    if kind == "ring":
        txt = "VC links form a ring: any single VC link can fail without splitting the stack."
        lvl = "ok"
        if down_links:
            txt = f"Ring cabling with {len(down_links)} VC port(s) down: redundancy is reduced until it is restored."
            lvl = "warning"
        out.append({"topic": "Topology", "level": lvl, "text": txt})
    elif kind == "chain":
        out.append(
            {
                "topic": "Topology",
                "level": "warning",
                "text": "VC links form a daisy chain: losing any one inter-member link splits the stack. Close the ring between the end members."
                + (f" {len(down_links)} VC port(s) are down." if down_links else ""),
            }
        )
    elif kind == "split":
        out.append(
            {
                "topic": "Topology",
                "level": "critical",
                "text": f"The stack is {topology['label'].lower()}: members on different islands cannot forward traffic between them.",
            }
        )
    elif kind == "unknown":
        out.append(
            {"topic": "Topology", "level": "info", "text": "Mist did not report VC link details for this stack."}
        )
    missing = [m for m in members if m["present"] is False]
    if missing:
        out.append(
            {
                "topic": "Membership",
                "level": "critical",
                "text": "FPC "
                + ", ".join(str(m["fpc"]) for m in missing)
                + " not present: ports on those members are down.",
            }
        )
    return out


# --------------------------------------------------------------------------- data collection
def _summary(row: dict) -> dict:
    """List-view row: everything except the bulky per-member detail."""
    keep = {k: v for k, v in row.items() if k not in {"members", "links", "events"}}
    keep["members_brief"] = [
        {"fpc": m["fpc"], "role": m["role"], "present": m["present"], "version": m["version"], "model": m["model"]}
        for m in row["members"]
    ]
    keep["last_event"] = row["events"][0] if row["events"] else None
    keep["top_issue"] = row["issues"][0]["text"] if row["issues"] else ""
    return keep


def _events_for(client, site_id: str | None, duration: str = "7d", limit: int = 1000) -> list[dict]:
    org = client.settings.org_id
    from app.services.mist_client import _path_id

    path = (
        f"/api/v1/sites/{_path_id(site_id, 'site ID')}/devices/events/search"
        if site_id
        else f"/api/v1/orgs/{org}/devices/events/search"
    )
    payload = client.get(path, {"duration": duration, "device_type": "switch", "sort": "-timestamp", "limit": limit})
    data = payload.get("results") if isinstance(payload, dict) else payload
    return [x for x in data if isinstance(x, dict)] if isinstance(data, list) else []


def collect_overview(client, site_id: str | None = None, site_names: dict | None = None) -> dict:
    """Org or site overview of every stack, ranked worst first."""
    site_id = site_id if site_id and site_id != "all" else None
    warnings: list[str] = []
    with ThreadPoolExecutor(max_workers=4, thread_name_prefix="vc-overview") as pool:
        stats_f = pool.submit(client.list_org_device_stats, "switch", site_id=site_id)
        alarms_f = pool.submit(client.search_org_alarms, duration="1d", limit=2000)
        events_f = pool.submit(_events_for, client, site_id)
        cfg_f = pool.submit(client.list_site_devices, site_id, "switch") if site_id else None
        stats = stats_f.result()  # required; errors propagate
        try:
            alarms = alarms_f.result()
        except MistApiError as exc:
            alarms = []
            warnings.append(f"Alarms unavailable: {exc}")
        try:
            events = events_f.result()
        except MistApiError as exc:
            events = []
            warnings.append(f"Device events unavailable: {exc}")
        configs: dict[str, dict] = {}
        if cfg_f is not None:
            try:
                configs = {str(d.get("id") or ""): d for d in cfg_f.result()}
            except MistApiError as exc:
                warnings.append(f"Switch configuration unavailable: {exc}")
    return build_overview(stats, alarms, events, configs, site_id=site_id, site_names=site_names, warnings=warnings)


def build_overview(
    stats: list[dict],
    alarms: list[dict],
    events: list[dict],
    configs: dict[str, dict] | None = None,
    *,
    site_id: str | None = None,
    site_names: dict | None = None,
    warnings: list[str] | None = None,
    now: float | None = None,
) -> dict:
    names = site_names or {}
    rows = []
    for stat in stats:
        if not isinstance(stat, dict) or not is_stack(stat):
            continue
        if site_id and str(stat.get("site_id") or "") != site_id:
            continue
        cfg = (configs or {}).get(str(stat.get("id") or ""))
        row = assess_stack(
            stat,
            config=cfg,
            events=events,
            alarms=alarms,
            site_name=str(names.get(str(stat.get("site_id") or "")) or ""),
            now=now,
        )
        rows.append(_summary(row))
    rows.sort(key=lambda r: (-SEV_RANK[r["severity"]], -r["score"], r["site_name"].lower(), r["name"].lower()))
    totals = {
        "stacks": len(rows),
        "critical": sum(1 for r in rows if r["severity"] == "critical"),
        "warning": sum(1 for r in rows if r["severity"] == "warning"),
        "healthy": sum(1 for r in rows if r["severity"] in {"ok", "info"}),
        "members": sum(r["member_count"] for r in rows),
        "sites": len({r["site_id"] for r in rows}),
    }
    for key in (
        "members_missing",
        "vcp_down",
        "no_backup",
        "mixed_firmware",
        "offline",
        "env_alarms",
        "recent_reboots",
        "switchovers",
        "config_issues",
        "alarms",
    ):
        totals[key] = sum(r["counts"][key] for r in rows)
    return {
        "scope": "site" if site_id else "org",
        "site_id": site_id or "",
        "generated_at": int((now or time.time()) * 1000),
        "totals": totals,
        "stacks": rows,
        "warnings": warnings or [],
    }


_SOURCE_LABELS = {"live": "Live VC view", "config": "Device config", "events": "Device events", "alarms": "Alarms"}


def collect_stack(client, site_id: str, device_id: str, site_name: str = "") -> dict:
    """Rich detail for one stack."""
    warnings: list[str] = []
    with ThreadPoolExecutor(max_workers=5, thread_name_prefix="vc-health") as pool:
        futures = {
            "stat": pool.submit(client.get_site_device_stats, site_id, device_id),
            "live": pool.submit(client.get_site_virtual_chassis, site_id, device_id),
            "config": pool.submit(client.get_site_device, site_id, device_id),
            "events": pool.submit(_events_for, client, site_id, "7d", 1000),
            "alarms": pool.submit(client.search_org_alarms, duration="1d", limit=2000),
        }
        got: dict[str, Any] = {}
        for key, fut in futures.items():
            try:
                got[key] = fut.result()
            except MistApiError as exc:
                got[key] = [] if key in {"events", "alarms"} else {}
                if key == "stat":
                    raise
                warnings.append(f"{_SOURCE_LABELS[key]} unavailable: {exc}")
    stat = dict(got["stat"] or {})
    stat.setdefault("id", device_id)
    stat.setdefault("site_id", site_id)
    row = assess_stack(
        stat,
        live_vc=got["live"],
        config=got["config"],
        events=got["events"],
        alarms=got["alarms"],
        site_name=site_name,
    )
    row["warnings"] = warnings
    return row


# --------------------------------------------------------------------------- sample (no Mist)
def sample_stats_from_vcs(vcs: list[dict], now: float | None = None) -> tuple[list[dict], list[dict]]:
    """Synthetic switch stats + events built from the built-in demo VCs (clearly flagged sample)."""
    now = now or time.time()
    stats, events = [], []
    for n, vc in enumerate(vcs):
        mods = []
        members = sorted(vc.get("members") or [], key=lambda m: m.get("member_id", 0))
        count = len(members)
        for i, m in enumerate(members):
            fpc = int(m.get("member_id", i))
            nxt = members[(i + 1) % count].get("member_id", (i + 1) % count) if count > 1 else None
            prv = members[(i - 1) % count].get("member_id", (i - 1) % count) if count > 1 else None
            links = []
            if count > 1:
                links.append({"port_id": "vcp-255/1/0", "neighbor_module_idx": nxt, "neighbor_port_id": "vcp-255/1/1"})
                links.append({"port_id": "vcp-255/1/1", "neighbor_module_idx": prv, "neighbor_port_id": "vcp-255/1/0"})
            mods.append(
                {
                    "_idx": fpc,
                    "mac": m.get("mac"),
                    "serial": m.get("serial"),
                    "model": m.get("model"),
                    "version": m.get("version"),
                    "vc_role": m.get("vc_role"),
                    "vc_state": "present",
                    "uptime": 86400 * (20 + n * 3 + i),
                    "temperatures": [{"name": "CPU Sensor", "celsius": 44 + i * 2, "status": "ok"}],
                    "fans": [{"name": "Fan 1", "status": "ok", "airflow": "out"}],
                    "psus": [{"name": "Power Supply 0", "status": "ok"}, {"name": "Power Supply 1", "status": "ok"}],
                    "poe": {"max_power": 1800, "power_draw": 420 + 37 * i},
                    "vc_links": links,
                    "pics": [{"index": 0, "port_groups": [{"count": 48, "type": "ge"}]}],
                }
            )
        stats.append(
            {
                "id": vc.get("device_id"),
                "site_id": vc.get("site_id"),
                "mac": vc.get("vc_mac"),
                "vc_mac": vc.get("vc_mac"),
                "name": vc.get("name"),
                "model": vc.get("model"),
                "status": "connected" if str(vc.get("status") or "").lower() == "connected" else "disconnected",
                "version": next((m.get("version") for m in members if m.get("vc_role") == "master"), ""),
                "uptime": 86400 * 20,
                "cpu_stat": {"idle": 82},
                "memory_stat": {"usage": 46},
                "module_stat": mods,
            }
        )
    return stats, events
