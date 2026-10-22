"""Mist alerts capability (see app/integrations/contracts.py).

Turns Mist's org alarm search, open device-event triggers and devices that are disconnected right now
into vendor-neutral :class:`~app.integrations.domain.Alert` records. Rules (v0.10.16):

* **Stable keys** — ``type + site + device (+ port)``, never an alarm id or a timestamp, so local triage
  (acknowledge / snooze / dismiss / mute) survives refreshes and Mist re-raising the same condition
  under a new alarm id. Several Mist alarms for the same thing merge into one alert (ids kept in
  ``vendor["alarm_ids"]`` for acknowledgement).
* **One alert per device** — Mist aggregates infrastructure alarms per site (``switches: [mac, …]``);
  each named device becomes its own alert so the device name, link and current state are known.
* **Devices down now** — every AP/switch/gateway Mist reports disconnected is one alert; disconnect
  alarms/events for the same device merge into it (no double counting).
* **Possibly resolved** — a disconnect alarm for a device that is connected now, or any alarm not seen
  for 24 h whose device is connected now, is flagged ``vendor["possibly_resolved"]``.
* **Flapping** — 3+ down/up transitions of the same device/port inside the event window set
  ``vendor["flaps"]``.
"""

from __future__ import annotations

import json
import threading
import time
from collections import OrderedDict, defaultdict
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable

from app.integrations.contracts import ALERTS, ALERTS_ACK
from app.integrations.domain import Alert, normalize_mac, stable_key

# Readable "reported by Mist" facts (field_rows over the whole alarm) are the expensive part of a
# build and are only shown when someone opens an incident, so they are built lazily: an alert keeps
# its parts here and :func:`hydrate_facts` replays the exact eager algorithm on demand. Results are
# memoised per exact alarm content, so a 20 s refresh never re-renders an unchanged alarm.
_PENDING: dict[str, list[tuple[Callable[[], list[dict]], dict, dict]]] = {}
_REPORTED_MEMO: OrderedDict[tuple[str, str], list[dict]] = OrderedDict()
_MEMO_MAX = 50_000
_MEMO_LOCK = threading.Lock()
EAGER_FACTS = False  # True = build every alert's facts up front (the pre-v0.10.16 behaviour; used by tests)

STALE_ALARM_S = 24 * 3600  # alarm not seen for this long + device connected now → possibly resolved
FLAP_THRESHOLD = 3
MAX_SPLIT = 200  # an alarm naming more devices than this stays a single alert

_DISCONNECT_TOKENS = ("disconnected", "offline", "device_down", "switch_down", "gateway_down", "ap_down")
_RECOVERY_SUFFIXES = ("_UP", "_CONNECTED", "_CLEAR", "_CLEARED", "_RECOVERY", "_RECOVERED", "_STABLE", "_RECONNECTED")
_ROLE = {"ap": "wireless_ap", "switch": "switch", "gateway": "sdwan_edge"}
_ROLE_LIST_KEYS = (("switches", "switch"), ("aps", "ap"), ("gateways", "gateway"))

# NodeWatch display groups (legacy Command Center categories) → vendor-neutral category.
_CATEGORY = {
    "Virtual Chassis": "switching",
    "Connectivity / Availability": "connectivity",
    "Switching / Interfaces": "switching",
    "Routing / WAN": "routing",
    "Power / Hardware": "hardware",
    "Security": "security",
    "Authentication / NAC": "authentication",
    "Wireless / RF": "wireless",
    "Network Services": "services",
    "Configuration / Software": "configuration",
    "Clients / Experience": "clients",
    "Marvis / AI Anomalies": "other",
}


def is_disconnect_type(value: str) -> bool:
    t = str(value or "").lower()
    if t.endswith("_currently_down"):
        return True
    if "port" in t or "tunnel" in t or "bgp" in t or "vpn" in t or "peer" in t or "member" in t:
        return False
    return any(tok in t for tok in _DISCONNECT_TOKENS)


def _sev(value: Any, atype: str) -> str:
    raw = str(value or "").lower()
    if raw in {"critical", "error"}:
        return "critical"
    if raw in {"major", "high"}:
        return "major"
    if raw in {"warn", "warning", "minor", "medium"}:
        return "warning"
    if raw in {"info", "low", "informational"}:
        return "info"
    from app.services.dashboard_service import CRITICAL_EVENT_TYPES

    if atype.upper() in CRITICAL_EVENT_TYPES or is_disconnect_type(atype):
        return "critical"
    return "warning"


def friendly_type(value: str) -> str:
    t = str(value or "").strip()
    known = {
        "device_down": "AP offline",
        "switch_down": "Switch offline",
        "gateway_down": "Gateway offline",
        "sw_port_flap": "Switch port flapping",
        "port_flap": "Port flapping",
        "bad_cable": "Bad cable",
        "ap_bad_cable": "AP bad cable",
        "device_restarted": "Device restarted",
        "switch_restarted": "Switch restarted",
        "gateway_restarted": "Gateway restarted",
        "rogue_ap": "Rogue AP",
        "honeypot_ssid": "Honeypot SSID",
        "switch_stp_loop": "STP loop",
        "sw_alarm_chassis_poe": "PoE controller alarm",
        "sw_alarm_chassis_psu": "Power supply alarm",
        "sw_alarm_chassis_fan": "Fan alarm",
        "sw_alarm_chassis_hot": "Chassis over temperature",
        "gw_bgp_neighbor_down": "BGP neighbor down",
        "gw_tunnel_down": "Tunnel down",
        "gw_vpn_path_down": "VPN path down",
        "sw_dhcp_pool_exhausted": "DHCP pool exhausted",
        "gw_dhcp_pool_exhausted": "DHCP pool exhausted",
        "vc_member_deleted": "VC member removed",
        "vc_master_changed": "VC primary changed",
        "high_cpu": "High CPU",
        "dhcp_failure": "DHCP failures",
        "dns_failure": "DNS failures",
        "missing_vlan": "Missing VLAN",
        "negotiation_mismatch": "Speed/duplex mismatch",
    }
    if t.lower() in known:
        return known[t.lower()]
    up = t.upper()
    for prefix, word in (("SW_", "Switch "), ("AP_", "AP "), ("GW_", "Gateway ")):
        if up.startswith(prefix) and not up.endswith("_CURRENTLY_DOWN"):
            return word + up[len(prefix) :].replace("_", " ").lower()
    if t.upper().endswith("_CURRENTLY_DOWN"):
        role = t.upper().split("_")[0]
        return {"AP": "Access point", "SWITCH": "Switch", "GATEWAY": "Gateway"}.get(role, "Device") + " disconnected"
    return t.replace("_", " ").strip().capitalize() if t else "Alert"


def _macs(row: dict) -> list[tuple[str, str]]:
    """[(mac, role)] named by an alarm (switches/aps/gateways lists, or a single mac)."""
    out: list[tuple[str, str]] = []
    for key, role in _ROLE_LIST_KEYS:
        value = row.get(key)
        if isinstance(value, list):
            out += [(m, role) for m in (normalize_mac(v) for v in value if isinstance(v, str)) if m]
    single = normalize_mac(row.get("mac"))
    if single and all(single != m for m, _ in out):
        out.append((single, ""))
    return out


def _ports(row: dict) -> list[str]:
    value = row.get("port_ids") or row.get("ports") or ([row.get("port_id")] if row.get("port_id") else [])
    return [str(p) for p in value if p] if isinstance(value, list) else [str(value)]


def _reported(row: dict, definition: dict) -> list[dict]:
    """``dashboard_service._facts`` for one alarm/event, memoised by exact content (copies returned)."""
    from app.services import dashboard_service as ds

    try:
        key = (json.dumps(row, sort_keys=True, default=str), json.dumps(definition, sort_keys=True, default=str))
    except (TypeError, ValueError):
        key = None
    if key is not None:
        with _MEMO_LOCK:
            hit = _REPORTED_MEMO.get(key)
            if hit is not None:
                _REPORTED_MEMO.move_to_end(key)
                return [dict(f) for f in hit]
    facts = ds._facts(row, definition)
    for f in facts:
        f["group"] = "reported"
    if key is not None:
        with _MEMO_LOCK:
            _REPORTED_MEMO[key] = [dict(f) for f in facts]
            while len(_REPORTED_MEMO) > _MEMO_MAX:
                _REPORTED_MEMO.popitem(last=False)
    return facts


def _merge_facts(base: list[dict], other: list[dict]) -> list[dict]:
    labels = {(f["label"], str(f["value"])) for f in base}
    return base + [f for f in other if (f["label"], str(f["value"])) not in labels][:6]


def hydrate_facts(alert: Alert) -> list[dict]:
    """Complete ``alert.facts`` (evidence + reported) — identical to building them eagerly."""
    if alert.vendor.get("facts_complete", True):
        return alert.facts
    parts = _PENDING.get(alert.key)
    if not parts:
        return alert.facts
    full: list[dict] = []
    for i, (evidence_fn, row, definition) in enumerate(parts):
        piece = evidence_fn() + _reported(row, definition)
        full = piece if i == 0 else _merge_facts(full, piece)
    # (Device-down alerts, which receive inserted "Mist says"/"Reason" facts, are always complete.)
    alert.facts = full
    alert.vendor["facts_complete"] = True
    return alert.facts


def mist_alerts_from_payloads(
    *,
    alarms: list[dict],
    devices: list[dict],
    sites: list[dict],
    events: list[dict],
    definitions: list[dict],
    api_host: str = "",
    org_id: str = "",
    now: float | None = None,
) -> list[Alert]:
    """Pure translation (no I/O) — unit-tested with a fake 2,219-alarm organisation."""
    from app.modules.history.activity import mist_device_url
    from app.services import dashboard_service as ds
    from app.services.event_correlation import correlate_event_states, event_type

    now = now or time.time()
    site_names = {str(s.get("id")): str(s.get("name") or s.get("id")) for s in sites if s.get("id")}
    by_mac: dict[str, dict] = {}
    by_id: dict[str, dict] = {}
    for d in devices:
        m = normalize_mac(d.get("mac"))
        if m:
            by_mac[m] = d
        if d.get("id") or d.get("device_id"):
            by_id[str(d.get("id") or d.get("device_id"))] = d
    defs = {str(x.get("key") or x.get("type") or x.get("name") or ""): x for x in definitions}

    events_by_mac: dict[str, list[dict]] = defaultdict(list)
    transitions: dict[tuple[str, str], int] = defaultdict(int)
    for ev in events:
        if not isinstance(ev, dict):
            continue
        m = normalize_mac(ev.get("mac"))
        if m:
            events_by_mac[m].append(ev)
            et = event_type(ev).upper()
            if et.endswith(("_DOWN", "_DISCONNECTED", "_OFFLINE")):
                transitions[(m, str(ev.get("port_id") or ""))] += 1
    for rows in events_by_mac.values():
        rows.sort(key=ds._timestamp, reverse=True)

    down_by_site: dict[str, list[dict]] = defaultdict(list)
    for d in devices:
        if ds._is_down(d) and ds._device_type(d) in _ROLE:
            down_by_site[str(d.get("site_id") or "")].append({"device": ds._name_from_row(d), "mac": d.get("mac")})

    merged: dict[str, Alert] = {}
    # Per-build lookups: the same few types, sites and devices repeat across thousands of alarms.
    memo: dict[tuple, Any] = {}

    def once(key: tuple, fn):
        if key not in memo:
            memo[key] = fn()
        return memo[key]

    def device_facts(dev: dict, mac: str, sid: str, row: dict, skip_type: str) -> list[dict]:
        ev = ds._evidence(row, dev, mac=mac, site_id=sid, events_by_mac=events_by_mac, down_by_site=down_by_site)
        for f in ev:
            f["group"] = "evidence"
        return ev

    def add(alert: Alert) -> None:
        cur = merged.get(alert.key)
        if cur is None:
            merged[alert.key] = alert
            return
        cur_has, new_has = bool(cur.vendor.get("alarm_ids")), bool(alert.vendor.get("alarm_ids"))
        ids = list(dict.fromkeys(cur.vendor.get("alarm_ids", []) + alert.vendor.get("alarm_ids", [])))
        cur.vendor["alarm_ids"] = ids
        cur.native_id = cur.native_id or alert.native_id
        cur.count += alert.count
        cur.first_seen = (
            min(x for x in (cur.first_seen, alert.first_seen) if x) if (cur.first_seen or alert.first_seen) else None
        )
        cur.last_seen = max(cur.last_seen or 0, alert.last_seen or 0) or None
        # Only rows backed by a Mist alarm id carry Mist's ack state; an open device event (no id)
        # must never clear it. Acknowledged = every alarm behind the alert is acknowledged.
        if cur_has and new_has:
            cur.acknowledged = cur.acknowledged and alert.acknowledged
        elif new_has:
            cur.acknowledged = alert.acknowledged
        if cur.acknowledged:
            cur.acknowledged_by = cur.acknowledged_by or alert.acknowledged_by
        else:
            cur.acknowledged_by = ""
        if not cur.detail and alert.detail:
            cur.detail = alert.detail
        cur.facts = _merge_facts(cur.facts, alert.facts)  # evidence only here; reported facts are lazy
        cur.vendor["_parts"] = cur.vendor.get("_parts", []) + alert.vendor.get("_parts", [])
        if not alert.vendor.get("facts_complete", True):
            cur.vendor["facts_complete"] = False

    def make(
        *, atype: str, row: dict, sid: str, mac: str, role: str, port: str, definition: dict, origin: str, native: str
    ) -> Alert:
        dev = by_mac.get(mac) or by_id.get(str(row.get("device_id") or "")) or {}
        if not mac:
            mac = normalize_mac(dev.get("mac"))
        role = role or (ds._device_type(dev) if dev else "")
        sid = sid or str(dev.get("site_id") or "")
        site = site_names.get(sid, sid or "Organization-wide")
        hostnames = row.get("hostnames") if isinstance(row.get("hostnames"), list) else []
        name = str(dev.get("name") or dev.get("hostname") or "")
        if not name and mac and len(_macs(row)) == 1 and hostnames:
            name = str(hostnames[0])
        if not name and mac:
            name = ":".join(mac[i : i + 2] for i in range(0, 12, 2))
        if not name:
            name = ds._name_from_row({**dev, **row}) if (dev or row.get("impacted_entities")) else ""
        connected_now = None if not dev else not ds._is_down(dev)
        last = ds._epoch(row.get("last_seen")) or ds._timestamp(row)
        first = ds._epoch(row.get("timestamp")) or ds._epoch(row.get("created_time")) or last
        disconnect = is_disconnect_type(atype)
        possibly = bool(
            connected_now
            and (disconnect or (last and now - last > STALE_ALARM_S))
            and not atype.upper().endswith("_CURRENTLY_DOWN")
        )
        mist_group = str(row.get("group") or definition.get("group") or "")
        group = once(("group", atype, mist_group), lambda: ds._group_for_type(atype, mist_group))
        sev = _sev(row.get("severity") or definition.get("severity"), atype)
        title = str(definition.get("display") or definition.get("name") or row.get("title") or friendly_type(atype))
        key_parts = ("mist", "offline" if disconnect else atype.lower(), sid, mac or "", port if not disconnect else "")
        if not mac and atype.lower() not in {"rogue_ap", "rogue_client", "honeypot_ssid"}:
            ents = sorted(
                str(x.get("entity_mac") or x.get("entity_name") or "")
                for x in row.get("impacted_entities") or []
                if isinstance(x, dict)
            )
            key_parts = key_parts + tuple(ents[:20])
        wants_evidence = bool(dev or origin != "alarm")

        def evidence(dev=dev, mac=mac, sid=sid, row=row) -> list[dict]:
            return device_facts(dev, mac, sid, row, atype) if wants_evidence else []

        if origin == "status":  # device-down alerts: small in number, facts built now
            facts, parts = evidence(), []
        elif EAGER_FACTS:
            facts, parts = evidence() + _reported(row, definition), []
        else:  # evidence + reported details are built when someone opens the incident
            facts, parts = [], [(evidence, row, definition)]
        flaps = transitions.get((mac, port), 0) or (transitions.get((mac, ""), 0) if not port else 0)
        acked = bool(native) and bool(row.get("acked") or row.get("ack_time") or row.get("ack_admin_name"))
        return Alert(
            key=stable_key(*key_parts),
            source="mist",
            type=atype.upper() if origin == "status" else atype,
            category=_CATEGORY.get(group, "connectivity" if disconnect else "other"),
            severity="critical" if origin == "status" else sev,
            title=title,
            detail=ds._message_from_row(row)
            if origin != "status"
            else (
                f"Mist reports this device as disconnected; last seen {ds._age(last)} ago."
                if last
                else "Mist reports this device as disconnected."
            ),
            site_key=once(("site", sid), lambda: stable_key("site", "mist", sid)) if sid else "",
            site_name=site,
            device_key=once(("mac", mac), lambda: stable_key("mac", mac)) if mac else "",
            device_name=name,
            device_role=_ROLE.get(role, ""),
            interface=port,
            first_seen=first or None,
            last_seen=last or None,
            count=max(1, int(row.get("count") or 1)) if origin == "alarm" else 1,
            acknowledged=acked,
            acknowledged_by=str(row.get("ack_admin_name") or ("Mist" if acked else "")),
            native_id=native,
            console_url=once(
                ("url", sid, role, str(dev.get("id") or ""), mac),
                lambda: mist_device_url(
                    api_host, org_id, site_id=sid, device_type=role, device_id=str(dev.get("id") or ""), mac=mac
                ),
            ),
            facts=facts,
            vendor={
                "alarm_ids": [native] if native else [],
                "group": group,
                "mist_group": str(row.get("group") or definition.get("group") or ""),
                "device_type": role,
                "device_id": str(dev.get("id") or ""),
                "mac": mac,
                "site_id": sid,
                "connected_now": connected_now,
                "possibly_resolved": possibly,
                "flaps": flaps if flaps >= FLAP_THRESHOLD else 0,
                "definition": str(definition.get("description") or definition.get("desc") or ""),
                "origin": origin,
                "model": str(dev.get("model") or ""),
                "ip": str(dev.get("ip") or ""),
                "device_last_seen": ds._timestamp(dev) if dev else None,
                "entities": [x for x in (row.get("impacted_entities") or []) if isinstance(x, dict)][:50],
                "hostnames": [str(h) for h in hostnames[:50]],
                "ports": _ports(row)[:50],
                "facts_complete": not parts,
                "_parts": parts,
            },
        )

    down_now: dict[str, dict] = {}
    for d in devices:
        dtype = ds._device_type(d)
        m = normalize_mac(d.get("mac"))
        if dtype in _ROLE and ds._is_down(d) and m:
            down_now[m] = d
            add(
                make(
                    atype=f"{dtype.upper()}_CURRENTLY_DOWN",
                    row=d,
                    sid=str(d.get("site_id") or ""),
                    mac=m,
                    role=dtype,
                    port="",
                    definition={},
                    origin="status",
                    native="",
                )
            )

    def add_condition(atype: str, row: dict, origin: str, native: str) -> None:
        definition = defs.get(atype, {})
        sid = str(row.get("site_id") or "")
        targets = _macs(row)
        if len(targets) > MAX_SPLIT:
            targets = []
        ports = _ports(row)
        port = ports[0] if len(ports) == 1 else ""
        for mac, role in targets or [("", "")]:
            if mac and mac in down_now and is_disconnect_type(atype):
                # Same device, already listed as down now: merge ids/ack state/Mist text into that alert.
                status_key = stable_key("mist", "offline", str(down_now[mac].get("site_id") or ""), mac, "")
                target = merged.get(status_key)
                if target is not None:
                    if native:  # only alarm-backed rows take part in the acknowledged calculation
                        had_ids = bool(target.vendor["alarm_ids"])
                        target.vendor["alarm_ids"] = list(dict.fromkeys(target.vendor["alarm_ids"] + [native]))
                        target.native_id = target.native_id or native
                        acked = bool(row.get("acked") or row.get("ack_time") or row.get("ack_admin_name"))
                        target.acknowledged = (target.acknowledged and acked) if had_ids else acked
                        target.acknowledged_by = (
                            (target.acknowledged_by or str(row.get("ack_admin_name") or "Mist"))
                            if target.acknowledged
                            else ""
                        )
                    # "Since" stays the device's own last contact: an older, still-open alarm from a
                    # previous outage must not make this outage look days old.
                    said = ds._message_from_row(row)
                    if said and not any(f["value"] == said for f in target.facts):
                        target.facts.insert(
                            0, {"label": "Mist says", "value": said, "kind": "text", "group": "evidence"}
                        )
                    reason = row.get("reason")
                    if isinstance(reason, str) and reason and reason != said:
                        target.facts.insert(
                            1, {"label": "Reason", "value": reason, "kind": "text", "group": "evidence"}
                        )
                    continue
            add(
                make(
                    atype=atype,
                    row=row,
                    sid=sid,
                    mac=mac,
                    role=role,
                    port=port,
                    definition=definition,
                    origin=origin,
                    native=native,
                )
            )

    for alarm in alarms:
        if not isinstance(alarm, dict) or not ds._alarm_open(alarm):
            continue
        atype = str(alarm.get("type") or alarm.get("key") or alarm.get("alarm_type") or "ALARM")
        add_condition(atype, alarm, "alarm", str(alarm.get("id") or alarm.get("alarm_id") or ""))

    open_events, _ = correlate_event_states(events)
    for ev in open_events:
        etype = event_type(ev) or "DEVICE_EVENT"
        add_condition(etype, ev, "event", "")

    pending: dict[str, list[tuple[Callable[[], list[dict]], dict, dict]]] = {}
    for a in merged.values():
        parts = a.vendor.pop("_parts", [])
        if not a.vendor.get("facts_complete", True):
            pending[a.key] = parts
    global _PENDING
    _PENDING = pending  # parts of the latest build only
    return list(merged.values())


_ENRICH_WAIT_S = 4.0  # beyond the alarms/devices reads, how long alerts wait for events / definitions


class MistAlerts:
    CAPABILITIES: tuple[str, ...] = (ALERTS, ALERTS_ACK)

    def list_alerts(self, site_key: str | None = None) -> list[Alert]:
        client = self.client  # type: ignore[attr-defined]
        jobs = {
            "alarms": client.search_org_alarms,
            "devices": lambda: client.search_org_inventory(limit=50_000),
            "sites": client.list_sites,
            "events": client.search_org_device_events,
            "definitions": client.list_alarm_definitions,
        }
        values: dict[str, Any] = {}
        pool = ThreadPoolExecutor(max_workers=len(jobs), thread_name_prefix="mist-alerts")
        try:
            futures = {k: pool.submit(fn) for k, fn in jobs.items()}
            for name, fut in futures.items():
                if name in {"alarms", "devices"}:
                    values[name] = self.call(fut.result, f"read {name}")  # type: ignore[attr-defined]
                else:
                    try:  # enrichment only: missing events/definitions never hide alerts
                        # v0.10.40: and never hold the alerts back for long (alarm definitions took
                        # up to 11 s on a cold start); the next refresh has them.
                        values[name] = fut.result(timeout=_ENRICH_WAIT_S) or []
                    except Exception:  # noqa: BLE001
                        values[name] = []
        finally:
            pool.shutdown(wait=False)  # a slow enrichment read finishes (and fills its cache) in the background
        alerts = mist_alerts_from_payloads(
            alarms=values["alarms"] or [],
            devices=values["devices"] or [],
            sites=values["sites"],
            events=values["events"],
            definitions=values["definitions"],
            api_host=str(getattr(client.settings, "api_host", "") or ""),
            org_id=str(getattr(client.settings, "org_id", "") or ""),
        )
        if site_key:
            alerts = [a for a in alerts if site_key in {a.site_key, a.vendor.get("site_id")}]
        return alerts

    def alert_facts(self, alert: Alert) -> list[dict]:
        """Optional hook (any connector may offer it): full readable facts for one alert, built lazily."""
        return hydrate_facts(alert)

    def acknowledge_alert(self, alert: Alert, note: str = "") -> dict[str, Any]:
        """Acknowledge every Mist alarm behind ``alert``. Callers confirm and audit (attention_service)."""
        ids = [i for i in (alert.vendor.get("alarm_ids") or ([alert.native_id] if alert.native_id else [])) if i]
        if not ids:
            return {
                "ok": False,
                "acked": [],
                "failed": [],
                "reason": "No Mist alarm behind this alert (device status only)",
            }
        client = self.client  # type: ignore[attr-defined]
        acked, failed = [], []
        for alarm_id in ids:
            try:
                self.call(
                    lambda a=alarm_id: client.ack_alarm(a, note or "Acknowledged from NodeWatch"), "acknowledge alarm"
                )  # type: ignore[attr-defined]
                acked.append(alarm_id)
            except Exception as exc:  # noqa: BLE001 - reported per alarm
                failed.append({"alarm_id": alarm_id, "error": str(exc)[:300]})
        return {"ok": not failed, "acked": acked, "failed": failed}
