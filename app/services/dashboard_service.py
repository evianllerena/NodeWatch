from __future__ import annotations

from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Any

from app.services.event_correlation import correlate_event_states, event_type
from app.modules.history.activity import field_rows, mist_device_url
from app.services.local_state import local_state
from app.services.mist_client import MistApiError, MistClient

CRITICAL_EVENT_TYPES = {
    "AP_DISCONNECTED",
    "SW_DISCONNECTED",
    "GW_DISCONNECTED",
    "SW_ALARM_VIRTUAL_CHASSIS_VERSION_MISMATCH",
    "SW_ALARM_CHASSIS_HOT",
    "SW_FPC_POWER_OFF",
}


def _epoch(value: Any) -> float:
    if value in (None, ""):
        return 0.0
    try:
        return float(value)
    except (TypeError, ValueError):
        pass
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
        except ValueError:
            return 0.0
    return 0.0


def _timestamp(row: dict) -> float:
    for key in ("timestamp", "last_seen", "last_reported", "created_time", "time"):
        ts = _epoch(row.get(key))
        if ts:
            return ts
    return 0.0


def _age(ts: float) -> str:
    if not ts:
        return "unknown"
    seconds = max(0, int(datetime.now(timezone.utc).timestamp() - ts))
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m"
    if seconds < 86400:
        return f"{seconds // 3600}h {(seconds % 3600) // 60:02d}m"
    return f"{seconds // 86400}d {(seconds % 86400) // 3600}h"


def _severity(value: Any, *, event: str = "") -> str:
    raw = str(value or "").lower()
    if raw in {"critical", "major", "high", "error"}:
        return "critical"
    if raw in {"warn", "warning", "minor", "medium"}:
        return "warning"
    if event in CRITICAL_EVENT_TYPES:
        return "critical"
    return "warning"


def _device_type(row: dict) -> str:
    raw = str(row.get("type") or row.get("device_type") or "").lower()
    if raw in {"ap", "switch", "gateway"}:
        return raw
    model = str(row.get("model") or "").upper()
    if model.startswith("AP"):
        return "ap"
    if model.startswith(("EX", "QFX")):
        return "switch"
    if model.startswith(("SRX", "SSR")):
        return "gateway"
    return raw or "unknown"


def _is_down(row: dict) -> bool:
    connected = row.get("connected")
    if connected is False:
        return True
    if connected is True:
        return False
    status = str(row.get("status") or row.get("connection_status") or row.get("device_status") or "").lower()
    if any(word in status for word in ("disconnected", "offline", "down", "unreachable")):
        return True
    if any(word in status for word in ("connected", "online", "up")):
        return False
    return False


def _alarm_open(row: dict) -> bool:
    status = str(row.get("status") or row.get("state") or "").lower()
    if status in {"resolved", "clear", "cleared", "closed", "inactive"}:
        return False
    return not bool(_epoch(row.get("resolved_time")))


def _friendly_type(value: str) -> str:
    return value.replace("_", " ").strip().title() if value else "Mist alert"


def _group_for_type(value: str, mist_group: str = "") -> str:
    t = str(value or "").upper()
    raw_group = str(mist_group or "").strip().lower().replace("_", " ")
    if "VIRTUAL_CHASSIS" in t or "SW_VC_" in t or "VC_" in t:
        return "Virtual Chassis"
    if any(
        x in t
        for x in ("DISCONNECTED", "OFFLINE", "CONNECTED", "ONLINE", "TUNNEL", "VPN_PEER", "VPN_PATH", "WAN_", "UPLINK")
    ):
        return "Connectivity / Availability"
    if any(x in t for x in ("STP", "LOOP", "LACP", "PORT", "INTERFACE", "VLAN", "MAC_LIMIT", "MAC_FLAP")):
        return "Switching / Interfaces"
    if any(x in t for x in ("BGP", "OSPF", "BFD", "EVPN", "ROUTE", "ROUTING")):
        return "Routing / WAN"
    if any(x in t for x in ("PSU", "PEM", "FAN", "HOT", "TEMP", "HUMIDITY", "POWER", "POE", "CHASSIS", "FPC")):
        return "Power / Hardware"
    if any(x in t for x in ("ROGUE", "ATTACK", "SECURITY", "DDOS", "IDP", "THREAT", "SPOOF", "MALWARE")):
        return "Security"
    if any(x in t for x in ("NAC", "RADIUS", "AUTH", "DOT1X", "8021X", "CERT", "PSK")):
        return "Authentication / NAC"
    if any(
        x in t for x in ("WLAN", "WIFI", "WIRELESS", "RF_", "CHANNEL", "RADAR", "INTERFERENCE", "COVERAGE", "CAPACITY")
    ):
        return "Wireless / RF"
    if any(x in t for x in ("DHCP", "DNS", "NTP", "ARP")):
        return "Network Services"
    if any(x in t for x in ("CONFIG", "ZTP", "UPGRADE", "FIRMWARE", "VERSION", "IMAGE")):
        return "Configuration / Software"
    if any(x in t for x in ("CLIENT", "ROAM", "SLE", "USER")):
        return "Clients / Experience"
    # Mist's Marvis group is useful provenance, but not a useful engineer category on its own.
    if raw_group in {"marvis", "ai", "marvis action", "marvis actions"}:
        return "Marvis / AI Anomalies"
    if raw_group and raw_group not in {"other", "unknown", "alarm", "alarms"}:
        return raw_group.title()
    return "Unclassified Mist Conditions"


def _device_marker(row: dict) -> str:
    mac = str(row.get("mac") or "").lower().replace(":", "").replace("-", "")
    return mac or str(row.get("id") or row.get("device_id") or _name_from_row(row))


def _name_from_row(row: dict) -> str:
    direct = (
        row.get("device_name")
        or row.get("hostname")
        or row.get("name")
        or row.get("device")
        or row.get("ap_name")
        or row.get("mac")
        or row.get("device_id")
    )
    if direct:
        return str(direct)
    impacted = row.get("impacted_entities") or []
    if isinstance(impacted, list):
        named = [x for x in impacted if isinstance(x, dict) and (x.get("entity_name") or x.get("entity_mac"))]
        if named:
            kinds = {str(x.get("entity_type") or "device").lower() for x in named}
            kind = next(iter(kinds)) if len(kinds) == 1 else "device"
            plural = {"switch": "switches", "gateway": "gateways", "ap": "APs", "device": "devices"}.get(
                kind, kind + "s"
            )
            label = kind if len(named) == 1 else plural
            return f"{len(named)} {label} impacted"
    return "Unknown device"


def _message_from_row(row: dict) -> str:
    value = row.get("text") or row.get("message") or row.get("reason") or row.get("detail") or row.get("details")
    if isinstance(value, dict):
        return "; ".join(f"{k}: {v}" for k, v in list(value.items())[:8])
    if value:
        return str(value)
    return ""  # v0.10.12: no filler text; the detail view explains the condition instead


# Fields already shown elsewhere in the alert view (title, severity, site, device, times).
_FACT_SKIP = {
    "type",
    "key",
    "alarm_type",
    "severity",
    "group",
    "site_id",
    "org_id",
    "id",
    "device_id",
    "alarm_id",
    "impacted_entities",
    "entities",
    "text",
    "message",
    "acked",
    "for_site",
    "_state",
}


def _facts(row: dict, definition: dict | None = None) -> list[dict]:
    """Readable 'Details reported by Mist' rows (labels + formatted values, never raw JSON)."""
    rows = field_rows(row, skip=_FACT_SKIP, limit=40)
    desc = (definition or {}).get("description") or (definition or {}).get("desc")
    if desc:
        rows.insert(0, {"label": "Mist definition", "value": str(desc), "kind": "text"})
    return rows


def _norm_mac(value: Any) -> str:
    return str(value or "").lower().replace(":", "").replace("-", "").replace(".", "")


def _evidence(
    row: dict,
    dev: dict,
    *,
    mac: str,
    site_id: str,
    events_by_mac: dict[str, list[dict]],
    down_by_site: dict[str, list[dict]],
) -> list[dict]:
    """The concrete facts behind a condition: what Mist said, device state, related events, peers down."""
    # Mist alarms often name the device only in switches/aps/gateways, not "mac": resolve it first so
    # the device's own row is never listed as "also down" and its recent events are found.
    if not mac:
        mac = _norm_mac(dev.get("mac") if dev else "")
    if not mac:
        for key in ("switches", "aps", "gateways", "macs"):
            value = row.get(key)
            if isinstance(value, list) and value and isinstance(value[0], str):
                mac = _norm_mac(value[0])
                break
    out: list[dict] = []
    said = _message_from_row(row)
    if said:
        out.append({"label": "Mist says", "value": said, "kind": "text"})
    reason = row.get("reason")
    if isinstance(reason, str) and reason and reason != said:
        out.append({"label": "Reason", "value": reason, "kind": "text"})
    if row.get("count") and str(row.get("count")) not in ("0", "1"):
        out.append({"label": "Times reported", "value": str(row.get("count")), "kind": "text"})
    if dev:
        state = "Disconnected / offline" if _is_down(dev) else "Connected"
        out.append({"label": "Device status now", "value": state, "kind": "text"})
        seen = _timestamp(dev)
        if seen:
            out.append({"label": "Device last seen", "value": int(seen * 1000), "kind": "time"})
        bits = [str(dev.get(k)) for k in ("model", "version") if dev.get(k)]
        if bits:
            out.append({"label": "Model / firmware", "value": " · ".join(bits), "kind": "text"})
        if dev.get("ip"):
            out.append({"label": "Management IP", "value": str(dev.get("ip")), "kind": "text"})
        if dev.get("uptime"):
            try:
                up = int(float(dev.get("uptime")))
                out.append(
                    {
                        "label": "Uptime",
                        "value": f"{up // 86400}d {up % 86400 // 3600}h {up % 3600 // 60}m",
                        "kind": "text",
                    }
                )
            except (TypeError, ValueError):
                pass
    this_type = event_type(row)
    for ev in (events_by_mac.get(mac) or [])[:6]:
        etype = event_type(ev)
        if not etype or etype == this_type and _timestamp(ev) == _timestamp(row):
            continue
        text = ev.get("text") or ev.get("reason") or ""
        value = _friendly_type(etype) + (f" — {text}" if isinstance(text, str) and text else "")
        if ev.get("port_id"):
            value += f" (port {ev.get('port_id')})"
        out.append({"label": "Recent event", "value": value, "kind": "text", "time": int(_timestamp(ev) * 1000)})
        if sum(1 for x in out if x["label"] == "Recent event") >= 3:
            break
    peers = [r for r in (down_by_site.get(site_id) or []) if _norm_mac(r.get("mac")) != mac]
    if peers:
        names = ", ".join(str(r.get("device")) for r in peers[:5]) + (
            f" and {len(peers) - 5} more" if len(peers) > 5 else ""
        )
        out.append(
            {
                "label": "Also down at this site",
                "value": f"{len(peers)} other device{'s' if len(peers) != 1 else ''}: {names}",
                "kind": "text",
            }
        )
    return out


def _site_id(row: dict) -> str:
    return str(row.get("site_id") or "")


def _safe_details(row: dict, definition: dict | None = None) -> dict:
    hidden = {"org_id"}
    details: dict[str, Any] = {}
    for key, value in row.items():
        if key in hidden or value in (None, "", [], {}):
            continue
        if isinstance(value, (str, int, float, bool)):
            details[key] = value
        elif isinstance(value, list) and len(value) <= 20:
            details[key] = value
        elif isinstance(value, dict) and len(value) <= 20:
            details[key] = value
    if definition:
        desc = definition.get("description") or definition.get("desc")
        if desc:
            details["definition"] = desc
    return details


def _dismiss_key(item: dict) -> str:
    if item.get("alarm_id"):
        return f"alarm:{item['alarm_id']}"
    return "event:" + "|".join(str(item.get(x) or "") for x in ("type", "device", "site", "timestamp"))


def _disconnect_identity(row: dict) -> str:
    mac = str(row.get("mac") or "").lower().replace(":", "").replace("-", "")
    if len(mac) == 12:
        return f"mac:{mac}"
    ident = str(row.get("id") or row.get("device_id") or "").strip()
    if ident:
        return f"id:{ident}"
    name = (
        str(row.get("name") or row.get("device_name") or row.get("hostname") or row.get("device") or "").strip().lower()
    )
    return f"name:{name}" if name else ""


def build_live_dashboard(client: MistClient, *, legacy_details: bool = True) -> dict:
    """Command Center data. Alerts come from every connected ``alerts`` source (vendor-neutral
    ``sdk.gather``); health, site availability and Disconnect Watch still read Mist inventory/stats."""
    from app.services import attention_service

    errors: list[str] = []

    def gather_alerts():
        return attention_service.collect()

    # All in parallel: the alerts sources (which read alarms, inventory, sites, events and alarm
    # definitions through the cached client) plus the Mist-only health inputs. The inventory/sites/events
    # reads below are the same cached, single-flight reads the alerts sources make, so nothing is
    # downloaded twice.
    jobs = {
        "organization": (client.get_org, {}),
        "site stats": (client.list_org_site_stats, []),
        "switch inventory": (lambda: client.list_org_inventory(device_type="switch", vc=True, unassigned=True), []),
        "alerts": (gather_alerts, ([], [], False)),  # a failed gather is never "healthy"
    }
    later = {
        "sites": (client.list_sites, []),
        # Paged: large organisations have more than one 1000-row page of devices.
        "device inventory": (lambda: client.search_org_inventory(limit=50_000), []),
        "device events": (client.search_org_device_events, []),
    }
    values: dict[str, Any] = {}

    def run(batch: dict) -> None:
        with ThreadPoolExecutor(max_workers=len(batch), thread_name_prefix="noc-dashboard") as pool:
            futures = {name: pool.submit(fn) for name, (fn, _) in batch.items()}
            for name, future in futures.items():
                default = batch[name][1]
                try:
                    values[name] = future.result()
                except MistApiError as exc:
                    errors.append(f"{name}: {exc}")
                    values[name] = default
                except Exception as exc:  # one broken section must not take down the whole dashboard
                    errors.append(f"{name}: unexpected {type(exc).__name__}: {exc}")
                    values[name] = default

    # v0.10.23: one phase. The Mist client's single-flight makes a read already in flight for the
    # alerts sources (inventory, sites, events) shared, not repeated, so the "later" reads no longer
    # need to wait for the slowest alert source (another vendor's alarms can take up to its timeout).
    run({**jobs, **later})

    org = values["organization"]
    sites = values["sites"]
    site_stats = values["site stats"]
    device_stats = values["device inventory"]
    switch_inventory = values["switch inventory"]
    events = values["device events"]
    alerts, source_errors, alerts_healthy = values["alerts"]
    if any(e.startswith("alerts:") for e in errors):
        alerts_healthy = False
    for e in source_errors:
        errors.append(f"alerts from {e.get('product') or e.get('source')}: {e.get('error')}")

    site_names = {str(s.get("id")): str(s.get("name") or s.get("id")) for s in sites if s.get("id")}
    device_by_mac = {
        str(d.get("mac") or "").lower().replace(":", "").replace("-", ""): d for d in device_stats if d.get("mac")
    }
    device_by_id = {
        str(d.get("id") or d.get("device_id") or ""): d for d in device_stats if d.get("id") or d.get("device_id")
    }
    _, event_states = correlate_event_states(events)
    api_host = str(getattr(client.settings, "api_host", "") or "")
    org_id = str(getattr(client.settings, "org_id", "") or "")

    # Disconnect Watch "Mark known" and Requires Attention share one truth: a device marked known-down
    # is dismissed in the attention list, and an attention dismissal/snooze/mute hides it here.
    known_down = local_state.dismissed_disconnects()
    known_keys = {
        a.key
        for a in alerts
        if a.type.upper().endswith("_CURRENTLY_DOWN") and f"mac:{a.vendor.get('mac') or ''}" in known_down
    }

    site_device_totals: dict[str, int] = {}
    stats_site_ids = set()
    for s_ in site_stats:
        sid_ = str(s_.get("site_id") or s_.get("id") or "")
        if sid_ and s_.get("num_devices"):
            site_device_totals[sid_] = int(s_.get("num_devices") or 0)
            stats_site_ids.add(sid_)
    for d in device_stats:  # sites without Mist site stats: count managed devices ourselves
        sid_ = str(d.get("site_id") or "")
        if sid_ and sid_ not in stats_site_ids and _device_type(d) in {"ap", "switch", "gateway"}:
            site_device_totals[sid_] = site_device_totals.get(sid_, 0) + 1
    attention_service.remember(
        alerts, source_errors, site_totals=site_device_totals, known_down=known_keys, healthy=alerts_healthy
    )
    rows = attention_service.annotate(alerts)
    incidents = attention_service.payload(rows=rows)
    # In-process callers (AI Engineer) get full rows; the 20 s HTTP refresh skips facts/explanations.
    visible_attention = attention_service.legacy_items(rows, details=legacy_details)
    hidden_down_macs = {
        a.vendor.get("mac")
        for a, st in rows
        if st["state"] in attention_service.SUPPRESSED_STATES and a.type.upper().endswith("_CURRENTLY_DOWN")
    }
    warning_devices: set[str] = set()
    critical_devices: set[str] = set()
    for a, st in rows:
        mac = a.vendor.get("mac") or ""
        if not mac or st["bucket"] not in {"new", "acknowledged"}:
            continue
        (critical_devices if a.severity in {"critical", "major"} else warning_devices).add(mac)

    by_type: dict[str, list[dict]] = defaultdict(list)
    down_devices: set[str] = set()
    for dev in device_stats:
        dtype = _device_type(dev)
        if dtype in {"ap", "switch", "gateway"}:
            by_type[dtype].append(dev)
            if _is_down(dev):
                down_devices.add(_device_marker(dev))

    labels = {"ap": "Access Points", "switch": "Switches", "gateway": "Gateways"}
    health: list[dict] = []
    for dtype in ("ap", "switch", "gateway"):
        items = by_type.get(dtype, [])
        ids = {_device_marker(x) for x in items}
        down = len(ids & down_devices)
        warn = len((ids & (warning_devices | critical_devices)) - (ids & down_devices))
        total = len(items)
        health.append(
            {
                "type": labels[dtype],
                "device_type": dtype,
                "up": max(0, total - down),
                "down": down,
                "warning": warn,
                "total": total,
            }
        )

    open_attention = [x for x in visible_attention if not x.get("possibly_resolved")]
    vc_issues = [x for x in open_attention if x.get("group") == "Virtual Chassis"]
    vc_macs = {
        str(x.get("vc_mac") or "").lower().replace(":", "").replace("-", "")
        for x in switch_inventory
        if x.get("vc_mac")
    }
    vc_macs.discard("")
    vc_down = 0
    for vc_mac in vc_macs:
        stat = device_by_mac.get(vc_mac, {})
        if stat and _is_down(stat):
            vc_down += 1
    vc_warning = len({(x["device"], x["site"]) for x in vc_issues})
    health.append(
        {
            "type": "Virtual Chassis",
            "device_type": "vc",
            "up": max(0, len(vc_macs) - vc_down),
            "down": vc_down,
            "warning": vc_warning,
            "total": len(vc_macs),
        }
    )
    group_counts: Counter[str] = Counter()
    group_severity: dict[str, str] = {}
    for item in open_attention:
        name = str(item.get("group") or _group_for_type(item.get("type") or ""))
        group_counts[name] += 1
        if name not in group_severity or item.get("severity") == "critical":
            group_severity[name] = "critical" if item.get("severity") == "critical" else "warning"
    alarm_groups = [
        {"name": name, "count": count, "severity": group_severity.get(name, "warning")}
        for name, count in sorted(group_counts.items(), key=lambda kv: (-kv[1], kv[0]))
    ]

    issues_by_site = defaultdict(lambda: {"critical": 0, "warning": 0})
    for item in open_attention:
        issues_by_site[item["site"]][item["severity"]] += 1

    # Use Mist's actual site-stat connectivity counts for Site Health. This is a device-availability metric,
    # not a made-up score and not an SLE score.
    stats_by_site = {str(s.get("site_id") or s.get("id") or ""): s for s in site_stats}
    site_rows = []
    for site in sites:
        sid = str(site.get("id") or "")
        name = str(site.get("name") or sid)
        st = stats_by_site.get(sid, {})
        total = int(st.get("num_devices") or 0)
        connected = int(st.get("num_devices_connected") or 0)
        # Fallback to the org device stats when site stats are unavailable.
        if total == 0:
            local = [
                d
                for d in device_stats
                if str(d.get("site_id") or "") == sid and _device_type(d) in {"ap", "switch", "gateway"}
            ]
            total = len(local)
            connected = sum(1 for d in local if not _is_down(d))
        availability = round((connected / total) * 100, 1) if total else None
        issues = issues_by_site[name]
        site_rows.append(
            {
                "id": sid,
                "name": name,
                "critical": issues["critical"],
                "warning": issues["warning"],
                "devices_total": total,
                "devices_connected": connected,
                "availability": availability,
                "aps": int(st.get("num_ap") or 0),
                "aps_connected": int(st.get("num_ap_connected") or 0),
                "switches": int(st.get("num_switch") or 0),
                "switches_connected": int(st.get("num_switch_connected") or 0),
                "gateways": int(st.get("num_gateway") or 0),
                "gateways_connected": int(st.get("num_gateway_connected") or 0),
            }
        )
    site_rows.sort(key=lambda x: (101 if x["availability"] is None else x["availability"], x["name"]))

    recent_events = []
    for event in event_states[:40]:
        ts = _timestamp(event)
        mac = str(event.get("mac") or "").lower().replace(":", "").replace("-", "")
        dev = device_by_mac.get(mac) or device_by_id.get(str(event.get("device_id") or "")) or {}
        sid = _site_id(event) or str(dev.get("site_id") or "")
        state = event.get("_state")
        if state == "info":
            state = (
                "cleared"
                if event_type(event).endswith(
                    ("_UP", "_CONNECTED", "_CLEAR", "_CLEARED", "_RECOVERY", "_RECOVERED", "_STABLE")
                )
                else "open"
            )
        recent_events.append(
            {
                "time": datetime.fromtimestamp(ts, tz=timezone.utc).astimezone().strftime("%H:%M") if ts else "--:--",
                "state": state,
                "type": event.get("_event_type") or event_type(event) or "DEVICE_EVENT",
                "device": _name_from_row({**dev, **event}),
                "site": site_names.get(sid, sid or "Unknown site"),
            }
        )

    aps_down = sum(1 for d in by_type.get("ap", []) if _is_down(d))
    switches_down = sum(1 for d in by_type.get("switch", []) if _is_down(d))
    gateways_down = sum(1 for d in by_type.get("gateway", []) if _is_down(d))
    counts = incidents["counts"]

    # Disconnect Watch: current managed-device losses plus recent down/up events.
    # Multiple devices down together are surfaced as a possible site/power/upstream
    # outage, but the application deliberately does not claim power loss without evidence.
    disconnect_types = {
        "AP_DISCONNECTED",
        "AP_OFFLINE",
        "AP_DOWN",
        "SW_DISCONNECTED",
        "SWITCH_DISCONNECTED",
        "SWITCH_DOWN",
        "GW_DISCONNECTED",
        "GATEWAY_DISCONNECTED",
        "GATEWAY_DOWN",
        "DEVICE_DOWN",
    }
    recovery_types = {
        "AP_CONNECTED",
        "AP_ONLINE",
        "AP_UP",
        "SW_CONNECTED",
        "SWITCH_CONNECTED",
        "SWITCH_UP",
        "GW_CONNECTED",
        "GATEWAY_CONNECTED",
        "GATEWAY_UP",
        "DEVICE_UP",
    }
    now_ts = datetime.now(timezone.utc).timestamp()
    recent_disconnect_rows = []
    recent_recovery_rows = []
    for event in event_states:
        et = str(event.get("_event_type") or event_type(event) or "").upper()
        ts = _timestamp(event)
        if not ts or now_ts - ts > 3600:
            continue
        mac = str(event.get("mac") or "").lower().replace(":", "").replace("-", "")
        dev = device_by_mac.get(mac) or device_by_id.get(str(event.get("device_id") or "")) or {}
        sid = _site_id(event) or str(dev.get("site_id") or "")
        row = {
            "timestamp": ts,
            "time": datetime.fromtimestamp(ts, tz=timezone.utc).astimezone().isoformat(),
            "age": _age(ts),
            "event_type": et,
            "device": _name_from_row({**dev, **event}),
            "device_type": _device_type(dev or event),
            "mac": str(event.get("mac") or dev.get("mac") or ""),
            "site": site_names.get(sid, sid or "Unknown site"),
            "site_id": sid,
        }
        # Device-level connectivity only. Do not count SW_PORT_DOWN, VC_PORT_DOWN,
        # routing/LACP transitions, etc. as infrastructure disconnects.
        if et in disconnect_types:
            recent_disconnect_rows.append(row)
        elif et in recovery_types:
            recent_recovery_rows.append(row)

    active_down_rows = []
    down_by_site: dict[str, list[dict]] = defaultdict(list)
    for dev in device_stats:
        dtype = _device_type(dev)
        if dtype not in {"ap", "switch", "gateway"} or not _is_down(dev):
            continue
        sid = str(dev.get("site_id") or "")
        row = {
            "device": _name_from_row(dev),
            "device_type": dtype,
            "mac": str(dev.get("mac") or ""),
            "site": site_names.get(sid, sid or "Unknown site"),
            "site_id": sid,
            "last_seen": _timestamp(dev),
            "age": _age(_timestamp(dev)),
            "dismiss_key": _disconnect_identity(dev),
            "device_id": str(dev.get("id") or ""),
            "mist_url": mist_device_url(
                api_host,
                org_id,
                site_id=sid,
                device_type=dtype,
                device_id=str(dev.get("id") or ""),
                mac=str(dev.get("mac") or ""),
            ),
        }
        active_down_rows.append(row)
    active_down_rows.sort(
        key=lambda x: (0 if x.get("device_type") in {"switch", "gateway"} else 1, -(x.get("last_seen") or 0))
    )
    dismissed_disconnects_all = local_state.dismissed_disconnects()
    current_disconnect_keys = {str(x.get("dismiss_key") or "") for x in active_down_rows if x.get("dismiss_key")}
    dismissed_disconnects = {k: v for k, v in dismissed_disconnects_all.items() if k in current_disconnect_keys}
    visible_down_rows = [
        x
        for x in active_down_rows
        if str(x.get("dismiss_key") or "") not in dismissed_disconnects
        and _norm_mac(x.get("mac")) not in hidden_down_macs
    ]
    down_by_site = defaultdict(list)
    for row in visible_down_rows:
        down_by_site[str(row.get("site_id") or "")].append(row)

    site_totals = {}
    for site in site_rows:
        site_totals[str(site.get("id") or "")] = int(site.get("devices_total") or 0)
    outage_clusters = []
    for sid, rows in down_by_site.items():
        total = site_totals.get(sid) or len(
            [
                d
                for d in device_stats
                if str(d.get("site_id") or "") == sid and _device_type(d) in {"ap", "switch", "gateway"}
            ]
        )
        down_count = len(rows)
        pct = round((down_count / total) * 100, 1) if total else None
        if down_count < 2:
            continue
        likely = down_count >= 3 and (pct is None or pct >= 25)
        device_types = sorted({r.get("device_type") for r in rows if r.get("device_type")})
        outage_clusters.append(
            {
                "site_id": sid,
                "site": site_names.get(sid, sid or "Unknown site"),
                "severity": "critical" if likely else "warning",
                "label": "Possible site / power / upstream outage" if likely else "Multiple devices disconnected",
                "down": down_count,
                "total": total,
                "percent_down": pct,
                "device_types": device_types,
                "message": (
                    f"{down_count} of {total} managed devices are disconnected at this site. "
                    "Simultaneous loss across multiple devices is consistent with a site power issue, upstream/core switching failure, WAN loss, or cloud reachability problem; confirm the cause before dispatching."
                    if total
                    else f"{down_count} managed devices are disconnected at this site. Check site power, core switching, WAN, and cloud reachability."
                ),
                "devices": rows[:12],
            }
        )
    outage_clusters.sort(key=lambda x: (0 if x["severity"] == "critical" else 1, -x["down"], x["site"]))

    disconnect_watch = {
        "active_down": len(visible_down_rows),
        "raw_active_down": len(active_down_rows),
        "dismissed_known_down": len(dismissed_disconnects),
        "new_last_15m": sum(1 for x in recent_disconnect_rows if now_ts - x["timestamp"] <= 900),
        "recovered_last_15m": sum(1 for x in recent_recovery_rows if now_ts - x["timestamp"] <= 900),
        "sites_impacted": len(down_by_site),
        "clusters": outage_clusters,
        "devices": visible_down_rows[:250],
        "dismissed_devices": list(dismissed_disconnects.values()),
        "recent_disconnects": sorted(recent_disconnect_rows, key=lambda x: x["timestamp"], reverse=True)[:20],
        "recent_recoveries": sorted(recent_recovery_rows, key=lambda x: x["timestamp"], reverse=True)[:20],
    }

    return {
        "mode": "live",
        "errors": errors,
        "last_updated": datetime.now(timezone.utc).astimezone().isoformat(),
        "organization": str(org.get("name") or client.settings.org_id),
        "summary": {
            # Every number below comes from the same incident pass as the Requires Attention list.
            "critical": counts["critical"],
            "warning": counts["warning"],
            # Devices Down = what Disconnect Watch lists (known-down / snoozed / muted devices excluded);
            # the raw Mist numbers are kept for the tile's sub-line.
            "devices_down": len(visible_down_rows),
            "devices_down_raw": aps_down + switches_down + gateways_down,
            "aps_down": aps_down,
            "switches_down": switches_down,
            "gateways_down": gateways_down,
            "vc_degraded": len({(x["device"], x["site"]) for x in vc_issues}),
            "open_issues": counts["open"],
            "unresolved_total": counts["open"],
            "needs_attention": counts["new"],
            "acknowledged": counts["acknowledged"],
            "possibly_resolved": counts["possibly_resolved"],
            "dismissed": counts["suppressed"],
        },
        "health": health,
        "disconnect_watch": disconnect_watch,
        # Full legacy row list for in-process consumers (AI Engineer); the HTTP route sends incidents.
        "attention": visible_attention,
        "incidents": incidents,
        "dismissed": [],
        "alarm_groups": alarm_groups,
        "recent_events": recent_events,
        "sites": site_rows,
        "meta": {
            "sites": len(sites),
            "devices": len(device_stats),
            "alerts_examined": counts["alerts_total"],
            "events_examined": len(events),
            "attention_total": counts["open"],
            "attention_truncated": False,
        },
    }
