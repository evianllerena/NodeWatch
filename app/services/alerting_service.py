from __future__ import annotations

from app.core.errors import NotConfiguredError
from app.core.version import APP_VERSION

import hashlib
import json
import ssl
import threading
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener

from app.core.config import AUTOMATION_ROOT, DATA_ROOT
from app.core.credential_store import delete_secret, load_secret, save_secret
from app.core.file_utils import write_private_text
from app.core.security import validate_http_url
from app.services.local_state import local_state
from app.core.freshness import in_context, no_stale, stale_allowed
from app.services.mist_client import MistApiError, get_mist_client

ALERT_SETTINGS_FILE = AUTOMATION_ROOT / "alerting.json"
ALERT_STATE_FILE = AUTOMATION_ROOT / "alerting-state.json"
WEBHOOK_TARGET = "NodeWatch:AlertWebhookUrl"
_STOP = threading.Event()
_THREAD: threading.Thread | None = None
_LOCK = threading.Lock()

DEVICE_DISCONNECT_EVENTS = {
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
DEVICE_RECOVERY_EVENTS = {
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


DEFAULT_COOLDOWN_SECONDS = 1800


def _defaults() -> dict:
    return {
        "enabled": True,
        "poll_seconds": 60,
        "outage_min_devices": 3,
        "outage_percent": 25,
        "notify_ap": True,
        "notify_switch": True,
        "notify_gateway": True,
        "notify_isolated_ap": False,
        "require_active_confirmation": True,
        "disconnect_grace_seconds": 120,
        "webhook_enabled": False,
        "webhook_format": "generic",
        "cooldown_seconds": DEFAULT_COOLDOWN_SECONDS,
    }


def _load(path: Path, default: dict) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else dict(default)
    except Exception:
        return dict(default)


def _save(path: Path, data: dict) -> None:
    write_private_text(path, json.dumps(data, indent=2, default=str))


def _epoch(value) -> float:
    if value in (None, ""):
        return 0.0
    try:
        n = float(value)
        if n > 1e12:
            n /= 1000.0
        return n
    except (TypeError, ValueError):
        return 0.0


def _fmt_mac(value) -> str:
    raw = "".join(c for c in str(value or "").lower() if c in "0123456789abcdef")
    return ":".join(raw[i : i + 2] for i in range(0, 12, 2)) if len(raw) == 12 else str(value or "")


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
    return raw or "device"


def _is_down(row: dict) -> bool:
    if row.get("connected") is False:
        return True
    if row.get("connected") is True:
        return False
    status = str(row.get("status") or row.get("connection_status") or "").lower()
    return any(x in status for x in ("disconnected", "offline", "down", "unreachable"))


def _event_type(row: dict) -> str:
    return (
        str(row.get("type") or row.get("event_type") or row.get("type_code") or "")
        .upper()
        .replace("-", "_")
        .replace(" ", "_")
    )


def _event_is_disconnect(t: str) -> bool:
    # Only infrastructure-device connectivity events belong here. Generic `_DOWN`
    # matching incorrectly classified SW_PORT_DOWN, SW_VC_PORT_DOWN, BGP_DOWN, etc.
    # as whole-device outages and was a major source of notification noise.
    return t in DEVICE_DISCONNECT_EVENTS


def _event_is_recovery(t: str) -> bool:
    return t in DEVICE_RECOVERY_EVENTS


def _norm_mac(value) -> str:
    return "".join(c for c in str(value or "").lower() if c in "0123456789abcdef")


def _event_mac(row: dict) -> str:
    for key in ("mac", "device_mac", "switch_mac", "ap", "gateway_mac"):
        value = _norm_mac(row.get(key))
        if len(value) == 12:
            return value
    return ""


def _identity(row: dict, dev: dict | None = None) -> str:
    dev = dev or {}
    mac = _event_mac(row) or _norm_mac(dev.get("mac"))
    if mac:
        return f"mac:{mac}"
    ident = str(row.get("device_id") or row.get("id") or dev.get("id") or "").strip()
    if ident:
        return f"id:{ident}"
    name = _device_name({**dev, **row}).strip().lower()
    return f"name:{name}" if name and name != "unknown device" else ""


def _alert_id(parts: list[str]) -> str:
    return hashlib.sha256("|".join(parts).encode("utf-8", errors="replace")).hexdigest()[:24]


def _settings() -> dict:
    cfg = _defaults()
    cfg.update(_load(ALERT_SETTINGS_FILE, {}))
    cfg["webhook_present"] = bool(load_secret(DATA_ROOT, WEBHOOK_TARGET))
    state = _load(ALERT_STATE_FILE, {})
    cfg["status"] = {
        "last_poll": state.get("last_poll"),
        "last_error": state.get("last_error"),
        "last_notification": state.get("last_notification"),
        "notifications_sent": int(state.get("notifications_sent") or 0),
    }
    return cfg


def get_alerting_config() -> dict:
    return _settings()


def save_alerting_config(payload: dict) -> dict:
    cfg = _defaults()
    cfg.update(_load(ALERT_SETTINGS_FILE, {}))
    for key in cfg:
        if key in payload:
            cfg[key] = payload[key]
    cfg["enabled"] = bool(cfg.get("enabled", True))
    cfg["webhook_enabled"] = bool(cfg.get("webhook_enabled", False))
    cfg["notify_ap"] = bool(cfg.get("notify_ap", True))
    cfg["notify_switch"] = bool(cfg.get("notify_switch", True))
    cfg["notify_gateway"] = bool(cfg.get("notify_gateway", True))
    cfg["notify_isolated_ap"] = bool(cfg.get("notify_isolated_ap", False))
    cfg["require_active_confirmation"] = bool(cfg.get("require_active_confirmation", True))
    cfg["disconnect_grace_seconds"] = max(30, min(900, int(cfg.get("disconnect_grace_seconds") or 120)))
    cfg["poll_seconds"] = max(30, min(900, int(cfg.get("poll_seconds") or 60)))
    cfg["outage_min_devices"] = max(2, min(100, int(cfg.get("outage_min_devices") or 3)))
    cfg["outage_percent"] = max(5, min(100, int(cfg.get("outage_percent") or 25)))
    cfg["cooldown_seconds"] = max(60, min(86400, int(cfg.get("cooldown_seconds") or DEFAULT_COOLDOWN_SECONDS)))
    fmt = str(cfg.get("webhook_format") or "generic").lower()
    if fmt not in {"generic", "slack"}:
        raise ValueError("Webhook format must be generic or slack")
    cfg["webhook_format"] = fmt
    url = str(payload.get("webhook_url") or "").strip()
    if url:
        url = validate_http_url(url, require_https=True)
        save_secret(DATA_ROOT, WEBHOOK_TARGET, url, username="NodeWatch Alert Webhook")
    if payload.get("clear_webhook"):
        delete_secret(DATA_ROOT, WEBHOOK_TARGET)
    if cfg["webhook_enabled"] and not (url or load_secret(DATA_ROOT, WEBHOOK_TARGET)):
        raise ValueError("A webhook URL is required when webhook alerting is enabled")
    _save(ALERT_SETTINGS_FILE, cfg)
    return _settings()


def _device_name(row: dict) -> str:
    return str(row.get("name") or row.get("device_name") or row.get("hostname") or row.get("mac") or "Unknown device")


_FEED_MEMO_SECONDS = 10.0
_FEED_SERVE_WHILE_BUILDING = 300.0  # a page asking during a build gets the last feed if it is this recent
_FEED_MEMO_LOCK = threading.Lock()  # guards _FEED_MEMO only (never held during a build)
_FEED_BUILD_LOCK = threading.Lock()  # single flight for non-fresh builds
_FEED_MEMO: dict = {"at": 0.0, "value": None}


def _memo(max_age: float):
    with _FEED_MEMO_LOCK:
        value, at = _FEED_MEMO["value"], _FEED_MEMO["at"]
    return value if value is not None and time.monotonic() - at < max_age else None


def build_alert_feed(*, fresh: bool = False) -> dict:
    """The alert feed. Non-fresh callers within 10 s share one build (v0.10.23): the page polls every
    20 s and the background monitor every 60 s, and each build re-scans the full inventory.
    v0.10.40: a page that asks while a build is running (usually the background monitor's) gets the last
    feed at once instead of waiting for the build's Mist reads."""
    if fresh:
        value = _build_alert_feed(fresh=True)
    elif not stale_allowed():
        # The monitor (inside no_stale) decides on current data: never a page's memo, which may have been
        # built from stale-while-refresh answers. Its own build still feeds the memo for the pages.
        with _FEED_BUILD_LOCK:
            value = _build_alert_feed(fresh=False)
    else:
        hit = _memo(_FEED_MEMO_SECONDS)
        if hit is not None:
            return hit
        if not _FEED_BUILD_LOCK.acquire(blocking=False):
            recent = _memo(_FEED_SERVE_WHILE_BUILDING)
            if recent is not None:
                return recent
            _FEED_BUILD_LOCK.acquire()
        try:
            hit = _memo(_FEED_MEMO_SECONDS)  # built while we waited
            if hit is not None:
                return hit
            value = _build_alert_feed(fresh=False)
        finally:
            _FEED_BUILD_LOCK.release()
    with _FEED_MEMO_LOCK:
        _FEED_MEMO.update(at=time.monotonic(), value=value)
    return value


# ---- other vendors (v0.10.24) ----------------------------------------------------------------------
# The rules above (confirmation window, "still down" check, site-outage clustering) are Mist's: they read
# Mist inventory and device events. Every other connected alert source (EdgeConnect Orchestrator,
# FortiGate, Panorama …) reports current conditions through the vendor-neutral ALERTS capability; its
# open connectivity conditions are added to the feed as they are, labelled with the source's product.
OTHER_SOURCE_CACHE_SECONDS = 60.0  # reuse Command Center's gather when it is this fresh
_ROLE_TYPES = {
    "ap": "ap",
    "access_point": "ap",
    "switch": "switch",
    "gateway": "gateway",
    "router": "gateway",
    "firewall": "gateway",
    "sdwan_edge": "gateway",
    "wan_edge": "gateway",
}


def _other_source_alerts() -> tuple[list, list]:
    """Open alerts from every connected ALERTS source except Mist, read in parallel (never raises).

    Errors are ``{source, product, error}`` dicts (plain strings are accepted from older callers): a
    source that failed this poll keeps its previous alerts active instead of looking resolved."""
    try:
        from app.integrations.connectors import sdk
        from app.integrations.contracts import ALERTS
        from app.services import attention_service

        cached = attention_service.fresh_cached_alerts(OTHER_SOURCE_CACHE_SECONDS)
        if cached is not None:
            alerts, errors = cached
            return (
                [a for a in alerts if getattr(a, "source", "") != "mist"],
                [e for e in errors if not (isinstance(e, dict) and e.get("source") == "mist")],
            )
        others = [c for c in sdk.sources(ALERTS) if c.manifest.connector_id != "mist"]
        if not others:
            return [], []
        rows: list = []
        errors: list = []
        with ThreadPoolExecutor(max_workers=min(4, len(others)), thread_name_prefix="feed-sources") as pool:
            futures = {pool.submit(in_context(c.list_alerts)): c for c in others}
            for future, c in futures.items():
                try:
                    rows.extend(future.result() or [])
                except Exception as exc:  # noqa: BLE001 - one vendor never hides the others
                    errors.append(
                        {"source": c.manifest.connector_id, "product": c.manifest.product, "error": str(exc)}
                    )
        return rows, errors
    except Exception as exc:  # noqa: BLE001
        return [], [{"source": "*", "product": "Other alert sources", "error": type(exc).__name__}]


def _error_text(e) -> str:
    if isinstance(e, dict):
        product, text = str(e.get("product") or e.get("source") or ""), str(e.get("error") or "")
        return text if not product or text.startswith(product) else f"{product}: {text}"
    return str(e)


def _failed_sources(errors: list) -> set[str]:
    """Connector ids whose read failed this poll ("*" = some source we cannot attribute: all of them)."""
    failed: set[str] = set()
    products: dict[str, str] = {}
    try:
        from app.integrations.connectors import sdk

        products = {c.manifest.product: c.manifest.connector_id for c in sdk.all_connectors() if c.manifest.product}
    except Exception:  # noqa: BLE001
        products = {}
    for e in errors or []:
        if isinstance(e, dict) and e.get("source"):
            failed.add(str(e["source"]))
            continue
        text = _error_text(e)
        match = next((cid for product, cid in products.items() if text.startswith(product)), None)
        failed.add(match or "*")
    return failed


def _polled_sources(alerts: list, failed: set[str]) -> list[str]:
    """Non-Mist sources that answered this poll (they may have no alerts at all)."""
    ids = {str(getattr(a, "source", "") or "") for a in alerts}
    try:
        from app.integrations.connectors import sdk
        from app.integrations.contracts import ALERTS

        ids |= {c.manifest.connector_id for c in sdk.sources(ALERTS)}
    except Exception:  # noqa: BLE001
        pass
    return sorted(i for i in ids if i and i != "mist" and i not in failed and "*" not in failed)


def _any_other_alert_source() -> bool:
    try:
        from app.integrations.connectors import sdk
        from app.integrations.contracts import ALERTS

        return any(c.manifest.connector_id != "mist" for c in sdk.sources(ALERTS))
    except Exception:  # noqa: BLE001
        return False


def _other_alert_rows(alerts: list, cfg: dict) -> list[dict]:
    """Feed rows for open connectivity conditions from non-Mist sources (deduplicated by alert key)."""
    try:
        from app.services.attention_service import source_labels

        labels = source_labels()
    except Exception:  # noqa: BLE001
        labels = {}
    rows: list[dict] = []
    seen: set[str] = set()
    for a in alerts:
        if getattr(a, "category", "") != "connectivity" or getattr(a, "resolved", False):
            continue
        if getattr(a, "acknowledged", False) or a.key in seen:
            continue
        seen.add(a.key)
        dtype = _ROLE_TYPES.get(str(a.device_role or "").lower(), "device")
        # Every row passes a per-type toggle: devices of an unknown role (controllers, appliances …)
        # follow the gateway / WAN-edge toggle, the category the Alerting settings call infrastructure.
        toggle = dtype if dtype in {"ap", "switch", "gateway"} else "gateway"
        if not cfg.get(f"notify_{toggle}"):
            continue
        label = (labels.get(a.source) or {}).get("label") or a.source
        where = f" at {a.site_name}" if a.site_name else ""
        severity = "critical" if str(a.severity).lower() in {"critical", "major"} else "warning"
        rows.append(
            {
                "id": _alert_id(["source_alert", a.source, a.key]),
                "severity": severity,
                "kind": "source_alert",
                "title": a.title,
                "message": (a.detail or a.title) + where + f" (reported by {label}).",
                "device": a.device_name,
                "device_type": dtype,
                "mac": "",
                "site": a.site_name or "",
                "site_id": "",
                "timestamp": a.last_seen or a.first_seen or 0,
                "identity": a.key,
                "source": a.source,
                "source_label": label,
                "console_url": a.console_url,
            }
        )
    return rows


def _build_alert_feed(*, fresh: bool = False) -> dict:
    c = get_mist_client()
    if not c.configured:
        # No Mist: the feed still carries every other connected source's open connectivity conditions.
        other_alerts, other_errors = _other_source_alerts()
        failed = _failed_sources(other_errors)
        rows = _other_alert_rows(other_alerts, _settings())
        rows.sort(key=lambda x: (0 if x.get("severity") == "critical" else 1, -(x.get("timestamp") or 0)))
        return {
            "alerts": rows[:100],
            "notification_alerts": rows[:100],
            "active_down": [],
            "clusters": [],
            "suppressed_transient": 0,
            "errors": [] if _any_other_alert_source() else ["No alert source is connected"],
            "source_errors": [_error_text(e) for e in other_errors],
            "failed_sources": sorted(failed),
            "polled_sources": _polled_sources(other_alerts, failed),
            "updated": datetime.now(timezone.utc).isoformat(),
        }

    errors: list[str] = []
    sites: list[dict] = []
    inventory: list[dict] = []
    events: list[dict] = []

    # These are independent Mist reads. Run them together so one slow event query
    # does not serially delay site/inventory state.
    def safe_sites():
        try:
            return c.list_sites(), None
        except MistApiError as exc:
            return [], str(exc)

    def safe_inventory():
        try:
            return c.search_org_inventory(limit=50_000), None
        except MistApiError as exc:
            return [], str(exc)

    def safe_events():
        try:
            return c.search_org_device_events_window(duration="30m", limit=1000, fresh=fresh), None
        except MistApiError as exc:
            return [], str(exc)

    with ThreadPoolExecutor(max_workers=4) as pool:
        fs = pool.submit(in_context(safe_sites))
        fi = pool.submit(in_context(safe_inventory))
        fe = pool.submit(in_context(safe_events))
        fo = pool.submit(in_context(_other_source_alerts))  # EdgeConnect, FortiGate, Panorama … (v0.10.24)
        other_alerts, other_errors = fo.result()
        sites, e1 = fs.result()
        inventory, e2 = fi.result()
        events, e3 = fe.result()
    errors.extend(x for x in (e1, e2, e3) if x)

    site_names = {str(x.get("id") or ""): str(x.get("name") or x.get("id") or "Unknown site") for x in sites}
    device_by_mac = {_norm_mac(x.get("mac")): x for x in inventory if len(_norm_mac(x.get("mac"))) == 12}
    device_by_id = {str(x.get("id") or ""): x for x in inventory if x.get("id")}
    total_by_site: dict[str, int] = defaultdict(int)
    down_by_site: dict[str, list[dict]] = defaultdict(list)
    active_down: list[dict] = []
    active_identity: set[str] = set()
    cfg = _settings()
    dismissed_disconnects = local_state.dismissed_disconnects()
    suppressed_identities = set(str(k) for k in dismissed_disconnects)

    for dev in inventory:
        dtype = _device_type(dev)
        if dtype not in {"ap", "switch", "gateway"}:
            continue
        sid = str(dev.get("site_id") or "")
        total_by_site[sid] += 1
        if not _is_down(dev):
            continue
        ident = _identity({}, dev)
        if ident and ident in suppressed_identities:
            continue
        if ident:
            active_identity.add(ident)
        row = {
            "device": _device_name(dev),
            "type": dtype,
            "mac": _fmt_mac(dev.get("mac")),
            "site_id": sid,
            "site": site_names.get(sid, sid or "Unknown site"),
            "identity": ident,
        }
        active_down.append(row)
        down_by_site[sid].append(row)

    # Keep only device-level connectivity events and choose the latest connectivity
    # event for each managed device. Port/LACP/VC-port/routing events are intentionally
    # excluded from disconnect notifications.
    connectivity_events: dict[str, dict] = {}
    now = datetime.now(timezone.utc).timestamp()
    for event in events:
        et = _event_type(event)
        if not (_event_is_disconnect(et) or _event_is_recovery(et)):
            continue
        mac_key = _event_mac(event)
        dev = device_by_mac.get(mac_key) or device_by_id.get(str(event.get("device_id") or "")) or {}
        ident = _identity(event, dev)
        if not ident or ident in suppressed_identities:
            continue
        ts = _epoch(event.get("timestamp") or event.get("time") or event.get("last_seen"))
        previous = connectivity_events.get(ident)
        if previous is None or ts > previous["timestamp"]:
            connectivity_events[ident] = {"event": event, "dev": dev, "type": et, "timestamp": ts}

    grace = int(cfg.get("disconnect_grace_seconds") or 120)
    require_active = bool(cfg.get("require_active_confirmation", True))
    candidate_alerts: list[dict] = []
    suppressed_transient = 0
    recent_confirmed_by_site: dict[str, list[dict]] = defaultdict(list)

    for ident, rec in connectivity_events.items():
        et = rec["type"]
        if not _event_is_disconnect(et):
            continue
        event, dev, ts = rec["event"], rec["dev"], rec["timestamp"]
        age = max(0, now - ts) if ts else 0
        # Events older than 30 minutes are useful history but are not new notification candidates.
        if ts and age > 1800:
            continue
        if ts and age < grace:
            suppressed_transient += 1
            continue
        if require_active and ident not in active_identity:
            # Mist already reports the device recovered/currently connected.
            suppressed_transient += 1
            continue

        dtype = _device_type(dev or event)
        if dtype not in {"ap", "switch", "gateway"}:
            if et.startswith("AP_"):
                dtype = "ap"
            elif et.startswith("SW_") or et.startswith("SWITCH_"):
                dtype = "switch"
            elif et.startswith("GW_") or et.startswith("GATEWAY_"):
                dtype = "gateway"
        if dtype == "ap" and not cfg.get("notify_ap"):
            continue
        if dtype == "switch" and not cfg.get("notify_switch"):
            continue
        if dtype == "gateway" and not cfg.get("notify_gateway"):
            continue

        sid = str(event.get("site_id") or dev.get("site_id") or "")
        device = _device_name({**dev, **event})
        mac_value = event.get("mac") or event.get("device_mac") or dev.get("mac")
        severity = "critical" if dtype in {"switch", "gateway"} else "warning"
        alert = {
            # Stable for the entire down episode. A recovery removes it from the active set;
            # a later genuine outage can then notify again.
            "id": _alert_id(["device_disconnect", ident]),
            "severity": severity,
            "kind": "device_disconnect",
            "title": f"{dtype.title()} disconnected" if dtype != "device" else "Device disconnected",
            "message": (
                f"{device} is still reported disconnected at {site_names.get(sid, sid or 'Unknown site')} "
                f"after a {grace}-second confirmation window. Check related site-wide losses before treating this as isolated."
            ),
            "device": device,
            "device_type": dtype,
            "mac": _fmt_mac(mac_value),
            "site": site_names.get(sid, sid or "Unknown site"),
            "site_id": sid,
            "timestamp": ts,
            "identity": ident,
        }
        candidate_alerts.append(alert)
        recent_confirmed_by_site[sid].append(alert)

    # Site outage alerts require both CURRENT down state and multiple recently-confirmed
    # device disconnect episodes. Long-standing/decommissioned inventory alone cannot create
    # a new outage notification.
    clusters: list[dict] = []
    cluster_sites: set[str] = set()
    min_devices = int(cfg.get("outage_min_devices") or 3)
    percent_threshold = float(cfg.get("outage_percent") or 25)
    for sid, rows in down_by_site.items():
        recent_rows = recent_confirmed_by_site.get(sid, [])
        down = len(rows)
        total = total_by_site.get(sid) or 0
        pct = round((down / total) * 100, 1) if total else 0.0
        if down < min_devices or (total and pct < percent_threshold):
            continue
        if len(recent_rows) < min_devices:
            continue
        site = site_names.get(sid, sid or "Unknown site")
        cluster_sites.add(sid)
        title = "Possible site / power / upstream outage"
        message = (
            f"{down} of {total} managed devices ({pct:.0f}%) are currently disconnected at {site}, "
            f"with {len(recent_rows)} recently confirmed disconnects. Check site power/UPS, core switching, "
            "WAN/ISP, and Mist cloud reachability."
        )
        cluster = {
            "id": _alert_id(["site_cluster", sid]),
            "severity": "critical",
            "kind": "site_disconnect_cluster",
            "title": title,
            "message": message,
            "site": site,
            "site_id": sid,
            "down": down,
            "total": total,
            "percent_down": pct,
            "devices": rows[:20],
            "timestamp": max([x.get("timestamp") or 0 for x in recent_rows] or [now]),
        }
        clusters.append(cluster)

    # Isolated AP flaps are common. By default only AP disconnects that participate in a
    # correlated site outage become notifications; engineers can explicitly enable isolated APs.
    notification_alerts: list[dict] = []
    for alert in candidate_alerts:
        if (
            alert.get("device_type") == "ap"
            and not cfg.get("notify_isolated_ap")
            and alert.get("site_id") not in cluster_sites
        ):
            continue
        notification_alerts.append(alert)
    notification_alerts.extend(clusters)
    seen_ids = {a.get("id") for a in notification_alerts}
    for alert in _other_alert_rows(other_alerts, cfg):
        if alert["id"] not in seen_ids:
            seen_ids.add(alert["id"])
            notification_alerts.append(alert)
    notification_alerts.sort(key=lambda x: (0 if x.get("severity") == "critical" else 1, -(x.get("timestamp") or 0)))

    # The visible feed follows the same confirmed set so it stays actionable rather than
    # becoming a raw flap/event viewer.
    alerts = list(notification_alerts)
    return {
        "alerts": alerts[:100],
        "notification_alerts": notification_alerts[:100],
        "active_down": active_down[:100],
        "clusters": clusters,
        "suppressed_transient": suppressed_transient,
        "errors": errors,
        # Other vendors' read errors are reported apart: ``errors`` (Mist data incomplete) holds back
        # webhook notifications, and one unreachable vendor must not silence the rest.
        "source_errors": [_error_text(e) for e in other_errors],
        "failed_sources": sorted(_failed_sources(other_errors)),
        "polled_sources": ["mist", *_polled_sources(other_alerts, _failed_sources(other_errors))],
        "policy": {"grace_seconds": grace, "require_active_confirmation": require_active},
        "updated": datetime.now(timezone.utc).isoformat(),
    }


def _webhook_payload(alert: dict, fmt: str) -> dict:
    text = f"[{str(alert.get('severity') or 'warning').upper()}] {alert.get('title')}: {alert.get('message')}"
    if fmt == "slack":
        return {"text": text}
    return {"source": "NodeWatch", "event": "network_alert", "alert": alert, "text": text}


class _NoRedirect(HTTPRedirectHandler):
    """Refuse redirects (v0.10.22), like every other credentialed NodeWatch request: the webhook
    URL itself is the secret, and a redirect would silently send alerts somewhere else."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        return None


def _send_webhook(alert: dict, cfg: dict) -> None:
    url = load_secret(DATA_ROOT, WEBHOOK_TARGET)
    if not url:
        raise NotConfiguredError("Alert webhook URL is not configured")
    body = json.dumps(_webhook_payload(alert, str(cfg.get("webhook_format") or "generic")), default=str).encode("utf-8")
    req = Request(
        url,
        data=body,
        method="POST",
        headers={"Content-Type": "application/json", "User-Agent": f"NodeWatch/{APP_VERSION}"},
    )
    context = ssl.create_default_context()
    try:
        opener = build_opener(HTTPSHandler(context=context), _NoRedirect())
        with opener.open(req, timeout=12) as resp:
            if resp.status >= 300:
                raise RuntimeError(f"Webhook returned HTTP {resp.status}")
    except HTTPError as exc:
        raise RuntimeError(f"Webhook returned HTTP {exc.code}") from exc
    except URLError as exc:
        raise RuntimeError(f"Unable to reach alert webhook: {exc.reason}") from exc


def poll_and_notify(*, force_test: bool = False) -> dict:
    with _LOCK:
        cfg = _settings()
        state = _load(ALERT_STATE_FILE, {})
        now = datetime.now(timezone.utc).timestamp()
        state["last_poll"] = datetime.now(timezone.utc).isoformat()
        try:
            if force_test:
                alert = {
                    "id": "test",
                    "severity": "warning",
                    "kind": "test",
                    "title": "NodeWatch test alert",
                    "message": "Alerting Center webhook test succeeded if you received this message.",
                    "site": "Test",
                    "timestamp": now,
                }
                _send_webhook(alert, cfg)
                sent = 1
            else:
                # Background poll: the shared event buffer already refreshes every ~30 s. fresh=True forced
                # an extra incremental Mist read on every poll (max_age 10 s) for no new information.
                feed = build_alert_feed(fresh=False)
                sent = 0
                if feed.get("errors"):
                    # Incomplete data from Mist: keep the previous active set. Resetting
                    # it would re-send every current alert as "new" on the next good poll.
                    state["last_error"] = "; ".join(str(e) for e in feed["errors"])[:1000]
                    _save(ALERT_STATE_FILE, state)
                    return {
                        "ok": False,
                        "sent": 0,
                        "status": _settings().get("status"),
                        "skipped": "Mist data incomplete; alert state kept",
                    }
                current = {str(a.get("id") or ""): a for a in (feed.get("notification_alerts") or []) if a.get("id")}
                current_ids = set(current)
                previous_ids = set(str(x) for x in (state.get("active_ids") or []))
                # v0.10.24 (other vendors): a source whose read failed this poll keeps its previous alerts
                # active - otherwise they would look resolved and be sent again on the next good poll.
                previous_sources = {str(k): str(v) for k, v in (state.get("active_sources") or {}).items()}
                failed = set(feed.get("failed_sources") or [])
                kept = {
                    i
                    for i in previous_ids - current_ids
                    if previous_sources.get(i, "mist") in failed
                    or ("*" in failed and previous_sources.get(i, "mist") != "mist")
                }
                # Each source has its own baseline: the first poll that sees a source records its open
                # alerts without sending them (after an upgrade, or when a connector is added).
                primed_sources = set(state.get("primed_sources") or [])
                if state.get("episode_tracking_primed"):
                    primed_sources.add("mist")  # earlier releases tracked Mist only

                def source_of(alert: dict) -> str:
                    return str(alert.get("source") or "mist")
                sent_keys = dict(state.get("sent") or {})
                cooldown = int(cfg.get("cooldown_seconds") or DEFAULT_COOLDOWN_SECONDS)
                delivered_ids = set(previous_ids & current_ids)

                # First background poll establishes a baseline. Do not blast existing outages
                # merely because the application was just opened/upgraded.
                if cfg.get("webhook_enabled"):
                    for key in sorted(current_ids):
                        alert = current[key]
                        if source_of(alert) not in primed_sources:
                            continue
                        is_new_episode = key not in previous_ids
                        is_cluster_reminder = (
                            alert.get("kind") == "site_disconnect_cluster"
                            and key in previous_ids
                            and now - float(sent_keys.get(key) or 0) >= cooldown
                        )
                        if not (is_new_episode or is_cluster_reminder):
                            continue
                        _send_webhook(alert, cfg)
                        sent_keys[key] = now
                        delivered_ids.add(key)
                        sent += 1
                        # Persist after every delivery so a later webhook failure in this
                        # loop cannot cause already-delivered alerts to be sent again.
                        state["sent"] = sent_keys
                        state["active_ids"] = sorted(delivered_ids | kept)
                        state["notifications_sent"] = int(state.get("notifications_sent") or 0) + 1
                        state["last_notification"] = datetime.now(timezone.utc).isoformat()
                        _save(ALERT_STATE_FILE, state)

                state["active_ids"] = sorted(current_ids | kept)
                state["active_sources"] = {
                    **{i: previous_sources.get(i, "mist") for i in kept},
                    **{i: source_of(current[i]) for i in current_ids},
                }
                polled = set(feed.get("polled_sources") or []) | {source_of(a) for a in current.values()}
                state["primed_sources"] = sorted(primed_sources | (polled - failed))
                state["episode_tracking_primed"] = True
                sent_keys = {k: v for k, v in sent_keys.items() if now - float(v or 0) < 7 * 86400}
                state["sent"] = sent_keys
                state["suppressed_transient"] = int(feed.get("suppressed_transient") or 0)

            if sent and force_test:
                state["last_notification"] = datetime.now(timezone.utc).isoformat()
                state["notifications_sent"] = int(state.get("notifications_sent") or 0) + sent
            state["last_error"] = ""
        except Exception as exc:
            state["last_error"] = str(exc)[:1000]
            _save(ALERT_STATE_FILE, state)
            raise
        _save(ALERT_STATE_FILE, state)
        return {"ok": True, "sent": sent, "status": _settings().get("status")}


# v0.10.24: the first background poll waits a little so the user's first page gets the network,
# the Mist connection and the shared caches to itself (it then finds the reads already cached).
STARTUP_DELAY_SECONDS = 20.0


def _loop() -> None:
    _STOP.wait(STARTUP_DELAY_SECONDS)
    while not _STOP.is_set():
        cfg = _settings()
        if cfg.get("enabled"):
            try:
                # Alerts are decided on current data: no stale-while-revalidate answers (v0.10.40).
                with no_stale():
                    poll_and_notify()
            except Exception:
                pass
        _STOP.wait(max(30, int(cfg.get("poll_seconds") or 60)))


def start_alerting_monitor() -> None:
    global _THREAD
    if _THREAD and _THREAD.is_alive():
        return
    _STOP.clear()
    _THREAD = threading.Thread(target=_loop, name="mist-alerting-monitor", daemon=True)
    _THREAD.start()


def stop_alerting_monitor() -> None:
    _STOP.set()
