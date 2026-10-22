"""Operations Assistant: deterministic, read-only answers from live Mist data.

The intent parser (``ai_engineer_intents``) decides what was asked; this module
gathers the data through existing NodeWatch services (Command Center analysis,
Device Finder search, Port Toolkit / Power Guard reads, the audit log) and turns
it into a short answer card: headline, plain-English facts, clickable chips that
open the right page, and follow-up questions. Nothing is sent to an external AI
service and nothing is ever changed in Mist.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable

from app.services import ai_engineer_intents as intents
from app.services.ai_engineer_intents import Intent, match_name, normalize
from app.services.dashboard_service import _age, _device_type, _epoch, _is_down, _name_from_row
from app.services.mist_client import MistApiError

NOTE = "Read-only analysis of your live Mist data on this PC. Network data is not sent to any external AI service."
PREVIEW_NOTE = "Mist is not connected yet, so this answer uses NodeWatch preview data."
KIND_LABEL = {"switch": "switch", "ap": "access point", "gateway": "gateway"}
KIND_PLURAL = {"switch": "switches", "ap": "access points", "gateway": "gateways"}
KIND_SHORT_PLURAL = {"switch": "Switches", "ap": "APs", "gateway": "Gateways"}
MAX_FACT_NAMES = 5


# --------------------------------------------------------------------------- answer model


@dataclass
class Answer:
    intent: str
    headline: str
    tone: str = "info"  # critical | warning | ok | info
    facts: list[dict] = field(default_factory=list)
    chips: list[dict] = field(default_factory=list)
    suggestions: list[str] = field(default_factory=list)
    interpreted_as: str = ""
    scope: dict = field(default_factory=dict)

    def fact(self, text: str, tone: str = "info") -> "Answer":
        if text:
            self.facts.append({"text": text, "tone": tone})
        return self

    def chip(self, label: str, action: dict, tone: str = "") -> "Answer":
        if label and not any(c["label"] == label and c["action"] == action for c in self.chips):
            self.chips.append({"label": str(label), "action": action, "tone": tone})
        return self

    def to_dict(self, *, mode: str) -> dict:
        suggestions: list[str] = []
        for s in self.suggestions:
            if s and s not in suggestions:
                suggestions.append(s)
        spoken = " ".join([self.headline] + [f["text"] for f in self.facts[:2]])
        return {
            "intent": self.intent,
            "headline": self.headline,
            "tone": self.tone,
            "facts": self.facts[:14],
            "chips": self.chips[:14],
            "suggestions": suggestions[:6],
            "interpreted_as": self.interpreted_as,
            "scope": self.scope,
            "mode": mode,
            "note": PREVIEW_NOTE if mode == "preview" else NOTE,
            "spoken": spoken,
            # Plain-text form for older clients and logs.
            "answer": "\n".join([self.headline] + [f"- {f['text']}" for f in self.facts]),
            "generated_at": datetime.now(timezone.utc).astimezone().isoformat(),
        }


def tool(name: str) -> dict:
    return {"type": "tool", "tool": name}


def device_action(query: str, site_id: str = "") -> dict:
    return {"type": "device", "query": str(query or ""), "site_id": str(site_id or "")}


def ask_action(question: str) -> dict:
    return {"type": "ask", "question": question}


def switch_action(page: str, site_id: str, *, device_id: str = "", mac: str = "") -> dict:
    return {"type": "switch", "tool": page, "site_id": site_id or "", "device_id": device_id or "", "mac": mac or ""}


def site_finder_action(site_id: str) -> dict:
    return {"type": "site", "site_id": site_id or ""}


# --------------------------------------------------------------------------- data access


class AssistantSource:
    """Read-only data boundary for one question (memoized per request)."""

    def __init__(self, client=None):
        if client is None:
            from app.services.mist_client import get_mist_client

            client = get_mist_client()
        self.client = client
        self._memo: dict[str, Any] = {}

    @property
    def mode(self) -> str:
        return "live" if getattr(self.client, "configured", False) else "preview"

    def _m(self, key: str, fn: Callable[[], Any]) -> Any:
        if key not in self._memo:
            self._memo[key] = fn()
        return self._memo[key]

    def sites(self) -> list[dict]:
        if self.mode == "preview":
            from app.data.sample_data import SITES

            return deepcopy(SITES)
        return self._m("sites", self.client.list_sites)

    def dashboard(self) -> dict:
        if self.mode == "preview":
            from app.data.sample_data import NOC_DASHBOARD

            return deepcopy(NOC_DASHBOARD)
        from app.services.dashboard_service import build_live_dashboard

        return self._m("dashboard", lambda: build_live_dashboard(self.client))

    def devices(self) -> list[dict]:
        if self.mode == "preview":
            return []
        # Same call (and cache entry) as Command Center.
        return self._m("devices", lambda: self.client.search_org_inventory(limit=50_000))

    def device_names(self) -> list[str]:
        try:
            return [_name_from_row(d) for d in self.devices() if d.get("name") or d.get("hostname")]
        except Exception:
            return []

    def vc_inventory(self) -> list[dict]:
        if self.mode == "preview":
            return []
        return self._m("vc", lambda: self.client.list_org_inventory(device_type="switch", vc=True, unassigned=True))

    def search(self, query: str, site_id: str | None = None) -> dict:
        from app.services.detective_service import search_detective

        return search_detective(query, site_id=site_id)

    def detail(self, kind: str, mac: str, site_id: str | None = None) -> dict:
        from app.services.detective_service import detective_detail

        return detective_detail(kind, mac, site_id)

    def audit(self, duration: str) -> list[dict]:
        if self.mode == "preview":
            return []
        return self.client.search_audit_logs(duration)

    def switches(self, site_id: str) -> list[dict]:
        from app.services.operations_service import list_switches

        return self._m(f"switches:{site_id}", lambda: list_switches(site_id, self.client))

    def switch_ports(self, site_id: str, device_id: str) -> dict:
        from app.services.operations_service import get_switch_ports

        return get_switch_ports(site_id, device_id, self.client)

    def poe(self, site_id: str, device_id: str) -> dict:
        from app.services.poe_service import poe_summary

        return poe_summary(site_id, device_id)

    def traffic(self, ip: str) -> dict:
        from app.services.assistant_data_service import ASSISTANT_DATA

        return ASSISTANT_DATA.device_activity(ip=ip, window="1h", limit=100)

    def security(self, site_id: str | None) -> dict:
        from app.services.security_service import posture

        return posture(site_id)

    def alarms(self) -> list[dict]:
        if self.mode == "preview":
            return []
        return self.client.search_org_alarms()


# --------------------------------------------------------------------------- helpers


def _names(rows: list[dict], *, with_site: bool = True, limit: int = MAX_FACT_NAMES) -> str:
    parts = []
    for r in rows[:limit]:
        name = str(r.get("device") or r.get("name") or "Unknown device")
        site = r.get("site")
        parts.append(f"{name} ({site})" if with_site and site else name)
    more = len(rows) - limit
    return ", ".join(parts) + (f" and {more} more" if more > 0 else "")


def _plural(n: int, word: str, plural: str | None = None) -> str:
    return f"{n} {word if n == 1 else (plural or word + 's')}"


def _ago(value: Any) -> str:
    ts = _epoch(value)
    if not ts:
        return ""
    age = _age(ts)
    return f"{age} ago" if age != "unknown" else ""


def _is_disconnect(item: dict) -> bool:
    """Device-down conditions are already listed by name under "... down"."""
    t = str(item.get("type") or "").upper()
    return (
        "CURRENTLY_DOWN" in t
        or t.endswith("_DISCONNECTED")
        or t in {"DEVICE_DOWN", "SWITCH_DOWN", "GATEWAY_DOWN", "AP_DOWN"}
    )


def _down_rows(dash: dict) -> list[dict]:
    return list((dash.get("disconnect_watch") or {}).get("devices") or [])


def _down_rows_with_preview(dash: dict) -> list[dict]:
    rows = _down_rows(dash)
    if rows:
        return rows
    # Preview data and older payloads only carry attention items.
    out = []
    for item in dash.get("attention") or []:
        if "DISCONNECTED" in str(item.get("type") or "").upper() or "CURRENTLY_DOWN" in str(item.get("type") or ""):
            out.append(
                {
                    "device": item.get("device"),
                    "device_type": item.get("device_type"),
                    "mac": item.get("mac"),
                    "site": item.get("site"),
                    "site_id": item.get("site_id"),
                    "age": item.get("age"),
                }
            )
    return out


def _site_label(answer: Answer, intent: Intent) -> str:
    return f" at {intent.site_name}" if intent.site else ""


def _device_chips(answer: Answer, rows: list[dict], limit: int = 8) -> None:
    for r in rows[:limit]:
        key = r.get("mac") or r.get("device")
        if key:
            answer.chip(str(r.get("device") or key), device_action(str(key), r.get("site_id") or ""), "critical")


def _condition_text(item: dict) -> str:
    title = str(item.get("title") or "Condition")
    device = str(item.get("device") or "")
    site = str(item.get("site") or "")
    where = " at ".join(x for x in (device if device and device != "Unknown device" else "", site) if x)
    age = item.get("age")
    text = f"{title}" + (f": {where}" if where else "")
    if age and age != "unknown":
        text += f" ({age})"
    return text


def _ambiguous(answer_intent: str, intent: Intent, verb: str) -> Answer | None:
    if not intent.site or not intent.site.ambiguous:
        return None
    a = Answer(
        intent=answer_intent,
        headline="Which site did you mean?",
        tone="info",
        interpreted_as="Site name is ambiguous",
    )
    for s in intent.site.ambiguous:
        a.fact(s["name"])
        a.chip(s["name"], ask_action(verb.format(site=s["name"])))
    a.suggestions = [verb.format(site=s["name"]) for s in intent.site.ambiguous[:4]]
    return a


def _worst_site_names(dash: dict, limit: int = 3) -> list[str]:
    rows = sorted(
        dash.get("sites") or [],
        key=lambda s: (
            -int(s.get("critical") or 0),
            -(int(s.get("devices_total") or 0) - int(s.get("devices_connected") or 0)),
            -int(s.get("warning") or 0),
            str(s.get("name") or ""),
        ),
    )
    out = []
    for s in rows:
        bad = int(s.get("critical") or 0) + int(s.get("warning") or 0)
        bad += int(s.get("devices_total") or 0) - int(s.get("devices_connected") or 0)
        if bad > 0 and s.get("name"):
            out.append(str(s["name"]))
    return out[:limit]


def _error_fact(answer: Answer, dash: dict) -> None:
    errors = dash.get("errors") or []
    if errors:
        sources = sorted({str(e).split(":", 1)[0] for e in errors})
        answer.fact(
            "Some Mist data could not be read (" + ", ".join(sources) + "), so this may be incomplete.", "warning"
        )


# --------------------------------------------------------------------------- answers


def answer_help(src: AssistantSource | None = None, intent: Intent | None = None) -> Answer:
    a = Answer(
        intent="help",
        headline="Ask me what's broken, where something is, or how a site is doing.",
        interpreted_as="Help",
    )
    a.fact("Network status: “What's broken?”, “Any issues?”, “Top problems”")
    a.fact("A site: “How is Dallas?”, “Issues at HQ” (partial names and typos are fine)")
    a.fact("Outages: “What's down?”, “Which switches are down?”, “Which APs are down at Dallas?”")
    a.fact("Find anything: “Where is aa:bb:cc:dd:ee:ff?”, “Is SW-CORE-01 up?”, “Find 10.20.30.55”")
    a.fact("Switches: “PoE on SW-IDF-2”, “Ports on SW-IDF-2”, “Virtual chassis problems”")
    a.fact("History: “What changed today?”, “Recent changes this week”")
    a.suggestions = [
        "What's broken?",
        "What's down?",
        "Top problems",
        "What changed today?",
        "Virtual chassis problems",
        "Which switches are down?",
    ]
    return a


def answer_unknown(src: AssistantSource, intent: Intent) -> Answer:
    a = answer_help()
    a.intent = "unknown"
    a.headline = "I'm not sure what you're asking. Here is what I can answer."
    a.interpreted_as = "Not recognised"
    return a


def answer_summary(src: AssistantSource, intent: Intent) -> Answer:
    dash = src.dashboard()
    s = dash.get("summary") or {}
    down = _down_rows_with_preview(dash)
    by_kind: dict[str, list[dict]] = defaultdict(list)
    for r in down:
        by_kind[str(r.get("device_type") or "device")].append(r)
    critical = int(s.get("critical") or 0)
    warning = int(s.get("warning") or 0)
    # Prefer the visible Disconnect Watch list so the headline matches the names below.
    devices_down = (
        len(down)
        if (dash.get("disconnect_watch") or {}).get("devices") is not None
        else int(s.get("devices_down") or len(down))
    )
    total_devices = sum(int(h.get("total") or 0) for h in dash.get("health") or [] if h.get("device_type") != "vc")

    a = Answer(intent="summary", headline="", interpreted_as="Organization summary")
    if not devices_down and not critical:
        a.tone = "ok" if not warning else "warning"
        a.headline = (
            f"Nothing looks broken: all {total_devices} managed devices are connected and no critical conditions are open."
            if total_devices
            else "Nothing looks broken: no devices are down and no critical conditions are open."
        )
        if warning:
            a.headline = f"Nothing is down, but {_plural(warning, 'warning')} {'is' if warning == 1 else 'are'} open."
    else:
        a.tone = "critical"
        bits = []
        if devices_down:
            bits.append(f"{_plural(devices_down, 'device')} {'is' if devices_down == 1 else 'are'} down")
        if critical:
            bits.append(f"{_plural(critical, 'critical condition')} {'is' if critical == 1 else 'are'} open")
        a.headline = " and ".join(bits).capitalize() + "."

    for kind in ("switch", "gateway", "ap"):
        rows = by_kind.get(kind) or []
        if rows:
            a.fact(f"{KIND_SHORT_PLURAL[kind]} down ({len(rows)}): {_names(rows)}", "critical")
    for cluster in ((dash.get("disconnect_watch") or {}).get("clusters") or [])[:3]:
        a.fact(
            f"{cluster.get('label')}: {cluster.get('site')}, {cluster.get('down')} of {cluster.get('total')} devices down.",
            cluster.get("severity") or "warning",
        )
    crit_items = [x for x in dash.get("attention") or [] if x.get("severity") == "critical" and not _is_disconnect(x)]
    for item in crit_items[:4]:
        a.fact(_condition_text(item), "critical")
    if warning:
        a.fact(f"{_plural(warning, 'warning condition')} also open.", "warning")
    if int(s.get("vc_degraded") or 0):
        a.fact(f"{_plural(int(s['vc_degraded']), 'virtual chassis', 'virtual chassis')} reporting problems.", "warning")
    worst = _worst_site_names(dash)
    if worst:
        a.fact("Sites needing attention: " + ", ".join(worst))
    _error_fact(a, dash)

    a.chip("Open Command Center", tool("dashboard"))
    _device_chips(
        a,
        [r for r in down if r.get("device_type") in {"switch", "gateway"}]
        + [r for r in down if r.get("device_type") == "ap"],
        6,
    )
    for name in worst[:3]:
        a.chip(f"How is {name}?", ask_action(f"How is {name}?"))
    a.suggestions = [
        *(f"What's wrong at {n}?" for n in worst[:2]),
        "Which switches are down?" if by_kind.get("switch") else "What's down?",
        "Top problems",
        "What changed today?",
        "Virtual chassis problems",
    ]
    if down:
        a.suggestions.insert(1, f"Is {down[0].get('device')} up?")
    return a


def answer_site_status(src: AssistantSource, intent: Intent) -> Answer:
    amb = _ambiguous("site_status", intent, "How is {site}?")
    if amb:
        return amb
    dash = src.dashboard()
    sid, name = intent.site_id or "", intent.site_name or ""
    site_row = next((s for s in dash.get("sites") or [] if str(s.get("id")) == sid), None) or {}
    down = [r for r in _down_rows_with_preview(dash) if str(r.get("site_id") or "") == sid or r.get("site") == name]
    items = [x for x in dash.get("attention") or [] if str(x.get("site_id") or "") == sid or x.get("site") == name]
    critical = [x for x in items if x.get("severity") == "critical" and not _is_disconnect(x)]
    warnings = [x for x in items if x.get("severity") != "critical"]
    total = int(site_row.get("devices_total") or 0)

    a = Answer(
        intent="site_status", headline="", interpreted_as=f"Site status · {name}", scope={"site": name, "site_id": sid}
    )
    if not down and not critical:
        a.tone = "warning" if warnings else "ok"
        a.headline = (
            f"{name} looks healthy"
            + (f": all {total} devices are connected" if total else "")
            + (
                f", with {_plural(len(warnings), 'warning')} open."
                if warnings
                else " and no critical conditions are open."
            )
        )
    else:
        a.tone = "critical"
        bits = []
        if down:
            bits.append(f"{len(down)} of {total} devices are down" if total else f"{_plural(len(down), 'device')} down")
        if critical:
            bits.append(f"{_plural(len(critical), 'critical condition')} open")
        a.headline = f"{name}: " + " and ".join(bits) + "."
    if site_row:
        parts = []
        for label, k in (("APs", "aps"), ("Switches", "switches"), ("Gateways", "gateways")):
            t = int(site_row.get(k) or 0)
            if t:
                parts.append(f"{label} {int(site_row.get(k + '_connected') or 0)}/{t}")
        if parts:
            a.fact(
                "Connected: "
                + ", ".join(parts)
                + (f" ({site_row.get('availability')}% available)" if site_row.get("availability") is not None else "")
            )
    by_kind: dict[str, list[dict]] = defaultdict(list)
    for r in down:
        by_kind[str(r.get("device_type") or "device")].append(r)
    for kind in ("switch", "gateway", "ap"):
        if by_kind.get(kind):
            a.fact(
                f"{KIND_SHORT_PLURAL[kind]} down ({len(by_kind[kind])}): {_names(by_kind[kind], with_site=False)}",
                "critical",
            )
    for cluster in (dash.get("disconnect_watch") or {}).get("clusters") or []:
        if str(cluster.get("site_id")) == sid:
            a.fact(str(cluster.get("message") or ""), cluster.get("severity") or "warning")
    for item in critical[:5]:
        a.fact(_condition_text({**item, "site": ""}), "critical")
    for item in warnings[:3]:
        a.fact(_condition_text({**item, "site": ""}), "warning")
    if len(warnings) > 3:
        a.fact(f"…and {len(warnings) - 3} more warnings.", "warning")
    if not total and not items and not down:
        a.fact("Mist reported no devices or open conditions for this site.")
    _error_fact(a, dash)

    _device_chips(a, down, 6)
    a.chip("List site devices", site_finder_action(sid))
    a.chip("Open Command Center", tool("dashboard"))
    a.suggestions = [
        f"Which APs are down at {name}?" if not by_kind.get("switch") else f"Which switches are down at {name}?",
        f"PoE at {name}",
        f"What changed at {name} today?",
        "What's broken?",
        "Top problems",
    ]
    return a


def answer_down(src: AssistantSource, intent: Intent) -> Answer:
    amb = _ambiguous("down", intent, "What's down at {site}?")
    if amb:
        return amb
    dash = src.dashboard()
    rows = _down_rows_with_preview(dash)
    kind = intent.device_kind
    if kind:
        rows = [r for r in rows if r.get("device_type") == kind]
    if intent.site:
        rows = [r for r in rows if str(r.get("site_id") or "") == intent.site_id or r.get("site") == intent.site_name]
    noun = KIND_PLURAL.get(kind or "", "devices")
    scope = _site_label(None, intent)
    a = Answer(
        intent="down",
        headline="",
        interpreted_as=f"Down {noun}" + (f" · {intent.site_name}" if intent.site else ""),
        scope={"site": intent.site_name, "site_id": intent.site_id, "device_type": kind},
    )
    dismissed = int((dash.get("disconnect_watch") or {}).get("dismissed_known_down") or 0)
    if not rows:
        a.tone = "ok"
        a.headline = f"No {noun} are down{scope}."
    else:
        a.tone = "critical"
        one = KIND_LABEL.get(kind or "", "device")
        a.headline = f"{_plural(len(rows), one, noun)} {'is' if len(rows) == 1 else 'are'} down{scope}."
        grouped: dict[str, list[dict]] = defaultdict(list)
        for r in rows:
            grouped[str(r.get("site") or "Unknown site")].append(r)
        for site, site_rows in sorted(grouped.items(), key=lambda kv: -len(kv[1]))[:8]:
            names = []
            for r in site_rows[:6]:
                age = r.get("age")
                label = str(r.get("device") or "device")
                if not kind:
                    label += f" ({KIND_LABEL.get(str(r.get('device_type')), 'device')}"
                    label += f", down {age})" if age and age != "unknown" else ")"
                elif age and age != "unknown":
                    label += f" (down {age})"
                names.append(label)
            more = len(site_rows) - 6
            a.fact(f"{site}: " + ", ".join(names) + (f" and {more} more" if more > 0 else ""), "critical")
        if len(grouped) > 8:
            a.fact(f"…plus {len(grouped) - 8} more sites.", "warning")
    if dismissed:
        a.fact(f"{_plural(dismissed, 'known-down device')} hidden because it was dismissed in Disconnect Watch.")
    _error_fact(a, dash)
    _device_chips(a, rows, 10)
    a.chip("Open Disconnect Watch", tool("dashboard"))
    sites = Counter(str(r.get("site")) for r in rows if r.get("site"))
    top_site = sites.most_common(1)[0][0] if sites else None
    a.suggestions = [
        *([f"How is {top_site}?"] if top_site else []),
        *([f"Is {rows[0].get('device')} up?"] if rows else []),
        "Which switches are down?" if kind != "switch" else "Which APs are down?",
        "Which gateways are down?" if kind != "gateway" else "Which switches are down?",
        "What's broken?",
        "What changed today?",
    ]
    return a


def _status_word(status: str) -> tuple[str, str]:
    low = (status or "").lower()
    if any(w in low for w in ("disconnected", "offline", "down", "unreachable")):
        return "down (disconnected)", "critical"
    if any(w in low for w in ("connected", "online", "up", "authorized", "authenticated")):
        return "up (connected)", "ok"
    return (status or "seen by Mist").lower(), "info"


def answer_locate(src: AssistantSource, intent: Intent) -> Answer:
    target = intent.target or ""
    result = src.search(target, site_id=intent.site_id)
    rows = result.get("results") or []
    a = Answer(intent="locate", headline="", interpreted_as=f"Find · {target}", scope={"target": target})
    if not rows and intent.site:
        rows = src.search(target).get("results") or []
    if not rows:
        a.tone = "warning"
        a.headline = f"I couldn't find “{target}” in Mist" + (f" at {intent.site_name}." if intent.site else ".")
        a.fact("I searched wireless clients, wired clients, NAC clients and Mist devices (APs, switches, gateways).")
        a.fact("Try the full MAC address, the IP address, or the exact hostname.")
        if result.get("errors"):
            a.fact("Some Mist sources could not be searched, so a match may have been missed.", "warning")
        a.chip("Search in Device Finder", device_action(target))
        a.suggestions = ["What's down?", "What's broken?", "Help"]
        return a
    rows = _rank_exact(rows, target)
    via = _attached_only(src, rows, target)
    if via is not None:
        return via
    top = rows[0]
    kind = str(top.get("kind") or "infrastructure")
    mac = str(top.get("mac") or "")
    site_id = str(top.get("site_id") or intent.site_id or "")
    detail: dict = {}
    if mac:
        try:
            detail = src.detail(kind, mac, site_id or None) or {}
        except (MistApiError, ValueError):
            detail = {}
    ident = detail.get("identity") or {}
    conn = detail.get("connection") or {}
    dev = detail.get("device") or {}
    title = str(ident.get("title") or top.get("title") or target)
    site = str(ident.get("site") or top.get("site") or "")
    display_mac = str(ident.get("mac") or top.get("display_mac") or mac)
    ip = str(ident.get("ip") or conn.get("ip") or top.get("ip") or "")
    last_seen = conn.get("last_seen") or top.get("last_seen")
    seen = _ago(last_seen)

    if kind == "infrastructure":
        status = str(conn.get("status") or dev.get("status") or "")
        if not status:
            inv = next((d for d in src.devices() if normalize(str(d.get("mac") or "")).replace(" ", "") == mac), None)
            if inv is not None:
                status = "Disconnected" if _is_down(inv) else "Connected"
        word, tone = _status_word(status)
        dtype = str(top.get("device_type") or conn.get("type") or "device").lower()
        a.tone = tone
        a.headline = f"{title} is {word}" + (f" at {site}" if site else "") + "."
        if tone == "critical" and seen:
            a.headline = a.headline[:-1] + f", last seen {seen}."
        a.fact(
            " · ".join(
                x
                for x in (
                    KIND_LABEL.get(dtype, dtype).capitalize(),
                    dev.get("model") or top.get("subtitle"),
                    f"firmware {dev.get('version')}" if dev.get("version") else "",
                )
                if x
            )
        )
        a.fact(" · ".join(x for x in (f"MAC {display_mac}" if display_mac else "", f"IP {ip}" if ip else "") if x))
        if seen and tone != "critical":
            a.fact(f"Last seen {seen}.")
        ps = detail.get("ports_summary") or {}
        if ps.get("total"):
            a.fact(f"Ports: {ps.get('up', 0)} up, {ps.get('down', 0)} down, {ps.get('poe_on', 0)} delivering PoE.")
        alarms = detail.get("alarms") or []
        if alarms:
            titles = Counter(str(x.get("type") or "alarm").replace("_", " ").lower() for x in alarms)
            a.fact(
                f"{_plural(len(alarms), 'active alarm')}: " + ", ".join(t for t, _ in titles.most_common(4)), "warning"
            )
        a.chip("Open in Device Finder", device_action(display_mac or title, site_id), tone)
        if dtype == "switch":
            a.chip("Ports (Port Toolkit)", switch_action("operations", site_id, mac=mac))
            a.chip("PoE (Power Guard)", switch_action("poe", site_id, mac=mac))
        a.suggestions = [
            f"Ports on {title}" if dtype == "switch" else f"How is {site}?",
            f"PoE on {title}" if dtype == "switch" else "What's down?",
            f"How is {site}?" if site else "What's broken?",
            "What changed today?",
            "Virtual chassis problems" if dtype == "switch" else "Which APs are down?",
        ]
    else:
        wired = kind == "wired_client" or bool(conn.get("switch") or conn.get("port_id"))
        status = str(conn.get("status") or "")
        word, tone = _status_word(status)
        where = []
        if wired:
            sw = conn.get("switch") or top.get("attachment")
            port = conn.get("port_id") or top.get("port_id")
            if sw:
                where.append(f"on switch {sw}" + (f" port {port}" if port else ""))
        else:
            ap = conn.get("ap") or top.get("attachment")
            if ap:
                where.append(f"on AP {ap}")
            if conn.get("ssid") or top.get("network"):
                where.append(f"SSID {conn.get('ssid') or top.get('network')}")
        a.tone = tone if tone != "info" else "ok"
        kind_label = "Wired client" if wired else ("Wireless client" if kind == "wireless_client" else "NAC client")
        a.headline = (
            f"{title} is a {kind_label.lower()}"
            + (f" at {site}" if site else "")
            + (f", {where[0]}" if where else "")
            + "."
        )
        if seen:
            a.fact(f"Last seen {seen}" + (f" · status: {word}" if status else "") + ".")
        a.fact(" · ".join(x for x in (f"MAC {display_mac}" if display_mac else "", f"IP {ip}" if ip else "") if x))
        vlan = conn.get("vlan") or top.get("vlan")
        extra = [x for x in where[1:]]
        if vlan:
            extra.append(f"VLAN {vlan}")
        if conn.get("band"):
            extra.append(f"{conn.get('band')} band")
        if conn.get("rssi") not in (None, ""):
            extra.append(f"signal {conn.get('rssi')} dBm")
        if extra:
            a.fact(" · ".join(str(x) for x in extra))
        auth = detail.get("authentication") or {}
        if auth.get("state") and auth.get("state") != "Not reported":
            a.fact(
                f"Authentication: {auth.get('state')}"
                + (f" ({auth.get('method')})" if auth.get("method") and auth.get("method") != "Not reported" else "")
            )
        port = detail.get("port") or {}
        if wired and isinstance(port, dict) and port.get("up") is not None:
            a.fact(
                f"Switch port is {'up' if port.get('up') else 'down'}"
                + (f" at {port.get('speed')}" if port.get("speed") else "")
                + ".",
                "ok" if port.get("up") else "critical",
            )
        a.chip("Open in Device Finder", device_action(display_mac or title, site_id), a.tone)
        sw_mac = str(top.get("attachment_mac") or "")
        if wired and sw_mac:
            a.chip("Switch ports", switch_action("operations", site_id, mac=sw_mac))
        if conn.get("switch") or conn.get("ap") or top.get("attachment"):
            att = str(conn.get("switch") or conn.get("ap") or top.get("attachment"))
            if att and not att.lower().endswith("unknown"):
                a.suggestions.append(f"Is {att} up?")
        a.suggestions += [f"How is {site}?" if site else "What's broken?", "What's down?", "What changed today?"]
    if len(rows) > 1:
        others = [r for r in rows[1:6] if r.get("mac") != mac]
        if others:
            a.fact(
                f"Also matched {_plural(len(rows) - 1, 'other record')}: "
                + ", ".join(f"{r.get('title')} ({r.get('kind_label') or r.get('kind')})" for r in others[:3])
            )
            for r in others[:3]:
                a.chip(
                    str(r.get("title") or r.get("display_mac")),
                    device_action(str(r.get("display_mac") or r.get("title")), str(r.get("site_id") or "")),
                )
    return a


def _rank_exact(rows: list[dict], target: str) -> list[dict]:
    """Put the record that IS the target first (a client attached to AP-1 must not win "is AP-1 up?")."""
    want = normalize(target).replace(" ", "")

    def exact(r: dict) -> int:
        keys = (r.get("title"), r.get("hostname"), r.get("mac"), r.get("display_mac"), r.get("ip"), r.get("serial"))
        return 0 if any(want and normalize(str(k or "")).replace(" ", "") == want for k in keys) else 1

    return sorted(
        rows, key=lambda r: (exact(r), 0 if r.get("kind") == "infrastructure" else 1) if exact(r) == 0 else (1, 0)
    )


def _attached_only(src: AssistantSource, rows: list[dict], target: str) -> Answer | None:
    """Search found only clients *attached to* the target (an AP/switch name), not the device itself."""
    want = normalize(target).replace(" ", "")
    if not want or any(
        normalize(str(r.get(k) or "")).replace(" ", "") == want for r in rows for k in ("title", "hostname", "mac")
    ):
        return None
    attached = [r for r in rows if normalize(str(r.get("attachment") or "")).replace(" ", "") == want]
    if not attached:
        return None
    name = str(attached[0].get("attachment"))
    site = str(attached[0].get("site") or "")
    a = Answer(intent="locate", headline="", interpreted_as=f"Find · {target}", scope={"target": target})
    try:
        down = [
            r
            for r in _down_rows_with_preview(src.dashboard())
            if normalize(str(r.get("device") or "")).replace(" ", "") == want
        ]
    except MistApiError:
        down = []
    if down:
        a.tone = "critical"
        a.headline = (
            f"{name} is down (disconnected)" + (f" at {down[0].get('site')}" if down[0].get("site") else "") + "."
        )
        if down[0].get("age") and down[0].get("age") != "unknown":
            a.fact(f"Down for {down[0]['age']}.", "critical")
        a.fact(
            f"{_plural(len(attached), 'client')} last seen through it: "
            + ", ".join(str(r.get("title")) for r in attached[:4])
        )
    else:
        a.tone = "ok"
        a.headline = (
            f"{name} has {_plural(len(attached), 'client')} connected through it"
            + (f" at {site}" if site else "")
            + "."
        )
        a.fact("Clients: " + ", ".join(str(r.get("title")) for r in attached[:5]))
    a.chip("Open in Device Finder", device_action(name, str(attached[0].get("site_id") or "")), a.tone)
    for r in attached[:3]:
        a.chip(
            str(r.get("title")), device_action(str(r.get("display_mac") or r.get("title")), str(r.get("site_id") or ""))
        )
    a.suggestions = [
        f"How is {site}?" if site else "What's broken?",
        "What's down?",
        "Which APs are down?",
        "What changed today?",
    ]
    return a


def _resolve_switch(src: AssistantSource, intent: Intent) -> dict | None:
    """Turn a switch name/IP into {site_id, device_id, name, mac} (read-only lookups)."""
    target = intent.target or ""
    if not target:
        return None
    candidates: list[dict] = []
    try:
        rows = src.devices()
    except MistApiError:
        rows = []
    names = {_name_from_row(r): r for r in rows if _device_type(r) == "switch"}
    hit = match_name(target, list(names))
    if hit:
        candidates.append(names[hit])
    if not candidates:
        found = src.search(target, site_id=intent.site_id).get("results") or []
        candidates = [
            {"name": r.get("title"), "mac": r.get("mac"), "site_id": r.get("site_id")}
            for r in found
            if r.get("kind") == "infrastructure" and str(r.get("device_type") or "") in {"switch", ""}
        ]
    for cand in candidates:
        site_id = str(cand.get("site_id") or "")
        mac = normalize(str(cand.get("mac") or "")).replace(" ", "")
        if not site_id:
            continue
        for sw in src.switches(site_id):
            if (mac and sw.get("mac") == mac) or normalize(str(sw.get("name"))) == normalize(str(cand.get("name"))):
                return {"site_id": site_id, "device_id": sw.get("id"), "name": sw.get("name"), "mac": sw.get("mac")}
    return None


def _site_name(src: AssistantSource, site_id: str) -> str:
    for s in src.sites():
        if str(s.get("id")) == site_id:
            return str(s.get("name") or site_id)
    return site_id


def answer_poe(src: AssistantSource, intent: Intent) -> Answer:
    amb = _ambiguous("poe", intent, "PoE at {site}")
    if amb:
        return amb
    a = Answer(intent="poe", headline="", interpreted_as="PoE")
    if intent.target:
        sw = _resolve_switch(src, intent)
        if not sw:
            a.tone = "warning"
            a.headline = f"I couldn't find a switch called “{intent.target}”."
            a.chip("Open Power Guard", tool("poe"))
            a.suggestions = ["Which switches are down?", "Help"]
            return a
        ps = src.poe(sw["site_id"], sw["device_id"])
        a.interpreted_as = f"PoE · {sw['name']}"
        draw = ps.get("draw_watts") or 0
        budget = ps.get("budget_watts")
        util = ps.get("utilization_pct")
        a.headline = (
            f"{sw['name']} is delivering {draw:.1f} W"
            + (f" of its {budget:.0f} W PoE budget ({util:.0f}%)" if budget and util is not None else "")
            + f" to {_plural(int(ps.get('powered_ports') or 0), 'powered port')}."
        )
        a.tone = "ok"
        for risk in ps.get("risks") or []:
            sev = str(risk.get("severity") or "info")
            if sev in {"critical", "warning"}:
                a.tone = "critical" if sev == "critical" or a.tone == "critical" else "warning"
            a.fact(f"{risk.get('title')}: {risk.get('detail')}" if sev != "info" else str(risk.get("title")), sev)
        ports = sorted(ps.get("ports") or [], key=lambda p: -(float(p.get("poe_watts") or 0)))
        if ports:
            a.fact(
                "Highest draw: "
                + ", ".join(
                    f"{p.get('port_id')} {float(p.get('poe_watts') or 0):.1f} W"
                    + (
                        f" ({p.get('neighbor_system_name') or p.get('client_hostname')})"
                        if p.get("neighbor_system_name") or p.get("client_hostname")
                        else ""
                    )
                    for p in ports[:4]
                )
            )
        for m in (ps.get("per_member") or [])[:4] if len(ps.get("per_member") or []) > 1 else []:
            if m.get("max_power"):
                a.fact(
                    f"Member {m.get('fpc')}: {float(m.get('power_draw') or 0):.1f} W of {float(m.get('max_power') or 0):.0f} W"
                )
        a.chip("Open in Power Guard", switch_action("poe", sw["site_id"], device_id=sw["device_id"], mac=sw["mac"]))
        a.chip(
            "Ports (Port Toolkit)", switch_action("operations", sw["site_id"], device_id=sw["device_id"], mac=sw["mac"])
        )
        site_name = _site_name(src, sw["site_id"])
        a.suggestions = [
            f"Ports on {sw['name']}",
            f"Is {sw['name']} up?",
            f"PoE at {site_name}",
            f"How is {site_name}?",
        ]
        return a
    if not intent.site:
        a.headline = "Which switch or site should I check PoE for?"
        a.fact("Ask “PoE on <switch name>” for one switch or “PoE at <site>” for a whole site.")
        try:
            worst = _worst_site_names(src.dashboard(), 3)
        except MistApiError:
            worst = []
        a.suggestions = [f"PoE at {n}" for n in worst] + ["Which switches are down?", "Help"]
        a.chip("Open Power Guard", tool("poe"))
        return a
    switches = src.switches(intent.site_id or "")[:60]
    a.interpreted_as = f"PoE · {intent.site_name}"
    results: list[tuple[dict, dict | None]] = []

    def read(sw: dict) -> tuple[dict, dict | None]:
        try:
            return sw, src.poe(intent.site_id or "", sw["id"])
        except Exception:
            return sw, None

    with ThreadPoolExecutor(max_workers=6, thread_name_prefix="assistant-poe") as pool:
        results = list(pool.map(read, switches))
    ok = [(sw, ps) for sw, ps in results if ps]
    draw = sum(float(ps.get("draw_watts") or 0) for _, ps in ok)
    powered = sum(int(ps.get("powered_ports") or 0) for _, ps in ok)
    a.headline = f"{intent.site_name}: {draw:.1f} W of PoE across {_plural(powered, 'powered port')} on {_plural(len(ok), 'switch', 'switches')}."
    a.tone = "ok"
    hot = [(sw, ps) for sw, ps in ok if (ps.get("utilization_pct") or 0) >= 80]
    for sw, ps in sorted(hot, key=lambda x: -(x[1].get("utilization_pct") or 0))[:5]:
        a.tone = "critical" if (ps.get("utilization_pct") or 0) >= 90 else "warning"
        a.fact(f"{sw['name']} is at {ps.get('utilization_pct'):.0f}% of its PoE budget.", a.tone)
    for sw, ps in sorted(ok, key=lambda x: -(float(x[1].get("draw_watts") or 0)))[:4]:
        a.fact(f"{sw['name']}: {float(ps.get('draw_watts') or 0):.1f} W, {ps.get('powered_ports') or 0} powered ports")
        a.chip(str(sw["name"]), switch_action("poe", intent.site_id or "", device_id=sw["id"], mac=sw.get("mac", "")))
    if len(ok) < len(results):
        a.fact(f"{_plural(len(results) - len(ok), 'switch', 'switches')} could not be read.", "warning")
    if not switches:
        a.headline = f"{intent.site_name} has no switches in Mist."
    a.suggestions = [f"How is {intent.site_name}?", f"Which switches are down at {intent.site_name}?", "Top problems"]
    if ok:
        a.suggestions.insert(0, f"Ports on {ok[0][0]['name']}")
    return a


def answer_ports(src: AssistantSource, intent: Intent) -> Answer:
    a = Answer(intent="ports", headline="", interpreted_as="Switch ports")
    sw = _resolve_switch(src, intent) if intent.target else None
    if not sw:
        a.tone = "warning" if intent.target else "info"
        a.headline = (
            f"I couldn't find a switch called “{intent.target}”."
            if intent.target
            else "Which switch should I check ports on?"
        )
        a.fact("Ask “Ports on <switch name>”, for example “Ports on SW-IDF-2”.")
        a.chip("Open Port Toolkit", tool("operations"))
        a.suggestions = ["Which switches are down?", "Help"]
        return a
    data = src.switch_ports(sw["site_id"], sw["device_id"])
    ports = [p for p in data.get("ports") or [] if not p.get("internal")]
    a.interpreted_as = f"Ports · {sw['name']}"
    action = switch_action("operations", sw["site_id"], device_id=sw["device_id"], mac=sw["mac"])
    if intent.port_id:
        p = next((x for x in ports if str(x.get("port_id")).lower() == intent.port_id), None)
        if not p:
            a.tone = "warning"
            a.headline = f"{sw['name']} did not report port {intent.port_id}."
        else:
            up = bool(p.get("up"))
            a.tone = "ok" if up else "critical"
            a.headline = (
                f"Port {p.get('port_id')} on {sw['name']} is {'up' if up else 'down'}"
                + (f" at {p.get('speed')}" if up and p.get("speed") and p.get("speed") != "—" else "")
                + "."
            )
            neighbor = p.get("neighbor_system_name") or p.get("client_hostname") or p.get("manufacturer")
            if neighbor:
                a.fact(f"Connected device: {neighbor}" + (f" ({p.get('mac')})" if p.get("mac") else ""))
            if p.get("poe_on") or p.get("poe_watts"):
                a.fact(f"PoE: {float(p.get('poe_watts') or 0):.1f} W")
            if p.get("vlan_id"):
                a.fact(f"VLAN {p.get('vlan_id')}")
            if p.get("description"):
                a.fact(f"Description: {p.get('description')}")
            errs = (p.get("rx_errors") or 0) + (p.get("tx_errors") or 0)
            if errs:
                a.fact(f"{int(errs)} interface errors recorded.", "warning")
        a.chip("Open in Port Toolkit", action)
        a.suggestions = [f"Ports on {sw['name']}", f"PoE on {sw['name']}", f"Is {sw['name']} up?"]
        return a
    up = [p for p in ports if p.get("up")]
    down = [p for p in ports if not p.get("up")]
    poe = [p for p in ports if p.get("poe_on") or (p.get("poe_watts") or 0) > 0]
    a.tone = "ok"
    a.headline = f"{sw['name']}: {len(up)} of {len(ports)} ports are up, {len(down)} down, {len(poe)} delivering PoE."
    errored = sorted(
        [p for p in up if (p.get("rx_errors") or 0) + (p.get("tx_errors") or 0) > 0],
        key=lambda p: -((p.get("rx_errors") or 0) + (p.get("tx_errors") or 0)),
    )
    if errored:
        a.tone = "warning"
        a.fact(
            "Ports with errors: "
            + ", ".join(
                f"{p.get('port_id')} ({int((p.get('rx_errors') or 0) + (p.get('tx_errors') or 0))})"
                for p in errored[:5]
            ),
            "warning",
        )
    busy = sorted([p for p in up if p.get("utilisation_pct")], key=lambda p: -(p.get("utilisation_pct") or 0))
    if busy and (busy[0].get("utilisation_pct") or 0) >= 50:
        a.fact("Busiest: " + ", ".join(f"{p.get('port_id')} {p.get('utilisation_pct')}%" for p in busy[:3]))
    uplinks = [p for p in up if p.get("neighbor_system_name")]
    if uplinks:
        a.fact(
            "Neighbors (LLDP): "
            + ", ".join(f"{p.get('port_id')} → {p.get('neighbor_system_name')}" for p in uplinks[:4])
        )
    speeds = Counter(p.get("speed") for p in up if p.get("speed") and p.get("speed") != "—")
    if speeds:
        a.fact("Link speeds: " + ", ".join(f"{n}× {s}" for s, n in speeds.most_common(4)))
    for w in (data.get("warnings") or [])[:2]:
        a.fact(str(w), "warning")
    a.chip("Open in Port Toolkit", action)
    a.chip("PoE (Power Guard)", switch_action("poe", sw["site_id"], device_id=sw["device_id"], mac=sw["mac"]))
    a.suggestions = [
        f"PoE on {sw['name']}",
        f"Is {sw['name']} up?",
        f"How is {_site_name(src, sw['site_id'])}?",
        "Virtual chassis problems",
    ]
    return a


def answer_vc(src: AssistantSource, intent: Intent) -> Answer:
    dash = src.dashboard()
    vc_row = next((h for h in dash.get("health") or [] if h.get("device_type") == "vc"), {}) or {}
    issues = [x for x in dash.get("attention") or [] if x.get("group") == "Virtual Chassis"]
    if intent.site:
        issues = [x for x in issues if str(x.get("site_id")) == intent.site_id or x.get("site") == intent.site_name]
    total = int(vc_row.get("total") or 0)
    vc_down = int(vc_row.get("down") or 0)
    a = Answer(
        intent="vc",
        headline="",
        interpreted_as="Virtual chassis health" + (f" · {intent.site_name}" if intent.site else ""),
    )
    affected = {(x.get("device"), x.get("site")) for x in issues}
    if not issues and not vc_down:
        a.tone = "ok"
        a.headline = (
            f"All {total} virtual chassis look healthy." if total else "No virtual chassis problems are reported."
        )
    else:
        a.tone = "critical" if vc_down or any(x.get("severity") == "critical" for x in issues) else "warning"
        bits = []
        if affected:
            bits.append(f"{_plural(len(affected), 'virtual chassis', 'virtual chassis')} reporting problems")
        if vc_down:
            bits.append(f"{vc_down} disconnected")
        a.headline = (" and ".join(bits) + (f" (of {total})" if total else "") + ".").capitalize()
    for item in issues[:8]:
        a.fact(_condition_text(item), item.get("severity") or "warning")
        if item.get("mac") or item.get("device"):
            a.chip(
                str(item.get("device") or item.get("mac")),
                device_action(str(item.get("mac") or item.get("device")), str(item.get("site_id") or "")),
                item.get("severity") or "",
            )
    if vc_down:
        down_switches = [r for r in _down_rows(dash) if r.get("device_type") == "switch"]
        if down_switches:
            a.fact(f"Disconnected switches (may include VC members): {_names(down_switches)}", "critical")
    _error_fact(a, dash)
    a.chip("Open Chassis Manager", tool("virtual-chassis"))
    a.suggestions = ["Which switches are down?", "What's broken?", "What changed today?", "Top problems"]
    if issues and issues[0].get("device"):
        a.suggestions.insert(0, f"Ports on {issues[0]['device']}")
    return a


def answer_top(src: AssistantSource, intent: Intent) -> Answer:
    dash = src.dashboard()
    sites = []
    for s in dash.get("sites") or []:
        down = int(s.get("devices_total") or 0) - int(s.get("devices_connected") or 0)
        score = int(s.get("critical") or 0) * 3 + down * 2 + int(s.get("warning") or 0)
        if score > 0:
            sites.append((score, down, s))
    sites.sort(key=lambda x: (-x[0], str(x[2].get("name"))))
    a = Answer(intent="top", headline="", interpreted_as="Top problems")
    if not sites:
        a.tone = "ok"
        a.headline = "No site has open problems right now."
    else:
        a.tone = "critical" if any(x[2].get("critical") or x[1] for x in sites[:1]) else "warning"
        a.headline = f"{sites[0][2].get('name')} has the most problems right now."
        for _, down, s in sites[:6]:
            bits = []
            if s.get("critical"):
                bits.append(_plural(int(s["critical"]), "critical"))
            if s.get("warning"):
                bits.append(_plural(int(s["warning"]), "warning"))
            if down:
                bits.append(f"{down} down")
            if s.get("availability") is not None:
                bits.append(f"{s.get('availability')}% connected")
            a.fact(f"{s.get('name')}: " + ", ".join(bits), "critical" if s.get("critical") or down else "warning")
            a.chip(str(s.get("name")), ask_action(f"How is {s.get('name')}?"))
    groups = dash.get("alarm_groups") or []
    if groups:
        a.fact("Most common problem types: " + ", ".join(f"{g.get('name')} ({g.get('count')})" for g in groups[:4]))
    _error_fact(a, dash)
    a.chip("Open Command Center", tool("dashboard"))
    a.suggestions = [f"How is {x[2].get('name')}?" for x in sites[:2]] + [
        "What's down?",
        "Virtual chassis problems",
        "What changed today?",
    ]
    return a


def answer_alarms(src: AssistantSource, intent: Intent) -> Answer:
    dash = src.dashboard()
    items = dash.get("attention") or []
    if intent.site:
        items = [x for x in items if str(x.get("site_id")) == intent.site_id or x.get("site") == intent.site_name]
    crit = [x for x in items if x.get("severity") == "critical"]
    warn = [x for x in items if x.get("severity") != "critical"]
    scope = f" at {intent.site_name}" if intent.site else ""
    a = Answer(
        intent="alarms",
        headline="",
        interpreted_as="Open conditions" + (f" · {intent.site_name}" if intent.site else ""),
    )
    a.tone = "critical" if crit else ("warning" if warn else "ok")
    a.headline = (
        f"{_plural(len(crit), 'critical condition')} and {_plural(len(warn), 'warning')} are open{scope}."
        if items
        else f"No open alarms or conditions{scope}."
    )
    for item in crit[:6]:
        a.fact(_condition_text(item), "critical")
    for item in warn[: max(0, 8 - min(6, len(crit)))]:
        a.fact(_condition_text(item), "warning")
    acked = sum(1 for x in items if x.get("acked"))
    if acked:
        a.fact(f"{acked} of these {'is' if acked == 1 else 'are'} acknowledged but still unresolved.")
    _error_fact(a, dash)
    a.chip("Open Command Center", tool("dashboard"))
    a.suggestions = ["What's down?", "Top problems", "Virtual chassis problems", "What changed today?"]
    return a


_DURATION_TEXT = {
    "1h": "last hour",
    "1d": "last 24 hours",
    "2d": "last 2 days",
    "7d": "last 7 days",
    "30d": "last 30 days",
}


def answer_changes(src: AssistantSource, intent: Intent) -> Answer:
    logs = src.audit(intent.duration)
    if intent.site:
        logs = [x for x in logs if str(x.get("site_id") or "") == intent.site_id]
    when = _DURATION_TEXT.get(intent.duration, "last 24 hours")
    scope = f" at {intent.site_name}" if intent.site else ""
    a = Answer(
        intent="changes",
        headline="",
        interpreted_as=f"Changes · {when}" + (f" · {intent.site_name}" if intent.site else ""),
    )
    if src.mode == "preview":
        a.headline = "Change history needs a Mist connection."
        a.chip("Open Activity Log", tool("history"))
        return a
    if not logs:
        a.tone = "ok"
        a.headline = f"No changes were recorded in Mist in the {when}{scope}."
    else:
        admins = Counter(str(x.get("admin_name") or x.get("admin") or "Unknown admin") for x in logs)
        a.headline = f"{_plural(len(logs), 'change')} recorded in Mist in the {when}{scope}, by {_plural(len(admins), 'person', 'people')}."
        a.fact("Who: " + ", ".join(f"{n} ({c})" for n, c in admins.most_common(4)))
        site_names = {str(s.get("id")): str(s.get("name")) for s in src.sites()} if not intent.site else {}
        for x in logs[:8]:
            ts = _epoch(x.get("timestamp"))
            when_txt = datetime.fromtimestamp(ts, tz=timezone.utc).astimezone().strftime("%a %H:%M") if ts else ""
            site = site_names.get(str(x.get("site_id") or ""), "")
            msg = str(x.get("message") or x.get("activity") or "Configuration change")
            who = str(x.get("admin_name") or x.get("admin") or "")
            a.fact(" · ".join(v for v in (when_txt, who, msg[:140], site) if v))
        if len(logs) > 8:
            a.fact(f"…and {len(logs) - 8} more in the Activity Log.")
    a.chip("Open Activity Log", tool("history"))
    a.suggestions = [
        "Recent changes this week" if intent.duration != "7d" else "What changed today?",
        "What's broken?",
        "What's down?",
        "Top problems",
    ]
    return a


def answer_firmware(src: AssistantSource, intent: Intent) -> Answer:
    rows = src.devices()
    if intent.site:
        rows = [d for d in rows if str(d.get("site_id") or "") == intent.site_id]
    versions: dict[str, Counter] = defaultdict(Counter)
    for d in rows:
        versions[str(d.get("model") or "Unknown model")][str(d.get("version") or "unknown")] += 1
    mixed = [(m, c) for m, c in versions.items() if len([v for v in c if v != "unknown"]) > 1]
    scope = f" at {intent.site_name}" if intent.site else ""
    a = Answer(intent="firmware", headline="", interpreted_as="Firmware consistency")
    a.tone = "warning" if mixed else "ok"
    a.headline = (
        f"{_plural(len(mixed), 'model')} {'runs' if len(mixed) == 1 else 'run'} more than one firmware version{scope}."
        if mixed
        else f"Every model runs a single firmware version{scope}."
    )
    for model, counts in sorted(mixed, key=lambda x: -sum(x[1].values()))[:8]:
        a.fact(f"{model}: " + ", ".join(f"{v} ×{n}" for v, n in counts.most_common(4)), "warning")
    a.chip("Open Security Operations", tool("security"))
    a.suggestions = ["Virtual chassis problems", "What's broken?", "What changed this week?"]
    return a


def answer_security(src: AssistantSource, intent: Intent) -> Answer:
    p = src.security(intent.site_id)
    s = p.get("summary") or {}
    scope = f" at {intent.site_name}" if intent.site else ""
    a = Answer(intent="security", headline="", interpreted_as="Security posture")
    crit, warn = int(s.get("critical") or 0), int(s.get("warning") or 0)
    a.tone = "critical" if crit else ("warning" if warn else "ok")
    a.headline = f"Security{scope}: {_plural(crit, 'critical finding')} and {_plural(warn, 'warning')}."
    for f in (p.get("findings") or [])[:6]:
        a.fact(
            f"{f.get('title')}: {f.get('count')} item(s)", "critical" if f.get("severity") == "critical" else "warning"
        )
    if s.get("nac_denials"):
        a.fact(f"{s.get('nac_denials')} recent access (NAC) denials.")
    a.chip("Open Security Operations", tool("security"))
    a.suggestions = ["What's broken?", "What changed today?", "Top problems"]
    return a


def answer_traffic(src: AssistantSource, intent: Intent) -> Answer:
    target = intent.target or ""
    activity = src.traffic(target)
    records = activity.get("records") or []
    a = Answer(intent="traffic", headline="", interpreted_as=f"Traffic · {target}")
    if records:
        a.headline = f"Found {_plural(int(activity.get('retrieved_count') or len(records)), 'recent session record')} for {target}."
        apps = Counter(
            str((x.get("data") or {}).get("application", {}).get("name") or "") for x in records if isinstance(x, dict)
        )
        apps.pop("", None)
        if apps:
            a.fact("Applications: " + ", ".join(f"{n} ({c})" for n, c in apps.most_common(5)))
    else:
        a.tone = "warning"
        err = (activity.get("error") or {}).get("message") if isinstance(activity.get("error"), dict) else ""
        a.headline = f"No traffic records are available for {target}."
        if err:
            a.fact(str(err), "warning")
    a.chip("Open in Device Finder", device_action(target))
    a.suggestions = [f"Where is {target}?", "What's broken?"]
    return a


HANDLERS: dict[str, Callable[[AssistantSource, Intent], Answer]] = {
    "help": answer_help,
    "unknown": answer_unknown,
    "summary": answer_summary,
    "site_status": answer_site_status,
    "down": answer_down,
    "locate": answer_locate,
    "changes": answer_changes,
    "poe": answer_poe,
    "ports": answer_ports,
    "vc": answer_vc,
    "top": answer_top,
    "alarms": answer_alarms,
    "firmware": answer_firmware,
    "security": answer_security,
    "traffic": answer_traffic,
}


def ask(question: str, source: AssistantSource | None = None) -> dict:
    src = source or AssistantSource()
    q = (question or "").strip()[:500]
    try:
        try:
            sites = src.sites()
        except MistApiError:
            sites = []
        intent = intents.parse(q, sites, src.device_names)
        answer = HANDLERS.get(intent.name, answer_unknown)(src, intent)
    except MistApiError as exc:
        answer = Answer(
            intent="error",
            headline="I couldn't read that from Mist right now.",
            tone="warning",
            interpreted_as="Mist request failed",
        )
        answer.fact(str(exc), "warning")
        answer.fact("Check the connection in Settings & Support, then ask again.")
        answer.chip("Open Settings", tool("settings"))
        answer.suggestions = ["What's broken?", "Help"]
    out = answer.to_dict(mode=src.mode)
    out["question"] = q
    return out
