"""NodeWatch's own security analytics (v0.10.30): Reach, Pressure and Cases.

Everything here is computed from vendor-neutral :class:`SecurityEvent` dictionaries plus NodeWatch's own
topology context, so it behaves identically whichever vendors deliver the detections.

**Reach** — how far a detection got into the organisation, on NodeWatch's five-step scale:

====  ===================  ==================================================================================
1     Knocking             scans, probes, floods, policy refusals: someone tried the door
2     Stopped at the door  an exploit, malware, credential or malicious-web attempt that a control blocked
3     Got through          the same attempt, but the control only alerted or allowed it
4     Calling out          an inside host contacting an attacker (callback / C2) — even when blocked, the
                           host is likely infected — or data that actually left
5     Spreading inside     attack activity between inside hosts
====  ===================  ==================================================================================

**Pressure** — per site, how hard it is being pushed: Σ severity weight × reach weight × √repeats, scaled so
the most pressed site is 100.

**Cases** — NodeWatch correlates detections into cases with these rules (one case per subject, reopened when
new detections arrive after it was closed):

* ``compromise`` — an inside host calling out or leaking data (Reach 4);
* ``lateral`` — an inside host attacking other inside hosts (Reach 5);
* ``breach`` — an attempt that got through to an inside target (Reach 3, inbound);
* ``campaign`` — one outside attacker reaching ≥ ``CAMPAIGN_TARGETS`` targets or ≥ ``CAMPAIGN_HIGH``
  high-severity attempts;
* ``wireless`` — wireless intrusions at a site;
* ``vendor`` — incidents a security platform already raised (``security.incidents``).

Each case carries a **score** (0–100): points for its highest Reach (10 / 20 / 55 / 70 / 75), for its worst
severity (−5 … +15), for volume (up to 10) and 10 more when the furthest step was not stopped — the parts are
returned with it (:func:`score_parts`), so the page shows why a case ranks where it does.
"""

from __future__ import annotations

import math
import re
from collections import Counter, defaultdict
from typing import Any, Iterable

from app.integrations.domain import SECURITY_EVENT_KIND_LABELS, safe_console_url, stable_key
from app.integrations.geo import country_name, country_point
from app.services.soc.context import Context, private_ip

REACH = {
    1: ("Knocking", "Scans, probes and floods: someone tried the door."),
    2: ("Stopped at the door", "An attack attempt that a security control blocked."),
    3: ("Got through", "An attack attempt the control only alerted on or allowed."),
    4: ("Calling out", "An inside host contacted an attacker or sent data out."),
    5: ("Spreading inside", "Attack activity between your own hosts."),
}
SEV_W = {"critical": 10.0, "major": 6.0, "warning": 3.0, "info": 1.0}
REACH_W = {1: 1.0, 2: 1.5, 3: 4.0, 4: 6.0, 5: 8.0}
SEV_ORDER = {"critical": 0, "major": 1, "warning": 2, "info": 3}
CAMPAIGN_TARGETS = 3
CAMPAIGN_HIGH = 10
MAX_CASE_EVENTS = 300

_ATTACK = {"exploit", "malware", "web", "credential", "data_loss", "policy", "other"}


# v0.10.32: DNS-security / URL reputation verdicts that are hygiene, not attacks. Firewalls log a DNS lookup of
# a "Proxy" (e.g. iCloud Private Relay, mask.icloud.com), "Grayware", "Ad Tracking", "Parked" or "Newly
# Registered" domain with the spyware/DNS sub-type, so it arrived as a callout to an attacker (Reach 4) and
# inflated "Got through" and "Hosts calling out". The category is the start of the threat name
# ("Proxy:mask.icloud.com"); those categories are policy decisions, not compromise.
_HYGIENE_PREFIX = re.compile(
    r"^\s*(proxy|proxy[- ]avoidance|anonymi[sz]er|grayware|greyware|ad[- ]?tracking|adtracking|parked|"
    r"newly[- ]registered(?: domain)?|nrd|dynamic[- ]dns|ddns|insufficient[- ]content|high[- ]risk|"
    r"low[- ]risk|questionable|unknown|stockpiled(?: domain)?|cname[- ]cloaking|ultra[- ]low[- ]ttl)\s*[:\-]",
    re.I,
)
# Categories that do mean an infected host or a malicious destination stay callouts / malicious web.
_C2_PREFIX = re.compile(r"^\s*(command[- ]and[- ]control|c2|malware|spyware|dns[- ]tunnel|dga|phishing|dangling)", re.I)


def classify(e: dict[str, Any]) -> str:
    """The event's kind after NodeWatch's own correction of reputation-category noise (see above)."""
    kind = e.get("kind") or "other"
    if kind in ("command_control", "web", "other"):
        name = str(e.get("name") or "")
        if _HYGIENE_PREFIX.match(name) and not _C2_PREFIX.match(name):
            return "policy"
        if kind == "command_control" and name.lower().startswith("phishing"):
            return "web"
    return kind


def stopped(e: dict[str, Any]) -> bool:
    return (e.get("outcome") or "") in ("blocked", "contained")


def got_through(e: dict[str, Any]) -> bool:
    """Reach 3 or further AND not stopped: a blocked or sinkholed callout did not get anywhere (v0.10.32)."""
    return int(e.get("reach") or 1) >= 3 and not stopped(e)


def reach_of(e: dict[str, Any]) -> int:
    kind, outcome, direction = classify(e), e.get("outcome") or "unknown", e.get("direction") or "unknown"
    if direction == "internal" and kind in ("exploit", "malware", "command_control", "reconnaissance", "credential"):
        return 5
    if kind == "command_control":
        return 4  # even blocked: a host that tries to reach an attacker is very likely infected
    if kind == "data_loss" and direction == "outbound":
        return 4 if outcome in ("alerted", "allowed") else 2  # data left / was stopped leaving
    if kind in ("reconnaissance", "flood") or kind == "policy":
        return 1
    if kind == "wireless":
        return 2
    if kind in _ATTACK:
        return 3 if outcome in ("alerted", "allowed") else 2
    return 1


def _sev_max(values: Iterable[str]) -> str:
    vals = [v for v in values if v in SEV_ORDER]
    return min(vals, key=lambda v: SEV_ORDER[v]) if vals else "info"


def enrich(events: list[dict[str, Any]], ctx: Context) -> list[dict[str, Any]]:
    """Add ``reach``, the inside party (``target``), the outside party (``actor``) and the resolved site."""
    out = []
    for raw in events:
        e = dict(raw)
        e["kind"] = classify(e)
        e["reach"] = reach_of(e)
        d = e.get("direction") or "unknown"
        src, dst = e.get("src_ip") or "", e.get("dst_ip") or ""
        if d == "outbound":
            inside, outside, oc = src, dst, e.get("dst_country") or ""
        elif d == "inbound":
            inside, outside, oc = dst, src, e.get("src_country") or ""
        elif d == "internal":
            inside, outside, oc = dst, src, ""
        else:
            inside, outside = (dst, src) if private_ip(dst) else (src, dst)
            oc = e.get("src_country") if outside == src else e.get("dst_country")
        target = ctx.asset(inside) if inside else None
        if target is None and inside:
            target = {"node_id": "", "name": inside, "role": "", "site_key": "", "site_name": "", "ip": inside, "managed": False}
        e["target"] = target
        e["actor"] = {
            "ip": outside,
            "country": oc or "",
            "user": e.get("src_user") or "",
            "inside": private_ip(outside) if outside else False,
        }
        sensor = ctx.sensor(e.get("source") or "", e.get("sensor_key") or "")
        if sensor and sensor.get("name") and not e.get("sensor_name"):
            e["sensor_name"] = sensor["name"]
        e["sensor_node"] = (sensor or {}).get("node_id") or ""
        site_key = (sensor or {}).get("site_key") or (target or {}).get("site_key") or ""
        site_name = (sensor or {}).get("site_name") or (target or {}).get("site_name") or ""
        if not site_key and e.get("site_key"):
            site_key, site_name = e["site_key"], (e.get("vendor") or {}).get("site_name") or ""
        e["site"] = {"key": site_key, "name": site_name or ctx.sites.get(site_key, "")}
        out.append(e)
    return out


def _weight(e: dict[str, Any]) -> float:
    return SEV_W.get(e.get("severity") or "info", 1.0) * REACH_W.get(int(e.get("reach") or 1), 1.0) * math.sqrt(
        max(1, int(e.get("count") or 1))
    )


def _n(e: dict[str, Any]) -> int:
    return max(1, int(e.get("count") or 1))


# --------------------------------------------------------------------------- overview


def overview(events: list[dict[str, Any]], *, since: float, until: float, buckets: int = 24) -> dict[str, Any]:
    total = sum(_n(e) for e in events)
    by_outcome: Counter = Counter()
    by_reach: Counter = Counter()
    by_kind: Counter = Counter()
    by_sev: Counter = Counter()
    for e in events:
        by_outcome[e.get("outcome") or "unknown"] += _n(e)
        by_reach[int(e.get("reach") or 1)] += _n(e)
        by_kind[e.get("kind") or "other"] += _n(e)
        by_sev[e.get("severity") or "info"] += _n(e)
    stopped = by_outcome["blocked"] + by_outcome["contained"]
    through = sum(_n(e) for e in events if got_through(e))
    attackers = {e["actor"]["ip"] for e in events if e.get("actor", {}).get("ip") and not e["actor"].get("inside")}
    countries = {e["actor"]["country"] for e in events if e.get("actor", {}).get("country") and _from_outside(e)}
    # Is an empty Origins map a data gap? Count outside attackers whose detections carry a country.
    outside = [e for e in events if (e.get("actor") or {}).get("ip") and not e["actor"].get("inside")]
    with_country = [e for e in outside if e["actor"].get("country")]
    targets = {(e.get("target") or {}).get("ip") for e in events if (e.get("target") or {}).get("ip")}
    calling = {(e.get("target") or {}).get("ip") for e in events if int(e.get("reach") or 0) == 4 and e.get("kind") == "command_control"}
    # timeline
    span = max(60.0, until - since)
    step = span / buckets
    tl = [{"t": since + i * step, "reach": {r: 0 for r in REACH}, "total": 0} for i in range(buckets)]
    for e in events:
        i = int((float(e.get("timestamp") or 0) - since) / step)
        if 0 <= i < buckets:
            tl[i]["reach"][int(e.get("reach") or 1)] += _n(e)
            tl[i]["total"] += _n(e)
    return {
        "kpis": {
            "detections": total,
            "stopped": stopped,
            "stopped_pct": round(100 * stopped / total, 1) if total else None,
            "through": through,
            "calling_out_hosts": len(calling - {None, ""}),
            "attackers": len(attackers),
            "countries": len(countries),
            "targets": len(targets - {None, ""}),
            "critical": by_sev["critical"],
        },
        "country_coverage": {
            "outside_events": sum(_n(e) for e in outside),
            "with_country": sum(_n(e) for e in with_country),
            "outside_attackers": len(attackers),
        },
        "reach": [
            {"level": r, "label": REACH[r][0], "help": REACH[r][1], "count": by_reach[r]} for r in sorted(REACH)
        ],
        "kinds": [
            {"kind": k, "label": SECURITY_EVENT_KIND_LABELS.get(k, k), "count": c} for k, c in by_kind.most_common()
        ],
        "outcomes": dict(by_outcome),
        "severity": dict(by_sev),
        "timeline": {"step_s": step, "buckets": tl},
    }


def _from_outside(e: dict[str, Any]) -> bool:
    """An attack from outside: inbound, or a direction the source could not tell with an outside actor."""
    if e.get("direction") == "inbound":
        return True
    a = e.get("actor") or {}
    return e.get("direction") in ("unknown", "", None) and bool(a.get("ip")) and not a.get("inside")


def _to_outside(e: dict[str, Any]) -> bool:
    """v0.10.35: a detection on traffic an inside host sent to an outside address (any kind)."""
    a = e.get("actor") or {}
    return e.get("direction") == "outbound" and bool(a.get("ip")) and not a.get("inside")


def countries(
    events: list[dict[str, Any]], *, outbound: bool = False, destinations: bool = False, limit: int = 40
) -> list[dict[str, Any]]:
    """Inbound: where attacks come from. Outbound (``outbound=True``): where inside hosts call out to
    (command-and-control). ``destinations=True``: every outside country inside hosts' flagged traffic went
    to (the Origins fallback when nothing came in)."""
    rows: dict[str, dict[str, Any]] = {}
    for e in events:
        if destinations:
            if not _to_outside(e):
                continue
        elif outbound:
            if int(e.get("reach") or 0) != 4:
                continue
        elif not _from_outside(e):
            continue
        code = (e.get("actor") or {}).get("country") or ""
        if not code:
            continue
        r = rows.get(code)
        if r is None:
            p = country_point(code) or {"code": code, "name": country_name(code), "lat": None, "lon": None, "region": ""}
            r = rows[code] = {
                **p,
                "events": 0,
                "stopped": 0,
                "through": 0,
                "weight": 0.0,
                "reach": 0,
                "kinds": Counter(),
                "targets": Counter(),
                "sites": Counter(),
                "sensors": Counter(),
                "attackers": set(),
                "last_seen": 0.0,
                "worst": "info",
            }
        n = _n(e)
        r["events"] += n
        r["weight"] += _weight(e)
        r["reach"] = max(r["reach"], int(e.get("reach") or 1))
        if e.get("outcome") in ("blocked", "contained"):
            r["stopped"] += n
        if got_through(e):
            r["through"] += n
        r["kinds"][e.get("kind") or "other"] += n
        t = e.get("target") or {}
        if t.get("name"):
            r["targets"][t["name"]] += n
        if (e.get("site") or {}).get("name"):
            r["sites"][e["site"]["name"]] += n
        if e.get("sensor_name"):
            r["sensors"][e["sensor_name"]] += n
        if (e.get("actor") or {}).get("ip"):
            r["attackers"].add(e["actor"]["ip"])
        r["last_seen"] = max(r["last_seen"], float(e.get("timestamp") or 0))
        r["worst"] = _sev_max([r["worst"], e.get("severity") or "info"])
    out = []
    for r in sorted(rows.values(), key=lambda x: -x["weight"]):
        out.append(
            {
                **{k: r[k] for k in ("code", "name", "lat", "lon", "region", "events", "stopped", "through", "reach", "last_seen", "worst")},
                "weight": round(r["weight"], 1),
                "attackers": len(r["attackers"]),
                "kinds": [{"kind": k, "label": SECURITY_EVENT_KIND_LABELS.get(k, k), "count": c} for k, c in r["kinds"].most_common(4)],
                "targets": [{"name": k, "count": c} for k, c in r["targets"].most_common(5)],
                "sites": [{"name": k, "count": c} for k, c in r["sites"].most_common(5)],
                "sensors": [{"name": k, "count": c} for k, c in r["sensors"].most_common(4)],
            }
        )
    return out[:limit]


def top(events: list[dict[str, Any]], field: str, *, limit: int = 10) -> list[dict[str, Any]]:
    """Ranked subjects: ``signature`` | ``target`` | ``attacker`` | ``sensor`` | ``site``."""
    rows: dict[str, dict[str, Any]] = {}
    for e in events:
        if field == "signature":
            key, label, extra = e.get("signature_id") or e.get("name") or "", e.get("name") or "", {"kind": e.get("kind"), "cves": e.get("cves") or []}
        elif field == "target":
            t = e.get("target") or {}
            key, label, extra = t.get("ip") or "", t.get("name") or t.get("ip") or "", {"site": t.get("site_name") or "", "node_id": t.get("node_id") or "", "role": t.get("role") or "", "managed": bool(t.get("managed"))}
        elif field == "attacker":
            a = e.get("actor") or {}
            if a.get("inside"):
                continue
            key, label, extra = a.get("ip") or "", a.get("ip") or "", {"country": a.get("country") or "", "country_name": country_name(a.get("country") or "") if a.get("country") else ""}
        elif field == "sensor":
            key, label, extra = f"{e.get('source')}:{e.get('sensor_key') or e.get('sensor_name')}", e.get("sensor_name") or "", {"node_id": e.get("sensor_node") or "", "source": e.get("source")}
        else:  # site
            s = e.get("site") or {}
            key, label, extra = s.get("key") or "", s.get("name") or "", {}
        if not key or not label:
            continue
        r = rows.get(key)
        if r is None:
            r = rows[key] = {"key": key, "label": label, **extra, "events": 0, "weight": 0.0, "reach": 0, "through": 0, "worst": "info", "last_seen": 0.0, "kinds": Counter()}
        n = _n(e)
        r["events"] += n
        r["weight"] += _weight(e)
        r["reach"] = max(r["reach"], int(e.get("reach") or 1))
        r["through"] += n if got_through(e) else 0
        r["stopped"] = r.get("stopped", 0) + (n if stopped(e) else 0)
        r["worst"] = _sev_max([r["worst"], e.get("severity") or "info"])
        r["last_seen"] = max(r["last_seen"], float(e.get("timestamp") or 0))
        r["kinds"][e.get("kind") or "other"] += n
    ranked = sorted(rows.values(), key=lambda x: (-x["weight"], -x["events"]))[:limit]
    top_w = ranked[0]["weight"] if ranked else 0.0
    for r in ranked:
        r["pressure"] = round(100 * r["weight"] / top_w) if top_w else 0
        r["weight"] = round(r["weight"], 1)
        r["kinds"] = [{"kind": k, "label": SECURITY_EVENT_KIND_LABELS.get(k, k), "count": c} for k, c in r["kinds"].most_common(3)]
    return ranked


def cve_pressure(events: list[dict[str, Any]], limit: int = 30) -> list[dict[str, Any]]:
    rows: dict[str, dict[str, Any]] = {}
    for e in events:
        for cve in e.get("cves") or []:
            r = rows.setdefault(cve, {"cve": cve, "events": 0, "through": 0, "targets": Counter(), "signatures": Counter(), "worst": "info", "first_seen": None, "last_seen": 0.0, "attackers": set()})
            n = _n(e)
            r["events"] += n
            if got_through(e):
                r["through"] += n
            t = e.get("target") or {}
            if t.get("name"):
                r["targets"][t["name"] + (f" · {t['site_name']}" if t.get("site_name") else "")] += n
            r["signatures"][e.get("name") or ""] += n
            r["worst"] = _sev_max([r["worst"], e.get("severity") or "info"])
            ts = float(e.get("timestamp") or 0)
            r["first_seen"] = ts if r["first_seen"] is None else min(r["first_seen"], ts)
            r["last_seen"] = max(r["last_seen"], ts)
            if (e.get("actor") or {}).get("ip"):
                r["attackers"].add(e["actor"]["ip"])
    out = []
    for r in sorted(rows.values(), key=lambda x: (-x["through"], SEV_ORDER.get(x["worst"], 9), -x["events"])):
        out.append({**{k: r[k] for k in ("cve", "events", "through", "worst", "first_seen", "last_seen")}, "attackers": len(r["attackers"]), "targets": [{"name": k, "count": c} for k, c in r["targets"].most_common(6)], "signatures": [k for k, _ in r["signatures"].most_common(3) if k]})
    return out[:limit]


# --------------------------------------------------------------------------- cases


REACH_POINTS = {1: 10, 2: 20, 3: 55, 4: 70, 5: 75}
SEV_POINTS = {"critical": 15, "major": 8, "warning": 0, "info": -5}


def score_parts(worst: str, reach: int, count: int, *, unstopped: bool) -> dict[str, Any]:
    """A case's score (0–100) and the parts it is made of, so the page can say why it ranks where it does:
    how far it got (Reach), how severe the worst detection is, how much of it there is, and whether the
    furthest step was let through."""
    reach_pts = REACH_POINTS.get(reach, 10)
    sev_pts = SEV_POINTS.get(worst, 0)
    vol_pts = round(min(10.0, 4 * math.log10(max(1, count))), 1)
    open_pts = 10 if unstopped and reach >= 3 else 0
    total = max(1, min(100, round(reach_pts + sev_pts + vol_pts + open_pts)))
    return {
        "score": total,
        "reach_points": reach_pts,
        "severity_points": sev_pts,
        "volume_points": vol_pts,
        "unstopped_points": open_pts,
        "severity": worst,
        "reach": reach,
        "volume": count,
    }


def _case_id(rule: str, subject: str) -> str:
    return "NW-" + stable_key("soc-case", rule, subject)[:7].upper()


def _subject(t: dict[str, Any] | None) -> str:
    t = t or {}
    return t.get("name") or t.get("ip") or "an inside host"


def _recommend(rule: str, c: dict[str, Any]) -> list[str]:
    tgt = c["subject_label"]
    dests = ", ".join(a["ip"] for a in c["attackers"][:3]) or "the destinations"
    cves = ", ".join(c["cves"][:3])
    rules = [r for r in c.get("rules", []) if r][:2]
    steps: list[str] = []
    if rule == "compromise":
        steps += [
            f"Isolate {tgt} (unplug, disable its port or move it to a quarantine network) before it does more.",
            f"Find who uses {tgt}: open it in Device Finder for the switch port, user and recent sessions.",
            f"Block {dests} on every internet exit, then check whether other hosts call the same destinations.",
            "Reimage or run a full endpoint scan; a blocked callback still means the host is infected.",
        ]
    elif rule == "lateral":
        steps += [
            f"Isolate {tgt}: it is attacking other hosts inside your network.",
            "List every host it touched (Detections, filtered by this source) and check each one.",
            "Segment the networks involved so this traffic must cross a firewall that blocks it.",
        ]
    elif rule == "breach":
        steps += [f"Check {tgt} for signs of compromise: the attempt was not blocked."]
        if cves:
            steps.append(f"Patch or mitigate {cves} on {tgt}.")
        if rules:
            steps.append(f"Make the security profile on rule {' / '.join(rules)} block this threat instead of only alerting.")
        steps.append(f"Watch for callbacks from {tgt} (Reach 4) over the next hours.")
    elif rule == "campaign":
        steps += [
            f"Block {dests} at the perimeter (or add it to your block list).",
            f"Confirm the {len(c['targets'])} targeted systems are patched{(' against ' + cves) if cves else ''}.",
            "Keep an eye on the same source country and signature for a change of tactic.",
        ]
    elif rule == "wireless":
        steps += [
            "Use the reporting access points to locate the device, then remove it or contain it.",
            "Check whether the rogue network shares your network names (an evil twin) and warn users if so.",
        ]
    return steps


def build_cases(events: list[dict[str, Any]], state: dict[str, dict[str, Any]], vendor_incidents: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    groups: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    by_attacker: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for e in events:
        r = int(e.get("reach") or 1)
        t = e.get("target") or {}
        a = e.get("actor") or {}
        if r == 4 and t.get("ip"):
            groups[("compromise", t["ip"])].append(e)
        elif r == 5 and a.get("ip"):
            groups[("lateral", a["ip"])].append(e)
        elif r == 3 and e.get("direction") == "inbound" and t.get("ip"):
            groups[("breach", t["ip"])].append(e)
        if e.get("kind") == "wireless":
            groups[("wireless", (e.get("site") or {}).get("key") or e.get("sensor_name") or "")].append(e)
        if a.get("ip") and not a.get("inside") and e.get("direction") == "inbound":
            by_attacker[a["ip"]].append(e)
    for ip, evs in by_attacker.items():
        targets = {(e.get("target") or {}).get("ip") for e in evs} - {None, ""}
        high = sum(_n(e) for e in evs if e.get("severity") in ("critical", "major"))
        if (len(targets) >= CAMPAIGN_TARGETS and high >= 3) or high >= CAMPAIGN_HIGH:
            groups[("campaign", ip)] = evs
    cases = []
    for (rule, subject), evs in groups.items():
        if not subject:
            continue
        evs = sorted(evs, key=lambda e: -float(e.get("timestamp") or 0))
        first = min(float(e.get("timestamp") or 0) for e in evs)
        last = max(float(e.get("timestamp") or 0) for e in evs)
        count = sum(_n(e) for e in evs)
        worst = _sev_max(e.get("severity") or "info" for e in evs)
        reach = max(int(e.get("reach") or 1) for e in evs)
        attackers: dict[str, dict[str, Any]] = {}
        targets: dict[str, dict[str, Any]] = {}
        for e in evs:
            a = e.get("actor") or {}
            if a.get("ip") and a["ip"] not in attackers:
                attackers[a["ip"]] = {"ip": a["ip"], "country": a.get("country") or "", "country_name": country_name(a["country"]) if a.get("country") else "", "inside": bool(a.get("inside"))}
            t = e.get("target") or {}
            if t.get("ip") and t["ip"] not in targets:
                targets[t["ip"]] = {k: t.get(k) for k in ("ip", "name", "site_name", "node_id", "role", "managed")}
        subj_ev = evs[0]
        if rule in ("compromise", "breach"):
            label = _subject(subj_ev.get("target"))
            site = (subj_ev.get("target") or {}).get("site_name") or (subj_ev.get("site") or {}).get("name") or ""
        elif rule == "wireless":
            label = (subj_ev.get("site") or {}).get("name") or subj_ev.get("sensor_name") or "a site"
            site = label
        else:
            label = subject
            site = (subj_ev.get("site") or {}).get("name") or ""
        kinds = Counter(e.get("kind") or "other" for e in evs)
        cc = Counter((e.get("actor") or {}).get("country") for e in evs if (e.get("actor") or {}).get("country"))
        sigs = Counter(e.get("name") or "" for e in evs if e.get("name"))
        cves = list(dict.fromkeys(c for e in evs for c in e.get("cves") or []))
        sensors = Counter(e.get("sensor_name") or "" for e in evs if e.get("sensor_name"))
        sources = sorted({e.get("source") or "" for e in evs})
        users = [u for u, _ in Counter(e.get("src_user") or "" for e in evs if e.get("src_user")).most_common(3)]
        outcomes = Counter(e.get("outcome") or "unknown" for e in evs)
        stopped_all = all(e.get("outcome") in ("blocked", "contained") for e in evs if int(e.get("reach") or 1) == reach)
        parts = score_parts(worst, reach, count, unstopped=not stopped_all)
        score = parts["score"]
        sig_top = sigs.most_common(1)[0][0] if sigs else ""
        titles = {
            "compromise": f"{label} is calling out to an attacker",
            "lateral": f"{label} is attacking hosts inside the network",
            "breach": f"Attack got through to {label}",
            "campaign": f"{label} is targeting {len(targets)} of your systems",
            "wireless": f"Wireless intrusion at {label}",
        }
        stopped = outcomes["blocked"] + outcomes["contained"]
        where = ""
        if rule == "compromise" and set(kinds) <= {"data_loss"}:
            titles["compromise"] = f"Data left the network from {label}"
            hosts = Counter(e.get("dst_host") or "" for e in evs if e.get("dst_host"))
            where = f" to {hosts.most_common(1)[0][0]}" if hosts else ""
        summary_bits = {
            "compromise": (f"{count} transfer{'s' if count != 1 else ''} not stopped{where}" if set(kinds) <= {"data_loss"} else None) or f"{count} callout{'s' if count != 1 else ''} to {len(attackers)} destination{'s' if len(attackers) != 1 else ''}" + (f" in {', '.join(country_name(c) for c, _ in cc.most_common(2))}" if cc else "") + (f"; {stopped} blocked" if stopped else "; none blocked"),
            "lateral": f"{count} attack{'s' if count != 1 else ''} on {len(targets)} inside host{'s' if len(targets) != 1 else ''}",
            "breach": f"{count} attempt{'s' if count != 1 else ''} not blocked" + (f" ({sig_top})" if sig_top else ""),
            "campaign": f"{count} attempt{'s' if count != 1 else ''} from {country_name(cc.most_common(1)[0][0]) if cc else 'an unknown country'}; {stopped} blocked",
            "wireless": f"{count} wireless-security detection{'s' if count != 1 else ''}" + (f" ({sig_top})" if sig_top else ""),
        }
        cid = _case_id(rule, subject)
        st = state.get(cid) or {}
        status = st.get("state") or "new"
        reopened = False
        if status in ("resolved", "dismissed") and last > float(st.get("state_at") or 0) + 60:
            status, reopened = "new", True
        case = {
            "id": cid,
            "rule": rule,
            "title": titles[rule],
            "summary": summary_bits[rule],
            "subject": subject,
            "subject_label": label,
            "site": site,
            "severity": worst,
            "reach": reach,
            "reach_label": REACH[reach][0],
            "score": score,
            "score_parts": parts,
            "first_seen": first,
            "last_seen": last,
            "events": count,
            "records": len(evs),
            "stopped": stopped,
            "kinds": [{"kind": k, "label": SECURITY_EVENT_KIND_LABELS.get(k, k), "count": c} for k, c in kinds.most_common()],
            "countries": [{"code": c, "name": country_name(c), "count": n} for c, n in cc.most_common(5)],
            "attackers": list(attackers.values())[:12],
            "targets": list(targets.values())[:12],
            "signatures": [s for s, _ in sigs.most_common(6)],
            "cves": cves[:10],
            "sensors": [s for s, _ in sensors.most_common(4)],
            "sources": sources,
            "users": users,
            "rules": [r for r, _ in Counter(e.get("rule") or "" for e in evs if e.get("rule")).most_common(3)],
            "state": status,
            "reopened": reopened,
            "owner": st.get("owner") or "",
            "notes": list(st.get("notes") or [])[-20:],
            "history": list(st.get("history") or [])[-20:],
            "event_keys": [e["key"] for e in evs[:MAX_CASE_EVENTS]],
        }
        case["recommended"] = _recommend(rule, case)
        cases.append(case)
    for v in vendor_incidents or []:
        cid = "V-" + stable_key("vendor-incident", v.get("source"), v.get("key"))[:7].upper()
        st = state.get(cid) or {}
        cases.append(
            {
                "id": cid,
                "rule": "vendor",
                "title": v.get("title") or "Incident",
                "summary": v.get("detail") or v.get("category") or "",
                "subject": v.get("key") or "",
                "subject_label": ", ".join(v.get("assets") or [])[:120],
                "site": "",
                "severity": v.get("severity") or "warning",
                "reach": 0,
                "reach_label": "",
                "score": {"critical": 80, "major": 60, "warning": 40}.get(v.get("severity") or "warning", 25),
                "score_parts": {},
                "first_seen": v.get("opened"),
                "last_seen": v.get("updated") or v.get("opened"),
                "events": 0,
                "records": 0,
                "stopped": 0,
                "kinds": [],
                "countries": [],
                "attackers": [],
                "targets": [{"ip": "", "name": a} for a in (v.get("assets") or [])[:12]],
                "signatures": [],
                "cves": [],
                "sensors": [],
                "sources": [v.get("source") or ""],
                "users": [],
                "rules": [],
                "state": st.get("state") or v.get("state") or "new",
                "reopened": False,
                "owner": st.get("owner") or "",
                "notes": list(st.get("notes") or [])[-20:],
                "history": list(st.get("history") or [])[-20:],
                "event_keys": [],
                "console_url": safe_console_url(v.get("console_url")),
                "recommended": [],
            }
        )
    open_first = {"new": 0, "investigating": 1, "contained": 2, "resolved": 3, "dismissed": 4}
    cases.sort(key=lambda c: (open_first.get(c["state"], 5), -c["score"], -float(c["last_seen"] or 0)))
    return cases


def case_brief(c: dict[str, Any]) -> dict[str, Any]:
    keep = ("id", "rule", "title", "summary", "subject_label", "site", "severity", "reach", "reach_label", "score", "first_seen", "last_seen", "events", "state", "owner", "reopened", "sources", "countries")
    return {k: c.get(k) for k in keep}
