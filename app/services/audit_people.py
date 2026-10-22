"""Vendor-neutral audit activity: who changed what, from every connected source (v0.10.24).

Reads the ``audit.log`` and ``directory.admins`` capabilities of every connected connector
(``sdk.gather(AUDIT_LOG, "list_audit")`` / ``sdk.gather(DIRECTORY_ADMINS, "list_actors")``, records
``domain.AuditEntry`` and ``domain.Actor``), joins each entry to its actor - by actor key, then email,
then name, always within the same source - and adds per-actor activity counts. Nothing here knows a
vendor's field names; today Juniper Mist implements both capabilities
(``app/integrations/connectors/mist/audit.py``); any other connector that implements them shows up
automatically.

Output (plain dicts for the Activity Log, Device Finder and assistants):

* ``entries``: AuditEntry fields plus ``actor_ref``, ``source_label`` (the product name people know,
  from the connector manifest) and readable extras: ``time``, ``verb`` / ``verb_kind``, ``what``,
  ``summary``, ``device_names``;
* ``actors``: {actor_ref: Actor fields plus ``kind_label``, ``role_text``, ``source_label``,
  ``changes_24h``, ``changes_7d``};
* ``errors`` (one line per failing source) and ``sources`` [{id, label}].

Every enrichment is optional: with no administrator list an entry still shows the name the source
recorded, classified by simple rules (token-like names → API token, vendor names → system).
"""

from __future__ import annotations

import inspect
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Any

KIND_LABELS = {
    "person": "Person (administrator account)",
    "api_token": "API token (a script or integration, not a person)",
    "system": "Automatic / vendor support",
    "unknown": "Account (details not available)",
}
_VERB_FOR_ACTION = {"create": "Create", "update": "Update", "delete": "Delete", "login": "Login", "other": "Activity"}
_KIND_FOR_ACTION = {"create": "added", "update": "changed", "delete": "removed", "login": "neutral", "other": "neutral"}


def source_labels() -> dict[str, str]:
    """connector id → "Vendor Product" for people (e.g. "Juniper Mist Cloud")."""
    try:
        from app.integrations.connectors import sdk

        return {
            c.manifest.connector_id: f"{c.manifest.vendor} {c.manifest.product}".strip() for c in sdk.all_connectors()
        }
    except Exception:  # noqa: BLE001
        return {}


def _hours(duration: str) -> int:
    m = re.fullmatch(r"\s*(\d+)\s*([hdw]?)\s*", str(duration or "7d").lower())
    if not m:
        return 168
    n = int(m.group(1))
    return max(1, n * {"": 1, "h": 1, "d": 24, "w": 168}[m.group(2)])


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).astimezone().isoformat() if ts else ""


def _past(verb: str) -> str:
    try:
        from app.modules.history.activity import past_tense

        return past_tense(verb)
    except Exception:  # noqa: BLE001
        return verb.lower()


def _fallback_kind(name: str) -> str:
    if re.search(r"(?i)\btoken\b|\bapi key\b", name):
        return "api_token"
    if (
        not name
        or name.lower() in {"system", "automatic"}
        or re.search(r"(?i)\bsupport\b|^(juniper|mist|meraki|aruba|cisco|fortinet|palo alto)\b", name)
    ):
        return "system"
    return "unknown"


def _actor_dict(actor: Any, label: str) -> dict[str, Any]:
    d = actor.to_dict() if hasattr(actor, "to_dict") else dict(actor)
    roles = [r for r in d.get("roles") or [] if isinstance(r, dict)]
    lines = [f"{r.get('role', '')} – {r.get('scope', '')}".strip(" –") for r in roles]
    d.update(
        source_label=label,
        kind_label=KIND_LABELS.get(d.get("kind") or "unknown", KIND_LABELS["unknown"]),
        role_text="; ".join(x for x in lines if x),
        role_lines=[x for x in lines if x],
        changes_24h=0,
        changes_7d=0,
    )
    return d


_MEMO_SECONDS = 60.0
_MEMO: dict[tuple, tuple[float, dict]] = {}
_MEMO_LOCK = threading.Lock()


def clear_cache() -> None:
    """Forget memoised results (the page's Refresh button)."""
    with _MEMO_LOCK:
        _MEMO.clear()


def collect(duration: str = "7d", *, site_key: str | None = None, device_key: str | None = None) -> dict[str, Any]:
    """Audit entries (newest first) and the people/tokens behind them, from every connected source.

    Memoised for 60 s per (range, site, device) - Device Finder opens and Activity Log refreshes reuse
    one build. ``device_key`` keeps only entries that touched that device; sources whose ``list_audit``
    accepts ``device_key`` filter before parsing (Mist), others are filtered afterwards."""
    key = (_hours(duration), site_key or "", device_key or "")
    now = time.monotonic()
    with _MEMO_LOCK:  # also single-flight: concurrent callers wait for one build
        hit = _MEMO.get(key)
        if hit and now - hit[0] < _MEMO_SECONDS:
            return hit[1]
        result = _collect(duration, site_key=site_key, device_key=device_key)
        _MEMO[key] = (time.monotonic(), result)
        for old in [k for k, (at, _) in _MEMO.items() if time.monotonic() - at >= _MEMO_SECONDS]:
            _MEMO.pop(old, None)
        return result


def _accepts_device_key(fn: Any) -> bool:
    try:
        params = inspect.signature(fn).parameters
    except (TypeError, ValueError):
        return False
    return "device_key" in params or any(p.kind is inspect.Parameter.VAR_KEYWORD for p in params.values())


def _gather_entries(site_key: str | None, hours: int, device_key: str | None) -> tuple[list[Any], list[dict]]:
    from app.integrations.base import IntegrationError
    from app.integrations.connectors import sdk
    from app.integrations.contracts import AUDIT_LOG

    if not device_key:
        return sdk.gather(AUDIT_LOG, "list_audit", site_key, hours=hours)
    records: list[Any] = []
    errors: list[dict] = []
    for c in sdk.sources(AUDIT_LOG):
        try:
            if _accepts_device_key(c.list_audit):
                rows = c.list_audit(site_key, hours=hours, device_key=device_key) or []
            else:
                rows = [r for r in c.list_audit(site_key, hours=hours) or [] if device_key in (r.device_keys or [])]
            records.extend(rows)
        except IntegrationError as exc:
            errors.append({"source": c.provider_id, "product": c.manifest.product, "error": str(exc)})
        except Exception as exc:  # noqa: BLE001 - one vendor never hides the others
            errors.append({"source": c.provider_id, "product": c.manifest.product, "error": type(exc).__name__})
    return records, errors


_DEVICE_OBJECTS = {"device", "switch", "access point", "ap", "gateway", "router", "firewall", "appliance"}


def _collect(duration: str, *, site_key: str | None, device_key: str | None) -> dict[str, Any]:
    from app.integrations.connectors import sdk
    from app.integrations.contracts import DIRECTORY_ADMINS

    labels = source_labels()
    hours = _hours(duration)
    with ThreadPoolExecutor(max_workers=2, thread_name_prefix="audit-gather") as pool:
        f_entries = pool.submit(_gather_entries, site_key, hours, device_key)
        f_actors = pool.submit(sdk.gather, DIRECTORY_ADMINS, "list_actors")
        entries, entry_errors = f_entries.result()
        actor_records, actor_errors = f_actors.result()  # optional: errors are not shown

    actors: dict[str, dict] = {}
    by_key: dict[tuple[str, str], str] = {}
    by_email: dict[tuple[str, str], str] = {}
    by_name: dict[tuple[str, str], str] = {}
    for a in actor_records:
        d = _actor_dict(a, labels.get(getattr(a, "source", ""), getattr(a, "source", "")))
        ref = f"{d['source']}:{d['key']}"
        actors[ref] = d
        by_key[(d["source"], d["key"])] = ref
        if d.get("email"):
            by_email[(d["source"], d["email"].lower())] = ref
        if d.get("name"):
            by_name.setdefault((d["source"], d["name"].lower()), ref)

    out: list[dict] = []
    now = time.time()
    for e in entries:
        d = e.to_dict() if hasattr(e, "to_dict") else dict(e)
        src = d.get("source") or ""
        label = labels.get(src, src)
        name = d.get("actor_name") or ""
        email = d.get("actor_email") or ""
        ref = (
            by_key.get((src, d.get("actor_key") or ""))
            or (by_email.get((src, email.lower())) if email else None)
            or (by_email.get((src, name.lower())) if "@" in name else None)
            or (by_name.get((src, name.lower())) if name else None)
        )
        if ref is None:  # not in the directory: a plain actor from what the entry recorded
            ref = f"{src}:{d.get('actor_key') or email.lower() or name.lower() or 'unknown'}"
            if ref not in actors:
                actors[ref] = {
                    "key": d.get("actor_key") or "",
                    "source": src,
                    "source_label": label,
                    "kind": _fallback_kind(name),
                    "kind_label": KIND_LABELS[_fallback_kind(name)],
                    "name": name or "System",
                    "email": email,
                    "roles": [],
                    "role_text": "",
                    "role_lines": [],
                    "changes_24h": 0,
                    "changes_7d": 0,
                }
        actor = actors[ref]
        ts = float(d.get("timestamp") or 0)
        actor["changes_in_range"] = actor.get("changes_in_range", 0) + 1
        if ts and now - ts <= 7 * 86_400:
            actor["changes_7d"] += 1
            if now - ts <= 86_400:
                actor["changes_24h"] += 1
        # Only neutral fields are read here (the vendor dict is dropped below, never interpreted).
        verb = _VERB_FOR_ACTION.get(d.get("action") or "other", "Activity")
        # The source's own verb when it has one ("Upgrade", "Reboot", "Enable" …), else the neutral one.
        label_verb = str(d.get("action_label") or "").strip().capitalize() or verb
        what = " ".join(
            x for x in (d.get("object_type") or "", f"“{d['object_name']}”" if d.get("object_name") else "") if x
        ).strip()
        obj = what or d.get("message") or ""
        if not what and d.get("message"):
            phrase = f"– {d['message']}"  # the source recorded only free text: show it as written
        elif d.get("action_label") and verb == "Activity":
            # The source's own verb (v0.10.24): "accessed Org" rather than "performed: Org".
            phrase = f"{_past(str(d['action_label']).strip().capitalize()).lower()} {obj}".strip()
        elif verb == "Activity":
            phrase = f"performed: {obj}" if obj else "performed an action"
        elif verb in {"Login", "Logout"}:
            phrase = f"{_past(verb)} {('with ' + obj) if obj else ''}".strip()
        else:
            phrase = f"{_past(verb)} {obj}".strip()
        summary = f"{actor['name']} {phrase}"
        if d.get("site_name"):
            summary += f" at {d['site_name']}"
        if d.get("src_ip"):
            summary += f" from {d['src_ip']}"
        if d.get("user_agent"):
            summary += f" using {d['user_agent']}"
        d.update(
            actor_ref=ref,
            source_label=label,
            time=_iso(ts),
            verb=label_verb,
            verb_kind=_verb_kind(label_verb, d.get("action") or "other"),
            device_names=[d["object_name"]]
            if d.get("object_name") and str(d.get("object_type") or "").strip().lower() in _DEVICE_OBJECTS
            else [],
            what=what or d.get("message") or "",
            summary=summary,
        )
        d.pop("vendor", None)  # vendor detail stays server-side
        out.append(d)
    out.sort(key=lambda x: float(x.get("timestamp") or 0), reverse=True)
    # Counts are honest about the range read: a 60-minute range cannot say "in the last 7 days".
    for actor in actors.values():
        actor.setdefault("changes_in_range", 0)
        actor["range_hours"] = hours
        if hours < 24:
            actor["changes_24h"] = None
        if hours < 168:
            actor["changes_7d"] = None
    errors = []
    for x in entry_errors:
        product, text = str(x.get("product") or x.get("source") or ""), str(x.get("error") or "")
        errors.append(text if not product or text.startswith(product) else f"{product}: {text}")
    return {
        "entries": out,
        "actors": actors,
        "errors": errors,
        "sources": [{"id": s, "label": labels.get(s, s)} for s in sorted({x.get("source") or "" for x in out} - {""})],
        "actor_errors": len(actor_errors),
    }


def _verb_kind(label: str, action: str) -> str:
    """Colour class for an action: added / removed / changed / neutral (Enable → added, Disable → removed)."""
    try:
        from app.modules.history.activity import action_kind

        kind = action_kind(label)
        if kind != "neutral" or label in {"Login", "Logout", "Access", "Activity"}:
            return kind
    except Exception:  # noqa: BLE001
        pass
    return _KIND_FOR_ACTION.get(action, "neutral")
