"""Human-readable helpers for activity/audit records and relay events.

Everything here turns provider payloads into labelled values for people to read:
parsed audit messages, before/after change lists, browser labels, humanised event
types and "Open in Mist" links. Nothing in this module returns JSON text for
display.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

from app.core.security import _SENSITIVE_KEY, redact_text
from app.core.volatile_fields import is_volatile_change, redact_signed_url

HIDDEN = "••• hidden •••"
MAX_VALUE_CHARS = 200
MAX_CHANGES = 400

# ---------------------------------------------------------------- audit messages

# Canonical verb → recognised spellings (first word of a Mist audit message).
_VERBS: dict[str, tuple[str, ...]] = {
    "Add": ("add", "added", "adding"),
    "Create": ("create", "created", "new"),
    "Update": ("update", "updated", "modify", "modified", "change", "changed", "set", "save", "saved"),
    "Edit": ("edit", "edited"),
    "Delete": ("delete", "deleted", "del"),
    "Remove": ("remove", "removed"),
    "Assign": ("assign", "assigned"),
    "Unassign": ("unassign", "unassigned"),
    "Claim": ("claim", "claimed"),
    "Unclaim": ("unclaim", "unclaimed"),
    "Release": ("release", "released"),
    "Login": ("login", "logged", "signin", "sign-in"),
    "Logout": ("logout", "signout", "sign-out"),
    "Invite": ("invite", "invited"),
    "Restart": ("restart", "restarted"),
    "Reboot": ("reboot", "rebooted"),
    "Upgrade": ("upgrade", "upgraded"),
    "Access": ("access", "accessed", "view", "viewed"),
    "Rename": ("rename", "renamed"),
    "Replace": ("replace", "replaced"),
    "Move": ("move", "moved"),
    "Clone": ("clone", "cloned", "copy", "copied"),
    "Enable": ("enable", "enabled"),
    "Disable": ("disable", "disabled"),
    "Acknowledge": ("acknowledge", "acknowledged", "ack"),
    "Revoke": ("revoke", "revoked"),
    "Bounce": ("bounce", "bounced"),
    "Reset": ("reset",),
    "Run": ("run", "ran", "execute", "executed"),
    "Import": ("import", "imported"),
    "Export": ("export", "exported"),
}
_VERB_LOOKUP = {spelling: canon for canon, words in _VERBS.items() for spelling in words}

_ACTION_KIND = {
    "removed": {"Delete", "Remove", "Unassign", "Unclaim", "Release", "Revoke", "Disable"},
    "added": {"Add", "Create", "Claim", "Invite", "Clone", "Import", "Enable"},
    "changed": {
        "Update",
        "Edit",
        "Assign",
        "Rename",
        "Replace",
        "Move",
        "Upgrade",
        "Restart",
        "Reboot",
        "Bounce",
        "Reset",
        "Run",
        "Acknowledge",
    },
}

_PAST = {
    "Add": "added",
    "Create": "created",
    "Update": "updated",
    "Edit": "edited",
    "Delete": "deleted",
    "Remove": "removed",
    "Assign": "assigned",
    "Unassign": "unassigned",
    "Claim": "claimed",
    "Unclaim": "unclaimed",
    "Release": "released",
    "Login": "logged in",
    "Logout": "logged out",
    "Invite": "invited",
    "Restart": "restarted",
    "Reboot": "rebooted",
    "Upgrade": "upgraded",
    "Access": "accessed",
    "Rename": "renamed",
    "Replace": "replaced",
    "Move": "moved",
    "Clone": "cloned",
    "Enable": "enabled",
    "Disable": "disabled",
    "Acknowledge": "acknowledged",
    "Revoke": "revoked",
    "Bounce": "bounced",
    "Reset": "reset",
    "Run": "ran",
    "Import": "imported",
    "Export": "exported",
}

_QUOTED = re.compile(r"\"([^\"]*)\"|“([^”]*)”|'([^']*)'")
_TRAILING_PREP = re.compile(r"\s+(to|from|for|on|in|of|at|with|by)$", re.IGNORECASE)
_LEADING_PREP = re.compile(r"^(to|from|for|on|in|of|at|with|by)\s+", re.IGNORECASE)


def action_kind(action: str) -> str:
    for kind, verbs in _ACTION_KIND.items():
        if action in verbs:
            return kind
    return "neutral"


def parse_audit_message(message: Any) -> dict:
    """Split a Mist audit message into action, object type and quoted object name.

    ``Update Site Settings "HQ"`` → ``{"action": "Update", "object_type": "Site Settings",
    "object_name": "HQ"}``.
    """
    text = " ".join(str(message or "").split())
    result = {"action": "", "object_type": "", "object_name": "", "kind": "neutral"}
    if not text:
        return result
    first, _, rest = text.partition(" ")
    word = first.strip(":,.").lower()
    canon = _VERB_LOOKUP.get(word)
    if canon == "Login" and rest.lower().startswith("out"):
        canon, rest = "Logout", rest[3:].lstrip()
    if canon is None:
        if word in {"log", "sign"} and rest.lower().startswith(("in", "out")):
            canon = "Login" if rest.lower().startswith("in") else "Logout"
            rest = rest[3:].lstrip() if rest.lower().startswith("out") else rest[2:].lstrip()
        else:
            canon = ""
            rest = text
    if canon == "Login" and rest.lower().startswith("in "):
        rest = rest[3:]
    match = _QUOTED.search(rest)
    if match:
        name = next(g for g in match.groups() if g is not None)
        obj = rest[: match.start()]
    else:
        name = ""
        obj = rest
    obj = _LEADING_PREP.sub("", _TRAILING_PREP.sub("", obj.strip(" :-,")).strip()).strip()
    if not canon:
        # Unknown verb: keep the message intact as the "what" so nothing is lost.
        obj = text if not match else obj
    result.update(
        {
            "action": canon or "Activity",
            "object_type": obj[:120],
            "object_name": redact_text(name)[:160],
            "kind": action_kind(canon),
        }
    )
    return result


def past_tense(action: str) -> str:
    return _PAST.get(action, (action or "changed").lower())


# ---------------------------------------------------------------- user agents


def user_agent_label(ua: Any) -> str:
    """Shorten a User-Agent to "Browser on OS" (or the client tool's name)."""
    text = str(ua or "").strip()
    if not text:
        return ""
    low = text.lower()
    tools = (
        ("python-requests", "Python script"),
        ("mistapi", "Mist API (Python)"),
        ("terraform", "Terraform"),
        ("postmanruntime", "Postman"),
        ("curl/", "curl"),
        ("go-http-client", "Go client"),
        ("powershell", "PowerShell"),
        ("ansible", "Ansible"),
        ("nodewatch", "NodeWatch"),
        ("okhttp", "Mist mobile app"),
        ("mist/", "Mist mobile app"),
    )
    for needle, label in tools:
        if needle in low:
            return label
    browser = ""
    for needle, label in (
        ("edg/", "Edge"),
        ("edga/", "Edge"),
        ("opr/", "Opera"),
        ("firefox/", "Firefox"),
        ("fxios/", "Firefox"),
        ("crios/", "Chrome"),
        ("chrome/", "Chrome"),
        ("safari/", "Safari"),
    ):
        if needle in low:
            browser = label
            break
    os_name = ""
    for needle, label in (
        ("windows", "Windows"),
        ("iphone", "iOS"),
        ("ipad", "iPadOS"),
        ("android", "Android"),
        ("cros", "ChromeOS"),
        ("mac os x", "macOS"),
        ("macintosh", "macOS"),
        ("linux", "Linux"),
    ):
        if needle in low:
            os_name = label
            break
    if browser and os_name:
        return f"{browser} on {os_name}"
    if browser or os_name:
        return browser or os_name
    return text.split("/")[0].split(" ")[0][:40]


# ---------------------------------------------------------------- labels/values

_ACRONYMS = {
    "id": "ID",
    "ip": "IP",
    "mac": "MAC",
    "ap": "AP",
    "ssid": "SSID",
    "vlan": "VLAN",
    "wlan": "WLAN",
    "poe": "PoE",
    "dhcp": "DHCP",
    "dns": "DNS",
    "vc": "VC",
    "rf": "RF",
    "radius": "RADIUS",
    "nac": "NAC",
    "wan": "WAN",
    "lan": "LAN",
    "lldp": "LLDP",
    "bgp": "BGP",
    "ospf": "OSPF",
    "stp": "STP",
    "url": "URL",
    "src": "Source",
    "dst": "Destination",
    "os": "OS",
    "cpu": "CPU",
    "sle": "SLE",
    "psk": "PSK",
    "vpn": "VPN",
    "evpn": "EVPN",
    "ntp": "NTP",
    "snmp": "SNMP",
    "uuid": "UUID",
    "gw": "Gateway",
    "sw": "Switch",
    "fw": "Firmware",
}

_TYPE_PREFIX = {
    "SW": "Switch",
    "AP": "Access point",
    "GW": "Gateway",
    "ESL": "ESL",
    "MXEDGE": "Mist Edge",
    "ME": "Mist Edge",
    "BLE": "BLE",
    "VC": "Virtual chassis",
}


def humanize_key(key: Any) -> str:
    text = str(key or "").strip()
    if not text:
        return ""
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_\- ]*", text):
        return text  # port names like ge-0/0/1, MACs, numbers: keep verbatim
    words = [w for w in re.split(r"[_\s]+", re.sub(r"(?<=[a-z])(?=[A-Z])", "_", text)) if w]
    out = []
    for i, w in enumerate(words):
        low = w.lower()
        if low in _ACRONYMS:
            out.append(_ACRONYMS[low])
        elif low.endswith("s") and low[:-1] in _ACRONYMS and _ACRONYMS[low[:-1]].isupper():
            out.append(_ACRONYMS[low[:-1]] + "s")
        else:
            out.append(low.capitalize() if i == 0 else low)
    return " ".join(out)


def humanize_type(code: Any) -> str:
    """SW_DISCONNECTED → "Switch disconnected"; device_down → "Device down"."""
    text = str(code or "").strip()
    if not text:
        return ""
    if " " in text and not re.fullmatch(r"[A-Z0-9_ ]+", text):
        return text[:1].upper() + text[1:]
    parts = [p for p in re.split(r"[_\s]+", text) if p]
    if not parts:
        return text
    head = _TYPE_PREFIX.get(parts[0].upper())
    words = [head] if head else []
    for i, p in enumerate(parts[1:] if head else parts):
        low = p.lower()
        word = _ACRONYMS.get(low, low)
        if not words and i == 0:
            word = word[:1].upper() + word[1:]
        words.append(word)
    return " ".join(words)


def format_mac(value: Any) -> str:
    raw = re.sub(r"[^0-9a-fA-F]", "", str(value or ""))
    if len(raw) != 12:
        return str(value or "")
    raw = raw.lower()
    return ":".join(raw[i : i + 2] for i in range(0, 12, 2))


def to_epoch(value: Any) -> float | None:
    """Seconds since epoch from seconds/ms numbers or ISO strings."""
    if value in (None, "") or isinstance(value, bool):
        return None
    try:
        num = float(value)
        if num > 1e12:
            num /= 1000.0
        return num if num > 0 else None
    except (TypeError, ValueError):
        pass
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    except (TypeError, ValueError):
        return None


def _is_time_key(key: str) -> bool:
    low = key.lower()
    return low in {"timestamp", "time", "last_seen", "first_seen", "when"} or low.endswith(
        ("_time", "_ts", "_at", "_timestamp")
    )


def _clip(text: str) -> str:
    return text if len(text) <= MAX_VALUE_CHARS else text[: MAX_VALUE_CHARS - 1] + "…"


def format_scalar(value: Any, key: str = "") -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "Yes" if value else "No"
    low = key.lower()
    if isinstance(value, str) and (
        ("mac" in low and len(re.sub(r"[^0-9a-fA-F]", "", value)) == 12)
        or (re.fullmatch(r"[0-9a-fA-F]{12}", value) and not value.isdigit())
    ):
        return format_mac(value)
    return _clip(redact_text(value))


def _scalar_list(value: list) -> bool:
    return all(not isinstance(x, (dict, list)) for x in value)


def _maybe_json(value: Any) -> Any:
    if isinstance(value, str):
        text = value.strip()
        if text[:1] in "{[":
            try:
                return json.loads(text)
            except ValueError:
                return value
    return value


def flatten(value: Any, prefix: str = "", out: dict | None = None) -> dict[str, Any]:
    """Flatten nested dicts/lists to ``a.b[0].c`` paths. Lists of scalars stay one value."""
    out = {} if out is None else out
    value = _maybe_json(value)
    if isinstance(value, dict):
        if not value and prefix:
            out[prefix] = {}
        for k, v in value.items():
            flatten(v, f"{prefix}.{k}" if prefix else str(k), out)
    elif isinstance(value, list) and not _scalar_list(value):
        for i, v in enumerate(value):
            flatten(v, f"{prefix}[{i}]", out)
    elif prefix:
        out[prefix] = value
    return out


def _path_parts(path: str) -> list[str]:
    return [p for p in re.split(r"\.|\[(\d+)\]", path) if p]


def _path_sensitive(path: str) -> bool:
    return any(_SENSITIVE_KEY.search(p) for p in _path_parts(path))


def path_label(path: str) -> str:
    pieces = []
    for part in re.split(r"\.", path):
        m = re.fullmatch(r"(.*?)((?:\[\d+\])+)$", part)
        if m:
            idx = " ".join(f"#{int(n) + 1}" for n in re.findall(r"\d+", m.group(2)))
            pieces.append(f"{humanize_key(m.group(1))} {idx}".strip())
        else:
            pieces.append(humanize_key(part))
    return " › ".join(p for p in pieces if p)


def display_value(value: Any, path: str = "") -> str:
    if _path_sensitive(path):
        return HIDDEN
    leaf = _path_parts(path)[-1] if path else ""
    if isinstance(value, list):
        return _clip(", ".join(format_scalar(v, leaf) for v in value)) if value else "(empty list)"
    if isinstance(value, dict):
        return "(empty)"
    if value is None:
        return "—"
    return format_scalar(value, leaf)


_DIFF_SKIP_LEAVES = {"modified_time", "created_time", "org_id", "id", "for_site", "_ttl"}


def _flatten_differences(before: Any, after: Any, prefix: str, ob: dict, oa: dict) -> None:
    before, after = _maybe_json(before), _maybe_json(after)
    if isinstance(before, dict) and isinstance(after, dict):
        for k in set(before) | set(after):
            path = f"{prefix}.{k}" if prefix else str(k)
            if k in before and k in after:
                if before[k] != after[k]:
                    _flatten_differences(before[k], after[k], path, ob, oa)
            elif k in before:
                flatten(before[k], path, ob)
            else:
                flatten(after[k], path, oa)
        return
    if before == after:
        return
    flatten(before, prefix, ob)
    flatten(after, prefix, oa)


def diff_changes(before: Any, after: Any) -> list[dict]:
    """Field-level change list between two payloads (dicts or JSON strings).

    Returns ``[{"path", "label", "op": added|removed|changed, "before", "after"}]``;
    secret fields only show that they changed, never their values.
    """
    b: dict[str, Any] = {}
    a: dict[str, Any] = {}
    # Only subtrees that differ are flattened (v0.10.24): an audit entry usually carries a whole device
    # configuration of which one or two values changed; flattening all of it for every row of a large
    # audit log cost seconds of CPU. Equal subtrees would produce equal paths, which are skipped anyway.
    _flatten_differences(before if before not in (None, "") else {}, after if after not in (None, "") else {}, "", b, a)
    rows: list[dict] = []
    for path in sorted(set(b) | set(a)):
        leaf = (_path_parts(path) or [""])[-1]
        if leaf in _DIFF_SKIP_LEAVES:
            continue
        in_b, in_a = path in b, path in a
        if in_b and in_a and b[path] == a[path]:
            continue
        bv, av = b.get(path), a.get(path)
        # Timestamps and signed links (image1_url …) change on every read: never a change (shared list).
        if is_volatile_change(leaf, bv, av):
            continue
        if in_b and in_a:
            op = "changed"
        elif in_a:
            op = "added"
            if av in (None, "", [], {}):
                continue
        else:
            op = "removed"
            if bv in (None, "", [], {}):
                continue
        rows.append(
            {
                "path": path,
                "label": path_label(path),
                "op": op,
                "before": redact_signed_url(display_value(bv, path)) if in_b else "",
                "after": redact_signed_url(display_value(av, path)) if in_a else "",
            }
        )
        if len(rows) >= MAX_CHANGES:
            break
    return rows


def field_rows(value: Any, *, skip: set[str] | None = None, limit: int = 120) -> list[dict]:
    """Labelled rows ``[{"label", "value", "kind"}]`` for every meaningful field.

    ``kind`` is "time" (value = epoch ms, formatted by the browser in local time) or
    "text". ids, org/internal keys and empty values are skipped.
    """
    skip = skip or set()
    rows: list[dict] = []
    for path, v in flatten(value).items():
        parts = _path_parts(path)
        leaf = parts[-1] if parts else path
        low = leaf.lower()
        if path in skip or leaf in skip:
            continue
        if low in {"id", "org_id", "_id", "for_site", "_ttl", "msp_id"} or low.endswith("_id") or low.startswith("_"):
            continue
        if v in (None, "", [], {}):
            continue
        if _path_sensitive(path):
            rows.append({"label": path_label(path), "value": HIDDEN, "kind": "text"})
            continue
        if _is_time_key(low) and not isinstance(v, (list, dict)):
            ts = to_epoch(v)
            if ts and ts > 1e8:
                rows.append({"label": path_label(path), "value": int(ts * 1000), "kind": "time"})
                continue
        rows.append({"label": path_label(path), "value": display_value(v, path), "kind": "text"})
        if len(rows) >= limit:
            break
    return rows


# ---------------------------------------------------------------- Mist links


def manage_host(api_host: str) -> str:
    """api.mist.com → manage.mist.com; api.eu.mist.com → manage.eu.mist.com."""
    text = str(api_host or "").strip()
    host = (urlparse(text if "://" in text else "https://" + text).hostname or "").lower()
    if not host:
        return ""
    if host.startswith("api."):
        return "manage." + host[4:]
    if host.startswith("api-"):
        return "manage-" + host[4:]
    return host


_DEVICE_ROUTE = {"ap": "ap", "switch": "switch", "gateway": "gateway"}


def device_type_from(code: Any, explicit: Any = "") -> str:
    t = str(explicit or "").lower()
    if t in _DEVICE_ROUTE:
        return t
    head = str(code or "").upper().split("_", 1)[0]
    return {"SW": "switch", "AP": "ap", "GW": "gateway"}.get(head, "")


def mist_device_url(
    api_host: str, org_id: str, *, site_id: str = "", device_type: str = "", device_id: str = "", mac: str = ""
) -> str:
    """Deep link into the Mist portal for a device (or the site insights page)."""
    host = manage_host(api_host)
    if not host or not org_id:
        return ""
    base = f"https://{host}/admin/?org_id={org_id}"
    route = _DEVICE_ROUTE.get(str(device_type or "").lower())
    bare = re.sub(r"[^0-9a-f]", "", str(mac or "").lower())
    dev = str(device_id or "") or (f"00000000-0000-0000-1000-{bare}" if len(bare) == 12 else "")
    if route and dev and site_id:
        return f"{base}#!{route}/detail/{dev}/{site_id}"
    if site_id:
        return f"{base}#!dashboard/insights/{site_id}"
    return ""


def action_phrase(parsed: dict) -> str:
    """ "updated WLAN “Guest”" / "logged in with Role “Super User”" for a parsed audit message."""
    action = parsed.get("action") or ""
    obj = parsed.get("object_type") or ""
    if parsed.get("object_name"):
        obj = f"{obj} “{parsed['object_name']}”".strip()
    if action == "Activity":
        return f"performed: {obj}" if obj else "performed an action"
    if action in {"Login", "Logout"} and obj:
        obj = f"with {obj}"
    return f"{past_tense(action)} {obj}".strip()
