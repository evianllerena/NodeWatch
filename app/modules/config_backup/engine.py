"""Pure helpers for Config Backups: secret redaction, the config diff engine and
template-override detection.

Nothing here talks to Mist or touches disk, so every function is easy to test.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from typing import Any

from app.core.volatile_fields import STATE_KEYS as _STATE_KEYS
from app.core.volatile_fields import VOLATILE_KEYS as _VOLATILE_KEYS
from app.core.volatile_fields import is_volatile_change, is_volatile_key, redact_signed_urls, same_signed_link

try:  # Reuse the Activity Log's key humaniser so labels read the same everywhere.
    from app.modules.history.activity import humanize_key as _humanize_key
except Exception:  # pragma: no cover - defensive: never let a sibling module break backups

    def _humanize_key(key: Any) -> str:
        text = str(key or "")
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_\- ]*", text):
            return text
        return text.replace("_", " ").capitalize()


# --------------------------------------------------------------------------- redaction

REDACTED_PREFIX = "***REDACTED"

# Key names whose scalar value is a secret. Matched against each dict key.
_SECRET_KEY = re.compile(
    r"(^|[_-])("
    r"token|secret|secrets|password|passwd|passphrase|psk|pre[_-]?shared[_-]?key|private[_-]?key|"
    r"api[_-]?key|apikey|auth[_-]?key|enc[_-]?key|community|credential|credentials|authorization|"
    r"key|md5|hash|wep[_-]?key|shared[_-]?key"
    r")([_-]|$)",
    re.IGNORECASE,
)
# Containers whose every scalar leaf is secret material (e.g. OSPF ``auth_keys``, WEP ``keys``).
_SECRET_CONTAINER = re.compile(r"(^|[_-])(keys|auth_keys|secrets|passwords|psks|communities)$", re.IGNORECASE)
# Keys that look secret by name but only hold configuration (booleans, ids, modes).
_NOT_SECRET = {
    "key_type",
    "keys_enabled",
    "psk_type",
    "dynamic_psk",
    "token_type",
    "community_type",
    "hash_algorithm",
    "md5_enabled",
    "key_id",
    "primary_key",
}
# Value shapes that are credentials wherever they appear.
_VALUE_SECRET = re.compile(
    r"(?i)^(bearer\s+\S{16,}|basic\s+[A-Za-z0-9+/]{20,}={0,2}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})$"
)


def is_redacted(value: Any) -> bool:
    return isinstance(value, str) and value.startswith(REDACTED_PREFIX)


def _fingerprint(value: Any, key: bytes) -> str:
    """Short keyed fingerprint so a snapshot can say *that* a secret changed without
    storing it. Truncated to 32 bits: too short to confirm a guessed password."""
    digest = hmac.new(key or b"nodewatch", str(value).encode("utf-8"), hashlib.sha256).hexdigest()
    return digest[:8]


def _placeholder(value: Any, key: bytes) -> str:
    if value in (None, ""):
        return value  # nothing to hide
    return f"{REDACTED_PREFIX}:{_fingerprint(value, key)}***"


def redact_config(value: Any, key: bytes = b"", *, _secret: bool = False, _name: str = "") -> Any:
    """Return a copy of ``value`` with every secret scalar replaced by a placeholder.

    Structure is preserved (objects like ``dynamic_psk: {enabled: true}`` keep their
    non-secret fields), so diffs and restore previews still work on redacted data.
    """
    if isinstance(value, dict):
        out = {}
        for k, item in value.items():
            name = str(k)
            low = name.lower()
            secret_key = low not in _NOT_SECRET and bool(_SECRET_KEY.search(name))
            container = low not in _NOT_SECRET and bool(_SECRET_CONTAINER.search(name))
            if isinstance(item, (dict, list)):
                out[k] = redact_config(item, key, _secret=_secret or container, _name=name)
            elif (_secret or secret_key) and not isinstance(item, bool):
                out[k] = item if is_redacted(item) else _placeholder(item, key)
            else:
                out[k] = _redact_scalar(item, key)
        return out
    if isinstance(value, list):
        secret_list = _secret or (bool(_name) and _name.lower() not in _NOT_SECRET and bool(_SECRET_KEY.search(_name)))
        return [
            redact_config(item, key, _secret=_secret, _name=_name)
            if isinstance(item, (dict, list))
            else (
                _placeholder(item, key)
                if secret_list and not isinstance(item, bool) and not is_redacted(item)
                else _redact_scalar(item, key)
            )
            for item in value
        ]
    if is_redacted(value):
        return value
    return _placeholder(value, key) if _secret and not isinstance(value, bool) else _redact_scalar(value, key)


def _redact_scalar(value: Any, key: bytes) -> Any:
    if isinstance(value, str) and _VALUE_SECRET.match(value.strip()):
        return _placeholder(value, key)
    return value


def contains_clear_secret(value: Any) -> bool:
    """True when ``value`` still holds a secret that redaction would hide."""
    return _mask_fp(redact_config(value, b"probe")) != _mask_fp(value)


def _mask_fp(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _mask_fp(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_mask_fp(v) for v in value]
    if is_redacted(value):
        return REDACTED_PREFIX
    return value


# --------------------------------------------------------------------------- diff engine

# Never meaningful as configuration changes: the shared list (timestamps, run-time state, signed /
# expiring links such as ``image1_url``) lives in app/core/volatile_fields.py (v0.10.24).
VOLATILE_KEYS = set(_VOLATILE_KEYS | _STATE_KEYS)

# Object keys that hold user-named entries; their children are names, not schema keys.
NAMED_CONTAINERS = {
    "port_usages",
    "port_config",
    "networks",
    "vlans",
    "ip_configs",
    "vrf_instances",
    "vrf_config",
    "port_mirroring",
    "acl_tags",
    "vars",
    "extra_routes",
    "extra_routes6",
    "dhcpd_config",
    "local_port_config",
    "port_config_overwrite",
    "bgp_config",
    "path_preferences",
    "tunnel_configs",
    "ospf_areas",
    "routing_policies",
    "evpn_config",
    "aggregate_routes",
    "aamw_profiles",
}

_LABELS = {
    "vlan_id": "VLAN",
    "vlan_ids": "VLANs",
    "port_usages": "Port profiles",
    "port_config": "Port assignments",
    "usage": "Profile",
    "ssid": "SSID",
    "networks": "Networks",
    "ntp_servers": "NTP servers",
    "dns_servers": "DNS servers",
    "dns_suffix": "DNS suffix",
    "radius_config": "RADIUS",
    "auth_servers": "Auth servers",
    "acct_servers": "Accounting servers",
    "switch_mgmt": "Switch management",
    "root_password": "Root password",
    "snmp_config": "SNMP",
    "poe_disabled": "PoE disabled",
    "port_auth": "Port authentication",
    "all_networks": "All networks (trunk)",
    "stp_edge": "STP edge",
    "enabled": "Enabled",
    "disabled": "Disabled",
    "auth": "Security",
    "psk": "PSK",
    "networktemplate_id": "Switch template",
    "gatewaytemplate_id": "WAN Edge template",
    "rftemplate_id": "RF template",
    "sitetemplate_id": "Site template",
    "alarmtemplate_id": "Alarm template",
    "deviceprofile_id": "Device profile",
    "sitegroup_ids": "Site groups",
    "ip_config": "IP config",
    "oob_ip_config": "OOB IP config",
    "dhcp_snooping": "DHCP snooping",
    "mtu": "MTU",
    "speed": "Speed",
    "duplex": "Duplex",
    "description": "Description",
    "notes": "Notes",
    "name": "Name",
    "band": "Band",
    "bands": "Bands",
    "interface": "Interface",
    "roam_mode": "Roaming",
    "hide_ssid": "Hidden SSID",
    "isolation": "Client isolation",
    "apply_to": "Apply to",
    "ap_ids": "APs",
    "wxtag_ids": "WxLAN tags",
    "dynamic_vlan": "Dynamic VLAN",
    "vlan_enabled": "VLAN tagging",
    "subnet": "Subnet",
    "gateway": "Gateway",
}

# For matching list items between two versions (first key present on every item wins).
_IDENTITY_KEYS = ("id", "name", "mac", "port_id", "ssid", "member", "member_id", "host", "key", "subnet")


def label_key(key: Any, parent: str = "") -> str:
    text = str(key)
    if parent in NAMED_CONTAINERS:
        return text  # a user's own name: ge-0/0/1, "cameras", "Guest"
    if text in _LABELS:
        return _LABELS[text]
    return _humanize_key(text) or text


def _identity(*sides: list) -> str | None:
    """Key that uniquely identifies every dict item within each side (e.g. ``name``)."""
    if not any(sides) or not all(isinstance(x, dict) for side in sides for x in side):
        return None
    for key in _IDENTITY_KEYS:
        ok = True
        for side in sides:
            values = [json.dumps(x.get(key), sort_keys=True, default=str) for x in side if x.get(key) not in (None, "")]
            if len(values) != len(side) or len(set(values)) != len(values):
                ok = False
                break
        if ok:
            return key
    return None


def _change(kind: str, path: list, labels: list, before: Any, after: Any) -> dict:
    secret = is_redacted(before) or is_redacted(after)
    return {
        "kind": kind,
        "path": [str(p) for p in path],
        "label": " › ".join(labels) if labels else "(whole object)",
        # A signed link's credentials (jwt=, token=, X-Amz-* …) are never shown.
        "before": redact_signed_urls(before),
        "after": redact_signed_urls(after),
        "secret": secret,
    }


def diff_config(before: Any, after: Any, *, max_changes: int = 500) -> list[dict]:
    """Human-readable, path-level differences between two configuration values.

    Each change is ``{kind: added|removed|changed, path, label, before, after, secret}``
    where ``label`` reads like ``Port profiles › cameras › VLAN``. Lists of objects are
    matched by identity (name/id/mac…) so reordering is not reported as a change.
    """
    out: list[dict] = []
    _walk(before, after, [], [], "", out, max_changes)
    return out


def _walk(before: Any, after: Any, path: list, labels: list, parent: str, out: list, cap: int) -> None:
    if len(out) >= cap:
        return
    if isinstance(before, dict) and isinstance(after, dict):
        for key in sorted(set(before) | set(after), key=str):
            b_has, a_has = key in before, key in after
            b, a = before.get(key), after.get(key)
            if is_volatile_change(key, b, a, include_state=True):
                continue
            lbl = labels + [label_key(key, parent)]
            if b_has and a_has:
                _walk(b, a, path + [key], lbl, str(key), out, cap)
            elif a_has:
                if a in (None, "", [], {}):
                    continue
                out.append(_change("added", path + [key], lbl, None, a))
            else:
                if b in (None, "", [], {}):
                    continue
                out.append(_change("removed", path + [key], lbl, b, None))
            if len(out) >= cap:
                return
        return
    if isinstance(before, list) and isinstance(after, list):
        if before == after:
            return
        ident = _identity(before, after) if before and after else None
        if ident:
            bmap = {json.dumps(x.get(ident), sort_keys=True, default=str): x for x in before}
            amap = {json.dumps(x.get(ident), sort_keys=True, default=str): x for x in after}
            for k in list(bmap) + [k for k in amap if k not in bmap]:
                item_label = str(json.loads(k))
                lbl = labels + [item_label]
                if k in bmap and k in amap:
                    _walk(bmap[k], amap[k], path + [item_label], lbl, "", out, cap)
                elif k in amap:
                    out.append(_change("added", path + [item_label], lbl, None, amap[k]))
                else:
                    out.append(_change("removed", path + [item_label], lbl, bmap[k], None))
            return
        if all(not isinstance(x, (dict, list)) for x in before + after):
            b_set = [x for x in before if x not in after]
            a_set = [x for x in after if x not in before]
            if not b_set and not a_set:
                return  # same members, different order
            row = _change("changed", path, labels, before, after)
            row["items_added"] = a_set
            row["items_removed"] = b_set
            out.append(row)
            return
        out.append(_change("changed", path, labels, before, after))
        return
    if before != after and not same_signed_link(before, after):
        out.append(_change("changed", path, labels, before, after))


def top_level_keys(changes: list[dict]) -> list[str]:
    seen: list[str] = []
    for c in changes:
        key = c["path"][0] if c["path"] else ""
        if key and key not in seen:
            seen.append(key)
    return seen


# --------------------------------------------------------------------------- restore helpers


def fill_redacted(
    proposed: Any, live: Any, path: tuple = (), *, key: bytes | None = None, strict: bool = False
) -> tuple[Any, list[dict]]:
    """Replace redacted placeholders in ``proposed`` with the live value at the same path.

    Returns ``(request, notes)``. Each note is ``{path, state}`` where state is
    ``kept`` (live secret matches the snapshot's fingerprint or simply reused) or
    ``missing`` (no live value to reuse: the object cannot be safely restored).

    ``strict`` is set for list items matched only by position (no unique name/id/mac/host): there
    the live item may be a different entry, so its secret is reused only when its fingerprint
    (computed with ``key``) equals the snapshot's; otherwise the secret is reported ``missing``.
    """
    notes: list[dict] = []
    if is_redacted(proposed):
        if live is None or is_redacted(live):
            notes.append({"path": ".".join(map(str, path)), "state": "missing"})
            return proposed, notes
        if strict and (key is None or proposed != _placeholder(live, key)):
            notes.append({"path": ".".join(map(str, path)), "state": "missing"})
            return proposed, notes
        notes.append({"path": ".".join(map(str, path)), "state": "kept"})
        return live, notes
    if isinstance(proposed, dict):
        out = {}
        live_d = live if isinstance(live, dict) else {}
        for k, v in proposed.items():
            out[k], sub = fill_redacted(v, live_d.get(k), path + (k,), key=key, strict=strict)
            notes.extend(sub)
        return out, notes
    if isinstance(proposed, list):
        live_l = live if isinstance(live, list) else []
        ident = _identity(proposed, live_l) if proposed and live_l else None
        out_l = []
        for i, item in enumerate(proposed):
            match, by_position = None, False
            if ident and isinstance(item, dict):
                match = next((x for x in live_l if isinstance(x, dict) and x.get(ident) == item.get(ident)), None)
            elif i < len(live_l):
                match, by_position = live_l[i], True
            filled, sub = fill_redacted(item, match, path + (i,), key=key, strict=strict or by_position)
            out_l.append(filled)
            notes.extend(sub)
        return out_l, notes
    return proposed, notes


# --------------------------------------------------------------------------- template overrides

# Per-device by nature: never reported as overriding a template.
PER_DEVICE_KEYS = {
    "name",
    "notes",
    "x",
    "y",
    "map_id",
    "height",
    "orientation",
    "ip_config",
    "oob_ip_config",
    "role",
    "router_id",
    "port_config",
    "deviceprofile_id",
    "image1_url",
    "image2_url",
    "image3_url",
    "managed",
    "disable_auto_config",
    "vc_mac",
    "evpntopo_id",
    "virtual_chassis",
}
IDENTITY_KEYS = {"id", "org_id", "site_id", "mac", "serial", "model", "type", "hw_rev", "sku", "for_site"}


def template_overrides(device: dict, parent: dict, *, max_changes: int = 80) -> list[dict]:
    """Settings a device defines itself that its template/profile also defines differently.

    Only keys present on both sides count; device-specific keys (name, IP, port
    assignments, map placement) are expected to differ and are skipped.
    """
    rows = []
    for key in sorted(set(device) & set(parent), key=str):
        if (
            key in PER_DEVICE_KEYS
            or key in IDENTITY_KEYS
            or is_volatile_key(key, include_state=True)
            or str(key).startswith("_")
        ):
            continue
        changes = diff_config({key: parent[key]}, {key: device[key]}, max_changes=max_changes)
        if changes:
            rows.append({"key": key, "label": label_key(key), "change_count": len(changes), "changes": changes[:25]})
    return rows
