"""PAN-OS log vocabulary → vendor-neutral :class:`SecurityEvent` (v0.10.30).

Shared by the two Palo Alto connectors that read threat and URL logs — Strata Cloud Manager (Log Viewer
JSON rows, ``paloalto_scm/threats.py``) and Panorama (XML API log entries, ``panorama/threats.py``) — so the
same detection counts the same way whichever system delivered it. This is the only module that knows PAN-OS
sub-types, actions and field spellings; nothing outside the two connectors imports it.

* **Vocabulary** — PAN-OS sub-types (vulnerability, spyware, virus, wildfire, scan, flood, packet, data,
  file, url …) become NodeWatch ``kind`` values; PAN-OS actions (alert, drop, reset-both, block-url,
  sinkhole …) become ``outcome``; severities informational … critical become info … critical.
* **Direction** from addresses and zones, never from PAN-OS "direction of attack" (client→server /
  server→client, which is not in or out of the organisation).
* **Countries** from ``source_location`` / ``srcloc`` (codes, names or private ranges) through
  :func:`app.integrations.geo.country_code`.
* **CVE ids** from a CVE field when present, else from the threat name.
"""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timezone
from typing import Any

from app.integrations.connectors.sdk import device_key as make_device_key
from app.integrations.connectors.sdk import epoch_seconds, stable_key
from app.integrations.domain import SecurityEvent
from app.integrations.geo import country_code

_CVE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
_THREAT_ID_SUFFIX = re.compile(r"\s*\((\d{3,})\)\s*$")

# PAN-OS threat sub-type → NodeWatch kind
_KIND = {
    "vulnerability": "exploit",
    "spyware": "command_control",
    "dns": "command_control",
    "dns-security": "command_control",
    "virus": "malware",
    "wildfire": "malware",
    "wildfire-virus": "malware",
    "ml-virus": "malware",
    "scan": "reconnaissance",
    "flood": "flood",
    "packet": "flood",
    "data": "data_loss",
    "file": "data_loss",
    "url": "web",
    "phishing": "web",
    "brute-force": "credential",
}
# PAN-OS threat category words that refine the kind (threat_category / category text)
_CATEGORY_KIND = (
    ("brute", "credential"),
    ("phishing", "web"),
    ("dns-c2", "command_control"),
    ("command-and-control", "command_control"),
    ("c2", "command_control"),
    ("info-leak", "reconnaissance"),
    ("scan", "reconnaissance"),
)
_SEVERITY = {
    "critical": "critical",
    "high": "major",
    "medium": "warning",
    "low": "info",
    "informational": "info",
    "info": "info",
}
_BLOCKED = {
    "drop",
    "drop-all",
    "drop-all-packets",
    "deny",
    "reset-client",
    "reset-server",
    "reset-both",
    "block",
    "block-url",
    "block-ip",
    "block-continue",
    "block-override",
    "override-lockout",
    "random-drop",
    "syncookie-sent",
}
_CONTAINED = {"sinkhole", "quarantine"}
_ALERTED = {"alert", "continue", "override"}
_ALLOWED = {"allow", "allowed"}
_OUTSIDE_ZONE = ("untrust", "outside", "internet", "external", "wan", "public", "isp")


def _value(raw: Any) -> Any:
    if isinstance(raw, dict):
        for k in ("value", "name", "id"):
            if raw.get(k) not in (None, ""):
                return raw[k]
        return None
    return raw


def _pick(row: dict[str, Any], *names: str) -> str:
    for n in names:
        if n in row:
            v = _value(row[n])
            if v not in (None, ""):
                if isinstance(v, (list, tuple)):
                    v = ", ".join(str(x) for x in v if x not in (None, ""))
                return str(v).strip()
    return ""


def _int(text: str) -> int | None:
    try:
        return int(float(text))
    except (TypeError, ValueError):
        return None


def _ip(text: str) -> str:
    try:
        return str(ipaddress.ip_address(str(text).strip()))
    except ValueError:
        return ""


def _private(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if a.version == 4 and a in ipaddress.ip_network("100.64.0.0/10"):
        return True
    return bool(a.is_private and not a.is_loopback and not a.is_link_local)


def _outside(zone: str) -> bool:
    z = zone.lower()
    return any(z == w or z.startswith(w) for w in _OUTSIDE_ZONE)


def direction(src: str, dst: str, src_zone: str = "", dst_zone: str = "") -> str:
    """inbound / outbound / internal / unknown from addresses, then zones."""
    sp, dp = (_private(src) if src else None), (_private(dst) if dst else None)
    if sp is False and dp is True:
        return "inbound"
    if sp is True and dp is False:
        return "outbound"
    if sp is True and dp is True:
        if _outside(src_zone) and not _outside(dst_zone):
            return "inbound"  # NAT'd inbound: the firewall logged the translated inside address
        return "internal"
    if src_zone and dst_zone:
        if _outside(src_zone) and not _outside(dst_zone):
            return "inbound"
        if not _outside(src_zone) and _outside(dst_zone):
            return "outbound"
    return "unknown"


def outcome(action: str) -> str:
    a = action.strip().lower()
    if a in _BLOCKED or a.startswith("reset") or a.startswith("drop") or a.startswith("block"):
        return "blocked"
    if a in _CONTAINED:
        return "contained"
    if a in _ALERTED:
        return "alerted"
    if a in _ALLOWED:
        return "allowed"
    return "unknown"


def kind_of(sub_type: str, category: str, dataset_kind: str) -> str:
    if dataset_kind == "url":
        cat = category.lower()
        return "web" if not any(w in cat for w in ("c2", "command-and-control")) else "command_control"
    st = sub_type.strip().lower()
    kind = _KIND.get(st, "")
    cat = category.lower()
    for word, k in _CATEGORY_KIND:
        if word in cat:
            if kind in ("", "reconnaissance", "exploit") and k == "credential":
                return k
            if not kind:
                kind = k
    return kind or "other"


def cves_of(row: dict[str, Any], name: str) -> list[str]:
    found: list[str] = []
    direct = row.get("cve") or row.get("cves") or row.get("cve_id")
    texts = [direct] if isinstance(direct, str) else list(direct or []) if isinstance(direct, list) else []
    texts.append(name)
    for t in texts:
        for m in _CVE.findall(str(t or "")):
            m = m.upper()
            if m not in found:
                found.append(m)
    return found[:8]


def when_of(row: dict[str, Any], naive_offset_s: float = 0.0) -> float | None:
    """Epoch seconds of a row: epoch numbers (s / ms / µs), ISO 8601 with an offset (Log Viewer,
    ``high_res_timestamp``), or the XML API's 'YYYY/MM/DD HH:MM:SS', which is the manager's wall clock:
    ``naive_offset_s`` (seconds that clock is ahead of UTC) converts it."""
    raw = _pick(row, "high_res_timestamp", "time_generated", "event_time", "receive_time", "log_time")
    when = epoch_seconds(raw)
    if when is not None or not raw:
        return when
    try:
        moment = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        try:
            moment = datetime.strptime(raw[:19], "%Y/%m/%d %H:%M:%S")
        except ValueError:
            return None
    if moment.tzinfo is None:
        return moment.replace(tzinfo=timezone.utc).timestamp() - naive_offset_s
    return moment.timestamp()


def to_event(
    row: dict[str, Any], source: str, dataset_kind: str = "threat", *, naive_offset_s: float = 0.0
) -> SecurityEvent | None:
    """One Log Viewer threat / URL row → :class:`SecurityEvent` (None when it has no time)."""
    when = when_of(row, naive_offset_s)
    if when is None:
        return None
    sub_type = _pick(row, "sub_type", "subtype", "log_subtype", "threat_type")
    category = _pick(row, "threat_category", "thr_category", "category", "url_category", "url_category_list")
    name = _pick(row, "threat_name", "threat_name_firewall", "threatid", "threat", "verdict")
    signature = _pick(row, "threat_id", "tid", "threatid_num", "signature_id")
    m = _THREAT_ID_SUFFIX.search(name)  # XML API: "Apache Log4j Remote Code Execution Vulnerability(91991)"
    if m:
        signature = signature or m.group(1)
        name = name[: m.start()].strip()
    if not name and signature:
        name = f"Threat {signature}"
    src = _ip(_pick(row, "source_ip", "src_ip", "src"))
    dst = _ip(_pick(row, "dest_ip", "destination_ip", "dst_ip", "dst"))
    src_zone = _pick(row, "from_zone", "source_zone", "from")
    dst_zone = _pick(row, "to_zone", "dest_zone", "destination_zone", "to")
    action = _pick(row, "action")
    url = _pick(row, "url", "url_domain", "misc", "uri") if dataset_kind == "url" else _pick(row, "url", "url_domain")
    host = _pick(row, "url_domain", "domain", "dns_query", "query_name")
    if not host and url:
        host = re.sub(r"^[a-z]+://", "", url).split("/", 1)[0].split(":", 1)[0]
    if dataset_kind == "url" and not name:
        name = f"Blocked web: {category or host or 'URL'}"
    serial = _pick(row, "log_source_id", "serial", "device_serial")
    seq = _pick(row, "sequence_no", "seqno", "log_id")
    key = stable_key(source, serial, seq) if seq else stable_key(
        source, serial, when, src, dst, signature or name, _pick(row, "session_id")
    )
    sev = _SEVERITY.get(_pick(row, "severity", "vendor_severity").lower(), "")
    if not sev:
        sev = "warning" if dataset_kind == "url" else "info"
    repeat = _int(_pick(row, "repeat_count", "repeatcnt", "count")) or 1
    file_hash = _pick(row, "file_sha_256", "file_hash", "sha256", "file_digest")
    file_name = _pick(row, "file_name", "filename")
    if dataset_kind != "url" and not file_name and sub_type.lower() in ("virus", "wildfire", "wildfire-virus", "file"):
        file_name = _pick(row, "misc")
    sensor = _pick(row, "log_source_name", "device_name")
    return SecurityEvent(
        key=key,
        source=source,
        timestamp=float(when),
        kind=kind_of(sub_type, category, dataset_kind),
        severity=sev,
        outcome=outcome(action),
        direction=direction(src, dst, src_zone, dst_zone),
        name=name[:200],
        signature_id=signature[:40],
        cves=cves_of(row, name),
        category=(category or sub_type)[:80],
        src_ip=src,
        src_port=_int(_pick(row, "source_port", "src_port", "sport")),
        src_country=country_code(
            _pick(row, "source_location", "src_location", "source_country", "source_country_code", "src_country", "srcloc", "src_loc")
        ),
        src_user=_pick(row, "source_user", "src_user", "srcuser")[:120],
        src_zone=src_zone[:60],
        dst_ip=dst,
        dst_port=_int(_pick(row, "dest_port", "destination_port", "dst_port", "dport")),
        dst_country=country_code(
            _pick(row, "dest_location", "dst_location", "destination_location", "destination_country", "dest_country_code", "dst_country", "dstloc", "dst_loc")
        ),
        dst_host=host[:200],
        dst_zone=dst_zone[:60],
        application=_pick(row, "app", "application")[:80],
        protocol=_pick(row, "protocol", "proto")[:20],
        sensor_key=make_device_key(serial=serial, source=source, native_id=serial) if serial else "",
        sensor_name=sensor[:120],
        rule=_pick(row, "rule_matched", "rule")[:120],
        url=url[:400],
        file_name=file_name[:200],
        file_hash=file_hash[:64],
        count=max(1, repeat),
        native_id=seq[:40],
        vendor={
            "log": dataset_kind,
            "sub_type": sub_type[:40],
            "action": action[:40],
            **({"direction_of_attack": _pick(row, "direction_of_attack")[:40]} if row.get("direction_of_attack") else {}),
        },
    )


