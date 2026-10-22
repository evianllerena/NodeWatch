"""Firewalls discovered from Strata Logging Service traffic logs (v0.10.25, inventory: preview).

Strata Cloud Manager's device list holds only firewalls *onboarded* to SCM. Panorama-managed firewalls that
forward logs to Strata Logging Service are missing there, but every traffic log names the firewall that
wrote it (``log_source_id`` = serial, ``log_source_name``). This module samples recent traffic logs in the
background and turns what it sees into firewall :class:`Device` records, keyed by serial (the same key
Panorama and SCM use, so the records merge), with vendor-neutral placement evidence:

* ``addresses``    — the most common private NAT source addresses (the firewall's own inside / egress IPs);
* ``lan_prefixes`` — the /24s of sources in inside zones (networks behind the firewall);
* ``status``       — up when it logged in the last 30 minutes, else unknown; ``last_seen``.

v0.10.27:

* **What each log source is**, from the rows (never from its name): Prisma Access writes traffic logs too and
  flags them (``is_prisma_mobile`` = a mobile-user / GlobalProtect cloud gateway, ``is_prisma_branch`` = a
  remote-network gateway, a ``*service*connection*`` flag = a service connection to a data center). Those
  become ``role="cloud_gateway"`` devices with ``cloud_kind`` on the connector's "cloud" site; the rest are
  firewalls.
* **Ports and peers**: per source the (interface, zone) pairs it logged and a bounded tally of the private
  addresses seen on each (source → inbound interface / from-zone, destination → outbound interface /
  to-zone): ``Device.observed_peers`` and the INTERFACES capability.
* **HA**: a passive HA unit writes no traffic logs. One read-only query of the Log Viewer *system* dataset
  over 24 h (a 4xx answer is remembered: never asked again) finds log sources missing from traffic, and HA
  events give ``ha_state`` (active / passive) and the peer when the event names it.

Cost and safety: never runs on a request thread; at most ``MAX_QUERIES`` read-only Log Viewer queries per
discovery, in parallel on the Traffic & Sessions query pool; the result is cached in the data folder for
``CACHE_S`` and refreshed at most every ``REFRESH_S``. When Log Viewer accepts a ``not_in`` filter on
``log_source_id``, quiet firewalls are found by excluding the ones already seen; a 4xx answer to that form
is remembered and plain time-window sampling is used instead.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import re
import threading
import time
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable

from app.integrations.connectors.sdk import device_key as make_device_key
from app.integrations.connectors.sdk import epoch_seconds, stable_key
from app.integrations.connectors.sdk import site_key as make_site_key
from app.integrations.domain import Device, Interface, Site
from app.core.file_utils import write_private_text

log = logging.getLogger("nodewatch.connectors.paloalto_scm")

STATE_NAME = "scm_log_firewalls.json"
CACHE_S = 6 * 3600.0  # a discovery is used this long
REFRESH_S = 3600.0  # and refreshed this often (in the background)
RETRY_S = 600.0  # after a discovery where no query answered
DISCOVERY_METHOD = 2  # bump when discovery learns a new way to find firewalls (forces one fresh run)
SYSTEM_RETRY_S = 24 * 3600.0  # a refused system-log query is tried again after this
MAX_QUERIES = 13  # + at most 8 system-log name probes, once a day until one answers
PAGE_SIZE = 1000
UP_WITHIN_S = 30 * 60.0
LABEL = "seen in logs"
SYSTEM_LABEL = "seen in system logs"
SYSTEM_DATASET = "firewall_system"
CLOUD_SITE_ID = "cloud:prisma-access"
CLOUD_SITE_NAME = "Prisma Access (Palo Alto cloud)"
MAX_PEERS = 200  # observed private addresses kept per log source
MAX_PORTS = 48
_TRUE = ("1", "true", "yes", "y")
_SERVICE_CONNECTION = re.compile(r"service.?conn", re.I)
_HA_TO_STATE = re.compile(r"to state\s+(active|passive|non-functional|suspended|initial|tentative)", re.I)
_HA_WORDS = re.compile(r"\bHA\b|ha[-_ ]?(state|group|peer|link)|\bpeer\b|\bpassive\b|\bactive\b", re.I)
_SERIAL_IN_TEXT = re.compile(r"\b(\d{12,15})\b")
# minutes ago → sampled window length (minutes): recent first, then spread over the last 24 h
WINDOWS = ((0, 15), (60, 15), (180, 15), (360, 15), (720, 15), (1080, 15), (1380, 15))
_OUTSIDE = ("untrust", "outside", "internet", "external", "wan", "public", "isp")
NOT_IN_UNKNOWN, NOT_IN_OK, NOT_IN_REFUSED = "unknown", "supported", "unsupported"

Sampler = Callable[[datetime, datetime, list[str]], list[dict[str, Any]]]


def _value(raw: Any) -> Any:
    if isinstance(raw, dict):
        for k in ("value", "name", "id"):
            if raw.get(k) not in (None, ""):
                return raw[k]
        return None
    return raw


def _text(raw: Any) -> str:
    v = _value(raw)
    return "" if v is None else str(v).strip()


def _when(raw: Any) -> float | None:
    v = _value(raw)
    num = epoch_seconds(v)
    if num is not None:
        return num
    try:
        return datetime.fromisoformat(str(v).replace("Z", "+00:00")).timestamp()
    except (TypeError, ValueError):
        return None


_LAN_NETS = tuple(
    ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fc00::/7")
)


def _private_ip(text: str) -> str:
    """A LAN (RFC 1918 / CGNAT / ULA) address, '' otherwise (documentation ranges are not LANs)."""
    try:
        ip = ipaddress.ip_address(text.split("/")[0])
    except ValueError:
        return ""
    return str(ip) if any(ip.version == n.version and ip in n for n in _LAN_NETS) else ""


_INSIDE_WORDS = ("trust", "trusted", "inside", "internal", "lan", "dmz", "guest")


def _inside(zone: str) -> bool:
    """An inside zone: not one whose words name the outside ("untrust", "internet-wan"), unless a word also
    names an inside network ("trust-sdwan", "Internet_Guest")."""
    words = [re.sub(r"\d+$", "", w) for w in re.split(r"[^a-z0-9]+", zone.lower()) if w]
    if not words:
        return False
    if any(w in _INSIDE_WORDS for w in words):
        return True
    return not any(w in _OUTSIDE for w in words)


def _flag(row: dict[str, Any], name: str) -> bool:
    return str(_value(row.get(name)) or "").strip().lower() in _TRUE


_FALSE = ("", "0", "false", "no", "n", "none", "null")
CLOUD_SHARE = 0.6  # a source is a cloud gateway only when most of its rows carry the flag
CLOUD_MIN_ROWS = 3


def _service_connection(row: dict[str, Any]) -> bool:
    """A service-connection flag (true) or name (e.g. ``service_connection_name: "SC-Miami"``) on the row."""
    for k, v in row.items():
        if _SERVICE_CONNECTION.search(str(k)):
            val = _value(v)
            if str(val if val is not None else "").strip().lower() not in _FALSE:
                return True
    return False


_CLOUD_FIELDS = ("sub_tenant", "sub_tenant_name", "container_id", "container_name", "log_source", "source_device_host")


def summarize(
    rows: list[dict[str, Any]], now: float | None = None, system_rows: list[dict[str, Any]] | None = None
) -> list[dict[str, Any]]:
    """Per log source serial: name, last seen, top NAT source addresses, top inside /24s, ports (interface,
    zone), observed peer addresses, what it is (``kind``: firewall / mobile_users / service_connection /
    remote_network) and, from system logs, sources missing from traffic and HA state / peer."""
    now = now or time.time()
    acc: dict[str, dict[str, Any]] = {}

    def entry(serial: str) -> dict[str, Any]:
        return acc.setdefault(
            serial,
            {
                "name": "", "last_seen": None, "nat": Counter(), "lan": Counter(), "rows": 0, "ifs": set(),
                "ports": Counter(), "peers": Counter(), "mobile": 0, "branch": 0, "svc": 0, "cloud_fields": {},
                "system_rows": 0, "ha": None, "ha_peer": "",
            },
        )  # fmt: skip

    for row in rows:
        if not isinstance(row, dict):
            continue
        serial = _text(row.get("log_source_id"))
        if not serial:
            continue
        a = entry(serial)
        a["rows"] += 1
        a["name"] = a["name"] or _text(row.get("log_source_name"))
        seen = _when(row.get("time_generated") or row.get("receive_time"))
        if seen is not None and (a["last_seen"] is None or seen > a["last_seen"]):
            a["last_seen"] = seen
        nat = _private_ip(_text(row.get("nat_source")))
        if nat:
            a["nat"][nat] += 1
        src = _private_ip(_text(row.get("source_ip")))
        if src and _inside(_text(row.get("from_zone"))):
            a["lan"][str(ipaddress.ip_network(f"{src}/24", strict=False))] += 1
        for k in ("inbound_if", "outbound_if"):
            name = _text(row.get(k))
            if name:
                a["ifs"].add(name)
        for ip_field, if_field, zone_field, way in (
            ("source_ip", "inbound_if", "from_zone", "in"),
            ("dest_ip", "outbound_if", "to_zone", "out"),
        ):
            itf, zone = _text(row.get(if_field)), _text(row.get(zone_field))
            if itf:
                a["ports"][(itf, zone)] += 1
            ip = _private_ip(_text(row.get(ip_field)))
            if ip:  # without an interface it still says which networks this source reaches
                a["peers"][(ip, itf, zone, way)] += 1
        a["mobile"] += _flag(row, "is_prisma_mobile")
        a["branch"] += _flag(row, "is_prisma_branch")
        a["svc"] += _service_connection(row)
        for k in _CLOUD_FIELDS:
            v = _text(row.get(k))
            if v and k not in a["cloud_fields"]:
                a["cloud_fields"][k] = v[:80]
    # System logs: sources that wrote no traffic (a passive HA unit) and HA state changes.
    names = {serial: a["name"] for serial, a in acc.items()}
    ha_events: list[tuple[float, str, str, str]] = []
    for row in system_rows or []:
        if not isinstance(row, dict):
            continue
        serial = _text(row.get("log_source_id"))
        if not serial:
            continue
        a = entry(serial)
        a["system_rows"] += 1
        a["name"] = a["name"] or _text(row.get("log_source_name"))
        names.setdefault(serial, a["name"])
        seen = _when(row.get("time_generated") or row.get("receive_time"))
        if seen is not None and (a["last_seen"] is None or seen > a["last_seen"]):
            a["last_seen"] = seen
        kind = " ".join(_text(row.get(k)) for k in ("subtype", "sub_type", "event_id", "eventid", "log_subtype"))
        text = " ".join(_text(row.get(k)) for k in ("description", "message", "opaque", "event_description"))
        if not (_HA_WORDS.search(kind) or ("ha" in kind.lower().split()) or re.search(r"HA Group|HA peer", text, re.I)):
            continue
        ha_events.append((seen or 0.0, serial, kind, text))
    for when, serial, _kind, text in sorted(ha_events):
        a = acc[serial]
        m = _HA_TO_STATE.search(text)
        if m and "peer" not in text[: m.start()].lower():
            a["ha"] = m.group(1).lower()  # its own state (latest event wins)
        elif m:
            peer_state = m.group(1).lower()  # "Peer device moved to state Active": this one is the other
            if peer_state in ("active", "passive") and a["ha"] is None:
                a["ha"] = "passive" if peer_state == "active" else "active"
        for other in _SERIAL_IN_TEXT.findall(text):
            if other != serial:
                a["ha_peer"] = other
        if not a["ha_peer"]:
            for other, nm in names.items():
                if other != serial and nm and len(nm) >= 3 and re.search(rf"\b{re.escape(nm)}\b", text, re.I):
                    a["ha_peer"] = other
    out = []
    for serial, a in sorted(acc.items()):
        need = max(CLOUD_MIN_ROWS, CLOUD_SHARE * a["rows"])
        if a["svc"] >= need:
            kind = "service_connection"
        elif a["mobile"] >= need and a["mobile"] >= a["branch"]:
            kind = "mobile_users"
        elif a["branch"] >= need:
            kind = "remote_network"
        else:
            kind = "firewall"
        out.append(
            {
                "serial": serial,
                "name": a["name"] or serial,
                "last_seen": a["last_seen"],
                "addresses": [ip for ip, _n in a["nat"].most_common(3)],
                "lan_prefixes": [p for p, _n in a["lan"].most_common(5)],
                "interfaces": sorted(a["ifs"])[:24],
                "rows": a["rows"],
                "kind": kind,
                "cloud_fields": dict(a["cloud_fields"]),
                "ports": [{"interface": i, "zone": z} for (i, z), _n in a["ports"].most_common(MAX_PORTS)],
                "peers": [
                    {"ip": ip, "interface": i, "zone": z, "dir": w}
                    for (ip, i, z, w), _n in a["peers"].most_common(MAX_PEERS)
                ],
                "system_rows": a["system_rows"],
                "ha_state": a["ha"] or "",
                "ha_peer": a["ha_peer"],
            }
        )
    return out


def cloud_site(source: str) -> Site:
    """The one "cloud" site that holds this source's cloud gateways (Prisma Access has no building)."""
    return Site(key=make_site_key(source, CLOUD_SITE_ID), source=source, name=CLOUD_SITE_NAME, kind="cloud",
                native_id=CLOUD_SITE_ID)  # fmt: skip


def to_devices(found: list[dict[str, Any]], source: str, now: float | None = None) -> list[Device]:
    now = now or time.time()
    out = []
    by_serial = {str(f.get("serial") or ""): f for f in found}
    dup = Counter(str(f.get("name") or "") for f in found)
    site = cloud_site(source)
    for f in found:
        serial = str(f.get("serial") or "")
        if not serial:
            continue
        seen = f.get("last_seen")
        kind = str(f.get("kind") or "firewall")
        cloud = kind in ("mobile_users", "service_connection", "remote_network")
        name = str(f.get("name") or serial)
        aliases = []
        if dup[name] > 1:  # five "GP cloud service" units: tell them apart
            aliases = [name]
            name = f"{name} (…{serial[-4:]})"
        labels = [LABEL] if f.get("rows") else [SYSTEM_LABEL]
        peer = str(f.get("ha_peer") or "")
        ha = str(f.get("ha_state") or "")
        members = []
        if peer:
            other = by_serial.get(peer) or {}
            members = [
                {"serial": serial, "name": name, "role": ha or "ha-member"},
                {"serial": peer, "name": str(other.get("name") or ""), "role": str(other.get("ha_state") or "") or "ha-peer"},
            ]  # fmt: skip
        out.append(
            Device(
                key=make_device_key(serial=serial, source=source, native_id=serial),
                source=source,
                name=name,
                role="cloud_gateway" if cloud else "firewall",
                cloud_kind=kind if cloud else "",
                native_id=serial,
                site_key=site.key if cloud else "",
                site_name=site.name if cloud else "",
                vendor_name="Palo Alto Networks",
                serial=serial,
                status="up" if isinstance(seen, (int, float)) and now - seen < UP_WITHIN_S else "unknown",
                last_seen=float(seen) if isinstance(seen, (int, float)) else None,
                labels=labels,
                aliases=aliases,
                addresses=[str(x) for x in f.get("addresses") or []][:3],
                lan_prefixes=[str(x) for x in f.get("lan_prefixes") or []][:5],
                ha_state=ha,
                members=members,
                observed_peers=[dict(p) for p in f.get("peers") or []][:MAX_PEERS],
                vendor={
                    "discovered_from": "traffic_logs" if f.get("rows") else "system_logs",
                    "log_rows_sampled": int(f.get("rows") or 0),
                    **({"prisma": dict(f.get("cloud_fields") or {})} if f.get("cloud_fields") else {}),
                },
            )
        )
    return out


def to_interfaces(f: dict[str, Any], device_key: str, source: str) -> list[Interface]:
    """The ports a log source logged traffic on, with their zones (role from the zone's words)."""
    out = []
    seen: set[str] = set()
    for p in f.get("ports") or []:
        name = str(p.get("interface") or "")
        if not name or name in seen:
            continue
        seen.add(name)
        zone = str(p.get("zone") or "")
        low = name.lower()
        out.append(
            Interface(
                key=stable_key(device_key, name),
                source=source,
                device_key=device_key,
                name=name,
                kind="tunnel" if low.startswith("tunnel") else ("loopback" if low.startswith("loopback") else
                                                                ("vlan" if "." in name else "physical")),
                zone=zone,
                role="" if not zone else ("lan" if _inside(zone) else "wan"),
                vendor={"seen_in": "traffic_logs"},
            )
        )  # fmt: skip
    return out


class LogFirewalls:
    """Background discovery with a persisted cache (one per connector instance)."""

    def __init__(self, state_dir: Path | None = None) -> None:
        self._lock = threading.Lock()
        self._running = threading.Lock()
        self._state: dict[str, Any] | None = None
        self._state_dir = state_dir

    # ---- persistence ---------------------------------------------------------------------------
    def _path(self) -> Path:
        if self._state_dir is not None:
            return self._state_dir / STATE_NAME
        from app.core.config import STATE_ROOT

        return STATE_ROOT / STATE_NAME

    def _load(self) -> dict[str, Any]:
        with self._lock:
            if self._state is None:
                try:
                    data = json.loads(self._path().read_text(encoding="utf-8"))
                    self._state = data if isinstance(data, dict) else {}
                except (OSError, ValueError):
                    self._state = {}
            return dict(self._state)

    def _save(self, data: dict[str, Any]) -> None:
        with self._lock:
            self._state = dict(data)
        p = self._path()
        try:
            p.parent.mkdir(parents=True, exist_ok=True)
            write_private_text(p, json.dumps(data, separators=(",", ":"), default=str))  # atomic, owner-only (v0.10.40)
        except OSError as exc:
            log.info("SCM log firewalls not persisted: %s", exc)

    def clear(self) -> None:
        with self._lock:
            self._state = {}

    # ---- public --------------------------------------------------------------------------------
    def found(self) -> list[dict[str, Any]]:
        """Last discovery (≤ CACHE_S old), [] when none."""
        st = self._load()
        if time.time() - float(st.get("at") or 0) > CACHE_S:
            return []
        return list(st.get("firewalls") or [])

    def due(self) -> bool:
        st = self._load()
        # A discovery saved by an older NodeWatch (different method version) is redone at once after an
        # upgrade, so new ways of finding firewalls (e.g. system logs for passive HA units) apply right away.
        if st and st.get("method") != DISCOVERY_METHOD:
            return True
        return time.time() - float(st.get("at") or 0) >= REFRESH_S

    def refresh(
        self, sampler: Sampler, *, pool: Any = None, background: bool = True, system_sampler: Sampler | None = None
    ) -> bool:
        """Start one discovery (never two at once). ``background=False`` runs it inline (tests)."""
        if not self._running.acquire(blocking=False):
            return False

        def run() -> None:
            try:
                self._discover(sampler, pool, system_sampler)
            except Exception as exc:  # noqa: BLE001 - discovery is best effort
                log.info("SCM firewall discovery from traffic logs failed: %s", exc)
            finally:
                self._running.release()

        if background:
            threading.Thread(target=run, name="scm-log-firewalls", daemon=True).start()
        else:
            run()
        return True

    # ---- discovery -----------------------------------------------------------------------------
    def _discover(self, sampler: Sampler, pool: Any, system_sampler: Sampler | None = None) -> None:
        started = time.monotonic()
        st = self._load()
        not_in = st.get("not_in_mode") or NOT_IN_UNKNOWN
        now = datetime.now(timezone.utc)
        queries = 0
        rows: list[dict[str, Any]] = []

        def window(ago: int, length: int) -> tuple[datetime, datetime]:
            end = now - timedelta(minutes=ago)
            return end - timedelta(minutes=length), end

        jobs = [window(a, n) for a, n in WINDOWS][:MAX_QUERIES]

        failures = 0

        def one(w: tuple[datetime, datetime]) -> list[dict[str, Any]]:
            nonlocal failures
            try:
                return list(sampler(w[0], w[1], []) or [])
            except Exception as exc:  # noqa: BLE001 - one window failing never hides the others
                failures += 1
                log.info("SCM log sample %s–%s failed: %s", w[0], w[1], exc)
                return []

        if pool is not None and len(jobs) > 1:
            for part in pool.map(one, jobs):
                rows += part
        else:
            for w in jobs:
                rows += one(w)
        queries += len(jobs)
        if not rows and failures:
            # Nothing answered (expired token, tenant unreachable…): keep what was found before and
            # try again in RETRY_S instead of wiping the list for an hour.
            st["at"] = time.time() - REFRESH_S + RETRY_S
            st["last_error_at"] = time.time()
            self._save(st)
            log.info(
                "SCM firewalls from traffic logs: %d of %d queries failed; keeping the previous list",
                failures,
                len(jobs),
            )
            return
        serials = {_text(r.get("log_source_id")) for r in rows if isinstance(r, dict)} - {""}
        # Quiet firewalls: exclude what was seen and look again over the whole day.
        while not_in != NOT_IN_REFUSED and serials and queries < MAX_QUERIES:
            queries += 1
            try:
                more = list(sampler(now - timedelta(hours=24), now, sorted(serials)) or [])
            except Exception as exc:  # noqa: BLE001
                status = getattr(exc, "status_code", None)
                if isinstance(status, int) and 400 <= status < 500:
                    not_in = NOT_IN_REFUSED
                    log.info("Log Viewer refuses not_in on log_source_id (HTTP %s); sampling windows only", status)
                else:
                    log.info("SCM quiet-firewall query failed: %s", exc)
                break
            not_in = NOT_IN_OK
            new = {_text(r.get("log_source_id")) for r in more if isinstance(r, dict)} - {""} - serials
            rows += more
            if not new:
                break
            serials |= new
        # Units that were active earlier this week (e.g. before a failover) left traffic logs then.
        if not_in == NOT_IN_OK and serials and queries < MAX_QUERIES:
            queries += 1
            try:
                older = list(sampler(now - timedelta(days=7), now - timedelta(hours=24), sorted(serials)) or [])
                rows += older
                serials |= {_text(r.get("log_source_id")) for r in older if isinstance(r, dict)} - {""}
            except Exception as exc:  # noqa: BLE001
                log.info("SCM 7-day quiet-firewall query failed: %s", exc)
        system_rows: list[dict[str, Any]] = []
        # v0.10.28: the v0.10.27 one-name probe ("system_mode") is ignored; refusals are retried daily.
        sys_variant = st.get("system_variant") or None
        sys_refused_at = float(st.get("system_refused_at") or 0)
        if system_sampler is not None and (sys_variant or time.time() - sys_refused_at > SYSTEM_RETRY_S):
            if sys_variant and hasattr(system_sampler, "combos"):
                try:
                    system_sampler.combos.remove(tuple(sys_variant))
                    system_sampler.combos.insert(0, tuple(sys_variant))
                except ValueError:
                    pass
            queries += 1
            try:
                system_rows = list(system_sampler(now - timedelta(hours=24), now, []) or [])
                working = getattr(system_sampler, "working", None)
                if working:
                    sys_variant = list(working)
                    log.info(
                        "Log Viewer system log answers as %s (time field %s): %d rows",
                        working[0],
                        working[1],
                        len(system_rows),
                    )
                sys_refused_at = 0
            except Exception as exc:  # noqa: BLE001
                status = getattr(exc, "status_code", None)
                tried = getattr(system_sampler, "refusals", [])
                if status in (400, 403, 404, 422):
                    sys_refused_at = time.time()
                    sys_variant = None
                    log.info(
                        "Log Viewer refused every system log name (retried in 24 h): %s",
                        " | ".join(tried)[:900] or f"HTTP {status}",
                    )
                else:
                    log.info("SCM system log query failed (%s); retried next discovery", status or exc)
        sys_mode = NOT_IN_OK if sys_variant else (NOT_IN_REFUSED if sys_refused_at else NOT_IN_UNKNOWN)
        found = summarize(rows, system_rows=system_rows)
        self._save(
            {
                "at": time.time(),
                "firewalls": found,
                "not_in_mode": not_in,
                "system_mode": sys_mode,
                "system_variant": sys_variant,
                "system_refused_at": sys_refused_at,
                "queries": queries,
                "method": DISCOVERY_METHOD,
            }
        )
        log.info(
            "SCM firewalls from traffic logs: %d found in %d rows with %d queries in %d ms (not_in %s)",
            len(found),
            len(rows),
            queries,
            round((time.monotonic() - started) * 1000),
            not_in,
        )
        names = sorted(
            f"{f.get('name') or '?'}(…{str(f.get('serial') or '')[-4:]}{', ' + f['ha_state'] if f.get('ha_state') else ''})"
            for f in found
            if not f.get("cloud_kind")
        )
        log.info("SCM firewalls by name (%d): %s", len(names), ", ".join(names[:40]))


def provider_sampler(provider: Any, dataset: str = "firewall_traffic") -> Sampler | None:
    """A sampler over the Traffic & Sessions Log Viewer provider; None when it cannot query raw rows."""
    post = getattr(provider, "_post_logviewer", None)
    build = getattr(provider, "_build_body", None)
    if not callable(post) or not callable(build) or not getattr(provider, "configured", False):
        return None

    def sample(start: datetime, end: datetime, exclude: list[str]) -> list[dict[str, Any]]:
        body = build(start, end, page_size=PAGE_SIZE, page_number=1)
        if exclude:
            body["filter"]["rules"].append({"property": "log_source_id", "operator": "not_in", "values": exclude})
        # A probe never marks the whole provider unhealthy: the not_in form and the optional system dataset
        # may be refused while ordinary traffic queries work.
        payload = post(dataset, body, probe=bool(exclude) or dataset != "firewall_traffic")
        return [r for r in (payload.get("data") or []) if isinstance(r, dict)]

    return sample


class SystemSampler:
    """System-log sampler that finds the Log Viewer name and time field the tenant accepts.

    The system log (where a passive HA unit, which passes no traffic, still writes HA and heartbeat
    events) is not documented for the Log Viewer API. Each dataset name in ``SYSTEM_DATASETS`` is tried
    with the time filter on ``event_time`` and then on ``time_generated``; the first combination that
    answers is kept in ``working`` (and stored by the discovery), refusals are kept in ``refusals`` with
    the API's own error text so diagnostics show why.
    """

    TIME_FIELDS = ("event_time", "time_generated")

    def __init__(self, provider: Any, preferred: tuple[str, str] | None = None) -> None:
        from app.integrations.providers.strata_logging import SYSTEM_DATASETS

        self._post = provider._post_logviewer
        self._build = provider._build_body
        combos = [(d, t) for d in SYSTEM_DATASETS for t in self.TIME_FIELDS]
        if preferred and tuple(preferred) in combos:
            combos.remove(tuple(preferred))
            combos.insert(0, tuple(preferred))
        self.combos = combos
        self.working: tuple[str, str] | None = None
        self.refusals: list[str] = []

    def __call__(self, start: datetime, end: datetime, exclude: list[str]) -> list[dict[str, Any]]:
        last: Exception | None = None
        for dataset, time_field in self.combos:
            body = self._build(start, end, page_size=PAGE_SIZE, page_number=1)
            if time_field != "event_time":
                for rule in body.get("filter", {}).get("rules", []):
                    if isinstance(rule, dict) and rule.get("property") == "event_time":
                        rule["property"] = time_field
            try:
                payload = self._post(dataset, body, probe=True)
            except Exception as exc:  # noqa: BLE001
                status = getattr(exc, "status_code", None)
                if status in (400, 403, 404, 422):  # this name / field refused (or not permitted): try the next
                    self.refusals.append(f"{dataset}/{time_field}: HTTP {status} {str(exc)[:160]}")
                    last = exc
                    continue
                raise  # 401/429/5xx: not a naming problem; asked again next discovery
            self.working = (dataset, time_field)
            return [r for r in (payload.get("data") or []) if isinstance(r, dict)]
        raise last or RuntimeError("no system log dataset answered")


_DISCOVERY_POOL: Any = None


def provider_pool() -> Any:
    """A small pool of its own: discovery queries take ~30 s each and must never queue the operator's
    Traffic & Sessions searches behind them."""
    global _DISCOVERY_POOL
    if _DISCOVERY_POOL is None:
        from concurrent.futures import ThreadPoolExecutor

        _DISCOVERY_POOL = ThreadPoolExecutor(max_workers=3, thread_name_prefix="scm-log-discovery")
    return _DISCOVERY_POOL


def group_rows_by_serial(rows: list[dict[str, Any]]) -> dict[str, int]:
    out: dict[str, int] = defaultdict(int)
    for r in rows:
        out[_text(r.get("log_source_id"))] += 1
    return dict(out)
