"""Canonical sites for the topology map (v0.10.23).

Every connector names sites in its own key space (``stable_key("site", <connector>, id)``), so the same
building is a Mist site, an EdgeConnect "site" text, a Panorama device group, an SNMP ``site_name``
setting … and none of their keys are equal. This module maps every connector site to one **canonical
site** and places every device record in one:

* Connector sites with the same normalized name are one canonical site; names that differ only by a
  company prefix ("LMC-Hialeah"), punctuation, case, affix words ("… Clinic") or word order / spacing
  ("WestKendall" vs "West Kendall") are joined automatically when the match is unambiguous.
* Strata Cloud Manager folders and Prisma Access remote networks are *secondary*: they never become a
  site of their own, they only join an existing one (by a strong name match or a user mapping).
* The user can override any of it (``state/topology/site_map.json``): connector site → canonical
  site, and device record → canonical site.

A device record is placed by (first answer wins):

1. a user device mapping;
2. its connector site (when that maps to a canonical site);
3. its connector site *name* (records whose site key is not listed);
4. LLDP adjacency learned by a site build (an inventory device of that site sees it as a neighbor);
5. its host name, display name or labels containing a site's name or code ("LMC-HIALEAH-EC1" → Hialeah,
   "EH590-PA-1" → EH590);
6. its management IP inside a site's LAN prefix (longest match, /22 or longer; never a factory-default
   address or one that other devices in the organisation share);
7. (organisation-wide / per build) the site of its HA peer or stack member (same serial / MAC);
8. otherwise it stays unassigned (listed in the site-map API and as a data gap).

The canonical key of a site is the key of one of its connector sites (the one from the source that
lists the most sites), so keys the UI already stored keep working.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import re
import threading
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable

from app.core.config import STATE_ROOT
from app.core.file_utils import write_private_text

log = logging.getLogger("nodewatch.topology")

ROOT: Path = STATE_ROOT / "topology"
SITE_MAP_FILE = "site_map.json"
PLACEMENTS_FILE = "placements.json"

AUTO_MIN = 0.8  # a name score at least this high (and unambiguous) joins sites automatically
SECONDARY_MIN = 0.9  # secondary sites (SCM folders / remote networks) need a stronger match
SUGGEST_MIN = 0.5  # shown as a suggestion in the site-map API
AMBIGUITY_GAP = 0.1  # best match must beat the second best by this much
MAX_LEARNED = 20000

_AFFIXES = {
    "site",
    "campus",
    "clinic",
    "office",
    "branch",
    "location",
    "facility",
    "store",
    "the",
}
# Host-name tokens that never identify a site on their own.
_GENERIC = {
    "sw",
    "ap",
    "fw",
    "gw",
    "rtr",
    "core",
    "dist",
    "access",
    "edge",
    "wan",
    "lan",
    "mdf",
    "idf",
    "main",
    "new",
    "old",
    "test",
    "lab",
    "hq",
}
# Site kinds that group devices without being a place (vendor-neutral convention: a connector puts
# ``kind`` in ``Site.vendor`` — or a future ``Site.kind`` field). They never become a site on their own and
# never place devices by themselves; "folder"/"group"/"container" never even auto-join a site by name.
# ``Site.kind`` (v0.10.24): "container" (SCM folder, Meraki organization, Central group, ADOM …) and
# "remote_network" never become a map of their own, for any vendor.
_SECONDARY_KINDS = {"container", "remote_network"}
_CLOUD_KINDS = {"cloud"}  # v0.10.27: a cloud service's own site ("Cloud services" tier of the org map)
_GROUPING_KINDS = {"container"}
# transition: connectors that predate Site.kind put their own word in Site.vendor["kind"]
_LEGACY_KIND = {
    "folder": "container",
    "group": "container",
    "device_group": "container",
    "prisma_access_remote_network": "remote_network",
}
_SUB_KINDS = {"building", "floor", "area"}  # part of a site: joins its parent (``Site.parent_key``)

# Placement by management IP (v0.10.24, review #3): only distinctive addresses place a device.
MIN_PLACE_PREFIX = 22  # a prefix wider than /22 says too little about where a box is
# Factory-default / commonly reused management addresses (consumer and appliance defaults); a device with
# one of these, or with an address any other device in the organisation also uses, is never placed by subnet.
DEFAULT_MGMT_IPS = frozenset(
    {
        "192.168.0.1",
        "192.168.1.1",
        "192.168.1.99",
        "192.168.1.254",
        "192.168.0.254",
        "192.168.100.1",
        "192.168.88.1",
        "192.168.2.1",
        "10.0.0.1",
        "10.0.0.138",
        "10.1.1.1",
        "10.10.10.1",
        "172.16.0.1",
    }
)

# Consumer / ISP-modem default LANs (v0.10.26): thousands of homes and modems use them, so they never place
# a device or join sites, whoever claims them.
CONSUMER_DEFAULT_NETS = tuple(
    ipaddress.ip_network(n)
    for n in ("192.168.0.0/24", "192.168.1.0/24", "192.168.100.0/24", "10.0.0.0/24", "10.0.1.0/24")
)
# Address space a site LAN uses (RFC 1918, carrier-grade NAT, IPv6 ULA) — not documentation ranges.
_LAN_SPACE = tuple(
    ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fc00::/7")
)
# Prefix-index origins that are a site's own LAN (the others only say where an address was seen).
LAN_ORIGIN_KINDS = frozenset({"connected", "routes", "lan-next-hop", "interfaces"})


def consumer_default(value: Any) -> bool:
    """An address or network inside one of :data:`CONSUMER_DEFAULT_NETS`."""
    try:
        net = ipaddress.ip_network(str(value).strip(), strict=False)
    except ValueError:
        return False
    return any(net.version == n.version and net.subnet_of(n) for n in CONSUMER_DEFAULT_NETS)


def lan_space(value: Any) -> bool:
    """A private LAN address (RFC 1918 / CGNAT / ULA), not loopback / link-local / documentation."""
    try:
        addr = ipaddress.ip_address(str(value).strip().split("/")[0])
    except ValueError:
        return False
    return any(addr.version == n.version and addr in n for n in _LAN_SPACE)


_lock = threading.RLock()
_user_cache: dict[str, Any] = {"mtime": None, "data": None}
_learned: dict[str, dict[str, Any]] = {}
_learned_loaded = False
_learned_dirty = False
_registry_cache: dict[str, Any] = {"sig": None, "reg": None}


# --------------------------------------------------------------------------- name handling


def tokens(name: Any) -> list[str]:
    """'LMC-Hialeah Clinic #2' → ['lmc', 'hialeah', 'clinic', '2']."""
    return [t for t in re.split(r"[^0-9a-z]+", str(name or "").lower()) if t]


def _source_prefixes(names: list[str]) -> tuple[set[str], bool]:
    """(company-code first tokens, strip a leading number?) common to most of one source's site names."""
    firsts = [tokens(n)[0] for n in names if len(tokens(n)) > 1]
    if len(names) < 3 or not firsts:
        return set(), False
    count = Counter(firsts)
    prefixes = {t for t, c in count.items() if c >= max(3, len(names) * 0.5) and len(t) <= 6 and not t.isdigit()}
    numeric = sum(1 for t in firsts if t.isdigit()) >= len(names) * 0.5
    return prefixes, numeric


def core_tokens(name: Any, prefixes: Iterable[str] = (), strip_number: bool = False) -> list[str]:
    """Tokens that identify the place: company prefix, a leading site number and affix words dropped."""
    words = tokens(name)
    if len(words) > 1 and words[0] in set(prefixes):
        words = words[1:]
    if strip_number and len(words) > 1 and words[0].isdigit():
        words = words[1:]
    core = [w for w in words if w not in _AFFIXES]
    return core or words


ABBREV_SCORE = 0.85
ABBREV_MIN = 5


def abbreviations(core: list[str]) -> set[str]:
    """Run-together abbreviations of a multi-word site name (v0.10.27): the 2–4 first letters of each of its
    distinctive words, in order — "DC1 QTS Miami" → qtsmi, qtsmia, qtsmiam, … (generic / numbered words such
    as dc1, site, campus are skipped). Only results of ≥ 5 letters; at most 4 words are combined."""
    words = [w for w in core if w.isalpha() and w not in _GENERIC and w not in _AFFIXES]
    if len(words) < 2 or len(words) > 4:
        return set()
    out = {""}
    for w in words:
        out = {x + w[:n] for x in out for n in range(2, min(4, len(w)) + 1)}
    return {x for x in out if len(x) >= ABBREV_MIN}


def name_score(a: list[str], b: list[str]) -> float:
    """Similarity of two core-token lists, 0 … 0.95."""
    if not a or not b:
        return 0.0
    ja, jb = "".join(a), "".join(b)
    if a == b or ja == jb:
        return 0.95
    # "QTSMIA" ↔ "DC1 QTS Miami": one word that is the other's words abbreviated and run together
    for one, many in ((a, b), (b, a)):
        if len(one) == 1 and len(one[0]) >= ABBREV_MIN and len(many) >= 2 and one[0] in abbreviations(many):
            return ABBREV_SCORE
    sa, sb = set(a), set(b)
    small, big = (sa, sb) if len(sa) <= len(sb) else (sb, sa)
    if small < big and len("".join(small)) >= 4 and not small <= _GENERIC:
        return 0.8
    short, long_ = (ja, jb) if len(ja) <= len(jb) else (jb, ja)
    if len(short) >= 5 and short in long_:
        return 0.75
    inter, union = len(sa & sb), len(sa | sb)
    jac = inter / union if union else 0.0
    if jac >= 0.5:
        return round(0.5 + 0.3 * jac, 3)
    return 0.0


# --------------------------------------------------------------------------- persistence


def _path(name: str) -> Path:
    return ROOT / name


def _read_json(name: str) -> Any:
    try:
        return json.loads(_path(name).read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    except (OSError, ValueError) as exc:
        log.info("topology: %s unreadable: %s", name, exc)
        return None


def _write_json(name: str, data: Any) -> None:
    p = _path(name)
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        write_private_text(p, json.dumps(data, separators=(",", ":"), default=str))  # atomic, owner-only (v0.10.40)
    except OSError as exc:
        log.info("topology: %s not saved: %s", name, exc)


def user_map() -> dict[str, Any]:
    """{"mappings": {connector site key: canonical key}, "device_sites": {record key: canonical key}}."""
    with _lock:
        try:
            mtime = _path(SITE_MAP_FILE).stat().st_mtime
        except OSError:
            mtime = None
        if _user_cache["data"] is not None and _user_cache["mtime"] == mtime:
            return _user_cache["data"]
        raw = _read_json(SITE_MAP_FILE) if mtime is not None else None
        data = {
            "mappings": {},
            "device_sites": {},
            "dismissed": [],
            "dismissed_pairs": [],
            "ha_partners": {},
            "updated_at": None,
        }
        if isinstance(raw, dict):
            for k in ("mappings", "device_sites"):
                v = raw.get(k)
                if isinstance(v, dict):
                    data[k] = {str(a)[:300]: str(b)[:300] for a, b in v.items() if str(a).strip() and str(b).strip()}
            if isinstance(raw.get("dismissed"), list):  # legacy (v0.10.25): per connector site
                data["dismissed"] = [str(x)[:300] for x in raw["dismissed"] if str(x).strip()]
            if isinstance(raw.get("dismissed_pairs"), list):  # v0.10.26: the joins the user undid
                data["dismissed_pairs"] = sorted(
                    {
                        tuple(sorted((str(p[0])[:300], str(p[1])[:300])))
                        for p in raw["dismissed_pairs"]
                        if isinstance(p, (list, tuple)) and len(p) == 2 and p[0] and p[1]
                    }
                )
            if isinstance(raw.get("ha_partners"), dict):  # v0.10.27: HA partners the user confirmed
                data["ha_partners"] = {
                    str(k)[:300]: _clean_partner(v) for k, v in raw["ha_partners"].items() if str(k).strip()
                }
            data["updated_at"] = raw.get("updated_at")
        _user_cache.update(mtime=mtime, data=data)
        return data


def _clean_partner(v: Any) -> dict[str, Any]:
    v = v if isinstance(v, dict) else {}
    state = str(v.get("state") or "passive").strip().lower()[:40]
    out: dict[str, Any] = {"name": str(v.get("name") or "").strip()[:200], "state": state or "passive"}
    try:  # v0.10.30: when the user confirmed it (the map's partner card says so)
        at = float(v.get("confirmed_at") or 0)
    except (TypeError, ValueError):
        at = 0.0
    if at > 0:
        out["confirmed_at"] = at
    return out


def save_user_map(
    mappings: dict[str, Any] | None,
    device_sites: dict[str, Any] | None,
    ha_partners: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Merge a PUT into the user map ("" or None removes an entry). ``ha_partners`` (v0.10.27):
    {unit record key or node id: {"name": optional, "state": "passive"} | None to remove}."""
    with _lock:
        cur = user_map()
        data = {
            "mappings": dict(cur["mappings"]),
            "device_sites": dict(cur["device_sites"]),
            "dismissed": list(cur.get("dismissed") or []),
            "dismissed_pairs": [list(p) for p in cur.get("dismissed_pairs") or []],
            "ha_partners": dict(cur.get("ha_partners") or {}),
        }
        for k, v in (ha_partners or {}).items():
            k = str(k).strip()[:300]
            if not k:
                continue
            if v is None or v == "" or v is False:
                data["ha_partners"].pop(k, None)
            else:
                prev = data["ha_partners"].get(k) or {}
                clean = _clean_partner(v)
                clean["confirmed_at"] = prev.get("confirmed_at") or clean.get("confirmed_at") or time.time()
                data["ha_partners"][k] = clean
        active = site_links()
        for field, patch in (("mappings", mappings), ("device_sites", device_sites)):
            for k, v in (patch or {}).items():
                k = str(k).strip()[:300]
                if not k:
                    continue
                if v in (None, "") or not str(v).strip():
                    data[field].pop(k, None)
                    join = active.get(k)
                    if field == "mappings" and join and join.get("b"):
                        # "" undoes the automatic join (subnet / naming evidence) shown on this site's row —
                        # only that pair; the site keeps any other join
                        pair = sorted((k, str(join["b"])))
                        if pair not in data["dismissed_pairs"]:
                            data["dismissed_pairs"].append(pair)
                else:
                    data[field][k] = str(v).strip()[:300]
                    if field == "mappings":
                        if k in data["dismissed"]:
                            data["dismissed"].remove(k)
                        data["dismissed_pairs"] = [p for p in data["dismissed_pairs"] if k not in p]
        data["updated_at"] = time.time()
        _write_json(SITE_MAP_FILE, data)
        _user_cache.update(mtime=None, data=None)
        _registry_cache.update(sig=None, reg=None)
        return user_map()


def _load_learned() -> None:
    global _learned_loaded
    if _learned_loaded:
        return
    raw = _read_json(PLACEMENTS_FILE)
    if isinstance(raw, dict):
        for k, v in raw.items():
            if isinstance(v, dict) and v.get("site"):
                _learned[str(k)] = v
    _learned_loaded = True


def learned() -> dict[str, dict[str, Any]]:
    with _lock:
        _load_learned()
        return dict(_learned)


def learn(record_key: str, site: str, via: str = "lldp", detail: str = "") -> None:
    """Remember where an otherwise unassigned device was found (LLDP adjacency)."""
    global _learned_dirty
    with _lock:
        _load_learned()
        old = _learned.get(record_key)
        if old and old.get("site") == site:
            return
        _learned[record_key] = {"site": site, "via": via, "detail": detail[:200], "at": time.time()}
        while len(_learned) > MAX_LEARNED:
            _learned.pop(next(iter(_learned)))
        _learned_dirty = True
        _registry_cache.update(sig=None, reg=None)


def flush_learned() -> None:
    global _learned_dirty
    with _lock:
        if not _learned_dirty:
            return
        _learned_dirty = False
        data = dict(_learned)
    _write_json(PLACEMENTS_FILE, data)


def clear() -> None:
    with _lock:
        _registry_cache.update(sig=None, reg=None)
        _user_cache.update(mtime=None, data=None)


# --------------------------------------------------------------------------- registry


class _Member:
    __slots__ = ("source", "key", "name", "native_id", "kind", "parent", "secondary", "core", "product")

    def __init__(self, site: Any, prefixes: set[str], strip_number: bool, product: str) -> None:
        self.source = str(getattr(site, "source", "") or "")
        self.key = str(getattr(site, "key", "") or "")
        self.name = str(getattr(site, "name", "") or self.key)
        self.native_id = str(getattr(site, "native_id", "") or "")
        # transition fallback (v0.10.24): remove when all connectors fill Site.kind
        vendor = getattr(site, "vendor", None) or {}
        kind = str(getattr(site, "kind", "") or "site")
        # transition fallback (v0.10.24): remove when all connectors fill Site.kind
        if kind == "site" and isinstance(vendor, dict) and vendor.get("kind"):
            # transition fallback (v0.10.24): remove when all connectors fill Site.kind
            kind = _LEGACY_KIND.get(str(vendor["kind"]), kind)
        self.kind = kind
        self.parent = str(getattr(site, "parent_key", "") or "")
        self.secondary = self.kind in _SECONDARY_KINDS or (self.kind in _SUB_KINDS and bool(self.parent))
        self.core = core_tokens(self.name, prefixes, strip_number)
        self.product = product


class Registry:
    """Canonical sites over every listed connector site, plus device placement."""

    def __init__(
        self,
        listed: dict[str, list[Any]],
        user: dict[str, Any] | None = None,
        learned_map: dict[str, dict[str, Any]] | None = None,
        products: dict[str, str] | None = None,
        subnets: dict[str, str] | None = None,
        shared_ips: Iterable[str] = (),
        links: dict[str, dict[str, Any]] | None = None,
        names: dict[str, Any] | None = None,
    ) -> None:
        self.naming = names or {"prefixes": {}, "stems": {}, "by_source": {}}
        self._inputs = (listed, user, learned_map, products, subnets, tuple(shared_ips), names)
        self._base: Registry | None = None
        self.links = dict(links or {})  # learned site joins: connector site key → {"b": site key, "evidence": n}
        self.shared_ips = frozenset(shared_ips)  # management IPs more than one device in the org uses
        self.user = user or {"mappings": {}, "device_sites": {}}
        self.subnets = dict(subnets or {})  # "10.1.2.0/24" → canonical site (unambiguous prefixes only)
        self._subnet_lens = sorted({int(k.rsplit("/", 1)[1]) for k in self.subnets if "/" in k}, reverse=True)
        self.learned = learned_map or {}
        products = products or {}
        self.members: dict[str, _Member] = {}
        self.prefixes: dict[str, tuple[set[str], bool]] = {}
        site_counts: dict[str, int] = {}
        for src, rows in listed.items():
            names = [str(getattr(s, "name", "") or "") for s in rows]
            self.prefixes[src] = _source_prefixes(names)
            site_counts[src] = len(rows)
            pfx, num = self.prefixes[src]
            for s in rows:
                m = _Member(s, pfx, num, products.get(src, src))
                if m.key and m.key not in self.members:
                    self.members[m.key] = m
        self._rank = {src: (-n, src) for src, n in site_counts.items()}
        self._build()

    # ---- grouping ------------------------------------------------------------------------------
    def _build(self) -> None:
        parent: dict[str, str] = {}

        def find(x: str) -> str:
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x

        def union(a: str, b: str) -> None:
            ra, rb = find(a), find(b)
            if ra != rb:
                parent[rb] = ra

        primary = [m for m in self.members.values() if not m.secondary]
        for m in primary:
            parent[m.key] = m.key
        manual = {
            k: v for k, v in self.user.get("mappings", {}).items() if k in self.members
        }  # connector site → target (any member key / canonical key)
        # "cloud" sites (v0.10.27: a provider's cloud security service) are never joined by name or evidence
        auto_ones = [m for m in primary if m.key not in manual and m.kind not in _CLOUD_KINDS]
        # 1. exact normalized name (whole name, then core tokens) across sources
        by_full: dict[str, list[_Member]] = defaultdict(list)
        for m in auto_ones:
            by_full[" ".join(tokens(m.name))].append(m)
        for group in by_full.values():
            per_src = Counter(m.source for m in group)
            if len(group) > 1 and max(per_src.values()) == 1:
                for m in group[1:]:
                    union(group[0].key, m.key)
        self.via: dict[str, tuple[str, float]] = {m.key: ("own", 1.0) for m in primary}
        for group in by_full.values():
            if len(group) > 1 and len({m.source for m in group}) == len(group):
                for m in group[1:]:
                    self.via[m.key] = ("name", 0.95)

        # 2. fuzzy: group pairs with disjoint sources, best unambiguous matches first
        def groups() -> dict[str, list[_Member]]:
            out: dict[str, list[_Member]] = defaultdict(list)
            for m in auto_ones:
                out[find(m.key)].append(m)
            return out

        scores: dict[str, list[tuple[float, str]]] = {}
        for _round in range(6):  # merged groups may now match what was ambiguous before
            gs = groups()
            index: dict[str, set[str]] = defaultdict(set)
            for gid, ms in gs.items():
                for m in ms:
                    for t in set(m.core):
                        index[t].add(gid)
                    index["#" + "".join(m.core)].add(gid)
                    for ab in abbreviations(m.core):
                        index["#" + ab].add(gid)

            def gscore(g1: list[_Member], g2: list[_Member]) -> float:
                return max((name_score(a.core, b.core) for a in g1 for b in g2), default=0.0)

            scores: dict[str, list[tuple[float, str]]] = defaultdict(list)
            for gid, ms in gs.items():
                cands: set[str] = set()
                for m in ms:
                    for t in set(m.core):
                        if len(index[t]) <= 50:
                            cands |= index[t]
                    cands |= index["#" + "".join(m.core)]
                    for ab in abbreviations(m.core):
                        cands |= index["#" + ab]
                cands.discard(gid)
                srcs = {m.source for m in ms}
                for other in cands:
                    if srcs & {m.source for m in gs[other]}:
                        continue
                    s = gscore(ms, gs[other])
                    if s >= SUGGEST_MIN:
                        scores[gid].append((s, other))
            for lst in scores.values():
                lst.sort(reverse=True)

            def clear_best(gid: str, scores: dict[str, list[tuple[float, str]]] = scores) -> tuple[float, str] | None:
                lst = scores.get(gid) or []
                if not lst:
                    return None
                best = lst[0]
                second = next((s for s, o in lst[1:] if o != best[1]), 0.0)
                return best if best[0] - second >= AMBIGUITY_GAP or best[0] >= 0.95 and second < 0.95 else None

            merged_any = False
            pairs = []
            for gid in scores:
                b = clear_best(gid)
                if b and b[0] >= AUTO_MIN:
                    back = clear_best(b[1])
                    if back and back[1] == gid:
                        pairs.append((b[0], gid, b[1]))
            for s, g1, g2 in sorted(pairs, reverse=True):
                r1, r2 = find(g1), find(g2)
                if r1 == r2:
                    continue
                s1 = {m.source for m in auto_ones if find(m.key) == r1}
                s2 = {m.source for m in auto_ones if find(m.key) == r2}
                if s1 & s2:
                    continue
                union(r1, r2)
                merged_any = True
                for m in gs[g2]:
                    if self.via[m.key][0] == "own":
                        self.via[m.key] = ("auto", s)
            if not merged_any:
                break
        self._scores = scores
        # 2b. joins learned from subnet evidence (sticky; never over a user mapping, never two sites of
        #     one source, undone by the user with mapping "")
        dismissed = set(self.user.get("dismissed") or [])  # legacy: per joining site
        pairs = {tuple(sorted(p)) for p in self.user.get("dismissed_pairs") or []}
        for a, info in sorted(self.links.items()):
            b = str((info or {}).get("b") or "")
            if (
                a in dismissed
                or tuple(sorted((a, b))) in pairs
                or a in manual
                or b in manual
                or a not in parent
                or b not in parent
            ):
                continue
            ra, rb = find(a), find(b)
            if ra == rb:
                continue
            sa = {m.source for m in auto_ones if find(m.key) == ra}
            sb = {m.source for m in auto_ones if find(m.key) == rb}
            if sa & sb:
                continue
            union(rb, ra)
            self.via[a] = (str((info or {}).get("via") or "subnet"), float((info or {}).get("evidence") or 0))

        # 3. canonical groups; anchor = member of the source listing most sites
        groups_final: dict[str, list[_Member]] = defaultdict(list)
        for m in auto_ones:
            groups_final[find(m.key)].append(m)
        self.sites: dict[str, dict[str, Any]] = {}
        self.of: dict[str, str] = {}  # connector site key → canonical key
        for ms in groups_final.values():
            ms.sort(key=lambda m: (self._rank.get(m.source, (0, m.source)), m.name.lower()))
            anchor = ms[0]
            self.sites[anchor.key] = {"key": anchor.key, "name": anchor.name, "members": list(ms)}
            for m in ms:
                self.of[m.key] = anchor.key
        self.cloud_sites: set[str] = set()
        for m in primary:
            if m.kind in _CLOUD_KINDS and m.key not in manual:
                self.sites[m.key] = {"key": m.key, "name": m.name, "members": [m], "kind": "cloud"}
                self.of[m.key] = m.key
                self.cloud_sites.add(m.key)
        # 4. manual mappings (targets may be canonical keys or any member key); primary sites mapped
        #    to "" keep their own site.
        for k, target in manual.items():
            m = self.members[k]
            tgt = self.of.get(target) or (target if target in self.sites else "")
            if not tgt and target in self.members and not self.members[target].secondary:
                tgt = self.of.get(target, "")
            if tgt:
                self.of[k] = tgt
                self.sites[tgt]["members"].append(m)
                self.via[k] = ("manual", 1.0)
            elif not m.secondary:  # unknown target: the site stays on its own
                self.sites[k] = {"key": k, "name": m.name, "members": [m]}
                self.of[k] = k
                self.via[k] = ("own", 1.0)
        # 5a. buildings / floors / areas join their parent site
        for m in self.members.values():
            if m.kind in _SUB_KINDS and m.parent and m.key not in self.of:
                parent = m.parent
                for _ in range(8):  # floor → building → site
                    if parent in self.of:
                        break
                    up = self.members.get(parent)
                    parent = up.parent if up is not None and up.parent else ""
                if parent in self.of:
                    self.of[m.key] = self.of[parent]
                    self.sites[self.of[parent]]["members"].append(m)
                    self.via[m.key] = ("parent", 1.0)
        # 5. secondary sites: only a strong, unambiguous name match joins them
        self.suggest: dict[str, tuple[str, float]] = {}
        canon_cores = {ck: [m.core for m in s["members"]] for ck, s in self.sites.items()}
        for m in self.members.values():
            if not m.secondary or m.key in self.of:
                continue
            ranked = sorted(
                ((max(name_score(m.core, c) for c in cores), ck) for ck, cores in canon_cores.items()),
                reverse=True,
            )[:2]
            if ranked and ranked[0][0] >= SUGGEST_MIN:
                self.suggest[m.key] = (ranked[0][1], ranked[0][0])
            if (
                ranked
                and m.kind not in _GROUPING_KINDS  # a folder groups devices of many sites: never auto-joined
                and ranked[0][0] >= SECONDARY_MIN
                and (len(ranked) < 2 or ranked[0][0] - ranked[1][0] >= AMBIGUITY_GAP)
            ):
                self.of[m.key] = ranked[0][1]
                self.sites[ranked[0][1]]["members"].append(m)
                self.via[m.key] = ("auto", ranked[0][0])
        # suggestions for primary sites that stayed alone
        for m in primary:
            if m.key in manual:
                continue
            ck = self.of.get(m.key)
            if ck and len(self.sites.get(ck, {}).get("members", [])) == 1:
                lst = self._scores.get(find(m.key)) or []
                if lst:
                    other = lst[0][1]
                    self.suggest[m.key] = (self.of.get(other, other), lst[0][0])
        # name index (connector site names → canonical), for records whose site key is not listed
        self.by_name: dict[str, str] = {}
        dup: set[str] = set()
        for ck, s in self.sites.items():
            for m in s["members"]:
                for nm in (" ".join(tokens(m.name)), " ".join(m.core)):
                    if nm and self.by_name.get(nm, ck) != ck:
                        dup.add(nm)
                    self.by_name.setdefault(nm, ck)
        for nm in dup:
            self.by_name.pop(nm, None)
        self.by_native: dict[str, str] = {}
        for m in self.members.values():
            if m.native_id and m.key in self.of:
                self.by_native.setdefault(m.native_id, self.of[m.key])
        # host-name matching: per canonical site, its distinctive core token lists
        self._host_keys: list[tuple[str, list[str], str]] = []
        for ck, s in self.sites.items():
            seen: set[str] = set()
            for m in s["members"]:
                core = [t for t in m.core if not t.isdigit()] or m.core
                j = "".join(core)
                if j in seen or len(j) < 4 or set(core) <= _GENERIC:
                    continue
                seen.add(j)
                self._host_keys.append((ck, core, j))
        sig = json.dumps(
            [
                sorted((k, v) for k, v in self.of.items()),
                sorted((k, v.get("site")) for k, v in self.learned.items()),
                sorted(self.user.get("device_sites", {}).items()),
                sorted(self.subnets.items()),
                sorted(self.shared_ips),
                sorted((k, str(v.get("b"))) for k, v in self.links.items()),
                sorted(self.user.get("dismissed") or []),
                sorted(map(list, self.user.get("dismissed_pairs") or [])),
                sorted((self.naming.get("stems") or {}).items()),
            ]
        )
        self.version = hashlib.sha256(sig.encode()).hexdigest()[:12]

    def base(self) -> "Registry":
        """This registry without learned site joins (what join learners and the prefix index key by)."""
        if not self.links:
            return self
        if self._base is None:
            listed, user, lrn, products, nets, shared, names = self._inputs
            self._base = Registry(listed, user, lrn, products, nets, shared, {}, names)
        return self._base

    # ---- lookups -------------------------------------------------------------------------------
    def name(self, ckey: str) -> str:
        return self.sites.get(ckey, {}).get("name", "")

    def resolve(self, key: str | None) -> str:
        """Canonical key for a canonical key, any connector site key, a native site id or a site name."""
        k = str(key or "").strip()
        if not k:
            return ""
        if k in self.sites:
            return k
        if k in self.of:
            return self.of[k]
        if k in self.by_native:
            return self.by_native[k]
        return self.by_name.get(" ".join(tokens(k)), "")

    def keys_of(self, ckey: str) -> set[str]:
        s = self.sites.get(ckey)
        return {ckey} | ({m.key for m in s["members"]} if s else set())

    def by_source(self, ckey: str) -> dict[str, list[str]]:
        out: dict[str, list[str]] = defaultdict(list)
        for m in (self.sites.get(ckey) or {}).get("members", []):
            out[m.source].append(m.key)
        return dict(out)

    def from_name(self, name: Any, source: str = "") -> str:
        if not str(name or "").strip():
            return ""
        hit = self.by_name.get(" ".join(tokens(name)))
        if hit:
            return hit
        pfx, num = self.prefixes.get(source, (set(), False))
        core = core_tokens(name, pfx, num)
        hit = self.by_name.get(" ".join(core))
        if hit:
            return hit
        best: list[tuple[float, str]] = []
        for ck, s in self.sites.items():
            sc = max((name_score(core, m.core) for m in s["members"]), default=0.0)
            if sc >= AUTO_MIN:
                best.append((sc, ck))
        best.sort(reverse=True)
        if best and (len(best) == 1 or best[0][0] - best[1][0] >= AMBIGUITY_GAP):
            return best[0][1]
        return ""

    def from_hostname(self, name: Any) -> str:
        """Canonical site whose distinctive name is in a device host name (unique longest match)."""
        words = tokens(name)
        if not words:
            return ""
        joined = "".join(words)
        wset = set(words)
        hits: dict[str, int] = {}
        for ck, core, j in self._host_keys:
            if set(core) <= wset or (len(j) >= 5 and j in joined):
                hits[ck] = max(hits.get(ck, 0), len(j))
        if not hits:
            return ""
        ranked = sorted(hits.items(), key=lambda kv: -kv[1])
        if len(ranked) > 1 and ranked[0][1] == ranked[1][1]:
            return ""
        return ranked[0][0]

    def place(self, rec: Any) -> tuple[str, str]:
        """(canonical site, via) for a device record; via ∈ manual, site, name, lldp, hostname, subnet, ''."""
        source = str(getattr(rec, "source", "") or "")
        key = str(getattr(rec, "key", "") or "")
        rk = f"{source}:{key}"
        ds = self.user.get("device_sites", {})
        manual = ds.get(rk) or ds.get(key)
        if manual:
            ck = self.resolve(manual)
            if ck:
                return ck, "manual"
        sk = str(getattr(rec, "site_key", "") or "")
        if sk:
            ck = self.of.get(sk)
            if ck:
                return ck, "site"
        if not (sk and sk in self.members):  # a site no source lists: try its name
            ck = self.from_name(getattr(rec, "site_name", ""), source)
            if ck:
                return ck, "name"
        hit = self.learned.get(rk)
        if hit and self.resolve(hit.get("site") or ""):
            return self.resolve(hit["site"]), hit.get("via") or "lldp"
        # Names / site codes / labels first: they are what the operator chose; an address can be reused.
        for text in self._names_of(rec):
            ck = self.from_hostname(text)
            if ck:
                return ck, "hostname"
        # Addresses: the management IP, then other addresses the device uses (Device.addresses).
        ips = [str(getattr(rec, "mgmt_ip", "") or "")] + [str(x) for x in getattr(rec, "addresses", None) or []]
        for ip in ips:
            ip = ip.strip().split("/")[0]
            if ip and ip not in self.shared_ips and ip not in DEFAULT_MGMT_IPS:
                ck = self.from_subnet(ip)
                if ck:
                    return ck, "subnet"
        # Networks seen behind it (Device.lan_prefixes): a clear majority over the site prefix index.
        votes: Counter = Counter()
        prefixes = [str(x) for x in getattr(rec, "lan_prefixes", None) or []]
        for p in prefixes:
            try:
                net = ipaddress.ip_network(p, strict=False)
            except ValueError:
                continue
            if consumer_default(net):
                continue
            probe = net.network_address + 1 if net.num_addresses > 2 else net.network_address
            ck = self.from_subnet(str(probe))
            if ck:
                votes[ck] += 1
        if votes:
            ranked = votes.most_common(2)
            if ranked[0][1] * 2 > len(prefixes) and (len(ranked) < 2 or ranked[0][1] > ranked[1][1]):
                return ranked[0][0], "subnet"
        ck = self.from_naming(rec)
        if ck:
            return ck, "naming"
        return "", ""

    def from_naming(self, rec: Any) -> str:
        """Learned naming convention: the record's name stem (its group's common prefix and trailing unit
        numbers removed) is the stem of one site; else a known stem of 4+ characters that is a whole word of
        the name (after the group prefix), alone or followed / preceded by unit numbers ("EHWC1", "2EHWC"),
        when exactly one site matches. Generic stems never match by containment."""
        stems = self.naming.get("stems") or {}
        if not stems:
            return ""
        group = f"{getattr(rec, 'source', '')}|{getattr(rec, 'role', '')}"
        prefix = (self.naming.get("prefixes") or {}).get(group, "")
        names = self._names_of(rec)
        for text in names:
            stem = name_stem(text, prefix)
            ck = self.resolve(stems.get(stem, "")) if stem else ""
            if ck:
                return ck
        hits: set[str] = set()
        for text in names:
            words = _name_tokens(text)
            if prefix and words:
                if words[0] == prefix:
                    words = words[1:]
                elif words[0].startswith(prefix) and len(words[0]) - len(prefix) >= 2:
                    words = [words[0][len(prefix) :], *words[1:]]
            for st, target in stems.items():
                if len(st) < 4 or generic_stem(st):
                    continue
                if any(_on_boundary(st, w) for w in words):
                    ck = self.resolve(target)
                    if ck:
                        hits.add(ck)
        return next(iter(hits)) if len(hits) == 1 else ""

    def owners(self, ip: Any) -> list[tuple[int, str]]:
        """Every (prefix length, site) whose prefix contains ``ip``, longest first (any length)."""
        try:
            addr = ipaddress.ip_address(str(ip or "").strip().split("/")[0])
        except ValueError:
            return []
        out = []
        for plen in self._subnet_lens:
            if plen > addr.max_prefixlen:
                continue
            ck = self.resolve(self.subnets.get(str(ipaddress.ip_network(f"{addr}/{plen}", strict=False))) or "")
            if ck:
                out.append((plen, ck))
        return out

    @staticmethod
    def _names_of(rec: Any) -> list[str]:
        """Host name, display name and labels of a record (SCM: hostname / display_name / labels)."""
        out = [str(getattr(rec, "name", "") or "")]
        out += [str(x) for x in getattr(rec, "aliases", None) or [] if x]  # Device.aliases
        out += [str(x) for x in getattr(rec, "labels", None) or [] if x]  # Device.labels
        # transition fallback (v0.10.24): remove when all connectors fill Device.aliases / Device.labels
        vendor = getattr(rec, "vendor", None) or {}
        # transition fallback (v0.10.24): remove when all connectors fill Device.aliases / Device.labels
        if len(out) == 1 and isinstance(vendor, dict):
            # transition fallback (v0.10.24): remove when all connectors fill Device.aliases
            out += [str(vendor[k]) for k in ("display_name", "hostname") if vendor.get(k)]
            # transition fallback (v0.10.24): remove when all connectors fill Device.labels
            if isinstance(vendor.get("labels"), (list, tuple)):
                # transition fallback (v0.10.24): remove when all connectors fill Device.labels
                out += [str(x) for x in vendor["labels"] if x]
        return [x for x in dict.fromkeys(out) if x.strip()]

    def from_subnet(self, ip: Any) -> str:
        """Canonical site whose LAN prefix (longest match, /22 or longer) contains ``ip``."""
        if not self.subnets:
            return ""
        try:
            addr = ipaddress.ip_address(str(ip or "").strip().split("/")[0])
        except ValueError:
            return ""
        if addr.is_loopback or addr.is_link_local or addr.is_unspecified or addr.is_multicast:
            return ""
        if consumer_default(addr):
            return ""  # a home / ISP-modem default LAN says nothing about the site
        for plen in self._subnet_lens:
            if plen > addr.max_prefixlen or plen < MIN_PLACE_PREFIX:
                continue
            net = ipaddress.ip_network(f"{addr}/{plen}", strict=False)
            ck = self.resolve(self.subnets.get(str(net)) or "")  # stored keys survive later site joins
            if ck:
                return ck
        return ""

    # ---- API view ------------------------------------------------------------------------------
    def describe(self) -> dict[str, Any]:
        canon = []
        for ck, s in sorted(self.sites.items(), key=lambda kv: kv[1]["name"].lower()):
            canon.append(
                {
                    "key": ck,
                    "name": s["name"],
                    "kind": s.get("kind") or "site",
                    "members": [
                        {"source": m.source, "product": m.product, "key": m.key, "name": m.name} for m in s["members"]
                    ],
                }
            )
        manual = self.user.get("mappings", {})
        rows = []
        for m in sorted(self.members.values(), key=lambda m: (m.source, m.name.lower())):
            ck = self.of.get(m.key, "")
            via, conf = self.via.get(m.key, ("", 0.0)) if ck else ("", 0.0)
            sug = self.suggest.get(m.key)
            rows.append(
                {
                    "source": m.source,
                    "product": m.product,
                    "key": m.key,
                    "name": m.name,
                    "kind": m.kind or "site",
                    "secondary": m.secondary,
                    "mapped_to": ck,
                    "mapped_name": self.name(ck),
                    "mapping": "manual"
                    if m.key in manual
                    else (
                        via
                        if via in ("subnet", "naming")
                        else ("auto" if via in ("auto", "name") else ("own" if ck else "none"))
                    ),
                    "via": "manual" if m.key in manual else (via or ""),
                    "evidence": int(conf) if via in ("subnet", "naming") else None,
                    "confidence": round(conf, 2) if via not in ("subnet", "naming") else 0.9,
                    "suggested": {"key": sug[0], "name": self.name(sug[0]), "confidence": round(sug[1], 2)}
                    if sug and sug[0] != ck
                    else None,
                }
            )
        return {"canonical_sites": canon, "connector_sites": rows, "version": self.version}


def registry(
    listed: dict[str, list[Any]] | None = None, products: dict[str, str] | None = None, *, links: bool = True
) -> "Registry":
    """The current registry (rebuilt only when the listed sites, the user map or learned placements change).

    ``links=False``: the same without learned site joins — what the join learners look at, so a join never
    becomes its own evidence (joins are re-evaluated every time, not sticky)."""
    if listed is None:
        from app.services.topology_service import listed_sites

        listed, products = listed_sites()
    user = user_map()
    lrn = learned()
    nets = subnets()
    if not links:
        return registry(listed, products).base()
    shared = shared_ips()
    links = site_links()
    names = naming()
    sig = hashlib.sha256(
        json.dumps(
            [
                sorted(nets.items()),
                sorted(shared),
                sorted((k, str(v.get("b"))) for k, v in links.items()),
                sorted(names["stems"].items()),
                sorted(names["prefixes"].items()),
                sorted(
                    (
                        src,
                        sorted(
                            (str(s.key), str(s.name), str(getattr(s, "kind", "")), str(getattr(s, "parent_key", "")))
                            for s in rows
                        ),
                    )
                    for src, rows in listed.items()
                ),
                user,
                sorted((k, v.get("site")) for k, v in lrn.items()),
            ],
            default=str,
        ).encode()
    ).hexdigest()
    with _lock:
        if _registry_cache["sig"] == sig and _registry_cache["reg"] is not None:
            return _registry_cache["reg"]
    reg = Registry(listed, user, lrn, products, nets, shared, links, names)
    with _lock:
        _registry_cache.update(sig=sig, reg=reg)
    return reg


def current_registry() -> "Registry | None":
    """The registry built last (never lists sites)."""
    with _lock:
        return _registry_cache.get("reg")


def cached_version() -> str | None:
    """Version of the registry already built (never lists sites); None when there is none yet."""
    with _lock:
        reg = _registry_cache.get("reg")
    return reg.version if reg is not None else None


# --------------------------------------------------------------------------- site prefixes (v0.10.24)

SUBNETS_FILE = "subnets.json"
_subnet_state: dict[str, Any] = {
    "loaded": False,
    "map": {},
    "built_at": 0.0,
    "detail": {},
    "shared": [],
    "origins": {},  # origin key → [[prefix, site]] (per device / input, so a failed read keeps its share)
}


def subnets() -> dict[str, str]:
    """{prefix: canonical site} used to place devices by management IP (persisted)."""
    with _lock:
        if not _subnet_state["loaded"]:
            _subnet_state["loaded"] = True
            raw = _read_json(SUBNETS_FILE)
            if isinstance(raw, dict) and isinstance(raw.get("map"), dict):
                _subnet_state["map"] = {str(k): str(v) for k, v in raw["map"].items()}
                _subnet_state["built_at"] = float(raw.get("built_at") or 0)
                _subnet_state["detail"] = raw.get("detail") or {}
                _subnet_state["shared"] = [str(x) for x in raw.get("shared") or []]
                _subnet_state["origins"] = raw.get("origins") if isinstance(raw.get("origins"), dict) else {}
        return dict(_subnet_state["map"])


def shared_ips() -> list[str]:
    subnets()
    with _lock:
        return list(_subnet_state["shared"])


def set_shared_ips(ips: Iterable[str]) -> None:
    """Management IPs used by more than one device in the organisation (never placed by subnet)."""
    new = sorted(set(ips))
    subnets()
    with _lock:
        if new == _subnet_state["shared"]:
            return
        _subnet_state["shared"] = new
        _registry_cache.update(sig=None, reg=None)
        data = {
            "built_at": _subnet_state["built_at"],
            "map": _subnet_state["map"],
            "detail": _subnet_state["detail"],
            "shared": new,
            "origins": _subnet_state["origins"],
        }
    _write_json(SUBNETS_FILE, data)


def subnets_built_at() -> float:
    subnets()
    with _lock:
        return float(_subnet_state["built_at"] or 0)


MIN_PREFIX = 16


# Strength of each prefix origin kind (higher wins a conflict on the same prefix).
ORIGIN_RANK = {
    "connected": 4,
    "routes": 4,
    "lan-next-hop": 3,
    "interfaces": 3,
    "device-addresses": 1,
    "mgmt": 1,
    "wan-addresses": 1,  # WAN-port / circuit addresses: place a box in front of an edge, never a LAN
}


def set_subnets(candidates: list[tuple[str, str, str]], keep: set[str] | None = None) -> tuple[dict[str, str], bool]:
    """Store the prefix index from ``[(prefix, canonical site, origin key)]`` → (index, changed?).

    Origin keys name where a prefix came from ("routes|<source>:<device key>", "mgmt", "iface|…").
    ``keep``: origins that could not be read this time (a source call failed) — their previous prefixes
    are carried over instead of disappearing until the next refresh. Default routes, prefixes shorter than
    /16, consumer default LANs (:data:`CONSUMER_DEFAULT_NETS`) and prefixes seen at more than one site are
    dropped."""
    subnets()
    with _lock:
        previous = {k: [tuple(x) for x in v] for k, v in (_subnet_state.get("origins") or {}).items()}
        before = dict(_subnet_state["map"])
    origins: dict[str, list[tuple[str, str]]] = defaultdict(list)
    for prefix, site, origin in candidates:
        origins[origin].append((prefix, site))
    for origin in keep or ():
        if origin in previous and origin not in origins:
            origins[origin] = previous[origin]
    # per prefix: the sites each origin kind claims; the strongest kind present decides (an address of a
    # device placed by name never outvotes a router's own connected LAN)
    claims: dict[str, dict[int, set[str]]] = defaultdict(lambda: defaultdict(set))
    kinds: dict[str, set[str]] = defaultdict(set)
    for origin, rows in origins.items():
        kind = origin.split("|", 1)[0]
        rank = ORIGIN_RANK.get(kind, 0)
        for prefix, site in rows:
            try:
                net = ipaddress.ip_network(str(prefix).strip(), strict=False)
            except ValueError:
                continue
            if net.prefixlen < MIN_PREFIX or not site or consumer_default(net):
                continue
            claims[str(net)][rank].add(site)
            kinds[str(net)].add(kind)
    sites_of = {k: by_rank[max(by_rank)] for k, by_rank in claims.items()}
    out = {k: next(iter(v)) for k, v in sites_of.items() if len(v) == 1}
    detail = {
        "schema": SUBNET_SCHEMA,
        "prefixes": len(out),
        "ambiguous": sum(1 for v in sites_of.values() if len(v) > 1),
        "by_origin": dict(Counter(o for k in out for o in kinds[k])),
        "carried_over": sorted(set(keep or ()) & set(previous)),
    }
    changed = out != before
    stored = {k: [list(x) for x in v] for k, v in origins.items()}
    with _lock:
        _subnet_state.update(loaded=True, map=out, built_at=time.time(), detail=detail, origins=stored)
        if changed:
            _registry_cache.update(sig=None, reg=None)
        shared = list(_subnet_state["shared"])
    _write_json(
        SUBNETS_FILE,
        {"built_at": time.time(), "map": out, "detail": detail, "shared": shared, "origins": stored},
    )
    return out, changed


def subnet_detail() -> dict[str, Any]:
    subnets()
    with _lock:
        return {"built_at": _subnet_state["built_at"] or None, **(_subnet_state["detail"] or {})}


# --------------------------------------------------------------------------- site joins from subnet evidence

SITE_LINKS_FILE = "site_links.json"
_links_state: dict[str, Any] = {"loaded": False, "links": {}}


def site_links() -> dict[str, dict[str, Any]]:
    """{connector site key: {"b": site key, "evidence": n, "at": epoch}} learned from subnet evidence."""
    with _lock:
        if not _links_state["loaded"]:
            _links_state["loaded"] = True
            raw = _read_json(SITE_LINKS_FILE)
            if isinstance(raw, dict):
                _links_state["links"] = {str(k): dict(v) for k, v in raw.items() if isinstance(v, dict) and v.get("b")}
        return {k: dict(v) for k, v in _links_state["links"].items()}


def _one_per_pair(found: dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """A join found from both sides (a → b and b → a) is stored once, under the smaller key."""
    out: dict[str, dict[str, Any]] = {}
    for a, info in sorted(found.items()):
        b = str(info.get("b") or "")
        if b in out and str(out[b].get("b") or "") == a:
            continue
        out[a] = info
    return out


SITE_LINKS_SEEN_FILE = "site_links_seen.json"
_seen_now: dict[str, dict[str, int]] = {}  # via → devices per source the last learner call looked at


def _note_seen(via: str, devices: list[Any]) -> None:
    with _lock:
        _seen_now[via] = dict(Counter(str(getattr(d, "source", "") or "") for d in devices))


def _inputs_complete(via: str) -> bool:
    """Every source that gave the learner devices before gave some this time too (a failed read never
    removes joins). Remembers the counts of complete reads."""
    with _lock:
        now = dict(_seen_now.get(via) or {})
    prev = _read_json(SITE_LINKS_SEEN_FILE)
    prev = prev if isinstance(prev, dict) else {}
    before = prev.get(via) if isinstance(prev.get(via), dict) else {}
    missing = [src for src, n in before.items() if int(n or 0) > 0 and not now.get(src)]
    if missing:
        log.info("topology: %s site joins kept as they are: no devices from %s this read", via, ", ".join(missing))
        return False
    if now and now != before:
        prev[via] = now
        _write_json(SITE_LINKS_SEEN_FILE, prev)
    return True


def add_site_links(found: dict[str, dict[str, Any]], via: str | None = None, *, complete: bool = True) -> bool:
    """Store learned joins → changed?

    ``via`` ("subnet" / "naming"): ``found`` is the complete current evidence of that kind — joins of that
    kind it no longer contains are dropped (re-evaluated, not sticky) — unless the read was incomplete
    (``complete=False``: a source failed, or a source that had devices before returned none), when joins
    are only added or updated. A join is stored once per pair; user mappings / dismissals are not touched."""
    current = site_links()
    new = {k: dict(v) for k, v in current.items()}
    found = _one_per_pair(found)
    if via and complete and _inputs_complete(via):
        for a in [a for a, v in new.items() if str(v.get("via") or "subnet") == via and a not in found]:
            del new[a]
    for a, info in found.items():
        b = str(info.get("b") or "")
        if not b or a == b:
            continue
        rev = new.get(b)
        if rev is not None and str(rev.get("b") or "") == a:
            continue  # the same join, stored from the other side
        old = new.get(a)
        if old is not None and old.get("b") == b and old.get("via") == info.get("via"):
            if old.get("evidence") != info.get("evidence") or old.get("of") != info.get("of"):
                new[a] = {**old, "evidence": info.get("evidence"), "of": info.get("of")}
            continue
        new[a] = {**info, "at": time.time()}
    sig = lambda d: sorted((k, str(v.get("b")), str(v.get("via")), v.get("evidence")) for k, v in d.items())  # noqa: E731
    changed = sig(new) != sig(current)
    if changed:
        with _lock:
            _links_state.update(loaded=True, links=new)
            _registry_cache.update(sig=None, reg=None)
        _write_json(SITE_LINKS_FILE, new)
    return changed


def _own_site(reg: "Registry", d: Any, place: dict[str, tuple[str, str]]) -> tuple[str, str]:
    """(site in ``reg``, via) of a device: for a device placed by its own connector site, that site as
    ``reg`` sees it (a registry without learned joins keeps the two sides of a join apart)."""
    ck, via = place.get(f"{d.source}:{d.key}", ("", ""))
    if via == "site":
        ck = reg.of.get(str(getattr(d, "site_key", "") or ""), "") or reg.resolve(ck)
    return ck, via


def learn_site_links(
    reg: "Registry", devices: list[Any], place: dict[str, tuple[str, str]]
) -> dict[str, dict[str, Any]]:
    """Single-source sites whose devices live inside another site's LAN prefixes (no shared source) are the
    same place: ``{site key: {"b": other site, "evidence": devices}}`` (≥ 2 devices and ≥ 60 % of the
    site's devices with a distinct private management IP, all pointing at one other site; or the site's
    only such device on a connected /24-or-longer LAN of the other site).

    Only prefixes of /22 or longer (:data:`MIN_PLACE_PREFIX`) count, never consumer default LANs and never
    prefixes known only as WAN-side addresses. ``reg`` should be ``registry(links=False)``."""
    _note_seen("subnet", devices)
    ips_of: dict[str, list[str]] = defaultdict(list)
    for d in devices:
        ck, via = _own_site(reg, d, place)
        ip = str(getattr(d, "mgmt_ip", "") or "").split("/")[0].strip()
        if not ck or via != "site" or not ip or ip in reg.shared_ips or ip in DEFAULT_MGMT_IPS:
            continue
        if not lan_space(ip) or consumer_default(ip):
            continue
        ips_of[ck].append(ip)
    found: dict[str, dict[str, Any]] = {}
    kinds = subnet_kinds()
    for ck, ips in ips_of.items():
        site = reg.sites.get(ck)
        if site is None:
            continue
        sources = {m.source for m in site["members"]}
        if len(sources) != 1 or any(m.secondary or m.kind in _CLOUD_KINDS for m in site["members"]):
            continue
        hits: Counter = Counter()
        strong = 0  # hits on a connected /24-or-longer LAN of the other site
        for ip in ips:
            hit = None
            for plen, owner in reg.owners(ip):
                if owner == ck or plen < MIN_PLACE_PREFIX:
                    continue
                net = str(ipaddress.ip_network(f"{ip}/{plen}", strict=False))
                k = kinds.get(net, set())
                if consumer_default(net) or (k and k <= {"wan-addresses"}):
                    continue
                hit = (plen, owner, k)
                break
            if hit:
                hits[hit[1]] += 1
                if hit[0] >= 24 and "connected" in hit[2]:
                    strong += 1
        if len(hits) != 1:
            continue
        other, n = hits.most_common(1)[0]
        target = reg.sites.get(other)
        if target is None or other in reg.cloud_sites or sources & {m.source for m in target["members"]}:
            continue
        if (n >= 2 and n >= 0.6 * len(ips)) or (len(ips) == 1 and strong == 1):
            found[ck] = {"b": other, "evidence": n, "of": len(ips), "via": "subnet"}
    return _one_per_pair(found)


def subnet_kinds() -> dict[str, set[str]]:
    """prefix → origin kinds ("connected", "lan-next-hop", "device-addresses", "interfaces")."""
    subnets()
    with _lock:
        origins = dict(_subnet_state.get("origins") or {})
    out: dict[str, set[str]] = defaultdict(set)
    for origin, rows in origins.items():
        kind = origin.split("|", 1)[0]
        for row in rows:
            try:
                out[str(ipaddress.ip_network(str(row[0]), strict=False))].add(kind)
            except (ValueError, IndexError):
                continue
    return out


# --------------------------------------------------------------------------- naming conventions (v0.10.26)

NAMING_FILE = "naming.json"
_naming_state: dict[str, Any] = {"loaded": False, "prefixes": {}, "stems": {}, "by_source": {}}
_HEX12 = re.compile(r"^[0-9A-F]{12}$")


def _clean_name(name: Any) -> str:
    text = str(name or "").strip().upper()
    return text.split(".", 1)[0] if "." in text and not text.replace(".", "").isdigit() else text


def _name_tokens(name: Any) -> list[str]:
    return [t for t in re.split(r"[^A-Z0-9]+", _clean_name(name)) if t]


PREFIX_SHARE = 0.6  # share of a group's single-word names that must start with a learned prefix


def group_prefix(names: list[str]) -> str:
    """The leading word / letters most names of one (source, role) group share (e.g. "SP" in SPEHWC1,
    SPCGD1, SPLAB1; "LMC" in LMC-HIALEAH-EC1 …): learned from the names, never a hard-coded vendor prefix.
    A prefix must be followed by different letters in different names (SPKND1/SPKND2 never make "SPKND")."""
    toks = [t for t in (_name_tokens(n) for n in names) if t]
    if len(toks) < 3:
        return ""
    multi = [t for t in toks if len(t) > 1]
    if len(multi) >= 0.8 * len(toks):
        first, count = Counter(t[0] for t in multi).most_common(1)[0]
        if count >= 0.8 * len(multi) and len({t[1] for t in multi if t[0] == first}) >= 2:
            return first
    runs = [re.match(r"[A-Z]*", t[0]).group(0) for t in toks]  # type: ignore[union-attr]
    for length in (4, 3, 2, 1):
        long_runs = [r for r in runs if len(r) >= length + 2]
        common = Counter(r[:length] for r in long_runs).most_common(1)
        if not common:
            continue
        pfx, count = common[0]
        share = PREFIX_SHARE if length >= 2 else 0.8
        if count >= max(3, share * len(runs)) and len({r[length] for r in long_runs if r.startswith(pfx)}) >= 2:
            return pfx
    return ""


def _on_boundary(stem: str, word: str) -> bool:
    """``stem`` is the whole word or the word minus leading / trailing unit numbers ("EHWC1", "2EHWC")."""
    if word == stem:
        return True
    if word.startswith(stem) and word[len(stem) :].isdigit():
        return True
    return word.endswith(stem) and word[: -len(stem)].isdigit()


def name_stem(name: Any, prefix: str = "") -> str:
    """'SPEHWC1' (prefix SP) → 'EHWC'; 'PAEHWC1-A' (PA) → 'EHWC'; 'EH590-PA-1' → 'EH590'; '' when unusable."""
    toks = _name_tokens(name)
    if not toks:
        return ""
    if len(toks) > 1:
        if prefix and toks[0] == prefix:
            toks = toks[1:]
        stem = toks[0]
    else:
        stem = re.sub(r"\d+[A-Z]?$", "", toks[0])
        if prefix and stem.startswith(prefix) and len(stem) - len(prefix) >= 2:
            stem = stem[len(prefix) :]
    if len(stem) < 2 or _HEX12.match(stem) or not re.search(r"[A-Z]", stem):
        return ""
    return stem


# Name stems that are roles / infrastructure words, never a site code on their own (v0.10.26): a stem
# like CORE, IDF2, MDF, HUB or LAB only names a site whose own code / name it is exactly.
GENERIC_STEMS = frozenset(
    {w.upper() for w in _GENERIC}
    | {
        "DISTRIBUTION",
        "AGG",
        "AGGREGATION",
        "HUB",
        "DC",
        "DR",
        "ROUTER",
        "SWITCH",
        "FIREWALL",
        "SPARE",
        "TEST",
        "TST",
        "DEV",
        "PROD",
        "STAGE",
        "STG",
        "SRV",
        "SERVER",
        "STACK",
        "VC",
        "BLDG",
        "BUILDING",
        "FLOOR",
        "FL",
        "RM",
        "ROOM",
        "CLOSET",
        "DEMO",
        "TEMP",
        "TMP",
        "BACKUP",
        "BKP",
        "PRIMARY",
        "SECONDARY",
        "PRI",
        "SEC",
        "MGMT",
        "OOB",
        "INET",
        "INTERNET",
        "VPN",
        "HA",
        "NODE",
        "GUEST",
        "VOICE",
        "WIFI",
        "WLAN",
        "UPLINK",
        "ISP",
        "MPLS",
        "LTE",
        "GATEWAY",
        "SDWAN",
        "SPOKE",
        "BRANCH",
        "SITE",
        "OFFICE",
        "REMOTE",
        "HOME",
    }
)


def _code(text: Any) -> str:
    """'EH_WC' → 'EHWC'; 'Data Center' → 'DATACENTER'."""
    return re.sub(r"[^A-Z0-9]", "", str(text or "").upper())


def generic_stem(stem: str) -> bool:
    """CORE, IDF2, MDF1, HUB, LAB … (trailing unit numbers ignored)."""
    st = str(stem or "").upper()
    return st in GENERIC_STEMS or re.sub(r"\d+$", "", st) in GENERIC_STEMS


def _site_codes(reg: "Registry | None", d: Any, ck: str, via: str) -> set[str]:
    """Normalised names of the device's own site (its connector site when placed by it, else the
    canonical site): the only codes a generic stem may stand for."""
    if reg is None:
        return set()
    out = set()
    sk = str(getattr(d, "site_key", "") or "")
    m = reg.members.get(sk) if via == "site" else None
    if m is not None:
        out.add(_code(m.name))
    else:
        out.add(_code(reg.name(ck)))
    return out - {""}


def _is_code(stem: str, codes: set[str]) -> bool:
    """``stem`` is one of ``codes``, trailing unit numbers ignored on both sides (DC ↔ "DC1")."""
    st = _code(stem)
    bare = re.sub(r"\d+$", "", st)
    return st in codes or bool(bare) and bare in {re.sub(r"\d+$", "", c) for c in codes}


def learn_naming(
    devices: list[Any], place: dict[str, tuple[str, str]], reg: "Registry | None" = None
) -> dict[str, Any]:
    """Stems of devices placed by their own site (or the user) → site, with each (source, role) group's
    learned common prefix. Generic stems (:data:`GENERIC_STEMS`) are kept only when they are the site's own
    code / name exactly ("LAB" of site LAB, never "CORE" of Alpha Clinic). ``reg``: the registry
    ``place`` came from (default: the one built last)."""
    reg = reg if reg is not None else current_registry()
    groups: dict[str, list[str]] = defaultdict(list)
    for d in devices:
        groups[f"{d.source}|{d.role}"].append(str(d.name or ""))
    prefixes = {g: p for g, p in ((g, group_prefix(n)) for g, n in groups.items()) if p}
    sites_of: dict[str, set[str]] = defaultdict(set)
    by_source: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
    # A site's own codes also include the stems of devices placed by that site whose group follows a learned
    # naming convention (edge SPHQ1 at "Headquarters" makes HQ that site's code, generic or not).
    convention: dict[str, set[str]] = defaultdict(set)
    for d in devices:
        ck, via = place.get(f"{d.source}:{d.key}", ("", ""))
        pfx = prefixes.get(f"{d.source}|{d.role}", "")
        if ck and via == "site" and pfx:
            stem = name_stem(d.name, pfx)
            if stem:
                convention[ck].add(stem)
    for d in devices:
        ck, via = place.get(f"{d.source}:{d.key}", ("", ""))
        if not ck or via not in ("site", "manual", "name") or d.role == "cloud_gateway":
            continue
        stem = name_stem(d.name, prefixes.get(f"{d.source}|{d.role}", ""))
        if not stem:
            continue
        if generic_stem(stem) and stem not in convention[ck] and not _is_code(stem, _site_codes(reg, d, ck, via)):
            continue
        if via == "site" and reg is not None and str(getattr(d, "site_key", "") or "") in reg.members:
            ck = reg.of.get(str(d.site_key), ck)  # its own site, not a site a learned join merged it into
        sites_of[stem].add(ck)
        by_source[stem][d.source].add(ck)
    stems = {k: next(iter(v)) for k, v in sites_of.items() if len(v) == 1}
    src = {stem: {s: next(iter(v)) for s, v in per.items() if len(v) == 1} for stem, per in by_source.items()}
    return {"prefixes": prefixes, "stems": stems, "by_source": src}


def naming() -> dict[str, Any]:
    with _lock:
        if not _naming_state["loaded"]:
            _naming_state["loaded"] = True
            raw = _read_json(NAMING_FILE)
            if isinstance(raw, dict):
                for k in ("prefixes", "stems", "by_source"):
                    if isinstance(raw.get(k), dict):
                        _naming_state[k] = raw[k]
        return {k: dict(_naming_state[k]) for k in ("prefixes", "stems", "by_source")}


def set_naming(learned_names: dict[str, Any]) -> bool:
    current = naming()
    new = {k: dict(learned_names.get(k) or {}) for k in ("prefixes", "stems", "by_source")}
    if new == current:
        return False
    with _lock:
        _naming_state.update(loaded=True, **new)
        _registry_cache.update(sig=None, reg=None)
    _write_json(NAMING_FILE, new)
    return True


def learn_naming_links(
    reg: "Registry", devices: list[Any], place: dict[str, tuple[str, str]]
) -> dict[str, dict[str, Any]]:
    """A one-source site whose devices' name stems all belong to one other site (of other sources) is that
    site: two or more such devices and no device of the site with a stem pointing elsewhere; or a single
    device whose stem is exactly the other site's own code / name and not a generic word.
    ``reg`` should be ``registry(links=False)`` (joins are re-evaluated, never their own evidence)."""
    _note_seen("naming", devices)
    nm = naming()
    stems_of: dict[str, list[str]] = defaultdict(list)
    for d in devices:
        ck, via = _own_site(reg, d, place)
        if ck and via == "site":
            stem = name_stem(d.name, nm["prefixes"].get(f"{d.source}|{d.role}", ""))
            if stem:
                stems_of[ck].append(stem)
    found: dict[str, dict[str, Any]] = {}
    for ck, stems in stems_of.items():
        site = reg.sites.get(ck)
        if site is None:
            continue
        sources = {m.source for m in site["members"]}
        if len(sources) != 1 or any(m.secondary or m.kind in _CLOUD_KINDS for m in site["members"]):
            continue
        hits: Counter = Counter()
        exact: Counter = Counter()
        for stem in stems:
            per = nm["by_source"].get(stem) or {}
            others = {reg.resolve(t) for s, t in per.items() if s not in sources} - {"", ck}
            if len(others) != 1:
                continue
            other = others.pop()
            hits[other] += 1
            target = reg.sites.get(other) or {}
            codes = {_code(m.name) for m in target.get("members", [])} | {_code(reg.name(other))}
            if not generic_stem(stem) and _code(stem) in codes:
                exact[other] += 1
        if len(hits) != 1:
            continue
        other, n = hits.most_common(1)[0]
        target = reg.sites.get(other)
        if target is None or other in reg.cloud_sites or sources & {m.source for m in target["members"]}:
            continue
        if (n >= 2 and n == len(stems)) or (len(stems) == 1 and exact[other] == 1):
            found[ck] = {"b": other, "evidence": n, "of": len(stems), "via": "naming"}
    return _one_per_pair(found)


# --------------------------------------------------------------------------- diagnostics (v0.10.26)

SUBNET_SCHEMA = 3  # bumped when the prefix index learns from new inputs: an older index is rebuilt at once


def subnets_schema() -> int:
    subnets()
    with _lock:
        return int((_subnet_state.get("detail") or {}).get("schema") or 1)


def _lan_ip(text: str) -> str:
    try:
        ip = ipaddress.ip_address(str(text).split("/")[0])
    except ValueError:
        return ""
    return str(ip) if ip.is_private and not ip.is_loopback and not ip.is_link_local else ""


def explain_unplaced(reg: "Registry", rec: Any) -> dict[str, Any]:
    """Why a device has no site: its address evidence, the best candidate site and why it was rejected."""
    probes: list[tuple[str, str]] = []
    for ip in [str(getattr(rec, "mgmt_ip", "") or ""), *[str(x) for x in getattr(rec, "addresses", None) or []]]:
        if _lan_ip(ip):
            probes.append((_lan_ip(ip), "address"))
    for p in getattr(rec, "lan_prefixes", None) or []:
        try:
            net = ipaddress.ip_network(str(p), strict=False)
        except ValueError:
            continue
        if net.is_private:
            probes.append((str(net.network_address + 1 if net.num_addresses > 2 else net.network_address), str(net)))
    evidence = sorted({str(ipaddress.ip_network(f"{ip}/24", strict=False)) for ip, _w in probes})
    if not probes:
        return {"evidence": [], "candidate": "", "reason": "no private address or network known for it"}
    best: tuple[int, str] | None = None
    sites: Counter = Counter()
    for ip, _what in probes:
        if ip in reg.shared_ips or ip in DEFAULT_MGMT_IPS:
            continue
        hits = reg.owners(ip)
        if hits:
            sites[hits[0][1]] += 1
            if best is None or hits[0][0] > best[0]:
                best = hits[0]
    if best is None:
        shared = [ip for ip, _w in probes if ip in reg.shared_ips or ip in DEFAULT_MGMT_IPS]
        reason = "only shared / default addresses" if shared and len(shared) == len(probes) else "no index hit"
        return {"evidence": evidence, "candidate": "", "reason": reason}
    name = reg.name(best[1])
    if len(sites) > 1:
        names = ", ".join(sorted(reg.name(k) for k in sites))
        return {"evidence": evidence, "candidate": name, "reason": f"ambiguous between {names}"}
    if best[0] < MIN_PLACE_PREFIX:
        return {
            "evidence": evidence,
            "candidate": name,
            "reason": f"below threshold: only a /{best[0]} of that site contains it (placement needs /{MIN_PLACE_PREFIX} or longer)",
        }
    return {
        "evidence": evidence,
        "candidate": name,
        "reason": f"below threshold: {sites[best[1]]} of {len(probes)} networks point there (needs a majority)",
    }
