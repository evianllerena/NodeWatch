"""Deterministic intent parser for the Operations Assistant.

Pure functions only: no Mist calls, no I/O. The service layer feeds in the site
list (and, lazily, device names) so typo-tolerant matching can work without any
external AI service.
"""

from __future__ import annotations

import ipaddress
import math
import re
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from typing import Callable, Iterable

# --------------------------------------------------------------------------- identifiers

_MAC_COLON = re.compile(r"\b(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}\b")
_MAC_DOTTED = re.compile(r"\b[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\b")
_MAC_BARE = re.compile(r"\b[0-9a-fA-F]{12}\b")
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_IPV6 = re.compile(r"(?<![\w:])(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}(?![\w:])")
_QUOTED = re.compile(r"[\"“”']([^\"“”']{2,80})[\"“”']")
_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]*[A-Za-z0-9]|[A-Za-z0-9]")


def find_mac(text: str) -> str | None:
    """Return a MAC in display form (aa:bb:cc:dd:ee:ff) when the text contains one."""
    for pattern in (_MAC_COLON, _MAC_DOTTED, _MAC_BARE):
        m = pattern.search(text or "")
        if not m:
            continue
        hexed = re.sub(r"[^0-9a-fA-F]", "", m.group(0)).lower()
        # A bare 12-digit decimal number is far more likely a ticket/phone number.
        if pattern is _MAC_BARE and not re.search(r"[a-f]", hexed):
            continue
        if len(hexed) == 12:
            return ":".join(hexed[i : i + 2] for i in range(0, 12, 2))
    return None


def find_ip(text: str) -> str | None:
    for m in _IPV4.finditer(text or ""):
        try:
            return str(ipaddress.ip_address(m.group(0)))
        except ValueError:
            continue
    for m in _IPV6.finditer(text or ""):
        candidate = m.group(0)
        if candidate.count(":") < 2 or _MAC_COLON.fullmatch(candidate):
            continue
        try:
            return str(ipaddress.ip_address(candidate))
        except ValueError:
            continue
    return None


def normalize(text: str) -> str:
    text = (text or "").lower().replace("’", "'")
    text = re.sub(r"[^a-z0-9]+", " ", text)
    return re.sub(r"\s+", " ", text).strip()


# Words that never identify a site or device on their own.
STOPWORDS = {
    "a",
    "about",
    "all",
    "an",
    "and",
    "any",
    "anything",
    "are",
    "at",
    "be",
    "broken",
    "by",
    "can",
    "check",
    "currently",
    "device",
    "devices",
    "do",
    "does",
    "doing",
    "down",
    "every",
    "everything",
    "find",
    "for",
    "from",
    "give",
    "going",
    "good",
    "has",
    "have",
    "health",
    "healthy",
    "how",
    "i",
    "in",
    "is",
    "issue",
    "issues",
    "it",
    "its",
    "last",
    "latest",
    "list",
    "locate",
    "look",
    "me",
    "my",
    "network",
    "now",
    "of",
    "offline",
    "ok",
    "okay",
    "on",
    "online",
    "or",
    "our",
    "please",
    "problem",
    "problems",
    "right",
    "s",
    "see",
    "show",
    "site",
    "sites",
    "so",
    "status",
    "tell",
    "that",
    "the",
    "there",
    "this",
    "to",
    "today",
    "up",
    "us",
    "what",
    "whats",
    "where",
    "wheres",
    "which",
    "who",
    "why",
    "with",
    "working",
    "wrong",
    "you",
    "any",
    "currently",
    "connected",
    "disconnected",
    "doing",
    "state",
    "fine",
    "location",
    "current",
    "look",
    "lookup",
    "search",
    "summary",
    "overview",
    "report",
    "happening",
    "on",
    "switch",
    "switches",
    "ap",
    "aps",
    "access",
    "point",
    "points",
    "gateway",
    "gateways",
    "client",
    "clients",
    "user",
    "port",
    "ports",
    "poe",
    "power",
    "alarm",
    "alarms",
    "alert",
    "alerts",
    "critical",
    "major",
    "warning",
    "warnings",
    "changes",
    "changed",
    "change",
    "recent",
    "recently",
    "virtual",
    "chassis",
    "vc",
    "top",
    "busiest",
    "worst",
    "most",
    "we",
    "got",
    "been",
    "were",
    "was",
    "hi",
    "hey",
    "hello",
    "thanks",
    "thank",
    "mist",
    "nodewatch",
    "again",
    "still",
    "wi",
    "fi",
    "wifi",
    "wireless",
    "internet",
    "lan",
    "wan",
    "wired",
    "anyone",
    "anybody",
    "something",
}

KIND_WORDS = {
    "switch": ("switch", "switches", "sw", "ex", "core switch", "access switch", "idf", "mdf"),
    "ap": ("ap", "aps", "access point", "access points", "wifi", "wi fi", "wireless", "radio", "radios"),
    "gateway": ("gateway", "gateways", "gw", "srx", "ssr", "wan edge", "wan", "firewall", "router", "routers"),
}


def _has_word(norm: str, *phrases: str) -> bool:
    padded = f" {norm} "
    return any(f" {p} " in padded for p in phrases)


def device_kind(norm: str) -> str | None:
    hits = [kind for kind, words in KIND_WORDS.items() if _has_word(norm, *words)]
    return hits[0] if len(hits) == 1 else None


_PORT_ID = re.compile(r"^(?:ge|xe|et|mge|ae|vcp|irb|fxp|em|me|xle|lt)-\d+(?:/\d+){0,2}(?:\.\d+)?$", re.IGNORECASE)
_UNIT = re.compile(
    r"^\d+(?:\.\d+)?(?:ghz|mhz|g|w|kw|mbps|gbps|kbps|m|h|d|hr|hrs|min|mins|s|x|am|pm|st|nd|rd|th)$", re.IGNORECASE
)
_COMMON_HYPHENATED = {
    "wi-fi",
    "e-mail",
    "check-in",
    "log-in",
    "sign-in",
    "up-to-date",
    "follow-up",
    "set-up",
    "re-check",
    "on-site",
    "off-site",
    "per-port",
    "802.1x",
    "dot1x",
    "real-time",
    "end-to-end",
    "built-in",
    "plug-in",
    "plugged-in",
}


def find_port_id(text: str) -> str | None:
    for token in _TOKEN.findall(text or ""):
        if _PORT_ID.match(token):
            return token.lower()
    return None


def looks_like_hostname(token: str) -> bool:
    """A token shaped like infrastructure/host naming (SW-CORE-01, ap12, lab.host)."""
    t = token.strip(".,?!:;()[]{}'\"")
    if len(t) < 3 or normalize(t) in STOPWORDS or t.lower() in _COMMON_HYPHENATED:
        return False
    if find_ip(t) or find_mac(t) or _PORT_ID.match(t) or _UNIT.match(t):
        return False
    has_alpha = any(c.isalpha() for c in t)
    has_digit = any(c.isdigit() for c in t)
    has_sep = any(c in "-_." for c in t.strip("-_."))
    if not has_alpha:
        return False
    if has_digit:
        return True
    return has_sep and len(t) >= 6


# --------------------------------------------------------------------------- fuzzy site matching


@dataclass
class SiteMatch:
    site_id: str
    name: str
    score: float
    ambiguous: list[dict] = field(default_factory=list)


def _similar(a: str, b: str) -> float:
    if a == b:
        return 1.0
    if len(a) >= 3 and b.startswith(a):
        return 0.92 if len(a) >= 4 else 0.85
    if len(a) < 4 or len(b) < 4:
        return 0.0
    ratio = SequenceMatcher(None, a, b).ratio()
    return ratio if ratio >= 0.8 else 0.0


def match_site(text: str, sites: Iterable[dict], *, exclude: Iterable[str] = ()) -> SiteMatch | None:
    """Typo-tolerant, partial-name site matcher.

    Each distinctive question word is compared with each site-name word (exact, prefix,
    or a close spelling). Words shared by many sites ("medical", "center") count for
    less than distinctive words ("dallas"), so "issues at dalas" finds "Dallas Medical
    Center". Ties are returned as ``ambiguous`` so the caller can ask which site.
    """
    sites = [s for s in sites if isinstance(s, dict) and s.get("name")]
    if not sites:
        return None
    excluded = {normalize(x) for x in exclude if x}
    q_norm = normalize(text)
    for ex in excluded:
        q_norm = re.sub(rf"\b{re.escape(ex)}\b", " ", q_norm)
    q_tokens = [t for t in q_norm.split() if t not in STOPWORDS and len(t) >= 2]
    if not q_tokens:
        return None
    site_tokens = {str(s.get("id")): normalize(str(s["name"])).split() for s in sites}
    df: dict[str, int] = {}
    for toks in site_tokens.values():
        for t in set(toks):
            df[t] = df.get(t, 0) + 1
    n = len(sites)

    def weight(tok: str) -> float:
        return math.log(1 + n / df.get(tok, 1)) + 0.15

    scored: list[tuple[float, float, dict]] = []
    padded_q = f" {q_norm} "
    for site in sites:
        sid = str(site.get("id"))
        toks = site_tokens[sid]
        full = " ".join(toks)
        if not toks:
            continue
        if full and f" {full} " in padded_q:
            scored.append((100.0 + len(full), 1.0, site))
            continue
        total_w = sum(weight(t) for t in toks)
        got = 0.0
        best_single = 0.0
        used: set[int] = set()
        for qt in q_tokens:
            best = (0.0, -1)
            for i, st in enumerate(toks):
                if i in used or (qt.isdigit() != st.isdigit()):
                    continue
                sim = _similar(qt, st)
                if sim > best[0]:
                    best = (sim, i)
            if best[1] >= 0:
                used.add(best[1])
                w = weight(toks[best[1]]) * best[0]
                got += w
                best_single = max(best_single, w)
        if got <= 0:
            continue
        coverage = got / total_w
        # Require at least one distinctive word, or most of the name.
        distinctive = best_single >= 0.6 * max(weight(t) for t in toks)
        if not distinctive and coverage < 0.6:
            continue
        scored.append((got + coverage, coverage, site))
    if not scored:
        return None
    scored.sort(key=lambda x: (-x[0], str(x[2].get("name"))))
    top = scored[0]
    ties = [s for s in scored[1:] if abs(s[0] - top[0]) < 0.05]
    match = SiteMatch(site_id=str(top[2].get("id") or ""), name=str(top[2].get("name")), score=top[0])
    if ties:
        match.ambiguous = [{"id": str(top[2].get("id")), "name": str(top[2]["name"])}] + [
            {"id": str(s[2].get("id")), "name": str(s[2]["name"])} for s in ties[:4]
        ]
    return match


def match_name(token: str, names: Iterable[str], *, cutoff: float = 0.86) -> str | None:
    """Best case-insensitive (typo-tolerant) match for a device name."""
    want = normalize(token).replace(" ", "")
    if len(want) < 3:
        return None
    best: tuple[float, str] | None = None
    for name in names:
        have = normalize(name).replace(" ", "")
        if not have:
            continue
        if have == want:
            return name
        ratio = SequenceMatcher(None, want, have).ratio()
        if ratio >= cutoff and (best is None or ratio > best[0]):
            best = (ratio, name)
    return best[1] if best else None


# --------------------------------------------------------------------------- intents

INTENTS = (
    "help",
    "summary",
    "site_status",
    "down",
    "locate",
    "changes",
    "poe",
    "ports",
    "vc",
    "top",
    "alarms",
    "firmware",
    "security",
    "traffic",
    "unknown",
)


@dataclass
class Intent:
    name: str
    question: str
    target: str | None = None
    target_kind: str | None = None  # mac | ip | name | text
    site: SiteMatch | None = None
    device_kind: str | None = None
    duration: str = "1d"
    port_id: str | None = None
    notes: list[str] = field(default_factory=list)

    @property
    def site_id(self) -> str | None:
        return self.site.site_id if self.site else None

    @property
    def site_name(self) -> str | None:
        return self.site.name if self.site else None


_LOCATE_PATTERNS = (
    re.compile(
        r"\b(?:where(?:'s| is| are)?|find|locate|look ?up|search(?: for)?|track(?: down)?|status of|state of|"
        r"details (?:for|on|of)|info (?:on|for|about)|tell me about|check(?: on)?)\s+(?P<t>.+)$"
    ),
    re.compile(
        r"^(?:is|are|can you see)\s+(?P<t>.+?)\s+(?:up|down|online|offline|connected|disconnected|"
        r"reachable|working|alive|ok|okay|healthy)\b"
    ),
    re.compile(r"^(?:is|are)\s+(?P<t>.+?)\s*\??$"),
)
_TARGET_TRAILERS = re.compile(
    r"\s+(?:up|down|online|offline|connected|disconnected|reachable|working|alive|ok|okay|healthy|"
    r"right now|now|currently|today|at|in|on|connected to|plugged into)\b.*$"
)
_TARGET_LEADERS = re.compile(
    r"^(?:the|a|an|my|our|device|client|host|hostname|switch|ap|access point|gateway|user|laptop|computer|"
    r"mac|ip|address|mac address|ip address)\s+"
)


def _clean_target(raw: str) -> str:
    t = raw.strip().strip("?.!,;:").strip()
    t = _TARGET_TRAILERS.sub("", t)
    for _ in range(3):
        t = _TARGET_LEADERS.sub("", t.lower() if t.islower() else t)
    return t.strip().strip("?.!,;:'\"").strip()


def _target_from_question(q: str) -> tuple[str | None, str | None]:
    mac = find_mac(q)
    if mac:
        return mac, "mac"
    ip = find_ip(q)
    if ip:
        return ip, "ip"
    quoted = _QUOTED.search(q)
    if quoted and len(quoted.group(1).strip()) >= 2:
        return quoted.group(1).strip(), "name"
    for token in _TOKEN.findall(q):
        if looks_like_hostname(token):
            return token.strip(".-_/"), "name"
    return None, None


_HELP = re.compile(
    r"^(?:hi |hey |hello |please )?(?:help(?: me)?$|help with|examples?$|show (?:me )?examples|give me examples|"
    r"commands$|what can (?:you|i) (?:do|ask)|what do you do|how do i use|how does this work)"
)


def _duration(norm: str) -> str:
    if _has_word(norm, "last hour", "past hour", "this hour", "60 minutes", "hour"):
        return "1h"
    if _has_word(norm, "this week", "last week", "past week", "7 days", "week", "seven days"):
        return "7d"
    if _has_word(norm, "this month", "30 days", "month"):
        return "30d"
    if _has_word(norm, "yesterday", "2 days", "two days"):
        return "2d"
    return "1d"


def _any(norm: str, *phrases: str) -> bool:
    return _has_word(norm, *phrases)


def parse(
    question: str,
    sites: Iterable[dict] = (),
    device_names: Callable[[], Iterable[str]] | Iterable[str] | None = None,
) -> Intent:
    q = (question or "").strip()
    norm = normalize(q)
    intent = Intent(name="unknown", question=q, duration=_duration(norm))
    sites = list(sites or [])
    if len(norm) < 2:
        intent.name = "help"
        return intent
    # Only an actual request for help: "Example Medical Center" must not trigger it.
    if _HELP.search(norm) and len(norm.split()) <= 7:
        intent.name = "help"
        return intent

    intent.device_kind = device_kind(norm)
    target, target_kind = _target_from_question(q)

    # A free-text "where is X" / "is X up" target (hostname without digits, a person's laptop name).
    phrase_target = None
    low = q.lower().replace("’", "'")
    for pattern in _LOCATE_PATTERNS:
        m = pattern.search(low.strip())
        if m:
            cleaned = _clean_target(m.group("t"))
            words = normalize(cleaned).split()
            if words and any(w not in STOPWORDS for w in words) and len(normalize(cleaned)) >= 2:
                phrase_target = cleaned
            break

    def resolve_site(*, exclude: Iterable[str] = ()) -> SiteMatch | None:
        return match_site(q, sites, exclude=exclude)

    exclude = [target] if target else []
    intent.site = resolve_site(exclude=exclude)

    cache: dict[str, list[str]] = {}

    def names() -> list[str]:
        if "names" not in cache:
            values = device_names() if callable(device_names) else (device_names or [])
            cache["names"] = [str(x) for x in values if x]
        return cache["names"]

    # "issues at DAL01": a hostname-shaped word that is really a site name.
    if target_kind == "name" and target:
        as_site = match_site(target, sites)
        squash = normalize(target).replace(" ", "")
        if as_site and (as_site.score >= 100 or normalize(as_site.name).replace(" ", "") == squash):
            exact_device = any(normalize(n).replace(" ", "") == squash for n in names())
            if not exact_device:
                intent.site = as_site
                target, target_kind = None, None
    intent.port_id = find_port_id(q)

    # ---- explicit keyword intents, most specific first
    if target_kind == "ip" and _any(
        norm, "traffic", "session", "sessions", "firewall", "application", "applications", "flows", "flow"
    ):
        intent.name, intent.target, intent.target_kind = "traffic", target, target_kind
        return intent

    if _any(
        norm,
        "what changed",
        "changed",
        "changes",
        "change",
        "audit",
        "audit log",
        "audit logs",
        "who changed",
        "who modified",
        "modified",
        "config change",
        "configuration change",
        "who did",
        "what did",
        "recent activity",
        "activity",
    ) and not _any(norm, "port change", "change port"):
        intent.name = "changes"
        return intent

    if _any(norm, "virtual chassis", "vc", "vcs", "chassis", "vc members", "vc member", "stack", "stacks", "stacking"):
        intent.name = "vc"
        return intent

    if _any(
        norm, "poe", "power over ethernet", "power draw", "power budget", "powered", "power usage", "watts", "wattage"
    ):
        intent.name = "poe"
        if target_kind == "name":
            intent.target, intent.target_kind = target, target_kind
        else:
            found = _switch_name_in(q, names())
            if found:
                intent.target, intent.target_kind = found, "name"
        return intent

    if _any(norm, "ports", "port", "interfaces", "interface") and not target_kind == "mac":
        intent.name = "ports"
        if target_kind in {"name", "ip"}:
            intent.target, intent.target_kind = target, target_kind
        else:
            found = _switch_name_in(q, names())
            if found:
                intent.target, intent.target_kind = found, "name"
        return intent

    if _any(
        norm,
        "top problems",
        "top issues",
        "biggest problems",
        "worst sites",
        "worst site",
        "busiest sites",
        "busiest site",
        "most issues",
        "most problems",
        "most alarms",
        "noisiest",
        "top sites",
        "rank",
        "ranking",
        "which sites",
        "which site",
        "problem sites",
        "unhealthy sites",
        "top 5",
        "top five",
        "top 10",
    ):
        intent.name = "top"
        return intent

    if _any(norm, "firmware", "version", "versions", "software", "junos", "code version", "upgrade", "upgrades"):
        intent.name = "firmware"
        return intent

    if _any(norm, "security", "rogue", "rogues", "nac", "802 1x", "dot1x", "radius", "denied", "denials", "honeypot"):
        intent.name = "security"
        return intent

    down_words = _any(
        norm,
        "down",
        "offline",
        "disconnected",
        "unreachable",
        "not connected",
        "dead",
        "lost",
        "outage",
        "outages",
        "not responding",
        "dropped",
    )
    up_words = _any(norm, "up", "online", "connected", "reachable", "alive", "working", "healthy", "ok", "okay")

    if target:
        intent.name, intent.target, intent.target_kind = "locate", target, target_kind
        if intent.port_id and target_kind == "name":
            intent.name = "ports"
        return intent

    # "where is jdoe laptop" / "is printer2 up" with a free-text target.
    if phrase_target:
        site_from_phrase = match_site(phrase_target, sites)
        known = match_name(phrase_target, names())
        if known:
            intent.name, intent.target, intent.target_kind = "locate", known, "name"
            return intent
        if site_from_phrase and not looks_like_hostname(phrase_target):
            intent.site = site_from_phrase
            intent.name = "down" if down_words and not up_words else "site_status"
            return intent
        if not (down_words and _any(norm, "what", "which", "anything", "any", "everything", "who")):
            intent.name, intent.target, intent.target_kind = "locate", phrase_target, "text"
            return intent

    if down_words or _any(norm, "which switches", "which aps", "which gateways"):
        intent.name = "down"
        return intent

    if _any(norm, "alarm", "alarms", "alert", "alerts", "critical", "major", "warnings", "events", "event"):
        intent.name = "alarms"
        return intent

    summaryish = _any(
        norm,
        "broken",
        "wrong",
        "issue",
        "issues",
        "problem",
        "problems",
        "status",
        "health",
        "healthy",
        "overview",
        "summary",
        "going on",
        "happening",
        "attention",
        "how is",
        "how s",
        "hows",
        "how are",
        "doing",
        "ok",
        "okay",
        "fine",
        "trouble",
        "errors",
        "error",
        "failing",
        "fail",
        "failed",
        "report",
        "anything",
        "situation",
        "everything",
        "good",
        "bad",
    )
    if intent.site:
        intent.name = "site_status"
        return intent
    if summaryish:
        intent.name = "summary"
        return intent

    # Last resort: a bare device name ("SWCORE1") or site ("dallas").
    tokens = [t for t in _TOKEN.findall(q) if normalize(t) not in STOPWORDS]
    for token in tokens:
        known = match_name(token, names())
        if known:
            intent.name, intent.target, intent.target_kind = "locate", known, "name"
            return intent
    return intent


def _switch_name_in(question: str, names: list[str]) -> str | None:
    tokens = [t for t in _TOKEN.findall(question) if normalize(t) not in STOPWORDS and len(t) >= 3]
    for token in tokens:
        known = match_name(token, names)
        if known:
            return known
    return None
