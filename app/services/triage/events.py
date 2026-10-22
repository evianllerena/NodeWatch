"""Triage events: the only thing a triage store ever writes (v0.10.18).

Every triage action — acknowledge, snooze, dismiss, mute, note, assign and their undos — is one small,
self-describing, append-only event::

    {
      "id": "6f1c…",                     # uuid4 hex, globally unique (dedupe key)
      "ts": 1760000000.123,              # epoch seconds (hybrid clock, see TriageStoreFacade)
      "seq": 42,                         # per-writer counter (tie-break only)
      "actor": {"user": "jdoe", "display": "Jane Doe", "machine": "NOC-PC-07"},
      "action": "snooze",                # one of ACTIONS
      "target_kind": "alert",            # alert | incident | mute
      "target": "<alert key>",           # alert key, incident id or mute rule id
      "targets": ["<key>", …],           # optional: the same action on many alerts (≤ MAX_TARGETS)
      "fields": {"until": …, "duration": "1h"},
      "context": {"title": "…", "type": "…", "source": "mist", "site_name": "…", "device_name": "…"},
      "source_vendor": "mist",
      "version": 1
    }

Events never carry secrets: only names, alert keys and the user's own short texts. Everything is
validated and bounded here — on write strictly (a bad event is a programming error), on read leniently
(unknown fields from a newer NodeWatch are dropped, damaged events are skipped and counted).
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import unicodedata
import time
import uuid
from typing import Any

SCHEMA_VERSION = 1
ACTIONS = (
    "ack",
    "unack",
    "snooze",
    "unsnooze",
    "dismiss",
    "restore",
    "mute",
    "unmute",
    "note",
    "assign",
    "unassign",
)
STATE_ACTIONS = {"ack": "acknowledged", "snooze": "snoozed", "dismiss": "dismissed"}
CLEAR_ACTIONS = ("unack", "unsnooze", "restore")
TARGET_KINDS = ("alert", "incident", "mute")
DURATIONS = ("", "1h", "4h", "24h", "change")
MAX_SKEW_S = 300.0  # events stamped further in the future than this are rejected
MAX_TARGETS = 2000  # alert keys per event; bigger actions are split into several events
MAX_LINE_BYTES = 64 * 1024  # one serialized event (with 2000 targets ≈ 46 KB)
MAX_FUTURE_UNTIL_S = 2 * 366 * 24 * 3600

_KEY_RE = re.compile(r"^[A-Za-z0-9:_.\-]{1,128}$")
_ID_RE = re.compile(r"^[A-Za-z0-9\-]{8,64}$")
_NAME_RE = re.compile(r"[^A-Za-z0-9._\-]")
_CTRL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")

# field name -> (kind, max length / enum)
FIELD_SPEC: dict[str, tuple[str, Any]] = {
    "until": ("epoch", None),
    "until_change": ("str", 64),
    "duration": ("enum", DURATIONS),
    "reason": ("str", 200),
    "note": ("text", 1000),
    "assignee": ("str", 80),
    "via": ("str", 60),  # "in Mist", "NodeWatch" … how an acknowledgement was made
    # mute rule
    "type": ("str", 120),
    "label": ("str", 120),
    "source": ("str", 40),
    "site_key": ("str", 64),
    "site_name": ("str", 120),
    # provenance flags
    "migrated": ("bool", None),
    "copied": ("bool", None),
}
CONTEXT_SPEC = {"title": 200, "type": 120, "source": 40, "site_name": 120, "device_name": 120}
ACTOR_SPEC = {"user": 64, "display": 80, "machine": 64}


class EventError(ValueError):
    """An event failed validation."""


def clean_text(value: Any, limit: int, *, multiline: bool = False) -> str:
    # v0.10.22: NFKC-normalise and drop invisible format characters (zero-width spaces, joiners,
    # direction marks) so "a\u200blice" cannot pass for "alice" in names, notes and assignees.
    text = unicodedata.normalize("NFKC", str(value if value is not None else ""))
    text = "".join(ch for ch in text if unicodedata.category(ch) != "Cf")
    if multiline:
        text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = _CTRL_RE.sub("", text) if multiline else _CTRL_RE.sub("", text.replace("\n", " ").replace("\t", " "))
    return text.strip()[:limit]


def safe_name(value: Any, limit: int = 64) -> str:
    """Windows user / machine name → file-name-safe token (letters, digits, '.', '_', '-')."""
    out = _NAME_RE.sub("_", str(value or "").strip())[:limit].strip("._-")
    return out or "unknown"


WRITER_SEP = "~"  # never produced by safe_name, so "<machine>~<user>" splits unambiguously


def writer_id(actor: dict) -> str:
    """The log file stem one actor writes to: ``<machine>~<user>`` (lower case, file-name safe)."""
    return f"{safe_name(actor.get('machine'))}{WRITER_SEP}{safe_name(actor.get('user'))}".lower()


# Cyrillic and Greek letters that render like Latin ones (the common spoofing set).
_CONFUSABLE = str.maketrans(
    "аеорсухіјѕԁԛԝАВЕКМНОРСТХІЈЅαοτνυικΑΒΕΖΗΙΚΜΝΟΡΤΥΧ",
    "aeopcyxijsdqwABEKMHOPCTXIJSaotvuikABEZHIKMNOPTYX",
)


def name_skeleton(value: Any) -> str:
    """Lower-case look-alike form of a name: NFKC, accents dropped, Cyrillic/Greek look-alikes mapped."""
    text = unicodedata.normalize("NFKD", str(value or ""))
    text = "".join(ch for ch in text if not unicodedata.combining(ch) and unicodedata.category(ch) != "Cf")
    return text.translate(_CONFUSABLE).casefold().strip()


def writer_matches(actor: dict, writer: str) -> bool:
    """True when ``writer`` (a log file stem) belongs to ``actor``.

    Only ``<machine>~<user>`` stems match (v0.10.22). Pre-release ``<machine>-<user>`` stems are
    refused: no current client writes them, so any such file was created by someone else.
    """
    return WRITER_SEP in writer and writer == writer_id(actor)


def ident(actor: dict) -> str:
    """``user@machine`` — always shown next to a display name (display names are free text)."""
    return f"{actor.get('user', '')}@{actor.get('machine', '')}"


def content_hash(event: dict) -> str:
    """Deterministic fingerprint of an event's content (tie-break between same-id copies)."""
    return hashlib.sha256(
        json.dumps(event, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str).encode("utf-8")
    ).hexdigest()


def _clean_actor(raw: Any, strict: bool) -> dict:
    if not isinstance(raw, dict):
        raise EventError("actor must be an object")
    out = {}
    for k, limit in ACTOR_SPEC.items():
        v = clean_text(raw.get(k), limit)
        if k in {"user", "machine"}:
            if not v:
                raise EventError(f"actor.{k} is required")
            if strict and len(str(raw.get(k))) > limit:
                raise EventError(f"actor.{k} is too long")
        out[k] = v
    out["display"] = out["display"] or out["user"]
    return out


def _clean_field(name: str, value: Any, ref: float, strict: bool) -> Any:
    # ``ref`` is the event's own timestamp, never the reader's clock: every PC accepts the same events.
    kind, arg = FIELD_SPEC[name]
    if kind == "epoch":
        if value in (None, ""):
            return None
        if isinstance(value, bool):
            raise EventError(f"{name} must be a time")
        try:
            v = float(value)
        except (TypeError, ValueError) as exc:
            raise EventError(f"{name} must be a time") from exc
        if not math.isfinite(v) or v <= 0 or v > ref + MAX_FUTURE_UNTIL_S:
            raise EventError(f"{name} is out of range")
        return v
    if kind == "bool":
        return bool(value)
    if kind == "enum":
        v = str(value or "")
        if v not in arg:
            raise EventError(f"{name} must be one of {', '.join(x or '(empty)' for x in arg)}")
        return v
    if not isinstance(value, (str, int, float)) or isinstance(value, bool):
        if value is None:
            return ""
        raise EventError(f"{name} must be text")
    v = clean_text(value, arg, multiline=kind == "text")
    if strict and len(str(value).strip()) > arg:
        raise EventError(f"{name} is too long ({arg} characters max)")
    return v


def validate_event(raw: Any, *, now: float | None = None, strict: bool = True) -> dict:
    """Return a clean copy of ``raw`` or raise :class:`EventError`.

    ``strict`` (writing): unknown fields, over-long text and bad types are errors. Lenient (reading
    another user's log, maybe from a newer NodeWatch): unknown fields are dropped and text is cut to
    size, but structural problems (bad id, action, target, actor, time from the future) still reject.
    """
    now = time.time() if now is None else now
    if not isinstance(raw, dict):
        raise EventError("event must be an object")
    eid = str(raw.get("id") or "")
    if not _ID_RE.match(eid):
        raise EventError("bad event id")
    try:
        ts = float(raw.get("ts"))
    except (TypeError, ValueError) as exc:
        raise EventError("bad timestamp") from exc
    if not math.isfinite(ts) or ts <= 0:
        raise EventError("bad timestamp")
    if ts > now + MAX_SKEW_S:
        raise EventError("timestamp is in the future (clock skew beyond tolerance)")
    seq = raw.get("seq", 0)
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0 or seq > 10**12:
        raise EventError("bad seq")
    action = str(raw.get("action") or "")
    if action not in ACTIONS:
        raise EventError(f"unknown action {action!r}")
    kind = str(raw.get("target_kind") or "alert")
    if kind not in TARGET_KINDS:
        raise EventError("bad target_kind")
    if action in {"mute", "unmute"} and kind != "mute":
        raise EventError("mute events must target a mute rule")
    if kind == "mute" and action not in {"mute", "unmute"}:
        raise EventError("only mute/unmute may target a mute rule")
    if kind == "incident" and action != "note":
        raise EventError("only notes may target an incident")
    target = str(raw.get("target") or "")
    if not _KEY_RE.match(target):
        raise EventError("bad target")
    targets_raw = raw.get("targets") or []
    if not isinstance(targets_raw, list):
        raise EventError("targets must be a list")
    if len(targets_raw) > MAX_TARGETS:
        raise EventError(f"too many targets ({MAX_TARGETS} max per event)")
    targets = []
    for t in targets_raw:
        t = str(t or "")
        if not _KEY_RE.match(t):
            raise EventError("bad target in targets")
        targets.append(t)
    fields_raw = raw.get("fields") or {}
    if not isinstance(fields_raw, dict):
        raise EventError("fields must be an object")
    fields = {}
    for name, value in fields_raw.items():
        if name not in FIELD_SPEC:
            if strict:
                raise EventError(f"unknown field {name!r}")
            continue
        fields[name] = _clean_field(name, value, ts, strict)
    if action == "note" and not fields.get("note"):
        raise EventError("a note needs text")
    if action == "assign" and not fields.get("assignee"):
        raise EventError("assign needs an assignee")
    if action == "dismiss" and not fields.get("reason"):
        raise EventError("dismiss needs a reason")
    ctx_raw = raw.get("context") or {}
    if not isinstance(ctx_raw, dict):
        raise EventError("context must be an object")
    context = {k: clean_text(ctx_raw.get(k), n) for k, n in CONTEXT_SPEC.items() if ctx_raw.get(k)}
    if strict and set(ctx_raw) - set(CONTEXT_SPEC):
        raise EventError("unknown context field")
    version = raw.get("version", SCHEMA_VERSION)
    if isinstance(version, bool) or not isinstance(version, int) or version < 1:
        raise EventError("bad version")
    return {
        "id": eid,
        "ts": round(ts, 6),
        "seq": seq,
        "actor": _clean_actor(raw.get("actor"), strict),
        "action": action,
        "target_kind": kind,
        "target": target,
        "targets": targets,
        "fields": fields,
        "context": context,
        "source_vendor": clean_text(raw.get("source_vendor"), 40),
        "version": version,
    }


def new_event(
    action: str,
    target: str,
    *,
    actor: dict,
    ts: float,
    seq: int,
    target_kind: str = "alert",
    targets: list[str] | None = None,
    fields: dict | None = None,
    context: dict | None = None,
    source_vendor: str = "",
) -> dict:
    """Build and strictly validate a new event."""
    return validate_event(
        {
            "id": uuid.uuid4().hex,
            "ts": ts,
            "seq": seq,
            "actor": actor,
            "action": action,
            "target_kind": target_kind,
            "target": target,
            "targets": list(targets or []),
            "fields": {k: v for k, v in (fields or {}).items() if v not in (None, "")},
            "context": {k: v for k, v in (context or {}).items() if v},
            "source_vendor": source_vendor,
            "version": SCHEMA_VERSION,
        },
        now=time.time(),
    )


def order_key(event: dict) -> tuple:
    """Total, deterministic order used for last-writer-wins: (ts, user, machine, seq, id)."""
    a = event.get("actor") or {}
    return (
        float(event.get("ts") or 0),
        str(a.get("user", "")).lower(),
        str(a.get("machine", "")).lower(),
        int(event.get("seq") or 0),
        str(event.get("id", "")),
    )


def event_keys(event: dict) -> list[str]:
    """Every alert key / incident id / mute id this event is about (target first, no duplicates)."""
    return list(dict.fromkeys([event["target"], *event.get("targets", [])]))
