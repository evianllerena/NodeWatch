"""Config Backups: a configuration safety net for a Mist organisation.

* Snapshots capture org objects (settings, WLANs, templates, profiles, networks, NAC
  rules…) plus site settings, site WLANs and every device's configuration.
* Snapshots are redacted (PSKs, RADIUS secrets, passwords and tokens are replaced by
  a short keyed fingerprint), gzip-compressed and encrypted for the current user (Windows DPAPI;
  on macOS a data key kept in the login keychain, app/core/local_protect.py).
* "What changed" compares any two snapshots (or a snapshot and live Mist) with a
  readable, path-level diff, correlated with Mist audit logs to show who changed it.
* Restore re-reads live Mist, keeps live secrets in place of redacted ones, needs
  ``confirmed is True`` and writes an AuditService record (same pattern as Port Toolkit).

Other tools call :func:`snapshot_before_change` before they write to Mist.
"""

from __future__ import annotations

import base64
import ctypes
import gzip
import hashlib
import io
import json
import math
import os
import re
import secrets
import threading
import time
import logging
import zipfile
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from ctypes import wintypes
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from app.core.auth import CONFIG_RESTORE, require
from app.modules.system.presence import holds_exit
from app.core import local_protect
from app.core.config import BACKUP_ROOT
from app.core.file_utils import locked_json_update, read_json, write_private_text
from app.core.security import redact_text
from app.core.volatile_fields import is_volatile_key, redact_signed_urls
from app.modules.config_backup.engine import (
    diff_config,
    fill_redacted,
    is_redacted,
    redact_config,
    template_overrides,
)
from app.services.audit_service import AuditService
from app.services.mist_client import _UUID, _path_id, get_mist_client
from app.services.validation_service import run_validation

try:
    from app.modules.history.activity import parse_audit_message
except Exception:  # pragma: no cover

    def parse_audit_message(message: Any) -> dict:
        return {"action": "", "object_type": "", "object_name": "", "kind": "neutral"}


POLICY_PATH = BACKUP_ROOT / "policy.json"
INDEX_PATH = BACKUP_ROOT / "index.json"
SNAP_DIR = BACKUP_ROOT / "snapshots"
KEY_PATH = BACKUP_ROOT / ".fingerprint-key"
SNAP_EXT = ".nwsnap"
FORMAT = "nodewatch-config-snapshot/2"
_DPAPI_MAGIC = b"NWDP1"
_GZIP_MAGIC = b"\x1f\x8b"
_LOG = logging.getLogger("nodewatch.backup")
_ID_RE = re.compile(r"^\d{8}T\d{6}Z-[a-z-]{2,20}-[0-9a-f]{6}$")
MAX_IMPORT_BYTES = 50 * 1024 * 1024

_SCHEDULER_STOP = threading.Event()
_SCHEDULER_THREAD: threading.Thread | None = None
_LIVE_CACHE: dict[str, tuple[float, dict]] = {}
_LIVE_TTL = 120.0
_LIVE_LOCK = threading.Lock()

# Fields Mist manages itself. They are never written back and never count as drift.
READ_ONLY_KEYS = {
    "id",
    "org_id",
    "site_id",
    "mac",
    "serial",
    "model",
    "type",
    "status",
    "version",
    "last_seen",
    "connected",
    "uptime",
    "modified_time",
    "created_time",
    "hw_rev",
    "sku",
    "vc_mac",
    "for_site",
    "msp_id",
    # Set by Mist itself (uploaded images, asset tags, EVPN topology membership).
    "image1_url",
    "image2_url",
    "image3_url",
    "tag_uuid",
    "tag_id",
    "evpntopo_id",
    "deviceprofile_name",
}

# kind → (label, org path suffix or site path suffix, is_list, restore support)
ORG_COLLECTIONS: list[tuple[str, str, str, bool]] = [
    ("org", "Organization", "", False),
    ("org_setting", "Org settings", "/setting", False),
    ("org_wlan", "WLAN", "/wlans", True),
    ("wlantemplate", "WLAN template", "/templates", True),
    ("networktemplate", "Switch template", "/networktemplates", True),
    ("gatewaytemplate", "WAN Edge template", "/gatewaytemplates", True),
    ("sitetemplate", "Site template", "/sitetemplates", True),
    ("deviceprofile", "Device profile", "/deviceprofiles", True),
    ("rftemplate", "RF template", "/rftemplates", True),
    ("network", "Network", "/networks", True),
    ("service", "Application", "/services", True),
    ("servicepolicy", "Service policy", "/servicepolicies", True),
    ("nacrule", "NAC rule", "/nacrules", True),
    ("nactag", "NAC label", "/nactags", True),
    ("sitegroup", "Site group", "/sitegroups", True),
    ("alarmtemplate", "Alarm template", "/alarmtemplates", True),
]
SITE_COLLECTIONS: list[tuple[str, str, str, bool]] = [
    ("site", "Site", "", False),
    ("site_setting", "Site settings", "/setting", False),
    ("site_wlan", "WLAN", "/wlans", True),
]
KIND_LABELS = {k: label for k, label, _, _ in ORG_COLLECTIONS + SITE_COLLECTIONS}
KIND_LABELS.update({"device": "Device", "switch": "Switch", "ap": "Access point", "gateway": "WAN Edge"})
_ORG_PATHS = {k: suffix for k, _, suffix, _ in ORG_COLLECTIONS}
_SITE_PATHS = {k: suffix for k, _, suffix, _ in SITE_COLLECTIONS}
KIND_ORDER = (
    ["org", "org_setting", "site", "site_setting", "device"]
    + [k for k, *_ in ORG_COLLECTIONS if k not in {"org", "org_setting"}]
    + ["site_wlan"]
)
# Restore is offered for these kinds (when the object still exists in Mist).
RESTORABLE = {"device", "site", "site_setting", "site_wlan", "org_setting"} | {
    k for k, _, _, is_list in ORG_COLLECTIONS if is_list
}


# =========================================================================== policy


def _default_policy() -> dict:
    return {
        "retention_days": 30,
        "keep_min": 5,
        "max_snapshots": 300,
        "daily_enabled": True,
        "interval_hours": 24,
        "pre_change_enabled": True,
        "site_ids": [],  # empty = every site
        "last_daily": None,
        "last_daily_error": None,
    }


def get_policy() -> dict:
    policy = _default_policy()
    data = read_json(POLICY_PATH, {})
    if isinstance(data, dict):
        policy.update({k: v for k, v in data.items() if k in policy})
    return _normalise_policy(policy)


def _normalise_policy(p: dict) -> dict:
    p["retention_days"] = max(1, min(3650, int(p.get("retention_days") or 30)))
    p["keep_min"] = max(1, min(100, int(p.get("keep_min") or 5)))
    p["max_snapshots"] = max(10, min(5000, int(p.get("max_snapshots") or 300)))
    p["interval_hours"] = max(1, min(168, int(p.get("interval_hours") or 24)))
    p["daily_enabled"] = bool(p.get("daily_enabled"))
    p["pre_change_enabled"] = bool(p.get("pre_change_enabled"))
    ids = p.get("site_ids") or []
    p["site_ids"] = [str(x) for x in ids if str(x).strip()] if isinstance(ids, list) else []
    return p


def save_policy(payload: dict) -> dict:
    payload = payload if isinstance(payload, dict) else {}

    def update(current):
        merged = _default_policy()
        if isinstance(current, dict):
            merged.update({k: v for k, v in current.items() if k in merged})
        for key in ("retention_days", "keep_min", "max_snapshots", "interval_hours", "site_ids"):
            if key in payload:
                merged[key] = payload[key]
        for key in ("daily_enabled", "pre_change_enabled"):
            if key in payload:
                merged[key] = payload[key] is True
        return _normalise_policy(merged)

    BACKUP_ROOT.mkdir(parents=True, exist_ok=True)
    policy = locked_json_update(POLICY_PATH, update, default={})
    prune()
    return policy


def _mark_daily(ok: bool, error: str | None = None) -> None:
    def update(current):
        merged = _default_policy()
        if isinstance(current, dict):
            merged.update({k: v for k, v in current.items() if k in merged})
        if ok:
            merged["last_daily"] = datetime.now(timezone.utc).isoformat()
            merged["last_daily_error"] = None
        else:
            merged["last_daily_error"] = error
        return merged

    locked_json_update(POLICY_PATH, update, default={})


# =========================================================================== storage


_KEY_DPAPI_PREFIX = "dpapi:"


_KEY_MAC_PREFIX = "keychain:"


def _platform_protect_available() -> bool:
    return os.name == "nt" or local_protect.available()


def _save_fingerprint_key(key: bytes) -> None:
    """Store the key DPAPI-protected on Windows (v0.10.22) and encrypted with the Keychain-held data
    key on macOS; plain hex only where neither is available."""
    text = key.hex()
    if os.name == "nt":
        try:
            text = _KEY_DPAPI_PREFIX + base64.b64encode(_dpapi(key, True)).decode("ascii")
        except Exception as exc:  # noqa: BLE001
            _LOG.warning("DPAPI unavailable; fingerprint key stored unprotected: %s", redact_text(exc))
    elif local_protect.available():
        try:
            text = _KEY_MAC_PREFIX + base64.b64encode(local_protect.protect(key)).decode("ascii")
        except Exception as exc:  # noqa: BLE001
            _LOG.warning("Keychain unavailable; fingerprint key stored unprotected: %s", redact_text(exc))
    write_private_text(KEY_PATH, text, encoding="ascii")


def _fingerprint_key() -> bytes:
    """Per-install key for secret fingerprints (so equal PSKs in two orgs never match).

    With the key and a snapshot, low-entropy PSKs could be guessed offline against their
    fingerprints, so the key is kept DPAPI-protected like the snapshots. A legacy plain-hex
    key is upgraded in place on first use.
    """
    try:
        raw = KEY_PATH.read_text(encoding="ascii").strip()
    except OSError:
        raw = ""
    if raw.startswith(_KEY_DPAPI_PREFIX):
        # Never replace a protected key that cannot be opened right now: a new key would
        # silently break secret refill for every existing snapshot.
        return _dpapi(base64.b64decode(raw[len(_KEY_DPAPI_PREFIX) :]), False)
    if raw.startswith(_KEY_MAC_PREFIX):
        return local_protect.unprotect(base64.b64decode(raw[len(_KEY_MAC_PREFIX) :]))
    try:
        if raw:
            key = bytes.fromhex(raw)
            if _platform_protect_available():
                _save_fingerprint_key(key)
            return key
    except (OSError, ValueError):
        pass
    key = secrets.token_bytes(32)
    _save_fingerprint_key(key)
    return key


class DATA_BLOB(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_byte))]


def _dpapi(raw: bytes, protect: bool) -> bytes:
    crypt32 = ctypes.windll.crypt32  # type: ignore[attr-defined]
    kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
    buf = ctypes.create_string_buffer(raw, len(raw))
    inb = DATA_BLOB(len(raw), ctypes.cast(buf, ctypes.POINTER(ctypes.c_byte)))
    out = DATA_BLOB()
    fn = crypt32.CryptProtectData if protect else crypt32.CryptUnprotectData
    args = (ctypes.byref(inb), "NodeWatch backup" if protect else None, None, None, None, 0x01, ctypes.byref(out))
    if not fn(*args):
        raise ctypes.WinError()  # type: ignore[attr-defined]
    try:
        return ctypes.string_at(out.pbData, out.cbData)
    finally:
        kernel32.LocalFree(out.pbData)


def _encode(snapshot: dict) -> bytes:
    raw = gzip.compress(json.dumps(snapshot, separators=(",", ":"), default=str).encode("utf-8"), compresslevel=6)
    if os.name == "nt":
        try:
            return _DPAPI_MAGIC + _dpapi(raw, True)
        except Exception as exc:  # noqa: BLE001 - keep the backup, but never claim it is encrypted
            _LOG.warning(
                "DPAPI encryption failed; snapshot %s stored unencrypted: %s", snapshot.get("id"), redact_text(exc)
            )
            return raw
    if local_protect.available():
        try:
            return local_protect.protect(raw)
        except Exception as exc:  # noqa: BLE001 - keep the backup, but never claim it is encrypted
            _LOG.warning(
                "Keychain encryption failed; snapshot %s stored unencrypted: %s", snapshot.get("id"), redact_text(exc)
            )
            return raw
    return raw


def _is_encrypted(blob: bytes) -> bool:
    """The real outcome of _encode (v0.10.22): metadata used to claim encryption on every Windows PC."""
    return blob.startswith(_DPAPI_MAGIC) or local_protect.is_protected(blob)


def _gunzip_bounded(raw: bytes, limit: int) -> bytes:
    """gzip.decompress with an output budget (v0.10.22): a 50 MB upload must not expand to GBs."""
    out = bytearray()
    with gzip.GzipFile(fileobj=io.BytesIO(raw)) as fh:
        while True:
            chunk = fh.read(1024 * 1024)
            if not chunk:
                break
            out += chunk
            if len(out) > limit:
                raise ValueError("The archive is too large when expanded")
    return bytes(out)


def _decode(blob: bytes) -> dict:
    if blob.startswith(_DPAPI_MAGIC):
        blob = _dpapi(blob[len(_DPAPI_MAGIC) :], False)
    elif local_protect.is_protected(blob):
        blob = local_protect.unprotect(blob)
    return json.loads(gzip.decompress(blob).decode("utf-8"))


def _write_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{secrets.token_hex(4)}.tmp")
    try:
        with open(tmp, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        try:
            tmp.chmod(0o600)
        except OSError:
            pass
        os.replace(tmp, path)
    finally:
        if tmp.exists():
            try:
                tmp.unlink()
            except OSError:
                pass


def _snap_path(snapshot_id: str) -> Path:
    sid = str(snapshot_id or "").strip()
    if sid.endswith(SNAP_EXT):
        sid = sid[: -len(SNAP_EXT)]
    if not _ID_RE.match(sid):
        raise FileNotFoundError("Snapshot not found")
    path = SNAP_DIR / f"{sid}{SNAP_EXT}"
    if not path.exists():
        raise FileNotFoundError("Snapshot not found")
    return path


def load_snapshot(snapshot_id: str) -> dict:
    _migrate_legacy()
    return _decode(_snap_path(snapshot_id).read_bytes())


def _read_index() -> list[dict]:
    data = read_json(INDEX_PATH, [])
    return [x for x in data if isinstance(x, dict) and x.get("id")] if isinstance(data, list) else []


def _new_id(trigger: str, when: datetime) -> str:
    slug = re.sub(r"[^a-z-]", "", trigger.lower())[:20] or "manual"
    if len(slug) < 2:
        slug = "manual"
    return f"{when.strftime('%Y%m%dT%H%M%SZ')}-{slug}-{secrets.token_hex(3)}"


def _content_hash(objects: dict) -> str:
    body = {k: v.get("data") for k, v in sorted(objects.items())}
    return hashlib.sha256(json.dumps(body, sort_keys=True, default=str).encode("utf-8")).hexdigest()[:16]


def _scope_key(scope: dict) -> str:
    sites = ",".join(sorted(scope.get("site_ids") or []))
    devices = ",".join(sorted(scope.get("device_ids") or []))
    objs = ",".join(sorted(scope.get("objects") or []))
    base = "org" if scope.get("org") else f"site:{sites}"
    return base + (f"|dev:{devices}" if devices else "") + (f"|obj:{objs}" if objs else "")


def _meta_for(snapshot: dict, size: int, *, encrypted: bool = False) -> dict:
    objects = snapshot.get("objects") or {}
    by_kind: dict[str, int] = {}
    for obj in objects.values():
        by_kind[obj.get("kind", "?")] = by_kind.get(obj.get("kind", "?"), 0) + 1
    scope = snapshot.get("scope") or {}
    return {
        "id": snapshot["id"],
        "created_at": snapshot.get("created_at"),
        "trigger": snapshot.get("trigger"),
        "reason": snapshot.get("reason") or "",
        "label": snapshot.get("label") or "",
        "scope": scope,
        "scope_key": _scope_key(scope),
        "site_names": snapshot.get("site_names") or {},
        "object_count": len(objects),
        "device_count": by_kind.get("device", 0),
        "by_kind": by_kind,
        "content_hash": _content_hash(objects),
        "errors": len(snapshot.get("errors") or []),
        "size_bytes": size,
        "encrypted": bool(encrypted),
        "pinned": bool(snapshot.get("pinned")),
        "changes_from_previous": None,
        "previous_id": None,
    }


def _store(snapshot: dict) -> dict:
    """Persist a snapshot (redacted again defensively) and add it to the index."""
    key = _fingerprint_key()
    for obj in (snapshot.get("objects") or {}).values():
        obj["data"] = redact_signed_urls(redact_config(obj.get("data"), key))
    blob = _encode(snapshot)
    SNAP_DIR.mkdir(parents=True, exist_ok=True)
    _write_bytes(SNAP_DIR / f"{snapshot['id']}{SNAP_EXT}", blob)
    meta = _meta_for(snapshot, len(blob), encrypted=_is_encrypted(blob))
    # Compare with the previous snapshot covering the same scope (for the timeline).
    prev = _latest_meta(lambda m: m.get("scope_key") == meta["scope_key"] and m["id"] != meta["id"])
    if prev:
        meta["previous_id"] = prev["id"]
        if prev.get("content_hash") == meta["content_hash"]:
            meta["changes_from_previous"] = 0
        else:
            try:
                result = compare_objects(load_snapshot(prev["id"]).get("objects") or {}, snapshot["objects"])
                meta["changes_from_previous"] = result["summary"]["objects_changed"]
            except Exception:
                meta["changes_from_previous"] = None

    def update(current):
        rows = [x for x in (current or []) if isinstance(x, dict) and x.get("id") != meta["id"]]
        rows.append(meta)
        rows.sort(key=lambda m: str(m.get("created_at") or ""), reverse=True)
        return rows

    locked_json_update(INDEX_PATH, update, default=[])
    with _LIVE_LOCK:
        _LIVE_CACHE.clear()
    prune()
    return meta


def _latest_meta(pred) -> dict | None:
    for meta in _read_index():  # newest first
        if pred(meta):
            return meta
    return None


_FLAGS_RECHECKED = False
_FLAGS_LOCK = threading.Lock()


def _recheck_encrypted_flags() -> None:
    """Once per run (v0.10.47, report: legacy flags not re-checked): set each index entry's "encrypted"
    from the snapshot file's own header. Before v0.10.22 the index claimed encryption on every Windows PC
    whatever _encode actually did, so an old entry could say encrypted for a plain file. Only the first
    bytes of each file are read; a missing or unreadable file keeps its entry unchanged."""
    global _FLAGS_RECHECKED
    with _FLAGS_LOCK:
        if _FLAGS_RECHECKED:
            return
        _FLAGS_RECHECKED = True
    actual: dict[str, bool] = {}
    for meta in _read_index():
        try:
            with _snap_path(meta["id"]).open("rb") as fh:
                actual[meta["id"]] = _is_encrypted(fh.read(64))
        except (OSError, ValueError):
            continue
    if not any(bool(m.get("encrypted")) != actual[m["id"]] for m in _read_index() if m["id"] in actual):
        return

    def update(current):
        rows = [dict(m) for m in (current or []) if isinstance(m, dict)]
        for m in rows:
            if m.get("id") in actual and bool(m.get("encrypted")) != actual[m["id"]]:
                _LOG.info("Backup %s: encrypted flag corrected to %s from the file header", m["id"], actual[m["id"]])
                m["encrypted"] = actual[m["id"]]
        return rows

    locked_json_update(INDEX_PATH, update, default=[])


def list_snapshots(limit: int = 500, site_id: str | None = None) -> list[dict]:
    _migrate_legacy()
    _recheck_encrypted_flags()
    rows = _read_index()
    if site_id:
        rows = [m for m in rows if _meta_touches_site(m, site_id)]
    return rows[:limit]


def _meta_touches_site(meta: dict, site_id: str) -> bool:
    scope = meta.get("scope") or {}
    if site_id in (scope.get("site_ids") or []):
        return True
    return bool(scope.get("org") and not scope.get("site_ids") and not scope.get("objects"))


def _meta_covers_site(meta: dict, site_id: str) -> bool:
    scope = meta.get("scope") or {}
    if scope.get("objects"):
        return False
    if scope.get("org") and (not scope.get("site_ids") or site_id in scope.get("site_ids", [])):
        return True
    return site_id in (scope.get("site_ids") or [])


def delete_snapshot(snapshot_id: str) -> dict:
    path = _snap_path(snapshot_id)
    sid = path.stem
    path.unlink()
    locked_json_update(INDEX_PATH, lambda cur: [m for m in (cur or []) if m.get("id") != sid], default=[])
    return {"ok": True, "deleted": sid}


def set_pinned(snapshot_id: str, pinned: bool) -> dict:
    sid = _snap_path(snapshot_id).stem

    def update(current):
        for m in current or []:
            if m.get("id") == sid:
                m["pinned"] = bool(pinned)
        return current or []

    locked_json_update(INDEX_PATH, update, default=[])
    return {"ok": True, "id": sid, "pinned": bool(pinned)}


def prune(policy: dict | None = None, *, now: datetime | None = None) -> list[str]:
    """Apply retention. Always keeps pinned snapshots, the newest ``keep_min`` overall
    and the newest snapshot of every scope (so each site keeps a baseline)."""
    policy = policy or get_policy()
    now = now or datetime.now(timezone.utc)
    rows = _read_index()
    if not rows:
        return []
    cutoff = now - timedelta(days=policy["retention_days"])
    keep: set[str] = {m["id"] for m in rows if m.get("pinned")}
    keep.update(m["id"] for m in rows[: policy["keep_min"]])
    seen_scope: set[str] = set()
    for m in rows:
        if m.get("scope_key") not in seen_scope:
            seen_scope.add(m.get("scope_key"))
            keep.add(m["id"])
    doomed: list[str] = []
    survivors: list[dict] = []
    for m in rows:
        created = _parse_time(m.get("created_at"))
        if m["id"] not in keep and created and created < cutoff:
            doomed.append(m["id"])
        else:
            survivors.append(m)
    excess = len(survivors) - policy["max_snapshots"]
    if excess > 0:
        for m in reversed(survivors):
            if excess <= 0:
                break
            if m["id"] not in keep:
                doomed.append(m["id"])
                excess -= 1
    if not doomed:
        return []
    for sid in doomed:
        try:
            (SNAP_DIR / f"{sid}{SNAP_EXT}").unlink()
        except OSError:
            pass
    gone = set(doomed)
    locked_json_update(INDEX_PATH, lambda cur: [m for m in (cur or []) if m.get("id") not in gone], default=[])
    return doomed


def _parse_time(value: Any) -> datetime | None:
    if value in (None, ""):
        return None
    try:
        if isinstance(value, (int, float)):
            v = float(value)
            return datetime.fromtimestamp(v / 1000 if v > 1e11 else v, tz=timezone.utc)
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except (ValueError, OSError, OverflowError):
        return None


def _migrate_legacy() -> None:
    """Convert pre-v0.10.15 ``*.mntbak`` device bundles to redacted v2 snapshots."""
    if not BACKUP_ROOT.exists():
        return
    for path in sorted(BACKUP_ROOT.glob("*.mntbak")):
        try:
            wrapper = json.loads(path.read_text(encoding="utf-8"))
            data = base64.b64decode(wrapper.get("data") or "")
            if wrapper.get("protected") and os.name == "nt":
                data = _dpapi(data, False)
            bundle = json.loads(data.decode("utf-8"))
            site_id = str(bundle.get("site_id") or "")
            objects = {}
            for device_id, cfg in (bundle.get("devices") or {}).items():
                if isinstance(cfg, dict):
                    obj = _make_object("device", cfg, site_id=site_id)
                    objects[obj["key"]] = obj
            created = _parse_time(bundle.get("created_at")) or datetime.now(timezone.utc)
            snap = {
                "format": FORMAT,
                "id": _new_id("legacy", created),
                "created_at": created.isoformat(),
                "trigger": "legacy",
                "reason": "Converted from an earlier NodeWatch backup",
                "scope": {"org": False, "site_ids": [site_id] if site_id else []},
                "site_names": {},
                "objects": objects,
                "errors": [],
            }
            _store(snap)
            path.unlink()
        except Exception:
            # Leave unreadable legacy files alone (e.g. protected by another Windows user).
            continue


# =========================================================================== capture


def _object_name(kind: str, data: dict, fallback: str) -> str:
    for key in ("name", "ssid", "hostname"):
        if data.get(key):
            return str(data[key])
    return fallback


def _make_object(kind: str, data: dict, *, site_id: str = "", obj_id: str = "") -> dict:
    data = data if isinstance(data, dict) else {}
    oid = str(obj_id or data.get("id") or "")
    if kind == "device":
        dtype = str(data.get("type") or "device")
        kind_label = KIND_LABELS.get(dtype, "Device")
        name = _object_name(kind, data, str(data.get("mac") or oid))
    else:
        kind_label = KIND_LABELS.get(kind, kind)
        name = _object_name(kind, data, kind_label)
    if kind in {"org", "org_setting"}:
        key = kind
    elif kind in {"site", "site_setting"}:
        key = f"{kind}:{site_id}"
    else:
        key = f"{kind}:{oid}"
    return {
        "key": key,
        "kind": kind,
        "kind_label": kind_label,
        "id": oid,
        "site_id": site_id or str(data.get("site_id") or ""),
        "name": name,
        "data": data,
    }


def _list(client, path: str) -> list[dict]:
    pager = getattr(client, "_get_paged", None)
    if callable(pager):
        return pager(path, fresh=True)
    data = client.get(path, {"limit": 1000}, cache=False)
    return [x for x in data if isinstance(x, dict)] if isinstance(data, list) else []


def _get(client, path: str) -> dict:
    data = client.get(path, cache=False)
    return data if isinstance(data, dict) else {}


def _err(where: str, exc: BaseException) -> dict:
    status = getattr(exc, "status_code", None)
    return {"collection": where, "error": redact_text(str(exc))[:300], "status": status}


def _capture_org(client, objects: dict, errors: list) -> None:
    """The org-level collections, read 6 at a time (v0.10.40: they were read one after another, ~16
    round trips on every Config Backup open). Objects are added in collection order, as before."""
    org = client._org

    def read(spec):
        kind, _label, suffix, is_list = spec
        path = f"/api/v1/orgs/{org}{suffix}"
        try:
            if is_list:
                return [_make_object(kind, row) for row in _list(client, path)], None
            return [_make_object(kind, _get(client, path), obj_id=org)], None
        except Exception as exc:
            if getattr(exc, "status_code", None) in (403, 404):
                return [], None  # feature not licensed / not available: nothing to back up
            return [], _err(kind, exc)

    with ThreadPoolExecutor(max_workers=6, thread_name_prefix="nw-backup-org") as pool:
        results = list(pool.map(read, ORG_COLLECTIONS))
    for objs, err in results:
        for obj in objs:
            objects[obj["key"]] = obj
        if err:
            errors.append(err)


def _capture_site(client, site_id: str, device_id: str | None = None, *, settings: bool = True) -> tuple[dict, list]:
    objects: dict = {}
    errors: list = []
    if device_id:
        try:
            dev = client.get_site_device(site_id, device_id, fresh=True)
            if dev:
                obj = _make_object("device", dev, site_id=site_id)
                objects[obj["key"]] = obj
        except Exception as exc:
            errors.append(_err("device", exc))
    if settings and hasattr(client, "get"):
        for kind, _label, suffix, is_list in SITE_COLLECTIONS:
            path = f"/api/v1/sites/{_path_id(site_id, 'site ID')}{suffix}"
            try:
                if is_list:
                    for row in _list(client, path):
                        obj = _make_object(kind, row, site_id=site_id)
                        objects[obj["key"]] = obj
                else:
                    obj = _make_object(kind, _get(client, path), site_id=site_id, obj_id=site_id)
                    objects[obj["key"]] = obj
            except Exception as exc:
                if getattr(exc, "status_code", None) in (403, 404):
                    continue
                errors.append(_err(f"{kind} ({site_id})", exc))
    if not device_id:
        try:
            for dev in client.list_site_devices(site_id, "all"):
                if isinstance(dev, dict) and dev.get("id"):
                    obj = _make_object("device", dev, site_id=site_id)
                    objects[obj["key"]] = obj
        except Exception as exc:
            errors.append(_err(f"devices ({site_id})", exc))
    return objects, errors


def _site_names(client) -> dict[str, str]:
    try:
        return {str(s.get("id")): str(s.get("name") or s.get("id")) for s in client.list_sites() if s.get("id")}
    except Exception:
        return {}


def capture(
    site_ids: list[str] | None = None,
    *,
    include_org: bool = True,
    device_id: str | None = None,
    all_sites: bool = False,
    client=None,
) -> dict:
    """Read configuration from Mist (redacted). Returns ``{objects, errors, site_names}``."""
    client = client or get_mist_client()
    key = _fingerprint_key()
    objects: dict = {}
    errors: list = []
    names = _site_names(client) if (include_org or all_sites) else {}
    if all_sites:
        site_ids = list(names)
    if include_org:
        _capture_org(client, objects, errors)
    site_ids = [s for s in (site_ids or []) if s]
    if site_ids:
        workers = max(1, min(4, len(site_ids)))
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="nw-backup") as pool:
            results = list(pool.map(lambda sid: _capture_site(client, sid, device_id), site_ids))
        for objs, errs in results:
            objects.update(objs)
            errors.extend(errs)
    for obj in objects.values():
        obj["data"] = redact_signed_urls(redact_config(obj["data"], key))
    _label_sites(objects, names)
    return {"objects": objects, "errors": errors, "site_names": names}


def _label_sites(objects: dict, names: dict) -> None:
    """Attach site names; site settings are named after their site ("HQ" not "Site settings")."""
    for obj in objects.values():
        sid = obj.get("site_id")
        site_obj = objects.get(f"site:{sid}") if sid else None
        name = names.get(sid) or ((site_obj or {}).get("data") or {}).get("name") if sid else None
        if name:
            obj["site_name"] = str(name)
            if obj.get("kind") == "site_setting":
                obj["name"] = str(name)


def create_full_snapshot(
    site_ids: list[str] | None = None,
    *,
    org: bool = True,
    trigger: str = "manual",
    reason: str = "",
    label: str = "",
    device_id: str | None = None,
    client=None,
) -> dict:
    """Capture and store a snapshot. ``org=True`` with no ``site_ids`` = whole org."""
    client = client or get_mist_client()
    all_sites = org and not site_ids
    result = capture(site_ids, include_org=org, device_id=device_id, all_sites=all_sites, client=client)
    now = datetime.now(timezone.utc)
    scope = {"org": bool(org), "site_ids": sorted(site_ids or []) if not all_sites else []}
    if device_id:
        scope["device_ids"] = [device_id]
    snap = {
        "format": FORMAT,
        "id": _new_id(trigger, now),
        "created_at": now.isoformat(),
        "trigger": trigger,
        "reason": redact_text(reason)[:300],
        "label": redact_text(label)[:120],
        "scope": scope,
        "site_names": result["site_names"],
        "objects": result["objects"],
        "errors": result["errors"],
    }
    if not snap["objects"]:
        detail = result["errors"][0]["error"] if result["errors"] else "Mist returned no configuration"
        raise RuntimeError(f"Nothing captured: {detail}")
    return _store(snap)


def create_snapshot(site_id: str, device_id: str | None = None) -> dict:
    """Backwards-compatible: snapshot one site (or one device) without org objects."""
    site_id = str(site_id or "").strip()
    if not site_id:
        meta = create_full_snapshot(org=True)
    else:
        meta = create_full_snapshot([site_id], org=False, device_id=device_id or None)
    return {
        "ok": True,
        "snapshot": meta["id"],
        "site_id": site_id,
        "device_count": meta["device_count"],
        "object_count": meta["object_count"],
        "encrypted": meta["encrypted"],
        "meta": meta,
    }


def snapshot_before_change(site_id: str, device_id: str | None = None, reason: str = "") -> dict:
    """Safety snapshot taken by other tools right before they write to Mist.

    Captures the device (when given) plus the site's settings. Never raises: a failed
    safety snapshot must not block an otherwise-confirmed change, but the caller gets
    ``ok: False`` and can surface the warning.
    """
    try:
        if not get_policy().get("pre_change_enabled"):
            return {"ok": False, "skipped": True, "reason": "Pre-change snapshots are turned off"}
        client = get_mist_client()
        site_id = str(site_id or "").strip()
        if not site_id:
            return {"ok": False, "error": "site_id is required"}
        objects, errors = _capture_site(client, site_id, device_id or None, settings=True)
        key = _fingerprint_key()
        for obj in objects.values():
            obj["data"] = redact_signed_urls(redact_config(obj["data"], key))
        _label_sites(objects, {})
        now = datetime.now(timezone.utc)
        if not objects:
            return {"ok": False, "error": errors[0]["error"] if errors else "Nothing captured"}
        scope = {"org": False, "site_ids": [site_id]}
        if device_id:
            scope["device_ids"] = [device_id]
        meta = _store(
            {
                "format": FORMAT,
                "id": _new_id("pre-change", now),
                "created_at": now.isoformat(),
                "trigger": "pre-change",
                "reason": redact_text(reason or "Before a NodeWatch change")[:300],
                "scope": scope,
                "site_names": {},
                "objects": objects,
                "errors": errors,
            }
        )
        return {"ok": True, "snapshot": meta["id"], "object_count": meta["object_count"]}
    except Exception as exc:
        return {"ok": False, "error": redact_text(str(exc))[:300]}


# =========================================================================== scheduler


def _scheduled_due(policy: dict, now: datetime) -> bool:
    if not policy.get("daily_enabled"):
        return False
    last = _parse_time(policy.get("last_daily"))
    if last is None:
        newest = _latest_meta(
            lambda m: m.get("trigger") in {"scheduled", "baseline"} and (m.get("scope") or {}).get("org")
        )
        last = _parse_time(newest.get("created_at")) if newest else None
    return last is None or (now - last) >= timedelta(hours=policy["interval_hours"])


def run_scheduled_snapshot(now: datetime | None = None) -> dict | None:
    policy = get_policy()
    now = now or datetime.now(timezone.utc)
    if not _scheduled_due(policy, now):
        return None
    try:
        client = get_mist_client()
        if not getattr(client, "configured", False):
            return None
        site_ids = policy["site_ids"] or None
        meta = create_full_snapshot(site_ids, org=True, trigger="scheduled", reason="Scheduled snapshot", client=client)
        _mark_daily(True)
        return meta
    except Exception as exc:
        _mark_daily(False, redact_text(str(exc))[:300])
        return None


def _daily_loop():
    # First check shortly after start-up, then every 30 minutes.
    wait = 120
    while not _SCHEDULER_STOP.wait(wait):
        wait = 1800
        try:
            run_scheduled_snapshot()
        except Exception:  # noqa: BLE001 - the scheduler keeps running; the failure is logged
            logging.getLogger("nodewatch.backup").warning("Scheduled snapshot failed", exc_info=True)


def start_backup_scheduler():
    global _SCHEDULER_THREAD
    if _SCHEDULER_THREAD and _SCHEDULER_THREAD.is_alive():
        return
    _SCHEDULER_STOP.clear()
    _SCHEDULER_THREAD = threading.Thread(target=_daily_loop, name="NodeWatchConfigBackup", daemon=True)
    _SCHEDULER_THREAD.start()


def stop_backup_scheduler():
    _SCHEDULER_STOP.set()


def schedule_info() -> dict:
    policy = get_policy()
    last = _parse_time(policy.get("last_daily"))
    nxt = None
    if policy["daily_enabled"]:
        nxt = (last + timedelta(hours=policy["interval_hours"])) if last else None
    return {
        "enabled": policy["daily_enabled"],
        "interval_hours": policy["interval_hours"],
        "last_run": last.isoformat() if last else None,
        "next_run": nxt.isoformat() if nxt else None,
        "last_error": policy.get("last_daily_error"),
        "pre_change_enabled": policy["pre_change_enabled"],
        "retention_days": policy["retention_days"],
    }


# =========================================================================== compare


def _clean(data: Any) -> Any:
    if not isinstance(data, dict):
        return data
    return {k: v for k, v in data.items() if k not in {"modified_time", "created_time", "for_site", "_meta"}}


def compare_objects(before: dict, after: dict, *, max_changes: int = 200) -> dict:
    """Object-level comparison of two ``{key: object}`` maps (snapshot → snapshot/live)."""
    rows = []
    for key in sorted(set(before) | set(after)):
        a, b = before.get(key), after.get(key)
        ref = b or a
        if a and b:
            changes = diff_config(_clean(a.get("data")), _clean(b.get("data")), max_changes=max_changes)
            if not changes:
                continue
            state = "changed"
        elif b:
            changes, state = [], "added"
        else:
            changes, state = [], "removed"
        rows.append(
            {
                "key": key,
                "kind": ref.get("kind"),
                "kind_label": ref.get("kind_label") or KIND_LABELS.get(ref.get("kind"), ref.get("kind")),
                "id": ref.get("id"),
                "name": ref.get("name"),
                "site_id": ref.get("site_id") or "",
                "site_name": ref.get("site_name") or "",
                "state": state,
                "change_count": len(changes) if state == "changed" else 1,
                "changes": changes,
                "secret_changes": sum(1 for c in changes if c.get("secret")),
            }
        )
    order = {k: i for i, k in enumerate(KIND_ORDER)}
    rows.sort(key=lambda r: (order.get(r["kind"], 99), str(r.get("site_name") or ""), str(r.get("name") or "").lower()))
    return {
        "objects": rows,
        "summary": {
            "objects_changed": len(rows),
            "settings_changed": sum(r["change_count"] for r in rows),
            "changed": sum(r["state"] == "changed" for r in rows),
            "added": sum(r["state"] == "added" for r in rows),
            "removed": sum(r["state"] == "removed" for r in rows),
            "compared_objects": len(set(before) | set(after)),
        },
    }


def _scope_filter(objects: dict, site_id: str | None) -> dict:
    """Objects relevant to one site: its own objects plus the org templates it uses."""
    if not site_id:
        return dict(objects)
    out = {k: v for k, v in objects.items() if v.get("site_id") == site_id and v.get("kind") != "org_wlan"}
    site = (objects.get(f"site:{site_id}") or {}).get("data") or {}
    refs: set[str] = set()
    for field, kind in (
        ("networktemplate_id", "networktemplate"),
        ("gatewaytemplate_id", "gatewaytemplate"),
        ("rftemplate_id", "rftemplate"),
        ("sitetemplate_id", "sitetemplate"),
        ("alarmtemplate_id", "alarmtemplate"),
    ):
        if site.get(field):
            refs.add(f"{kind}:{site[field]}")
    for gid in site.get("sitegroup_ids") or []:
        refs.add(f"sitegroup:{gid}")
    for obj in list(out.values()):
        prof = (obj.get("data") or {}).get("deviceprofile_id")
        if obj.get("kind") == "device" and prof:
            refs.add(f"deviceprofile:{prof}")
    # WLAN templates applied to this site (directly, through a site group, or org-wide).
    groups = set(site.get("sitegroup_ids") or [])
    for key, obj in objects.items():
        if obj.get("kind") != "wlantemplate":
            continue
        applies = (obj.get("data") or {}).get("applies") or {}
        if (
            applies.get("org_id")
            or site_id in (applies.get("site_ids") or [])
            or groups & set(applies.get("sitegroup_ids") or [])
        ):
            refs.add(key)
            tid = obj.get("id")
            for k2, o2 in objects.items():
                if o2.get("kind") == "org_wlan" and (o2.get("data") or {}).get("template_id") == tid:
                    refs.add(k2)
    for ref in refs:
        if ref in objects:
            out[ref] = objects[ref]
    return out


# =========================================================================== audit correlation


def _audit_entries(since: datetime, until: datetime | None = None, client=None) -> tuple[list[dict], str | None]:
    client = client or get_mist_client()
    now = datetime.now(timezone.utc)
    days = max(1, min(90, math.ceil((now - since).total_seconds() / 86400) + 1))
    try:
        rows = client.search_audit_logs(f"{days}d")
    except Exception as exc:
        return [], redact_text(str(exc))[:200]
    lo = since.timestamp()
    hi = (until or now).timestamp()
    out = []
    for row in rows or []:
        if not isinstance(row, dict):
            continue
        ts = row.get("timestamp")
        try:
            ts = float(ts)
            ts = ts / 1000 if ts > 1e11 else ts
        except (TypeError, ValueError):
            continue
        if ts < lo or ts > hi:
            continue
        message = redact_text(row.get("message") or "")
        parsed = parse_audit_message(message)
        ids = set()
        for k in ("device_id", "wlan_id", "template_id", "id"):
            if row.get(k):
                ids.add(str(row[k]))
        for side in ("before", "after"):
            blob = row.get(side)
            if isinstance(blob, dict) and blob.get("id"):
                ids.add(str(blob["id"]))
        out.append(
            {
                "ts": ts,
                "when": datetime.fromtimestamp(ts, tz=timezone.utc).isoformat(),
                "admin": str(row.get("admin_name") or row.get("email") or "Mist"),
                "message": message,
                "object_type": parsed.get("object_type") or "",
                "object_name": parsed.get("object_name") or "",
                "site_id": str(row.get("site_id") or ""),
                "src_ip": str(row.get("src_ip") or ""),
                "_ids": ids,
            }
        )
    out.sort(key=lambda r: r["ts"], reverse=True)
    return out, None


_AUDIT_KIND_WORDS = {
    "device": ("device", "switch", "ap", "gateway", "access point"),
    "site_setting": ("site setting", "site settings"),
    "site": ("site",),
    "org_setting": ("org setting", "organization setting", "org settings"),
    "org_wlan": ("wlan",),
    "site_wlan": ("wlan",),
    "networktemplate": ("network template", "switch template"),
    "gatewaytemplate": ("gateway template",),
    "deviceprofile": ("device profile", "deviceprofile"),
    "rftemplate": ("rf template", "rftemplate"),
    "nacrule": ("nac rule", "nacrule"),
    "nactag": ("nac tag", "nactag", "label"),
    "wlantemplate": ("template", "wlan template"),
}


def _audit_matches(obj: dict, entry: dict) -> bool:
    if obj.get("id") and obj["id"] in entry["_ids"]:
        return True
    if obj.get("site_id") and entry["site_id"] and obj["site_id"] != entry["site_id"]:
        return False
    if obj.get("kind") in {"org", "org_setting"} or obj.get("kind") in {k for k, *_ in ORG_COLLECTIONS}:
        if entry["site_id"]:
            return False
    msg = entry["message"].lower()
    words = _AUDIT_KIND_WORDS.get(obj.get("kind"), ())
    name = str(obj.get("name") or "").lower()
    if obj.get("kind") in {"site_setting"} and any(w in msg for w in words):
        return True
    if name and len(name) >= 2 and (entry["object_name"].lower() == name or f'"{name}"' in msg or f"“{name}”" in msg):
        return True
    return bool(name and words and any(w in msg for w in words) and name in msg)


def correlate(rows: list[dict], entries: list[dict]) -> None:
    """Attach ``who`` (Mist audit entries) to each changed object row."""
    for row in rows:
        hits = [e for e in entries if _audit_matches(row, e)][:6]
        row["who"] = [{k: v for k, v in e.items() if not k.startswith("_")} for e in hits]


_READ_VERBS = {"Access", "Login", "Logout", "View", "Export"}
_KIND_RANK = {"person": 0, "api_token": 1, "unknown": 2, "system": 3}


def _source_label() -> str:
    try:
        from app.services.audit_people import source_labels

        return source_labels().get("mist") or "Juniper Mist"
    except Exception:  # noqa: BLE001
        return "Juniper Mist"


def _classify_audit(entries: list[dict], since: datetime | None) -> None:
    """Who and what for each audit row (v0.10.24), from the vendor-neutral audit people service
    (``audit.log`` + ``directory.admins``): the person's full name, email, role and whether the row
    is a change or only a read (access, sign-in). Matched on (time, message); never raises."""
    people: dict[tuple[int, str], tuple[dict, dict]] = {}
    try:
        from app.services import audit_people

        days = (
            max(1, min(90, math.ceil((datetime.now(timezone.utc) - since).total_seconds() / 86400) + 1)) if since else 7
        )
        res = audit_people.collect(f"{days}d")
        for e in res.get("entries") or []:
            if e.get("source") == "mist":
                actor = (res.get("actors") or {}).get(e.get("actor_ref") or "", {})
                people[(int(float(e.get("timestamp") or 0)), str(e.get("message") or ""))] = (e, actor)
    except Exception:  # noqa: BLE001 - enrichment is optional
        people = {}
    for e in entries:
        hit = people.get((int(e["ts"]), e["message"]))
        neutral, actor = hit if hit else ({}, {})
        verb = str(neutral.get("verb") or parse_audit_message(e["message"]).get("action") or "Activity")
        action = str(neutral.get("action") or "")
        e["action_label"] = verb
        e["is_change"] = action in {"create", "update", "delete"} or (
            action in {"", "other"} and verb not in _READ_VERBS
        )
        if action == "login":
            e["is_change"] = False
        e["actor_name"] = str(actor.get("name") or e["admin"])
        e["actor_email"] = str(actor.get("email") or "")
        e["actor_role"] = str((actor.get("role_lines") or [""])[0])
        e["actor_kind"] = str(
            actor.get("kind") or ("system" if e["admin"].lower() in {"mist", "system"} else "unknown")
        )


def _change_admins(changes: list[dict]) -> list[dict]:
    """Who changed things: people and API tokens first; automatic actors never outrank a person."""
    by: dict[str, dict] = {}
    for e in changes:
        a = by.setdefault(
            e["actor_name"],
            {
                "admin": e["actor_name"],
                "email": e["actor_email"],
                "kind": e["actor_kind"],
                "role": e["actor_role"],
                "count": 0,
            },
        )
        a["count"] += 1
    return sorted(by.values(), key=lambda a: (_KIND_RANK.get(a["kind"], 2), -a["count"], a["admin"].lower()))


def _read_summary(reads: list[dict]) -> list[dict]:
    """Access / sign-in rows collapsed per (who, what): "Mist · Accessed by Mist Marvis × 24"."""
    groups: dict[tuple[str, str], dict] = {}
    for e in reads:
        g = groups.setdefault(
            (e["actor_name"], e["message"]),
            {"actor": e["actor_name"], "kind": e["actor_kind"], "message": e["message"], "count": 0, "last": e["when"]},
        )
        g["count"] += 1
        g["last"] = max(g["last"], e["when"])
    return sorted(groups.values(), key=lambda g: -g["count"])[:20]


def _public_audit(entries: list[dict], limit: int = 60) -> list[dict]:
    return [{k: v for k, v in e.items() if not k.startswith("_")} for e in entries[:limit]]


# =========================================================================== live status (landing)


def _live(site_id: str | None, site_ids: list[str] | None, *, refresh: bool) -> dict:
    key = f"{site_id or 'org'}|{','.join(sorted(site_ids or []))}"
    now = time.monotonic()
    with _LIVE_LOCK:
        hit = _LIVE_CACHE.get(key)
        if hit and not refresh and now - hit[0] < _LIVE_TTL:
            return hit[1]
    sites = [site_id] if site_id else list(site_ids or [])
    result = capture(sites, include_org=True)
    result["captured_at"] = datetime.now(timezone.utc).isoformat()
    with _LIVE_LOCK:
        _LIVE_CACHE[key] = (now, result)
    return result


def _restore_mode(row: dict, live_objects: dict) -> dict:
    kind = row.get("kind")
    if row.get("state") == "added":
        return {
            "mode": "none",
            "reason": "Created after the snapshot. Rolling back would mean deleting it; do that in Mist if intended.",
        }
    if kind not in RESTORABLE:
        return {
            "mode": "export",
            "reason": "NodeWatch does not write this object type. Download the JSON to re-apply it by hand.",
        }
    if row.get("state") == "removed" or row.get("key") not in live_objects:
        return {
            "mode": "export",
            "reason": "Deleted in Mist. Re-creating it would give it a new ID, so download the JSON instead.",
        }
    return {"mode": "restore", "reason": ""}


def _is_whole(meta: dict) -> bool:
    """A snapshot of a whole scope (not one device / one object / an import)."""
    scope = meta.get("scope") or {}
    return not (scope.get("device_ids") or scope.get("objects") or scope.get("imported"))


def overview(site_id: str | None = None, *, refresh: bool = False, full: bool = False) -> dict:
    """Landing view: last capture, what changed since, who changed it, can it roll back."""
    site_id = (site_id or "").strip() or None
    if site_id:
        base_meta = _latest_meta(lambda m: _meta_covers_site(m, site_id) and _is_whole(m))
    else:
        base_meta = _latest_meta(lambda m: (m.get("scope") or {}).get("org") and _is_whole(m))
    any_meta = _latest_meta(lambda m: True)
    result: dict = {
        "scope": {"site_id": site_id},
        "schedule": schedule_info(),
        "last_snapshot": base_meta,
        "latest_any": any_meta,
        "snapshot_count": len(_read_index()),
    }
    client = get_mist_client()
    if not getattr(client, "configured", True):
        result["error"] = "Mist is not connected. Add the API token in Settings to capture configuration."
        return result

    base_objects: dict = {}
    base_snapshot: dict = {}
    if base_meta:
        base_snapshot = load_snapshot(base_meta["id"])
        base_objects = _scope_filter(base_snapshot.get("objects") or {}, site_id)
    names = {}

    # Which sites to read live. Org-wide quick check: only sites the audit log says were
    # touched since the snapshot (plus org objects); "full" reads every snapshotted site.
    entries: list[dict] = []
    audit_error = None
    since = _parse_time(base_meta.get("created_at")) if base_meta else None
    if since:
        entries, audit_error = _audit_entries(since, client=client)
    if site_id:
        live_sites = [site_id]
        result["check"] = "site"
    else:
        snap_sites = sorted({o.get("site_id") for o in base_objects.values() if o.get("site_id")})
        touched = sorted({e["site_id"] for e in entries if e["site_id"]})
        if full or audit_error or not base_meta:
            live_sites = snap_sites
            result["check"] = "full"
        else:
            live_sites = [s for s in touched if s in snap_sites] + [s for s in touched if s not in snap_sites]
            result["check"] = "quick"
            result["sites_checked"] = len(live_sites)
            result["sites_total"] = len(snap_sites)
        if not base_meta:
            live_sites = None  # baseline below captures everything

    if not base_meta:
        # First visit for this scope: capture a baseline so there is something to compare.
        try:
            meta = create_full_snapshot(
                [site_id] if site_id else None,
                org=True,
                trigger="baseline",
                reason="First capture (baseline)",
                client=client,
            )
            result["baseline_created"] = True
            result["last_snapshot"] = meta
            result["summary"] = {"objects_changed": 0, "settings_changed": 0, "changed": 0, "added": 0, "removed": 0}
            result["objects"] = []
            result["audit"] = []
            result["admins"] = []
            result["live_at"] = meta["created_at"]
            result["restore_summary"] = {"restore": 0, "export": 0, "none": 0}
            return result
        except Exception as exc:
            result["error"] = redact_text(str(exc))[:300]
            return result

    live = _live(site_id, live_sites, refresh=refresh)
    cov_base = _coverage(
        base_snapshot.get("scope") or {}, base_snapshot.get("objects") or {}, base_snapshot.get("site_names")
    )
    cov_live = {"org": True, "sites": set(live_sites or []), "devices": None, "keys": None}
    if site_id and not cov_base["org"]:
        cov_live["org"] = False  # base did not capture org objects: do not report them all as new
    base_cmp = _scope_filter(_restrict(base_snapshot.get("objects") or {}, cov_base, cov_live), site_id)
    live_objects = _scope_filter(_restrict(live["objects"], cov_base, cov_live), site_id)
    cmp = compare_objects(base_cmp, live_objects)
    for row in cmp["objects"]:
        row["restore"] = _restore_mode(row, live_objects)
        if row["site_id"] and not row.get("site_name"):
            row["site_name"] = (live.get("site_names") or {}).get(row["site_id"], "")
    if site_id:
        entries = [e for e in entries if not e["site_id"] or e["site_id"] == site_id]
    names = live.get("site_names") or base_snapshot.get("site_names") or {}
    for e in entries:
        e["site_name"] = names.get(e["site_id"], "") if e["site_id"] else "Organization"
    _classify_audit(entries, since)
    changes = [e for e in entries if e["is_change"]]
    reads = [e for e in entries if not e["is_change"]]
    correlate(cmp["objects"], changes)  # only real changes explain a changed object
    for e in changes:
        e["object_key"] = next((r["key"] for r in cmp["objects"] if _audit_matches(r, e)), "")
    result.update(
        {
            "live_at": live.get("captured_at"),
            "source_label": _source_label(),
            "summary": cmp["summary"],
            "objects": cmp["objects"],
            "audit": _public_audit(changes),
            "audit_reads": _read_summary(reads),
            "audit_error": audit_error,
            "admins": _change_admins(changes),
            "errors": live.get("errors", [])[:20],
            "restore_summary": {
                m: sum(1 for r in cmp["objects"] if r["restore"]["mode"] == m) for m in ("restore", "export", "none")
            },
            "site_names": names,
        }
    )
    return result


def _coverage(scope: dict, objects: dict, site_names: dict | None = None) -> dict:
    """What a capture actually covered: org objects, which sites, which devices."""
    scope = scope or {}
    sites = set(scope.get("site_ids") or [])
    if scope.get("org") and not sites:
        sites = {o.get("site_id") for o in objects.values() if o.get("site_id")} | set(site_names or {})
    devices = set(scope.get("device_ids") or []) or None
    keys = set(scope.get("objects") or []) or None
    return {"org": bool(scope.get("org")), "sites": sites, "devices": devices, "keys": keys}


def _restrict(objects: dict, *coverages: dict) -> dict:
    """Keep only objects every coverage captured, so a partial snapshot never reads as deletions."""
    out = {}
    for key, obj in objects.items():
        if any(c.get("keys") is not None and key not in c["keys"] for c in coverages):
            continue
        sid = obj.get("site_id")
        if not sid:
            if all(c["org"] for c in coverages):
                out[key] = obj
            continue
        if not all(sid in c["sites"] for c in coverages):
            continue
        if obj.get("kind") == "device" and any(
            c["devices"] is not None and obj.get("id") not in c["devices"] for c in coverages
        ):
            continue
        out[key] = obj
    return out


def compare(a_id: str, b_id: str, site_id: str | None = None) -> dict:
    """Compare two snapshots, or a snapshot with live Mist (``b_id == "live"``).

    The older side is always "before", so kinds read naturally (added = new since).
    """
    a = load_snapshot(a_id)
    a_objs = a.get("objects") or {}
    cov_a = _coverage(a.get("scope") or {}, a_objs, a.get("site_names"))
    index = {m["id"]: m for m in _read_index()}
    a_meta = index.get(a["id"], {"id": a["id"], "created_at": a.get("created_at"), "trigger": a.get("trigger")})
    live_objects = None
    if b_id == "live":
        sites = [site_id] if site_id else sorted(cov_a["sites"])
        live = _live(site_id, sites, refresh=False)
        b_objs = live["objects"]
        cov_b = {"org": True, "sites": set(sites), "devices": None, "keys": None}
        b_meta = {"id": "live", "created_at": live.get("captured_at"), "trigger": "live"}
    else:
        b = load_snapshot(b_id)
        b_objs = b.get("objects") or {}
        cov_b = _coverage(b.get("scope") or {}, b_objs, b.get("site_names"))
        b_meta = index.get(b["id"], {"id": b["id"], "created_at": b.get("created_at"), "trigger": b.get("trigger")})
    a_cmp = _scope_filter(_restrict(a_objs, cov_a, cov_b), site_id)
    b_cmp = _scope_filter(_restrict(b_objs, cov_a, cov_b), site_id)
    if b_id == "live":
        live_objects = b_cmp
    a_t, b_t = _parse_time(a_meta.get("created_at")), _parse_time(b_meta.get("created_at"))
    swap = bool(a_t and b_t and b_t < a_t)
    older, newer = (b_cmp, a_cmp) if swap else (a_cmp, b_cmp)
    result = compare_objects(older, newer)
    times = sorted(t for t in (a_t, b_t) if t)
    entries, audit_error = [], None
    if times:
        entries, audit_error = _audit_entries(times[0], times[-1] if len(times) > 1 else None)
    if site_id:
        entries = [e for e in entries if not e["site_id"] or e["site_id"] == site_id]
    correlate(result["objects"], entries)
    for row in result["objects"]:
        row["restore"] = (
            _restore_mode(row, live_objects) if live_objects is not None else {"mode": "preview", "reason": ""}
        )
    result.update(
        {
            "from": b_meta if swap else a_meta,
            "to": a_meta if swap else b_meta,
            "coverage_note": _coverage_note(cov_a, cov_b),
            "audit": _public_audit(entries),
            "audit_error": audit_error,
        }
    )
    return result


def _coverage_note(a: dict, b: dict) -> str:
    notes = []
    if a["org"] != b["org"]:
        notes.append("org-level objects are only in one side, so they were not compared")
    if a["sites"] != b["sites"]:
        notes.append("only sites captured in both snapshots were compared")
    if a.get("keys") is not None or b.get("keys") is not None:
        notes.append("one side holds a single object only")
    if a["devices"] is not None or b["devices"] is not None:
        notes.append("one side holds selected devices only")
    return "; ".join(notes).capitalize()


# =========================================================================== template drift


def template_drift(site_id: str | None = None, snapshot_id: str | None = None) -> dict:
    """Devices whose own settings override what their template / profile defines.

    With a site: live Mist (cached briefly). Org-wide: computed from the latest org
    snapshot so it never costs hundreds of API calls.
    """
    site_id = (site_id or "").strip() or None
    if snapshot_id:
        objects = load_snapshot(snapshot_id).get("objects") or {}
        source = {"type": "snapshot", "id": snapshot_id}
    elif site_id:
        live = _live(site_id, [site_id], refresh=False)
        objects = live["objects"]
        source = {"type": "live", "at": live.get("captured_at")}
    else:
        meta = _latest_meta(lambda m: (m.get("scope") or {}).get("org") and _is_whole(m))
        if not meta:
            return {"devices": [], "source": None, "message": "Take an org-wide snapshot first."}
        objects = load_snapshot(meta["id"]).get("objects") or {}
        source = {"type": "snapshot", "id": meta["id"], "at": meta.get("created_at")}
    rows = []
    for obj in objects.values():
        if obj.get("kind") != "device" or (site_id and obj.get("site_id") != site_id):
            continue
        dev = obj.get("data") or {}
        sid = obj.get("site_id")
        site = (objects.get(f"site:{sid}") or {}).get("data") or {}
        parent, parent_label = None, ""
        prof = objects.get(f"deviceprofile:{dev.get('deviceprofile_id')}") if dev.get("deviceprofile_id") else None
        if prof:
            parent, parent_label = prof.get("data") or {}, f"Device profile “{prof.get('name')}”"
        elif dev.get("type") == "switch":
            tmpl = (
                objects.get(f"networktemplate:{site.get('networktemplate_id')}")
                if site.get("networktemplate_id")
                else None
            )
            setting = (objects.get(f"site:{sid}".replace("site:", "site_setting:")) or {}).get("data") or {}
            parent = {**((tmpl or {}).get("data") or {}), **setting}
            parent_label = f"Switch template “{tmpl.get('name')}” + site settings" if tmpl else "Site settings"
        elif dev.get("type") == "gateway" and site.get("gatewaytemplate_id"):
            tmpl = objects.get(f"gatewaytemplate:{site.get('gatewaytemplate_id')}")
            if tmpl:
                parent, parent_label = tmpl.get("data") or {}, f"WAN Edge template “{tmpl.get('name')}”"
        if not parent:
            continue
        overrides = template_overrides(dev, parent)
        rows.append(
            {
                "key": obj["key"],
                "device_id": obj.get("id"),
                "name": obj.get("name"),
                "kind_label": obj.get("kind_label"),
                "site_id": sid,
                "site_name": obj.get("site_name") or "",
                "parent": parent_label,
                "override_count": len(overrides),
                "overrides": overrides,
            }
        )
    rows.sort(key=lambda r: (-r["override_count"], str(r.get("name") or "").lower()))
    return {
        "source": source,
        "devices": rows,
        "devices_with_overrides": sum(1 for r in rows if r["override_count"]),
        "devices_checked": len(rows),
    }


# =========================================================================== object access / export / import


def get_object(snapshot_id: str, key: str) -> dict:
    snap = load_snapshot(snapshot_id)
    obj = (snap.get("objects") or {}).get(key)
    if not isinstance(obj, dict):
        raise KeyError("Object is not in this snapshot")
    # Snapshots taken before v0.10.24 may still hold signed links: never show their credentials.
    return {**redact_signed_urls(obj), "snapshot_id": snap["id"], "snapshot_created_at": snap.get("created_at")}


def _safe_name(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", str(text or "")).strip("._")[:80] or "object"


def export_snapshot(snapshot_id: str, fmt: str = "zip") -> tuple[bytes, str, str]:
    snap = load_snapshot(snapshot_id)
    meta = next((m for m in _read_index() if m["id"] == snap["id"]), {})
    doc = {
        "format": FORMAT,
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "note": "Secrets (PSKs, RADIUS secrets, passwords, tokens) are redacted.",
        **{k: snap.get(k) for k in ("id", "created_at", "trigger", "reason", "label", "scope", "site_names", "errors")},
        "objects": redact_signed_urls(snap.get("objects") or {}),
    }
    if fmt == "json":
        return (
            json.dumps(doc, indent=2, default=str).encode("utf-8"),
            f"nodewatch-config-{snap['id']}.json",
            "application/json",
        )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        manifest = {k: v for k, v in doc.items() if k != "objects"}
        manifest["object_index"] = []
        for key, obj in sorted((snap.get("objects") or {}).items()):
            folder = _safe_name(obj.get("kind"))
            site = _safe_name(obj.get("site_name") or obj.get("site_id") or "org")
            name = f"{folder}/{site}/{_safe_name(obj.get('name'))}__{_safe_name(obj.get('id') or key)[:12]}.json"
            zf.writestr(f"objects/{name}", json.dumps(obj, indent=2, default=str))
            manifest["object_index"].append({"key": key, "file": f"objects/{name}"})
        manifest["meta"] = meta
        zf.writestr("manifest.json", json.dumps(manifest, indent=2, default=str))
        zf.writestr(
            "README.txt",
            "NodeWatch configuration snapshot.\n"
            "manifest.json lists every object; objects/<type>/<site>/<name>.json holds each one.\n"
            "Secrets are redacted. Import this file in NodeWatch > Config Backups to compare it.\n",
        )
    return buf.getvalue(), f"nodewatch-config-{snap['id']}.zip", "application/zip"


def import_snapshot(raw: bytes, filename: str = "") -> dict:
    if not raw:
        raise ValueError("The file is empty")
    if len(raw) > MAX_IMPORT_BYTES:
        raise ValueError("The file is larger than 50 MB")
    if raw[:2] == b"PK":
        with zipfile.ZipFile(io.BytesIO(raw)) as zf:
            infos = zf.infolist()
            if sum(i.file_size for i in infos) > 4 * MAX_IMPORT_BYTES:
                raise ValueError("The archive is too large when expanded")
            manifest = json.loads(zf.read("manifest.json").decode("utf-8"))
            objects = {}
            for item in manifest.get("object_index") or []:
                name = str(item.get("file") or "")
                if not name.startswith("objects/") or ".." in name:
                    continue
                obj = json.loads(zf.read(name).decode("utf-8"))
                if isinstance(obj, dict) and obj.get("key"):
                    objects[obj["key"]] = obj
            doc = {**manifest, "objects": objects}
    elif raw[:2] == _GZIP_MAGIC:
        doc = json.loads(_gunzip_bounded(raw, 4 * MAX_IMPORT_BYTES).decode("utf-8"))
    else:
        doc = json.loads(raw.decode("utf-8-sig"))
    if not isinstance(doc, dict) or not isinstance(doc.get("objects"), dict):
        raise ValueError("Not a NodeWatch configuration snapshot (missing objects)")
    objects = {}
    for key, obj in doc["objects"].items():
        if not isinstance(obj, dict) or not isinstance(obj.get("data"), (dict, list)):
            continue
        kind = str(obj.get("kind") or "")
        oid, osid = str(obj.get("id") or "").strip(), str(obj.get("site_id") or "").strip()
        if kind not in KIND_LABELS and kind not in {"org", "org_setting", "site_setting"}:
            continue  # unknown object type: never restorable, so not imported
        if (oid and not _UUID.match(oid)) or (osid and not _UUID.match(osid)):
            continue  # IDs that are not Mist UUIDs could redirect a later restore to another object
        clean = {
            "key": str(key),
            "kind": kind,
            "kind_label": str(obj.get("kind_label") or KIND_LABELS.get(kind, kind)),
            "id": str(obj.get("id") or ""),
            "site_id": str(obj.get("site_id") or ""),
            "site_name": str(obj.get("site_name") or ""),
            "name": str(obj.get("name") or key),
            "data": obj["data"],
        }
        objects[clean["key"]] = clean
    if not objects:
        raise ValueError("The snapshot contains no configuration objects")
    now = datetime.now(timezone.utc)
    scope = doc.get("scope") if isinstance(doc.get("scope"), dict) else {}
    snap = {
        "format": FORMAT,
        "id": _new_id("import", now),
        "created_at": str(doc.get("created_at") or now.isoformat()),
        "imported_at": now.isoformat(),
        "trigger": "import",
        "reason": f"Imported from {redact_text(filename)[:120] or 'file'}",
        "label": redact_text(str(doc.get("label") or ""))[:120],
        "scope": {
            "org": bool(scope.get("org")),
            "site_ids": [str(x) for x in scope.get("site_ids") or []],
            "imported": True,
        },
        "site_names": doc.get("site_names") if isinstance(doc.get("site_names"), dict) else {},
        "objects": objects,
        "errors": [],
    }
    # _store re-redacts every object, so an import that carries clear secrets is cleaned.
    meta = _store(snap)
    return {"ok": True, "snapshot": meta["id"], "meta": meta}


# =========================================================================== restore


def _writeable(data: dict) -> dict:
    return {
        k: v
        for k, v in (data or {}).items()
        if k not in READ_ONLY_KEYS and not str(k).startswith("_") and not is_volatile_key(k)
    }


def _object_path(client, obj: dict) -> str:
    # IDs may come from an imported file: validate them so they can only ever name the object shown.
    kind = obj.get("kind")
    oid = _path_id(obj.get("id"), "object ID") if kind not in {"site", "site_setting", "org_setting"} else ""
    sid = _path_id(obj.get("site_id"), "site ID") if kind in {"site", "site_setting", "site_wlan"} else ""
    if kind == "site":
        return f"/api/v1/sites/{sid}"
    if kind == "site_setting":
        return f"/api/v1/sites/{sid}/setting"
    if kind == "site_wlan":
        return f"/api/v1/sites/{sid}/wlans/{oid}"
    if kind == "org_setting":
        return f"/api/v1/orgs/{client._org}/setting"
    if kind in _ORG_PATHS and _ORG_PATHS[kind]:
        return f"/api/v1/orgs/{client._org}{_ORG_PATHS[kind]}/{oid}"
    raise ValueError("This object type cannot be restored from NodeWatch")


def _read_live(client, obj: dict) -> dict:
    if obj.get("kind") == "device":
        return client.get_site_device(obj["site_id"], obj["id"], fresh=True) or {}
    return _get(client, _object_path(client, obj))


def _write_live(client, obj: dict, body: dict) -> Any:
    if obj.get("kind") == "device":
        return client.update_site_device(obj["site_id"], obj["id"], body)
    return client.put(_object_path(client, obj), body)


def _find_object(snap: dict, key: str | None, device_id: str | None) -> dict:
    objects = snap.get("objects") or {}
    if key and key in objects:
        return objects[key]
    if device_id and f"device:{device_id}" in objects:
        return objects[f"device:{device_id}"]
    raise KeyError("Object is not present in snapshot")


def _top_diff(before: dict, after: dict) -> list[dict]:
    rows = []
    for key in sorted(set(before) | set(after)):
        in_b, in_a = key in before, key in after
        if in_b and in_a and before[key] == after[key]:
            continue
        kind = "added" if not in_b else "removed" if not in_a else "changed"
        rows.append({"field": key, "before": before.get(key), "after": after.get(key), "kind": kind})
    return rows


def _plan_restore(snapshot_id: str, key: str | None = None, device_id: str | None = None, client=None) -> dict:
    snap = load_snapshot(snapshot_id)
    obj = _find_object(snap, key, device_id)
    client = client or get_mist_client()
    plan: dict = {
        "snapshot": snap["id"],
        "snapshot_created_at": snap.get("created_at"),
        "key": obj["key"],
        "kind": obj.get("kind"),
        "kind_label": obj.get("kind_label"),
        "name": obj.get("name"),
        "site_id": obj.get("site_id"),
        "device_id": obj.get("id") if obj.get("kind") == "device" else None,
        "device_name": obj.get("name"),
        "saved": obj.get("data"),
    }
    if obj.get("kind") not in RESTORABLE:
        plan.update(
            {"supported": False, "reason": "NodeWatch does not write this object type. Download the JSON instead."}
        )
        return plan
    try:
        live_raw = _read_live(client, obj)
    except Exception as exc:
        if getattr(exc, "status_code", None) == 404:
            plan.update(
                {
                    "supported": False,
                    "reason": "This object no longer exists in Mist. Download the JSON to re-create it.",
                }
            )
            return plan
        raise
    if not live_raw:
        plan.update(
            {"supported": False, "reason": "This object no longer exists in Mist. Download the JSON to re-create it."}
        )
        return plan
    fp_key = _fingerprint_key()
    current = _writeable(live_raw)
    proposed_redacted = _writeable(obj.get("data") or {})
    proposed, notes = fill_redacted(proposed_redacted, current, key=fp_key)
    missing = [n["path"] for n in notes if n["state"] == "missing"]
    # Settings added after the snapshot must be cleared, otherwise "rollback" leaves them.
    # Mist clears a field that is sent as null.
    cleared = sorted(k for k in current if k not in proposed)
    request = {**proposed, **{k: None for k in cleared}}
    current_red = redact_config(current, fp_key)
    changes = diff_config(current_red, redact_config(proposed, fp_key))
    # A secret whose live fingerprint differs from the snapshot cannot be put back (we never
    # stored it); the live value is kept and the preview says so.
    secrets_changed = []
    for n in notes:
        if n["state"] != "kept":
            continue
        snap_val = _dig(proposed_redacted, n["path"])
        live_val = _dig(current_red, n["path"])
        if is_redacted(snap_val) and is_redacted(live_val) and snap_val != live_val:
            secrets_changed.append(n["path"])
    top = _top_diff(current, proposed)
    plan.update(
        {
            "supported": not missing,
            "reason": (
                "The snapshot has a redacted secret that no longer exists in Mist ("
                + ", ".join(missing[:5])
                + "). Download the JSON and set the secret by hand."
            )
            if missing
            else "",
            "changes": changes,
            "change_count": len(changes),
            "changed_keys": [r["field"] for r in top],
            "cleared_keys": cleared,
            "diff": top,
            "secrets_kept_from_live": [n["path"] for n in notes if n["state"] == "kept"],
            "secrets_changed_since_snapshot": secrets_changed,
            "current": current_red,
            "proposed": redact_config(proposed, fp_key),
            "_proposed": proposed,
            "_request": request,
            "_live": live_raw,
            "_obj": obj,
            "warning": (
                "Restore writes the saved settings of this object and clears settings added since the snapshot. "
                "Secrets are never stored in snapshots; the current secret values in Mist are kept."
                + (" Inherited site/template configuration is not rewritten." if obj.get("kind") == "device" else "")
            ),
        }
    )
    return plan


def _dig(value: Any, dotted: str) -> Any:
    cur = value
    for part in dotted.split(".") if dotted else []:
        if isinstance(cur, dict):
            cur = cur.get(part)
        elif isinstance(cur, list):
            try:
                cur = cur[int(part)]
            except (ValueError, IndexError):
                return None
        else:
            return None
    return cur


def _public_plan(plan: dict) -> dict:
    out = redact_signed_urls({k: v for k, v in plan.items() if not k.startswith("_")})
    # Never return live secrets: request preview is shown redacted.
    if "_request" in plan:
        out["request"] = redact_config(plan["_request"], _fingerprint_key())
    return out


def _snapshot_live_object(obj: dict, live: dict, reason: str) -> dict:
    """Store a one-object pre-change snapshot of the live object (never raises)."""
    try:
        if not get_policy().get("pre_change_enabled"):
            return {"ok": False, "skipped": True}
        now = datetime.now(timezone.utc)
        site_id = obj.get("site_id") or ""
        live_obj = _make_object(obj["kind"], deepcopy(live), site_id=site_id, obj_id=obj.get("id") or "")
        live_obj["key"] = obj["key"]
        for k in ("name", "kind_label", "site_name"):
            if obj.get(k) and not live_obj.get(k):
                live_obj[k] = obj[k]
        scope = {"org": not site_id, "site_ids": [site_id] if site_id else [], "objects": [obj["key"]]}
        if obj.get("kind") == "device":
            scope["device_ids"] = [obj.get("id")]
        meta = _store(
            {
                "format": FORMAT,
                "id": _new_id("pre-change", now),
                "created_at": now.isoformat(),
                "trigger": "pre-change",
                "reason": redact_text(reason)[:300],
                "scope": scope,
                "site_names": {},
                "objects": {obj["key"]: live_obj},
                "errors": [],
            }
        )
        return {"ok": True, "snapshot": meta["id"]}
    except Exception as exc:
        return {"ok": False, "error": redact_text(str(exc))[:200]}


def restore_object_preview(snapshot_id: str, key: str | None = None, device_id: str | None = None) -> dict:
    return _public_plan(_plan_restore(snapshot_id, key, device_id))


@holds_exit
def restore_object(snapshot_id: str, key: str | None = None, device_id: str | None = None, *, confirmed: bool) -> dict:
    require(CONFIG_RESTORE)  # v0.10.22: per-person permission (desktop: always granted)
    if confirmed is not True:
        raise ValueError("Explicit confirmation is required")
    client = get_mist_client()
    plan = _plan_restore(snapshot_id, key, device_id, client=client)
    if not plan.get("supported"):
        raise ValueError(plan.get("reason") or "This object cannot be restored")
    obj = plan["_obj"]
    # Safety net for the safety net: keep a copy of exactly what is about to be overwritten.
    pre = _snapshot_live_object(obj, plan["_live"], f"Before restoring {plan['name']} from {plan['snapshot']}")
    before = plan["_live"]
    response = _write_live(client, obj, plan["_request"])
    try:
        # Org-level objects (templates) feed many derived site views, so "" flushes every cached read
        # on purpose; the event buffer is kept (see MistClient.clear_cache_matching).
        client.clear_cache_matching(plan["site_id"] or "", plan["key"].split(":", 1)[-1])
    except Exception:  # noqa: BLE001 - the change is written; a failed cache flush only means one stale read
        pass
    after = _read_live(client, obj)
    remaining = _top_diff(_writeable(after), plan["_proposed"])
    verified = not remaining
    record = {
        "tool": "config-backup",
        "action": "restore",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "snapshot": plan["snapshot"],
        "object": plan["key"],
        "object_type": plan["kind_label"],
        "object_name": plan["name"],
        "site_id": plan["site_id"],
        "device_id": plan["device_id"],
        "pre_change_snapshot": pre.get("snapshot"),
        # Config payloads go through the same redaction as snapshots (catches OSPF auth_keys, WEP keys,
        # md5 and other secrets the generic audit redaction does not know about).
        "before": redact_config(before, _fingerprint_key()),
        "request": redact_config(plan["_request"], _fingerprint_key()),
        "response": redact_config(response, _fingerprint_key()),
        "after": redact_config(after, _fingerprint_key()),
        "verified": verified,
        "remaining_differences": remaining,
    }
    path = AuditService().write(record, f"restore_{_safe_name(plan['key'])}")
    validation = None
    if plan["kind"] == "device" and plan["site_id"]:
        try:
            validation = run_validation(
                plan["site_id"], plan["device_id"], expected=plan["_proposed"], label="rollback"
            )
        except Exception as exc:
            validation = {"ok": False, "error": redact_text(str(exc))[:200]}
    with _LIVE_LOCK:
        _LIVE_CACHE.clear()
    fp_key = _fingerprint_key()
    return {
        "ok": True,
        "verified": verified,
        "remaining_differences": redact_config(remaining[:50], fp_key),
        "response": redact_config(response, fp_key) if isinstance(response, (dict, list)) else response,
        "audit_file": path.name,
        "pre_change_snapshot": pre.get("snapshot"),
        "changed_keys": plan["changed_keys"],
        "cleared_keys": plan["cleared_keys"],
        "validation": validation,
        "message": f"{plan['name']} matches the snapshot."
        if verified
        else f"Restore submitted but {len(remaining)} setting(s) still differ from the snapshot; review the audit record.",
    }




__all__ = [
    "capture",
    "compare",
    "compare_objects",
    "create_full_snapshot",
    "create_snapshot",
    "delete_snapshot",
    "export_snapshot",
    "get_object",
    "get_policy",
    "import_snapshot",
    "list_snapshots",
    "overview",
    "prune",
    "restore_object",
    "restore_object_preview",
    "run_scheduled_snapshot",
    "save_policy",
    "set_pinned",
    "snapshot_before_change",
    "template_drift",
]
