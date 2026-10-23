from __future__ import annotations

import hashlib
import json
import os
import shutil
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from app.core.credential_store import delete_token, load_token, save_token
from app.core.file_utils import write_private_text

APP_DATA_DIRNAME = "NodeWatch"
LEGACY_APP_DATA_DIRNAME = "MistNetworkTools"
MIGRATION_MARKER = ".nodewatch-v0.8.9-migration.json"


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _same_file(a: Path, b: Path) -> bool:
    try:
        if a.stat().st_size != b.stat().st_size:
            return False
        return _file_sha256(a) == _file_sha256(b)
    except OSError:
        return False


def _migrate_legacy_data_root(base: Path) -> Path:
    """Move/merge the old MistNetworkTools profile into NodeWatch without data loss.

    The common case is an atomic rename on the same LOCALAPPDATA volume.  If a
    stale legacy process or an existing NodeWatch directory prevents that, files
    are merged conservatively. Conflicts are retained below migration-backup so
    the legacy directory can be retired without silently overwriting newer data.
    """
    target = base / APP_DATA_DIRNAME
    legacy = base / LEGACY_APP_DATA_DIRNAME
    if not legacy.exists():
        return target

    # Fast/safest path: same-volume atomic directory rename.
    if not target.exists():
        try:
            legacy.rename(target)
            marker = {
                "migration": "v0.8.9",
                "completed_at": datetime.now(timezone.utc).isoformat(),
                "mode": "atomic-rename",
                "legacy_cleanup_pending": False,
            }
            target.mkdir(parents=True, exist_ok=True)
            write_private_text(target / MIGRATION_MARKER, json.dumps(marker, indent=2))
            return target
        except OSError:
            pass

    target.mkdir(parents=True, exist_ok=True)
    backup_root = target / "migration-backup" / "MistNetworkTools-v0.8.9"
    copied = 0
    identical = 0
    conflicts = 0
    errors: list[str] = []

    for source in sorted(legacy.rglob("*"), key=lambda p: (len(p.parts), str(p).lower())):
        try:
            relative = source.relative_to(legacy)
            destination = target / relative
            if source.is_dir():
                destination.mkdir(parents=True, exist_ok=True)
                continue
            if not source.is_file():
                continue
            destination.parent.mkdir(parents=True, exist_ok=True)
            if not destination.exists():
                shutil.copy2(source, destination)
                if not _same_file(source, destination):
                    raise OSError(f"verification failed for {relative}")
                copied += 1
            elif _same_file(source, destination):
                identical += 1
            else:
                conflict_dest = backup_root / relative
                conflict_dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, conflict_dest)
                if not _same_file(source, conflict_dest):
                    raise OSError(f"conflict backup verification failed for {relative}")
                conflicts += 1
        except Exception as exc:  # migration must never block app startup
            errors.append(f"{source.name}: {type(exc).__name__}: {exc}")

    cleanup_pending = True
    if not errors:
        try:
            shutil.rmtree(legacy)
            cleanup_pending = legacy.exists()
        except OSError as exc:
            errors.append(f"legacy cleanup: {type(exc).__name__}: {exc}")

    marker = {
        "migration": "v0.8.9",
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "mode": "verified-merge",
        "copied_files": copied,
        "identical_files": identical,
        "preserved_conflicts": conflicts,
        "legacy_cleanup_pending": cleanup_pending,
        "errors": errors[:20],
    }
    try:
        write_private_text(target / MIGRATION_MARKER, json.dumps(marker, indent=2))
    except Exception:  # noqa: BLE001 - without the marker the migration simply runs again next start
        pass
    return target


def _default_data_root() -> Path:
    explicit = os.environ.get("NODEWATCH_DATA")
    if explicit:
        return Path(explicit).expanduser()

    if os.name == "nt":
        base = Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local")
        return _migrate_legacy_data_root(base)

    if sys.platform == "darwin":
        # v0.10.22 Mac build: the standard per-user location for application data.
        return Path.home() / "Library" / "Application Support" / "NodeWatch"

    # Legacy environment name remains read-only compatibility for non-Windows
    # development/test installs; all new configuration uses NODEWATCH_DATA.
    legacy_explicit = os.environ.get("MIST_NETWORK_TOOLS_DATA")
    if legacy_explicit:
        return Path(legacy_explicit).expanduser()
    return Path.home() / ".nodewatch"


DATA_ROOT = _default_data_root()
SETTINGS_FILE = DATA_ROOT / "settings.json"
AUDIT_ROOT = DATA_ROOT / "audit"
DIAGNOSTICS_ROOT = DATA_ROOT / "diagnostics"
STATE_ROOT = DATA_ROOT / "state"
LOG_ROOT = DATA_ROOT / "logs"
BACKUP_ROOT = DATA_ROOT / "backups"
VALIDATION_ROOT = DATA_ROOT / "validation"
EXPORT_ROOT = DATA_ROOT / "exports"
AUTOMATION_ROOT = DATA_ROOT / "automation"


@dataclass(frozen=True)
class Settings:
    api_host: str = "https://api.mist.com"
    org_id: str = ""
    token: str = ""
    verify_tls: bool = True
    request_timeout: int = 20
    cache_seconds: int = 30
    event_lookback: str = "1d"
    alarm_lookback: str = "30d"
    fallback_to_simulation: bool = False

    @property
    def configured(self) -> bool:
        return bool(self.org_id and self.token and self.api_host)

    @property
    def safe_api_host(self) -> str:
        return self.api_host

    @property
    def public_dict(self) -> dict:
        payload = asdict(self)
        payload.pop("token", None)
        payload["token_present"] = bool(self.token)
        payload["data_root"] = str(DATA_ROOT)
        return payload

    def validate(self) -> list[str]:
        errors: list[str] = []
        if not self.api_host:
            errors.append("Mist API host is missing")
        else:
            parsed = urlparse(self.api_host)
            if parsed.scheme != "https":
                errors.append("Mist API host must use https")
            host = (parsed.hostname or "").lower()
            if host != "api.mist.com" and not host.endswith(".mist.com"):
                errors.append("Mist API host must be a Juniper Mist API hostname")
            if parsed.path not in ("", "/") or parsed.query or parsed.fragment:
                errors.append("Mist API host must contain only the API host, with no /api path or query string")
        if not self.org_id:
            errors.append("Mist organization ID is missing")
        if not self.token:
            errors.append("Mist API token is missing")
        return errors


def _coerce_int(value, default: int, minimum: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return max(minimum, min(maximum, parsed))


def _load_public_settings() -> dict:
    if not SETTINGS_FILE.exists():
        return {}
    try:
        payload = json.loads(SETTINGS_FILE.read_text(encoding="utf-8"))
        return payload if isinstance(payload, dict) else {}
    except Exception:
        return {}


def get_settings() -> Settings:
    payload = _load_public_settings()
    token = load_token(DATA_ROOT)
    return Settings(
        api_host=str(payload.get("api_host") or "https://api.mist.com").strip().rstrip("/"),
        org_id=str(payload.get("org_id") or "").strip(),
        token=token.strip(),
        verify_tls=bool(payload.get("verify_tls", True)),
        request_timeout=_coerce_int(payload.get("request_timeout"), 20, 3, 120),
        cache_seconds=_coerce_int(payload.get("cache_seconds"), 30, 5, 600),
        event_lookback=str(payload.get("event_lookback") or "1d").strip() or "1d",
        alarm_lookback=str(payload.get("alarm_lookback") or "30d").strip() or "30d",
        fallback_to_simulation=bool(payload.get("fallback_to_simulation", False)),
    )


def save_settings(*, api_host: str, org_id: str, token: str | None = None, verify_tls: bool = True) -> Settings:
    DATA_ROOT.mkdir(parents=True, exist_ok=True)
    current = _load_public_settings()
    payload = {
        "api_host": (api_host or "https://api.mist.com").strip().rstrip("/"),
        "org_id": (org_id or "").strip(),
        "verify_tls": bool(verify_tls),
        "request_timeout": _coerce_int(current.get("request_timeout"), 20, 3, 120),
        "cache_seconds": _coerce_int(current.get("cache_seconds"), 30, 5, 600),
        "event_lookback": str(current.get("event_lookback") or "1d"),
        "alarm_lookback": str(current.get("alarm_lookback") or "30d"),
        "fallback_to_simulation": False,
    }
    candidate = Settings(token=(token or load_token(DATA_ROOT)).strip(), **payload)
    validation = candidate.validate()
    if validation:
        raise ValueError("; ".join(validation))
    write_private_text(SETTINGS_FILE, json.dumps(payload, indent=2))
    if token is not None and token.strip():
        save_token(DATA_ROOT, token.strip())
    return get_settings()


def reset_settings() -> None:
    delete_token(DATA_ROOT)
    try:
        SETTINGS_FILE.unlink(missing_ok=True)
    except OSError:
        pass
