from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from app.core.config import DIAGNOSTICS_ROOT
from app.core.file_utils import append_jsonl_rotating
from app.core.security import redact_text

_TIMING_LOG = DIAGNOSTICS_ROOT / "integration_api_timing.jsonl"
_MAX_BYTES = 2_000_000
_ALLOWED_META_KEYS = {
    "phase",
    "enabled",
    "verified",
    "sample_count",
    "provider_status",
    "http_method",
    "path",
    "host",
    # v0.10.15 Traffic & Sessions timing (numbers only)
    "connect_ms",
    "wait_ms",
    "download_ms",
    "parse_ms",
    "bytes",
    "wire_bytes",
    "rows",
    "reused_connection",
    "or_query",
}


def record_integration_event(
    *,
    provider: str,
    operation: str,
    ok: bool,
    duration_ms: int = 0,
    status_code: int | None = None,
    error: str = "",
    metadata: dict[str, Any] | None = None,
) -> None:
    """Write a sanitized, credential-free integration trace record.

    This intentionally accepts only a very small metadata allow-list.  Request
    bodies, tokens, credential identifiers and authorization headers must never
    be persisted to diagnostics.
    """
    try:
        record: dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "provider": str(provider)[:80],
            "operation": str(operation)[:120],
            "duration_ms": max(0, int(duration_ms or 0)),
            "status_code": int(status_code) if status_code is not None else None,
            "ok": bool(ok),
        }
        if error:
            record["error"] = redact_text(str(error))[:1000]
        if metadata:
            safe_meta: dict[str, Any] = {}
            for key, value in metadata.items():
                if key not in _ALLOWED_META_KEYS:
                    continue
                if isinstance(value, (str, int, float, bool)) or value is None:
                    safe_meta[key] = value
            if safe_meta:
                record["meta"] = safe_meta
        append_jsonl_rotating(_TIMING_LOG, record, max_bytes=_MAX_BYTES)
    except Exception:
        # Diagnostics must never break the integration workflow.
        pass
