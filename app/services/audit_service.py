"""Redacted local audit-store boundary for operational changes."""

from __future__ import annotations

import json
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from pathlib import Path

from app.core.config import AUDIT_ROOT
from app.core.file_utils import write_private_text
from app.core.security import redact_sensitive


class AuditService:
    def __init__(self, root: str | Path = AUDIT_ROOT):
        self.root = Path(root)

    def write(self, record, name: str) -> Path:
        self.root.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")  # microseconds: no same-second overwrite
        safe_name = (
            "".join(ch if ch.isalnum() or ch in {"-", "_", "."} else "_" for ch in str(name)).strip(".")[:120]
            or "audit"
        )
        path = self.root / f"{stamp}_{safe_name}.json"
        payload = asdict(record) if is_dataclass(record) else record
        write_private_text(path, json.dumps(redact_sensitive(payload), indent=2, default=str))
        return path
