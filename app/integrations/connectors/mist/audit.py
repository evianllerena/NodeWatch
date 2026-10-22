"""Juniper Mist: audit log and administrators as vendor-neutral records (AUDIT_LOG, DIRECTORY_ADMINS).

The only place that knows Mist's audit field names (v0.10.24):

* ``GET /orgs/{org}/logs`` (``MistClient.search_audit_logs``): ``admin_id``, ``admin_name``, ``email``,
  ``src_ip``, ``user_agent``, ``site_id``, ``device_id`` / ``device_ids``, ``message``, ``timestamp``,
  ``before`` / ``after`` (configuration diff), ``id``;
* ``GET /orgs/{org}/admins``: ``admin_id``, ``first_name``, ``last_name``, ``email``, ``privileges``
  [{``scope`` org | site | sitegroup, ``role`` admin | write | read | helpdesk | installer, ``site_id``,
  ``name``, ``views``}], ``two_factor_verified`` / ``enable_two_factor``, ``last_login``;
* ``GET /orgs/{org}/apitokens``: ``id``, ``name``, ``created_by``, ``privileges``, ``last_used`` (the key
  is dropped by the client and never leaves this module).

Admins and tokens are optional (the API token may not be allowed to list them): ``list_actors`` then
returns what it can, and the audit entries still carry the names Mist recorded.
"""

from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from app.integrations.contracts import AUDIT_LOG, DIRECTORY_ADMINS
from app.integrations.domain import Actor, AuditEntry, normalize_mac, stable_key

SOURCE = "mist"
_ROLE_LABELS = {
    "admin": "Super user (full access)",
    "write": "Network admin (can make changes)",
    "read": "Observer (read-only)",
    "helpdesk": "Helpdesk",
    "installer": "Installer",
    "poweruser": "Power user",
}
_SCOPE_LABELS = {"org": "Whole organization", "msp": "MSP", "orggroup": "Organization group"}
# Readable verb (activity.parse_audit_message) → neutral AuditEntry.action.
_ACTIONS = {
    "Add": "create",
    "Create": "create",
    "Claim": "create",
    "Clone": "create",
    "Import": "create",
    "Update": "update",
    "Edit": "update",
    "Assign": "update",
    "Unassign": "update",
    "Rename": "update",
    "Replace": "update",
    "Move": "update",
    "Enable": "update",
    "Disable": "update",
    "Reset": "update",
    "Delete": "delete",
    "Remove": "delete",
    "Unclaim": "delete",
    "Release": "delete",
    "Revoke": "delete",
    "Login": "login",
    "Logout": "login",
}


def _text(value: Any) -> str:
    return str(value or "").strip()


def _epoch(value: Any) -> float | None:
    try:
        n = float(value)
    except (TypeError, ValueError):
        return None
    if n <= 0:
        return None
    return n / 1000.0 if n > 1e12 else n


def _full_name(row: dict) -> str:
    name = " ".join(x for x in (_text(row.get("first_name")), _text(row.get("last_name"))) if x)
    return name or _text(row.get("name"))


def actor_key(native_id: str) -> str:
    return stable_key(SOURCE, "actor", native_id)


def _roles(privileges: Any, site_names: dict[str, str]) -> list[dict[str, str]]:
    """Mist ``privileges`` → [{"role": readable role, "scope": readable scope}]."""
    out: list[dict[str, str]] = []
    for p in privileges if isinstance(privileges, list) else []:
        if not isinstance(p, dict):
            continue
        role = _ROLE_LABELS.get(_text(p.get("role")).lower(), _text(p.get("role")).replace("_", " ").title())
        scope = _text(p.get("scope")).lower()
        if scope == "site":
            where = f"Site {site_names.get(_text(p.get('site_id'))) or _text(p.get('name')) or 'one site'}"
        elif scope == "sitegroup":
            where = f"Site group {_text(p.get('name')) or _text(p.get('sitegroup_name')) or 'one site group'}"
        else:
            where = _SCOPE_LABELS.get(scope, scope.title() or "Organization")
        if p.get("views"):
            where += f" (views: {', '.join(str(v) for v in p['views'] if v)})"
        row = {"role": role, "scope": where}
        if row not in out:
            out.append(row)
    return out


def _device_mac(device_id: str) -> str:
    """Mist device ids end in the device MAC (``00000000-0000-0000-1000-<mac>``)."""
    tail = re.sub(r"[^0-9a-f]", "", device_id.lower())[-12:]
    return normalize_mac(tail) if len(tail) == 12 else ""


def _duration(hours: int) -> str:
    hours = max(1, int(hours or 168))
    return f"{hours // 24}d" if hours % 24 == 0 else f"{hours}h"


class MistAudit:
    CAPABILITIES: tuple[str, ...] = (AUDIT_LOG, DIRECTORY_ADMINS)

    def _optional_read(self, fn, what: str) -> list[dict]:
        """A read the API token may not be allowed to make (HTTP 403/404): empty, without marking the
        connection unhealthy. Any other failure is raised through ``call`` (redacted, normalised)."""
        try:
            return fn() or []
        except Exception as exc:  # noqa: BLE001
            if getattr(exc, "status_code", None) in (403, 404):
                return []
            failure = exc

            def fail() -> list[dict]:
                raise failure

            return self.call(fail, what)  # type: ignore[attr-defined]  # redacts, records health, normalises

    def _site_names(self) -> dict[str, str]:
        client = self.client  # type: ignore[attr-defined]
        return self.call(client.site_name_map, "read site names") or {}  # type: ignore[attr-defined]

    def list_actors(self) -> list[Actor]:
        client = self.client  # type: ignore[attr-defined]
        site_names = self._site_names()
        with ThreadPoolExecutor(max_workers=2, thread_name_prefix="mist-actors") as pool:
            f_admins = pool.submit(self._optional_read, client.list_org_admins, "list administrators")
            f_tokens = pool.submit(self._optional_read, client.list_org_api_tokens, "list API tokens")
            admins, tokens = f_admins.result(), f_tokens.result()
        actors: list[Actor] = []
        for a in admins:
            native = _text(a.get("admin_id") or a.get("id"))
            if not native and not _text(a.get("email")):
                continue
            two_factor = None
            if a.get("two_factor_verified") is not None or a.get("enable_two_factor") is not None:
                two_factor = bool(a.get("two_factor_verified") or a.get("enable_two_factor"))
            actors.append(
                Actor(
                    key=actor_key(native or _text(a.get("email")).lower()),
                    source=SOURCE,
                    kind="person",
                    name=_full_name(a) or _text(a.get("email")),
                    email=_text(a.get("email")),
                    roles=_roles(a.get("privileges"), site_names),
                    two_factor=two_factor,
                    last_login=_epoch(a.get("last_login") or a.get("last_login_time")),
                    vendor={"admin_id": native},
                )
            )
        for t in tokens:
            native = _text(t.get("id"))
            if not native:
                continue
            actors.append(
                Actor(
                    key=actor_key(native),
                    source=SOURCE,
                    kind="api_token",
                    name=_text(t.get("name")) or "API token",
                    roles=_roles(t.get("privileges"), site_names),
                    last_used=_epoch(t.get("last_used")),
                    created_by=_text(t.get("created_by")),
                    vendor={"token_id": native},
                )
            )
        return actors

    def list_audit(
        self, site_key: str | None = None, *, hours: int = 168, device_key: str | None = None
    ) -> list[AuditEntry]:
        """Audit entries of the last ``hours``. ``device_key`` (optional, beyond the contract) keeps only
        entries that touched that device, filtered before any message parsing or config diffing."""
        from app.core.security import redact_text
        from app.integrations.base import IntegrationError
        from app.modules.history.activity import diff_changes, parse_audit_message, to_epoch, user_agent_label

        client = self.client  # type: ignore[attr-defined]
        site_names = self._site_names()
        try:
            rows = client.search_audit_logs(_duration(hours))
        except Exception as exc:  # noqa: BLE001
            status = getattr(exc, "status_code", None)
            if status in (403, 404):
                # The API token may not read the audit log: a note for the page, not a broken connection.
                product = getattr(getattr(self, "manifest", None), "product", "Mist")
                raise IntegrationError(
                    f"{product}: the audit log is not available to this API token (HTTP {status})",
                    code="PERMISSION_DENIED",
                    status_code=status,
                ) from None
            failure = exc

            def fail() -> list[dict]:
                raise failure

            rows = self.call(fail, "read audit log")  # type: ignore[attr-defined]  # redacts, records health
        directory: dict[str, dict] = {}
        if any(isinstance(r, dict) and (r.get("device_id") or r.get("device_ids")) for r in rows or []):
            try:
                directory = client.device_directory() or {}  # cached; names for the devices a change touched
            except Exception:  # noqa: BLE001 - names are optional
                directory = {}
        out: list[AuditEntry] = []
        for row in rows or []:
            if not isinstance(row, dict):
                continue
            site_id = _text(row.get("site_id"))
            entry_site_key = stable_key("site", SOURCE, site_id) if site_id else ""
            if site_key and entry_site_key != site_key:
                continue
            device_ids = [_text(x) for x in [row.get("device_id"), *(row.get("device_ids") or [])] if _text(x)]
            macs = [m for m in (_device_mac(d) for d in device_ids) if m]
            device_keys = [stable_key("mac", m) for m in macs]
            if device_key and device_key not in device_keys:
                continue
            message = redact_text(
                row.get("message") or row.get("activity") or row.get("text") or row.get("action") or "Audit event"
            )
            parsed = parse_audit_message(message)
            admin_id = _text(row.get("admin_id"))
            names = [str((directory.get(d) or {}).get("name") or "") for d in device_ids]
            ts = to_epoch(row.get("timestamp") or row.get("created_time") or row.get("time")) or 0.0
            out.append(
                AuditEntry(
                    key=stable_key(SOURCE, "audit", _text(row.get("id")) or f"{ts}|{admin_id}|{message}"),
                    source=SOURCE,
                    timestamp=ts,
                    message=message,
                    actor_key=actor_key(admin_id) if admin_id else "",
                    actor_name=_text(row.get("admin_name") or row.get("admin") or row.get("user")),
                    actor_email=_text(row.get("email")),
                    src_ip=_text(row.get("src_ip") or row.get("source_ip")),
                    user_agent=user_agent_label(row.get("user_agent")),
                    site_key=entry_site_key,
                    site_name=_text(row.get("site_name") or site_names.get(site_id, "")),
                    device_keys=device_keys,
                    # A device change whose message names no object: name the device itself.
                    object_type=parsed["object_type"] or ("Device" if any(names) else ""),
                    object_name=parsed["object_name"] or ", ".join(n for n in names if n),
                    action=_ACTIONS.get(parsed["action"], "other"),
                    action_label=str(parsed["action"] or ""),
                    changes=[
                        {
                            "field": str(c.get("label") or c.get("path") or ""),
                            "before": str(c.get("before") or ""),
                            "after": str(c.get("after") or ""),
                            "op": str(c.get("op") or "changed"),
                        }
                        for c in diff_changes(row.get("before"), row.get("after"))
                    ],
                    vendor={"id": _text(row.get("id")), "site_id": site_id, "device_ids": device_ids},
                )
            )
        return out
