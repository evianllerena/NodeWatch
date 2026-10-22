"""Who and where: resolve a detection's addresses and sensor to NodeWatch's own assets and sites (v0.10.30).

Built from the topology organisation index (every connected inventory source, already merged and placed on
canonical sites) — so the SOC names "PA-WHL1 at West Hialeah" or "10.40.1.20 (a LAN of West Hialeah)" for
any vendor's detection without asking a vendor anything. Cached for ``TTL_S``.
"""

from __future__ import annotations

import ipaddress
import threading
import time
from typing import Any

TTL_S = 60.0

_PRIVATE = tuple(
    ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fc00::/7")
)


def private_ip(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(str(ip or "").strip())
    except ValueError:
        return False
    return any(a in n for n in _PRIVATE if a.version == n.version)


class Context:
    """Read-only lookups over the organisation index (one instance per refresh)."""

    def __init__(self) -> None:
        self.by_ip: dict[str, dict[str, Any]] = {}
        self.by_record: dict[str, dict[str, Any]] = {}
        self.by_bare: dict[str, dict[str, Any]] = {}
        self.sites: dict[str, str] = {}
        self._lookups: Any = None
        self.ready = False

    @classmethod
    def build(cls) -> "Context":
        ctx = cls()
        try:
            from app.services import topology_search

            idx = topology_search._current()
            ctx._lookups = topology_search.Lookups()
        except Exception:  # noqa: BLE001 - no index yet: detections stay unresolved, never fail
            return ctx
        for n in idx.get("nodes") or []:
            node = {
                "node_id": n.get("id") or "",
                "name": n.get("name") or "",
                "role": n.get("role") or "unknown",
                "site_key": n.get("site_key") or "",
                "site_name": n.get("site_name") or "",
                "model": n.get("model") or "",
            }
            if node["site_key"]:
                ctx.sites[node["site_key"]] = node["site_name"]
            for ip in [n.get("mgmt_ip"), *(n.get("ips") or [])]:
                ip = str(ip or "").split("/", 1)[0].strip()
                if ip:
                    ctx.by_ip.setdefault(ip, node)
            for r in n.get("records") or []:
                ctx.by_record[f"{r.get('source')}:{r.get('key')}"] = node
                ctx.by_bare.setdefault(str(r.get("key") or ""), node)
        ctx.ready = bool(idx.get("built_at"))
        return ctx

    def asset(self, ip: str) -> dict[str, Any] | None:
        """The managed device that owns ``ip``, else a description of the network it is on."""
        ip = str(ip or "").strip()
        if not ip:
            return None
        hit = self.by_ip.get(ip)
        if hit:
            return {**hit, "ip": ip, "managed": True}
        if self._lookups is not None and private_ip(ip):
            try:
                ck, name = self._lookups.site_of_ip(ip)
            except Exception:  # noqa: BLE001
                ck, name = "", ""
            if ck:
                return {"node_id": "", "name": ip, "role": "endpoint", "site_key": ck, "site_name": name, "ip": ip, "managed": False}
        if private_ip(ip):
            return {"node_id": "", "name": ip, "role": "endpoint", "site_key": "", "site_name": "", "ip": ip, "managed": False}
        return None

    def sensor(self, source: str, key: str) -> dict[str, Any] | None:
        if not key:
            return None
        hit = self.by_record.get(f"{source}:{key}") or self.by_bare.get(key)
        if hit:
            return hit
        if self._lookups is not None:
            try:
                ck, name = self._lookups.site_of_record(source, key)
            except Exception:  # noqa: BLE001
                ck, name = "", ""
            if ck:
                return {"node_id": "", "name": "", "role": "", "site_key": ck, "site_name": name}
        return None


_cache: dict[str, Any] = {"at": 0.0, "ctx": None}
_lock = threading.Lock()


def current() -> Context:
    with _lock:
        if _cache["ctx"] is not None and time.time() - _cache["at"] < TTL_S:
            return _cache["ctx"]
    ctx = Context.build()
    with _lock:
        _cache.update(at=time.time(), ctx=ctx)
    return ctx
