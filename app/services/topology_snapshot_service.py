"""Topology change awareness (v0.10.18): compare a site's map with a saved baseline.

The first time a site's map is built its devices and links are saved as the baseline (a small JSON
file per site under the data folder). Every later build is compared with it: devices and links that
are new, and ones that disappeared (drawn as ghosts on the map). "Accept changes" replaces the
baseline with the current map. Nothing here calls a source; it only reads the built graph.
"""

from __future__ import annotations

import hashlib
import json
import logging
import threading
import time
from pathlib import Path
from typing import Any

from app.core.config import STATE_ROOT
from app.core.file_utils import write_private_text

log = logging.getLogger("nodewatch.topology")

SNAPSHOT_ROOT: Path = STATE_ROOT / "topology"
MAX_LISTED = 200
_lock = threading.Lock()


def _path(scope: str) -> Path:
    digest = hashlib.sha256(str(scope or "").encode("utf-8")).hexdigest()[:24]
    return SNAPSHOT_ROOT / f"baseline-{digest}.json"


def _snapshot(result: dict[str, Any]) -> dict[str, Any]:
    nodes = {}
    for n in result.get("nodes") or []:
        if n.get("synthetic"):
            continue
        nodes[n["id"]] = {
            "name": n.get("name") or "",
            "role": n.get("role") or "unknown",
            "tier": n.get("tier", 5),
            "uplink": n.get("uplink") or "",
            "model": n.get("model") or "",
            "mgmt_ip": n.get("mgmt_ip") or "",
        }
    links = {}
    for link in result.get("links") or []:
        if link.get("layer") not in ("physical", "lag", "overlay"):
            continue  # inferred L2 / L3 adjacencies come and go with ARP and route tables
        a, b = link.get("a_device"), link.get("b_device")
        if a not in nodes or b not in nodes:
            continue
        links[link["key"]] = {
            "a": a,
            "b": b,
            "layer": link.get("layer"),
            "a_interface": link.get("a_interface") or "",
            "b_interface": link.get("b_interface") or "",
        }
    return {"version": 1, "scope": result.get("scope") or "", "saved_at": time.time(), "nodes": nodes, "links": links}


def _read(scope: str) -> dict[str, Any] | None:
    p = _path(scope)
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    except (OSError, ValueError) as exc:
        log.info("topology: baseline %s unreadable: %s", p.name, exc)
        return None
    if not isinstance(data, dict) or not isinstance(data.get("nodes"), dict) or not isinstance(data.get("links"), dict):
        return None
    return data


def _write(scope: str, snap: dict[str, Any]) -> None:
    p = _path(scope)
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        write_private_text(p, json.dumps(snap, separators=(",", ":")))  # atomic, owner-only (v0.10.40)
    except OSError as exc:
        log.info("topology: baseline %s not saved: %s", p.name, exc)


def changes(result: dict[str, Any]) -> dict[str, Any]:
    """Diff of ``result`` (a built topology) against the saved baseline; saves one when none exists."""
    scope = str(result.get("scope") or "")
    current = _snapshot(result)
    # v0.10.23: never take the automatic first baseline from an incomplete map (a source failed, or the
    # devices-first partial answer): everything would later show as new / missing.
    complete = (
        not result.get("partial")
        and not result.get("degraded")
        and all(s.get("ok", True) for s in result.get("sources") or [])
    )
    with _lock:
        base = _read(scope)
        if base is None:
            if current["nodes"] and complete:
                _write(scope, current)
            return {
                "baseline_at": current["saved_at"] if current["nodes"] and complete else None,
                "new_nodes": [],
                "missing_nodes": [],
                "new_links": [],
                "missing_links": [],
                "total": 0,
            }
    cur_n, base_n = current["nodes"], base["nodes"]
    cur_l, base_l = current["links"], base["links"]
    new_nodes = sorted((k for k in cur_n if k not in base_n), key=lambda k: cur_n[k]["name"].lower())
    missing = sorted((k for k in base_n if k not in cur_n), key=lambda k: str(base_n[k].get("name", "")).lower())
    new_links = [k for k in cur_l if k not in base_l and cur_l[k]["a"] in base_n and cur_l[k]["b"] in base_n]
    gone_links = [k for k in base_l if k not in cur_l]
    return {
        "baseline_at": base.get("saved_at"),
        "new_nodes": new_nodes[:MAX_LISTED],
        "missing_nodes": [{"id": k, **base_n[k]} for k in missing[:MAX_LISTED]],
        "new_links": new_links[:MAX_LISTED],
        "missing_links": [{"key": k, **base_l[k]} for k in gone_links[:MAX_LISTED]],
        "total": len(new_nodes) + len(missing) + len(new_links) + len(gone_links),
    }


def accept(result: dict[str, Any]) -> dict[str, Any]:
    """Make the current map the baseline (POST /api/v1/topology/baseline)."""
    snap = _snapshot(result)
    with _lock:
        _write(str(result.get("scope") or ""), snap)
    return {"baseline_at": snap["saved_at"], "nodes": len(snap["nodes"]), "links": len(snap["links"])}
