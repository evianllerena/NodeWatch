"""Regenerate the suite's baseline files. Run deliberately, review the diff, commit with the change it reflects.

    python tests/tools/update_baselines.py --routes        # tests/baselines/routes.txt
    python tests/tools/update_baselines.py --permissions   # add new unsafe routes to permission_map.json as "unreviewed"
    python tests/tools/update_baselines.py --no-mist       # tests/baselines/no_mist.json
    python tests/tools/update_baselines.py --neutrality    # LOWER neutrality counts only (never raises them)
    python tests/tools/update_baselines.py --all
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
BASE = REPO / "tests" / "baselines"
sys.path.insert(0, str(REPO))

import tests.support  # noqa: E402,F401


def routes():
    import app.main as main
    from tests.support.asgi import api_routes

    lines = sorted(f"{m} {p}" for m, p, _ in api_routes(main.app))
    (BASE / "routes.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"routes.txt: {len(lines)} routes")


def permissions():
    import app.main as main
    from tests.support.asgi import api_routes

    path = BASE / "permission_map.json"
    current = json.loads(path.read_text("utf-8")) if path.exists() else {}
    added = 0
    for m, p, _ in api_routes(main.app):
        key = f"{m} {p}"
        if m != "GET" and key not in current:
            current[key] = "unreviewed"
            added += 1
    path.write_text(json.dumps(dict(sorted(current.items())), indent=2) + "\n", encoding="utf-8")
    print(f"permission_map.json: {len(current)} unsafe routes ({added} added as unreviewed)")


def no_mist():
    from tests.test_no_mist_baseline import measure

    data = measure()
    (BASE / "no_mist.json").write_text(json.dumps(dict(sorted(data.items())), indent=2) + "\n", encoding="utf-8")
    counts = {}
    for c in data.values():
        counts[c] = counts.get(c, 0) + 1
    print(f"no_mist.json: {counts}")


def neutrality(init: bool = False):
    from tests.test_neutrality_ratchet import BASELINE, measure

    now = measure()
    old = {} if init or not BASELINE.exists() else json.loads(BASELINE.read_text("utf-8"))
    new = {k: (v if init or k not in old else min(v, old[k])) for k, v in now.items()}
    BASELINE.write_text(json.dumps(new, indent=2) + "\n", encoding="utf-8")
    print(f"neutrality_baseline.json: {new}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    for flag in ("routes", "permissions", "no-mist", "neutrality", "all", "init-neutrality"):
        ap.add_argument(f"--{flag}", action="store_true")
    a = ap.parse_args()
    BASE.mkdir(parents=True, exist_ok=True)
    if a.routes or a.all:
        routes()
    if a.permissions or a.all:
        permissions()
    if getattr(a, "no_mist") or a.all:
        no_mist()
    if a.neutrality or a.all:
        neutrality()
    if getattr(a, "init_neutrality"):
        neutrality(init=True)
