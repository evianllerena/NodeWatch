"""The "no Mist" baseline: what every page API returns on a fresh install with no vendor connected.

Each GET route is classed as:
  ok          200 with real (here: empty) data
  sample      200 but the answer is sample/simulated data
  needs_setup 4xx/503 explaining that a source must be connected
  needs_input 400/422: the route needs parameters a page would send (a site, a device, a snapshot)
  locked      403: owner-only content
  error       anything else
The recorded classes live in tests/baselines/no_mist.json. A route may move toward "needs_setup" or "ok" (the
neutrality work's goal: say "connect a source that offers X", never show sample data silently) but never
toward "error". Regenerate with: python tests/tools/update_baselines.py --no-mist
"""

from __future__ import annotations

import json
import re
import unittest
from pathlib import Path

import tests.support  # noqa: F401
from tests.support.asgi import Client, api_routes

BASELINE = Path(__file__).with_name("baselines") / "no_mist.json"
RANK = {"error": 0, "sample": 1, "needs_input": 2, "locked": 2, "needs_setup": 2, "ok": 3}
SKIP = {"/api/v1/system/shutdown"}


def classify(status: int, body: bytes) -> str:
    text = body[:200_000].decode("utf-8", "replace").lower()
    if status == 200:
        if re.search(r'"(simulat\w*|sample(_data)?|demo(_mode)?)"\s*:\s*true|"mode"\s*:\s*"(simulation|demo|sample)"', text):
            return "sample"
        return "ok"
    if status in (400, 401, 403, 404, 409, 412, 422, 424, 503) and re.search(
            r"configur|connect|not set up|setup|no source|credential|token|organization|org id|api host", text):
        return "needs_setup"
    if status in (400, 422):
        return "needs_input"
    if status == 403:
        return "locked"
    return "error"


def measure() -> dict[str, str]:
    import app.main as main

    client = Client(main.app)
    out = {}
    for method, path, _ in api_routes(main.app):
        if method != "GET" or "{" in path or path in SKIP:
            continue
        r = client.get(path, timeout=60)
        out[path] = classify(r.status, r.body)
    return out


class NoMistBaseline(unittest.TestCase):
    def test_no_route_gets_worse_without_a_vendor(self):
        baseline = json.loads(BASELINE.read_text("utf-8"))
        now = measure()
        worse = {p: (baseline.get(p), c) for p, c in now.items()
                 if p in baseline and RANK[c] < RANK[baseline[p]]}
        self.assertEqual(worse, {}, "a page API got worse with no vendor connected")
        self.assertEqual(sorted(set(now) - set(baseline)), [], "new GET route: regenerate tests/baselines/no_mist.json")


if __name__ == "__main__":
    unittest.main()
