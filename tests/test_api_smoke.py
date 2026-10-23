"""Every API route answers without a server error, and the desktop access rules hold.

No vendor is configured in the test data folder, so this is also the "fresh install" path: every page's API
must answer something sensible (data, sample data, 4xx with a reason, or 503 "not configured"), never a 500.
Routes with path parameters get a dummy value; a 404/422 there is fine, a 500 is not.
"""

from __future__ import annotations

import re
import unittest

import tests.support  # noqa: F401
from tests.support.asgi import Client, api_routes

# GET routes that start long-running work or wait on the network even when nothing is configured.
SKIP_GET: set[str] = set()
# Routes allowed to answer 5xx on a fresh install. Empty since Phase 1 ("not configured" now answers 409).
KNOWN_5XX: set[str] = set()


class _App(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import app.main as main

        cls.app = main.app
        cls.client = Client(main.app)
        cls.routes = api_routes(main.app)


class AccessRules(_App):
    def test_token_required_on_api(self):
        r = Client(self.app, token=None).get("/api/status")
        self.assertEqual(r.status, 403)

    def test_wrong_token_refused(self):
        r = Client(self.app, token="not-the-token").get("/api/status")
        self.assertEqual(r.status, 403)

    def test_non_loopback_refused(self):
        r = Client(self.app, host="10.20.30.40").get("/api/status")
        self.assertEqual(r.status, 403)

    def test_cross_site_refused(self):
        r = self.client.get("/api/status", headers={"sec-fetch-site": "cross-site"})
        self.assertEqual(r.status, 403)

    def test_probe_is_token_free_but_carries_no_org_data(self):
        r = Client(self.app, token=None).get("/api/status", params={"probe": "true"})
        self.assertEqual(r.status, 200)
        body = r.json()
        for key in ("api_host", "configuration_errors", "org_scope"):
            self.assertNotIn(key, body)

    def test_oversized_body_refused(self):
        big = {"x": "a" * (11 * 1024 * 1024)}
        r = self.client.post("/api/v1/alerting/settings", json_body=big)
        self.assertEqual(r.status, 413)

    def test_security_headers(self):
        r = self.client.get("/api/status", params={"quick": "true"})
        for h in ("content-security-policy", "x-frame-options", "x-content-type-options", "referrer-policy"):
            self.assertIn(h, r.headers)


class EveryRouteAnswers(_App):
    def test_route_inventory_is_known(self):
        """New or removed routes must be a reviewed change: update tests/baselines/routes.txt."""
        from pathlib import Path

        listed = Path(__file__).with_name("baselines") / "routes.txt"
        current = sorted(f"{m} {p}" for m, p, _ in self.routes)
        expected = [line for line in listed.read_text(encoding="utf-8").splitlines() if line.strip()]
        self.assertEqual(current, expected, "route list changed; review it and update tests/baselines/routes.txt")

    def test_get_routes_never_500(self):
        for method, path, _ in self.routes:
            if method != "GET" or path in SKIP_GET:
                continue
            concrete = re.sub(r"\{[^}]+\}", "test-id", path)
            with self.subTest(path=path):
                r = self.client.get(concrete, timeout=60)
                self.assertLess(r.status, 500, f"{path} → {r.status}: {r.text[:300]}")

    def test_unsafe_routes_reject_empty_bodies_without_500(self):
        for method, path, _ in self.routes:
            if method == "GET" or "shutdown" in path or "exit" in path or f"{method} {path}" in KNOWN_5XX:
                continue
            concrete = re.sub(r"\{[^}]+\}", "test-id", path)
            with self.subTest(route=f"{method} {path}"):
                r = self.client.request(method, concrete, json_body={}, timeout=60)
                self.assertLess(r.status, 500, f"{method} {path} → {r.status}: {r.text[:300]}")


class HomePage(_App):
    def test_home_renders_with_token(self):
        r = self.client.get("/")
        self.assertEqual(r.status, 200)
        from app.core.security import WRITE_REQUEST_TOKEN

        self.assertIn(WRITE_REQUEST_TOKEN, r.text)


if __name__ == "__main__":
    unittest.main()
