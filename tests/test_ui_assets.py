"""The page and its assets: every /static reference resolves, lazy tool scripts exist, templates render."""

from __future__ import annotations

import re
import unittest

import tests.support  # noqa: F401
from tests.support import app_dir
from tests.support.asgi import Client


class StaticAssets(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import app.main as main

        cls.client = Client(main.app)
        cls.home = cls.client.get("/").text

    def test_every_static_reference_in_the_page_resolves(self):
        refs = sorted(set(re.findall(r"""(?:src|href)=["'](/static/[^"'?#]+)""", self.home)))
        self.assertTrue(refs, "the page references no static files")
        for ref in refs:
            with self.subTest(ref=ref):
                self.assertEqual(self.client.get(ref).status, 200, ref)

    def test_every_static_reference_in_scripts_resolves(self):
        static = app_dir() / "static"
        missing = []
        for js in static.rglob("*.js"):
            for ref in set(re.findall(r"""["'`](/static/[A-Za-z0-9_./-]+\.(?:js|json|css|svg|png|woff2?))["'`?#]""", js.read_text("utf-8", "replace"))):
                if not (app_dir() / ref.lstrip("/")).exists():
                    missing.append(f"{js.name}: {ref}")
        self.assertEqual(missing, [])

    def test_static_files_served_with_security_headers(self):
        r = self.client.get("/static/core.js")
        self.assertEqual(r.status, 200)
        self.assertIn("x-content-type-options", r.headers)


if __name__ == "__main__":
    unittest.main()


class PageMatchesBackend(unittest.TestCase):
    """The page compares its own version and build with the backend's on every status read and shows
    "Build mismatch" when they differ (core.js). A release must stamp both the same."""

    def test_page_build_equals_backend_build(self):
        from app.core.version import APP_BUILD, APP_VERSION

        js = (app_dir() / "static" / "core.js").read_text("utf-8")
        # Quote- and spacing-tolerant so it still matches after the release build minifies core.js.
        self.assertEqual(re.search(r"""FRONTEND_VERSION\s*=\s*['"]([^'"]+)['"]""", js).group(1), APP_VERSION)
        self.assertEqual(re.search(r"""FRONTEND_BUILD\s*=\s*['"]([^'"]+)['"]""", js).group(1), APP_BUILD)

    def test_manifest_build_equals_backend_build(self):
        import json
        from app.core.version import APP_BUILD

        manifest = app_dir().parent / "integrity.json"
        if not manifest.exists():
            self.skipTest("no integrity.json next to app/ (source tree)")
        self.assertEqual(json.loads(manifest.read_text("utf-8"))["build"], APP_BUILD)


class CacheKeys(unittest.TestCase):
    """Static files are cached for a week, keyed by their ?v= value. Pilot builds share version 0.10.42, so the
    key must be the build: keyed on the version, an upgraded app kept the old core.js ("Build mismatch")."""

    def test_every_static_url_on_the_page_carries_the_build(self):
        from app.core.version import APP_BUILD
        import app.main as main

        html = Client(main.app).get("/").body.decode("utf-8")
        refs = re.findall(r'(?:src|href)="(/static/[^"]+)"', html)
        self.assertTrue(refs)
        unkeyed = [r for r in refs if not r.endswith(f"?v={APP_BUILD}")]
        self.assertEqual(unkeyed, [])
