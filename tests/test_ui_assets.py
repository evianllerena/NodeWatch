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
