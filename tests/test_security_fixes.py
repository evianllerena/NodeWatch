"""Regression tests for the baseline security findings that v0.10.42 closed (report scorecard #1–#11).

If one of these fails, a fixed finding has come back.
"""

from __future__ import annotations

import asyncio
import unittest

import tests.support  # noqa: F401


class Redaction(unittest.TestCase):
    def test_known_and_pattern_secrets_are_scrubbed(self):
        from app.core.security import redact_text

        text = ("failed: Authorization: Bearer abcdefghijklmnop123456 url=https://x.example/?token=SECRET123&a=1 "
                "password=hunter22 jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJlc2lnbmF0dXJl")
        out = redact_text(text, "MYKNOWNSECRET")
        for leaked in ("abcdefghijklmnop123456", "SECRET123", "hunter22", "eyJhbGciOiJIUzI1NiJ9"):
            self.assertNotIn(leaked, out)
        self.assertNotIn("MYKNOWNSECRET", redact_text("x MYKNOWNSECRET y", "MYKNOWNSECRET"))

    def test_http_exception_details_are_redacted_centrally(self):
        """Finding #11: every HTTPException detail passes through redaction."""
        from starlette.exceptions import HTTPException

        import app.main as main

        exc = HTTPException(status_code=502, detail="upstream said Bearer abcdefghijklmnop123456")

        class _Req:
            headers = {}
            scope = {"type": "http"}

        resp = asyncio.run(main._redacting_http_exception_handler(_Req(), exc))
        self.assertNotIn(b"abcdefghijklmnop123456", resp.body)


class Transport(unittest.TestCase):
    def test_splunk_hec_requires_https(self):
        """Finding #7."""
        from app.services.siem_service import _normalize_splunk_endpoint

        with self.assertRaises(ValueError):
            _normalize_splunk_endpoint("http://splunk.example.com:8088/services/collector/event")

    def test_url_validator(self):
        from app.core.security import validate_http_url

        for bad in ("javascript:alert(1)", "ftp://x.example", "https://user:pw@x.example", "https://x.example/#frag", ""):
            with self.subTest(url=bad), self.assertRaises(ValueError):
                validate_http_url(bad)
        with self.assertRaises(ValueError):
            validate_http_url("http://x.example", require_https=True)
        self.assertEqual(validate_http_url("https://x.example/a"), "https://x.example/a")


class SafeXml(unittest.TestCase):
    def test_utf16_and_utf32_bodies_refused(self):
        """Finding #8: multi-byte encodings cannot bypass the DOCTYPE guard."""
        from app.integrations.base import IntegrationError
        from app.integrations.connectors.panorama.client import parse_xml

        payload = '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><x>&e;</x>'
        for enc in ("utf-16", "utf-16-le", "utf-16-be", "utf-32"):
            with self.subTest(enc=enc), self.assertRaises(IntegrationError):
                parse_xml(payload.encode(enc))

    def test_doctype_refused_in_utf8(self):
        from app.integrations.base import IntegrationError
        from app.integrations.connectors.panorama.client import parse_xml

        with self.assertRaises(IntegrationError):
            parse_xml(b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "b">]><x>&a;</x>')

    def test_plain_xml_parses(self):
        from app.integrations.connectors.panorama.client import parse_xml

        self.assertEqual(parse_xml(b"<response status='success'><result>ok</result></response>").tag, "response")


class SupplyChain(unittest.TestCase):
    def test_runtime_requirements_are_pinned(self):
        """Finding #1/#2: every requirement is an exact pin (hashes live in the lock file the launcher uses)."""
        from tests.support import ROOT

        for name in ("requirements.txt", "requirements-optional.txt"):
            path = ROOT / name
            if not path.exists():
                self.skipTest(f"{name} not in this tree")
            for line in path.read_text(encoding="utf-8").splitlines():
                line = line.split("#", 1)[0].strip()
                if line:
                    with self.subTest(file=name, line=line):
                        self.assertRegex(line, r"^[A-Za-z0-9_.\-\[\]]+==[0-9][0-9A-Za-z.\-+]*$")


if __name__ == "__main__":
    unittest.main()


class TokenFreeProbe(unittest.TestCase):
    """v0.10.44 (report: the probe revealed configured, mode and TLS flags): only what the launchers read."""

    def test_probe_answers_only_the_handshake_fields(self):
        import app.main as main
        from tests.support.asgi import Client

        body = Client(main.app, token=None).get("/api/status", params={"probe": "true"})
        self.assertEqual(body.status, 200)
        import json as _json

        keys = set(_json.loads(body.body))
        self.assertLessEqual(keys, {"version", "build", "pid", "port", "read_only", "launch_proof", "identity_proof"})
