"""Regression tests for the v0.10.22 security release (stdlib unittest; also collected by pytest).

    python -m unittest discover -s tests -p "test_v0_10_22*.py"
"""

from __future__ import annotations

import gzip
import hashlib
import hmac
import json
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from tests import conftest_env  # noqa: F401  (sets NODEWATCH_DATA first)

from app.core import security
from app.integrations.base import IntegrationError


class LaunchAndIdentityProofs(unittest.TestCase):
    CHALLENGE = "ab" * 32

    def test_launch_proof_matches_spec_and_binds_port(self):
        nonce = "f0" * 32
        expected = hmac.new(nonce.encode(), f"nodewatch-launch:v2:8766:{self.CHALLENGE}".encode(), "sha256").hexdigest()
        self.assertEqual(security.launch_proof(nonce, self.CHALLENGE, 8766), expected)
        self.assertNotEqual(security.launch_proof(nonce, self.CHALLENGE, 8765), expected)

    def test_launch_proof_is_not_the_old_echo(self):
        nonce = "f0" * 32
        self.assertNotEqual(security.launch_proof(nonce, self.CHALLENGE, 8766), hashlib.sha256(nonce.encode()).hexdigest())

    def test_launch_proof_rejects_bad_input(self):
        self.assertIsNone(security.launch_proof("", self.CHALLENGE, 8766))
        self.assertIsNone(security.launch_proof("n" * 64, "not-hex", 8766))
        self.assertIsNone(security.launch_proof("n" * 64, self.CHALLENGE, 0))
        self.assertIsNone(security.launch_proof("n" * 64, self.CHALLENGE, "x"))

    def test_identity_proof_binds_port(self):
        with tempfile.TemporaryDirectory() as state:
            a = security.identity_proof(state, self.CHALLENGE, 8765)
            b = security.identity_proof(state, self.CHALLENGE, 8766)
            self.assertTrue(a and b)
            self.assertNotEqual(a, b, "a proof relayed from another port must not verify")
            key = bytes.fromhex(Path(state, security.IDENTITY_KEY_FILENAME).read_text().strip())
            expected = hmac.new(key, f"nodewatch-identity:v2:8765:{self.CHALLENGE}".encode(), "sha256").hexdigest()
            self.assertEqual(a, expected)
            self.assertIsNone(security.identity_proof(state, self.CHALLENGE, None))


# backup_service only reads os.name; patching the global os.name would break pathlib on Python 3.13.
WINDOWS = __import__("types").SimpleNamespace(name="nt")


class BackupStorage(unittest.TestCase):
    def setUp(self):
        from app.services import backup_service

        self.bs = backup_service

    def test_encrypted_flag_follows_real_outcome(self):
        plain = self.bs._encode({"id": "x", "objects": {}})
        self.assertFalse(self.bs._is_encrypted(plain))
        self.assertTrue(self.bs._is_encrypted(self.bs._DPAPI_MAGIC + b"cipher"))
        meta = self.bs._meta_for({"id": "x", "objects": {}}, len(plain), encrypted=self.bs._is_encrypted(plain))
        self.assertIs(meta["encrypted"], False)

    def test_dpapi_failure_is_not_reported_as_encrypted(self):
        with mock.patch.object(self.bs, "os", WINDOWS), mock.patch.object(self.bs, "_dpapi", side_effect=OSError("no DPAPI")):
            blob = self.bs._encode({"id": "y", "objects": {}})
        self.assertFalse(self.bs._is_encrypted(blob))

    def test_gzip_import_budget(self):
        bomb = gzip.compress(b"0" * (3 * 1024 * 1024))
        with self.assertRaises(ValueError):
            self.bs._gunzip_bounded(bomb, 1024 * 1024)
        self.assertEqual(self.bs._gunzip_bounded(gzip.compress(b"{}"), 1024), b"{}")

    def test_fingerprint_key_upgrade_and_protected_key_not_replaced(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d, ".fingerprint-key")
            path.write_text("11" * 32, encoding="ascii")
            with mock.patch.object(self.bs, "KEY_PATH", path), mock.patch.object(self.bs, "os", WINDOWS), mock.patch.object(
                self.bs, "_dpapi", side_effect=lambda raw, protect: raw[::-1]
            ):
                self.assertEqual(self.bs._fingerprint_key(), bytes.fromhex("11" * 32))
                self.assertTrue(path.read_text().startswith("dpapi:"), "legacy key is re-saved protected")
                self.assertEqual(self.bs._fingerprint_key(), bytes.fromhex("11" * 32))
            with mock.patch.object(self.bs, "KEY_PATH", path), mock.patch.object(self.bs, "_dpapi", side_effect=OSError("locked")):
                with self.assertRaises(OSError):
                    self.bs._fingerprint_key()
                self.assertTrue(path.read_text().startswith("dpapi:"), "an unreadable protected key is never overwritten")


class SiemAndWebhook(unittest.TestCase):
    def test_hec_requires_https(self):
        from app.services import siem_service

        with self.assertRaises(ValueError) as ctx:
            siem_service._normalize_splunk_endpoint("http://splunk.example.com:8088/services/collector/event")
        self.assertIn("https", str(ctx.exception))
        self.assertTrue(
            siem_service._normalize_splunk_endpoint("https://splunk.example.com:8088/services/collector/event").startswith("https://")
        )

    def test_webhook_refuses_redirects(self):
        from app.services import alerting_service

        handler = alerting_service._NoRedirect()
        self.assertIsNone(handler.redirect_request(None, None, 302, "Found", {}, "https://evil.example/"))


class PanoramaXml(unittest.TestCase):
    def test_multibyte_and_nul_refused(self):
        from app.integrations.connectors.panorama.client import parse_xml

        for body in (b"\xff\xfe<\x00r\x00/\x00>\x00", b"\xfe\xff\x00<\x00r\x00/\x00>", b"<r>\x00</r>"):
            with self.assertRaises(IntegrationError):
                parse_xml(body)
        with self.assertRaises(IntegrationError):
            parse_xml(b"<!DOCTYPE r [<!ENTITY a 'b'>]><r>&a;</r>")
        self.assertEqual(parse_xml(b"<response status='success'/>").get("status"), "success")


class ConnectorAllowList(unittest.TestCase):
    def test_unknown_package_is_not_imported(self):
        from app.integrations.connectors import sdk

        self.assertEqual(
            sdk.SHIPPED_CONNECTORS, {"fortigate", "mist", "paloalto_scm", "panorama", "silverpeak_orchestrator", "snmp"}
        )
        pkg_dir = Path(sdk.__file__).parent
        shipped = {p.name for p in pkg_dir.iterdir() if p.is_dir() and not p.name.startswith(("_", "."))}
        self.assertEqual(shipped, set(sdk.SHIPPED_CONNECTORS), "every shipped connector folder is on the allow-list")

    def test_discover_skips_unlisted(self):
        from app.integrations.connectors import sdk

        fake = [mock.Mock(ispkg=True, name="x")]
        fake[0].name = "evil_connector"
        with mock.patch.object(sdk, "_DISCOVERED", False), mock.patch.object(sdk, "_CONNECTORS", {}), mock.patch.object(
            sdk, "_FAILED", {}
        ), mock.patch.object(sdk.pkgutil, "iter_modules", return_value=fake), mock.patch.object(sdk, "_load_one") as load:
            sdk.discover()
            load.assert_not_called()
            self.assertIn("evil_connector", sdk._FAILED)


class PresenceHold(unittest.TestCase):
    def test_holds_exit_counts_while_running(self):
        from app.modules.system import presence

        seen = []

        @presence.holds_exit
        def change():
            seen.append(presence.TRACKER._busy)
            return "done"

        before = presence.TRACKER._busy
        self.assertEqual(change(), "done")
        self.assertEqual(seen, [before + 1])
        self.assertEqual(presence.TRACKER._busy, before)

    def test_write_entry_points_are_wrapped(self):
        from app.services import attention_service, backup_service, operations_service

        for fn in (operations_service.execute_port_action, backup_service.restore_object, attention_service.acknowledge_in_source):
            self.assertTrue(hasattr(fn, "__wrapped__"), fn.__name__)


class PaloAltoTokenLifetime(unittest.TestCase):
    def test_missing_expires_in_defaults_to_900(self):
        src = Path(__file__).resolve().parents[1] / "app/integrations/providers/palo_alto_device_security.py"
        text = src.read_text(encoding="utf-8")
        self.assertIn('int(payload.get("expires_in") or 900)', text)


class MistEventBuffer(unittest.TestCase):
    def test_catch_all_flush_keeps_event_buffer(self):
        from app.services.mist_client import MistClient

        client = MistClient.__new__(MistClient)
        import threading

        client._cache_lock = threading.Lock()
        client._cache = {"/api/v1/sites/s/devices": 1}
        client._forget = lambda key: client._cache.pop(key, None)
        buf = mock.Mock()
        client.__dict__["_event_buffer"] = buf
        client.clear_cache_matching("", "abc")
        self.assertEqual(client._cache, {})
        buf.invalidate.assert_not_called()


if __name__ == "__main__":
    unittest.main()
