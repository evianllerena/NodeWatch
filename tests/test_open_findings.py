"""Open findings from the v0.10.42 review and the vendor-neutrality audit, tracked as tests.

Each test describes the FIXED behaviour and is marked ``expectedFailure`` while the finding is open, so the suite
passes today. When a fix lands the test passes, unittest reports an "unexpected success", the run fails, and
whoever fixed it removes the decorator — the finding is then a permanent regression test. Ids match the plan doc.
"""

from __future__ import annotations

import ast
import json
import re
import unittest
from dataclasses import fields

import tests.support  # noqa: F401
from tests.support import app_dir

APP = app_dir()
open_finding = unittest.expectedFailure


def _src(rel: str) -> str:
    return (APP / rel).read_text(encoding="utf-8")


class _FakeClient:
    def __init__(self, host):
        self.host = host


class _FakeRequest:
    def __init__(self, host):
        self.client = None if host is None else _FakeClient(host)


# ------------------------------------------------------------------ review: Medium


class PermissionCoverage(unittest.TestCase):
    """Medium: TRIAGE / SETTINGS_ADMIN declared but enforced nowhere. Phase 1 maps every unsafe route."""

    @classmethod
    def setUpClass(cls):
        from tests.support.asgi import api_routes
        import app.main as main
        from pathlib import Path

        cls.unsafe = sorted(f"{m} {p}" for m, p, _ in api_routes(main.app) if m != "GET")
        cls.map = json.loads((Path(__file__).with_name("baselines") / "permission_map.json").read_text("utf-8"))

    def test_every_unsafe_route_is_in_the_permission_map(self):
        missing = [r for r in self.unsafe if r not in self.map]
        self.assertEqual(missing, [], "new unsafe route: add it to tests/baselines/permission_map.json")

    @open_finding
    def test_no_unsafe_route_is_unreviewed(self):
        unreviewed = [r for r, v in self.map.items() if v == "unreviewed"]
        self.assertEqual(unreviewed, [])

    @open_finding
    def test_triage_and_settings_permissions_are_enforced_somewhere(self):
        uses = "\n".join(p.read_text("utf-8") for p in APP.rglob("*.py"))
        self.assertRegex(uses, r"require\((?:PERM_)?TRIAGE\)")
        self.assertRegex(uses, r"require\((?:PERM_)?SETTINGS_ADMIN\)")


# ------------------------------------------------------------------ review: Low


class LowFindings(unittest.TestCase):
    @open_finding
    def test_is_loopback_fails_closed_without_client_info(self):
        from app.core.auth import LocalTokenAuth

        self.assertFalse(LocalTokenAuth.is_loopback(_FakeRequest(None)))

    @open_finding
    def test_testclient_sentinel_not_accepted_by_default(self):
        from app.core.auth import LocalTokenAuth

        self.assertFalse(LocalTokenAuth.is_loopback(_FakeRequest("testclient")))

    @open_finding
    def test_console_url_only_http_or_https(self):
        from app.integrations.domain import Alert

        a = Alert(key="k", source="x", type="t", category="connectivity", severity="info", title="t",
                  console_url="javascript:alert(1)")
        self.assertFalse(a.console_url.lower().startswith("javascript:"))

    @open_finding
    def test_soc_collector_and_topology_report_errors_redacted(self):
        self.assertNotRegex(_src("services/soc/collector.py"), r"error=str\(exc\)")
        self.assertNotRegex(_src("services/topology_report.py"), r'job\["error"\] = str\(exc\)')

    @open_finding
    def test_triage_registry_error_redacted(self):
        self.assertNotIn('f"{type(exc).__name__}: {exc}"', _src("services/triage/registry.py"))

    @open_finding
    def test_topology_job_eviction_keeps_running_jobs(self):
        src = _src("services/topology_report.py")
        block = src.split("if len(_jobs) >= MAX_JOBS", 1)[1].split("_jobs[job_id] = job", 1)[0]
        self.assertIn("state", block, "eviction must skip jobs that are still running")

    @open_finding
    def test_default_owner_key_verifier_removed(self):
        """Baseline finding #9."""
        self.assertNotIn("OWNER_KEY_DEFAULT_DIGEST", _src("modules/system/router.py"))

    @open_finding
    def test_keychain_items_use_explicit_accessibility(self):
        self.assertIn("kSecAttrAccessible", _src("core/macos_keychain.py"))


    @open_finding
    def test_missing_configuration_is_not_reported_as_bad_gateway(self):
        """New (test suite): 'not configured' answers 502 Bad Gateway on the test endpoints; it is a 4xx."""
        from tests.support.asgi import Client
        import app.main as main

        c = Client(main.app)
        for path in ("/api/v1/alerting/test", "/api/v1/siem/forwarder/test"):
            with self.subTest(path=path):
                self.assertLess(c.post(path, json_body={}).status, 500)


# ------------------------------------------------------------------ review: cleanup


class Cleanup(unittest.TestCase):
    @open_finding
    def test_no_unreachable_probe_block_in_status(self):
        tree = ast.parse(_src("modules/system/router.py"))
        fn = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "status")
        probe_ifs = [n for n in ast.walk(fn) if isinstance(n, ast.If) and isinstance(n.test, ast.Name) and n.test.id == "probe"]
        self.assertEqual(len(probe_ifs), 1)

    @open_finding
    def test_subscriberless_event_bus_removed(self):
        self.assertFalse((APP / "integrations" / "event_bus.py").exists())

    @open_finding
    def test_soc_collector_stopped_on_shutdown(self):
        lifespan = _src("main.py").split("async def lifespan", 1)[1].split("\napp = ", 1)[0]
        self.assertRegex(lifespan, r"soc|collector")

    @open_finding
    def test_one_html_escape_helper(self):
        copies = [p.name for p in (APP / "static").rglob("*.js")
                  if re.search(r"(const|function) *(esc|escapeHtml|escHtml|_esc)\b", p.read_text("utf-8", "replace"))]
        self.assertLessEqual(len(copies), 1, copies)


# ------------------------------------------------------------------ new: discovery allowlists


class DiscoveryAllowlists(unittest.TestCase):
    @open_finding
    def test_triage_backends_import_from_an_allowlist(self):
        self.assertNotIn("iter_modules", _src("services/triage/registry.py"))

    @open_finding
    def test_triage_sinks_import_from_an_allowlist(self):
        self.assertNotIn("iter_modules", _src("services/triage/sinks/__init__.py"))


# ------------------------------------------------------------------ neutrality audit N1–N9


class Neutrality(unittest.TestCase):
    @open_finding
    def test_N1_records_carry_connection_and_tenant(self):
        from app.integrations import domain

        for cls_name in ("Site", "Device", "Interface", "Alert", "Event", "SecurityEvent"):
            names = {f.name for f in fields(getattr(domain, cls_name))}
            with self.subTest(record=cls_name):
                self.assertTrue({"connection_id", "tenant_id"} <= names)

    @open_finding
    def test_N3_sdk_imports_nothing_vendor_named(self):
        self.assertNotIn("app.integrations.providers", _src("integrations/connectors/sdk.py"))

    @open_finding
    def test_N5_pages_never_default_a_source_to_mist(self):
        self.assertNotRegex(_src("static/modules/alerting.js"), r"\|\|\s*'mist'")

    @open_finding
    def test_N6_triage_does_not_parse_vendor_text(self):
        for rel in ("services/triage/store.py", "services/triage/backends/local.py"):
            with self.subTest(file=rel):
                self.assertNotIn('"in Mist" in by', _src(rel))

    @open_finding
    def test_N9_no_os_specific_credential_text_in_connectors(self):
        hits = [p.relative_to(APP).as_posix() for p in (APP / "integrations" / "connectors").rglob("*.py")
                if "Windows Credential Manager" in p.read_text("utf-8")]
        self.assertEqual(hits, [])


if __name__ == "__main__":
    unittest.main()
