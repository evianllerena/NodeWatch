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

    def test_no_unsafe_route_is_unreviewed(self):
        unreviewed = [r for r, v in self.map.items() if v == "unreviewed"]
        self.assertEqual(unreviewed, [])

    def test_permission_map_matches_the_app(self):
        from app.core.route_permissions import ROUTE_PERMISSIONS

        self.assertEqual(self.map, {k: (v or "none") for k, v in ROUTE_PERMISSIONS.items()})

    def test_triage_and_settings_permissions_are_enforced_somewhere(self):
        """A principal without permissions gets 403 from every route that names one, before the route runs."""
        import app.main as main
        from app.core.auth import AuthResult, Principal
        from app.core.route_permissions import ROUTE_PERMISSIONS
        from tests.support.asgi import Client

        nobody = Principal(id="t", display="t", kind="user", permissions=frozenset())
        real = main.AUTH_PROVIDER.authenticate
        main.AUTH_PROVIDER.authenticate = lambda request, path: AuthResult(principal=nobody)
        try:
            c = Client(main.app)
            guarded = [k for k, v in ROUTE_PERMISSIONS.items() if v]
            self.assertTrue({"alerts.triage", "settings.admin"} <= set(ROUTE_PERMISSIONS.values()))
            for key in guarded:
                method, path = key.split(" ", 1)
                url = re.sub(r"\{[^}]+\}", "x", path)
                with self.subTest(route=key):
                    self.assertEqual(c.request(method, url, json_body={}).status, 403)
        finally:
            main.AUTH_PROVIDER.authenticate = real


class OwnerCheckDisclosure(unittest.TestCase):
    """Medium (fixed in Phase 1): an unverifiable shared triage folder is disclosed where people act, not only in Settings."""

    def test_team_summary_carries_owner_check(self):
        from app.services import attention_service

        self.assertIn("owner_check", attention_service.team_summary())

    def test_command_center_shows_it(self):
        js = _src("static/modules/dashboard.js")
        self.assertEqual(js.count("owner_check === 'unavailable'"), 2)  # header line and incident Team section


# ------------------------------------------------------------------ review: Low


class LowFindings(unittest.TestCase):
    def test_is_loopback_fails_closed_without_client_info(self):
        from app.core.auth import LocalTokenAuth

        self.assertFalse(LocalTokenAuth.is_loopback(_FakeRequest(None)))

    def test_testclient_sentinel_not_accepted_by_default(self):
        from app.core.auth import LocalTokenAuth

        self.assertFalse(LocalTokenAuth.is_loopback(_FakeRequest("testclient")))

    def test_console_url_only_http_or_https(self):
        from app.integrations.domain import Alert

        a = Alert(key="k", source="x", type="t", category="connectivity", severity="info", title="t",
                  console_url="javascript:alert(1)")
        self.assertEqual(a.console_url, "")

    def test_console_url_keeps_vendor_deep_links(self):
        """Fixed in Phase 1: the check must not drop real links. Mist routes on a '#!' fragment."""
        from app.integrations.domain import Alert, Device

        mist = "https://manage.mist.com/admin/?org_id=o#!dashboard/insights/s"
        a = Alert(key="k", source="x", type="t", category="connectivity", severity="info", title="t", console_url=mist)
        self.assertEqual(a.console_url, mist)
        for bad in ("data:text/html,x", "//host/x", "https://user:pw@host/", "/relative"):
            with self.subTest(url=bad):
                self.assertEqual(Device(key="d", source="x", name="n", console_url=bad).console_url, "")

    def test_topology_eviction_refuses_when_every_slot_is_running(self):
        from app.services import topology_report as tr

        saved = dict(tr._jobs)
        try:
            tr._jobs.clear()
            for i in range(tr.MAX_JOBS):
                tr._jobs[f"r{i}"] = {"state": "running", "started": float(i)}
            with self.assertRaises(tr.TooManyJobs):
                tr.start()
            self.assertEqual(sorted(tr._jobs), sorted(f"r{i}" for i in range(tr.MAX_JOBS)))
        finally:
            tr._jobs.clear()
            tr._jobs.update(saved)

    def test_soc_collector_and_topology_report_errors_redacted(self):
        self.assertNotRegex(_src("services/soc/collector.py"), r"error=str\(exc\)")
        self.assertNotRegex(_src("services/topology_report.py"), r'job\["error"\] = str\(exc\)')

    def test_triage_registry_error_redacted(self):
        self.assertNotIn('f"{type(exc).__name__}: {exc}"', _src("services/triage/registry.py"))

    def test_topology_job_eviction_keeps_running_jobs(self):
        src = _src("services/topology_report.py")
        block = src.split("if len(_jobs) >= MAX_JOBS", 1)[1].split("_jobs[job_id] = job", 1)[0]
        self.assertIn("state", block, "eviction must skip jobs that are still running")

    def test_default_owner_key_verifier_removed(self):
        """Baseline finding #9: closed by removing Platform Overview and its owner key (you, 2026-10-22)."""
        self.assertNotIn("OWNER_KEY_DEFAULT_DIGEST", _src("modules/system/router.py"))

    def test_platform_overview_is_gone(self):
        from tests.support.asgi import api_routes
        import app.main as main
        from app.core.registry import get_tools

        self.assertEqual([p for _, p, _ in api_routes(main.app) if "platform-overview" in p], [])
        self.assertNotIn("future-tools", [t["id"] for t in get_tools()])
        for rel in ("templates/index.html", "static/core.js", "static/modules/dashboard.js", "static/modules/settings.js"):
            with self.subTest(file=rel):
                self.assertNotRegex(_src(rel), r"platform-overview|future-tools|platformLock|owner_key")
        self.assertNotIn("owner_session", _src("core/security.py"))

    def test_keychain_items_use_explicit_accessibility(self):
        self.assertIn("kSecAttrAccessible", _src("core/macos_keychain.py"))


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
    def test_no_unreachable_probe_block_in_status(self):
        tree = ast.parse(_src("modules/system/router.py"))
        fn = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "status")
        probe_ifs = [n for n in ast.walk(fn) if isinstance(n, ast.If) and isinstance(n.test, ast.Name) and n.test.id == "probe"]
        self.assertEqual(len(probe_ifs), 1)

    def test_subscriberless_event_bus_removed(self):
        self.assertFalse((APP / "integrations" / "event_bus.py").exists())

    def test_soc_store_marks_updated_detections(self):
        """Fixed in Phase 1: an update to a known detection (e.g. a higher count) is saved and bumps the version."""
        import time as _t
        from app.services.soc.store import EventStore

        st = EventStore(persist=False)
        e = {"key": "k1", "timestamp": _t.time(), "count": 1}
        self.assertEqual(st.add("src", [e]), 1)
        v, st._dirty = st.version, False
        self.assertEqual(st.add("src", [dict(e, count=5)]), 0)
        self.assertTrue(st._dirty)
        self.assertEqual(st.version, v + 1)
        st._dirty = False
        st.add("src", [dict(e, count=5)])  # identical: nothing to save
        self.assertFalse(st._dirty)
        self.assertEqual(st.version, v + 1)

    def test_soc_collector_stopped_on_shutdown(self):
        lifespan = _src("main.py").split("async def lifespan", 1)[1].split("\napp = ", 1)[0]
        self.assertRegex(lifespan, r"soc|collector")

    def test_one_html_escape_helper(self):
        """Fixed in v0.10.44: pages alias core.js's nwEscapeHtml; only one escaping table exists."""
        copies = [p.name for p in (APP / "static").rglob("*.js") if "'&': '&amp;'" in p.read_text("utf-8", "replace")]
        self.assertEqual(copies, ["core.js"])

    def test_one_fetch_helper(self):
        """Fixed in v0.10.44: pages call core.js's nwFetchJSON instead of their own fetch-and-parse copies."""
        own = [p.name for p in (APP / "static").rglob("*.js")
               if re.search(r"async function (getJSON|postJSON|api|j|call|vcJSON)\(", p.read_text("utf-8", "replace"))
               and p.name != "core.js"]
        self.assertEqual(own, [])


class SilentExcepts(unittest.TestCase):
    def test_every_silent_broad_except_says_why(self):
        """Fixed in v0.10.44: an `except Exception: pass` carries a reason on the except, the pass or the next line."""
        bare = []
        for p in APP.rglob("*.py"):
            src = p.read_text("utf-8").splitlines()
            for n in ast.walk(ast.parse("\n".join(src))):
                if isinstance(n, ast.ExceptHandler) and len(n.body) == 1 and isinstance(n.body[0], ast.Pass):
                    broad = n.type is None or (isinstance(n.type, ast.Name) and n.type.id in ("Exception", "BaseException"))
                    near = src[n.lineno - 1:n.lineno + 1]
                    if broad and not any("#" in x for x in near):
                        bare.append(f"{p.relative_to(APP)}:{n.lineno}")
        self.assertEqual(bare, [])


# ------------------------------------------------------------------ new: discovery allowlists


class DiscoveryAllowlists(unittest.TestCase):
    def test_triage_backends_import_from_an_allowlist(self):
        self.assertNotIn("iter_modules", _src("services/triage/registry.py"))

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
    def test_N1_stored_keys_carry_connection(self):
        """Fields alone are not enough: site and device keys must differ between two connections of one vendor."""
        import inspect
        from app.integrations.connectors import sdk

        for fn in (sdk.site_key, sdk.device_key, sdk.save_connector_settings):
            with self.subTest(function=fn.__name__):
                self.assertIn("connection_id", inspect.signature(fn).parameters)

    def test_N3_sdk_imports_nothing_vendor_named(self):
        """Fixed in v0.10.45: the shared HTTPS client moved to app.core.http_pool."""
        self.assertNotIn("app.integrations.providers", _src("integrations/connectors/sdk.py"))

    def test_N5_pages_never_default_a_source_to_mist(self):
        """Fixed in v0.10.45: the alert feed says which source unlabelled rows belong to (core_source)."""
        self.assertNotRegex(_src("static/modules/alerting.js"), r"\|\|\s*'mist'")

    def test_N6_triage_does_not_parse_vendor_text(self):
        """Fixed in v0.10.45: older "by" texts are read for any "in <Product>", not one vendor name."""
        for rel in ("services/triage/store.py", "services/triage/backends/local.py"):
            with self.subTest(file=rel):
                self.assertNotRegex(_src(rel), r"[\"']in Mist[\"']")
        from app.services.triage.store import legacy_via
        self.assertEqual(legacy_via("Acknowledged by ana in Mist"), "in Mist")
        self.assertEqual(legacy_via("Acknowledged by ana in Aruba Central"), "in Aruba Central")
        self.assertEqual(legacy_via("NodeWatch (ana)"), "")

    def test_N7_optional_hooks_are_declared(self):
        """Fixed in v0.10.45: features ask sdk.hook() for optional connector hooks; start-up warms every connector."""
        for rel in ("services/topology_service.py", "services/attention_service.py"):
            with self.subTest(file=rel):
                self.assertNotRegex(_src(rel), r"(?:getattr|hasattr)\(\w+,\s*[\"'](?:list_device_facts|list_topology_devices|acknowledge_alert)")
        main = _src("main.py")
        self.assertIn("warm_up_all", main)
        self.assertNotIn("mist_client import warm_up", main)
        from app.integrations.connectors import sdk
        with self.assertRaises(KeyError):
            sdk.hook(object(), "not_a_declared_hook")

    def test_N9_no_os_specific_credential_text_in_connectors(self):
        """Fixed in v0.10.45: help texts name both stores (Windows Credential Manager or the macOS Keychain)."""
        pattern = re.compile(r"Windows[\s\"']*Credential[\s\"']*Manager(?! or the macOS Keychain)|(?<!Windows )Credential Manager")
        hits = [p.relative_to(APP).as_posix() for p in (APP / "integrations" / "connectors").rglob("*.py")
                if pattern.search(p.read_text("utf-8"))]
        self.assertEqual(hits, [])


if __name__ == "__main__":
    unittest.main()
