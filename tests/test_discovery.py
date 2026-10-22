"""Plugin discovery: connectors, triage backends and triage sinks load, and only what is meant to load.

These are the paths most likely to break under Nuitka (pkgutil.iter_modules + importlib), so they run first
on every target. Expected names are pinned here: adding or removing a plugin is a deliberate, reviewed change.
"""

from __future__ import annotations

import unittest
from unittest import mock

import tests.support  # noqa: F401

EXPECTED_CONNECTORS = {"fortigate", "mist", "paloalto_scm", "panorama", "silverpeak_orchestrator", "snmp"}
EXPECTED_TRIAGE_BACKENDS = {"local", "nodewatch_server", "shared_folder"}


class ConnectorDiscovery(unittest.TestCase):
    def setUp(self):
        from app.integrations.connectors import sdk

        self.sdk = sdk

    def test_allowlist_is_pinned(self):
        self.assertEqual(set(self.sdk.SHIPPED_CONNECTORS), EXPECTED_CONNECTORS)

    def test_every_shipped_connector_loads(self):
        self.sdk.reset_for_tests()
        loaded = {c.manifest.connector_id for c in self.sdk.discover().values()}
        failures = self.sdk.load_failures()
        self.assertEqual(failures, {}, f"connectors failed to load: {failures}")
        self.assertEqual(loaded, EXPECTED_CONNECTORS)

    def test_manifests_validate(self):
        for c in self.sdk.discover().values():
            with self.subTest(connector=c.manifest.connector_id):
                self.assertEqual(c.manifest.validate(), [])
                self.assertIsNotNone(c.manifest.setup, "every connector needs an Add-connection guide")

    def test_unlisted_package_is_refused_and_never_imported(self):
        import pkgutil

        real = pkgutil.iter_modules

        def with_intruder(path=None, prefix=""):
            yield from real(path, prefix)
            yield pkgutil.ModuleInfo(None, "dropped_in_evil", True)

        self.sdk.reset_for_tests()
        with mock.patch.object(self.sdk.pkgutil, "iter_modules", with_intruder), \
                mock.patch.object(self.sdk, "_load_one", wraps=self.sdk._load_one) as load_one:
            self.sdk.discover()
            imported = {call.args[1] for call in load_one.call_args_list}
        self.assertNotIn("dropped_in_evil", imported)
        self.assertIn("dropped_in_evil", self.sdk.load_failures())
        self.sdk.reset_for_tests()
        self.sdk.discover()


class TriageDiscovery(unittest.TestCase):
    def test_backends_load(self):
        from app.services.triage import registry

        registry.reset_for_tests()
        names = set(registry.discover())
        self.assertEqual(registry.load_failures(), {})
        self.assertEqual(names, EXPECTED_TRIAGE_BACKENDS)

    def test_sinks_load(self):
        from app.services.triage import sinks

        sinks.discover()
        self.assertTrue(sinks.registered(), "at least the built-in sink must register")


if __name__ == "__main__":
    unittest.main()
