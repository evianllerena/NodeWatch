"""Multiple connections of one connector (N1), through the Settings › Connections API (v0.10.56).

End to end on the ASGI app, no network: a second FortiGate is added, both are configured independently, and the
extra one is removed. Standard library only; the test run has its own empty data folder and credential store.
"""

from __future__ import annotations

import unittest

import tests.support  # noqa: F401


class MultiConnectionApi(unittest.TestCase):
    def setUp(self):
        from app.integrations.connectors import sdk

        self.sdk = sdk
        sdk.reset_for_tests()
        # Start from a clean connectors.json / credential store for every test.
        for c in list(sdk.discover().values()):
            if not c.is_first_connection:
                try:
                    sdk.remove_connection(c.connection_id)
                except ValueError:
                    pass

    def _client(self):
        import app.main as main
        from tests.support.asgi import Client

        return Client(main.app)

    def _fortigate_rows(self, client):
        cat = client.get("/api/v1/connectors").json()["connectors"]
        return [r for r in cat if r.get("connector_id") == "fortigate"]

    def test_add_configure_and_remove_a_second_connection(self):
        c = self._client()

        # One FortiGate row to begin with, and it is the first connection.
        rows = self._fortigate_rows(c)
        self.assertEqual([r["connection_id"] for r in rows], ["fortigate"])
        self.assertTrue(rows[0]["is_first_connection"])

        # Add a second connection.
        added = c.post("/api/v1/connectors/fortigate/connections", json_body={"label": "Branch"})
        self.assertEqual(added.status, 200)
        cid = added.json()["connection_id"]
        self.assertEqual(cid, "fortigate-2")

        rows = {r["connection_id"]: r for r in self._fortigate_rows(c)}
        self.assertEqual(set(rows), {"fortigate", "fortigate-2"})
        self.assertFalse(rows["fortigate-2"]["is_first_connection"])
        self.assertEqual(rows["fortigate-2"]["connection_label"], "Branch")

        # Configure each independently.
        self.assertEqual(c.post("/api/v1/connectors/fortigate", json_body={
            "values": {"base_url": "https://hq.example.com", "api_token": "a" * 30, "vdom": "root"}, "enabled": True,
        }).status, 200)
        self.assertEqual(c.post("/api/v1/connectors/fortigate-2", json_body={
            "values": {"base_url": "https://branch.example.com", "api_token": "b" * 30, "vdom": "dmz"}, "enabled": True,
        }).status, 200)

        first = self.sdk.get_connector("fortigate")
        second = self.sdk.get_connector("fortigate-2")
        self.assertEqual(first.settings()["base_url"], "https://hq.example.com")
        self.assertEqual(second.settings()["base_url"], "https://branch.example.com")
        self.assertEqual((first.secret("api_token"), second.secret("api_token")), ("a" * 30, "b" * 30))
        self.assertEqual((first.tenant_id(), second.tenant_id()), ("root", "dmz"))

        # Removing the extra connection takes it away entirely; the first stays.
        self.assertEqual(c.request("DELETE", "/api/v1/connectors/fortigate-2").status, 200)
        self.assertEqual([r["connection_id"] for r in self._fortigate_rows(c)], ["fortigate"])
        self.assertIsNone(self.sdk.get_connector("fortigate-2"))
        # The first connection still exists and kept its settings.
        self.assertEqual(self.sdk.get_connector("fortigate").settings()["base_url"], "https://hq.example.com")

    def test_cannot_add_a_connection_to_a_managed_elsewhere_connector(self):
        c = self._client()
        # Mist is configured on its own page; it does not take extra SDK connections here.
        r = c.post("/api/v1/connectors/mist/connections", json_body={"label": "Org 2"})
        self.assertEqual(r.status, 409)

    def tearDown(self):
        from app.integrations.connectors import sdk

        for c in list(sdk.discover().values()):
            if not c.is_first_connection:
                try:
                    sdk.remove_connection(c.connection_id)
                except ValueError:
                    pass
            elif not c.manifest.managed_elsewhere:
                try:
                    sdk.remove_connector_settings(c.connection_id)
                except ValueError:
                    pass


if __name__ == "__main__":
    unittest.main()
