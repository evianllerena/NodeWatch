from __future__ import annotations

import time
import unittest

from app.integrations.base import ProviderAdapter, ProviderDescriptor, registry
from app.integrations.cache import TieredCache
from app.integrations.event_bus import EventBus, NodeWatchEvent
from app.integrations.field_registry import FIELD_REGISTRY
from app.integrations.models import CanonicalRecord
from app.integrations.query import NodeWatchQuery, QueryFilter, QueryResult, QUERY_ENGINE
from app.integrations.raw_store import RawRecordStore
from app.integrations.vendor import VENDORS
from app.services.assistant_data_service import ASSISTANT_DATA
from app.services.investigation_service import INVESTIGATION_SERVICE
from app.services.timeline_service import TIMELINE_SERVICE


class FakeProvider(ProviderAdapter):
    descriptor = ProviderDescriptor(
        "qa_fake", "QA Fake", ("qa.records",), vendor="qa", query_capabilities=("qa.records",)
    )

    @property
    def configured(self) -> bool:
        return True

    def query(self, query):
        return QueryResult(
            records=[CanonicalRecord("qa.event", self.provider_id, data={"summary": "ok"})],
            provider_id=self.provider_id,
            next_cursor="next-1",
            has_more=True,
            total=2,
            retrieved_count=1,
        )


class DataPlatformTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if registry.descriptor("qa_fake") is None:
            registry.register(FakeProvider.descriptor, FakeProvider)

    def test_01_provider_contract_and_capabilities(self):
        provider = registry.get("qa_fake")
        self.assertIsInstance(provider, ProviderAdapter)
        self.assertTrue(provider.supports("qa.records"))
        self.assertTrue(provider.configured)

    def test_02_generic_query_engine(self):
        result = QUERY_ENGINE.execute(
            NodeWatchQuery("qa.event", "qa.records", (QueryFilter("device.ip", "eq", "10.0.0.1"),), fresh=True)
        )
        self.assertEqual(result.provider_id, "qa_fake")
        self.assertEqual(result.retrieved_count, 1)

    def test_03_canonical_model_hides_raw_by_default(self):
        record = CanonicalRecord("qa.event", "qa", data={"x": 1}, raw={"secret": "value"})
        self.assertNotIn("raw", record.public_dict())
        self.assertEqual(record.public_dict(include_raw=True)["raw"]["secret"], "value")

    def test_04_raw_store_is_backend_only_and_bounded(self):
        store = RawRecordStore(max_records=100, ttl_seconds=30)
        rid = store.put("qa", {"raw": True})
        self.assertEqual(store.get(rid), {"raw": True})
        self.assertEqual(store.stats()["records"], 1)

    def test_05_field_registry_has_extended_metadata(self):
        field = FIELD_REGISTRY.get("traffic.source_port")
        self.assertIsNotNone(field)
        self.assertEqual(field.data_type, "integer")
        self.assertTrue(field.indexed)

    def test_07_pagination_metadata_survives_dispatch(self):
        result = QUERY_ENGINE.execute(NodeWatchQuery("qa.event", "qa.records", fresh=True))
        self.assertTrue(result.has_more)
        self.assertEqual(result.next_cursor, "next-1")
        self.assertEqual(result.total, 2)

    def test_08_query_validation_blocks_unsupported_operator(self):
        with self.assertRaises(ValueError):
            NodeWatchQuery("qa.event", "qa.records", (QueryFilter("x", "raw-vendor-syntax", "y"),)).validate()

    def test_09_cache_tiers_and_expiry(self):
        cache = TieredCache()
        cache.put("x", 1, tier="hot", ttl_seconds=0.01)
        self.assertEqual(cache.get("x"), 1)
        time.sleep(0.02)
        self.assertIsNone(cache.get("x"))

    def test_10_capability_discovery(self):
        providers = registry.providers_for("qa.records", configured_only=True)
        self.assertEqual([p.provider_id for p in providers], ["qa_fake"])

    def test_12_event_bus_isolates_subscriber_errors(self):
        bus = EventBus()
        called = []
        bus.subscribe("qa", lambda e: called.append(e.event_type))
        bus.subscribe("qa", lambda e: (_ for _ in ()).throw(RuntimeError("boom")))
        errors = bus.publish(NodeWatchEvent("qa", {}))
        self.assertEqual(called, ["qa"])
        self.assertEqual(len(errors), 1)

    def test_13_investigation_service_uses_capability_layer(self):
        caps = INVESTIGATION_SERVICE.capabilities()
        self.assertIn("mist", caps)
        self.assertIn("palo_alto_device_security", caps)

    def test_14_timeline_orders_records(self):
        rows = [
            CanonicalRecord("b", "qa", observed_at="2026-01-01T00:00:02+00:00", data={"summary": "b"}),
            CanonicalRecord("a", "qa", observed_at="2026-01-01T00:00:01+00:00", data={"summary": "a"}),
        ]
        timeline = TIMELINE_SERVICE.from_records(rows)
        self.assertEqual([x.event_type for x in timeline], ["a", "b"])

    def test_15_assistant_consumes_stable_data_boundary(self):
        caps = ASSISTANT_DATA.capability_map()
        self.assertIn("traffic_framework", caps)

    def test_16_internal_vendor_catalog(self):
        ids = {x["vendor_id"] for x in VENDORS.catalog()}
        self.assertTrue({"juniper", "palo_alto", "nodewatch"}.issubset(ids))
        self.assertTrue(all(x["internal"] for x in VENDORS.catalog()))


if __name__ == "__main__":
    unittest.main(verbosity=2)
