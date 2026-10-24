"""The report's performance quick wins (v0.10.53), written as regression tests where there is a clean seam.

Standard library only, no network: the Mist client's HTTP round trip is replaced with a stub.
"""

from __future__ import annotations

import threading
import time
import unittest
from unittest import mock

import tests.support  # noqa: F401
from tests.support import needs_source


def _client():
    from app.core.config import Settings
    from app.services import mist_client as mc

    client = mc.MistClient(Settings(org_id="11111111-1111-1111-1111-111111111111", token="t" * 40))
    return mc, client


class MistWriteInvalidation(unittest.TestCase):
    """Report perf #2: a write no longer clears the whole cache when it does not have to."""

    def _run(self, call):
        mc, client = _client()
        calls = {"clear": 0, "match": []}
        with mock.patch.object(client, "_send", return_value=(None, {})), \
                mock.patch.object(client, "clear_cache", lambda: calls.__setitem__("clear", calls["clear"] + 1)), \
                mock.patch.object(client, "clear_cache_matching", lambda *p: calls["match"].append(p)):
            call(client)
        return calls

    def test_bounce_port_clears_nothing(self):
        calls = self._run(lambda c: c.bounce_device_port("44444444-4444-4444-4444-444444444444", "33333333-3333-3333-3333-333333333333", ["ge-0/0/1"]))
        self.assertEqual(calls["clear"], 0)
        self.assertEqual(calls["match"], [])

    def test_cable_test_clears_nothing(self):
        calls = self._run(lambda c: c.cable_test_from_switch("44444444-4444-4444-4444-444444444444", "33333333-3333-3333-3333-333333333333", "ge-0/0/1"))
        self.assertEqual(calls["clear"], 0)
        self.assertEqual(calls["match"], [])

    def test_device_update_invalidates_site_and_org_only(self):
        site = "22222222-2222-2222-2222-222222222222"
        calls = self._run(lambda c: c.update_site_device(site, "33333333-3333-3333-3333-333333333333", {"x": 1}))
        self.assertEqual(calls["clear"], 0, "a device config write must not wipe the whole cache")
        self.assertEqual(len(calls["match"]), 1)
        parts = calls["match"][0]
        self.assertIn(f"/sites/{site}/", parts)
        self.assertTrue(any("/orgs/" in p for p in parts))


class AuditPeoplePerKeyFlight(unittest.TestCase):
    """Report perf #4: a build for one key no longer blocks a build for a different key."""

    def test_different_keys_run_in_parallel(self):
        from app.services import audit_people

        audit_people.clear_cache()
        started = threading.Barrier(2, timeout=5)

        def slow(duration, *, site_key=None, device_key=None):
            started.wait()  # both builds must be in flight at once, or this times out
            time.sleep(0.05)
            return {"site": site_key}

        with mock.patch.object(audit_people, "_collect", side_effect=slow):
            errors: list = []
            threads = [
                threading.Thread(target=lambda sk: errors.append(audit_people.collect("7d", site_key=sk) is None),
                                 args=("site-a",)),
                threading.Thread(target=lambda sk: errors.append(audit_people.collect("7d", site_key=sk) is None),
                                 args=("site-b",)),
            ]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=5)
            self.assertFalse(any(t.is_alive() for t in threads), "different keys blocked each other")

    def test_same_key_builds_once(self):
        from app.services import audit_people

        audit_people.clear_cache()
        builds = {"n": 0}
        in_build = threading.Event()
        release = threading.Event()

        def slow(duration, *, site_key=None, device_key=None):
            builds["n"] += 1
            in_build.set()
            release.wait(timeout=5)  # hold the build until the second caller is blocked on the key's lock
            return {}

        with mock.patch.object(audit_people, "_collect", side_effect=slow):
            first = threading.Thread(target=lambda: audit_people.collect("7d", site_key="same"))
            first.start()
            self.assertTrue(in_build.wait(timeout=5), "the first build never started")
            second = threading.Thread(target=lambda: audit_people.collect("7d", site_key="same"))
            second.start()
            time.sleep(0.1)  # give the second caller time to reach the key's flight lock
            release.set()
            first.join(timeout=5)
            second.join(timeout=5)
        self.assertEqual(builds["n"], 1, "two callers of the same key should share one build")


class SocDatasetLru(unittest.TestCase):
    """Report perf #9: the SOC dataset cache keeps the last few builds instead of only one."""

    def test_recent_datasets_are_kept(self):
        from app.services.soc import service

        with service._cache_lock:
            service._cache.clear()
            for i in range(service._CACHE_MAX + 3):
                service._cache[("w", f"site-{i}", False, 0, 0)] = (time.time(), {"i": i})
                service._cache.move_to_end(("w", f"site-{i}", False, 0, 0))
                while len(service._cache) > service._CACHE_MAX:
                    service._cache.popitem(last=False)
            self.assertEqual(len(service._cache), service._CACHE_MAX)
            # The oldest were evicted; the most recent survive (not just one).
            self.assertIn(("w", f"site-{service._CACHE_MAX + 2}", False, 0, 0), service._cache)
            self.assertGreater(service._CACHE_MAX, 1)


@needs_source  # reads detective_service.py source; the compiled build has it inside app.<suffix>
class DetectivePrefixOnly(unittest.TestCase):
    """Report perf #8: the detective text search runs the prefix form only (four Mist calls, not eight)."""

    def test_source_runs_prefix_only(self):
        from tests.support import app_dir

        src = (app_dir() / "services" / "detective_service.py").read_text("utf-8")
        # The exact-token variants (text=value) and the separate ":prefix" tasks are gone.
        self.assertNotIn("text=value)", src)
        self.assertNotIn('"wireless:prefix"', src)
        self.assertIn("text=prefix", src)


if __name__ == "__main__":
    unittest.main()
