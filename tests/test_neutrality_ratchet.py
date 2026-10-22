"""Vendor-neutrality ratchet: coupling counts may only go down.

Counts live in tests/baselines/neutrality_baseline.json. A count above its baseline fails the run (new
vendor-specific code in shared code). A count below it also fails, with a message to lower the baseline, so the
improvement is locked in. Rules come from docs/VENDOR_NEUTRALITY.md and the plan's audit (N1–N9).
"""

from __future__ import annotations

import json
import re
import unittest
from pathlib import Path

import tests.support  # noqa: F401
from tests.support import app_dir

APP = app_dir()
BASELINE = Path(__file__).with_name("baselines") / "neutrality_baseline.json"
SHARED = ("services", "modules", "core")


def _py(*tops: str):
    for top in tops:
        base = APP / top
        if base.is_file():
            yield base
        else:
            yield from (p for p in base.rglob("*.py") if "__pycache__" not in p.parts)


def measure() -> dict[str, int]:
    shared = [p for p in _py(*SHARED, "main.py") if p.name != "mist_client.py"]
    text = {p: p.read_text("utf-8") for p in shared}
    static = {p: p.read_text("utf-8", "replace") for p in (APP / "static").rglob("*.js")}
    routes = "\n".join(p.read_text("utf-8") for p in _py("modules"))
    return {
        "mist_direct_files": sum(1 for t in text.values() if re.search(r"mist_client|get_mist_client", t)),
        "vendor_extra_reads": sum(len(re.findall(r"\.vendor\[|\.vendor\.get\(|\[\"vendor\"\]\[|\[\"vendor\"\]\.get", t))
                                  for t in text.values()),
        "mist_source_branches": sum(len(re.findall(r"[=!]=\s*[\"']mist[\"']", t)) for t in text.values()),
        "duck_typed_connector_calls": sum(len(re.findall(r"getattr\(\w+,\s*[\"'](?:list_|search_|get_|warm)", t))
                                          + len(re.findall(r"hasattr\(\w+,\s*[\"'](?:list_|acknowledge_|search_)", t))
                                          for t in text.values()),
        "vendor_named_routes": len(re.findall(r"@router\.\w+\(\"[^\"]*(?:mist|palo|strata|forti|panorama|silver|meraki|aruba|cisco)",
                                              routes, re.I)),
        "connector_ids_in_page_scripts": sum(len(re.findall(r"['\"](?:mist|panorama|fortigate|silverpeak_orchestrator|paloalto_scm|snmp)['\"]", t))
                                             for t in static.values()),
        "sdk_imports_from_vendor_modules": len(re.findall(r"from app\.integrations\.providers", (APP / "integrations/connectors/sdk.py").read_text("utf-8"))),
        "legacy_provider_modules": len([p for p in (APP / "integrations" / "providers").glob("*.py") if p.name != "__init__.py"]),
    }


class Ratchet(unittest.TestCase):
    def test_counts_never_rise(self):
        baseline = json.loads(BASELINE.read_text("utf-8"))
        now = measure()
        for key, value in now.items():
            with self.subTest(metric=key):
                self.assertIn(key, baseline, f"new metric {key}: add it to {BASELINE.name}")
                self.assertLessEqual(value, baseline[key], f"{key} rose from {baseline[key]} to {value}")

    def test_improvements_are_locked_in(self):
        baseline = json.loads(BASELINE.read_text("utf-8"))
        now = measure()
        lower = {k: (baseline[k], v) for k, v in now.items() if k in baseline and v < baseline[k]}
        self.assertEqual(lower, {}, "a count went down: lower it in tests/baselines/neutrality_baseline.json "
                                    "(python tests/tools/update_baselines.py --neutrality)")


if __name__ == "__main__":
    unittest.main()
