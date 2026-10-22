"""Run the NodeWatch test suite against the source tree or a packaged build.

    python tests/run.py                                   # source tree (this repository)
    python tests/run.py --target bundle --root <_internal> # an unpacked release, e.g.
        NodeWatch\\_internal\\runtime\\python\\python.exe tests\\run.py --target bundle --root NodeWatch\\_internal
    python tests/run.py -k discovery                      # only tests whose name contains "discovery"
    python tests/run.py --report report.json              # also write a machine-readable result file

Exit code 0 = all tests passed (expected failures for still-open findings count as passing).
Only the Python standard library is used, so the bundled interpreter can run it as shipped.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", choices=("source", "bundle"), default="source")
    ap.add_argument("--root", help="folder that contains app/ (bundle: the _internal folder)")
    ap.add_argument("-k", dest="pattern", help="only run tests whose id contains this text")
    ap.add_argument("--report", help="write a JSON result file here")
    ap.add_argument("-v", action="store_true")
    args = ap.parse_args()

    os.environ["NODEWATCH_TEST_TARGET"] = args.target
    if args.root:
        os.environ["NODEWATCH_TEST_ROOT"] = str(Path(args.root).resolve())
    elif args.target == "bundle":
        ap.error("--target bundle needs --root <the _internal folder>")
    sys.path.insert(0, str(HERE.parent))
    import tests.support  # noqa: F401  (sets the environment before app is imported)

    suite = unittest.defaultTestLoader.discover(str(HERE), pattern="test_*.py", top_level_dir=str(HERE.parent))
    if args.pattern:
        suite = unittest.TestSuite(t for t in _flatten(suite) if args.pattern in t.id())
    started = time.time()
    result = unittest.TextTestRunner(verbosity=2 if args.v else 1).run(suite)
    if args.report:
        Path(args.report).write_text(json.dumps({
            "target": args.target,
            "root": os.environ.get("NODEWATCH_TEST_ROOT") or str(HERE.parent),
            "python": sys.version.split()[0],
            "seconds": round(time.time() - started, 1),
            "run": result.testsRun,
            "failures": [t.id() for t, _ in result.failures],
            "errors": [t.id() for t, _ in result.errors],
            "skipped": [[t.id(), why] for t, why in result.skipped],
            "expected_failures": [t.id() for t, _ in result.expectedFailures],
            "unexpected_successes": [t.id() for t in result.unexpectedSuccesses],
        }, indent=2), encoding="utf-8")
    return 0 if result.wasSuccessful() else 1


def _flatten(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from _flatten(item)
        else:
            yield item


if __name__ == "__main__":
    sys.exit(main())
