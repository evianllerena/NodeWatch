# NodeWatch test suite

Standard library only (`unittest`), so it runs on the interpreter NodeWatch ships, with nothing to install.

```
python tests/run.py                                    # the source tree (this repository)
python tests/run.py --target bundle --root <_internal> # an installed or unpacked release
python tests/run.py -k open_findings -v                # a subset, verbose
python tests/run.py --report result.json               # machine-readable result for release evidence
```

On Windows, against an install, use the bundled interpreter so the test exercises exactly what ships:
`<NodeWatch>\_internal\runtime\python\python.exe tests\run.py --target bundle --root <NodeWatch>\_internal`.
Bundle mode never writes `__pycache__` into the install, because the launcher would quarantine it.

| File | What it proves |
| --- | --- |
| `test_discovery.py` | All 6 connectors and 3 triage backends load. An unlisted connector package is refused and never imported |
| `test_api_smoke.py` | Token, loopback, cross-site and body-size rules hold. All 134 routes are known (`baselines/routes.txt`). No route answers 5xx on a fresh install |
| `test_ui_assets.py` | The page renders, and every `/static` file it or its scripts reference exists |
| `test_security_fixes.py` | Regression tests for the closed baseline findings: redaction, HEC https, UTF-16 XXE guard, pinned requirements |
| `test_integrity.py` | Bundle: every file matches `integrity.json` and nothing unlisted hides in `app/` or `runtime/`. Source: no v0.10.42 file vanished unannounced |
| `test_open_findings.py` | Every open finding (review plus neutrality audit), written as the fixed behaviour and marked `expectedFailure`. A fix turns it into an "unexpected success", which fails the run until the marker is removed |
| `test_neutrality_ratchet.py` | Vendor-coupling counts (`baselines/neutrality_baseline.json`) may only go down |
| `test_no_mist_baseline.py` | What each page API answers with no vendor connected (`baselines/no_mist.json`). It may improve, never regress |

Baselines change only on purpose: `python tests/tools/update_baselines.py --routes | --permissions | --no-mist | --neutrality`.
Review the diff, and record the reason in the plan's change log.

Development note (2026-10-22): the suite was built from the recovered v0.10.42 source and run on Python 3.13
with pydantic 2.13.5. Run it on the bundled 3.12.15 runtime (bundle target) before relying on it for a release.

CI: `.github/workflows/tests.yml` runs the suite on every push with Python 3.12 and the exact package versions
listed in `tests/requirements-ci.txt` (copied from the shipped runtime). It runs the source target only; the
bundle target needs the Windows or macOS bundled interpreter and is run on those machines.
