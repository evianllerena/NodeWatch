# CHANGE-013 — Unified Investigation Service

**Status:** PASS

## Approved objective
Added feature-facing investigation service for canonical activity, device investigation and capability discovery.

## Files modified / added
- `app/services/investigation_service.py`
- `app/modules/platform/router.py`

## Verification
- Python compilation performed after implementation.
- Architecture unit test `test_13_*` passed.
- Regression checks preserve existing provider registration/import behavior.

## Security review
Traffic activity handles unavailable providers without leaking vendor errors into UI architecture.

## Loose ends / improvement opportunities
Device investigation currently delegates the proven unified-device service internally; more modules can migrate behind this boundary over time.

## Scope control
No unapproved external provider endpoint, credential model or Panorama integration was introduced by this change.
