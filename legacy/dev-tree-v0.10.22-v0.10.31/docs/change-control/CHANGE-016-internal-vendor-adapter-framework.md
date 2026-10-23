# CHANGE-016 — Internal Vendor Adapter Framework

**Status:** PASS

## Approved objective
Added internal vendor manifests and allow-listed adapter catalog for Juniper, Palo Alto and NodeWatch framework providers.

## Files modified / added
- `app/integrations/vendor.py`
- `app/integrations/__init__.py`
- `app/integrations/providers/__init__.py`

## Verification
- Python compilation performed after implementation.
- Architecture unit test `test_16_*` passed.
- Regression checks preserve existing provider registration/import behavior.

## Security review
Dynamic arbitrary third-party code/plugin loading is explicitly not supported.

## Loose ends / improvement opportunities
Future approved vendors add an adapter+manifest without requiring feature modules to know the vendor.

## Scope control
No unapproved external provider endpoint, credential model or Panorama integration was introduced by this change.
