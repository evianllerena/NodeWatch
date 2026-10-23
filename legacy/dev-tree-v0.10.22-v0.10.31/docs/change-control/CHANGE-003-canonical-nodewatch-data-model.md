# CHANGE-003 — Canonical NodeWatch Data Model

**Status:** PASS

## Approved objective
Added versioned CanonicalRecord with vendor-neutral data, provenance and backend raw payload support.

## Files modified / added
- `app/integrations/models.py`

## Verification
- Python compilation performed after implementation.
- Architecture unit test `test_03_*` passed.
- Regression checks preserve existing provider registration/import behavior.

## Security review
Raw payload is excluded from public serialization by default.

## Loose ends / improvement opportunities
Domain-specific typed submodels can be added later without replacing the envelope.

## Scope control
No unapproved external provider endpoint, credential model or Panorama integration was introduced by this change.
