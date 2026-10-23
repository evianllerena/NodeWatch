# CHANGE-006 — Schema Versioning

**Status:** PASS

## Approved objective
Added explicit schema version and ordered migration registry.

## Files modified / added
- `app/integrations/schema.py`
- `app/integrations/models.py`

## Verification
- Python compilation performed after implementation.
- Architecture unit test `test_06_*` passed.
- Regression checks preserve existing provider registration/import behavior.

## Security review
Downgrades are rejected to avoid silently losing newer data.

## Loose ends / improvement opportunities
No migrations are needed yet because canonical schema begins at v1.

## Scope control
No unapproved external provider endpoint, credential model or Panorama integration was introduced by this change.
