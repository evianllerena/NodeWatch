# CHANGE-012 — Internal Event Bus

**Status:** PASS

## Approved objective
Added thread-safe bounded event history and subscriber fan-out; successful provider queries publish internal events.

## Files modified / added
- `app/integrations/event_bus.py`
- `app/integrations/query.py`

## Verification
- Python compilation performed after implementation.
- Architecture unit test `test_12_*` passed.
- Regression checks preserve existing provider registration/import behavior.

## Security review
Subscriber exceptions are isolated and returned as errors instead of crashing publishers.

## Loose ends / improvement opportunities
Persistence is intentionally not enabled yet; current history is in-memory.

## Scope control
No unapproved external provider endpoint, credential model or Panorama integration was introduced by this change.
