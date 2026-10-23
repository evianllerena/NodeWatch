# CHANGE-015 — Operations Assistant Data Interface

**Status:** PASS WITH MIGRATION NOTE

## Approved objective
Assistant now consumes a NodeWatch data facade; traffic/session questions use the investigation layer and Mist authentication/request construction is outside intent logic.

## Files modified / added
- `app/services/assistant_data_service.py`
- `app/services/ai_engineer_service.py`

## Verification
- Python compilation performed after implementation.
- Architecture unit test `test_15_*` passed.
- Regression checks preserve existing provider registration/import behavior.

## Security review
No external AI data exfiltration was added.

## Loose ends / improvement opportunities
Some compatibility methods remain Mist-backed behind the facade until equivalent canonical services exist.

## Scope control
No unapproved external provider endpoint, credential model or Panorama integration was introduced by this change.
