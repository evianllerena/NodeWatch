# CHANGE-007 — Central Pagination / Cursor

**Status:** PASS

## Approved objective
QueryResult retains cursor/next_cursor/has_more/total/retrieved_count and enforces page-size maximums.

## Files modified / added
- `app/integrations/query.py`

## Verification
- Python compilation performed after implementation.
- Architecture unit test `test_07_*` passed.
- Regression checks preserve existing provider registration/import behavior.

## Security review
Limits are explicit instead of hidden provider truncation.

## Loose ends / improvement opportunities
Each future adapter must accurately propagate provider cursors/totals.

## Scope control
No unapproved external provider endpoint, credential model or Panorama integration was introduced by this change.
