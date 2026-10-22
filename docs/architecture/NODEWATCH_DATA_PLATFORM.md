# NodeWatch Data Platform Architecture — v0.10.0

## Governing principle

**Vendors plug into NodeWatch. NodeWatch features do not plug directly into vendors.**

```text
External vendors
  Mist / Strata / future providers
          |
          v
Provider adapters + vendor manifests
          |
          v
Generic query + resilience + cache
          |
          v
Canonical versioned records + raw backend store
          |
          v
Event bus + field registry
          |
          v
Investigation + timeline services
          |
          v
Device Finder / Security / Operations Assistant / future modules
```

## Rules locked by this release

1. UI modules do not construct vendor queries or own vendor credentials.
2. Provider adapters declare capabilities and implement a stable contract.
3. Generic queries use NodeWatch field/operator intent; adapters translate it.
4. Canonical records are vendor-neutral and carry a schema version (the migration registry was removed in v0.10.7 because no migrations existed; reintroduce it with the first real schema change).
5. Raw provider payloads are backend-only by default and currently ephemeral.
6. Field metadata is centrally registered.
7. Pagination metadata is explicit and cannot be silently discarded.
8. Retry, rate limiting and circuit-breaker behavior is centralized; provider transports still enforce hard network timeouts.
9. Cache tiers are explicit: hot, warm and cold.
10. Capabilities are discovered instead of hard-coded by vendor name.
11. Values from several providers are merged with provenance by `correlation.py` (the separate, unused enrichment pipeline was removed in v0.10.7).
12. Internal events can fan out to independent consumers without one subscriber breaking others.
13. Investigation services sit above providers.
14. Timeline records share a common chronological shape.
15. Operations Assistant consumes a NodeWatch data facade rather than vendor authentication/request construction.
16. Vendor adapters are internal and allow-listed; arbitrary runtime plugin loading is intentionally not enabled.

## Traffic & Sessions

The Traffic & Sessions UI is provider-neutral. `traffic_framework` is a facade; the approved `strata_logging_service` adapter advertises `traffic.sessions` only after a verified live query. Since v0.10.7 that adapter uses the Strata Cloud Manager Log Viewer API (see `docs/CHANGELOG_v0.10.7.md`). No Panorama/PAN-OS provider code is present.

## Security boundaries

- Raw vendor records are not included in `CanonicalRecord.public_dict()` unless explicitly requested by backend code.
- The raw-record store is memory-only, TTL-bound and size-bounded.
- Generic query operators are allow-listed; feature code cannot pass raw vendor query syntax through the generic API.
- Multiple providers for the same capability are not silently resolved. An explicit authority/aggregation policy is required.
- Vendor plugins are not dynamically loaded from arbitrary paths.
- Loopback-only binding, the per-launch request token (required on every API call since v0.10.7), CSP, host validation and the credential store are described in `docs/SECURITY_MODEL.md`.
