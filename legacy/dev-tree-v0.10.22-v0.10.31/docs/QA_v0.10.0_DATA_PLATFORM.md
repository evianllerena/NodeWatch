# NodeWatch v0.10.0 — Data Platform Foundation QA

## Scope

This release implements the one-time approved 16-change multi-vendor architecture program. It does **not** add an unapproved traffic-log vendor endpoint. Traffic & Sessions stays provider-neutral until an approved adapter advertises the `traffic.sessions` query capability.

## 16-change verification

| # | Change | Result |
|---:|---|---|
| 1 | Generic Provider Interface | PASS |
| 2 | Generic Query Engine | PASS |
| 3 | Canonical NodeWatch Data Model | PASS |
| 4 | Raw Record Preservation | PASS |
| 5 | Field Registry | PASS |
| 6 | Schema Versioning | PASS |
| 7 | Central Pagination / Cursor | PASS |
| 8 | Retry / Rate Limit / Timeout | PASS WITH NOTE |
| 9 | Cache Tiers | PASS |
| 10 | Capability Discovery | PASS |
| 11 | Enrichment Pipeline | PASS |
| 12 | Internal Event Bus | PASS |
| 13 | Unified Investigation Service | PASS |
| 14 | Timeline Engine | PASS |
| 15 | Operations Assistant Data Interface | PASS WITH MIGRATION NOTE |
| 16 | Internal Vendor Adapter Framework | PASS |

Every row has a separate `docs/change-control/CHANGE-xxx-*.md` record with files, security review, verification and loose ends.

## Automated verification

- Python compileall: PASS
- 16 architecture unit tests: PASS (16/16)
- All frontend JavaScript syntax checks: PASS
- FastAPI platform status endpoint through loopback TrustedHost path: PASS
- Existing Traffic & Sessions provider-neutral unavailable state: PASS
- Integration status reports `awaiting_approved_provider`: PASS
- Content-Security-Policy / X-Frame-Options regression: PASS
- HTML duplicate-ID check: PASS (0 duplicates)
- Raw canonical record default serialization does not expose `raw`: PASS
- Search for accidentally carried Panorama traffic implementation (`X-PAN-KEY`, `PanosTrafficConfig`, PAN-OS/Panorama Traffic): PASS, none found
- Operations Assistant no longer constructs a Mist client directly: PASS
- Provider registry validates adapter instance types: PASS
- Ambiguous-provider behavior refuses silent provider choice: covered by design and query engine

## Findings and improvements made during verification

### 1. Raw vendor records can contain sensitive operational data

**Finding:** Full vendor payloads may contain usernames, internal URLs, policy names, device IDs and addressing.

**Change:** Raw records are excluded from public canonical serialization by default. The raw store is memory-only, bounded and TTL-limited. Durable raw-log retention was deliberately not enabled without a separate retention/security approval.

### 2. Capability declaration and generic-query support are not the same thing

**Finding:** Existing adapters can legitimately advertise capabilities that are still served by legacy service APIs, even if their generic `query()` translator is not implemented yet.

**Change:** `ProviderDescriptor` now distinguishes `capabilities` from `query_capabilities`, preventing the new query engine from falsely dispatching to an adapter that cannot translate that query.

### 3. Multiple data sources must not become last-writer-wins

**Finding:** As NodeWatch gains vendors, multiple sources may disagree about identity, risk, status or attachment.

**Change:** Enrichment is additive with provenance, and the existing correlation engine keeps explicit authority/freshness/confidence rules. The query engine also refuses to silently select between multiple query providers.

### 4. Hidden result caps are unacceptable

**Finding:** The previous Device Finder 70/706 incident demonstrates why provider limits cannot be implicit.

**Change:** Generic query results carry cursor, next cursor, `has_more`, provider total and retrieved count. Query page size has an explicit maximum rather than silent truncation.

### 5. Hard version strings existed in provider headers

**Finding:** Mist, Palo Alto Device Security, Splunk and alerting code contained literal `NodeWatch/0.9.2` User-Agent strings.

**Change:** Those now use the central `APP_VERSION`, avoiding future version-string edits across integrations.

### 6. Operations Assistant owned vendor access

**Finding:** Natural-language intent code directly acquired the Mist client.

**Change:** Assistant data access now goes through `OperationsAssistantDataService`; network-session questions use the Investigation Service. Compatibility methods are still Mist-backed behind that boundary until canonical equivalents are available.

### 7. Dynamic third-party plugin loading would expand attack surface

**Finding:** A generic plugin framework could easily become arbitrary code execution if it loaded adapters from user-controlled paths.

**Decision:** v0.10.0 implements an **internal allow-listed adapter catalog only**. No arbitrary runtime plugin loader was added.

### 8. Central hard timeout has a Python limitation

**Finding:** The resilience layer can enforce retry/rate/circuit policy and a total timeout budget, but Python cannot safely kill an arbitrary synchronous provider call after it has blocked.

**Control:** Each real transport adapter must continue to set hard socket/HTTP request timeouts. The central layer catches budget overrun and circuit-breaks repeated failures. Existing Mist and Device Security transports already use bounded request timeouts.

## Known migration debt

The following is intentional, documented debt rather than hidden work:

- Several older Mist-only feature services still call the proven Mist service layer internally. They remain operational and were not rewritten wholesale because that would create avoidable regression risk.
- New multi-vendor development must use the v0.10.0 provider/query/canonical/investigation interfaces.
- As existing modules are materially revised in future work, their vendor access should move behind the new platform boundary.
- The timeline/event bus are currently in-memory. Durable cross-restart event history requires a separately designed retention/storage policy.
- No approved Strata Logging Service traffic-query adapter is implemented in this release. The architecture is ready for it, but the endpoint/credential/query mapping still requires explicit approval.

## Security posture

Existing NodeWatch desktop protections remain in place:

- loopback-only request policy;
- TrustedHost restriction;
- per-launch write token for unsafe API methods;
- cross-site write rejection;
- request-size limits;
- CSP, frame denial, no-sniff and restrictive Permissions-Policy;
- Windows Credential Manager for stored provider secrets;
- integrity manifest verified by the native launcher.

## Release assessment

**Data-platform foundation: PASS.**

**External Strata Traffic & Sessions provider: NOT IMPLEMENTED BY DESIGN / AWAITS SEPARATE APPROVAL.**
