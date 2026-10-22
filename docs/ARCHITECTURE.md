# NodeWatch v0.9.0 Architecture — Unified Device Investigation

## Product boundary

Device Finder is the single engineer-facing workspace for looking up and investigating a device. Vendor integrations are implementation details. Normal users do not select "Mist lookup" or "Palo Alto lookup" and do not see source badges beside fields.

The backend retains provenance, timestamps, authority, health, and provider-specific errors so it can correlate safely, but that metadata is not part of the normal Device Finder presentation.

## Logical flow

```text
Device Finder
    |
    v
Unified Device Resolver
    |
    +-- Search classifier
    +-- Provider capability registry
    +-- Correlation (multi-provider merge with provenance)
    +-- Field registry
    +-- Cache / health / error model
    |
    +-- Mist compatibility provider
    +-- Palo Alto Device Security provider
    +-- future Traffic / SLS provider
    +-- future vendors
```

For an IP query on a network where Device Security knows the endpoint:

```text
IP -> Device Security -> MAC + identity/security
                        |
                        v
                    Mist MAC lookup
                        |
                        v
              switch / member / port / VLAN
                        |
                        v
                 unified device result
```

For a MAC query, Mist and Device Security can be queried concurrently, then correlated by normalized MAC.

## Integration contract

`app/integrations/base.py` provides provider descriptors, health state, and the provider registry. A provider advertises capabilities rather than forcing Device Finder to know vendor internals.

Examples:

- Mist: device/network attachment, site, switch, port, wireless context.
- Device Security: IP/MAC identity, profile/classification, risk, security posture.
- Future SLS provider: traffic/session search, rule/action/application/bytes/session outcome.

A provider failure must degrade only the capability it supplies. It must not crash Device Finder.

## Authentication and secrets

`SecretStore` is the application-facing abstraction. On Windows it delegates to Windows Credential Manager through the existing credential-store implementation. The rest of NodeWatch does not need to know how a secret is physically stored.

Palo Alto Device Security uses OAuth client credentials:

- Client ID, Client Secret, and TSG ID are persisted as an opaque credential payload in Windows Credential Manager.
- Access tokens are short lived and held only by `TokenManager` in process memory.
- Tokens are refreshed before expiry.
- A 401 invalidates the token and permits one authentication retry.
- Tokens are not persisted to JSON, SQLite, diagnostics, or logs.

Future authentication strategies should be added behind the integration framework rather than implemented directly inside Device Finder.

## Destination and TLS safety

The Device Security provider permits only the known Palo Alto HTTPS API and authentication hosts. TLS certificate verification is mandatory. UI configuration cannot redirect the credential-bearing client to an arbitrary host.

Future providers should adopt the same default-deny destination model unless a deliberate, validated custom-endpoint feature is approved.

## Unified field registry

`app/integrations/field_registry.py` defines stable, vendor-neutral field IDs and metadata used by the Device Finder Fields drawer. The registry supports default visibility, category grouping, filtering/search metadata, and sensitivity flags.

Provider code maps vendor-specific response fields into normalized values. The UI consumes stable field IDs rather than raw vendor JSON names.

This allows future integrations to add useful fields without redesigning the Device Finder layout.

## Device Finder progressive disclosure

Default Device Finder intentionally shows a small operational set. Engineers can open the Fields drawer and switch Standard / Network / Security / Identity / Full / Custom views or select extra fields. Empty attributes do not need to clutter the main result.

Provider/source attribution is not shown in normal Device Finder UI. Provenance remains backend-only for correlation, troubleshooting, and future policy decisions.

## Caching

Provider data should use bounded TTL caches. The Device Security provider currently uses a short in-memory cache. Access tokens and response caches die with the process. Future providers should use the shared cache policy rather than building permanent copies of cloud data unless a product requirement explicitly needs history.

## Diagnostics and logging

All integration errors should be sanitized before local logging. Diagnostic exports are a trust boundary:

- known stored secret values are removed,
- Bearer/Basic/JWT/token-like strings are redacted,
- UTF-8 text logs are sanitized before being placed in the ZIP,
- binary/opaque logs are skipped because they cannot be centrally inspected,
- a sanitization report lists skipped files without exposing their contents.

Support packages never intentionally include credentials or raw configuration snapshots.

## Future Traffic & Sessions phase

Traffic & Sessions belongs inside Device Finder and will lazy-load only when the engineer expands it. It is intentionally not active in v0.9.0 until the live Strata Logging Service query path is validated.

The planned backend contract will support controlled, allowlisted fields and operators, server-side filtering, bounded time ranges, pagination, and result limits. The browser will not submit arbitrary raw SLS query expressions.

Planned normalized traffic fields include rule, action, receive time, source/destination, source user, source/destination ports, from/to zones, application, sent/received bytes, protocol, session duration, and session end reason.

## Future-proofing rules

1. Do not create vendor-specific Device Finder tabs.
2. Do not put provider authentication logic into UI modules.
3. Do not persist short-lived access tokens.
4. Do not expose secrets in browser responses or diagnostics.
5. Do not let one provider failure take down a unified result.
6. Do not bulk-copy cloud traffic logs into NodeWatch by default.
7. Add future integrations through provider capabilities and normalized fields.
8. Preserve existing working Mist behavior through adapters before considering deeper refactors.


## v0.10.0 Data Platform Foundation
The governing multi-vendor architecture is documented in `docs/architecture/NODEWATCH_DATA_PLATFORM.md`.
The 16 approved changes and verification records are under `docs/change-control/`.
