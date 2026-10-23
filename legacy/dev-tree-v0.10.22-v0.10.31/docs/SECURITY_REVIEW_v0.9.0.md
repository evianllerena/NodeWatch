# NodeWatch v0.9.0 Security Review

## Scope

This review covers the new integration framework, Palo Alto Device Security OAuth flow, unified Device Finder enrichment, dynamic fields, local credential handling, and diagnostic export changes.

## Secrets

- Mist API token continues to use Windows Credential Manager.
- Palo Alto Device Security OAuth Client ID, Client Secret, and TSG ID are stored in Windows Credential Manager as one opaque credential payload.
- OAuth access tokens are process-memory only through `TokenManager`.
- Browser APIs expose configuration state, not stored credential values.
- No production credentials are embedded in the release package.

## OAuth lifecycle

The Device Security provider obtains an access token only when needed, caches it in memory, refreshes before expiration, and invalidates/retries once on HTTP 401. Infinite authentication retries are prohibited.

## API destination controls

The Device Security API and authentication endpoints are fixed to approved Palo Alto HTTPS hosts. TLS verification cannot be disabled through configuration. This reduces SSRF-style credential redirection and prevents accidental insecure transport.

## Read-only integration

The v0.9.0 Device Security provider implements read-only GET operations for device lookup and a read-only health probe. No device mutation, policy change, tag operation, firewall change, or write API is implemented.

## Browser boundary

Vendor credentials and bearer tokens remain backend-only. Device Finder receives normalized device data, not authentication material. Provider provenance is intentionally retained as backend implementation metadata rather than displayed to normal engineers.

## Logging / diagnostics

Central secret redaction covers known secret values and common Bearer, Basic, JWT, query-string and key/value credential patterns. Device Security timing diagnostics contain operation, timing, status and sanitized error text, not request authorization headers or response bodies.

Support ZIP creation no longer copies arbitrary diagnostic/log files verbatim. UTF-8 text is sanitized in memory before packaging; binary/opaque files are skipped. A sanitization report records skips without including skipped file contents.

## Sensitive operational data

Device Security can expose IPs, MACs, hostnames, serial numbers, risk, zones, classifications, usernames and endpoint posture. v0.9.0 keeps enrichment in a bounded in-memory response cache and does not introduce a new permanent device-intelligence warehouse.

Preview/simulation records shipped with the application are anonymized examples. Production organization names, site IDs, endpoint identifiers, user domains, and validated Device Security test identifiers are not embedded in the release package.

## Traffic logging gate

The Traffic & Sessions UI shell is future-facing only. No Strata Logging Service query capability is enabled in this build. Live SLS permissions, query schema, filtering and pagination must be validated before Phase 5 is activated.

## Remaining release/security items

- Sign `NodeWatch.exe` with a trusted BWN code-signing identity before broad deployment to remove the Windows Unknown Publisher warning and add publisher authenticity.
- Consider an offline, hashed Python wheelhouse for stronger first-run dependency supply-chain control.
- Add automated tests for secret non-persistence and diagnostic redaction as the integration provider count grows.
- For future write-capable providers, keep write capability separate from read providers and require explicit authorization/preview/confirmation controls.
