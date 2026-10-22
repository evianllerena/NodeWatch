# NodeWatch v0.10.7 — Log Viewer traffic + hardening

Build: `2026-10-09-v0.10.7-logviewer-hardening-r2`

r2: Log Viewer query timeout default raised to 90 s (a real verification took ~33 s; installs that
still had the old 45 s default are upgraded automatically); launcher log states whether dependencies were
hash-verified; leftover files from older releases are moved to the quarantine folder instead of blocking startup.

## Root cause of "SLS_PERMISSION_DENIED … HTTP 403 Access denied" (v0.10.3–v0.10.6)

OAuth succeeded, then NodeWatch sent `POST https://api.strata.paloaltonetworks.com/logging-service/v1/queries`.
That path belongs to the retired Logging Service v1 API, on a host that does not serve it, and that API never
accepted Common Services (TSG service-account) tokens. Palo Alto's gateway answered `403 {"msg":"Access denied"}`
regardless of the account's roles. The "needs SOC Analyst / View Only Administrator" text was NodeWatch's own
guess, appended to every 403.

A HAR capture from Strata Cloud Manager showed the console querying the **Log Viewer API**:
`POST https://pa-us01.api.prismaaccess.com/api/sase/v3.0/resource/query/logviewer/firewall_traffic` with
`Prisma-Tenant` and a JSON filter body. v0.10.7 uses that API.

## Traffic & Sessions
- New query path (Log Viewer), regional **Log query host** setting (allow-listed to `*.api.prismaaccess.com`)
  and optional **Prisma-Tenant override**.
- IP lookups query source and destination in parallel and merge newest-first; page-number pagination with
  cursors bound to the query.
- 403/404 messages state the host, tenant and Palo Alto's exact response instead of guessing a role.
- Configs saved by older versions must be re-verified once.
- Fixed: traffic table crashed whenever sessions existed (`formatBytes` was undefined).
- Fixed: slow-but-successful queries were discarded and retried (time budget checked after success).
- Fixed: naming a provider explicitly bypassed the enabled/verified gate; cached traffic survived disable/reset.
- "Verify Again" with the switch off is remembered (Verified · Disabled).
- Palo Alto credentials can be saved with an OAuth-only check when Device Intelligence is off.

## Production write safety (Mist)
- Port actions: port must exist on the switch; uplink/VC/AE/management ports need a protected-port override
  (UI asks twice); usage/speed/duplex allow-listed; strict boolean confirmation; unknown switch MAC no longer
  merges every port in the site.
- Rollback: ignores server-managed fields, clears settings added since the snapshot, verifies the whole writable
  config and reports remaining differences. Drift shows added/removed/changed.
- Virtual Chassis: `preprovisioned` and `original_members` required; master/backup kept distinct; VC ports
  preserved; malformed member IDs return 400; role changes Mist cannot confirm are reported as unconfirmed.
- Validation: unknown connection state no longer passes; only open config-failure alarms for this device count;
  report filenames cannot escape their folder.

## Reliability
- Mist client: IDs validated before use in URLs; timeouts/resets wrapped as Mist errors; full pagination
  (page headers and `next` links) instead of stopping at 1000 rows; bounded LRU cache; TLS context reused
  (removes ~30 ms per request).
- Dashboard degrades per section; one failed read no longer returns HTTP 500.
- Alerting: failed polls keep the active-alert set (no alert storms); state saved after each webhook delivery.
- Event correlation accepts ISO/ms/second timestamps; `*_CURRENTLY_DOWN` items get the right explanation.
- Sample data is flagged (`"sample": true`) and labelled in Inventory, Chassis Manager and Marvis output.

## Security
- Per-launch token required on every API request (reads too), except the minimal launcher probe.
- Launcher reuse requires an HMAC identity proof with a per-install key (Go and Python launchers).
- Integrity manifest must cover the bundled runtime; unlisted code files block startup; generator script added.
- Dependencies install only from hash-pinned `requirements.lock`; runtime zip hash verified; unused
  `cryptography` dependency removed.
- Redaction covers JSON/quoted secrets; support summary scrubbed; old diagnostic zips pruned (keep 5).
- Owner sessions expire; owner-key lockout is per browser with backoff.
- Persistent warning while Mist TLS verification is off; HTML/CSS-class escaping fixes; nav badges work again.
- Atomic writes use unique temp files; integrations settings and diagnostics logs written under file locks.

## Cleanup
- Removed unused enrichment pipeline and schema-migration registry, dead functions and imports.
- CEF export escaping corrected; product version no longer hard-coded.
- Frontend formatted with Prettier, Python with Ruff; ESLint and Ruff configs added (both clean).

## Independent review fixes
A separate review of the full diff found eleven defects, all fixed with regression tests:
VC apply refused (409) after a master/backup switchover; lock file only covered Python 3.12 (now 3.10–3.13);
`requirements.lock` not checked against the manifest; `.pyc` caches and bundled-runtime files could bypass the
unlisted-code check (bytecode cache now lives in the data folder, runtime files must all be listed); owner-key
lockout bypassable by changing the User-Agent (global cap added); a failed page request invalidated its cursor;
cursors broke when the time window moved; `query_timeout` unused; credential changes did not refresh Traffic &
Sessions; disabling could fail without credentials; channelized ports (`et-0/0/48:1`) rejected. Also: uplinks
defined by range keys are protected, more server-managed fields excluded from rollback, post-change validation
reads only the last day of alarms.

## Tests
149 automated tests (Python + Node). New behavioural suites use a response captured from SCM Log Viewer,
fake Mist clients for every write path, FastAPI endpoint calls, and Node tests that render the traffic table
and drive the Strata settings controls. An optional live test queries your tenant when credentials are set.
Removed tests that encoded the retired `/logging-service/v1/queries` endpoint in their mocks.

## Action required before shipping
1. `release\Update-Lockfile.ps1` (creates `requirements.lock`). The shipped v0.10.7 build has no lock yet, so on
   first start it installs the pinned `requirements.txt` versions without hash checks, as v0.10.6 did.
2. `python release\generate_integrity.py --update-launcher`, build and sign the launcher
   (`docs/RELEASE_PROCESS.md`).
3. In Settings → Traffic & Sessions: confirm the log query host and turn the switch on.
