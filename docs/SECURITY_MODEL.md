# NodeWatch security model (v0.10.22)

NodeWatch is a **single-user desktop tool**. It holds powerful credentials (a Mist API token that can change
production switches, a Palo Alto service account, device-connector API keys, a Splunk HEC token) and exposes a
local web API on `127.0.0.1`.

## What is protected

| Threat | Control |
|---|---|
| A web page in the user's browser calling the local API (CSRF, DNS rebinding) | Server binds to loopback only; `TrustedHostMiddleware` accepts only `127.0.0.1`/`localhost`; `Sec-Fetch-Site` must be same-origin (or absent/`none`); **every** `/api/` request needs the per-launch token `X-NodeWatch-Request` (reads included since v0.10.7). No CORS. The only token-free route is `GET /api/status?probe=true` (version, build, port and the handshake proofs below). Security headers are on every response, including the server's own refusals (v0.10.22). |
| A look-alike service on ports 8765–8795 capturing the browser (for example run by another user of a shared Windows host) | **Fresh launch (v0.10.22):** the launcher keeps a 256-bit per-launch nonce secret (it reaches only the backend's environment) and sends each port a random challenge; the backend answers `HMAC-SHA256(nonce, "nodewatch-launch:v2:<port>:<challenge>")` for the port it actually listens on. Before v0.10.22 the nonce itself was sent to every port, so any listener could answer. **Reuse of a running backend:** an HMAC-SHA256 proof with the per-install key in `%LOCALAPPDATA%\NodeWatch\state\launcher-identity.key`, also bound to the backend's own port so another listener cannot relay it. The answer must name the probed port exactly. |
| The launcher killing an unrelated process | An older NodeWatch backend is retired only when the PID it reports is the process that owns the listening socket (GetExtendedTcpTable), and its image is a NodeWatch/Python host (v0.10.22). |
| Script injection in the UI | Strict CSP (`script-src 'self'`, no inline script). Values from vendors are HTML-escaped; values used as CSS classes are reduced to `[a-z0-9_-]`. |
| Credentials at rest | Mist token, Palo Alto client secret, connector secrets, webhook URL and Splunk token in Windows Credential Manager. Config backups are DPAPI-encrypted (current user); the snapshot index records whether encryption actually succeeded, and a failure is logged (v0.10.22). The backup fingerprint key is DPAPI-protected too (v0.10.22). |
| Credentials in logs, errors and diagnostics | Known secret values and common credential patterns (including JSON/quoted forms) are redacted; every API error detail is redacted centrally before it reaches the page (v0.10.22); diagnostic metadata is allow-listed; files that still look sensitive are left out of support packages and listed in `files_skipped`. |
| Tampered application files | The launcher checks every manifest file's SHA-256 (manifest hash compiled into the launcher), requires the bundled runtime to be listed, and moves **any** unlisted file under `app/` and `runtime/` (v0.10.22: any type — an unlisted `.js` or `.html` under `app/static` would otherwise be served same-origin) plus unlisted code at the top level into `%LOCALAPPDATA%\NodeWatch\quarantine\`. `branding/` is covered too (the splash bitmap is parsed before the backend starts). |
| Other users of the PC changing NodeWatch's files | NodeWatch does not run from a folder whose permissions let Everyone, Users, Authenticated Users, Interactive, Guests or Domain Users write (a new folder directly under `C:\` does by default); it offers to install a verified copy into `%LOCALAPPDATA%\Programs\NodeWatch` (every file checked against the manifest before it is used) and starts that. `NODEWATCH_ALLOW_SHARED_INSTALL=1` starts anyway and logs a warning (single-user lab PCs only). The launcher resolves DLLs from System32 only (`SetDefaultDllDirectories`), so a DLL planted next to `NodeWatch.exe` is never loaded. FAT32/exFAT drives have no permissions at all and are refused for the same reason. |
| Malicious dependency from PyPI, or a redirected package index | Releases ship every Python package pre-installed in `runtime\site-packages`, listed file by file in `integrity.json` and hash-checked at every start; users' PCs never run pip (v0.10.22). Builds without the bundle use the private venv, which installs only with `pip --require-hashes` from `requirements.lock` / `requirements-optional.lock` and refuses otherwise; there, a redirected index (for example a planted `C:\ProgramData\pip\pip.ini`) can only make installation fail. |
| Palo Alto token sent to the wrong host | Auth host is fixed; the log query host must match `*.api.prismaaccess.com`; HTTP redirects are refused for credentialed requests. TLS verification cannot be disabled for the Palo Alto **cloud** integrations (SCM, Device Security, Strata Logging). **Panorama** has a per-connection "verify TLS" switch (for lab certificates). |
| Mist token sent to the wrong host | API host must be `*.mist.com`. TLS verification *can* be turned off for lab use. |
| Any connection without certificate checks | A persistent red banner lists every connection with TLS verification off: Mist, device connectors (Panorama, FortiGate, Silver Peak) and Splunk HEC (v0.10.22; before, Mist only). Splunk HEC must use `https://` (v0.10.22). The alert webhook must use `https://`, is always verified and refuses redirects. |
| Hostile XML from a Panorama | No DTDs or entities, UTF-16/32 and NUL bytes refused before the check (v0.10.22), 20 MB cap. |
| Unexpected code in the connector folder | Only allow-listed connector packages are imported (v0.10.22). |
| Accidental production changes | Strict confirmations, input allow-lists, protected-port override, concurrency guard (VC, alarm ack), audit before/after, automatic validation report. The backend stays up until a change and its verification finish, even if the browser disconnects (v0.10.22). |
| Forged entries in a shared triage folder | A log file is read only when its Windows owner is the user its name claims (on shares that keep owners — NodeWatch tests this and shows "Identity checks: OFF" otherwise); pre-release file names are refused; a writer never appends to a segment someone else created; writers are capped per user; events more than 1 hour ahead are refused (all v0.10.22). See `TEAM_TRIAGE.md` › Trust for what remains. |

## Mac build (v0.10.22)

The same controls apply to `NodeWatch.app`, with macOS equivalents:

| Windows | Mac |
|---|---|
| `NodeWatch.exe` pins the manifest hash | The universal launcher `Contents/MacOS/NodeWatch` pins the Mac manifest (`Contents/Resources/_internal/integrity.json`, covering `app/`, `branding/` and `runtime-macos/**`); unlisted files under `app/` and `runtime-macos/`, top-level `.py/.pyc/.pth/.so/.dylib` files and any unexpected top-level folder go to `~/Library/Application Support/NodeWatch/quarantine/`. |
| Install-folder ACL check | Every file and folder of the app, and every folder above it, must not be writable by everyone or by a group other than `wheel`/`admin`, and must be owned by you, root or an administrator (sticky folders such as `/tmp` are allowed above the app). Run from a disk image or a translocated copy (opened straight from Downloads), NodeWatch checks its files and offers to install itself into `/Applications` (administrators) or `~/Applications` and checks the copy against the manifest first. |
| DLL search hardening | The backend gets no `PYTHON*`, `__PYVENV_LAUNCHER__` or `DYLD_*` variables from the launcher's environment (no library injection or foreign packages). |
| Windows Credential Manager | Login keychain (generic passwords `NodeWatch:…`, account `NodeWatch`). Only the NodeWatch Python runtime that created an item reads it silently; macOS asks before any other program can. A release that ships a different Python binary makes macOS ask once for the login password (*Always Allow*); releases keep the pinned python-build-standalone build so this is rare. |
| DPAPI-encrypted backups and fingerprint key | AES-256-CBC + HMAC-SHA256 (encrypt-then-MAC, CommonCrypto) with a 512-bit key kept in the login keychain (`NodeWatch:LocalDataKey`). A changed, truncated or foreign file is refused before decryption; a key that exists but cannot be read (locked keychain, denied prompt) is never replaced. |
| Windows trust store | Python trusts macOS's public roots (`/private/etc/ssl/cert.pem`) plus root CAs in the System and login keychains that macOS itself trusts for TLS (for example a TLS-inspection root deployed by IT); roots marked *Never Trust* are left out. |
| Team-triage owner check | Off on a Mac (SMB mounts show every file as yours); see `TEAM_TRIAGE.md`. |
| Authenticode signature | Ad-hoc signed, not notarized: macOS warns on first open and the user approves it once in Privacy & Security. The launcher then clears the download-quarantine flag from its own (already verified) files. A notarized Developer ID build removes the warning (docs/RELEASE_PROCESS.md step 10). As on Windows, the chain of trust starts at the launcher: only run a NodeWatch.app you downloaded from the publisher. |

## What is not protected (by design)

- **Malware running as the same Windows user.** It can read the page (and its token) like the browser does,
  read Credential Manager entries for the user, read DPAPI-protected backups, and change the private runtime in
  `%LOCALAPPDATA%\NodeWatch` (installed packages and the bytecode cache are not re-hashed on each start). No
  desktop app can defend against this; keep the workstation clean.
- **Browser extensions** you installed yourself cannot see NodeWatch when it runs in its own window (v0.10.22): the
  app window uses a private NodeWatch browser profile with extensions disabled. Extensions an organisation
  force-installs by policy may still load there. With `NODEWATCH_OPEN_IN_BROWSER=1`, or on a
  PC without Edge or Chrome, NodeWatch opens in the normal browser, where extensions with access to
  `http://127.0.0.1/*` can still read the page and its token.
- **Deployment mode.** NodeWatch is a desktop app only; `NODEWATCH_DEPLOYMENT_MODE=server` refuses to start until
  sign-in, HTTPS and roles exist (docs/architecture/DEPLOYMENT_MODES.md).
- **Other users on a shared Windows host** can reach loopback ports and probe `/api/status?probe=true`
  (version/build/port only). They cannot read your token, cannot answer the launch handshake, and cannot change an
  install folder that passes the permission check.
- **Shared triage folder administrators** (and shares that map every user to one account) can still forge
  triage entries. Triage is a coordination aid, not an audit trail; production changes are audited locally.
- **Unofficial Palo Alto API.** Traffic & Sessions uses the SCM Log Viewer API, which Palo Alto does not
  document as a public API. It is read-only, but its behaviour can change without notice.
- **The launcher's signature.** The integrity chain starts at `NodeWatch.exe`: it holds the manifest hash. Only
  run a launcher signed by the publisher (check *Properties › Digital Signatures*); an unsigned or re-signed
  launcher can vouch for any files.

## Reporting

Diagnostics export (Settings → Support) produces a sanitized zip. Check `sanitization_report.json` inside it
before sending it to anyone.
