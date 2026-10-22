# NodeWatch v0.10.22 — Security release

Build: `2026-10-14-v0.10.22-security`. Delivered as **`NodeWatch.exe`** (Windows) and **`NodeWatch.zip`** (Mac:
`NodeWatch.app`).

This release closes the findings of the October 2026 security review. It changes no features.

> **Release steps:** `tools/bundle_site_packages.py` (or `release\Build-Bundle.cmd`), `release\generate_integrity.py
> --update-launcher`, `release\build_launcher.py`, sign `NodeWatch.exe`, `release\build_setup.py`, sign the setup
> (docs/RELEASE_PROCESS.md).

## NodeWatch for Mac
- **New: a Mac version.** `NodeWatch.zip` holds one `NodeWatch.app` for Apple silicon and Intel Macs (macOS 11+),
  with its own Python and packages inside: nothing to install first. Opened from Downloads it offers to install
  itself in Applications. It opens in its own window (Chrome/Edge app mode, else the default browser) and stops when
  the window closes, like on Windows.
- Same protections as Windows: every file is hash-checked at each start, the handshake and identity checks are
  identical, and the app refuses to run from a place other users can change. Secrets live in the **login keychain**;
  configuration backups are encrypted with a key kept there. Data: `~/Library/Application Support/NodeWatch`.
- Not notarized by Apple yet: the first open needs **System Settings › Privacy & Security › Open Anyway**.
- Settings › Support › *Open data folder* now works on the Mac (Finder).

## Easier installation
- **One setup file.** `NodeWatch.exe` (named just *NodeWatch*) is a single file with a normal wizard: Welcome →
  choose folder (Browse…, desktop shortcut) → Install with a progress bar → Finish ("Start NodeWatch now").
  Per-user, no administrator rights; Start-menu shortcut, Settings › Apps entry and uninstaller (which can
  keep or delete your settings and backups); silent install `/S` for IT. NodeWatch.exe and the setup
  now have the NodeWatch icon and version details. Double-clicked again once installed, it simply offers to open
  NodeWatch.
- **Everything is in the zip.** All Python packages ship pre-installed and hash-checked with the rest
  of the application. Unzip, double-click, done: no internet, no pip, no proxy settings, no waiting on
  the first start.
- **One-click install from the wrong folder.** Started from a folder other users can change (such as
  `C:\` or a shared drive), NodeWatch offers to install itself into your user folder and starts from
  there. Later double-clicks on the original copy open the installed one.
- Messages about folders now say who can change them in plain words ("Every signed-in user").

## Its own window
- NodeWatch opens in **its own app window** (Microsoft Edge's app mode, built into Windows 10/11; Chrome if Edge is
  missing) instead of a browser tab: no address bar or tabs, its own taskbar entry. It uses a private NodeWatch
  browser profile, so the extensions you installed in your normal browser cannot see NodeWatch's page. Closing the window still closes
  NodeWatch. `NODEWATCH_OPEN_IN_BROWSER=1` brings back the browser tab.
- **Ready for a shared version later.** How NodeWatch is deployed, who is signed in and what they may change now
  each have one home in the code (`app/core/deployment.py`, `app/core/auth.py`); every production change checks a
  named permission. Desktop behaviour is unchanged; a server mode refuses to start until sign-in, HTTPS and roles
  exist (docs/architecture/DEPLOYMENT_MODES.md).

## Start-up and installation
- **No unverified downloads.** With the packages bundled nothing is downloaded at all. A build without
  the bundle falls back to the private venv, which now refuses to install without `requirements.lock`
  (before: an unhashed fallback).
- **A redirected package index cannot swap packages.** Any local user can create
  `C:\ProgramData\pip\pip.ini`; with mandatory hashes that can now only make installation fail.
  Corporate mirrors and proxies configured for pip keep working. `PYTHON*` variables no longer reach pip.
- **Launcher handshake fixed.** The launcher used to send its secret launch code to every port it
  probed, so any program listening on 8765–8795 could answer and receive the browser. It now sends a
  random challenge and checks a proof bound to the port; the reuse check is port-bound too.
- **Older backends** are stopped only if they really own the listening port.
- **Install folder check.** NodeWatch does not run from a folder other users can write to (a new
  folder directly under `C:\`, a shared drive, a FAT32/exFAT USB stick); it offers the one-click install
  instead. `NODEWATCH_ALLOW_SHARED_INSTALL=1` overrides it (single-user lab PCs).
- **DLL planting.** The launcher loads Windows DLLs from System32 only.
- **Any unlisted file under `app\`** is moved to quarantine, not only code; `branding\` is
  hash-checked too.

## Web boundary and data
- Every error message is scrubbed of credentials before it reaches the page.
- Security headers are also sent on the server's own refusals.
- Backups record whether DPAPI encryption really worked (and log when it did not); the backup
  fingerprint key is now DPAPI-protected as well. Gzip snapshot imports have a 200 MB expansion limit.
- Splunk HEC must use `https://`. The red banner now lists **every** connection with certificate
  checks off (Mist, Panorama, FortiGate, Silver Peak, Splunk HEC), not just Mist.
- The alert webhook refuses redirects. Panorama XML in UTF-16/32 is refused.
- Only the shipped connector packages are loaded.

## Team triage (shared folder)
- A log file is read only if its Windows owner is the user its name claims. Creating
  `pc~alice.0001.jsonl` no longer lets anyone act as Alice. **The previous documentation was wrong**
  to say folder permissions prevented this. NodeWatch tests each share first: on shares that do not
  keep Windows owners (a NAS "force user" setting) the check is off and Settings says so.
- Pre-release `<machine>-<user>` file names are no longer read.
- A writer never appends to a segment someone else created first.
- Writers are kept most-recently-active first, at most 8 machines per user, so junk files cannot
  hide your teammates.
- Events more than 1 hour in the future are refused instead of held.
- Your name comes from the signed-in account, not `%USERNAME%`; look-alike names (Cyrillic letters,
  accents, zero-width characters) are flagged.
- Settings › Team triage shows the identity-check counts.

## Fixes
- Palo Alto Device Security re-authenticated on every call when the token had no lifetime; it now
  assumes 900 s.
- Panorama calls appear in Support › API timing.
- Restoring an org-level template no longer re-downloads the whole Mist event history.
- NodeWatch stays running until a production change and its verification finish, even if the
  browser tab closes mid-change.
- Removed the unused `transaction_service.py`.

## Tests
`tests/test_v0_10_22_*.py` (57 tests, including the Mac build (`_macos`), stdlib `unittest`, also run by pytest) cover each change,
including a check that the Go launcher and the Python backend compute identical handshake proofs.
