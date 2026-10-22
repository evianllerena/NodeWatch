# Launcher rebuild spec (recovered 2026-10-22)

The Go source of the three Windows launchers and the macOS launcher was not recovered: only the compiled
binaries from v0.10.42 exist. Every launcher **pins the SHA-256 of `integrity.json`** (verified: the hex digest
of each platform's manifest is embedded in `NodeWatch.exe` and `Contents/MacOS/NodeWatch`). So **no changed
build can ship until the launchers are rebuilt**. Any edit to a listed file changes the manifest, and the old
launcher refuses it.

This spec is reconstructed from three sources:

- the function names left in the binaries (Go keeps them, even with `-trimpath`)
- `docs/SECURITY_MODEL.md`, which describes every launcher check
- `app/launcher.py` and `app/core/security.py`, the backend's side of each handshake

Rebuild in Go (free; the originals were Go with `CGO_ENABLED=0`, `-trimpath`). Use `-ldflags="-s -w"` this time,
and add the manifest hash at build time with `-ldflags "-X main.manifestSHA256=<hex>"`. That makes
"regenerate manifest, then rebuild launcher" one scripted step instead of a source edit.

## Binaries and responsibilities

| Binary | Recovered functions (selection) | Responsibility |
| --- | --- | --- |
| `NodeWatch.exe` (Windows, about 101 functions) | `verifyRuntime`, `hashManifestFiles`, `hashFile`, `manifest`, `copyVerified`, `installFolderMessage`, `writableByOthers`, `broadPrincipal`, `principalName`, `profileInstallDir`, `probePorts`, `portStatus`, `probeBackendWithChallenge`, `launchProof`, `identityProof`, `makeNonce`, `listeningPID`, `queryProcessPath`, `startDetached`, `runHidden`, `findPython`, `pythonCandidate`, `pipEnvironment`, `readVenvHome`, `startSplash`, `bmpDimensions`, `findAppBrowser`, `openBrowser`, `systemDLLPath`, `askYesNo`, `messageBox` | Main entry point. Holds the embedded `_internal` payload (a zip inside the exe) and the pinned manifest hash |
| `NodeWatchApp.exe` (about 66 functions) | `createWindow`, `runWindow`, `comCall`, `comHandler`, `hardenDllSearch`, `findRuntime`, `supervise`, `runChild`, `holdLockfile`, `isLoopback`, `versionAtLeast`, `regString`, `windowDpi`, `shellOpen` | Own app window (WebView2 over COM), loopback-only, DLL search hardened, supervises the backend child |
| `NodeWatchBackend.exe` (about 9 functions) | `run`, `fail`, `utf16Ptr` | Hidden-window wrapper that starts the bundled `pythonw.exe` running `app.launcher` |
| `NodeWatch` (macOS universal, about 72 functions) | `checkTree`, `readManifest`, `hashManifestFiles`, `safeRel`, `permissionProblem`, `isAdmin`, `accountName`, `groupName`, `installTarget`, `isNodeWatchBundle`, `backendEnv`, `osascript`, `newChallenges`, `probePorts`, `launchProof`, `identityProof` | Same role as `NodeWatch.exe` for the `.app` bundle |

## Behaviour to reproduce (each row maps to SECURITY_MODEL.md)

1. **Manifest pin.** Read `integrity.json` and compare its SHA-256 to the pinned value; refuse on mismatch.
2. **File verification.** Hash every listed file; refuse to start on any mismatch or missing file. The bundled runtime must be listed.
3. **Quarantine.** Move any unlisted file under `app/`, `runtime/` (`runtime-macos/`) and `branding/`, plus unlisted top-level code (`.py/.pyc/.pth/.so/.dylib/.dll`), to `%LOCALAPPDATA%\NodeWatch\quarantine\` (`~/Library/Application Support/NodeWatch/quarantine/`). `__pycache__` handling: see SECURITY_MODEL.md line 47 (bytecode cache is not re-hashed).
4. **Install-folder ACL.**
    - Windows: refuse when Everyone, Users, Authenticated Users, Interactive, Guests or Domain Users can write the folder or any parent. Offer a verified copy into `%LOCALAPPDATA%\Programs\NodeWatch` (`copyVerified`). `NODEWATCH_ALLOW_SHARED_INSTALL=1` overrides with a warning. FAT32/exFAT is refused.
    - macOS: the owner must be the user, root or an admin; no world or group write except `wheel`/`admin`. Offer `/Applications` or `~/Applications` when translocated or run from a DMG.
5. **DLL hardening.** `SetDefaultDllDirectories` (System32 only). The backend environment drops `PYTHON*`, `__PYVENV_LAUNCHER__` and `DYLD_*`, then sets `PYTHONHOME`, `PYTHONPATH`, `PYTHONUTF8=1` and `NODEWATCH_LAUNCH_NONCE` explicitly.
6. **Fresh-launch handshake (v2).** Keep a 256-bit nonce secret, passed only in the backend's environment. Probe ports 8765–8795 with `GET /api/status?probe=true&launch_challenge=<random>`. Accept only `HMAC-SHA256(nonce, "nodewatch-launch:v2:<port>:<challenge>")` naming the probed port. The backend side is `launch_proof` in `app/core/security.py`.
7. **Reuse handshake.** Use the per-install key `<data root>/state/launcher-identity.key` (64 hex characters), with `&challenge=`. The backend side is `identity_proof`.
8. **Retiring an old backend.** Only when the PID it reports owns the listening socket (`GetExtendedTcpTable` / `lsof`) and its image is NodeWatch or the bundled Python.
9. **Python fallback (non-bundled builds only).** Use the private venv plus `pip --require-hashes --no-cache-dir` from `requirements.lock` / `runtime/wheels`, with `PIP_NO_INPUT=1`. Refuse without a lock file. (`requirements.lock` was not recovered: regenerate it from the versions in `runtime/site-packages`.)
10. **Profile migration.** Move the legacy `MistNetworkTools` profile into `NodeWatch` (with `migration-backup`). Python also does this in `app/core/config.py`; keep one owner.
11. **UI.**
    - Show the splash `branding/startup.bmp` (parsed only after branding is verified).
    - Open the app window: WebView2 via `NodeWatchApp.exe`, or the browser in `--app=` mode with its own `--user-data-dir` and `--no-first-run`.
    - `NODEWATCH_OPEN_IN_BROWSER=1` opens a normal browser instead.
12. **macOS only.** Clear the download-quarantine xattr from the launcher's own already-verified files (`/usr/bin/xattr`). Install copies with `/usr/bin/ditto`.

## Acceptance tests for the rebuilt launcher (add to the release pipeline)

- [ ] It starts the unmodified v0.10.42 tree when built with that tree's manifest hash.
- [ ] Changing one byte of any listed file is refused; an added `app/static/x.js` is quarantined.
- [ ] A folder writable by Users is refused, and the verified-copy offer works.
- [ ] A fake listener on port 8765 that echoes the challenge is not accepted.
- [ ] A `PYTHONPATH` set in the user's environment does not reach the backend.
- [ ] The test suite passes against the installed tree: `python tests/run.py --target bundle --root <_internal>`.
