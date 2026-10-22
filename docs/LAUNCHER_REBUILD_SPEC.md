# Launcher rebuild spec (draft, 2026-10-22, NOT VERIFIED against the binaries' behaviour)

**Status:** this is a working draft. It was written without running any of the binaries (they are Windows and
macOS programs). Every "responsibility" below is inferred from function names and from `docs/SECURITY_MODEL.md`.
Check it against the real launchers before anyone builds from it.

What is verified (by inspecting the files, 2026-10-22):

- The Windows `NodeWatch.exe` that is distributed is an **installer** (Go build path `nodewatch/setup`). It embeds a
  zip with the launcher `NodeWatch/NodeWatch.exe` plus the `_internal` files.
- The **launcher** `NodeWatch/NodeWatch.exe` (Go build path `nodewatch/launcher`) and the macOS launcher
  `Contents/MacOS/NodeWatch` each contain the SHA-256 of their platform's `integrity.json`. `NodeWatchApp.exe` and
  `NodeWatchBackend.exe` do not.
- All are Go 1.24.7 binaries built with `-trimpath` and `CGO_ENABLED=0`. No Go source for any of them is in the build.

`SECURITY_MODEL.md` says the launcher checks every manifest file against the pinned manifest. A changed build
therefore cannot pass the existing launchers until they are rebuilt, or their source is found.

How the original build injected the hash is unknown. The release scripts named in the changelogs are not in the
build.

## Binaries and function names found in them

| Binary | Function names found (selection) | Role (inferred from names, not observed) |
| --- | --- | --- |
| `NodeWatch.exe` (distributed file) | `runWizard`, `extractPayload`, `install`, `createShortcuts`, `registerUninstall`, `runUninstall`, `validateInstallDir`, `checkDrive` | Installer and uninstaller |
| `NodeWatch/NodeWatch.exe` (inside the installer) | `verifyRuntime`, `hashManifestFiles`, `hashFile`, `manifest`, `copyVerified`, `installFolderMessage`, `writableByOthers`, `broadPrincipal`, `profileInstallDir`, `probePorts`, `probeBackendWithChallenge`, `launchProof`, `identityProof`, `makeNonce`, `listeningPID`, `queryProcessPath`, `findPython`, `pipEnvironment`, `startSplash`, `findAppBrowser`, `openBrowser`, `systemDLLPath` | Launcher: verifies files, checks the install folder, starts and finds the backend, opens the window |
| `app/bin/NodeWatchApp.exe` | `createWindow`, `runWindow`, `comCall`, `comHandler`, `hardenDllSearch`, `findRuntime`, `supervise`, `runChild`, `holdLockfile`, `isLoopback` | App window and backend supervision |
| `runtime/NodeWatchBackend.exe` | `run`, `fail`, `utf16Ptr` | Small process starter |
| macOS `Contents/MacOS/NodeWatch` (universal) | `checkTree`, `readManifest`, `hashManifestFiles`, `safeRel`, `permissionProblem`, `isAdmin`, `installTarget`, `isNodeWatchBundle`, `backendEnv`, `osascript`, `newChallenges`, `probePorts`, `launchProof`, `identityProof` | macOS launcher |

## Behaviour to reproduce (from `docs/SECURITY_MODEL.md`, the changelogs and strings found in the binaries; not observed by running them)

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
    - Open the app window: WebView2 via `NodeWatchApp.exe` (`CHANGELOG_v0.10.39.md`; its source was `tools/nwwindow`, not in the build), or the browser in `--app=` mode with its own `--user-data-dir` and `--no-first-run`.
    - `NODEWATCH_OPEN_IN_BROWSER=1` opens a normal browser instead.
12. **macOS only.** Clear the download-quarantine xattr from the launcher's own already-verified files (`/usr/bin/xattr`). Install copies with `/usr/bin/ditto`.

## Acceptance tests for the rebuilt launcher (add to the release pipeline)

- [ ] It starts the unmodified v0.10.42 tree when built with that tree's manifest hash.
- [ ] Changing one byte of any listed file is refused; an added `app/static/x.js` is quarantined.
- [ ] A folder writable by Users is refused, and the verified-copy offer works.
- [ ] A fake listener on port 8765 that echoes the challenge is not accepted.
- [ ] A `PYTHONPATH` set in the user's environment does not reach the backend.
- [ ] The test suite passes against the installed tree: `python tests/run.py --target bundle --root <_internal>`.
