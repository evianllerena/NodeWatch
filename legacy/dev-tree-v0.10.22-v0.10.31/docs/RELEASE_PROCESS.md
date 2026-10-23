# Releasing NodeWatch

Run these steps on a trusted build machine with internet access, from the `_internal` folder (the repository root). The Go builds cross-compile from Linux or macOS; Windows Authenticode signing needs Windows. The Mac app is built in step 10.

1. **Bump the version** in `app/core/version.py` and the two constants at the top of `app/static/core.js`
   (`tests/test_strata_ui_v0104.py` fails if they differ).

2. **Run the tests**
   ```
   python -m pytest
   eslint app/static
   ruff check app tests release
   ```
   Optional live check against your tenant: see `tests/test_strata_live_optional.py`.

3a. **Optional: offline package** (for customers without internet access from the PC): run
   `release\Build-Offline-Wheels.ps1` on a connected Windows PC. It fills `runtime\wheels\` with every wheel for
   `requirements.txt` and `requirements-optional.txt`; the launcher then installs from there and never contacts PyPI.
   Optional components (`requirements-optional.txt`, the SNMP connector) never block start-up: if they can't be
   installed NodeWatch starts without them and retries on the next start.

3. **Bundle the Python packages** (v0.10.22, every release): NodeWatch ships with all its Python packages
   pre-installed in `runtime\site-packages`, so users' PCs never run pip, need no internet and no lock file.
   On a machine with internet access to PyPI (or your mirror):
   ```
   python tools/bundle_site_packages.py          # any Python 3.10+, Windows/Linux/macOS
   ```
   or, on Windows without Python installed, double-click `release\Build-Bundle.cmd` (uses the bundled
   interpreter and also leaves `nodewatch-site-packages.zip` on the Desktop, for whoever builds the launcher).
   Wheels are fetched for the bundled interpreter (win_amd64, CPython 3.12) whatever machine runs this. If
   `requirements.lock` / `requirements-optional.lock` exist (`release\Update-Lockfile.ps1`) they are used with
   `--require-hashes`; they are optional now. Every bundled file is hash-checked by `integrity.json` at each start.
   Do it after step 4 (the interpreter) and before step 6 (the manifest). Do not run an older `NodeWatch.exe`
   against a tree with a fresh `runtime\site-packages`: files its manifest does not list are quarantined.

   Without a bundle the launcher falls back to the pre-v0.10.22 private venv, which **requires**
   `requirements.lock` (it refuses unhashed installs). Development builds may opt out with
   `-ldflags "-X main.allowUnhashedInstall=true"`; never ship one.

4. **Stage the bundled Python interpreter** (v0.10.12+; target PCs then need no Python install,
   only internet on the first start of each version, when the launcher pip-installs the pinned packages).
   Download `cpython-3.12.15+20261003-x86_64-pc-windows-msvc-install_only_stripped.tar.gz` from the
   python-build-standalone release `20261003` (github.com/astral-sh/python-build-standalone), check it against
   that release's `SHA256SUMS`, then:
   ```
   python tools/stage_runtime.py --archive <path>\cpython-3.12.15+20261003-x86_64-pc-windows-msvc-install_only_stripped.tar.gz --sha256 6fba7f2ae506facf41d457ea8293c7497910a675c69a4e954875169410a50402
   ```
   This (re)creates `runtime/python/` (about 570 files, 34 MB after trimming tcl/Tk, IDLE, tests, headers,
   import libraries, caches and the base pip; `ensurepip` is kept so the private venv still gets pip).
   `runtime/` is git-ignored: never commit it. `release\Build-Bundled-Runtime.ps1` is the legacy
   embeddable-zip alternative and refuses to run over this layout.

5. **Build the backend host** `runtime/NodeWatchBackend.exe` (Go 1.23+, no cgo, console subsystem). It runs the
   bundled interpreter in-process so Task Manager shows *NodeWatchBackend.exe* instead of *python.exe*:
   ```
   cd release/backend_host
   GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go vet main.go
   GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o ../../runtime/NodeWatchBackend.exe main.go
   ```
   (Windows cmd: `set GOOS=windows& set GOARCH=amd64& set CGO_ENABLED=0` first.) Sign it now with
   `release\Sign-NodeWatch.ps1 -Executable runtime\NodeWatchBackend.exe` – signing changes the file, so it must
   happen before step 6. Without the host the release still works; the backend then runs as `python.exe`.

6. **Regenerate the integrity manifest and pin it in the launcher**
   ```
   python release/generate_integrity.py --update-launcher
   ```
   This rewrites `integrity.json` and updates `manifestSHA256`, `appVersion` and `appBuild` in
   `release/native_launcher.go`. Every file under `runtime/` (interpreter and host) is listed individually;
   the output prints the runtime file count/size and warns if the host is missing or caches slipped in.
   Do not edit any file under `app/` or `runtime/` after this step.

7. **Build the launcher** (Go 1.23+, plus `llvm-windres` and Pillow for its icon/manifest/version info):
   ```
   python release/build_launcher.py
   ```
   It writes `..\NodeWatch.exe` (same Go flags as before: `-H windowsgui -s -w -trimpath`).

8. **Sign** `NodeWatch.exe` with `release\Sign-NodeWatch.ps1` (see `docs/WINDOWS_SIGNING_BWN.md`).

9. **Build the Windows download** — one file people download and run (v0.10.22):
   ```
   python release/build_setup.py
   ```
   It zips `NodeWatch.exe` + `_internal\` (without `tests\`, `__pycache__\`, `runtime-macos\` or the installer's own
   sources) into the installer and writes `..\..\NodeWatch.exe` (about 28 MB; the file people get is simply called
   *NodeWatch.exe*). **Sign it too.** The wizard installs per user without administrator rights (default
   `%LOCALAPPDATA%\Programs\NodeWatch`), makes the folder private, adds Start-menu (and optional desktop) shortcuts and a
   Settings › Apps entry with an uninstaller. Double-clicked again once that version is installed, it offers to open
   NodeWatch instead (No = install again). IT deployment: `NodeWatch.exe /S [/NODESKTOP] [/D=C:\path]`; uninstall:
   `"%LOCALAPPDATA%\Programs\NodeWatch\Uninstall NodeWatch.exe" /uninstall [/S]`.

10. **Build the Mac download** (v0.10.22) — `NodeWatch.zip`, holding one universal `NodeWatch.app` (Apple silicon
    and Intel, macOS 11 or later). Needs the Mac runtimes and packages, which steps 3/4 make for Windows:
    ```
    python tools/stage_runtime_macos.py --dir <folder with the two macOS archives>   # python-build-standalone 20261003, SHA-256 pinned in the script
    python tools/bundle_site_packages.py --platforms all                             # or release\Build-Bundle.cmd (does all three platforms)
    python release/build_macos.py --rcodesign <path>\rcodesign
    ```
    `build_macos.py` cross-builds from Linux/Windows/macOS: it stages `NodeWatch.app/Contents/Resources/_internal`
    (application, branding, docs and `runtime-macos/` only), signs the bundle, writes the Mac `integrity.json`, builds
    the launcher (`release/native_launcher_darwin.go`, arm64 + x86_64 merged into one universal binary) with the
    manifest hash, version and build compiled in via `-ldflags -X`, signs again, refuses to continue if signing
    changed a hashed file, and zips the app with Unix permissions kept. The Mac manifest is separate from the
    Windows one; `release/generate_integrity.py` and `native_launcher.go` are not involved.

    **Signing.** Without an Apple Developer ID the app is ad-hoc signed ([rcodesign](https://github.com/indygreg/apple-platform-rs)),
    which Apple silicon requires, and macOS shows *"Apple could not verify NodeWatch is free of malware"* the first
    time: users open it once from **System Settings › Privacy & Security › Open Anyway** (macOS 15+) or by
    right-click › Open (macOS 14 and earlier). With a Developer ID, sign `NodeWatch.app` (and its nested Mach-O
    files) with `codesign --options runtime --timestamp`, notarize with `xcrun notarytool submit NodeWatch.zip
    --wait`, staple, and re-zip: macOS then opens it without any warning.

11. **Distribute** `NodeWatch.exe` (Windows) and `NodeWatch.zip` (Mac). (A plain zip of `NodeWatch.exe` + `_internal\`
    still works on Windows too.)

## How NodeWatch starts (bundled interpreter)

1. The launcher verifies `integrity.json` (every listed file, including `runtime\python\**`).
2. The private venv `%LOCALAPPDATA%\NodeWatch\runtime\deps-<hash>` (keyed by `requirements.lock` and the bundled
   interpreter, so upgrades with unchanged dependencies reuse it; older runtimes are removed) is created from the first working interpreter:
   `_internal\runtime\python\python.exe`, then `py.exe -3.12/-3.13/-3.11/-3.10`, then
   `%LOCALAPPDATA%\Programs\Python\Python3xx\python.exe`, then `python.exe`/`python3.exe` on PATH. The pinned
   packages are pip-installed into it from PyPI (hash-verified with `requirements.lock`). A legacy release that
   ships only `runtime\NodeWatchBackend.exe` with the embeddable runtime (no `runtime\python\`) still uses it directly.
3. The backend is started as `_internal\runtime\NodeWatchBackend.exe -X faulthandler -m app.launcher` with
   `PYTHONHOME=_internal\runtime\python` and `PYTHONPATH=<venv>\Lib\site-packages;_internal`, but only when the
   host exists and the venv was created from the bundled interpreter (`pyvenv.cfg` `home`). If the host is missing,
   cannot start, exits, or has not answered the per-launch handshake within 40 s, it is killed and the backend is
   started the pre-v0.10.12 way with `<venv>\Scripts\python.exe`. After such a fallback succeeds, later starts of the
   same version skip the host (marker `%LOCALAPPDATA%\NodeWatch\state\backend-host-disabled-v<version>`; delete it to
   retry). Logs: `%LOCALAPPDATA%\NodeWatch\logs\native-launcher.log` and `backend-launcher.log`.

## Which processes run, and how to stop NodeWatch (for users)

| Process (Task Manager) | What it is | Lifetime |
| --- | --- | --- |
| `NodeWatch.exe` | Launcher: checks files, prepares the runtime, starts the backend, opens the browser | Exits once the browser tab is opened |
| `NodeWatchBackend.exe` | The NodeWatch backend (local web server on 127.0.0.1:8765–8795) | Stops by itself about 15 s after the last NodeWatch tab closes |
| `python.exe` (one or two) | The backend on the fallback path (venv redirector + interpreter), instead of `NodeWatchBackend.exe` | Stops by itself about 15 s after the last NodeWatch tab closes |
| Browser tab | The NodeWatch UI | Closing the last tab stops the backend (a reload or a second tab keeps it running) |

To stop NodeWatch: close its browser tab(s). Tabs send a heartbeat every 30 s and say goodbye when closed; the
backend stops 15 s after the last goodbye, or about 4 minutes after the browser goes silent (crash, killed).
A sleeping PC does not count as closed. **Settings & Support → Support → Exit NodeWatch now** stops it at once.
`NODEWATCH_KEEP_RUNNING=1` disables the automatic stop (development). Otherwise end `NodeWatchBackend.exe` (or the NodeWatch `python.exe`)
in Task Manager. Starting the launcher again starts a new backend; a launcher of a newer version also retires an
older running backend automatically.
