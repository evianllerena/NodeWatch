# Pilot releases

Every push to `main` that changes `app/`, the shipped docs or the build tool runs `.github/workflows/release.yml`.
It publishes a private prerelease on GitHub (Releases) with:

- `NodeWatch.exe`: the Windows installer
- `NodeWatch.zip`: the macOS app (Apple silicon runtime; the launcher is universal)

The build id is in the release title and inside the app (Settings › Support & data › Running version).
- `SHA256SUMS.txt`

`<build>` is `<date>-v0.10.42-pilot-<commit>`. It has the same length as the v0.10.42 build string, because it is
written into the shipped launchers in place.

## Versions

The version is set in one place: `app/core/version.py` (`APP_VERSION`), with the same value in
`app/static/core.js` (`FRONTEND_VERSION`); the build stops if they differ. Every change that goes out gets the next
version (0.10.43, 0.10.44, ...). The release is named after it, and the build id (`<date>-v<version>-pilot-<commit>`)
tells two builds of one version apart.

## How a release is built (`tools/build_release.py`)

1. `_internal/app/` and the shipped `docs/` files take this repository's content; the build id replaces the
   placeholder `APP_BUILD` in `version.py` and `core.js`. `integrity.json` is regenerated with the v0.10.42 rules.
2. **Windows launcher: built from source** (`release/windows-launcher`, Go 1.24.7, the v0.10.42 build flags) with
   the version, build id and manifest hash in its constants, and the NodeWatch icon and version details
   (`release/resources/icon-256.png`, made into a resource file by `go-winres` in the workflow).
3. Programs with no source here are reused from v0.10.42 with their version text updated in place: the installer
   (version text), the macOS launcher (version, build id, manifest hash; plus `Info.plist`), the backend host and
   the window program (`NodeWatchApp.exe`, unchanged). In-place updates keep the version at 7 characters (0.10.xx).

Windows: the installer's payload zip is rebuilt with unchanged entries copied exactly and padded to its original
size. macOS: the `.app` is updated, re-signed ad hoc and zipped with `ditto`.

## What CI checks before publishing

- Upgrade: the page of v0.10.42, then of this build, then of a second build, opened in one browser profile
  (as the app window keeps its cache): each page must be its own build, never "Build mismatch".
  Static files are cached for a week keyed by `?v=<build>`; until 2026-10-23 the key was the version, which
  all pilot builds share, so an upgraded window kept the old `core.js`.

- Windows: the launcher shows the NodeWatch icon and this version; the payload matches its `integrity.json`; the 66-test suite passes with the bundled Python; the
  installer installs silently (`/S`) over an existing v0.10.42 install in `%LOCALAPPDATA%\Programs\NodeWatch`; the installed launcher verifies
  the files, starts the backend and app window, and the backend answers as the new build; a second launch
  reuses it. The launcher log lines match the recorded v0.10.42 behaviour (`docs/parity/`). Started from a folder
  other users can change, it shows the "Install NodeWatch" offer.
- macOS: the app passes `codesign --verify`; the suite passes with the bundled Python; the launcher starts
  the backend and it answers as the new build.

## Not yet

- Code signing (Phase 3). The downloads are unsigned, like v0.10.42: Windows SmartScreen and macOS
  Gatekeeper will warn on first open.
- Intel Macs: the bundled Python runtime is arm64 only.
