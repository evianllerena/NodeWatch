# Pilot releases

Every push to `main` that changes `app/`, the shipped docs or the build tool runs `.github/workflows/release.yml`.
It publishes a private prerelease on GitHub (Releases) with:

- `NodeWatch.exe`: the Windows installer
- `NodeWatch.zip`: the macOS app (Apple silicon runtime; the launcher is universal)

The build id is in the release title and inside the app (Settings › Support & data › Running version).
- `SHA256SUMS.txt`

`<build>` is `<date>-v0.10.42-pilot-<commit>`. It has the same length as the v0.10.42 build string, because it is
written into the shipped launchers in place.

## How a release is built (`tools/build_release.py`)

The source of the launchers, the installer and the window app is not available, so the pilot builds reuse the
shipped v0.10.42 binaries unchanged except for two pinned values in each launcher:

1. `_internal/app/` and the shipped `docs/` files take this repository's content. Files listed in
   `tests/baselines/removed_files.json` are dropped; new app files are added.
2. `app/core/version.py` gets the new build id; `integrity.json` is regenerated with the v0.10.42 rules
   (every file is listed except `README.md`, `integrity.json` and `docs/`).
3. The launcher's pinned `integrity.json` SHA-256 and its build string are replaced byte for byte
   (Windows launcher: one copy each; macOS universal launcher: two copies each, one per architecture).

Windows: the installer's embedded payload zip is rebuilt with unchanged entries copied exactly as shipped and
padded to its original size, so it drops in at the same offset. macOS: the `.app` is patched, re-signed ad hoc
and zipped with `ditto`.

## What CI checks before publishing

- Upgrade: the page of v0.10.42, then of this build, then of a second build, opened in one browser profile
  (as the app window keeps its cache): each page must be its own build, never "Build mismatch".
  Static files are cached for a week keyed by `?v=<build>`; until 2026-10-23 the key was the version, which
  all pilot builds share, so an upgraded window kept the old `core.js`.

- Windows: the payload matches its `integrity.json`; the 66-test suite passes with the bundled Python; the
  installer installs silently (`/S`) over an existing v0.10.42 install in `%LOCALAPPDATA%\Programs\NodeWatch`; the installed launcher verifies
  the files, starts the backend and app window, and the backend answers as the new build; a second launch
  reuses it. The launcher log lines match the recorded v0.10.42 behaviour (`docs/parity/`).
- macOS: the app passes `codesign --verify`; the suite passes with the bundled Python; the launcher starts
  the backend and it answers as the new build.

## Not yet

- Code signing (Phase 3). The downloads are unsigned, like v0.10.42: Windows SmartScreen and macOS
  Gatekeeper will warn on first open.
- Intel Macs: the bundled Python runtime is arm64 only.
