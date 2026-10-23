# Provenance of this folder

Copied read-only on 2026-10-22 from `C:\Users\Evision\_internal` on the owner's Windows PC.

- This is an OLDER development tree, not v0.10.42: its `integrity.json` says build
  `2026-10-14-v0.10.22-security`, and its `README.md` says v0.10.31. Only 114 of its 275 `app/` files match
  the shipped v0.10.42 build, so its `app/` folder was NOT copied. The v0.10.42 app code is in `../../app`.
- `release/native_launcher.go` is an older version of the shipped Windows launcher. It shares 46 function
  names with the shipped v0.10.42 launcher. The shipped one has about 16 newer functions (for example
  `findAppBrowser`, `installFolderMessage`, `offerProfileInstall`, `hashManifestFiles`, `verifyRuntimeEnv`).
- `release/native_launcher.go` and `release/backend_host/main.go` compile for windows/amd64 with Go 1.24.7
  (CGO_ENABLED=0, standard library only). They have not been run.
- Not found in this tree: macOS launcher source, the installer (`nodewatch/setup`) source, the window
  program source (`tools/nwwindow`), `tests/test_connectors_contract.py`, `tests/vendor_reads_allowlist.json`,
  `requirements.lock`.
