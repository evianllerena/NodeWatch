# Release sources (work in progress)

| Folder | State |
| --- | --- |
| `backend-host/` | Source of `_internal\runtime\NodeWatchBackend.exe`. Built with Go 1.24.7, `GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" main.go`, it is byte-for-byte identical to the shipped v0.10.42 file (SHA-256 921ee25f3d7f5b22…). |
| `windows-launcher/` | Source of the Windows launcher (`NodeWatch\NodeWatch.exe`), updated from the v0.10.31 copy toward v0.10.42 (parallel integrity check, folder-permission names, bundled packages, app window). The start-up sequence, the "Install NodeWatch" offer and the install step are now written from the documented behaviour (docs/SECURITY_MODEL.md, CHANGELOG_v0.10.22.md). It builds, but has not been tested on Windows yet and has no icon or version information. Not used by any release yet. |

Releases still use the shipped v0.10.42 launchers, installer and window program (`tools/build_release.py`, `docs/RELEASE.md`).
Original v0.10.31 copies of these files stay unchanged in `legacy/dev-tree-v0.10.22-v0.10.31/release/`.
