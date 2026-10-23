# Shipped builds (reference copies)

The exact files the owner supplied as the working v0.10.42 release. They are kept here so CI can test the real
shipped runtime on Windows and macOS. Do not edit them; a new release goes in a new version folder.

| File | SHA-256 |
| --- | --- |
| `v0.10.42/NodeWatch-windows-installer.exe` (Windows installer; Go build path `nodewatch/setup`) | `808d30c555e58faba5066f42593446ce09e2190563195cf5c7176fdc5be1d2b0` |
| `v0.10.42/NodeWatch-macos.zip` (macOS `NodeWatch.app`) | `eaa8bc7e23d4323c3432dc593c21a6f48c4dbee5b5d4c2ed4f9f66b809c5fd4f` |

`tools/extract_windows_payload.py` unpacks the Windows payload and checks it against its `integrity.json`.
