# Signing NodeWatch releases (Phase 3)

Your keys were made on your PC with **NodeWatch-Sign.exe** (Releases › "NodeWatch-Sign (signing tool …)"; not for
customers). Since v0.10.52 GitHub signs every release with them (your decision, 2026-10-23): menu option 6 copies the
keys into the repository's encrypted secrets once. Each release is then published already signed, after GitHub checks
the signatures with the public keys in `release/keys/` and installs and starts the signed installer. Without the
secrets a release is published unsigned. Signing on your PC (option 3) still works.

## Using it (double-click, no commands)

Double-click `NodeWatch-Sign.exe`. A window opens with a menu; type a number and press Enter.
(Windows may first say it protected your PC: click **More info**, then **Run anyway**.)

| Number | What it does | When |
|---|---|---|
| 1 | First-time setup: makes your code-signing certificate and signing key, and puts two public files next to the program: `BWN-NodeWatch-CodeSigning.cer` (for the customer's IT) and `minisign.pub` (for the customer) | Once |
| 2 | Backs up both keys to a USB drive, protected by a password you choose | Once, right after 1 |
| 3 | Signs `NodeWatch.exe` and `NodeWatch.zip` (found next to the program or in Downloads) and makes `.minisig` files | Every release |
| 4 | Checks a signed file | When you want |
| 5 | Restores the keys from the backup | Only on a new PC |
| 6 | Copies the keys into GitHub's encrypted secrets (one value at a time, via the clipboard) so GitHub signs every release | Once |

Every release: download `NodeWatch.exe` and `NodeWatch.zip` from the latest release, choose 3, then send the customer
`NodeWatch.exe`, `NodeWatch.zip`, `NodeWatch.exe.minisig` and `NodeWatch.zip.minisig`.

The customer's IT adds `BWN-NodeWatch-CodeSigning.cer` to **Trusted Publishers** and **Trusted Root Certification
Authorities** by Group Policy (once). Customers can check a download with the official minisign:
`minisign -Vm NodeWatch.exe -p minisign.pub`.

Command-line use (the same steps): `NodeWatch-Sign.exe setup | backup E:\ | sign NodeWatch.exe NodeWatch.zip |
verify NodeWatch.exe minisign.pub | restore <backup file>`.

## What it does

- Windows: every program file inside the installer (launcher, backend host, app window, compiled app,
  Python runtime) is Authenticode-signed and timestamped (timestamp.digicert.com; without internet the signature has
  no timestamp), the integrity list and the launcher's pinned hash are updated, and the installer is signed last.
  Files the Python runtime's makers already signed keep their signature.
- macOS: the app keeps its ad-hoc Apple signature (Apple's Developer ID and notarization are not free).
- Keys: the certificate is in your Windows certificate store (Current User); the minisign key is in
  `%APPDATA%\NodeWatch-Signing`, encrypted for your Windows account. Nothing is uploaded.

## What is checked on GitHub

`.github/workflows/signing.yml` runs the whole flow with throw-away keys on a clean Windows machine: setup, sign,
minisign verification (NodeWatch-Sign and the official minisign 0.12), install the signed installer, every
installed program file validly signed, and the launcher starts (so the rebuilt integrity list is right).

## Limits (free signing)

- The signatures are trusted only on PCs whose IT trusts your certificate. Elsewhere Windows shows the publisher
  as unknown.
- macOS: no notarization; users open the app once via System Settings › Privacy & Security › Open Anyway.
