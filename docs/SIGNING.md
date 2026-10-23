# Signing NodeWatch releases (Phase 3)

Your signing keys stay on your PC. GitHub builds and tests the release; you sign it on your PC with
**NodeWatch-Sign.exe** (Releases › "NodeWatch-Sign (signing tool …)"; not for customers).

## Once

1. Put `NodeWatch-Sign.exe` in a folder, open a Command Prompt or PowerShell there, and run:

       NodeWatch-Sign.exe setup

   It makes:
   - a code-signing certificate "BWN NodeWatch Code Signing" (RSA 3072, SHA-256, valid 5 years) in your
     Windows certificate store (Current User), and `BWN-NodeWatch-CodeSigning.cer`, its public part;
   - a minisign key (Ed25519), stored encrypted for your Windows account in `%APPDATA%\NodeWatch-Signing`,
     and `minisign.pub`, its public part.

2. Make an offline backup (a USB drive kept safe; the password is asked for):

       NodeWatch-Sign.exe backup E:\

   To move signing to another PC: `NodeWatch-Sign.exe restore E:\NodeWatch-signing-backup.nwsb`.

3. Give the customer's IT `BWN-NodeWatch-CodeSigning.cer`. They deploy it by Group Policy to
   **Trusted Publishers** and **Trusted Root Certification Authorities**. Give customers `minisign.pub` too.

## Every release

Download `NodeWatch.exe` and `NodeWatch.zip` from the release, put them next to `NodeWatch-Sign.exe`, and run:

    NodeWatch-Sign.exe sign NodeWatch.exe NodeWatch.zip

- Windows: every program file inside the installer (launcher, backend host, app window, compiled app,
  Python runtime) is Authenticode-signed and timestamped (timestamp server: timestamp.digicert.com; without
  internet the signature has no timestamp), the integrity list and the launcher's pinned hash are updated, and
  the installer itself is signed last. The files the Python runtime's makers already signed keep their signature.
- macOS: the app keeps its ad-hoc Apple signature (Apple's Developer ID and notarization are not free).
- Both files get a `.minisig`. Customers check a download with the official minisign:
  `minisign -Vm NodeWatch.exe -p minisign.pub`, or `NodeWatch-Sign.exe verify NodeWatch.exe minisign.pub`.

Send customers `NodeWatch.exe`, `NodeWatch.zip` and the two `.minisig` files.

## What is checked on GitHub

`.github/workflows/signing.yml` runs the whole flow with throw-away keys on a clean Windows machine: setup, sign,
minisign verification (NodeWatch-Sign and the official minisign 0.12), install the signed installer, every
installed program file validly signed, and the launcher starts (so the rebuilt integrity list is right).

## Limits (free signing)

- The signatures are trusted only on PCs whose IT trusts your certificate. Elsewhere Windows shows the publisher
  as unknown.
- macOS: no notarization; users open the app once via System Settings › Privacy & Security › Open Anyway.
