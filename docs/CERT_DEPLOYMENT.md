# Deploying the NodeWatch code-signing certificate (for the customer's IT)

NodeWatch is signed with BWN's own code-signing certificate (there is no public CA). Windows trusts the signature
only after your IT deploys the certificate. This is a one-time task; it does not need repeating per release.

## The file

`BWN-NodeWatch-CodeSigning.cer` — the public certificate (no private key; safe to distribute). Subject
"BWN NodeWatch Code Signing", valid to 2031-10-23. Confirm the SHA-1 thumbprint out of band before deploying:
`D0 97 45 51 7D 7D B4 62 4E 6D 47 38 53 C3 30 0D CD 86 48 7F`
(PowerShell: `Get-PfxCertificate BWN-NodeWatch-CodeSigning.cer | Format-List Subject,Thumbprint,NotAfter`).

## Deploy by Group Policy (recommended)

Add the certificate to two stores for the pilot machines:

1. **Trusted Publishers** — so the signature is trusted without a prompt.
   Group Policy: Computer Configuration → Policies → Windows Settings → Security Settings →
   Public Key Policies → **Trusted Publishers** → Import `BWN-NodeWatch-CodeSigning.cer`.
2. **Trusted Root Certification Authorities** — because the certificate is self-signed, its own root must be
   trusted. Same path → **Trusted Root Certification Authorities** → Import the same file.

Scope the GPO to the pilot machines (an OU or security group). No reboot is needed; `gpupdate /force` applies it.

## Verify on a pilot machine

- `Get-AuthenticodeSignature "C:\Users\<user>\AppData\Local\Programs\NodeWatch\NodeWatch.exe"` → Status **Valid**,
  SignerCertificate subject "BWN NodeWatch Code Signing".
- The installer and every program file inside it are signed the same way.

## The minisign check (anyone, no install)

Each download also has a `.minisig` file. Users or IT can confirm a file came from BWN with the public key
`minisign.pub`:

    minisign -Vm NodeWatch.exe -p minisign.pub

This is independent of Windows trust and works on any OS.

## macOS

The macOS app is ad-hoc signed (Apple's Developer ID and notarization are paid and not used). On first launch a
user opens it once via System Settings → Privacy & Security → **Open Anyway**. The `.minisig` check above also
applies to `NodeWatch.zip`.

## When the certificate is replaced

If the certificate ever changes (it expires in 2031, or is reissued), IT repeats the import with the new
`BWN-NodeWatch-CodeSigning.cer`. Releases signed with the old certificate stay valid until it expires.
