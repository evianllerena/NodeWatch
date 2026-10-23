# Public signing keys (safe to share)

Made on the owner's PC with NodeWatch-Sign.exe setup on 2026-10-23. The private keys never left that PC.

- `BWN-NodeWatch-CodeSigning.cer`: code-signing certificate "BWN NodeWatch Code Signing" (O=BWN), valid
  2026-10-23 to 2031-10-23, SHA-1 thumbprint D0974551 7D7DB462 4E6D4738 53C3300D CD86487F. The customer's IT
  adds it to Trusted Publishers and Trusted Root Certification Authorities.
- `minisign.pub`: minisign public key 57C81AE34D0D220B. Customers check a download with
  `minisign -Vm NodeWatch.exe -p minisign.pub`.
