# BWN publisher identity and Windows SmartScreen

## Why Windows currently says `Unknown publisher`

Windows SmartScreen does not derive the Publisher shown in its warning from the EXE filename, application title, CompanyName metadata, or a string embedded in the launcher. It comes from a valid Authenticode signature whose certificate identity is trusted by Windows.

This package is intentionally left unsigned because the build environment does not have a trusted BWN code-signing certificate or Microsoft Artifact Signing identity.

## Recommended production release flow

1. Obtain/validate a BWN signing identity using Microsoft Artifact Signing (recommended by Microsoft for non-Store distribution) or an organization-validated code-signing certificate from a trusted CA.
2. Build the final NodeWatch package.
3. Sign `NodeWatch.exe` with SHA-256.
4. Timestamp the signature.
5. Verify the signature and certificate chain before distribution.
6. Never modify the EXE after signing.
7. Reuse the same trusted BWN publisher identity for subsequent releases so SmartScreen publisher reputation can accumulate.

A correctly signed new application can still receive an `unrecognized app` warning while reputation is being established, but the verified publisher identity will be shown instead of `Unknown publisher`. Self-signed certificates do not solve public SmartScreen reputation.

## Generic local certificate signing helper

`_internal/release/Sign-NodeWatch.ps1` is included as a release helper for a trusted code-signing certificate already installed in the Windows certificate store. It does not create or acquire a certificate.
