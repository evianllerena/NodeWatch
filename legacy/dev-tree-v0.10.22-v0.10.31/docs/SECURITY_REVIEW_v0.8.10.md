# NodeWatch v0.8.10 Security Review

Scope: native Windows launcher, loopback web backend, browser UI, owner-only Platform Overview, local persistence, credentials, diagnostics, alert/SIEM integrations, dependency bootstrap and release packaging.

## Material changes in v0.8.10

- Keeps the `%LOCALAPPDATA%\NodeWatch` migration introduced in v0.8.9.
- Uses the version-scoped private runtime `python.exe` with Windows `CREATE_NO_WINDOW` instead of `pythonw.exe`, preserving a GUI-only startup while making stderr/stdout capture reliable.
- Enables Python faulthandler and unbuffered output for startup diagnostics.
- Truncates `backend-launcher.log` at each launch so the active failure is easy to identify instead of being buried under historical output.
- Prefers Python 3.12 first when preparing the private runtime on Windows, while retaining support for 3.13/3.11/3.10.
- Keeps a fresh cryptographically random per-launch nonce. Exact version + exact build + nonce proof is the authoritative backend handoff check.
- Treats Windows process-image lookup as defense-in-depth diagnostics instead of a hard acceptance gate. This avoids false rejection caused by venv redirectors, EDR hooks, or process-query restrictions after the backend has already proven knowledge of the fresh secret.
- Records candidate-backend exit status in the native launcher log and captures backend startup output in a dedicated backend log.
- Corrects frontend version/build constants so a healthy v0.8.10 backend is not mislabeled as a browser/backend build mismatch.

## Existing hardening retained

- Loopback-only backend and Host allowlist.
- Per-launch unpredictable write token and same-origin enforcement for unsafe API methods.
- 2 MiB request-body ceiling.
- Swagger/ReDoc/OpenAPI disabled.
- Strict CSP and related browser security headers.
- Backend-enforced owner session using HttpOnly SameSite=Strict cookie.
- Windows Credential Manager for API/integration secrets.
- Current-user DPAPI protection for configuration snapshots.
- Redaction for audits, diagnostics, validation output and SIEM material.
- Protected POST for state-producing diagnostic/SIEM exports.
- HTTPS requirement and URL validation for alert webhooks.
- Pinned direct dependencies and binary-wheel-only bootstrap.
- SHA-256 integrity manifest anchored by a digest compiled into the native launcher.

## Residual risks / intentional exceptions

1. **Unsigned executable** — verified BWN publisher identity requires Authenticode or Microsoft Artifact Signing using a trusted BWN identity.
2. **Local administrator / host compromise** — a sufficiently privileged local attacker can patch processes, credentials, or the launcher; desktop controls cannot create an absolute anti-tamper boundary against the host administrator.
3. **Dependency bootstrap** — dependencies are pinned and source distributions are blocked, but first-run installation is not yet an offline hash-locked wheelhouse. Move to `--no-index --require-hashes` before broad distribution.
4. **Optional TLS bypass** — deliberate TLS verification disablement remains available for exceptional environments and produces an explicit warning.
5. **CEF syslog** — ordinary UDP/TCP CEF forwarding is not encrypted.
