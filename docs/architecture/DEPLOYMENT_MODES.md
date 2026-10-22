# NodeWatch deployment modes

**Today (v0.10.22): desktop only.** One Windows user runs NodeWatch on their own PC. The backend listens on
`127.0.0.1`, the UI opens in its own app window, and the person at the keyboard holds every permission.
NodeWatch already reaches the internet *outbound* (Mist, Palo Alto, Splunk…); nothing can reach *it* from
another machine.

**Planned: server mode** — one NodeWatch shared by a team, on a server/VM on the LAN or VPN, and later
hosted (reachable from the internet). v0.10.22 lays the plumbing so this is an addition, not a rewrite.
Setting `NODEWATCH_DEPLOYMENT_MODE=server` today makes NodeWatch refuse to start: a shared NodeWatch
without real sign-in would hand a production write token to anyone who can reach it.

## What is already plumbed (v0.10.22)

| Seam | Where | Desktop behaviour (unchanged) | What server mode plugs in |
|---|---|---|---|
| Deployment config | `app/core/deployment.py` | `bind_host=127.0.0.1`, allowed Host headers `127.0.0.1`/`localhost`, loopback only, single user | Bind address, public host name(s), TLS, multi-user = true |
| Authentication provider | `app/core/auth.py` (`AuthProvider.authenticate(request, path)`) | `LocalTokenAuth`: loopback + same-origin + per-launch token, exactly the pre-v0.10.22 rules | e.g. OpenID Connect (Microsoft Entra ID / Okta) with a session cookie |
| Principal per request | `request.state.principal`, `auth.current_principal()` (context variable, reaches services in worker threads) | `LOCAL_USER` | The signed-in person, with their roles |
| Permissions on every production write | `auth.require(...)` at the top of `execute_port_action` (`ports.write`), VC `apply_changes` (`stacking.write`), `restore_object` (`config.restore`), `acknowledge_in_source` and the legacy alarm ack (`alerts.ack.write`) | Always granted | Roles → permissions (viewer / operator / admin); refusal is HTTP 403 |
| Fail closed outside a request | `current_principal()` returns `None` in multi-user modes | Background jobs run as `LOCAL_USER` | Background jobs run as an explicit service principal |
| Launcher | `app/launcher.py` checks the deployment; the native launcher opens a private app window | Desktop only | A server is run as a service, not by the desktop launcher |

## What server mode still needs (in order)

1. **Sign-in.** An OIDC provider in `app/core/auth.py` (authorization-code + PKCE, `Secure; HttpOnly; SameSite=Strict`
   session cookie, idle and absolute timeouts, sign-out). The per-launch token becomes a CSRF token bound to the session.
2. **HTTPS** with a real certificate (or behind a reverse proxy that terminates TLS), HSTS, and the Host allow-list
   from `deployment.allowed_hosts`.
3. **Roles.** Map identity-provider groups to the permissions above; add `require(...)` to settings and connection
   endpoints (`settings.admin`) and triage (`alerts.triage`).
4. **Per-person audit.** Every audit and validation record carries the principal (`current_principal().id/display`).
   This also replaces the shared-folder triage identity with signed-in identity, which closes the spoofing class of
   findings #3/N6 for good.
5. **Server-side secrets.** Windows Credential Manager and DPAPI are per Windows user; a service needs a machine-level
   store (DPAPI machine scope, or a vault such as Azure Key Vault / HashiCorp Vault) behind `app/core/credential_store.py`.
6. **Multi-user state.** Settings, saved views and UI preferences per user; shared state (triage, backups) with
   per-user attribution; concurrency guards on the write flows (the plan-token work in the migration plan).
7. **Running as a service.** Windows service or container, health endpoint, log shipping, backups of the data folder.
8. **Hosted (internet-facing) adds:** MFA via the identity provider, rate limiting and lock-out, a WAF/reverse proxy,
   security headers already in place, an external penetration test, and a way to reach on-prem devices (Panorama, SNMP)
   from the cloud (a small on-prem relay rather than opening inbound firewall holes).

## Rules for code written now

- Never hard-code `127.0.0.1`, `localhost` or "the user" in feature code: use `get_deployment()` and `current_principal()`.
- Every new production write calls `auth.require(<permission>)` before it does anything else.
- Never treat "the request came from this PC" as identity in new code; loopback is a desktop-mode transport detail.
