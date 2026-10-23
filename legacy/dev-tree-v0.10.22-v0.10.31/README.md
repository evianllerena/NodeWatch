# NodeWatch v0.10.31

NodeWatch is a local Windows network-operations portal for Juniper Mist, with read-only Palo Alto Networks
integrations. A small native launcher (`NodeWatch.exe`) starts a private Python backend bound to
`127.0.0.1` (ports 8765–8795) and opens the browser UI.

## What it does

| Area | Tools | Mist access |
|---|---|---|
| Monitor | Command Center (dashboard plus disconnect alerts, browser and webhook notifications), Security Operations (vendor-neutral SOC: Watch floor, Case desk, Atlas, detections, vulnerabilities), Event Relay (JSONL/CEF/syslog/Splunk HEC) | read |
| Investigate | Device Finder (clients/devices, Marvis troubleshoot, Palo Alto device intelligence, Traffic & Sessions), Operations Assistant | read |
| Operate | Port Toolkit (bounce, cable test, port profile), Chassis Manager (Virtual Chassis membership/roles) | **writes to production** |
| Govern | Config Backups (encrypted snapshots, drift, change verification, rollback) | snapshots read; **rollback writes** |
| Shared | Asset Library, Activity Log, Settings & Support (diagnostics export) | read |

Every production write requires an explicit confirmation, is validated before it is sent (see "Write safety"),
is written to the local audit store before and after, and is followed by an automatic validation report.

## Installing (users)

**Windows:** run `NodeWatch.exe` and click **Next → Install → Finish**. It installs for your Windows account
only: no administrator rights, no internet connection and nothing else to install first. The default folder is
`%LOCALAPPDATA%\Programs\NodeWatch`; **Browse…** picks another. NodeWatch then appears in the Start menu (and on the
desktop if you keep that box ticked), and **Settings › Apps** removes it. Running a newer `NodeWatch.exe` updates
NodeWatch in place and keeps your settings and backups; running the same one again just opens NodeWatch.
IT can install silently: `NodeWatch.exe /S [/NODESKTOP] [/D=C:\path\NodeWatch]`.

**Mac** (macOS 11 or later, Apple silicon or Intel): open `NodeWatch.zip` and double-click **NodeWatch**. The first
time, macOS says it cannot verify the app (it is not notarized by Apple yet): open **System Settings › Privacy &
Security**, click **Open Anyway** next to NodeWatch, and confirm. NodeWatch then offers to install itself in
Applications and opens from there. Settings, backups and logs are kept in `~/Library/Application Support/NodeWatch`;
passwords and API tokens in your login keychain (Keychain Access shows them as `NodeWatch:…`). To remove NodeWatch,
drag it from Applications to the Bin.

NodeWatch opens in its own window (Edge or Chrome app mode, on Windows and Mac). Without either browser, or with
`NODEWATCH_OPEN_IN_BROWSER=1`, it opens in your default browser.

## Palo Alto integrations

Both use one Common Services service account (Client ID + Client Secret + TSG ID), stored in Windows
Credential Manager. Tokens come from `auth.apps.paloaltonetworks.com` (client-credentials, scope `tsg_id:<TSG>`).

- **Device Intelligence** – IoT Security device lookups by IP/MAC on `api.strata.paloaltonetworks.com/iot/pub/v1/...`.
- **Traffic & Sessions** – firewall traffic logs from the Strata Cloud Manager **Log Viewer API**:
  `POST https://<region>.api.prismaaccess.com/api/sase/v3.0/resource/query/logviewer/firewall_traffic`
  with `Prisma-Tenant: <TSG>`. Set the **Log query host** (default `pa-us01`) to the host your SCM Log Viewer
  uses (browser DevTools → Network → `logviewer/firewall_traffic`). If Palo Alto expects a sub-tenant, put
  `<TSG>:<sub-tenant>` in **Prisma-Tenant override**. Turning the switch on runs one real read-only query and
  saves only if it succeeds. This API is what the SCM console itself uses; Palo Alto does not publish it as
  a supported public API, so re-verify after SCM changes.

## Write safety (v0.10.7)

- Port actions: the port must exist on that switch; uplink/VC/aggregated/management ports need an explicit
  second confirmation; usage, speed and duplex are allow-listed; confirmation must be the boolean `true`.
- Rollback: compares only writable fields, clears settings added after the snapshot, and reports
  `verified: true` only when the device matches the snapshot; otherwise it lists what still differs.
- Virtual Chassis: `preprovisioned` and the editor's original member list are mandatory; master/backup are
  tracked separately; existing VC ports are preserved; a master/backup change Mist cannot confirm is reported
  as unconfirmed, not verified.

## Development

```
python -m venv .venv && .venv\Scripts\pip install -r requirements.txt pytest httpx
.venv\Scripts\python -m pytest            # Python tests (+ Node/ESLint frontend tests when installed)
eslint app/static                         # frontend lint (eslint.config.cjs)
ruff check app tests release              # Python lint (ruff.toml)
```

`tests/test_strata_live_optional.py` runs one real Log Viewer query against your tenant when the
`NODEWATCH_LIVE_PA_*` environment variables are set (see the file header).

## Releasing

See `docs/RELEASE_PROCESS.md` (lock file, integrity manifest, launcher build, signing) and
`docs/SECURITY_MODEL.md` (what the local protections do and do not cover).

## Documentation

- `docs/CHANGELOG_v0.10.13.md` – firewall-style traffic log
- `docs/CHANGELOG_v0.10.14.md` – Port Toolkit faceplate + port configuration, Power Guard live refresh
- `docs/CHANGELOG_v0.10.15.md` – org overviews, Config Backups safety net, layouts, readability, auto-exit, faster start
- `docs/CHANGELOG_v0.10.16.md` – incident-based Requires Attention, vendor connector platform, Topology
- `docs/CHANGELOG_v0.10.17.md` – Panorama + SCM, Silver Peak validated, SNMPv3, path trace, live health
- `docs/CHANGELOG_v0.10.18.md` – Topology v2, team triage, connection wizard, Mist API budget, offline install
- `docs/CHANGELOG_v0.10.19.md` – Silver Peak connection fixes
- `docs/CHANGELOG_v0.10.22.md` – this release (security release: install hardening, launcher handshake, shared triage identity)
- `docs/CHANGELOG_v0.10.21.md` – Topology: Closets layout, much faster maps
- `docs/CHANGELOG_v0.10.20.md` – Silver Peak overlay tunnels on large fabrics
- `docs/TOPOLOGY.md` – topology research and design
- `docs/TEAM_TRIAGE.md` – shared triage design
- `docs/CONNECTORS.md` – how NodeWatch connects to vendors and how to add one
- `docs/CHANGELOG_v0.10.12.md` – operations fixes
- `docs/CHANGELOG_v0.10.11.md` – Notification Hub merged, Config Backups
- `docs/CHANGELOG_v0.10.10.md` – Aurora default, night mode, hideable menu
- `docs/CHANGELOG_v0.10.9.md` – modern themes
- `docs/CHANGELOG_v0.10.8.md` – UI themes
- `docs/UI_MAP.md` – how to ask for UI changes in plain English
- `docs/SECURITY_MODEL.md` – threat model and controls
- `docs/RELEASE_PROCESS.md` – how to cut a release
- `docs/ARCHITECTURE.md`, `docs/architecture/NODEWATCH_DATA_PLATFORM.md` – architecture
- `docs/change-control/`, `docs/traffic-sessions/` – historical change records
