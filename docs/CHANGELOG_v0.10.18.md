# NodeWatch v0.10.18 — Topology v2, team triage, connection wizard, lighter on Mist

Build: `2026-10-09-v0.10.18-team-triage`. Delivered as `NodeWatch.zip` (`NodeWatch.exe` + `_internal\`).

## Topology v2 (research: Auvik, Dynatrace Smartscape, Scanopy, ExtraHop; see docs/TOPOLOGY.md)
- **Three levels:** Organization (sites with SD-WAN/VPN trunks and their health) → Site → Device (every port with its neighbour).
  - Move between levels with breadcrumbs, double-click/Enter and Backspace.
- **Cleaner layout:**
  - Rows ordered to reduce line crossings; right-angle links that route around boxes.
  - LAGs drawn as double lines; APs stacked under their switch.
  - Labels that never overlap; groups with counts.
- **Easier to read and navigate:**
  - Hovering a device or link shows its details, including ports, speed, utilization and errors.
  - Port names appear when you zoom in; a minimap is available.
  - Search with 1–3-hop neighbourhood focus; filters by role, vendor, status, problems only and changes only.
- **Saved views, export (SVG/PNG/JSON) and changes since baseline:** new devices and links are marked NEW, missing ones are drawn as dashed ghosts.
- **Path trace and live health** work on every level.
- **Performance:** a 1,000-device site renders in under 0.3 s.

## Team triage
- **Pluggable triage store**, choosable in Settings › Team triage:
  - Only this PC (default; existing state migrated, old file kept as a backup).
  - Shared folder: each PC appends to its own log file in a network share, so there are no locks.
  - Team server: designed, coming later.
- **Who did what:** every action names the person and time. Incidents can be assigned (Assign to me / to a teammate) and carry a notes thread; a new "Mine" tab lists your incidents.
- **Undo** writes a correcting event and never overrides a teammate's later change.
- **Shared folder edge cases:** offline actions queue and sync when the share returns; a read-only share is shown as read-only.
- **Ticketing and chat hooks:** a `TriageSink` interface is ready for Jira, ServiceNow, Teams or Slack. See docs/TEAM_TRIAGE.md.

## Connections: a guided workflow for every vendor
- **"+ Add connection" wizard:**
  1. Choose a vendor.
  2. Before you start: what to create on the vendor side, with least-privilege steps.
  3. Connect.
  4. Test: reachable, TLS, authenticated, permissions, and what was found.
  5. Done: what you get and where to see it.
- **Per-capability permission check:** for example, with a read-only Silver Peak key the Test shows exactly what the key can read and whether more permission would unlock anything.
- **Layout:** Connected and Available sections. Connectors this company doesn't use, such as Panorama, stay available without clutter.
- **For developers:** `tools/new_connector.py` scaffolds a new vendor from the template, and docs/CONNECTORS.md has "Add a new vendor in 6 steps".

## Lighter on the Mist API
- **Fewer calls:** about 1,900 → 510 Mist calls per hour with Command Center open, and about 2,600 → 690 on Topology. Mist allows 5,000 calls per hour per token.
- **Device events:** loaded once, then only new events every 30 s, shared by all features.
- **Rarely-changing data is cached longer:** sites, inventory and alarm definitions.
- **Usage guard:** above 70% of the limit, NodeWatch slows its refreshes and shows a notice. HTTP 429 (Retry-After) is honoured.
- **Faster Command Center builds:** about 3.5× faster with 2,000 alarms. Alarm detail is now built only when an incident is opened.
- **Fixed:** the device directory asked Mist for `inventory?type=all`, which Mist rejects.

## Start-up and install
- **Optional components never block start-up.** The SNMP connector's packages are now in `requirements-optional.txt`; if they can't be downloaded, NodeWatch starts without them and retries on the next start.
- **Offline packages:** `release\Build-Offline-Wheels.ps1` bundles every package into `runtime\wheels\`, so a package built this way installs with no internet access.

## Event Relay (Splunk)
- **Splunk forwarding in Support diagnostics:** the export now includes the forwarding settings (no token), delivery status, last error and the last "Diagnose connection" result.
