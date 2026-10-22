# NodeWatch v0.10.14 — Port Toolkit switch view and port configuration

Build: `2026-10-09-v0.10.14-port-config`

## Power Guard (PoE power safety)
- Quiet 30-second auto-refresh with a countdown ("Refresh in 24s · Updated … · Refresh now"). The table is
  only redrawn when something changed; scroll position, filters and focus are kept. A failed refresh shows
  "Refresh failed — retrying" instead of clearing the page.
- Full-width layout: capacity cards across the top, the port table below using the whole width.
- Click (or Enter on) any row to open the full port details (link, speed, PoE, LLDP neighbor, wired clients,
  VLANs, errors, profile) — the same details dialog as Port Toolkit.

## Port Toolkit — switch faceplate
- A front-panel view of the switch: even ports on top, odd below, in blocks of 12, grouped by RJ-45 / SFP+ /
  QSFP28. Tiles show up / down / PoE / uplink / disabled; hover shows port, speed, profile, draw and device.
- Virtual Chassis members appear as tabs (Primary / Backup / Member).
- Click selects a port, Ctrl-click adds/removes, Shift-click selects a range. Table rows select too.

## Port Toolkit — port configuration (Mist-style)
- Port IDs (editable, ranges allowed: `ge-0/0/1, ge-0/0/4, ge-0/1/1-23`), Interface (L2; L3 stays in Mist),
  Configuration Profile with its VLAN summary (e.g. `ap — WAP(199), A, B, trunk, edge`), Dynamic Port
  Configuration, Description, Up/Down Port Alerts, Port Aggregation (+ AE index), Allow switch port operator
  to modify port profile.
- Values are prefilled from the switch config; mixed values across a multi-port selection are shown as mixed
  and are left alone unless changed. Only changed fields are sent.
- "Review N changes" shows Port / Setting / Now / After plus warnings before anything is written; then
  "Apply to Mist". Protected ports (uplinks, VC, aggregated links, uplink/trunk profiles) and any aggregation
  change need an extra tick-box.
- Writes split existing range keys (`ge-0/0/0-47`) so no port is listed twice in Mist; at most 96 ports per
  change. Each change is audited (Activity Log) and validated afterwards.
- Bounce Port, Run Cable Test and Port details remain under Port actions.
