# NodeWatch v0.10.12 — operations fixes (47 requests)

Build: `2026-10-09-v0.10.12-ops-fixes`

## Everywhere
- Every table: click a column header to sort (again to reverse); a filter box where the page has none.
- Every site drop-down: alphabetical, with a search box (Command Center, Device Finder, Chassis Manager,
  Port Toolkit, Config Backups, Power Guard).
- No "Raw Mist fields" anywhere: alerts, devices, events and audit records show labelled, readable details.

## Command Center
- Header: green dot + "Refresh in Ns" countdown + "Updated <time>" (the "Live attention view" text is gone).
- Quick search finds any device or client org-wide and shows it first; Enter opens Device Finder.
- Summary tiles (Critical, Warnings, Devices Down, VC Degraded, Needs Attention) filter the alerts; click again to clear.
- Disconnect Watch tiles open lists (currently down, new, recovered, sites affected).
- "Currently down" list redesigned: one aligned row per device with type, site, how long down, Mist link, Mark known.
- Requires Attention fills its row; filler text "Mist reports an active condition…" removed.
- Issue Categories show critical/warning split and top issues, highlight when active, click again to clear.
- Menu badge shows the real number of alerts needing attention.
- Alert details: "What Mist reported" (Mist's own text/reason, device status, last seen, model/firmware,
  recent events with reasons, other devices down at the site) and "Details reported by Mist";
  device names and "Open in Mist" go to the device's page in the Mist portal.

## Device Finder
- Site only + Investigate lists every device and client at the site (no 1,000-row cap).
- Partial IPs such as "10.7" are matched as IP prefixes (previously matched only names/MACs).
- Pager above and below results (50/100/200/500); "More information" shows curated fields.

## Port Toolkit / Power Guard
- MAC column shows the connected device (never the switch's own MAC); wired-client hostname/manufacturer/VLAN.
- Internal interfaces (bme0, vme0, …) hidden by default; LAG members shown; speeds as 1G/10G; port details dialog.
- PoE budget and draw read from Mist's per-member module statistics; per-member table; mode and high-draw filters.

## Chassis Manager
- Cancel/× in the member dialog no longer adds a switch to the commit list; nothing is pre-selected.
- Discovery tiles keep long switch names inside the card.

## Event Relay / Splunk / Activity Log
- Event rows open a detail dialog with readable fields and an "Open in Mist" link; local date/time; colour coding
  (red deleted, green added/committed, yellow no change); severity chips; site names.
- Splunk HEC: Splunk Cloud GCP hosts accepted, web URLs rejected with the exact HEC URL to use, clear timeout
  messages, 512 KB chunks, delivered chunks never re-sent, no backlog re-send after restarts.
- Activity Log: Action, What, Site, Source IP columns; dialog with a sentence summary and a colour-coded
  "What changed" table. Local change records show time, tool, target and result.

## Operations Assistant
- Understands "what's broken", "how is <site>" (typo-tolerant), "is <device> up", "where is <mac/ip/host>",
  "what's down", "what changed today", PoE/ports/VC questions; answers with facts, buttons and follow-ups.
- Voice: microphone button (Edge/Chrome speech), "read answers aloud". "Open Mist (Marvis)" link.

## Install / processes
- Python is bundled (no Python install needed); first start still downloads the Python packages once.
- The backend runs as **NodeWatchBackend.exe** (falls back to python.exe if that ever fails twice).
- Settings & Support → Exit NodeWatch stops the backend.
- Palo Alto Test Connection only reports "Verified" after it actually reads devices from IoT Security.
