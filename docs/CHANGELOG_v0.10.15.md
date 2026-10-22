# NodeWatch v0.10.15: overviews, configuration safety net, layouts, readability, auto-exit

Build: `2026-10-09-v0.10.15-overviews`. Delivered as `NodeWatch.zip`, which contains `NodeWatch.exe` and `_internal\`.
The exe name no longer changes between versions.

## Org overview first, then drill down by site
- **Port Toolkit › Port health overview.** Shown when no switch is selected: for the whole org, or for one site
  once a site is picked.
  - Issue categories: uplink/LAG down; err-disabled, loop or BPDU; CRC/input errors; flapping; PoE faults;
    down but expected up; STP blocking; half duplex or low speed; 802.1X failures.
  - Ranked by severity and grouped by site and switch. A row opens that site, switch and port.
- **Chassis Manager › Stack health.** Every stack in the org ranked by health:
  - members missing, VC ports down, no backup routing engine, mixed firmware;
  - PSU, fan and temperature faults, CPU and memory;
  - reboots and master switchovers in the last 7 days, preprovisioned members that don't match.
- **Power Guard › PoE risk overview.** Switches and VC members ranked by PoE budget use. Also shows PSU
  problems, PoE faults and alarms, PoE-powered APs that are offline or on reduced power, and the ports drawing
  the most power. Refreshes quietly.

## Chassis Manager: much more data
When a stack is selected:
- A topology diagram, with ring or daisy-chain detection and link state.
- Plain-English verdicts on redundancy, firmware, topology and membership.
- A member table: role, state, serial, firmware, uptime, CPU and memory, temperature, PSUs and fans, PoE used
  against budget, ports up.
- Environment cards, a VC port table and a 7-day timeline of VC events.

## Port Toolkit
- The switch view stacks every Virtual Chassis member at once: FPC, role and model, plus an
  up / PoE / unused / issues summary. Unused ports have a distinct look.
- Empty cells are explained:
  - `ae` and `irb` are logical interfaces, so they have no PoE, MAC or LLDP of their own.
  - Auth only applies to 802.1X ports.
  - The cells now show a muted "n/a" with the reason on hover.
- `ae` interfaces now show their member links' neighbors. `irb` shows its IP addresses and networks (read from
  `if_stat`).
- **▦ Columns.** Add any of 55 fields (VLAN, STP, LLDP, counters, errors, transceiver, PoE class, …, plus any
  raw Mist field). The choice is remembered.

## Config Backups, rebuilt as a safety net
- **Snapshots.** Scheduled snapshots of org and site configuration, redacted (PSKs, RADIUS secrets, passwords
  and tokens are never stored). A safety snapshot is also taken automatically before every Port Toolkit and
  Chassis Manager write.
- **Opening view.** Answers four questions: when was it last captured, what changed since, who changed it
  (from the Mist audit log), and can it be rolled back.
- **Comparing.** Readable diffs between any two snapshots, or between a snapshot and live Mist. Drift between a
  template and the devices using it.
- **Restore.** A per-object restore preview. Restores are confirmed and audited.
- **Export and import.** As zip or json.

## Look & layout
- **Page layout** is separate from the colour theme: Aurora glass (default), Compact NOC, Top navigation,
  Focus / wide, or Custom. Custom covers menu position, density, content width, corners, glass and shadows.
- **Text size**: Small, Default, Large or Extra large.
- **Menu handle.** The round handle in the middle of the menu's right edge folds and unfolds the menu. The
  "Hide menu" button at the bottom is gone.
- **Readability.** Larger type everywhere: body 15 px, table cells 14 px, no text below 11.5 px.
- **Night mode.** Softer off-white text. Muted text, links, borders and row separators are all raised to well
  above WCAG AA contrast.

## Traffic & Sessions
- The 15-minute and full-window queries run at the same time instead of one after the other.
- Connections to Palo Alto are kept open and compressed between queries.
- Results are cached for 60 s, and a device is prefetched when you hover over it.
- A single combined source/destination query is tried, and used only once it has been proven to return the
  same rows.
- **Full screen.** Always shows a ✕ Exit button. Esc, the Restore toggle and clicking outside also exit. Rows
  render 100 at a time, and scrolling is smooth (60 fps).
- **Status line** is now compact: log count and time range, a response-time chip, a Live pill (its tooltip
  explains the 1–2 minute Strata delay), and a thin loading bar.

## Event Relay (Splunk HEC)
- **Diagnose connection** checks each stage in turn and stops at the first one that fails: URL, proxy, DNS,
  TCP, proxy tunnel, TLS, HEC health, then the token. The token check sends no event. It explains the likely
  cause:
  - a proxy or PAC script is required;
  - a firewall blocks 443;
  - Splunk Cloud's HEC IP allow list;
  - TLS inspection;
  - a wrong stack name.
- It runs automatically when a test event fails.
- **Proxy (optional)** field for Splunk HEC. Without it, the Windows/system proxy is used.

## Closing and starting
- NodeWatch stops by itself about 15 s after its last browser tab closes, so the Exit click is no longer
  needed. A reload or a second tab keeps it running.
- If the browser crashes, it stops after about 4 minutes. A sleeping PC is not treated as closed.
- **Faster start:**
  - The launcher probes its ports in parallel; this was a multi-second delay on Windows.
  - Upgrades reuse the private Python runtime when dependencies haven't changed, instead of re-downloading
    packages.
  - Compiled Python files are shared across versions.
  - The first page no longer waits for the live Mist connection test.

## Safety fixes from the release review
- **Restore requests only reach the object shown.** Restore builds Mist URLs only from validated Mist IDs, and
  imported snapshot objects with non-UUID IDs or unknown types are dropped.
- **Secrets are not swapped between unnamed list entries.** If a list entry has no unique name, a live secret is
  reused only when its fingerprint matches the snapshot. Otherwise the restore is blocked.
- **Restore and Chassis Manager audit records** use the full configuration redaction (OSPF/WEP keys, md5 and
  similar).
- **The pre-change safety snapshot ID** is now recorded in the Port Toolkit and Chassis Manager audit records.
- **Snapshot import** accepts files up to 50 MB.
- **Auto-exit:**
  - A tab the browser puts to sleep (Edge sleeping tabs, Memory Saver) keeps NodeWatch running for up to
    8 hours.
  - A change still being written to Mist holds off the exit.
  - A tab that comes back after NodeWatch stopped says so.
- **Launcher:** an old private runtime is removed only after the new one is ready, and only if it has been
  unused for 14 days.
- **Diagnose connection** reports a proxy or firewall that cuts the connection mid-check, instead of failing,
  and never shows proxy credentials.
