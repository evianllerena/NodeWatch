# NodeWatch v0.10.40 — pages open faster, less deadweight

Based on the diagnostics from your machine (two days of timings: 11,700 Mist calls, plus the EdgeConnect calls). Mist usage was only about 2% of the hourly limit, so the time went to waiting, not to the budget: device statistics take about 5 s per read, alarms about 1 s, port statistics 1–4 s, and pages waited for those reads every time a cached copy expired.

## Faster
- **Pages answer from the last reading while it refreshes.** When Mist data has just expired (within a few minutes), a page now gets it immediately while one background read refreshes it. Before, the page waited for Mist (up to 5–7 s for device statistics). Refresh buttons, changes you make and the alerting monitor still always read current data.
- **The same treatment for device events and EdgeConnect Orchestrator.** Readers of the event history no longer wait for each incremental read, and Orchestrator answers (tunnels, circuits, health) refresh in the background.
- **Warm start.** At start-up NodeWatch reads the site list, site and device statistics, device inventory, open alarms and alarm definitions in the background, so the first visit to most pages finds them ready. Alarm definitions (a fixed Mist table that took up to 11 s) are kept on disk for a week.
- **One read instead of several.** Device statistics for one type or one site are taken from the organisation-wide reading when it is current, instead of a separate ~5 s read; Virtual Chassis takes its 1-day alarms from the shared alarm reading.
- **Refresh refreshes only that page.** Refresh on the Command Center, Asset Library, Activity Log or Chassis Manager re-reads that page's data instead of emptying every cache (which made the next page you opened start cold).
- **No more 40–90 s calls.** Every Mist and connector request now has an overall deadline (its timeout plus 10 s, including a slowly arriving answer); connecting gives up after 10 s. A read that hits a Mist gateway error (502/503/504) or a refused connection is retried once.
- **More reused connections.** Up to 16 idle connections per host are kept (was 4), so a page's burst of parallel reads does not pay for new TLS handshakes.
- **Reads that waited on each other now run together:** Config Backups (16 organisation reads), Port Toolkit overview (the port search is the unsorted, parallel-page one; site and device names alongside), Chassis Manager all-sites (switch statistics alongside the inventory), Activity Log (audit sources and name lookups).
- **The alerts panel never waits for a background check:** a page asking while the alerting monitor builds gets the last feed at once. Missing alarm definitions or events no longer hold the alerts back for more than 4 s.
- **Power Guard** stops forcing uncached Mist reads every 30 s for the selected switch (Mist updates those figures about once a minute); Refresh now still reads Mist directly.
- **EdgeConnect:** route tables are kept 5 minutes, WAN deployment settings an hour.

## Smoother pages
- The Command Center starts its data and the alerts panel together and wires its controls straight away; incident rows no longer search the whole list each.
- The alerts feed stops polling every 20 s while you are on another page (unless browser notifications are on).
- Device Finder no longer waits for the site list (and Enter before it arrives no longer reloads the window).
- Chassis Manager, Config Backups, the Validator and Settings start their independent requests together.
- Port Toolkit's 30 s refresh no longer re-requests port profiles or **overwrites unsaved edits in the port form** (fixed).
- Event Relay and the Activity Log refresh every 2 minutes while open instead of rebuilding up to 1,000 rows every 30 s; going back to Activity Log, Event Relay, Config Backups or Device Finder within 20 s does not reload them.
- A page opened again while it is still starting no longer starts twice (which registered its controls twice).

## Cleanup
- Removed: 250 unused style rules (≈33 KB of CSS no page uses), an unused topology drawing function, unused API endpoints (`/api/platform/*`, legacy config-backup routes `/drift`, `/validations`, `/validate`, `/snapshot-detail`, the old single-alarm acknowledge, `/api/roadmap`, the deprecated `mist_logs` history field) and the in-memory raw-record store that kept copies of traffic log rows nobody read.
- Removed the `MNT_ACTIVE_PORT` compatibility variable.
- State files (topology caches, search index, DNS cache, security log cursors, …) are written through the same atomic, owner-only writer as everything else.
- The installer no longer carries internal QA, review, change-control, release and signing notes.

## For support
- Every page request is timed: `Server-Timing` on each response, and "NodeWatch API" (slowest page requests by route) in the diagnostics export next to the Mist and EdgeConnect timings, so the next export shows exactly which page request was slow.
