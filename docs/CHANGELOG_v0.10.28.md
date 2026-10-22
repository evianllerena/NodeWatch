# NodeWatch v0.10.28 — Finding the second firewall of each HA pair

Build: `2026-10-16-v0.10.28-ha-partners`. Delivered as **`NodeWatch.exe`** (Windows) and **`NodeWatch.zip`** (Mac).
Both carry the identical application tree.

## Why only one Palo Alto per site was visible (from the v0.10.27 diagnostics)
- **Routes work now:**
  - 54,093 routes were read from the EdgeConnects;
  - 1,396 of them point at devices behind the routers;
  - 543 site networks were learned (up from 28).
- **Traffic logs name 11 site firewalls and 5 cloud gateways.** None of the 11 has an HA partner in those logs.
  - A passive HA unit passes no traffic, so it never writes traffic logs.
  - Strata Cloud Manager lists no firewalls at all.
  - So nothing NodeWatch received named the second unit. It was not hidden by the drawing.
- **The system logs refused NodeWatch's query.** The passive unit does write system logs (HA, heartbeat), but
  the log service refused the query (HTTP 400) under the one dataset name NodeWatch tried, and NodeWatch then
  stopped asking.

## Changed
- **System logs, every candidate tried:**
  - The system log is now tried under every name and time field the Log Viewer may use.
  - The first combination that answers is remembered.
  - If all are refused, the log service's own error text is written to the diagnostics, and NodeWatch tries
    again after 24 hours instead of never.
- **Firewalls active earlier this week are found:** traffic logs from the past 7 days are also searched for
  firewalls not seen in the last 24 hours. This finds a unit that was active before a failover.
- **The organization page says it plainly** when HA partners cannot be seen yet. Connecting Panorama
  (Settings › Connections) shows both units of every pair directly.
- **Diagnostics list every firewall found by name**, with its HA state when known, so the next file shows whether
  PA1 and PA2 both appear.
