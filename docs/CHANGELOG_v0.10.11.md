# NodeWatch v0.10.11 — one place for alerts, simpler names

Build: `2026-10-09-v0.10.11-merge-alerts`

## Notification Hub merged into Command Center
- Command Center now ends with **Alerts & Notifications**: the live alert feed, browser alerts, the alert
  policy (poll interval, outage thresholds, confirmation delay, device types) and the HTTPS/Slack webhook.
- Disconnect Watch's button is now **Alert settings** and jumps to that section.
- Removed duplicates: the hub's own "currently down / outage clusters" counters (Disconnect Watch already shows
  them) and its separate Refresh button (Refresh NOC now refreshes alerts too).
- Browser alerts now start when NodeWatch opens. Before, they only ran after you visited Notification Hub.
- The server-side monitor and webhook delivery are unchanged, and so are your saved alert settings.
- Old links and bookmarks to `#alerting` open Command Center at the alerts section.
- The Command Center menu badge shows the number of devices currently down.

## Renamed
**Change & Config Vault → Config Backups** (menu short name "Backups"). Same page, same snapshots and settings.

The menu now has 13 items (was 14), so the whole menu fits on a laptop screen in Aurora.
