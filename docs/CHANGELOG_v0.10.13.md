# NodeWatch v0.10.13 — firewall-style Traffic & Sessions

Build: `2026-10-09-v0.10.13-traffic-log`

## Why it was slow
Diagnostics showed each lookup sends two Log Viewer queries (source IP, destination IP; the API has no OR).
Palo Alto took 31 s to answer them for a one-hour window at 12:37 (8–16 s earlier in the day); NodeWatch's own
time was negligible. Changes:
- The query starts the moment a device is clicked (before its details finish loading).
- The last 15 minutes are fetched first and shown (small windows answer faster), then the selected window.
- The meta line shows how long Palo Alto took.

## The table (Device Finder › Security & access › Traffic & Sessions)
- Same columns and order as the firewall Traffic log: Receive Time, Type, From/To Zone, Source, Destination,
  Source User, To Port, Application, Action, Rule, Decrypted, Bytes Received/Sent.
- Denied and dropped traffic is shown and tinted; All / Allowed / Denied-dropped switch.
- Click a header to sort; drag headers to reorder; ▦ chooses columns from every field Palo Alto sends
  (33+ fields; new fields appear automatically). Layout is remembered.
- Filter bar: text and field filters (`action=deny port=443 app:ssl -dns rule="Permit all"`); click any value to
  filter on it; ⊕ builds a filter; → applies; ✕ clears; ⇩ exports CSV; ⤢ full screen; 🔍 opens every field of a log.
- Live: adds new logs every 20 s by asking only for the newest minutes. Strata indexes logs 1–2 minutes after
  the firewall writes them, so live is about 1–2 minutes behind.
