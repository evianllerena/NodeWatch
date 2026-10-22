# NodeWatch v0.10.32 — Back and forward everywhere, clearer Topology, Settings in sections, Security Operations you can click into

Build: `2026-10-17-v0.10.32-navigation-paths`. Built on v0.10.30 (v0.10.31 was withdrawn). Delivered as
**`NodeWatch.exe`** (Windows) and **`NodeWatch.zip`** (Mac). Both carry the identical application tree.

## Back and forward, across the whole app
- Every page change is a browser history entry: **Back** (mouse back button, Alt+←, ⌘[) returns to where you were,
  **Forward** goes again.
- Pages add their own steps:
  - Port Toolkit: all sites → a site → a switch / port.
  - Topology: organization ↔ site, Overview ↔ Wiring.
  - Security Operations: renditions, tabs and every detail page.
  - Settings & Support: its sections.
- Back also closes an open dialog (port details, confirmations).
- Mouse back/forward buttons work in app windows that ignore them (seen on Macs).

## Port Toolkit
- **Chassis are the same length.** Every Virtual Chassis member is as wide as the widest (the 48-port ones), so the
  stack lines up.
- **Port configuration opens where you are.** It is a panel docked to the right edge of the window instead of a
  card below the port table. Esc or × closes it. On wide screens the page makes room for it.

## Device Finder
- **Show in Topology** (Requires attention) opens the device's site in Wiring, highlights the port the condition
  names, and paints the path its traffic takes now: port → switch → core → firewall → SD-WAN edge → internet
  circuit, with any problem on the way.
- **More details** no longer contains Marvis (and no longer asks Mist for it).

## Topology
- **HA role dots:** green = primary / active unit, yellow = passive / standby (map boxes, device cards, panel, legend).
- **Full screen** next to + / − (and in the toolbar). Shift+F toggles, Esc leaves.
- **Panning no longer gets stuck.** The map can be grabbed anywhere, devices included (a drag never opens a device),
  and a drag always ends, even when the button is released outside the window.
- **Internet circuits, no duplicates:**
  - one line used by both units of an EdgeConnect HA pair is one circuit (cabled to both routers), not two;
  - the same port reported by two sources is listed once;
  - the organization's circuit counts use the same rule.
- **No duplicated cables:** an LLDP neighbour reported by two sources for the same box (cloud controller + SNMP …)
  is one cable, not "2 links"; the device panel lists each neighbour / port once.
- **Routing, explained and usable:**
  - turning on **Routing** says what it does (dotted blue routed links);
  - it opens the new **Routes** tab: every route of the site's firewalls, routers and SD-WAN edges;
  - search, filter by device and protocol, sort by any column.
- **Path trace paints the path:**
  - the map switches to Wiring and fades everything else;
  - the path flows in blue, each device carries its hop number;
  - the verdict says plainly *Gets through / Blocked / No route / Partly traced*;
  - every hop shows what it does and any problem on it (device down or over threshold, link errors, a deny or drop),
    gathered at the top as "N problems on this path".
- **Organization › Wiring:** the organization now has Overview / Wiring too. Wiring draws how everything is
  interconnected: cloud services, hubs and data centers, then every site grouped by the hubs it reaches, with one
  line per pair of sites with SD-WAN / VPN tunnels (colour = health, thickness = tunnel count). Hover a site to light
  up its tunnels, click to open it.
- UI fixes: the legend no longer covers the zoom buttons, the Path trace form fits the panel, lane names wrap
  instead of being cut, the Routes tab is highlighted when open.

## Settings & Support
- **Four sections** instead of one long page: Connections, Appearance, Team, Support & data.
- **Connections** opens first, with a three-step "get connected" guide while nothing is connected. The Mist and
  Palo Alto cards sit under it with plain descriptions of where each key comes from.
- On a Mac the pages say "macOS keychain", not Windows Credential Manager.
- **Preview → Stable when it works here.** A Preview connector that is connected and answering is validated on a
  live system (yours), so it shows **Stable** (remembered across restarts).
- **No cap in the count:** "3 connected" instead of "3 of 6 connected".
- **No "Available" catalog:** products not connected yet are simply listed, ready to connect.

## Security Operations
- **Everything opens a page:**
  - **Detections** (feed rows, table rows): what it is, what happened, how far it got, what to do, every field
    (ports, zones, rule, URL, file, CVEs, log ID), and links to Device Finder, Topology, the threat and everything
    from the same attacker.
  - **Top threats:** what the threat does, whether it was stopped (outcome bar), targets, sources, sites, sensors
    and its detections.
  - **Sites under pressure:** what pressure means (and how it is computed), what is hitting the site, outcome,
    top threats, most targeted systems, and a button to filter the whole page to that site.
  - **Headline numbers** open what they count (detections, stopped, got through, hosts calling out, cases, Atlas),
    with a line saying what the number means.
- **Result colours:** Blocked (and contained) red, Alert orange, Allowed green.
- **Got through and Hosts calling out were inflated:**
  - DNS-security lookups of proxy / anonymizer (e.g. iCloud Private Relay, `mask.icloud.com`), grayware,
    ad-tracking, parked and newly registered domains arrived as "callouts to an attacker". They are now policy
    hygiene (Reach 1), not compromise;
  - "Got through" now counts only detections at Reach 3+ that were **not** blocked or contained (a sinkholed
    callout did not get through).
- **Origins:** attacks with an unknown direction but an outside attacker now count; more country field names are
  read. When the map is empty the card says why: no attack from outside, or a data gap ("N outside attacker
  addresses, but the source sent no country").

## Traffic & Sessions
- **Live is on by default.** The on/off choice was kept per local port, and the port can change between starts, so
  Live was often off again (seen in the Mac app). It stays on unless you turn it off.
- Times with microseconds or a space instead of "T" are read correctly in Safari (the Mac app without
  Chrome/Edge), so live updates find the newest row.

## Event Relay: Diagnose connection
- When the firewall logs cannot say where the HEC connection stops ("Can't tell yet"), NodeWatch now makes two
  **control connections**: the internet in general and the same Splunk Cloud stack's web address.
  - Internet and the web address answer, HEC does not → **Splunk Cloud's side**: the HEC IP allow list. It names the
    exact address to add, with the ACS command.
  - Internet answers, neither Splunk address does → **most likely Splunk Cloud's allow lists**. A silent TCP drop of
    only Splunk's addresses is an address block; URL filtering would let the handshake complete.
  - Nothing answers → **your network** (proxy / VPN needed).
