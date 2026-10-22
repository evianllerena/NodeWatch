# NodeWatch v0.10.26 — Automatic discovery fixed at the root

Build: `2026-10-16-v0.10.26-auto-discovery`. Delivered as **`NodeWatch.exe`** (Windows) and **`NodeWatch.zip`**
(Mac). Both carry the identical application tree.

## Why the switch at EH_WC and the Palo Altos were not found automatically
- **Diagnostics from v0.10.25:**
  - all 39 EdgeConnects gave **zero** LAN networks and **zero** devices behind them;
  - 16 firewalls were found in the traffic logs, but **0** could be placed until you mapped them by hand.
- **Cause:** every EdgeConnect route names a "peer" (`peername`). For the appliance's own routes that peer is
  **the appliance itself** (documented in Aruba's official SDK). NodeWatch read every route with a peer as
  "learned from another site" and threw all of them away. Without the sites' own networks, nothing could be
  matched to a site.

## Fixed
- **EdgeConnect routes:**
  - The appliance's own routes, statics to a LAN device and OSPF/BGP from the LAN are now read correctly.
  - Routes from other sites over the SD-WAN, and anything on WAN ports, stay out.
  - Older and newer Orchestrator route paths are tried in turn; the working one is remembered per appliance.
- **Devices behind the router:** a switch or firewall the router sends traffic to appears as a dashed
  **"Device at 10.x.x.x"** box, linked to the router's LAN port. If a connected system knows that address,
  the real device is linked instead.
- **Firewalls placed automatically**, using, in order:
  1. the networks seen behind them in their traffic logs;
  2. their NAT addresses;
  3. the EdgeConnect circuit address they sit in front of, which also draws the firewall → router link;
  4. the naming convention your devices already follow (SP**EHWC**1 ↔ PA**EHWC**1), learned from the data
     with no vendor prefixes hard-coded, and with generic words such as CORE, LAB or HUB never treated as
     site codes.
- **Sites joined by evidence:** two systems' versions of the same site (e.g. a Mist site with a different
  name) are joined when their devices share the site's LAN networks or naming code. Joins are re-checked on
  every read, are never made on home-router networks (192.168.1.x and similar) or on wide /16 networks, and
  can be undone under **Assign sites**.
- **Circuits** showing a private WAN address (e.g. 10.0.51.24 at EH_WC) say so: another router or firewall
  sits between that port and the internet.

## Ready for other vendors
- **New shared field `Interface.role`** (lan / wan / mgmt). It is filled by EdgeConnect, FortiGate, Mist,
  Panorama and SNMP.
- **Shared code recognises WAN ports** from that field, from the circuits a connector reports, or from the
  port name. So a future router or SD-WAN connector gets the same behaviour without special code.
- **A route whose "peer" is the device itself counts as local**, whichever vendor sends it.
- **Connected networks also come from a device's own interface addresses**, for vendors that never mark
  routes as local.
- **The connector contract tests now run each connector's own regression cases.** The EdgeConnect route bug
  above is one of them.

## Checked independently
An independent reviewer reproduced each risk with scripts against the real code, before and after the fixes:
- WAN or ISP gateways shown as LAN devices;
- home-router networks joining sites;
- generic words treated as site codes;
- cloud VPN link addresses (169.254.x.x) joining sites;
- joins changing when one source misses a read.

## For the next diagnostics
- One log line per organization read gives:
  - networks learned by kind (connected / behind the router / device addresses);
  - route counts per source;
  - devices found behind routers;
  - sites joined;
  - firewalls found and placed.
- Any firewall still unplaced gets one line saying why.
- The first route entry's field names are logged once, so a future format change is visible.
