# NodeWatch v0.10.27 — HA pairs, firewall ↔ SD-WAN wiring, cloud services, new logo

Build: `2026-10-16-v0.10.27-ha-plumbing-brand`. Delivered as **`NodeWatch.exe`** (Windows) and **`NodeWatch.zip`**
(Mac). Both carry the identical application tree.

## EdgeConnect routes, second half of the fix
- **v0.10.26 diagnostics:** the route reader still got **zero** routes from the 37 reachable EdgeConnects.
- **Cause:** your Orchestrator answers in a per-VRF layout (documented in Aruba's SDK). In that layout:
  - routes sit directly under each VRF;
  - each route names its peer by number, and the appliance's own routes carry its own system ID.
- **Fix:** NodeWatch now reads that layout too.
  - The sites' own networks are learned again.
  - So are the devices behind each router (e.g. the switch behind SPEHWC1).
  - The evidence that places firewalls comes back with them.
  - A permanent automatic test guards this layout.

## Firewalls in HA
- **Both units are shown:** each firewall of an HA pair (PA1 and PA2) is its own box, side by side, joined by
  a dotted **HA pair** line. Each box is tagged ACTIVE or PASSIVE.
- **Passive units are found:** a passive firewall passes no traffic, so it writes no traffic logs. NodeWatch now
  also reads the firewalls' **system logs**, which passive units do write. These also give the
  active/passive state.
- **A unit seen in no log at all** is shown dashed as "probably here", with the reason, only when most
  other sites clearly have two units.
- EdgeConnect HA pairs are also shown as two boxes.

## How the Palo Altos connect to the Silver Peaks
- **The link is learned from the firewall's traffic logs.** When a firewall logs an EdgeConnect's address on one
  of its ports, NodeWatch draws that link with the port names at both ends. Hovering the line shows the
  evidence, for example: *"Seen in PAEHWC1's traffic logs: 10.0.51.24 (SPEHWC1 wan0) enters on ethernet1/1
  (zone trust-sdwan)"*.
- The firewall is drawn in front of the router when it carries the router's internet side, and behind it
  when it sits on the router's LAN.
- The firewall's panel lists its ports and zones seen in the logs.

## "GP cloud service", LMC-DC1, LMC-DC2: what they are
- **GP cloud service:** Prisma Access, Palo Alto's cloud firewall, where remote GlobalProtect users connect.
- **LMC-DC1 / LMC-DC2:** most likely Prisma Access connections to your data centers (or remote-network
  links). NodeWatch decides from fields in the log rows, not from the names; if those fields don't mark
  them as cloud links, they stay in the firewall list.
- **Where they appear now:**
  - in **Cloud services**: a tier at the top of the organization map, and a lane on the maps of the
    sites they reach;
  - no longer under "Devices without a site".
- **Assign sites:** any device still without a site has a plain sentence saying what it is and why it could not
  be placed.

## Topology diagram
- **Long names fit their box:**
  - the start most devices share (e.g. `MIST_SW_EX4400_`) is left out, and the diagram says so;
  - names still too long are shortened in the middle, so the end that tells them apart stays visible;
  - the stack count no longer overlaps the name.
- A malformed attribute on every link of the diagram is fixed.
- Devices found from routes show their address as the name.

## New logo
- **The boot artwork is now the logo everywhere:**
  - the sidebar;
  - the window's title bar and taskbar (the page icon);
  - the Windows program icon;
  - the Mac app icon.
- The old "A" mark is removed.

## Ready for other vendors
- **New shared fields:**
  - role `cloud_gateway`, for any cloud security edge (Prisma Access, Zscaler, Cloudflare, Netskope);
  - `Device.cloud_kind`;
  - site kind `cloud`;
  - link layer `ha`.
- HA pairs, cloud services and log-based wiring are built from these shared fields, so the next vendor only
  fills them in its connector.
