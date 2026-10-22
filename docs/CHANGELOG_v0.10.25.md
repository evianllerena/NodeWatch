# NodeWatch v0.10.25 — Organization map, devices behind the SD-WAN router, Palo Alto discovery, Config Backups

Build: `2026-10-16-v0.10.25-org-map-discovery`. Delivered as **`NodeWatch.exe`** (Windows) and **`NodeWatch.zip`**
(Mac). Both carry the identical application tree.

## Topology: the whole organization on one page
- **Map view (new default for Organization):**
  - hubs and data centers on top, joined by the SD-WAN;
  - every other site below, grouped by the hubs it is linked to ("Linked to every hub", "Linked to Data
    Center West only", "Not linked to a hub over SD-WAN");
  - each group shows its hubs as pills whose dot is the health of the tunnels to that hub;
  - hovering a group highlights its hubs; clicking a site opens it.
  - **Cards** is still one click away.
- **Open a site:** the list now starts with **Entire organization**.

## Topology: what was missing
- **Devices behind the SD-WAN router** (e.g. the switch behind the EdgeConnect at EH_WC):
  - NodeWatch now reads the router's routes. A route whose next hop sits on the router's own LAN means
    another device (a core switch or firewall) carries those networks.
  - If a connected system knows that address, NodeWatch draws a link to that device.
  - Otherwise it shows **"Device at 10.x.x.x"**: a dashed box below the router, labelled *found from routes*.
    Its panel says which networks it carries. The site overview has a new step, **Devices behind the router**.
- **More LAN networks per site:** these routes are also counted as the site's networks (diagnostics showed
  only 24 networks for 39 routers). Firewalls and other devices are placed with them.
- **Sites joined by their networks:** a site seen by only one system (e.g. a Mist site whose name differs from
  the EdgeConnect site) is joined to the site whose networks hold most of its devices. You can undo any
  join under **Assign sites**.
- **Palo Alto firewalls:**
  - **Why they still did not show:** Strata Cloud Manager answers but lists **no** firewalls (they are managed
    by Panorama, not onboarded to SCM).
  - NodeWatch now finds them in their **Strata Logging traffic logs**: serial, name and last seen. It places
    them by the inside networks and NAT address seen in those logs.
  - Discovery runs in the background, at most 12 queries an hour, on its own queue (your Traffic & Sessions
    searches are never held up). If no query answers, the previous list is kept.
  - The organization page says how many firewalls were found and placed, and which are not placed yet.
  - **For ports, routes and neighbours, connect Panorama** (Settings › Connections). Panorama and log
    records of the same firewall merge by serial number.

## Config Backups
- **The false "changed" AP is gone:** Mist sends access point images as signed links that change on every
  read. Signed links, timestamps and uptime no longer count as changes in any comparison (live vs snapshot,
  snapshots, template drift, Activity Log). The link's token is never shown or saved.
- **Who changed it** shows people and API tokens with role and scope. Read-only accesses (e.g. Mist Marvis)
  are collapsed into one line. Each entry jumps to the object it changed.
- **"Changed by"** counts changes only, and people rank before automatic accounts.
- **Layout:**
  - long values wrap inside their card;
  - the two cards line up, and stack on narrow windows;
  - the stray scrollbar on the tab bar is gone;
  - the toolbar is one aligned row;
  - product names come from the connection.

## For the next diagnostics
One log line per organization read lists the networks learned by kind, the devices found behind routers, the
sites joined by networks, and the firewalls found in logs (found / placed).
