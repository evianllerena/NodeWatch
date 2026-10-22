# NodeWatch v0.10.24 — Plain-language Topology, WAN circuits, Palo Alto placement

Build: `2026-10-16-v0.10.24-topology-overview`. Delivered as **`NodeWatch.exe`** (Windows) and **`NodeWatch.zip`**
(Mac). Both carry the identical application tree.

## Topology
- **Site Overview (new default):** written so someone who is not a network engineer can follow it.
  - One sentence says how the site connects, and what is down right now.
  - A left-to-right flow shows Internet circuits → SD-WAN routers → Firewalls → Core → Distribution → Closet
    switches → Wi-Fi access points. Each step has a count, a plain status and a one-line explanation. Click a step
    to list its devices.
  - **Internet circuits:** one row per WAN port of each EdgeConnect:
    - label and carrier, router and port, public IP, DHCP/NAT, gateway;
    - contracted bandwidth, traffic right now, latency/loss/jitter, and how many SD-WAN tunnels run over it.
    - A link that is up but carries no tunnel is flagged *Up, but no traffic flowing*.
  - **Connected sites** (separate from the internet): the other locations this site reaches over SD-WAN tunnels,
    with tunnels up/total and latency. Click one to open it.
  - **Closets:** one card per wiring closet (IDF/MDF/floor), with its switches, access points, clients and what is
    down.
- **Wiring view:** the lane diagram, kept for engineers.
  - Internet circuits are now their own top lane, each cabled to its router.
  - Remote sites are no longer drawn in the diagram; they are listed under Connected sites.
- Site cards on the organization board show circuits (and how many are down).
- The Overview loads a lighter map; full device details load when you click a device.

## Palo Alto firewalls on the map
- **Why they were missing:**
  - Strata Cloud Manager files firewalls under folders ("All Firewalls", "Branches"), which are not locations.
  - With no matching LLDP name, the firewall was left unplaced.
  - Site builds also skipped Strata Cloud Manager entirely.
- **Firewalls are now placed by, in order:**
  1. your mapping;
  2. LLDP neighbours;
  3. the IP subnet of their management address (subnets learned from EdgeConnect connected/static routes and Mist
     device addresses; ambiguous subnets are ignored);
  4. their HA peer;
  5. host name, display name or SCM labels containing the site name or code (e.g. `EH590`).
- Anything still unplaced is listed under **Assign sites** and counted on the board.
- Strata Cloud Manager lists only firewalls onboarded to it. Panorama-managed firewalls need the Panorama
  connection.

## Device Finder
- **More information** no longer repeats what is at the top of the page. It shows only new facts:
  - client details and history;
  - connection quality;
  - the switch port;
  - access/NAC details;
  - the access point or switch and the path upstream.
- The "Current path" section, which duplicated the Connection card, is gone.
- Marvis shows only findings with a fix.
- Infrastructure devices list their recent changes (7 days) with who made them.

## Activity Log: who made the change
- **Each change shows the person or API token:**
  - full name and email;
  - role and scope in plain words;
  - two-step login and last login;
  - for tokens: name, creator and last use;
  - how many changes they made in the last 24 h and 7 days.
- Admins and API tokens are read from Mist (cached 10 min). Token secrets are never read or shown.

## Speed and reliability
- **DNS:** the last good addresses are saved, so the first calls after a launch survive the PC's DNS timeouts. Mist
  reads also retry once after a failed lookup.
- **Start-up:**
  - Start-up no longer runs a separate connection test.
  - The org and recent events load in the background while the window opens.
  - Background monitors start a little later, so the first page gets the connection first.
- **Settings:** saving Mist settings without changing them keeps the warm cache.
- **Topology:** site lists, organization and site maps answer from the saved copy immediately after a restart.
- **Auto-close:**
  - NodeWatch now waits about a minute (was 15 s) after its window closes before stopping.
  - A new setting, **Keep NodeWatch running when its window is closed**, is in Settings › Support.
  - The stopped message says how to reopen it.

## Alerts and start-up without Mist
- **No repeat alerts:**
  - If a source (EdgeConnect, Palo Alto, FortiGate…) misses one read, its open alerts stay open. They are no
    longer sent again as new webhooks or browser notifications on the next good read.
  - The first time NodeWatch sees a source, it records that source's open alerts without sending them, so
    upgrading does not send a burst of old alerts.
- **Devices with an unknown role** follow the "Gateway, WAN edge & other infrastructure" alert toggle.
- **Without Mist:**
  - NodeWatch opens on Topology, not the sample dashboard.
  - Command Center shows what is connected instead of example numbers.
  - The header turns amber and names any source that is failing.
- **Activity Log:**
  - The Action column again shows the exact action (Upgrade, Reboot, Bounce, Enable…).
  - Device names are filled in.
  - "Changes by them" counts only what the selected range covers.
  - An API token without audit-log access shows one note instead of marking Mist as failing.
- **Device Finder:** opening a device reads only its own changes. That takes under half a second, was about 4 s.
- **Topology:**
  - A failed route read no longer drops the subnets used to place firewalls.
  - Saving site assignments no longer waits on every source listing its sites.
  - The site list refreshes every few minutes.
  - EdgeConnect ports in the default segment trace correctly.
  - Circuit types match whole words, so "Alternate" is not taken for LTE.

## Ready for more vendors
- **New shared contracts:**
  - **WAN circuits** (`wan.circuits`) gives any SD-WAN or router vendor a place for its circuits. EdgeConnect
    implements it.
  - **Change history and administrators** (`audit.log`, `directory.admins`) are implemented for Mist.
  - Topology and the Activity Log read these contracts, not Mist or EdgeConnect fields.
- **New shared fields** that features used to read from vendor-private data:
  - `Site.kind`: places vs containers such as folders, groups and ADOMs.
  - `Device`:
    - identity: aliases, labels, chassis MACs;
    - placement: network tier, floor;
    - live figures: clients, session capacity, PoE.
  - `Interface` packet counts and last flap.
  - `Tunnel.layer`, jitter and circuit.
- **Connector contract tests** (`tests/test_connectors_contract.py`) now exist and run every connector against its
  recorded answers. They also guard against new vendor-specific code in shared features. They are referenced by
  docs/CONNECTORS.md and `tools/new_connector.py`, but were missing before.
- docs/VENDOR_NEUTRALITY.md records the rules and the staged plan for what is still Mist-only (Device Finder clients,
  Port Toolkit, dashboard tiles).
