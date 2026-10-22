# NodeWatch v0.10.23 — Speed, connection reliability and a new Topology

Build: `2026-10-16-v0.10.23-performance-topology`. Delivered as **`NodeWatch.exe`** (Windows) and **`NodeWatch.zip`**
(Mac: `NodeWatch.app`). Both carry the identical application tree (`app/`, `branding/`, `docs/`); only the bundled
Python runtime differs per platform.

## Why this release
Field diagnostics from v0.10.22 (support bundle 2026-10-16) showed:
- **Start-up:** 13–14 s of a ~17 s cold start went to checking ~1,750 files one at a time.
- **DNS failures:** about 5 % of name lookups on the PC timed out after ~12 s (`[Errno 11001] getaddrinfo failed`), for
  Mist, Palo Alto and the Orchestrator alike. Every API call opened a new connection, so every call paid for a fresh
  lookup. 16 % of Mist calls stalled ~12 s, which was 65 % of all Mist wait time.
- **Connections looking broken:** one failed call turned a connection card red until it was edited and saved again.
- **EdgeConnect tunnels:** every refresh downloaded the org-wide tunnel list (~20 MB), threw it away as too large,
  then read it again one appliance at a time (81 calls/hour). Tunnel statistics always hit the 20 s timeout.
- **Topology:** slow (vendor reads one after another, rebuilt every minute) and devices from different vendors never
  matched to the same site, so EdgeConnect edges and firewalls showed up twice or not at all.

## Faster everywhere
- The launcher checks its files in parallel (same check, every file).
- **Connections stay open:** Mist and every connector now reuse open connections and ask for compressed answers.
- **DNS cache:** NodeWatch keeps the last good address for each cloud API, so a lookup that times out falls back to
  it instead of failing the call.
- **Pages load only when opened:** Topology, Config Backups, Event Relay, Operations Assistant and Change Verifier
  load the first time you open them. Page files are kept between launches of the same version.
- **Background work stops wasting calls:**
  - The Splunk/syslog forwarder checks the destination is reachable before reading anything, and backs off while it
    is not.
  - The alert monitor no longer forces extra event reads.
  - Connection status checks no longer wipe the Mist cache.
  - Device Finder and alert polling pause when you are not looking at them.
- **Vendors are asked at the same time,** not one after another.
- **The Mist event history loads the last hour first;** the rest of the day fills in in the background.
- **Settings and history files:** diagnostics are written in the background, and `connectors.json` is read only when
  it changed.

## Connections (Settings › Connections)
- **No false failures:**
  - A single failed call between successful ones shows **Connected · last call failed** instead of **Error**.
  - A card that is in error re-checks itself in the background when you open the page.
  - Re-test now allows for a slow network: 40 s in total and 15 s per request, up from 20 s and 8 s.
- **Editing keeps On/Off:** saving an edited connection no longer switches it on by itself.
- **EdgeConnect Orchestrator:**
  - It remembers that the org-wide tunnel list is too large and reads per appliance straight away.
  - One tunnel list is shared by every map and health view.
  - One appliance that cannot be read no longer hides every tunnel.
  - Tunnel statistics are read in smaller batches with a longer time limit, and back off for 10 min after a timeout.
  - When the Orchestrator is briefly unreachable, the last good answer (up to 15 min old) is shown.
- **Strata Cloud Manager:**
  - The firewall inventory added in v0.10.17 switched itself on with the Traffic & Sessions account and had no off
    switch. It now has one on its card, **Firewall inventory on/off**. It stays on for existing installs, as since
    v0.10.17.
  - Re-test signs in and reads one firewall record, instead of running a 7–45 s log query that could not finish in
    time.
  - A rejected sign-in token is fetched again once instead of failing for up to 15 min.
- **Palo Alto shared account:**
  - Resetting Device Security no longer deletes the service account while Traffic & Sessions still uses it.
  - Saving Device Security also refreshes the SCM inventory.
- **Traffic & Sessions:**
  - The log query timeout you save is kept. v0.10.7 silently turned a saved 45 s into 90 s on every read.
  - The "single OR query" check is remembered across restarts and stops after two HTTP 500 answers. It returned 500
    on every try for this tenant and slowed lookups after each start.
- **Saved settings are protected:** a `connectors.json` that is briefly locked (antivirus) is retried and never
  overwritten with only one connection.

## Topology, redesigned
- **Organization:**
  - A board of site cards, worst first, instead of the force-directed graph.
  - Each card shows a status rail, devices by role, tunnels, and what is down.
  - Filter (all / need attention / healthy), sort, and separate hubs and data centers.
- **Site:**
  - One fixed lane diagram from top to bottom: WAN and remote sites → edge and firewalls → core → distribution →
    access switches → servers and other devices.
  - Access points fold into a chip under their switch (`12 APs, 1 down`); click to unfold, or press **A** for all.
  - Links run as orthogonal buses between lanes.
  - One status channel: the bar on each device and the link colour (live health when it is on).
- **Search everything:** one box (`/`) finds any device in the organization by name, IP, MAC, serial, model or HA
  member name, and opens its site with the device selected.
- **Side panel:**
  - **Device:** facts, live health reasons, HA and stack members, ports with problems, every connection, and actions:
    Port Toolkit, Device Finder, trace from here, open in the vendor console.
  - **Issues:** sources not answering, data gaps, changes since the baseline.
  - **Path trace.**
- **Site matching:** EdgeConnect, Mist, Panorama, SCM, FortiGate and SNMP sites are matched to one site by name.
  Devices without a site (for example an EdgeConnect with a blank site field) are placed by their LLDP neighbours or
  host name. **Assign sites** lists every match and every device that could not be placed, so you can correct them.
- **Fixes:**
  - Devices from different vendors are matched within the same site, so a firewall or EdgeConnect seen by a Mist
    switch is one box with its cable, not a duplicate "?" box.
  - HA pairs list both units.
- **Faster and steadier:**
  - Sources are read in parallel, and ARP is read only for the site's devices.
  - Routing (layer 3) is read only when you turn it on.
  - Live health answers from a 45 s cache that refreshes in the background.
  - The page asks whether the map changed and redraws only when it did, keeping your zoom and selection.
  - A source that fails keeps its last good devices, marked stale, instead of emptying the map.
- **Gaps:** every limit that was hit is listed under Issues.

## Release steps
Windows: `release/generate_integrity.py --update-launcher`, `release/build_launcher.py`, sign, `release/build_setup.py`,
sign the setup. Mac: `release/build_macos.py --rcodesign <path>`. See docs/RELEASE_PROCESS.md.
