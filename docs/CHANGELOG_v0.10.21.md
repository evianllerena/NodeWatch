# NodeWatch v0.10.21 — Topology: Closets layout, faster maps

Build: `2026-10-10-v0.10.21-closets`. Delivered as `NodeWatch.zip` (`NodeWatch.exe` + `_internal\`).

## Topology: Closets layout (new default for a site)
- **Layer bands on top:** Internet, SD-WAN, Security and Core. Each band has a label column showing its name, device count and health.
- **One glass column per wiring closet below the bands.** Each column shows:
  - the switch and model;
  - the uplink port, LAG members × speed and a load bar;
  - access points;
  - clients;
  - a port faceplate with ports up/total and PoE draw.
- **Cables:**
  - Coloured by speed: 1G grey, 10G cyan, 40G violet, 100G green.
  - Busy links show amber, down links red dashed, WAN links orange dashed.
  - Port names appear on the cables, e.g. "lan0 ⇄ ethernet1/1".
- **Selecting a closet or device** lights its whole upstream path in violet and dims the rest. Problems are never dimmed.
- **Columns:** by closet, floor or switch stack. **Sort:** A–Z, worst first or busiest uplink.
- **More room for the map:**
  - The map runs to the bottom of the window.
  - The minimap and side panel start hidden in this layout; selecting something opens the panel.
  - Many closets scroll sideways instead of shrinking.
- **Missing data is hidden, never invented.** No new Mist API calls: the counts come from statistics already read for the map.
- Layered and Free flow are still available in Layout and are remembered per level. See docs/TOPOLOGY.md.

## Topology: much faster
- **Instant open:**
  - The last map of every site and the organization is saved and shown immediately ("Updated 40 s ago · refreshing…").
  - A fresh map is built in the background and swapped in when ready.
  - It survives restarts.
- **Fewer, faster Mist reads:**
  - Port statistics pages are read in parallel instead of one by one.
  - Organization-wide reads ask only for live ports.
  - Switch ports, gateway ports and device statistics are read at the same time.
- **Progressive first build:** devices appear first, and cables follow when they're ready.
- **Free flow layout:** a deterministic force-directed layout that uses the whole canvas. Clusters read as clusters, and boxes you drag stay pinned.
- **Support diagnostics:** now include `integration_api_timing`, with calls, time and the slowest endpoints per connector. Only endpoint templates are recorded, never values or tokens.

## Event Relay (Splunk)
- **Firewall cross-check in "Diagnose connection":** when the connection to Splunk is silently dropped, NodeWatch checks the connected firewall traffic logs (Palo Alto) for the last hour.
  - If the firewall blocks the traffic, Diagnose names the rule.
  - If the firewall allows it, the block is beyond your firewall, most likely the Splunk Cloud HEC IP allow list.
