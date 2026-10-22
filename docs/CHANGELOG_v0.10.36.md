# NodeWatch v0.10.36 — site Layers view and topology report

## Topology › Layers (new default site view)
- The site from the internet inwards, one band per layer: internet circuits grouped by the router they plug into (provider, type, bandwidth, live utilization bar, latency/loss), SD-WAN / WAN routers, firewalls, core and distribution switches, then every closet.
- HA pairs side by side with an HA link between them (green active, yellow passive; a unit no system reports is dashed and says so).
- The links between layers are drawn as pills: ports, speed, and for aggregated links (AE / LAG) the bundle name, members × speed and members up (e.g. "ae1 · 2 × 10 Gb/s · 2/2 up"). A bundle missing a member turns amber.
- Closets show their uplink bundle, a port strip per switch (up / errors / down), PoE and clients, and one dot per access point.
- Click any circuit, device or link for its details in the side panel; links show every member port pair.
- Overview and Wiring are still one click away; Back returns to the previous view.

## Export (topology report)
- New Export button on the Topology toolbar (and on each site). Pick who it is for — Executive, IT leadership, Engineer or Custom — which sites (whole organization, SD-WAN sites, this site, or pick), and the sections.
- One report: cover and contents, executive summary (KPIs, health, decisions with an owner column), organization map (WAN shape detected automatically: hub-and-spoke, full mesh, partial mesh or standalone), resilience and risk register (ranked, from the maps), per-site pages (layers diagram in landscape + HA, circuits, links, closets, optional routing tables), circuits register, device inventory, fabric links and data gaps.
- Preview on screen, then Save as PDF from the print window. Optional masking of public IPs, MACs and serial numbers. The same data downloads as CSV + JSON (sites, devices, circuits, links, fabric links, risks).
