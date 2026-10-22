# Topology

> **v0.10.23: redesigned.** The force-directed org graph and the three per-level layouts (Layered, Free flow,
> Closets) were replaced by:
> - an **organization board** of site cards, worst first;
> - one deterministic **site lane diagram**: WAN and remote sites → edge and firewalls → core → distribution →
>   access switches → servers and other devices, with APs folded per switch and orthogonal bus links;
> - a **side panel** with Device, Issues and Path trace tabs;
> - **org-wide search** (`GET /api/v1/topology/search`);
> - **site matching** across vendors (`GET`/`PUT /api/v1/topology/site-map`, `app/services/topology_sites.py`).
>
> The data model and APIs below are unchanged and only extended. Sections 2–4 describe the v0.10.18 renderer and are
> kept for history. See docs/CHANGELOG_v0.10.23.md.

## History: how the market leaders draw networks, and what NodeWatch adopted (v0.10.18)

NodeWatch's Topology tool (v0.10.16 phase 1, v0.10.17 live health + path trace) drew one site as a
tiered diagram. For v0.10.18 we studied four products the user named — Auvik, Dynatrace, Scanopy and
ExtraHop — and adopted the patterns that help a network engineer most. This page records what we
found, what we built, what we skipped and why, and what comes next.

## 1. Findings

### Auvik (network maps)
- **Levels.** A global "all locations" map gives a 10,000-ft view of distributed sites; you drill into
  each site, then into layers, devices and links. ([Auvik network mapping][auvik-nav])
- **Layers 1–3 on one map**, wires colour- and style-coded: Layer 1 solid blue, inferred connections
  black, VPN tunnels purple, Wi-Fi dotted. ([Auvik support: Your network map][auvik-map])
- **Grouping.** Stacked or clustered devices are aggregated; collapsed nodes carry a badge with the
  number of hidden devices; click expands; expand-all / collapse-all buttons. ([Auvik support][auvik-map], [mapping page][auvik-mapping])
- **Lightweight drill-down on hover.** Hover a device for type, name, IP and status; hover a wire for
  connection type, negotiated speed and the interfaces on each end; hover a collapsed node to list its
  members. ([Auvik support][auvik-map]) "Hover for interface status, utilization, and error details";
  "colour-coded connections show link health at a glance." ([Auvik network mapping][auvik-nav])
- **Status overlays.** A real-time alert overlay marks affected devices on the map. ([Auvik network mapping][auvik-nav])
- **Search and filter** by device type, connection type, network segment, role, site, VLAN or logical
  group; **custom views** per team; hide "noise" when presenting. ([Auvik network mapping][auvik-nav], [mapping page][auvik-mapping])
- **Path to the internet** ("Northstar"): a mini map of a device's path with per-hop inspection. ([mapping page][auvik-mapping])
- **Export** any view as VSDX, SVG or PDF; **history**: "rewind the map to the offending moment." ([mapping page][auvik-mapping])
- **Geo/site map**: nearby sites cluster into bubbles coloured by worst alert severity; zoom splits them. ([Auvik support][auvik-map])

### Dynatrace (Smartscape)
- **Vertical stack + horizontal dependencies**: tiers (applications → services → processes → hosts →
  data centres) on one axis, calls within a tier on the other. Each tier tab shows a health count such
  as "1/33". ([Smartscape classic][dt-classic])
- **Selecting an entity** shows its vertical dependencies; a "Show problems" view colours affected
  entities red. Large tiers are summarised (most important processes only; counts on tabs). ([Smartscape classic][dt-classic])
- **Focused topology views** keep a *trigger node* centred and always visible (filters never hide it);
  modes show neighbours, call chains "at any depth", grouped by entity type; layouts Force / Vertical /
  Horizontal; filter by nodes, edges and problems. ([View topology][dt-view])

### Scanopy (verified: an AGPL-3.0 / commercial dual-licensed self-hosted discovery and diagram tool)
- Discovers hosts and services with daemons per segment (SNMP, LLDP, ARP, Docker) and generates
  **four views from one scan**: L2 physical ("every switch, every port, every link"), L3 logical
  (subnets), workloads, applications. ([GitHub][scanopy-gh], [scanopy.net][scanopy-site])
- Clicking a host "highlights everything connected to it and opens an info panel"; hosts can be grouped
  in **hub-and-spoke** layouts; edges can be styled (step / straight / bezier); ports can be toggled;
  topologies can be **saved, versioned and locked** against incoming scans. ([noted.lol review][scanopy-review])
- Export as SVG, Mermaid, Confluence; live embeds. ([GitHub][scanopy-gh]) Reviewers praise that
  "connections are readable and layouts are not messy". ([VirtualizationHowto][scanopy-vhowto])

### ExtraHop (Reveal(x) activity maps)
- Device-to-device **communication over time**: circles for devices, lines for connections; 2D by
  default, rotating 3D on demand; **labels on hover** (not all shown by default). ([ExtraHop docs 9.6][eh-maps])
- **Size encodes a metric** (bytes, connections, TCP turns); **steps** build the map hop by hop with a
  protocol and a device-group filter per step. ([ExtraHop docs][eh-maps])
- **Hold focus** on a device and its peers; **time comparison** colours new (green), gone (red) and
  unchanged (blue) activity; live refresh every minute or frozen custom intervals. ([ExtraHop docs][eh-maps])
- Saved maps are private until shared; export PDF / PNG / SVG. ([ExtraHop docs][eh-maps])

### What makes these maps good for a network engineer
1. **Levels with progressive disclosure** (org → site → device), never everything at once.
2. **Grouping with counts** and one-click expand; summaries instead of 300 boxes.
3. **Facts on hover**: both port names, speed, utilization, errors — without leaving the map.
4. **Status overlay on the map itself** plus a "show only problems" filter.
5. **Focus**: a trigger node stays visible, its neighbourhood (N hops) highlighted, the rest dimmed.
6. **Change awareness**: what is new, what disappeared (Auvik history, ExtraHop time comparison,
   Scanopy versioning).
7. **Saved views and export** for the team and for change tickets.

## 2. What NodeWatch adopts now (implemented in v0.10.18)

| Pattern | Source of the idea | NodeWatch implementation |
|---|---|---|
| Multi-level maps | Auvik global → site → device | **Organization** map (every site a tile, hubs on top), **site** map (tiered), **device** view (one box with every port as a pin, each neighbour and the remote port). Breadcrumbs; double-click / Enter opens, Backspace goes up. |
| Tunnels between sites with health | Auvik site map, Smartscape tier health | `/api/v1/topology/org`: one organization-wide inventory and tunnel call per source (cached 60 s, never per site). Tunnels resolved to site pairs (peer key → tunnel local IP → host name), graded with the live-health loss / latency / jitter thresholds. Branch tunnels run along each hub's **trunk** (edge bundling); the coloured stub above a tile is that site's tunnel health. |
| Layers L1/L2, L3, overlay | Auvik layers, Scanopy L2/L3 views | Layer toggles kept (renamed "L1 / L2"), legend per level; LAG drawn as a double line. |
| Clean layout | Scanopy "not messy", Smartscape vertical stack | Tiered layout with barycentre crossing reduction (repeated up/down sweeps, leaves never pull infrastructure rows), **orthogonal edge routing** with rounded corners, one attach point per link spread along the box edge (sorted by where the far end is), a bus per parent, **lanes through gaps** for links that skip a tier, **comb stacks** for APs under their switch, wrapped rows stay centred. |
| Labels never overlap | — | Spatial-grid collision avoidance for link labels, health badges and port names; text auto-fits boxes using measured widths. |
| Grouping | Auvik collapsed nodes | APs/endpoints per switch, access switches per parent (> 48), remote tunnel peers; badge counts and health roll-up; "Groups" expands all. |
| Hover facts | Auvik hover, ExtraHop labels on hover | Tooltip for devices (role, model, IP, status, health reasons) and links (both ends' ports, speed, utilization, errors, flaps, evidence). |
| Semantic zoom | ExtraHop labels on hover | Far: one large name per box; mid: name + model; near (≥ 125 %): port names on every cable and link speeds. |
| Minimap + fit | common | Click/drag minimap (hidden automatically when the whole map fits), Fit, zoom buttons, side panel can be hidden for a wider map. |
| Search-to-focus + N-hop neighbourhood | Smartscape trigger node, ExtraHop hold focus | Search with suggestions (name, IP, MAC); selection highlights 1 / 2 / 3 hops. |
| Filters, "only problems" | Auvik filters, Smartscape show problems | Role, vendor, status, only problems, only changes; dim or hide others. |
| Saved views, export | Auvik custom views/export, ExtraHop saved maps | Views saved on this computer (level, site/device, layers, filters, groups, zoom) with JSON export/import; map export as SVG (theme colours resolved, opens in Visio / draw.io), PNG, and graph JSON. |
| Change awareness | Auvik history, ExtraHop comparison, Scanopy versions | Per-site baseline under the data folder; new devices/links marked NEW, missing ones drawn as ghosts; "Accept" makes the current map the baseline. |
| Path trace & health everywhere | Auvik Northstar | Trace overlay on all three levels (sites + tunnel bundles on the org map, ports on the device view); live health on all levels. |
| Keyboard | — | `/` find, arrows move between devices, Enter open, Backspace up, F fit, G groups, M minimap, P panel, Esc clear. |

Measured on a 1,001-device site in headless Chromium at 1440 px: full render with every group expanded
≈ 190–280 ms (12,100 SVG elements), grouped view (81 boxes) ≈ 25–35 ms, wheel zoom ≈ 4 ms per step
(stage geometry cached, view updates coalesced per animation frame), selection with neighbourhood ≈ 60 ms.
SVG stays fast enough; a canvas fallback is not needed at this size.

## Closets layout (v0.10.21, the default site layout)

The site map's third layout (Layout › Closets, next to Layered and Free flow). Layer bands on top —
Internet (WAN cloud, tunnel peers), SD-WAN (edges), Security (firewalls; an HA pair is joined by a
dotted "HA" line when live health reports an HA state), Core (core / distribution switches plus
servers, aggregation switches and anything else not behind a closet) — each with a label column
(name, count, health dot). Below them one glass column card per wiring closet: header (closet token
from the switch name such as "IDF2", else the switch name), switch and model, uplink chip (local
port or LAG · members × speed) with a load bar from live health, access points (with "N down" or
"N APs lost" when the switch is down), clients (wired + Wi-Fi) and a port faceplate (4 × 12 for 48
ports, sized to the real count) with "up / total · PoE W".

* **Cables** are vertical beziers coloured by per-member speed: 1G grey, 10G cyan, 40G violet, 100G
  green; busy (≥ 80 % utilized, live health) amber; down red dashed; WAN / tunnels orange dashed. Port
  chips ("lan0 ⇄ ethernet1/1") sit on band cables when both ends are named; on closet cables and links
  inside a band they show on hover, on the selected slice and when zoomed in.
* **Toolbar:** Columns — wiring closets (switches sharing a closet token, plus cascaded switches),
  floors (Mist floor plan id, or a floor in the switch name; disabled when neither exists), switch
  stacks (one card per switch / virtual chassis). Sort — name, worst first, busiest uplink.
* **Selection** lights the upstream path ("slice") with a violet glow and dims everything else to
  40 %; problems (down, degraded, AP down, busy, health warning / critical) stay at full strength.
  Click shows the usual details, double-click opens the device view. Searching for an access point
  selects it and lights its closet.
* **Data** (site payload, per node; `None` / `""` when no source reports it): `ports_total`,
  `ports_up`, `ports_warn`, `port_map` (one character per physical port: `u` up, `w` up with errors
  ≥ 0.1 % of packets, `d` down / empty), `poe_draw_w`, `clients` (wired for switches, Wi-Fi for APs),
  `floor_id`. Mist answers them from the device and port statistics it already reads for LLDP (the
  client caches each read for its TTL), so the map costs no extra API call; org-wide reads (no site)
  see only live ports and leave port counts out. Uplink utilization comes from live health.
* **Space:** the map card runs to the bottom of the window whatever the toolbar wraps to (no page
  scroll). In Closets the minimap starts off and the side panel starts folded away; selecting something
  opens the panel (a drawer over the map below 1,100 px) and clearing the selection folds it again. M /
  P (or the buttons) choose for good; both are remembered separately from the other layouts. Below
  1,200 px the toolbar hides its field labels (still read by screen readers).
* **Missing data is hidden, never invented:** a card row no closet has data for disappears (clients,
  ports, uplink, wireless); a single card without it says "no client data" / "no port data"; the load
  bar appears only once live health reports the uplink.
* **Works with** search, filters ("only problems" keeps a card whose APs or uplink are down), path
  trace (a hop inside a closet marks its card), live health, Fit / zoom, minimap, saved views and
  SVG / PNG export. Many closets keep one row and scroll sideways (drag, Shift + wheel or a sideways
  swipe) rather than shrinking below a readable size. Not applicable here: dragging / pinning boxes
  (Free flow only), the 1–3-hop neighbourhood buttons (the slice replaces them) and the Groups button
  for access points behind a closet (the card summarises them). A site without access switches falls
  back to the layered map. 60 closets × 48 ports render in about 40–60 ms in headless Chromium.

## 3. What we skip (for now) and why

- **Geo map of sites** (Auvik). Needs coordinates and map tiles; tiles would mean an external CDN,
  which the CSP forbids and an offline desktop app should not need. Site addresses exist in some
  connectors; a tile-free projected scatter is a later option.
- **3D view** (ExtraHop). Looks impressive, rarely helps troubleshooting; costs a WebGL stack.
- **Flow-based activity maps** (ExtraHop). NodeWatch has no packet / flow source; the map stays
  topology + health. A flow capability can feed link weights later without changing the map.
- **Full time travel / rewind** (Auvik). We keep one baseline per site instead of a history store;
  enough to answer "what changed since it worked" without growing the data folder.
- **Manual node placement / locked layouts** (Scanopy). Auto layout plus saved zoom/filters covers the
  daily need; manual positions are fragile when devices come and go.
- **Visio (.vsdx) export**. SVG imports into Visio and draw.io; native VSDX needs a writer library.

## 4. Next phases

1. **History**: keep a small ring of snapshots per site (daily) and let the change panel pick the
   comparison point; show the date a device first / last appeared.
2. **VLAN and subnet lenses** (Auvik VLAN filter, Scanopy L3 view): highlight every port carrying a
   VLAN; an L3 view grouped by subnet once INTERFACES data is cached per site.
3. **Site geography**: projected org map when sites carry coordinates; cluster bubbles by region.
4. **Utilisation over time** on links (sparkline on hover) from the live-health samples.
5. **Edge bundling for mesh overlays** (branch ↔ branch) when full-mesh SD-WAN is common.

[auvik-nav]: https://www.auvik.com/network-management-software/network-navigation
[auvik-mapping]: https://auvik.com/network-management-software/network-mapping-software
[auvik-map]: https://support.auvik.com/hc/en-us/articles/204908674-Your-network-map
[dt-classic]: https://docs.dynatrace.com/managed/analyze-explore-automate/smartscape-classic
[dt-view]: https://docs.dynatrace.com/docs/analyze-explore-automate/smartscape/smartscape-in-context-views/smartscape-view-topology
[scanopy-gh]: https://github.com/scanopy/scanopy
[scanopy-site]: https://scanopy.net
[scanopy-review]: https://noted.lol/scanopy/
[scanopy-vhowto]: https://www.virtualizationhowto.com/2025/12/stop-drawing-network-diagrams-manually-scanopy-does-it-for-you/
[eh-maps]: https://docs.extrahop.com/9.6/activity-maps
