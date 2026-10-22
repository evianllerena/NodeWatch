# NodeWatch v0.10.37 — whole-organization views

Topology › Organization now has the same three views as a site, built from roles, overlay kinds and cloud services — never from a product name — so any vendor's connector feeds them.

## Layers (new default)
- **Cloud and internet services**: cloud security services (with gateways and the sites attached), suggested cloud on-ramps (one WAN edge, no LAN devices — confirm with one click), and internet circuits up across all sites.
- **WAN overlays**: one bar per site-to-site tunnel network (SD-WAN, VPN, MPLS …) with its detected shape (full mesh, hub and spoke, partial mesh), pairs, tunnels and pairs not fully up, plus one bar per cloud service the sites tunnel to. The system that reports each one is shown as "from: …".
- **Sites grouped by type** (detected: hubs and data centers, large, branches, small, standalone, staging, empty — you can override any site's type). Each tile reads like the site's own Layers view: W circuits · E WAN edges · F firewalls · S switches · A access points, with the layer that has a problem in red.
- Needs attention alongside.

## Overview
- One plain sentence about the whole network, five headline numbers, a ranked Needs attention list with actions, every site worst first (with its layers), sites by health, and **Coverage by layer**: for each layer (circuits, WAN edges, overlay, firewalls, cloud security, switching, Wi-Fi) how many sites have it and which connected system reports it.

## Wiring — one site and everything it connects to
- Pick a site (or click one anywhere): outside the site (internet underlay, cloud services, overlays), the site itself, and its connections — hubs first, then pairs that need a look, then pairs that were never built in a mesh, then the healthy rest folded into one line. Click any peer to focus on it; a trail and Back take you back.
- Reads the same with 10 sites or 1,000, for a mesh, hub-and-spoke or mixed network.

## Other
- The side panel stays closed on the organization views (Panel opens it).
