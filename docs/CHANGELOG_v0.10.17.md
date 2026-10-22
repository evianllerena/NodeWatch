# NodeWatch v0.10.17 — Panorama, SCM, Silver Peak, SNMPv3, path trace, live health

Build: `2026-10-09-v0.10.17-trace-health`. Delivered as `NodeWatch.zip` (`NodeWatch.exe` + `_internal\`).

## Palo Alto
- **Panorama connector (new, Preview)**
  - Uses the PAN-OS XML API through Panorama with an API key, sent in a header only. It queries each firewall by serial.
  - Reads: firewall inventory with HA, interfaces, zones and VRF, ARP, routes (legacy and Advanced Routing), LLDP and IPsec tunnels.
  - Alerts: firewall disconnected, device-group out of sync, and HA problems.
  - Health: CPU, memory, sessions and HA state. Policy lookup uses `test security-policy-match`.
  - **Read-only by construction.** Every request passes a guard that allows only show/test operations and config reads. A `writer.py` stub documents the future change-module flow (lock → snapshot → candidate edit → validate → diff → commit → push → audit → rollback); it is not implemented.
- **Strata Cloud Manager connector:** now also lists firewalls and Prisma Access remote networks (`/config/setup/v1/devices`, `/config/deployment/v1/remote-networks`). It has the same design-only writer stub.

## Silver Peak / EdgeConnect Orchestrator
- **Checked against the 9.4.11 API spec** from your Orchestrator. Still Preview: it has not been run against your live Orchestrator.
- **Fixed:** the alarm list returned at most 5 alarms, because the API's default for `maxAlarms` is 5.
- **New data:**
  - HA pairs and regions
  - overlay (bonded) tunnels with tunnel IPs
  - LAN/WAN interface labels
  - routes per segment
  - health: memory, sessions, tunnel latency, loss and jitter, and interface rates and packet counts
- Every read-only POST must be on a fixed allow-list.

## SNMPv3 (new, Preview)
- **For devices without a usable API.** Read-only and v3 only, with authPriv required (SHA-2 and AES).
- **What it reads** from standard MIBs: inventory, interfaces, LLDP and CDP neighbours, ARP, MAC tables, routes, and CPU and memory.
- **Polling limits:** at most 8 hosts at a time, with deadlines per host and per poll, and up to 256 configured hosts. Broadcast, multicast and other reserved addresses are refused.
- **New dependencies:** pysnmp 7.1.29, pyasn1 0.6.4 and cryptography 50.0.1. They are installed into the private runtime on first start.

## Topology
- **Live health layer.**
  - Colours nodes and links and makes busy links thicker.
  - Tracks CPU, memory, sessions, PoE budget, HA state, port errors, flaps and utilization, LAG members, and tunnel latency, loss and jitter.
  - The "Worst right now" list refreshes quietly every 30 s. Thresholds are adjustable.
- **Path trace.** Enter a source and destination (IP, MAC or name). The trace:
  - locates each endpoint, then walks layer 2 up to its gateway;
  - picks the longest-prefix route in the right VRF;
  - checks firewall policy for allow or deny, with the rule name;
  - follows the best SD-WAN tunnel to the far side, then down to the destination port.

  The hops are highlighted on the map. The trace never invents a hop: when data is missing it says where it stopped and which connection would fill the gap.
- **Sites match across vendors by name.** A Mist site also shows the Panorama firewalls and Silver Peak edges for that site. Panorama's device-group → site-name map makes the names line up.

## Review fixes
- **Path trace:**
  - the VRF is matched for firewalls with a named virtual router;
  - the DNS timeout is enforced;
  - interface tables are reused and fetched in parallel at scale;
  - tunnel selection is indexed instead of scanning every tunnel.
- **Health:** no internal scope data in responses, no duplicate port issues, and its per-site locks are capped.
- **SNMP:** polls that outlive their deadline are tracked and never stacked; a malformed row is skipped instead of failing the host.
- **Silver Peak:** guards against malformed responses.
