# NodeWatch v0.10.16 — incidents, vendor connectors, Topology

Build: `2026-10-09-v0.10.16-connectors`. Delivered as `NodeWatch.zip` (`NodeWatch.exe` + `_internal\`).

## Requires Attention, rebuilt around incidents
- **Why the old list misbehaved:**
  - Only 1,000 rows were loaded while the counts covered all 2,219, so the numbers disagreed.
  - Mist alarms name their devices in lists, not in `mac`, so every alarm was "Unknown device" with an
    empty explanation.
  - Dismissed alarms came back, because Mist issues a new alarm id each time and events were keyed by
    timestamp.
  - "Review" only flipped a filter.
- **Incidents, not rows.** Alerts are grouped server-side into incidents, for example "25 APs and 14 switches
  disconnected at Doral — dropped within 1 minute, probably one power or uplink event". Every count comes from
  one pass and agrees everywhere. Each refresh sends about 58 KB instead of 2 MB.
- **Detail drawer.** Clicking an incident opens a drawer that answers what is wrong, where, since when, how
  bad, and what to do. It also lists likely causes, the affected devices (with Mist, Device Finder and Port
  Toolkit links), a timeline and the per-site breakdown. Esc closes it; ↑/↓ move between incidents.
- **Actions that do something:**
  - Acknowledge, either in Mist (confirmed, recorded in the audit log, and bound to exactly the alerts you
    saw) or only in NodeWatch.
  - Snooze for 1 h / 4 h / 24 h / until it changes.
  - Dismiss with a reason, and mute an alert type (optionally per site).
  - Every action updates the counts at once and offers Undo.
- **Views:** Needs attention / Acknowledged / All open / Possibly resolved / Snoozed & muted. A "Noisiest alert
  types" row has one-click Mute.
- **Possibly resolved:** an old disconnect alarm for a device that is connected now is moved out of the
  critical list. Flapping is detected.
- **Better explanations** for port flap, bad cable, STP/BPDU, VC changes, restarts, PoE, PSU/fan/temperature,
  rogue AP, BGP, tunnels, DHCP/DNS, VLAN, duplex, CPU and memory.

## Vendor connector platform
- Vendor-neutral records (`app/integrations/domain.py`) and capability contracts
  (`app/integrations/contracts.py`): inventory, interfaces, alerts, acknowledge, events, LLDP neighbors, MAC
  tables, ARP, routes, tunnels and traffic logs.
- **Connectors** are packages under `app/integrations/connectors/`. Each has a manifest (vendor, product,
  capabilities, settings fields) and only the capabilities it really implements. They are discovered at
  start-up; one broken connector is shown as "Failed to load" and never stops the others.
- Included connectors:
  - **Juniper Mist:** inventory, interfaces, alerts, acknowledge, events, LLDP neighbors.
  - **Palo Alto Strata Cloud Manager:** traffic logs.
  - **Preview — HPE Aruba EdgeConnect (Silver Peak) Orchestrator:** inventory, interfaces, alerts, tunnels.
  - **Preview — FortiGate:** inventory incl. HA, interfaces, LLDP, ARP, routes, IPsec tunnels.
  - Preview connectors are built from the vendors' public API documentation and have not yet been tested
    against a live system.
- **Settings › Connections:** a card per connector with its state, capabilities and a form generated from its
  manifest. Secrets go to Windows Credential Manager. A saved secret is never sent to a changed address.
- **Contract tests** run against every connector: record types, stable keys, normalized MACs, allowed values,
  no secrets in output, and read-only behaviour.
- `docs/CONNECTORS.md` covers the architecture and how to add a vendor in 6 steps; there is also a `_template`
  connector to copy.

## Topology (phase 1)
- **New Topology tool**, under Investigate. It draws a tiered map: Internet/WAN → SD-WAN edges →
  firewalls/routers → core → access → APs. The map is built only from connector capabilities, so other
  vendors draw on the same map.
- **One node per device.** The same box seen by several vendors becomes one node; MAC and serial always
  merge, while IP and hostname merge only within a site, and placeholder ids are ignored. LLDP neighbors that
  no connector knows appear as dashed "LLDP only" nodes, with role and model guessed from what they advertise.
- **Links:**
  - A cable seen from both ends has 100% confidence; from one end, 70%; inferred, 40%.
  - Parallel cables become one LAG link.
  - L3 links come from shared subnets and next hops; SD-WAN and IPsec overlays come from tunnels.
- **Using the map:** layer toggles, find, pan and zoom, AP groups that expand on click, and details for any
  node or link (both ends, interfaces, evidence and confidence).
- A **Data gaps** panel says what is missing and which connection would fill it.
