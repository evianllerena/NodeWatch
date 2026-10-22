# Vendor neutrality: how NodeWatch stays ready for the next vendor (v0.10.24)

Today NodeWatch reads Juniper Mist, HPE Aruba EdgeConnect (Silver Peak), Palo Alto (Strata Cloud Manager,
Panorama), FortiGate and SNMP. Tomorrow it may be Cisco Meraki, Aruba Central, Catalyst Center, Cisco SD-WAN,
Versa, Prisma SD-WAN, Extreme or Ubiquiti. The design goal: **adding a vendor means writing one connector,
never changing a feature.**

## The rule, in five steps

| Step | Where | What |
|---|---|---|
| 1. Capability | `app/integrations/contracts.py` | A stable name (`wan.circuits`) and a `Protocol` with the method signature. Add it to `ALL_CAPABILITIES`, `CAPABILITY_LABELS`, `CAPABILITY_PROTOCOLS`. Writes end in `.write`. |
| 2. Domain record | `app/integrations/domain.py` | Neutral field names; `None`/`""` when unknown; `source`, a stable `key`, and a small `vendor` dict for display only. Vocabularies (roles, states, kinds) are tuples next to the record. |
| 3. Connector adapter | `app/integrations/connectors/<vendor>/` | Translates the vendor API into records, including the vendor's own vocabulary (RBAC roles, alarm types, transport names). Every call goes through `self.call(...)`, so errors are normalised and secrets redacted. |
| 4. Consumers | `app/services`, `app/modules` | Ask `sdk.sources(CAP)` / `sdk.gather(CAP, method)`. Read **record fields**, never `record.vendor[...]`. No `getattr(connector, "list_…")`. Serialise with `.to_dict()` at the API edge. |
| 5. Pages | `app/static/modules` | Use domain fields and product names from the API (`sources[].product`, `/api/v1/connectors`). Never connector ids or vendor ids. Gate buttons and pages on `available_capabilities()`. |

If two consumers need a value from `vendor`, it becomes a domain field. If a feature needs data no capability
covers, add a capability first.

## The gate

`tests/test_connectors_contract.py` runs every connector against its recorded fixtures. Run it with
`python tests/test_connectors_contract.py` (pytest optional); `tools/new_connector.py` generates a
per-connector file. It checks:

- **Capabilities:** every claimed capability satisfies its Protocol.
- **Records:**
  - methods return only that capability's records;
  - `source` and keys are set and stable across calls;
  - enum fields stay within the vocabularies;
  - the `vendor` extras stay small.
- **References and secrets:** device references resolve, and no secret appears in records or errors.
- **Reads only:** connectors only read.
- **Connection test, guide and probe:** the connection test is cheap, the setup guide exists, and the probe is
  safe.

It also guards the repository:

- **No duck typing of connector methods in shared code.**
- **No new `record.vendor[...]` reads in shared code.** Pre-v0.10.24 reads are grandfathered in
  `tests/vendor_reads_allowlist.json`; this list only shrinks.
- **No new direct Mist client use outside the legacy allow-list.**
- **No connector ids hard-coded in new page scripts.**

## What v0.10.24 made neutral

- **WAN circuits:** `wan.circuits` → `Circuit` (label, carrier, kind, public IP, bandwidth, state, tunnels,
  quality). EdgeConnect implements it; Topology shows circuits from any connector that declares it.
- **Audit and administrators:** `audit.log` → `AuditEntry`, and `directory.admins` → `Actor` (person / API
  token / system, readable roles and scope). Mist implements both; the Activity Log shows any source's entries.
- **Promoted fields**, which shared code used to read from vendor extras:
  - `Site.kind` / `parent_key`: places vs containers such as SCM folders, Meraki organizations, Aruba Central
    groups or FortiManager ADOMs.
  - `Device`:
    - identity: `aliases`, `labels`, `alias_macs`;
    - placement: `network_tier`, `floor_key` / `floor_name`;
    - live figures: `clients`, `sessions_max`, `poe_budget_w`, `poe_used_w`.
  - `Interface.rx_pkts` / `tx_pkts` / `last_flapped`.
  - `Tunnel.layer` (overlay / underlay / passthrough), `jitter_ms`, `circuit_key`.
- **Topology:** firewalls are placed by vendor-neutral evidence (LLDP, IP subnet, HA peer, names/labels), never by a
  vendor's folder names.
- **Pages:** source names come from the connectors that answered.

## What v0.10.25 adds

- **Placement evidence on `Device`** (fill what the system knows; leave empty otherwise):
  - `addresses`: other IPs the device uses besides `mgmt_ip` — a NAT / untrust address, inside interface
    addresses. Topology places a device whose address falls in a site's LAN, and links a router's next hop
    that equals one of these addresses to the device.
  - `lan_prefixes`: networks seen *behind* the device (CIDR). Topology places the device by a majority vote
    of these networks over the site prefix index.
  Strata Cloud Manager fills both for firewalls it discovers from traffic logs (NAT source addresses and the
  /24s of inside-zone sources); any connector that knows interface addresses or protected networks can too.
- **LAN next hops (`Route`)**: a non-overlay route whose `next_hop` lies inside one of the device's own
  connected prefixes (`Route.local`) is a LAN-side layer-3 neighbour. Topology counts its prefix as the
  site's LAN and draws the neighbour (a known device that owns the address, else an inferred
  "Device at <ip>" node) — for any vendor that reports routes.

## What v0.10.26 adds

- **`Interface.role`**: which side of the device the port faces — `"lan"` (site networks), `"wan"`
  (ISP / MPLS / LTE / transport), `"mgmt"` (out-of-band management) or `""` (unknown). The contract suite
  checks the vocabulary. EdgeConnect fills it from `lan-if` / `wan-if`, FortiGate from the interface role (a
  DMZ counts as `lan`), Mist gateways from the port usage, Panorama / SNMP mark management ports.
- **What Topology never counts as a site LAN**, for any vendor:
  - networks of `wan` / `mgmt` ports, `kind == "mgmt"` ports, and the port a `Circuit.interface` names. When
    the role is unknown, a port whose name or security zone is, or starts with, a transport word (wan1,
    Internet, isp, mpls, lte, untrust, outside) counts as WAN — unless it also names an inside network
    (trust, lan, inside, guest, dmz: "Internet_Guest", "trust-uplink" stay LANs);
  - routes out of those ports, default routes, and next hops on a WAN network;
  - link-local, /31–/32, public and documentation networks. LAN space means RFC 1918, CGNAT
    (100.64.0.0/10) and IPv6 ULA only;
  - a prefix that equals or contains a `Circuit.ip` of the same site. It stays in the index as a WAN
    address, which can place a box (a firewall in front of an edge) but never joins sites;
  - consumer / ISP-modem default LANs (192.168.0.0/24, 192.168.1.0/24, 192.168.100.0/24, 10.0.0.0/24,
    10.0.1.0/24). These never place a device or join sites.
- **Connectors that report routes** should set `Route.local = False` for a WAN-interface subnet. A route
  table that also lists the WAN side (as EdgeConnect does) must not present it as the site's LAN.
- **Site joins** from subnets and naming conventions are re-evaluated on every read and are never sticky:
  - only prefixes of /22 or longer count;
  - generic name stems (CORE, IDF2, MDF, HUB, LAB …) count only when they are the site's own code;
  - a learned stem that a site's own devices carry under a naming convention (SPHQ1 at Headquarters → HQ)
    is that site's code too;
  - mapping a site to "" undoes only the join shown on that site's row (stored per pair);
  - a read in which a source failed or returned no devices never removes joins.
- **Site scoping vs LAN space**: links, tunnel peers and path-trace owners on any non-globally-routed address
  (169.254/16 BGP-over-IPsec, 198.18/15, CGNAT, documentation ranges, RFC 1918) match only within a site;
  only RFC 1918 / CGNAT / ULA count as LAN space for the prefix index and placement.

## What v0.10.27 adds

- **`Device.role = "cloud_gateway"`**: a provider's cloud security edge, for any vendor (Prisma Access, Zscaler,
  Cloudflare, Netskope …). **`Device.cloud_kind`** says which kind it is:
  - `mobile_users`: where remote users connect;
  - `service_connection`: the cloud's tunnel to a data center;
  - `remote_network`: where a branch's tunnel ends.

  Connectors put these devices on a site with **`Site.kind = "cloud"`**, one per provider. Such a site is never
  joined to another site, never takes part in learned joins, and is shown as the org map's cloud tier. Cloud
  gateways are never "unplaced". A cloud gateway whose `lan_prefixes` or observed addresses fall in a site's
  prefix index is linked to that site, with evidence "traffic-logs".
- **`Device.observed_peers`**: addresses of other boxes a device saw on its own ports, bounded, as
  `{ip, interface, zone, dir}`. A firewall's traffic logs are one source. Topology links the device to the
  box owning that address at the same site: a circuit, an interface or the management IP. Both interface
  names go on the link, and the evidence kind is "traffic-logs". The device sits in front of an edge whose
  WAN address it sees, and behind an edge or router whose LAN address it sees.
- **HA pairs**: each unit of a pair is its own node. They are joined by a link with layer `"ha"` and label
  "HA pair", and each node carries `ha_state` and `ha_peer`.
  - Member serials of firewalls, edges, routers and load balancers no longer merge records into one node.
    They still carry the site from one unit to the other.
  - Without vendor HA data, two units of one source at one site whose names differ only by 1/2 or A/B are
    paired as an inferred pair.
  - A site showing only unit 1 gets an inferred unit 2 when at least 70% of sites with that naming have both
    units.
- **Link layer `"ha"`** is added to `LINK_LAYERS`.

## What v0.10.30 adds

- **Security operations as capabilities:** `security.events` → `SecurityEvent`, `security.exposures` →
  `Exposure`, `security.incidents` → `SecurityIncident` (see `docs/architecture/SECURITY_DATA_PLANE.md`).
  Strata Cloud Manager and Panorama implement `security.events` through one shared PAN-OS vocabulary module
  (`connectors/panos_logs.py`); Mist implements it from its security alarms. Security Operations
  (`app/services/soc`, `static/modules/security.js`) reads only these records and the topology index — no
  vendor names, no `vendor[...]` reads, no connector ids.
- **HA units placed by their partner's name** (`propagate_name_partners`): vendor-neutral (source, role,
  unit 1/2 or A/B, a stem at exactly one site).

## Still Mist-only (roadmap, in order)

| # | Area | What a second vendor would miss | Plan | Size |
|---|---|---|---|---|
| 1 | Notification feed (alerting) | Partly done in v0.10.24: non-Mist alerts are added from `alerts` | Finish: device down from `inventory` status for all sources | S |
| 2 | Dashboard health / Disconnect Watch tiles | Counts only Mist devices | Derive from `inventory` + `alerts` via the site registry | M |
| 3 | Device Finder (clients) | No clients from other vendors | New `clients` capability with a `ClientSession` record; curated sections keyed on neutral fact keys | L |
| 4 | Two capability registries | Legacy `ProviderDescriptor` ids (`device.by_mac`, `nac.context`, …) beside `contracts` | Fold into `contracts` (`clients`, `nac.context`), retire the legacy registry | M |
| 5 | Port Toolkit, PoE, Chassis, Backups | Writes exist for Mist only; pages shown regardless | Declare `ports.config.write`, `stack.write`, `config.backup`; gate pages; port the read side via `interfaces` first | L, staged |
| 6 | `list_device_facts` / `list_topology_devices` hooks | Duck-typed, invisible to manifests and tests | Formalise as a capability or fold into `Device` / `Interface` fields | S |
| 7 | Start-up warm-up | Mist only | Optional `Connector.warm_up()` hook called for every connector | S |

Each step keeps the current Mist behaviour; it only opens the same path to other vendors.
