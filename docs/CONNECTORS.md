# NodeWatch connectors — plug-and-play vendors (v0.10.16, Add-connection workflow v0.10.18)

NodeWatch must work for any company, whatever it runs: Juniper Mist + Palo Alto + Silver Peak at one,
Cisco + Fortinet + FortiGate SD-WAN at another. So the tools never talk to a vendor directly. They ask
for **data of a kind** ("sites & devices", "alerts", "tunnels" …) and NodeWatch collects it from
whichever connected vendors offer it.

## The picture

```
 Vendor APIs                Connectors                 Capability contracts       Domain records
 ───────────                ──────────                 ────────────────────       ──────────────
 Juniper Mist  ───────────▶ connectors/mist/        ─┐
 Palo Alto SCM ───────────▶ connectors/paloalto_scm/ │  inventory                 Site, Device
 Palo Alto Panorama ──────▶ connectors/panorama/     │
 Silver Peak Orchestrator ▶ connectors/silverpeak_…  ├▶ interfaces          ───▶  Interface
 FortiGate     ───────────▶ connectors/fortigate/    │  alerts / events           Alert, Event
 (your vendor) ───────────▶ connectors/<id>/        ─┘  topology.* / tunnels      Neighbor, L2Entry,
                                                         traffic.logs              L3Entry, Route, Tunnel
                                                                │
                                                                ▼
                                       sdk.sources(capability) / sdk.gather(capability, method)
                                       (merges every connected vendor, reports per-vendor errors)
                                                                │
                                                                ▼
                                  Correlation / topology engine — joins records by MAC, serial, IP
                                  (a FortiGate's LLDP neighbor with MAC f4b5… IS the Mist switch f4b5…)
                                                                │
                                                                ▼
                      Features: Command Center, Topology, Port Toolkit, Device Finder, Traffic & Sessions …
```

* **Connector** — one folder per vendor product under `app/integrations/connectors/<connector_id>/`.
  It knows that vendor's API: authentication, endpoints, paging, field names. Nothing else does.
* **Capability contract** — `app/integrations/contracts.py`: a stable name (`topology.tunnels`) and
  the Python method it requires (`list_tunnels(site_key) -> list[Tunnel]`).
* **Domain records** — `app/integrations/domain.py`: vendor-neutral dataclasses with fixed vocabularies
  (device roles, severities, link layers, up/down/degraded/unknown).
* **Discovery** — at start-up NodeWatch imports every connector folder (names starting with `_` are
  skipped), validates its manifest, and **rejects a connector that claims a capability without
  implementing its method**.
* **Settings › Connections** — draws the catalog, the Add-connection wizard (setup guide, form, Test)
  and the connected cards straight from each manifest. No UI code per vendor.
* **`GET /api/v1/connectors/capabilities`** — tells the UI which kinds of data at least one connected
  source offers, so a tool can hide what nobody can supply (`MistTools.connections.has('topology.tunnels')`).

## Keys: how two vendors' records about the same box meet

Every record has a stable `key`. Build device keys with `sdk.device_key(mac=…, serial=…)`:
base MAC first, then serial, and only if neither is known a key scoped to your connector. Because Mist,
FortiGate and any future Cisco connector all compute `stable_key("mac", "<12 hex>")` for the same
chassis MAC, their records correlate with no vendor-specific glue. Always pass MACs through
`normalize_mac`. Sites are per connector: `sdk.site_key(connector_id, native_site_id)`.

## Connect a vendor (end users) — Settings › Connections › Add connection

Every product is connected the same way, in five steps, with a read-only account:

1. **Choose** — search the catalog (grouped by category, with Preview/Stable badges and "Already
   connected").
2. **Before you start** — what you need, numbered steps to create the least-privilege account or API
   key in the vendor's console (values you can copy, a link to the vendor's own page), what the Test will
   check, and anything not yet confirmed on a live system. Mist and Strata Cloud Manager point to their
   own settings sections instead.
3. **Connect** — the form drawn from the connector manifest; secrets are masked (Show/Hide), checked
   inline (required, `https://`, numbers) and stored in Windows Credential Manager.
4. **Test** — read-only, at most 20 seconds, with the unsaved values: a checklist (*Reachable*, *TLS
   certificate*, *Authenticated*, *Permissions sufficient*, *Found*), then one result per capability
   (Readable / Refused / Empty / Timed out …) with the exact reads behind it, what permission a refused
   read needs, and **"Would more permission help?"** — whether a broader role would unlock anything.
5. **Done** — the connection is saved and switched on (toggle), with what data is now available and
   buttons to the places that use it (Topology, Command Center, Device Finder …).

The page lists **Connected** products as cards (on/off switch, *Edit*, *Re-test*, *Disconnect*) and
keeps everything else under a collapsed **Available** list, so products a company does not use (for
example Panorama where there is no Panorama) stay one click away without cluttering the page.

## Add a new vendor in 6 steps (developers)

```
python tools/new_connector.py cisco_meraki --vendor "Cisco" --product "Meraki Dashboard" --category network_management
```

copies `_template` to `app/integrations/connectors/cisco_meraki/` (ids, class name, vendor, product and
category filled in; example fixtures; a setup-guide stub), writes `tests/test_connector_cisco_meraki.py`
(runs the whole contract below for this connector) and prints the next steps. It never overwrites an
existing connector. Then:

1. **Manifest + setup guide.** Settings fields (`url`, `secret`, `boolean`, `number`, `select`, `text`),
   **only the capabilities you implement**, `maturity="preview"`, and `SETUP` — the guide the wizard
   shows (see *The setup guide* below). Replace every `TODO`.
2. **Capabilities.** Implement each method through `self.http()` (HTTPS only, TLS verified, timeouts,
   no redirects, secrets scrubbed) inside `self.call(fn, "what")`, returning domain records. Cite the
   vendor doc for each endpoint next to the call. Delete what you do not support.
3. **Fixtures from real responses.** Record real API answers, **sanitize** them (hostnames →
   `example.com`, RFC 5737 / RFC 1918 addresses, invented serials, no customer names — a test guards
   connector code), save them in `fixtures/` and route them in `fixtures.py`. Never call a live system in
   tests.
4. **Contract tests.** `pytest -q tests/test_connector_<id>.py` (and `tests/test_connectors_contract.py`
   runs it for every connector): manifest valid, capabilities implemented, record types and
   vocabularies, stable unique keys, references resolve, no secret in records or errors,
   `test_connection()` is one read-only call, only reads, **setup guide complete**, **probe read-only,
   bounded and secret-free**.
5. **Probe.** The default `probe_plan()` reads each capability once (one device where the method takes
   one). Override it for a cheaper, explained plan — see `silverpeak_orchestrator/probe.py`: one
   `Probe(capability, check, run, noun, needs, optional, sample)` per read, `needs` saying which
   permission allows it.
6. **Maturity: preview → stable.** Promote only when every box is ticked.

**Checklist**

- [ ] `MANIFEST` valid; `connector_id` = folder name; only implemented capabilities
- [ ] `SETUP` complete: summary, prerequisites, numbered steps with menu paths, least-privilege
      `permissions`, `verify`, `troubleshooting`, `data_you_get`, `estimated_minutes`; unknowns in
      `uncertain`
- [ ] every endpoint cited; read-only (GETs, or a documented read-query POST added to the contract's
      allow-list with a reason)
- [ ] fixtures are real, sanitized captures (not invented) for every capability
- [ ] contract tests pass; probe reports every capability within 20 s
- [ ] **preview → stable:** ran against a live system; fixtures replaced by real captures; the Test's
      probe shows every capability readable with the documented least-privilege role; the setup guide
      has no `TODO` and its `uncertain` notes are resolved (the contract tests refuse a `stable`
      connector whose guide contains `TODO`)

## The setup guide (`ConnectorManifest.setup`, v0.10.18)

Additive SDK fields — a connector without them still loads (third-party packages keep working), but the
contract tests require them for every shipped connector:

```python
SETUP = ConnectorSetup(
    summary="One line: what you get.",
    prerequisites=("Version and reachability", "Who can create the account"),
    steps=(SetupStep("Create a read-only role", "Menu › path … exact permissions", link="https://…", copy="nodewatch-readonly"), …),
    permissions="The least-privilege role/key and what NodeWatch never needs.",
    verify="What Test reads.",
    troubleshooting=(SetupIssue("Authenticated: fail (HTTP 401)", "Cause and fix."), …),
    data_you_get=("Each capability in plain words", …),
    estimated_minutes=10,
    uncertain=("Anything not yet confirmed on a live system",),
)
MANIFEST = ConnectorManifest(..., setup=SETUP)
```

`SetupStep.copy` is shown with a Copy button; `link` must be `https://`. `ConnectorSetup.problems()` runs
inside `ConnectorManifest.validate()` when a guide is present; `ConnectorManifest.setup_problems()` is
what the contract tests call.

## The Test and the capability probe (v0.10.18)

`POST /api/v1/connectors/{id}/test` with `{"values": {…unsaved form…}, "probe": true}` (or without
`values` to re-test the saved connection) returns:

* `checks` — `reachable`, `tls`, `authenticated`, `permissions`, `found`, each `pass|fail|warn|skip` with
  a sentence;
* `capabilities` — one row per claimed capability: `ok`, `partial` (works, an optional detail was
  refused), `denied`, `empty` (answered with nothing — e.g. an SNMPv3 view without that MIB),
  `unsupported`, `error`, `timeout`, `skipped`;
* `probes` — every individual read with its status, count, and the permission it `needs`;
* `unlock` — `more_needed` plus, per refused read, what it would unlock and what it needs;
* `sample` — what was found ("5 appliances in 3 sites · 8 underlay tunnels (6 up) · …").

How it stays safe: it runs on a throw-away connector instance (the live connector's caches are
untouched; a re-test records the result as the connection's health), probes call only the connector's
read methods, 4 run in parallel, each HTTP request is capped at 8 s, and the whole Test at 20 s —
anything still running is reported as `timeout` and not waited for. All text is redacted; secrets never
appear in the answer. Query-style capabilities (policy lookup, endpoint locate, traffic logs) and writes
are listed as "not checked", never exercised. `POST /api/v1/connectors/{id}/enabled {"enabled": bool}`
switches a saved connection on or off.

| Connector | What the probe reads |
|---|---|
| `silverpeak_orchestrator` | `GET /gmsserver/info`, `/appliance`, `/appliance/haPeerMeta`, `/regions/appliances`, `/gms/interfaceLabels?type=wan`, one appliance's `/interfaceState` and `/subnets/all`, `/tunnels2/physical` and `/tunnels2/bonded`, the alarm query, and one memory + one flow statistics query (one appliance, 5 minutes) |
| `panorama` | `show system info`, `show devices all`, `show devicegroups`; through Panorama on ONE connected firewall: interfaces, ARP, routes, LLDP, `show vpn flow`, `show system resources`, HA state. Policy lookup is not run |
| `fortigate` | `monitor/system/status`, `ha-peer`, `monitor/system/interface`, `cmdb/system/interface`, LLDP, ARP, `router/ipv4`, `vpn/ipsec` |
| `snmp` | the system group of the first target, then ≤ 5 rows of each table (IF-MIB, LLDP/CDP, ARP, bridge, routes, HOST-RESOURCES) |
| others | the default plan: each capability's own read method, one device where it takes one |

## What each capability means — and where vendors usually provide it

| Capability (name) | Method → records | Juniper Mist | Cisco Meraki | Cisco Catalyst Center | Aruba Central | Palo Alto SCM / Panorama | FortiGate / FortiManager | Silver Peak Orchestrator | Cisco SD-WAN (vManage) | Meraki MX |
|---|---|---|---|---|---|---|---|---|---|---|
| Sites & devices (`inventory`) | `list_sites`, `list_devices` → Site, Device | orgs/{id}/sites, stats/devices | organizations/{id}/networks, devices/statuses | site-health, network-device | monitoring/v2/switches, aps | Panorama op `show devices all` + `show devicegroups`; SCM `GET /config/setup/v1/devices` | monitor/system/status; FortiManager dvmdb/device | /appliance | /dataservice/device | org devices/statuses |
| Interfaces & ports (`interfaces`) | `list_interfaces` → Interface | stats/ports/search | devices/{serial}/switch/ports/statuses | interface/network-device/{id} | switches/{serial}/ports | Panorama op `show interface all` (target=serial; includes zones) | monitor/system/interface, cmdb/system/interface | /interfaceState | device/interface | appliance/uplinks/statuses |
| Alerts (`alerts`) | `list_alerts` → Alert | alarms/search | assurance/alerts | issues | monitoring alerts | Panorama: disconnected / HA / policy-sync checks (SCM incidents: POST search, not used) | monitor/log/event; FortiAnalyzer | /alarm/appliance | /alarms | assurance/alerts |
| Acknowledge (`alerts.ack.write`) | `acknowledge_alert` | alarms/{id}/ack | — | issue resolve | alert ack | incident update | — | /alarm/acknowledgement/appliance (not used) | alarms/markviewed | dismiss |
| Device events (`events`) | `list_events` → Event | devices/events/search | networks/{id}/events | event series | audit/events | system logs | event logs | alarm history | /events | appliance events |
| LLDP/CDP neighbors (`topology.neighbors`) | `list_neighbors` → Neighbor | port stats neighbor_* | devices/{serial}/lldpCdp | topology/physical-topology | switch lldp | Panorama op `show lldp neighbors all` (when LLDP is enabled) | monitor/network/lldp/neighbors | — | device/lldp | lldpCdp |
| MAC tables (`topology.mac_table`) | `list_mac_table` → L2Entry | wired_clients/search | clients | — | switch mac table | — | switch-controller | — | — | — |
| ARP tables (`topology.arp`) | `list_arp` → L3Entry | gateway ARP | appliance ARP | — | gateway ARP | Panorama op `show arp all` (target=serial) | monitor/network/arp | — | device/arp | — |
| Routing tables (`topology.routes`) | `list_routes` → Route | gateway routes | appliance static routes | — | gateway routes | Panorama op `show routing route` / `show advanced-routing route` | monitor/router/ipv4 | /subnets/all | device/ip/routetable | appliance routes |
| VPN / SD-WAN tunnels (`topology.tunnels`) | `list_tunnels` → Tunnel | WAN edge peer paths | appliance/vpn/statuses | — | tunnel status | Panorama op `show vpn flow` (target=serial) | monitor/vpn/ipsec | /tunnels2/physical, /tunnels2/bonded | device/tunnel/statistics | vpn statuses |
| WAN circuits (`wan.circuits`, v0.10.24) | `list_circuits` → Circuit | WAN edge port stats (wan ports) | appliance/uplinks/statuses | — | gateway uplinks | — | monitor/virtual-wan/health-check | /interfaceState, /deployment, /tunnels2/physical | device/tloc, device/interface | appliance uplink statuses |
| Traffic logs (`traffic.logs`) | `search_traffic` → Traffic & Sessions payload | — | — | — | — | Strata Logging Service / Log Viewer | FortiAnalyzer logview | flow export | — | — |

(Endpoints are pointers to where each vendor documents the data; each connector cites the exact ones it calls.)

**WAN circuits:** one `Circuit` per WAN port / uplink / TLOC, keyed on the device it terminates on. Fill `label` with the vendor's transport name and `carrier` with the ISP or circuit comment; `kind` via `domain.circuit_kind()`; leave figures the API does not give as `None`. Topology shows circuits from every connector that declares `wan.circuits`.

## What ships (v0.10.16 – v0.10.18)

| Connector | Category | Capabilities | Maturity | Configured on |
|---|---|---|---|---|
| `mist` — Juniper Mist Cloud | Network management | inventory, interfaces, events, alerts, alerts.ack.write, topology.neighbors | stable | Settings › Mist Connection |
| `paloalto_scm` — Strata Cloud Manager | Logging | traffic.logs; inventory (v0.10.17) | traffic.logs stable (wraps the verified Traffic & Sessions provider); inventory **preview** | Settings › Security & Logging Integrations |
| `panorama` — Palo Alto Panorama (PAN-OS XML API, v0.10.17) | Firewall | inventory, interfaces, alerts, topology.neighbors, topology.arp, topology.routes, topology.tunnels, health.metrics, security.policy_lookup | **preview** | Settings › Connections |
| `silverpeak_orchestrator` — EdgeConnect Orchestrator | SD-WAN | inventory, interfaces, alerts, topology.tunnels, topology.routes, health.metrics (v0.10.17), wan.circuits (v0.10.24) | **preview** (validated against the Orchestrator 9.4 API spec) | Settings › Connections |
| `fortigate` — FortiGate (FortiOS REST) | Firewall | inventory, interfaces, topology.neighbors, topology.arp, topology.routes, topology.tunnels | **preview** | Settings › Connections |
| `snmp` — SNMPv3 read-only (standard MIBs, v0.10.17) | Network management | inventory, interfaces, topology.neighbors, topology.arp, topology.mac_table, topology.routes, health.metrics | **preview** | Settings › Connections |

## Palo Alto Networks: Panorama (`panorama`) and Strata Cloud Manager (`paloalto_scm`), v0.10.17

Most companies manage Palo Alto firewalls from **Panorama** (device groups for policy, templates for
network settings) and use **Strata Cloud Manager (SCM)** for cloud services such as Strata Logging
Service and Prisma Access. NodeWatch has one connector for each; use either or both. They key a
firewall by its **serial number**, so a firewall that both report becomes one node in Topology.

| | `panorama` | `paloalto_scm` |
|---|---|---|
| API | PAN-OS XML API on Panorama, `https://<panorama>/api/` | SCM REST APIs, `https://api.strata.paloaltonetworks.com` + Log Viewer |
| Credential | Panorama API key (`X-PAN-KEY` header) | Common Services OAuth service account (Client ID, Secret, TSG ID) |
| Configured on | Settings › Connections (form drawn from the manifest) | Settings › Security & Logging Integrations (unchanged) |
| Firewalls seen | Every firewall Panorama manages | Firewalls onboarded to SCM (cloud-managed; Panorama-managed only if onboarded to SCM) |
| Capabilities | inventory, interfaces (+ zones), alerts, LLDP neighbors, ARP, routes, IPsec tunnels, live health, security policy lookup | traffic.logs (stable), inventory (preview) |
| Maturity | preview — built from docs, not yet run against a live Panorama | logs stable; inventory preview |

### Panorama — what NodeWatch calls

Everything is a read-only operational command (`GET /api/?type=op&cmd=<xml>`). Firewall-level commands
carry `target=<serial>`, which makes Panorama run them on that managed firewall
([Query a Firewall from Panorama (API)](https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-panorama-api/pan-os-xml-api-use-cases/query-a-firewall-from-panorama-api)),
so one URL and one key cover the fleet. Per-firewall commands run 4 at a time (configurable, 1–16), skip
disconnected firewalls, are capped per refresh, and are cached 30 s; one unreachable firewall never hides
the others.

| Command | Target | Used for |
|---|---|---|
| `<show><system><info/></system></show>` | Panorama | Test connection |
| `<show><devices><all/></devices></show>` | Panorama | Firewalls: serial, hostname, model, PAN-OS version, management IP, connected, uptime, HA state + peer, vsys |
| `<show><devicegroups/></show>` | Panorama | Device group per firewall (→ sites) and shared-policy sync status |
| `<show><interface>all</interface></show>` | firewall | Interfaces: state, speed, MAC, IPs, VLAN tag, **security zone**, virtual router |
| `<show><arp><entry name='all'/></arp></show>` | firewall | ARP table |
| `<show><routing><route/></routing></show>`, then `<show><advanced-routing><route/></advanced-routing></show>` if the firewall runs the Advanced Routing Engine | firewall | Active routes (host routes and inactive candidates dropped) |
| `<show><lldp><neighbors>all</neighbors></lldp></show>` | firewall | LLDP neighbors (empty unless LLDP is enabled on the firewall's interfaces) |
| `<show><vpn><flow/></vpn></show>` | firewall | IPsec tunnels: name, state (active → up, init → down), local/peer IP, tunnel interface. Panorama itself rejects `show vpn` |
| `<show><high-availability><state/></high-availability></show>` | HA firewalls | Alerts (HA unhealthy, peer down, config not synchronized) and HA state |
| `<show><system><resources/></system></show>`, `<show><session><info/></session></show>`, `<show><running><resource-monitor><minute><last>1</last></minute></resource-monitor></running></show>` | firewall | Live health: data-plane CPU (management CPU when unavailable), memory, active/max sessions |
| `<test><security-policy-match>…</security-policy-match></test>` | firewall | "Would this flow be allowed?" — zones are resolved from the interface subnets and routes when not given |

Alerts: firewall disconnected from Panorama (major), device-group policy out of sync (warning), HA
member suspended/non-functional (critical), HA peer unreachable (major), HA config not synchronized
(warning). Sites: one per device group, or map device groups to site names in *Device group → site*.
An HA pair is shown in Topology as one node with both units as members.

**Verified** against Palo Alto documentation or Palo Alto's own SDK (pan-os-python) / NAPALM's PAN-OS
driver parsers: `X-PAN-KEY`, `target=`, error codes, `show devices all`, `show devicegroups`,
`show system info`, interface/ARP/route/LLDP answer shapes, HA state paths, `show system resources`,
`test security-policy-match` (both answer forms). **Assumed until tested live:** the advanced-routing
answer (JSON in `<result>`), `show vpn flow` element names, `show session info` fields, the
resource-monitor shape and HA `peer-info/conn-status`. Missing elements leave fields empty; nothing is
invented.

**Create a read-only Panorama API account**

1. Panorama › *Admin Roles* › *Add*. Role: **Panorama**. On the *XML API* tab enable only
   **Operational Requests**; disable Report, Log, Configuration, Commit, User-ID Agent, Import, Export.
   Disable the *REST API* tab and set *Command Line* to *None*; the Web UI can stay disabled.
2. Panorama › *Administrators* › *Add* (for example `nodewatch-ro`), *Administrator Type* **Custom
   Panorama Admin** with that profile, a long random password. *Commit › Commit to Panorama*.
3. Generate the key with the documented keygen call, sending the password in the request body, not
   the URL: `curl -X POST https://panorama.example.com/api/?type=keygen --data-urlencode user=nodewatch-ro --data-urlencode password=…`
   ([Get Your API Key](https://docs.paloaltonetworks.com/pan-os/10-0/pan-os-panorama-api/get-started-with-the-pan-os-xml-api/get-your-api-key)).
   NodeWatch never generates keys itself. Generating a new key for the same admin, or changing its
   password, invalidates the old key. Set an expiry under Panorama › *Setup* › *Management* ›
   *Authentication Settings* › *API Key Lifetime* if your policy requires rotation.
4. NodeWatch: Settings › Connections › **Add connection** › Panorama (Panorama stays under *Available*
   until you connect it). Enter the address you open Panorama at and paste the
   key. Keep *Verify TLS certificate* on; point *Private CA certificate* at your company CA for an
   internal certificate. Optionally limit *Device groups*.

"Operational Requests" lets a key run any operational command, so NodeWatch's client also refuses,
before sending, every `type` other than `op`/`config get|show`/`log`, and every operational command
other than `<show>` and the read-only `<test><security-policy-match>`/`<nat-policy-match>` (tested). The key
travels only in the `X-PAN-KEY` header, is stored in Windows Credential Manager, and is scrubbed from
every error. XML answers with a DOCTYPE/ENTITY declaration are rejected (no XXE, no entity expansion).

### Strata Cloud Manager — what NodeWatch calls

Traffic & Sessions is unchanged (Log Viewer query). New in v0.10.17 (preview), with the same OAuth token:

| Call | Used for |
|---|---|
| `GET /config/setup/v1/devices` (paged by `limit`/`offset`) — [List devices](https://pan.dev/scm/api/config/ngfw/setup/list-devices/) | Firewalls: name (serial), hostname, folder (→ site), model, PAN-OS version, MAC, management IP, connected, HA state + peer serial |
| `GET /config/deployment/v1/remote-networks?folder=Remote Networks` — List remote networks (pan.dev SASE deployment spec) | Prisma Access remote networks as sites (name, region, SPN, subnets). Skipped on tenants without Prisma Access. BGP peering secrets in the answer are never copied |

**Service account roles.** The account saved on Settings › Security & Logging Integrations needs a
read-only role on the tenant (TSG) that can view configuration — for example *View Only Administrator*
— in Common Services › Identity & Access. Without it the inventory reports a permission error next to
the other sources while traffic logs keep working. **Assumed:** that the device `name` is the serial
number (used as the serial only when it looks like one).

**Not used yet** (documented but asynchronous POST job/search APIs): `POST /operations/v1/jobs/route-table`
and `/jobs/device-interfaces` + `GET /operations/v1/device/jobs/{id}` (routes and interfaces per serial),
and `POST /incidents/v1/search` (incidents → alerts). Panorama-managed firewalls get these from `panorama`.

### Future change module (Panorama first, SCM second)

Both packages are split so writes can be added without touching the readers: `client.py` (transport,
read-only guard), `reader.py`/`inventory.py` (capabilities) and a design-only `writer.py` whose methods
all refuse today. The planned Panorama flow: config lock → save a named snapshot → edit the candidate
in the device group / template (`type=config&action=set|edit|delete`) → `validate` (job, polled) →
show the candidate-vs-running diff in NodeWatch's confirm dialog → `commit` to Panorama (job) →
`commit-all` to the device groups/templates (job, per-firewall results) → audit every step → rollback
by loading the snapshot, commit and push, confirmed and audited. SCM mirrors it: edit the candidate in a
folder → preview `config-versions` → `POST /config/operations/v1/config-versions/candidate:push` → poll
`/config/operations/v1/jobs/{id}`. Writes will use a separate admin/service account with write rights;
the read-only key and account above stay read-only, and the connectors will only then declare a
`.write` capability (confirmed + audited, like Port Toolkit and Mist writes).

## Silver Peak / HPE Aruba EdgeConnect Orchestrator (`silverpeak_orchestrator`, v0.10.17)

Checked call by call against the Orchestrator **9.4** REST API specification (OpenAPI 3.0, the
Support › REST API page of a 9.4.11 Orchestrator): method, path, query parameters, request body and
response fields. Fixtures are synthesized from those response schemas. It has not yet run against a
live Orchestrator, so it stays **preview**. It is read-only.

**Create a read-only API key** (Orchestrator 9.3 or later):

1. Orchestrator › *Orchestrator Server* › *Users & Authentication* › *API Keys* › *Add*.
2. Name it (for example `nodewatch-readonly`) and set *Permission* to **Read Only** (`net_read`).
   Optionally pin it to the NodeWatch PC's address (*IP allow list*) and set an expiry date.
3. If you use RBAC, give the key a role and appliance access group that can see every appliance
   NodeWatch should show (monitoring views for appliances, alarms, tunnels, routes and statistics).
4. Copy the key once, then in NodeWatch: Settings › Connections › **Add connection** › EdgeConnect
   Orchestrator (the wizard shows these steps too). Enter the
   address you open Orchestrator at (`https://orchestrator.example.com`; `/gms/rest` is added for you)
   and paste the key. Keep *Verify TLS certificate* on; point *Private CA certificate* at your company CA
   if Orchestrator uses an internal certificate.

**What the Test shows for a Read-Only key.** One row per capability: the appliance list (and how many
are unreachable), HA pairs and regions (details), one appliance's interfaces and routes, underlay and
overlay tunnel counts, active alarms and the memory/flow statistics. Every plain read should pass with
`net_read`; if one is refused, Orchestrator is limiting what the key may see (more permission is not the
fix). The alarm and statistics reads are POST queries: if *those* are refused, the Test says that only a
Read-Write key would unlock them (alarms → Requires Attention, statistics → Live health) and that
everything else works without it. If nothing is refused it says so: more permission would not unlock
anything, because NodeWatch only reads.

**How NodeWatch authenticates.** The key travels in the `X-Auth-Token` header on every request (the
same header HPE's `pyedgeconnect` SDK uses). API-key requests are stateless: no login call, no session
cookie and so no CSRF (`X-XSRF-TOKEN`) token — that is only needed for username/password sessions.
Redirects are never followed, responses are capped at 20 MB, every call has the configured timeout.

**What NodeWatch calls** (base path `/gms/rest`):

| Call | Used for |
|---|---|
| `GET /gmsserver/info` | Test connection (hostname and release) |
| `GET /appliance` | Appliances: nePk, hostname, model, serial, management IP, software version, state, site, group, hub/spoke role |
| `GET /appliance/haPeerMeta` | HA pairs (each appliance lists its peer; shown as members, `ha_state`) — optional |
| `GET /regions/appliances` | Region per appliance — optional |
| `POST /alarm/appliance?view=active&maxAlarms=2000&orderBySeverity=true` body `{"nePks": [...]}` | Active alarms. A read query; `maxAlarms` must be sent because the server default is 5 |
| `GET /tunnels2/physical?limit=…` and `GET /tunnels2/bonded?limit=…` (`&nePk=` when a site is chosen) | Underlay and overlay (bonded) tunnels: state, peer appliance, endpoint IPs, overlay name |
| `GET /interfaceState?nePk=…&cached=true` | Interfaces: admin/oper state, IPv4, MAC, speed, duplex, WAN/LAN role, label |
| `GET /gms/interfaceLabels?type=wan` / `type=lan` | Label ids → names (INETA, MPLS, …), cached 10 minutes |
| `GET /subnets/all?nePk=…&cached=true` | Routes per segment (VRF): local, static, BGP, OSPF and SD-WAN-learned routes with the peer appliance |
| `POST /stats/timeseries/memory`, `POST /stats/aggregate/flow/active`, `POST /stats/aggregate/tunnel`, `POST /stats/aggregate/jitter`, `POST /stats/aggregate/interface` (body `{"nePks": [...]}`, last 15 minutes, minute granularity) | Live health: memory %, active flows, tunnel latency/loss (tunnel aggregate) and jitter (`AVG_JITTER`, in the tunnel's `jitter_ms`), interface bit rates and packet counts. Batched (≤ 50 appliances per call), cached 45 s; one failing statistic does not hide the others |

`cached=true` reads Orchestrator's copy of the appliance data, so NodeWatch never queries the
appliances themselves. Per-appliance reads run in a pool of 4; at most *Maximum appliances* (default 500)
are read. The only POSTs are the documented read queries above (a closed list in the connector).

**Deliberately not used:** alarm acknowledgement (`POST /alarm/acknowledgement/appliance` needs an alarm id
the alarm list does not return, and the connector stays read-only), LLDP (the 9.4 API documents none for
appliances), per-CPU statistics (`/stats/timeseries/cpustat` needs one call per CPU id per appliance, so
CPU % stays empty) and `/appliance/rest` (raw pass-through to appliances).

**Still to confirm on a live Orchestrator:** that a `net_read` key may send the read-query POSTs above;
the exact `/appliance/haPeerMeta` and `/regions/appliances` list shapes (the spec documents single
items); whether tunnel statistics are keyed by tunnel alias or id (both are matched); the unit of
`MAX_POST_PCT_LOSS` (treated as percent) and the shape of the memory time series rows.

## SNMPv3 (read-only) — for devices without a usable API (v0.10.17, preview)

Vendor APIs stay the primary source. The `snmp` connector fills the gaps: switches, routers or
firewalls that have no API NodeWatch can use (unmanaged by a cloud controller, old firmware, or a
vendor without a connector yet). Because it reads only **standard MIBs**, the same connector works for
any vendor. A box seen by SNMP and by an API connector merges into one node in Topology: the SNMP
device key is the LLDP chassis MAC (`lldpLocChassisId` when it is a MAC), else the ENTITY-MIB chassis
serial, else the bridge base MAC — the same `sdk.device_key` scheme every connector uses.

**Security model**
* SNMPv3 USM only. SNMPv1/v2c are not offered (community strings travel in clear text).
* authPriv required: SHA-256 (default), SHA-384, SHA-512 or SHA-1 (legacy) + AES-128 (default) or
  AES-256. MD5 and DES are not offered. authNoPriv needs two explicit steps (privacy "None" **and** the
  toggle labelled INSECURE).
* Read-only by construction: the transport has GET and GETBULK only; there is no SET code. Give the
  SNMPv3 user a read-only view anyway.
* Passphrases (≥ 8 characters, RFC 3414) live in Windows Credential Manager, are never logged and are
  scrubbed from errors. Changing the target list in the test form requires typing them again.
* Targets: IP addresses, host names, or **private** ranges no larger than /24 (IPv6 /120); at most 256
  hosts. Multicast, broadcast, link-local, reserved and unspecified addresses are refused; a range's
  network and broadcast addresses are never polled.
* Bounded load: 8 hosts in parallel, per-request timeout/retries from the form, 60 s per host, 120 s
  per poll, answers (and "did not answer") cached for 60 s. Targets that do not answer are listed in the
  connection's last error; the others still return data.

**What it reads**

| Capability | Standard MIB objects |
|---|---|
| Sites & devices | SNMPv2-MIB `sysName`, `sysDescr`, `sysObjectID`, `sysUpTime`, `sysLocation`, `sysServices`; ENTITY-MIB `entPhysicalClass/SerialNum/ModelName/MfgName/SoftwareRev` (chassis rows); LLDP-MIB `lldpLocChassisId`, `lldpLocSysCapEnabled`; BRIDGE-MIB `dot1dBaseBridgeAddress`. Role from the topology fingerprints + LLDP/sysServices capabilities. |
| Interfaces & ports | IF-MIB `ifTable` (descr, type, speed, MAC, admin/oper status, in/out errors) and `ifXTable` (`ifName`, `ifAlias`, `ifHighSpeed`, `ifHCIn/OutOctets`); IP-MIB `ipAddrTable` + `ipAddressTable` (IPv6); IEEE8023-LAG-MIB `dot3adAggPortAttachedAggID` (LAG members) |
| LLDP/CDP neighbors | LLDP-MIB `lldpLocPortTable`, `lldpRemTable`, `lldpRemManAddrTable`; CISCO-CDP-MIB `cdpCacheTable` when the agent has it |
| ARP tables | IP-MIB `ipNetToPhysicalTable`, fallback `ipNetToMediaTable` |
| MAC tables | Q-BRIDGE-MIB `dot1qTpFdbTable` + `dot1qVlanFdbId` (FDB id → VLAN), fallback BRIDGE-MIB `dot1dTpFdbTable`; `dot1dBasePortIfIndex` (bridge port → interface) |
| Routing tables | IP-FORWARD-MIB `inetCidrRouteTable`, fallback `ipCidrRouteTable`, then RFC 1213 `ipRouteTable` (≤ 20 000 rows) |
| Live health | HOST-RESOURCES-MIB `hrProcessorLoad` (CPU, average), `hrStorageTable` RAM rows (memory); interface errors; rx/tx bps and utilization from two `ifHC*Octets` samples on consecutive refreshes |

**Creating a read-only SNMPv3 user** — examples; check the syntax of your release, restrict SNMP to
the NodeWatch PC's address with the platform's ACL/trusted-host feature, and pick the same protocols
in NodeWatch.

* Generic (Net-SNMP `snmpd.conf`):
  `createUser nodewatch-ro SHA-256 "<auth-passphrase>" AES "<priv-passphrase>"` and `rouser nodewatch-ro priv`
* Juniper Junos:
  `set snmp v3 usm local-engine user nodewatch-ro authentication-sha256 authentication-password "<auth>"` ·
  `set snmp v3 usm local-engine user nodewatch-ro privacy-aes128 privacy-password "<priv>"` ·
  `set snmp v3 vacm security-to-group security-model usm security-name nodewatch-ro group nw-ro` ·
  `set snmp v3 vacm access group nw-ro default-context-prefix security-model usm security-level privacy read-view all` ·
  `set snmp view all oid .1 include` (older releases: `authentication-sha` → choose SHA-1 (legacy))
* Cisco IOS / IOS-XE:
  `snmp-server view NW-RO iso included` · `snmp-server group NW-RO v3 priv read NW-RO access <acl>` ·
  `snmp-server user nodewatch-ro NW-RO v3 auth sha <auth> priv aes 128 <priv>` (use SHA-2 where your
  release offers it; Cisco `aes 256` → choose "AES-256 (Cisco key extension)")
* Fortinet FortiOS:
  `config system snmp user` · `edit "nodewatch-ro"` · `set security-level auth-priv` · `set auth-proto sha256` ·
  `set auth-pwd <auth>` · `set priv-proto aes` · `set priv-pwd <priv>` · `set queries enable` · `next` · `end`,
  plus `set allowaccess` … `snmp` on the interface NodeWatch polls
* Palo Alto PAN-OS: Device › Setup › Operations › SNMP Setup → Version V3: add a view (OID `1`,
  include) and a user with SHA-256 + AES; allow SNMP in the management interface (or interface
  management profile) permitted-IP list.

**Limits (preview)** — built from the MIB RFCs and recorded walks, not yet validated on live devices.
Per-VLAN BRIDGE-MIB instances (Cisco IOS `vlan-<id>` contexts) are not walked, so MAC tables on such
platforms show only what the default context exposes. The newer LLDP-V2-MIB and vendor CPU/memory MIBs
are not read. A firewall seen by SNMP merges with its API record only when both sides key it the same
way (the FortiGate API connector keys by serial; SNMP keys by LLDP MAC when the firewall advertises one).

## Packaging NodeWatch for another company

* **No company-specific values in code.** Org IDs, hostnames, site names, tenant IDs and URLs come from
  settings. Placeholders use `example.com`. A test fails if a known customer name appears in connector code.
* **Per-install configuration.** Non-secret settings live in `%LOCALAPPDATA%\NodeWatch\connectors.json`
  (plus the older `integrations.json` and Mist settings); nothing is baked into the build.
* **Secrets in Windows Credential Manager.** Secret fields are saved under
  `NodeWatch:Connector:<id>:<field>`, never written to disk in clear text, never sent back to the page
  ("Saved — leave blank to keep"), and scrubbed from every error and diagnostic line.
* **Read-only by default.** Connectors read. Anything that changes a vendor system must be a `.write`
  capability and go through the calling feature's confirmed + audited path.
* **TLS.** HTTPS only and certificate verification on by default. For on-prem appliances with private
  certificates, point "Private CA certificate" at the company CA instead of turning checks off; turning
  them off is a per-connection choice that the page flags with a warning.
* **Maturity levels.** `preview` = built from the vendor's public API documentation and recorded
  fixtures, not yet validated on a live system (shown with a Preview badge). `stable` = validated on a
  live system and covered by recorded tests.
* **The gate.** `tests/test_connectors_contract.py` must pass for every connector before it ships. A
  connector that fails discovery is logged and skipped; it never takes NodeWatch down.

## Limits today

* One connection per connector (one FortiGate, one Orchestrator). Fleets belong in the manager's
  connector (FortiManager, Panorama) rather than many device connections.
* Features are moving to capabilities tool by tool; some older tools still call the Mist client directly.
