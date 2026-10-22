# Network Detective — v0.7.0 Data Contract

Network Detective is a read-only resolver and investigation module. It does not perform operational changes.

## Search sources

### Wireless clients

`GET /api/v1/orgs/{org_id}/clients/search`

Used for MAC, IP, hostname, username, and broad text lookup. Current Mist API supports filters including site, AP, band, hostname, IP, MAC, SSID, text, username, and VLAN.

Juniper API reference:
https://www.juniper.net/documentation/us/en/software/mist/api/http/api/orgs/clients/wireless/search-org-wireless-clients

### Wired clients

`GET /api/v1/orgs/{org_id}/wired_clients/search`

Used for MAC, IP, hostname/username text lookup and attachment context. Current generated Mist SDK supports auth state/method, source, site, device MAC, client MAC, port, VLAN, IP, manufacturer, text, NAC rule and DHCP-related filters.

Generated Mist Python SDK:
https://github.com/tmunzer/mistapi_python/blob/main/src/mistapi/api/v1/orgs/wired_clients.py

### Inventory

`GET /api/v1/orgs/{org_id}/inventory/search`

Used to resolve AP, switch, gateway, name, MAC and serial. The endpoint defaults to AP when type is omitted, so Detective explicitly searches the documented concrete types `ap`, `switch`, and `gateway` and merges the results.

Generated Mist Python SDK:
https://github.com/tmunzer/mistapi_python/blob/main/src/mistapi/api/v1/orgs/inventory.py

### Access Assurance / NAC

`GET /api/v1/orgs/{org_id}/nac_clients/search`

`GET /api/v1/orgs/{org_id}/nac_clients/events/search`

Used as optional authentication/policy context. Detective remains functional if the organization/token does not have Access Assurance data.

Generated Mist Python SDK:
https://github.com/tmunzer/mistapi_python/blob/main/src/mistapi/api/v1/orgs/nac_clients.py

## Detail enrichment

### Site client statistics

`GET /api/v1/sites/{site_id}/stats/clients/{client_mac}?wired={true|false}`

This is the primary current-state enrichment once a client and site are resolved. The API can return either wireless or wired client statistics.

Juniper API reference:
https://www.juniper.net/documentation/us/en/software/mist/api/http/api/sites/stats/clients-wireless/get-site-wireless-client-stats/

### Switch / gateway port statistics

`GET /api/v1/orgs/{org_id}/stats/ports/search`

For a wired client, Detective resolves the switch MAC + port ID and requests the matching interface statistics. Current fields include interface state, speed/duplex, PoE, STP, and LLDP neighbor context when Mist reports them.

Generated Mist Python SDK:
https://github.com/tmunzer/mistapi_python/blob/main/src/mistapi/api/v1/orgs/stats.py

### Active alarms

`GET /api/v1/orgs/{org_id}/alarms/search`

Detective reuses the application's current unified Mist Alerts source. Resolved/cleared alarm records are excluded from the Detective "Active Alarms" panel.

### Marvis troubleshoot (optional)

`GET /api/v1/orgs/{org_id}/troubleshoot?mac={device_mac}`

Juniper documents this for wired/wireless clients, APs, switches and WAN Edges. It requires a valid observer token and Marvis subscription. Detective treats this as optional enrichment and does not fail if it is unavailable.

Juniper documentation:
https://www.juniper.net/documentation/us/en/software/mist/mist-aiops/topics/concept/marvis-api-troubleshooting.html

## Safety boundary

Network Detective does not expose:

- Port bounce
- PoE cycle
- Cable test
- VLAN/profile changes
- 802.1X reauthentication / CoA
- Device configuration writes

Those actions belong in Port Operations and must use the application's shared preview / approval / transaction / verification / audit workflow.

## v0.7.1 Performance and Presentation Notes

- Search sources (wireless, wired, inventory, NAC) are queried concurrently.
- Infrastructure inventory type searches (AP/switch/gateway) are queried concurrently.
- Detail enrichment runs independent NAC, alarm, inventory, device-stat, and port-stat requests in parallel.
- Marvis troubleshoot is lazy-loaded after the core investigation so optional AIOps latency does not block the result.
- Wired port telemetry fallback order is: org port stats -> site port stats -> switch embedded `ports` / `port_stat` data.
- If Mist identifies a switch/port but no port telemetry is returned, the UI preserves the known attachment and reports which telemetry sources were attempted.
- Client result badges are presentation-only heuristics based on Mist device/family/model/OS/manufacturer/DHCP identity fields. They never affect matching or configuration.
- MAC values are normalized to colon-separated display format and last-seen timestamps are rendered as human-friendly relative/local time in the browser.

## v0.7.2 Wired Port Resolution Notes

Mist wired-client search is historical/aggregated. Fields such as `device_mac`, `port_id`, `vlan`, and `ip` can be arrays. The `device_mac_port` array preserves the relationship between a switch device MAC and the port where the client was observed, including a `when` timestamp. Detective therefore resolves the most recent paired relationship before issuing a port-stat query.

For Virtual Chassis, the physical member MAC reported in client context can differ from the device identifier used by switch-port statistics. Detective resolves inventory `vc_mac` and prefers the VC anchor/device identity for telemetry lookups.

Port telemetry lookup order:
1. Org port stats using the client-reported device identifier + exact port ID.
2. Site port stats using the same pair.
3. Embedded ports in already-fetched switch stats.
4. VC-aware retries using resolved inventory MAC / `vc_mac`.
5. Site port search by exact port ID, accepted only when the returned device MAC matches a known resolved switch identity.
6. Direct site device stats (`/api/v1/sites/{site_id}/stats/devices/{device_id}`) and embedded port extraction.

Current Mist documentation notes that the port-search endpoints return current/last port status and statistics within approximately the last hour, so a disconnected/older client may legitimately lack a port-search row even when its last-known attachment is known.

Reference sources checked for this change:
- Juniper Mist API: Search Org Switch/Gateway Ports
- Juniper Mist API: Search Site Switch/Gateway Ports
- Juniper Mist API / Postman: Search Org Wired Clients
- Juniper Mist REST API overview: per-device site statistics
- Juniper Mist Virtual Chassis inventory/status documentation
