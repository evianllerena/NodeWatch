# Security data plane and Security Operations (v0.10.30)

NodeWatch's Security Operations Center (SOC) is built the same way as the rest of the product: **features read
capabilities, never vendors**. Today the detections come from Palo Alto (Strata Cloud Manager / Strata Logging
Service, Panorama) and Juniper Mist; tomorrow they can come from FortiGate / FortiAnalyzer, Cisco Secure
Firewall, Check Point, Zscaler, Netskope, CrowdStrike, Defender, SentinelOne, Suricata, a SIEM or a scanner.
**Adding one means writing one connector adapter. No SOC code changes.**

## Layers

```
 vendor API / logs                 connector (the ONLY vendor-aware code)          NodeWatch (vendor-neutral)
 ───────────────────               ──────────────────────────────────────          ───────────────────────────────────────
 SLS Log Viewer threat/url rows ─▶ paloalto_scm/threats.py ─┐                      app/services/soc/
 Panorama XML log entries ──────▶ panorama/threats.py ──────┼─▶ SecurityEvent ──▶  collector → store (7 d, bounded)
   (shared PAN-OS vocabulary:      connectors/panos_logs.py)│                        → context (topology index: who, where)
 Mist security alarms ──────────▶ mist/security.py ─────────┘                        → engine (Reach, Pressure, Cases)
 scanners / EDR / IoT platforms ─▶ <vendor>/…  ──────────────▶ Exposure ──────────▶  → API /api/v1/security/soc*
 SIEM / XDR incidents ───────────▶ <vendor>/…  ──────────────▶ SecurityIncident ──▶  → page (renditions)
```

## Contracts (`app/integrations/contracts.py`)

| Capability | Method | Record |
|---|---|---|
| `security.events` | `list_security_events(*, since, until=None, limit=2000)` | `SecurityEvent` |
| `security.exposures` | `list_exposures(site_key=None)` | `Exposure` |
| `security.incidents` | `list_security_incidents(*, hours=168)` | `SecurityIncident` |

All three are read-only, bounded, and return records (never raw rows). A connector claims only what its API
really offers; the conformance check (`isinstance(connector, CAPABILITY_PROTOCOLS[cap])`) holds for all of
them, and every claimed capability has a probe in Settings › Connections › Test.

## Records (`app/integrations/domain.py`)

`SecurityEvent` — one detection. NodeWatch vocabulary for what the SOC counts:

* `kind`: exploit · malware · command_control · reconnaissance · flood · web · data_loss · credential ·
  wireless · policy · other
* `outcome`: blocked · contained · alerted · allowed · unknown (what the control did)
* `direction`: inbound · outbound · internal · unknown (relative to the organisation's own networks — computed
  from addresses and zones, never from a vendor's "direction of attack")
* `severity`: critical · major · warning · info

…and the vendor's own words where they matter to a person (`name`, `category`, `rule`), plus addresses, ports,
countries (ISO-2, from the source — NodeWatch never geolocates addresses), user, application, the sensor
(`sensor_key` = the same `Device.key` the inventory uses), URL / file / hash, `count` and a small `vendor` dict
for display only. The SOC never reads `vendor[...]`.

`Exposure` — a known weakness on an asset (CVE, CVSS, exploited-in-the-wild, fixed-in, state).
`SecurityIncident` — an incident another platform already correlated.

## NodeWatch's own analytics (`app/services/soc/engine.py`)

These are NodeWatch concepts, computed identically for every vendor:

* **Reach** — how far a detection got: 1 Knocking · 2 Stopped at the door · 3 Got through · 4 Calling out ·
  5 Spreading inside. A blocked callback still counts as 4: the host tried to reach an attacker.
* **Pressure** — per site / target / attacker / country: Σ severity weight × reach weight × √repeats, scaled so
  the most pressed one is 100.
* **Cases** — correlation rules: `compromise` (Reach 4 per inside host), `lateral` (Reach 5 per source),
  `breach` (Reach 3 inbound per target), `campaign` (one attacker, ≥ 3 targets with high-severity attempts, or
  ≥ 10 high-severity attempts), `wireless` (per site), and `vendor` (platform incidents). The **case score**
  is explainable: Reach points (10/20/55/70/75) + severity (−5…+15) + volume (≤ 10) + 10 when the furthest step
  was not stopped. Triage (state, owner, notes, history) is local; a closed case reopens on new detections.
* **Context** — targets and sensors are resolved through the topology organisation index (managed device by
  address, else the site whose LAN contains the address), so "10.40.1.20" becomes "DC-EHR-APP at Data Center
  East" for any vendor's detection.

## Storage and safety

* Detections are kept locally for 7 days, at most 30,000, as NodeWatch records (no raw vendor rows), in the
  private data folder (`state/security/detections.json`, owner-only). Not part of diagnostics exports; the
  export carries counts and source health only (`security_operations` in `support_summary.json`).
* Collection runs in the background (every 2 min while the page is open, every 15 min otherwise), per source,
  with a moving window (re-reading the last 10 minutes for late logs); one failing source never hides the
  others.
* Sample data (`?sample=true`) is a fictitious organisation on documentation address ranges, always labelled,
  never stored, and runs through the same engine.

## Adding a security vendor — checklist

1. In `app/integrations/connectors/<vendor>/`, add a mixin with `CAPABILITIES = (SECURITY_EVENTS,)` and
   `list_security_events(...)` translating the vendor's detections into `SecurityEvent`. Map its vocabulary to
   `kind` / `outcome` / `severity`; compute `direction` from addresses; set `sensor_key` with
   `sdk.device_key(...)` so the sensor joins the inventory record; keep the vendor's names in `name`.
2. Add the capability to the manifest and a probe (the default plan already reads the last hour).
3. Nothing else. Security Operations, Coverage, cases, countries, vulnerabilities and diagnostics pick it up.

The same applies to `security.exposures` (a scanner, an endpoint / IoT platform, an advisory feed matched to
inventory) and `security.incidents` (a SIEM or XDR).

## Known limits (v0.10.30)

* Palo Alto does not publish the Log Viewer names of the threat and URL logs: `firewall_threat`, `log_threat`,
  `threat` (and `firewall_url`, `log_url`) are tried and the first that answers is remembered; refusals are
  retried after 24 h and listed in diagnostics with the service's own error text. The threat-log field names
  seen are written to the application log once per start.
* Panorama's XML API log times carry no zone: NodeWatch queries with relative windows (`receive_time in
  last-…`), reads Panorama's clock once (`show clock`) to convert zone-less times, and prefers
  `high_res_timestamp` (with offset) when present. Reads are paged with `skip` (≤ 5,000 per call).
* A read that reaches its limit leaves a gap; the collector reads that gap on the following passes until it is
  closed, so busy periods are not lost.
* Mist contributes wireless-security conditions only (its alarms with category "security").
