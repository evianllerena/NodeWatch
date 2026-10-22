# NodeWatch v0.10.30 — Security Operations, built vendor-neutral; HA partners explained

Build: `2026-10-16-v0.10.30-security-console`. Delivered as **`NodeWatch.exe`** (Windows) and **`NodeWatch.zip`** (Mac).
Both carry the identical application tree.

## Security Operations (was Security View)
- **A SOC fed by any security source.** Three new capabilities — *Security detections*, *Vulnerabilities &
  exposures*, *Security incidents* — with neutral records (`SecurityEvent`, `Exposure`, `SecurityIncident`).
  The page reads only those. See `docs/architecture/SECURITY_DATA_PLANE.md`.
- **Sources today:**
  - Strata Cloud Manager: threat logs (exploits, malware, spyware/callbacks, scans, floods, data) and blocked
    web requests, through the same Log Viewer API and service account as Traffic & Sessions.
  - Panorama: the same, through the XML API's log query.
  - Mist: wireless-security conditions (rogue APs, honeypot SSIDs).
  - The two Palo Alto readers share one PAN-OS vocabulary module, so a detection counts the same way
    whichever system delivered it.
- **Three renditions:**
  - **Watch floor** — headline numbers, the Reach ladder, detections over time by reach, origins, open cases,
    live feed, site pressure, top threats.
  - **Case desk** — NodeWatch-correlated cases with an explainable score, how far it got, what to do,
    targets / attackers / threats / CVEs / sensors / rules, state, owner, notes and history.
  - **Atlas** — where attacks come from and where inside hosts call out to, per-country detail, the
    most-targeted systems and busiest attackers.
- **Also:** Detections explorer, Vulnerabilities (CVEs attackers try on you, software spread per model,
  exposures from security platforms), Coverage (which systems feed it) and Posture (the earlier findings).
- **Wall display:** full screen, dark, rotates the renditions every 45 s.
- **Preview with sample data** when no source is connected. A fictitious organisation, clearly labelled and
  never stored.
- **NodeWatch's own measures:**
  - **Reach** (1 Knocking … 5 Spreading inside);
  - **Pressure** per site / target / country;
  - **Cases** (compromise, lateral, breach, campaign, wireless, platform incidents).
- **Storage:** detections are kept locally for 7 days (≤ 30,000) as NodeWatch records and excluded from
  diagnostics exports.

## Topology: the HA partner card
- **It reasons now, instead of repeating a template.** The partner you confirmed was shown with the "found
  from the router's routes" text, which was wrong. Its card now lists:
  - when you confirmed it;
  - the pair's naming (PA-WHL1 → PA-WHL2) and how many other sites show both units;
  - whether the active unit is up and logging;
  - which systems were asked;
  - records that could be the missing unit, each with **Place it here**.
- **Naming:** the drawn unit takes the pair's name (PA-WHL2) instead of "PA-WHL1 partner".
- **When a system reports the real unit,** the active unit's card says your confirmation checked out.
- **Log-only units placed by their partner's name.** A passive unit named only by system logs (it carries no
  address) used to stay unplaced, so your placeholder was never replaced. Such a unit now goes to its partner's
  site when the names say they are units 1/2 or A/B of one pair (same source, same role, a stem found at one
  site only). The v0.10.29 diagnostics show PA-WHL2 (…0895) in the system logs, so this applies directly.

## Diagnostics
- `security_operations`: stored counts, per-source reads and errors.
- `strata_logging_service.security_logs`: which threat / URL log names answered or were refused, and why.
