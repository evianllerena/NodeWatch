# NodeWatch v0.10.29 — "Where is the problem?", clickable conditions, HA partners you confirm

Build: `2026-10-16-v0.10.29-diagnose-verdict`. Delivered as **`NodeWatch.exe`** (Windows) and **`NodeWatch.zip`** (Mac).
Both carry the identical application tree.

## Event Relay: Diagnose connection names the side
- **The result opens with "Where the problem is"**: *Your network*, *Splunk Cloud's side* or *Can't tell yet*. A
  plain explanation follows.
- **How NodeWatch decides:**
  - It checks whether this PC's **other** traffic shows in the firewall logs, and whether any session to Splunk
    was denied, allowed without an answer, or not seen at all.
  - It looks for this PC's address and your public egress address (copy button). The egress address is what
    Splunk's HEC allow list must contain (*Splunk Cloud › Settings › Server settings › IP allow list › HEC
    access*).
  - "Other traffic is logged but nothing to Splunk" means your firewall drops it with a rule that does not
    log. That is typically the default interzone deny, which does not log by default.

## Device Finder
- **Requires attention:** every condition is now clickable.
  - **Each row opens to show:**
    - what happened and where (site, device, port);
    - since when and how often;
    - which system reported it, and how to fix it;
    - links to open the device in Device Finder or in Topology.
  - **Filters:** All / Critical / Warning.
- **More details** (was "More information"):
  - The cards sit in an even grid with equal heights per row and aligned labels and values.
  - Long sections span the full width, and empty sections are hidden.
  - The subtitle lists only the sections that have data.

## Topology
- **"It has a passive HA partner":** a firewall's panel has this one click. It adds the passive unit, which writes
  no traffic logs, to the map next to its active partner. A real partner found later (system logs, Panorama)
  replaces it automatically, and "Remove" takes it away.
- **Firewall discovery runs again right after an upgrade.** v0.10.28's new system-log search applies immediately
  instead of after the previous hour-long cache.
- **Abbreviated site names join:** "QTSMIA" (EdgeConnect) and "DC1 QTS Miami" (Mist) are now one site. This
  works only when the abbreviation fits exactly one site.
