# NodeWatch v0.10.35 — always-on health

## Reliability
- **NodeWatch no longer stops overnight.** While the NodeWatch window is open, silence from the page (a PC in modern standby freezes the browser but keeps NodeWatch running) never stops the backend; only closing the window or the last tab does. Without the app window the silence limit is 30 minutes (was 3.5).
- The presence watchdog can no longer die or stop NodeWatch by mistake on an internal error.
- The "NodeWatch has stopped" notice asks three times before showing, removes itself when NodeWatch answers again, and has **Close this window** and **Dismiss** buttons. "Exit NodeWatch now" closes the window too.
- **Release guard:** every build is checked before it ships — integrity manifest, launcher pinned hash, version text and the Windows launcher's inlined version comparisons, all Python/JS parse, and the staged backend must answer the launcher handshake with the right version.

## Connections
- Every configured connection checks itself at start-up, so Strata Cloud Manager (and the rest) show **Connected** without a manual Re-test. Settings refreshes itself while checks are running.

## Security Operations
- Origins: with no attack coming in from outside, the card shows where inside hosts' flagged traffic went (with a clear note) instead of an empty map. Atlas gains "All flagged traffic out".
- **Vulnerabilities attackers are trying on you:** each CVE opens a page — what it is, links to NVD and CISA KEV, blocked vs got through, whether a connected scanner reports you exposed, what to do, targets / sources / countries / sites / sensors, and every attempt.

## Topology
- The passive firewall of an HA pair is drawn automatically when a system reports the unit as active/passive, or when the naming convention (including pairs you confirmed before) says so — no "It has a passive HA partner" click needed.
- The site sentence counts both units of an HA pair ("then 2 firewalls (an HA pair)"); a confirmed partner was counted as an unmanaged device before. Organization counts include drawn partners.

## Speed
- DNS: the last good address is used immediately while the lookup refreshes in the background (a failing resolver cost 12–18 s per new connection).
- Mist alarm definitions are cached for 12 hours (≈3 s per read before).
