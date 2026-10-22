# NodeWatch v0.10.20 — Silver Peak overlay tunnels on large fabrics

Build: `2026-10-09-v0.10.20-sp-tunnels`.

- **Overlay tunnel reads are much smaller.** The overlay tunnel list (`GET /tunnels2/bonded`) now asks
  Orchestrator to leave out the physical member tunnels embedded in each overlay (`children=false`). With them, a
  large fabric answered more than NodeWatch's 20 MB safety limit, so overlay tunnels were missing from Topology,
  path trace and tunnel health.
- **Fallback for very large fabrics:** if the org-wide answer is still too large, NodeWatch reads tunnels one
  appliance at a time instead of failing. The connection Test uses the same read.
- **Not a permission problem:** the read-only key was sufficient throughout.
