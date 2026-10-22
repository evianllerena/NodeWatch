"""NodeWatch Security Operations (v0.10.30) — a vendor-neutral SOC built only on capability records.

Data flow (docs/architecture/SECURITY_DATA_PLANE.md)::

    connectors ──security.events──▶ collector ──▶ store (bounded, local) ──▶ engine ──▶ API ──▶ page
               ──security.exposures─────────────────────────────────────▶ engine
               ──security.incidents─────────────────────────────────────▶ engine
    topology index (sites, devices, subnets) ──▶ context (who is the target, which site) ──▶ engine

Nothing in this package knows a vendor: it reads :class:`SecurityEvent`, :class:`Exposure` and
:class:`SecurityIncident` records through ``sdk.sources`` and NodeWatch's own topology index. A new security
vendor appears here by implementing the capability in its connector — no change in this package.
"""
