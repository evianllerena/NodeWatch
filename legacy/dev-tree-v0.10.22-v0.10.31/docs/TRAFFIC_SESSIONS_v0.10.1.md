# NodeWatch v0.10.1 — Traffic & Sessions

See `docs/traffic-sessions/TRAFFIC_SESSIONS_CHANGELOG_v0.10.1.md` for the complete 16-point implementation ledger and `docs/traffic-sessions/TRAFFIC_SESSIONS_QA_v0.10.1.md` for verification.

Architecture rule: **query narrowly, ingest richly, display selectively**. Traffic records are normalized into the NodeWatch canonical schema; raw SLS records stay backend-only and bounded.

SLS direct query authentication uses the Palo Alto SCM registration credential flow (Registration ID + Encryption Key + Client Secret), which is separate from the Device Intelligence Client ID / Secret / TSG OAuth integration.
