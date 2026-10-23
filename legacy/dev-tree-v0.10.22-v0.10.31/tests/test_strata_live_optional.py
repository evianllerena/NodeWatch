"""Optional live check against YOUR Strata Cloud Manager tenant.

Skipped unless these environment variables are set (never commit them):

    NODEWATCH_LIVE_PA_CLIENT_ID, NODEWATCH_LIVE_PA_CLIENT_SECRET, NODEWATCH_LIVE_PA_TSG_ID
    optional: NODEWATCH_LIVE_SLS_QUERY_HOST (default https://pa-us01.api.prismaaccess.com)
              NODEWATCH_LIVE_SLS_TENANT     (Prisma-Tenant override, e.g. "<TSG>:<sub-tenant>")

Windows PowerShell example:
    $env:NODEWATCH_LIVE_PA_CLIENT_ID="..."; $env:NODEWATCH_LIVE_PA_CLIENT_SECRET="..."; $env:NODEWATCH_LIVE_PA_TSG_ID="..."
    python -m pytest tests/test_strata_live_optional.py -s

It performs the same read-only 1-row firewall_traffic query that "Enable" runs.
"""

from __future__ import annotations

import os

import pytest

from app.integrations.config import StrataLoggingConfig, normalize_sls_query_host
from app.integrations.providers.strata_logging import StrataLoggingProvider

_REQUIRED = ("NODEWATCH_LIVE_PA_CLIENT_ID", "NODEWATCH_LIVE_PA_CLIENT_SECRET", "NODEWATCH_LIVE_PA_TSG_ID")

pytestmark = pytest.mark.skipif(
    not all(os.environ.get(name) for name in _REQUIRED),
    reason="live Palo Alto credentials not provided",
)


def test_live_logviewer_traffic_query():
    config = StrataLoggingConfig(
        enabled=True,
        verified=True,
        query_host=normalize_sls_query_host(os.environ.get("NODEWATCH_LIVE_SLS_QUERY_HOST", "")),
        tenant_header=os.environ.get("NODEWATCH_LIVE_SLS_TENANT", ""),
    )
    provider = StrataLoggingProvider(
        config=config,
        credentials={
            "client_id": os.environ["NODEWATCH_LIVE_PA_CLIENT_ID"],
            "client_secret": os.environ["NODEWATCH_LIVE_PA_CLIENT_SECRET"],
            "tsg_id": os.environ["NODEWATCH_LIVE_PA_TSG_ID"],
        },
    )
    result = provider.test_connection()
    print("Live Log Viewer query OK:", {k: result[k] for k in ("api_host", "sample_count")})
    assert result["ok"] is True
