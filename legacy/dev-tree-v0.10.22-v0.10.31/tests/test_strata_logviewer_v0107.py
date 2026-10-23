"""Behavioural tests for Traffic & Sessions on the SCM Log Viewer API (v0.10.7).

The fake HTTP layer below answers with the response shape captured from a real
Strata Cloud Manager Log Viewer request (values replaced with test data), so these
tests check what NodeWatch sends and how it reads the real format. They do not
prove Palo Alto's live behaviour; ``test_strata_live_optional.py`` does that when
credentials are supplied.
"""

from __future__ import annotations

import io
import json
import time
from email.message import Message
from urllib.error import HTTPError

import pytest
from fastapi.testclient import TestClient

from app.core.security import WRITE_REQUEST_TOKEN
from app.integrations import config as int_config
from app.integrations.base import IntegrationError
from app.integrations.cache import CACHE
from app.integrations.config import StrataLoggingConfig, normalize_sls_query_host
from app.integrations.providers import strata_logging as sls
from app.integrations.query import NodeWatchQuery, QueryFilter, QUERY_ENGINE
from app.integrations.resilience import RetryPolicy, execute_resilient

TOKEN_URL = "https://auth.apps.paloaltonetworks.com/oauth2/access_token"
LOGVIEWER_URL = "https://pa-us01.api.prismaaccess.com/api/sase/v3.0/resource/query/logviewer/firewall_traffic"
CREDS = {"client_id": "svc@123.iam.panserviceaccount.com", "client_secret": "s3cret-value", "tsg_id": "1234567890"}


def logviewer_row(seq: int, src: str, dst: str, t_us: int, **extra):
    row = {
        "source_ip": {"value": src, "hex": "00"},
        "dest_ip": {"value": dst, "hex": "00"},
        "dest_port": 443,
        "source_port": 50000 + seq,
        "app": "ssl",
        "from_zone": "Trusted",
        "to_zone": "Untrust",
        "rule_matched": "Allow-Web",
        "action": {"id": 0, "value": "allow"},
        "protocol": {"id": 6, "value": "tcp"},
        "session_end_reason": {"id": 6, "value": "tcp-fin"},
        "log_source_name": "PA-TEST1",
        "log_source_id": "000000000001",
        "time_generated": t_us,
        "bytes_total": 1000 + seq,
        "bytes_sent": 600,
        "bytes_received": 400 + seq,
        "packets_total": 10,
        "session_id": 9000 + seq,
        "total_time_elapsed": 3,
        "risk_of_app": 2,
        "app_category": "networking",
        "url_category": {"id": 1, "value": "any"},
        "inbound_if": {"value": "ae1.10", "hex": 1},
        "sequence_no": seq,
    }
    row.update(extra)
    return row


def logviewer_payload(rows):
    return {
        "header": {"dataCount": len(rows), "status": {"subCode": 200}, "name": "logviewer/firewall_traffic"},
        "data": rows,
    }


class FakeResponse(io.BytesIO):
    def __init__(self, payload, status=200):
        super().__init__(json.dumps(payload).encode())
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class FakeOpener:
    def __init__(self, handler):
        self.handler = handler
        self.calls = []

    def open(self, req, timeout=None):
        body = json.loads(req.data.decode()) if req.data and req.full_url != TOKEN_URL else None
        headers = {k.lower(): v for k, v in req.header_items()}
        self.calls.append({"url": req.full_url, "method": req.get_method(), "headers": headers, "body": body})
        if req.full_url == TOKEN_URL:
            return FakeResponse({"access_token": "tok-123", "expires_in": 899})
        return self.handler(req.full_url, body, headers)


def http_error(url, code, payload):
    return HTTPError(url, code, "error", Message(), io.BytesIO(json.dumps(payload).encode()))


def make_provider(handler, **cfg):
    config = StrataLoggingConfig(enabled=True, verified=True, **cfg)
    opener = FakeOpener(handler)
    return sls.StrataLoggingProvider(config=config, credentials=dict(CREDS), opener=opener), opener


def logviewer_calls(opener):
    return [c for c in opener.calls if c["url"] != TOKEN_URL]


@pytest.fixture(autouse=True)
def _clean_state():
    from app.integrations.auth import TOKEN_MANAGER

    TOKEN_MANAGER.clear()
    CACHE.invalidate("")
    yield
    TOKEN_MANAGER.clear()
    CACHE.invalidate("")


# --------------------------------------------------------------------- request


def test_test_connection_posts_logviewer_query_with_bearer_and_tenant():
    provider, opener = make_provider(
        lambda url, body, h: FakeResponse(
            logviewer_payload([logviewer_row(1, "10.0.0.5", "8.8.8.8", 1791506714000000)])
        )
    )
    result = provider.test_connection()

    assert result["ok"] is True and result["sample_count"] == 1
    calls = logviewer_calls(opener)
    assert len(calls) == 1
    call = calls[0]
    assert call["url"] == LOGVIEWER_URL
    assert call["method"] == "POST"
    assert call["headers"]["authorization"] == "Bearer tok-123"
    assert call["headers"]["prisma-tenant"] == CREDS["tsg_id"]
    rules = call["body"]["filter"]["rules"]
    assert rules[0]["property"] == "event_time" and rules[0]["operator"] == "between"
    start_us, end_us = rules[0]["values"]
    assert end_us - start_us == 15 * 60 * 1_000_000  # microseconds, 15 minute probe
    assert call["body"]["pagination"] == {"page_size": 1, "page_number": 1}
    assert call["body"]["orderBy"]["properties"][0]["property"] == "time_generated"
    # The retired API must never be called again.
    assert all("logging-service" not in c["url"] and "api.strata" not in c["url"] for c in opener.calls)


def test_tenant_override_and_regional_host_are_used():
    provider, opener = make_provider(
        lambda url, body, h: FakeResponse(logviewer_payload([])),
        query_host="https://pa-eu01.api.prismaaccess.com",
        tenant_header="1234567890:555",
    )
    provider.test_connection()
    call = logviewer_calls(opener)[0]
    assert call["url"].startswith("https://pa-eu01.api.prismaaccess.com/api/sase/v3.0/resource/query/logviewer/")
    assert call["headers"]["prisma-tenant"] == "1234567890:555"


def test_ip_lookup_queries_source_and_destination_then_merges_newest_first():
    rows_src = [
        logviewer_row(1, "10.0.0.5", "8.8.8.8", 1_000_000_000_000_100),
        logviewer_row(2, "10.0.0.5", "1.1.1.1", 1_000_000_000_000_300),
    ]
    rows_dst = [
        logviewer_row(2, "10.0.0.5", "1.1.1.1", 1_000_000_000_000_300),
        logviewer_row(3, "9.9.9.9", "10.0.0.5", 1_000_000_000_000_200),
    ]

    def handler(url, body, headers):
        rule = body["filter"]["rules"][1]
        assert rule["operator"] == "ip_match_cidr" and rule["values"] == ["10.0.0.5/32"]
        return FakeResponse(logviewer_payload(rows_src if rule["property"] == "source_ip.value" else rows_dst))

    provider, opener = make_provider(handler)
    query = NodeWatchQuery(
        event_type="network.session",
        capability="traffic.sessions",
        filters=(QueryFilter("source_or_destination.ip", "eq", "10.0.0.5"),),
        start_time="2026-10-08T00:00:00+00:00",
        end_time="2026-10-08T01:00:00+00:00",
        page_size=100,
    )
    result = provider.query(query)

    props = sorted(c["body"]["filter"]["rules"][1]["property"] for c in logviewer_calls(opener))
    assert props == ["dest_ip.value", "source_ip.value"]
    sessions = [r.data["traffic"] for r in result.records]
    assert [s["session_id"] for s in sessions] == [9002, 9003, 9001]  # deduplicated, newest first
    first = sessions[0]
    assert first["action"] == "allow" and first["protocol"] == "tcp"
    assert first["destination_port"] == 443 and first["bytes_total"] == 1002
    assert first["source"] == "10.0.0.5" and first["destination"] == "1.1.1.1"
    assert first["inbound_interface"] == "ae1.10" and first["elapsed_time"] == 3
    assert first["receive_time"].startswith("2001-09-09")  # microsecond epoch converted correctly
    assert result.has_more is False and result.next_cursor is None


def test_ipv6_uses_128_prefix():
    seen = []

    def handler(url, body, headers):
        seen.append(body["filter"]["rules"][1]["values"][0])
        return FakeResponse(logviewer_payload([]))

    provider, _ = make_provider(handler)
    provider.query(
        NodeWatchQuery(
            "network.session",
            "traffic.sessions",
            filters=(QueryFilter("source_or_destination.ip", "eq", "2001:db8::1"),),
        )
    )
    assert seen == ["2001:db8::1/128", "2001:db8::1/128"]


def test_pagination_cursor_requests_next_page_and_is_bound_to_query():
    pages = []

    def handler(url, body, headers):
        pages.append(body["pagination"]["page_number"])
        size = body["pagination"]["page_size"]
        return FakeResponse(logviewer_payload([logviewer_row(i, "10.0.0.5", "8.8.8.8", 1000 + i) for i in range(size)]))

    provider, _ = make_provider(handler)
    base = dict(
        event_type="network.session",
        capability="traffic.sessions",
        start_time="2026-10-08T00:00:00+00:00",
        end_time="2026-10-08T01:00:00+00:00",
        page_size=2,
    )
    first = provider.query(NodeWatchQuery(**base))
    assert first.has_more and first.next_cursor
    provider.query(NodeWatchQuery(**base, cursor=first.next_cursor))
    assert pages == [1, 2]
    other = provider.query(NodeWatchQuery(**base))
    with pytest.raises(IntegrationError) as err:
        provider.query(NodeWatchQuery(**{**base, "page_size": 3}, cursor=other.next_cursor))
    assert err.value.code == "INVALID_CURSOR"


def test_unverified_provider_refuses_to_query():
    provider = sls.StrataLoggingProvider(
        config=StrataLoggingConfig(enabled=True, verified=False), credentials=dict(CREDS), opener=FakeOpener(None)
    )
    with pytest.raises(IntegrationError) as err:
        provider.query(NodeWatchQuery("network.session", "traffic.sessions"))
    assert err.value.code == "SLS_NOT_CONFIGURED"


# ---------------------------------------------------------------------- errors


def test_403_reports_host_tenant_and_provider_detail_without_guessing_a_role():
    def handler(url, body, headers):
        raise http_error(url, 403, {"msg": "Access denied"})

    provider, _ = make_provider(handler)
    with pytest.raises(IntegrationError) as err:
        provider.test_connection()
    message = str(err.value)
    assert err.value.code == "SLS_PERMISSION_DENIED"
    assert "pa-us01.api.prismaaccess.com" in message
    assert CREDS["tsg_id"] in message
    assert "Provider response: Access denied" in message
    assert "SOC Analyst" not in message
    assert "tok-123" not in message


def test_401_refreshes_token_once():
    attempts = []

    def handler(url, body, headers):
        attempts.append(headers["authorization"])
        if len(attempts) == 1:
            raise http_error(url, 401, {"error": "expired"})
        return FakeResponse(logviewer_payload([]))

    provider, opener = make_provider(handler)
    provider.test_connection()
    assert len(attempts) == 2
    assert sum(1 for c in opener.calls if c["url"] == TOKEN_URL) >= 2


def test_logviewer_body_status_error_is_raised():
    provider, _ = make_provider(
        lambda url, body, h: FakeResponse({"header": {"status": {"subCode": 400, "message": "bad filter"}}, "data": []})
    )
    with pytest.raises(IntegrationError) as err:
        provider.test_connection()
    assert err.value.code == "SLS_QUERY_INVALID" and "bad filter" in str(err.value)


@pytest.mark.parametrize(
    "value,expected",
    [
        ("", "https://pa-us01.api.prismaaccess.com"),
        ("pa-eu01.api.prismaaccess.com", "https://pa-eu01.api.prismaaccess.com"),
        ("https://PA-US01.api.prismaaccess.com/", "https://pa-us01.api.prismaaccess.com"),
        ("https://evil.example.com", ""),
        ("https://pa-us01.api.prismaaccess.com.evil.com", ""),
        ("http://pa-us01.api.prismaaccess.com", ""),
        ("https://user:pw@pa-us01.api.prismaaccess.com", ""),
        ("https://pa-us01.api.prismaaccess.com/other/path", ""),
        ("https://pa-us01.api.prismaaccess.com:8443", ""),
    ],
)
def test_query_host_allow_list(value, expected):
    assert normalize_sls_query_host(value) == expected


def test_invalid_tenant_override_rejected():
    assert StrataLoggingConfig(tenant_header="abc").validate()
    assert not StrataLoggingConfig(tenant_header="1844525482:572447260").validate()


# ------------------------------------------------------------------ resilience


def test_slow_successful_operation_is_returned_not_retried():
    calls = []

    def slow():
        calls.append(1)
        time.sleep(0.05)
        return "result"

    assert execute_resilient("qa_slow", slow, retry=RetryPolicy(attempts=3, timeout_budget_seconds=0.01)) == "result"
    assert len(calls) == 1


def test_retry_stops_when_budget_spent():
    calls = []

    def failing():
        calls.append(1)
        raise IntegrationError("down", code="SLS_QUERY_UNAVAILABLE")

    with pytest.raises(IntegrationError):
        execute_resilient(
            "qa_budget", failing, retry=RetryPolicy(attempts=5, base_delay_seconds=0.2, timeout_budget_seconds=0.1)
        )
    assert len(calls) == 1


def test_provider_retry_budget_exceeds_query_timeout():
    provider, _ = make_provider(lambda *a: FakeResponse(logviewer_payload([])), query_timeout=45, request_timeout=30)
    assert provider.retry_policy().timeout_budget_seconds > 45


# ------------------------------------------------------- endpoints + persistence


@pytest.fixture
def client(monkeypatch):
    from app.main import app
    from app.modules.integrations import router as int_router

    state = {
        "handler": lambda url, body, h: FakeResponse(logviewer_payload([logviewer_row(1, "10.0.0.5", "8.8.8.8", 1)]))
    }
    monkeypatch.setattr(int_config, "get_palo_alto_credentials", lambda: dict(CREDS))
    monkeypatch.setattr(sls, "get_strata_logging_credentials", lambda: dict(CREDS))
    monkeypatch.setattr(int_router, "get_strata_logging_credentials", lambda: dict(CREDS))

    real_init = sls.StrataLoggingProvider.__init__

    def init(self, config=None, credentials=None, *, opener=None):
        real_init(self, config, credentials, opener=opener or FakeOpener(lambda *a: state["handler"](*a)))

    monkeypatch.setattr(sls.StrataLoggingProvider, "__init__", init)
    int_config.reset_strata_logging_config()
    sls.get_strata_logging_provider(reset=True)
    c = TestClient(app, base_url="http://127.0.0.1")
    c.headers.update({"X-NodeWatch-Request": WRITE_REQUEST_TOKEN})
    c.state = state
    yield c
    int_config.reset_strata_logging_config()
    sls.get_strata_logging_provider(reset=True)


def test_enable_failure_persists_nothing(client):
    client.state["handler"] = lambda url, body, h: (_ for _ in ()).throw(http_error(url, 403, {"msg": "Access denied"}))
    r = client.post("/api/integrations/strata-logging/enable", json={"enabled": True})
    assert r.status_code == 403
    assert "Integration was not enabled" in r.json()["detail"]
    cfg = int_config.get_strata_logging_config()
    assert cfg.enabled is False and cfg.verified is False


def test_enable_success_persists_verified_with_host(client):
    r = client.post(
        "/api/integrations/strata-logging/enable",
        json={"enabled": True, "query_host": "pa-eu01.api.prismaaccess.com", "tenant_header": ""},
    )
    assert r.status_code == 200, r.text
    assert r.json()["sample_count"] == 1
    cfg = int_config.get_strata_logging_config()
    assert cfg.enabled and cfg.verified and cfg.verified_at
    assert cfg.query_host == "https://pa-eu01.api.prismaaccess.com"
    state = client.get("/api/integrations").json()["strata_logging_service"]
    assert state["status"] == "connected" and state["query_host"] == "https://pa-eu01.api.prismaaccess.com"


def test_enable_rejects_unapproved_host(client):
    r = client.post(
        "/api/integrations/strata-logging/enable", json={"enabled": True, "query_host": "https://evil.example.com"}
    )
    assert r.status_code == 400
    assert int_config.get_strata_logging_config().enabled is False


def test_verify_while_disabled_is_remembered(client):
    r = client.post("/api/integrations/strata-logging/test", json={"enabled": False})
    assert r.status_code == 200, r.text
    state = client.get("/api/integrations").json()["strata_logging_service"]
    assert state["enabled"] is False and state["verified"] is True
    assert state["status_label"] == "Verified · Disabled"


def test_disable_clears_cached_traffic(client):
    client.post("/api/integrations/strata-logging/enable", json={"enabled": True})
    CACHE.put("query:abc", "cached-result", ttl_seconds=60)
    client.post("/api/integrations/strata-logging/enable", json={"enabled": False})
    assert CACHE.get("query:abc") is None


def test_query_engine_will_not_use_unverified_provider_even_when_named(client):
    with pytest.raises(IntegrationError) as err:
        QUERY_ENGINE.execute(
            NodeWatchQuery("network.session", "traffic.sessions"), provider_id="strata_logging_service"
        )
    assert err.value.code == "CAPABILITY_UNAVAILABLE"


def test_config_saved_by_older_version_requires_reverification(client):
    int_config.INTEGRATIONS_FILE.write_text(
        json.dumps(
            {
                "strata_logging_service": {
                    "config_version": 3,
                    "enabled": True,
                    "verified": True,
                    "verified_at": "2026-10-01T00:00:00+00:00",
                }
            }
        )
    )
    cfg = int_config.get_strata_logging_config()
    assert cfg.enabled is True and cfg.verified is False
    assert cfg.query_host == "https://pa-us01.api.prismaaccess.com"


def test_ui_traffic_endpoint_returns_sessions(client, monkeypatch):
    client.post("/api/integrations/strata-logging/enable", json={"enabled": True})
    from app.integrations.providers.traffic import get_traffic_sessions_provider

    data = get_traffic_sessions_provider().search_by_ip("10.0.0.5", window="1h", limit=50, fresh=True)
    assert data["available"] is True and data["count"] == 1
    assert data["sessions"][0]["action"] == "allow"


def test_diagnostics_trace_never_contains_token_or_secret(client):
    from app.integrations.diagnostics import _TIMING_LOG

    client.state["handler"] = lambda url, body, h: (_ for _ in ()).throw(http_error(url, 403, {"msg": "Access denied"}))
    client.post("/api/integrations/strata-logging/enable", json={"enabled": True})
    client.state["handler"] = lambda url, body, h: FakeResponse(logviewer_payload([]))
    client.post("/api/integrations/strata-logging/enable", json={"enabled": True})
    trace = _TIMING_LOG.read_text(encoding="utf-8")
    assert "SLS_QUERY_HTTP_403" in trace and "SLS_VERIFICATION_SAVED" in trace
    assert "pa-us01.api.prismaaccess.com" in trace  # host is recorded for troubleshooting
    for secret in ("tok-123", CREDS["client_secret"], "Bearer "):
        assert secret not in trace


# ------------------------------------------------------- review regressions (v0.10.7)


def _paged_handler(pages_seen, fail_once_on_page=None):
    state = {"failed": False}

    def handler(url, body, headers):
        page = body["pagination"]["page_number"]
        pages_seen.append((page, body["filter"]["rules"][0]["values"]))
        if page == fail_once_on_page and not state["failed"]:
            state["failed"] = True
            raise http_error(url, 503, {"msg": "busy"})
        size = body["pagination"]["page_size"]
        return FakeResponse(
            logviewer_payload([logviewer_row(page * 100 + i, "10.0.0.5", "8.8.8.8", 1000 + i) for i in range(size)])
        )

    return handler


def test_cursor_survives_a_failed_page_request():
    seen = []
    provider, _ = make_provider(_paged_handler(seen, fail_once_on_page=2))
    base = dict(
        event_type="network.session",
        capability="traffic.sessions",
        start_time="2026-10-08T00:00:00+00:00",
        end_time="2026-10-08T01:00:00+00:00",
        page_size=2,
    )
    first = provider.query(NodeWatchQuery(**base))
    with pytest.raises(IntegrationError) as err:
        provider.query(NodeWatchQuery(**base, cursor=first.next_cursor))
    assert err.value.code == "SLS_QUERY_UNAVAILABLE"
    retry = provider.query(NodeWatchQuery(**base, cursor=first.next_cursor))  # same cursor still valid
    assert retry.retrieved_count == 2


def test_cursor_keeps_original_time_range_when_window_moves():
    seen = []
    provider, _ = make_provider(_paged_handler(seen))
    q1 = dict(
        event_type="network.session",
        capability="traffic.sessions",
        start_time="2026-10-08T00:00:00+00:00",
        end_time="2026-10-08T01:00:00+00:00",
        page_size=2,
    )
    first = provider.query(NodeWatchQuery(**q1))
    moved = {**q1, "start_time": "2026-10-08T00:00:30+00:00", "end_time": "2026-10-08T01:00:30+00:00"}
    provider.query(NodeWatchQuery(**moved, cursor=first.next_cursor))
    assert seen[0][1] == seen[1][1], "page 2 must use the same time range as page 1"


def test_log_query_uses_query_timeout():
    timeouts = []

    class TimeoutOpener(FakeOpener):
        def open(self, req, timeout=None):
            if req.full_url != TOKEN_URL:
                timeouts.append(timeout)
            return super().open(req, timeout)

    config = StrataLoggingConfig(enabled=True, verified=True, request_timeout=30, query_timeout=90)
    provider = sls.StrataLoggingProvider(
        config=config, credentials=dict(CREDS), opener=TimeoutOpener(lambda *a: FakeResponse(logviewer_payload([])))
    )
    provider.test_connection()
    assert timeouts == [90]


def test_disable_works_without_credentials_and_bad_tenant_is_400(client, monkeypatch):
    from app.modules.integrations import router as int_router

    client.post("/api/integrations/strata-logging/enable", json={"enabled": True})
    monkeypatch.setattr(
        int_router, "get_strata_logging_credentials", lambda: {"client_id": "", "client_secret": "", "tsg_id": ""}
    )
    r = client.post("/api/integrations/strata-logging/enable", json={"enabled": False})
    assert r.status_code == 200, r.text
    assert int_config.get_strata_logging_config().enabled is False
    r = client.post("/api/integrations/strata-logging/enable", json={"enabled": False, "tenant_header": "abc"})
    assert r.status_code == 400


def test_palo_alto_reset_refreshes_traffic_provider(client, monkeypatch):
    client.post("/api/integrations/strata-logging/enable", json={"enabled": True})
    before = sls.get_strata_logging_provider()
    CACHE.put("query:x", "cached", ttl_seconds=60)
    monkeypatch.setattr("app.modules.integrations.router.reset_palo_alto_config", lambda: None)
    assert client.post("/api/integrations/palo-alto-device-security/reset").status_code == 200
    assert sls.get_strata_logging_provider() is not before
    assert CACHE.get("query:x") is None


def test_merge_sort_handles_wrapped_timestamps():
    rows_src = [
        logviewer_row(1, "10.0.0.5", "8.8.8.8", {"value": 100}),
        logviewer_row(2, "10.0.0.5", "8.8.8.8", {"value": 300}),
    ]

    def handler(url, body, headers):
        return FakeResponse(
            logviewer_payload(rows_src if body["filter"]["rules"][1]["property"] == "source_ip.value" else [])
        )

    provider, _ = make_provider(handler)
    result = provider.query(
        NodeWatchQuery(
            "network.session", "traffic.sessions", filters=(QueryFilter("source_or_destination.ip", "eq", "10.0.0.5"),)
        )
    )
    assert [r.data["traffic"]["session_id"] for r in result.records] == [9002, 9001]


def test_old_default_query_timeout_is_upgraded():
    int_config.INTEGRATIONS_FILE.write_text(
        json.dumps({"strata_logging_service": {"config_version": 4, "query_timeout": 45}})
    )
    assert int_config.get_strata_logging_config().query_timeout == 90
    int_config.INTEGRATIONS_FILE.write_text(
        json.dumps({"strata_logging_service": {"config_version": 4, "query_timeout": 120}})
    )
    assert int_config.get_strata_logging_config().query_timeout == 120
    int_config.INTEGRATIONS_FILE.unlink()
