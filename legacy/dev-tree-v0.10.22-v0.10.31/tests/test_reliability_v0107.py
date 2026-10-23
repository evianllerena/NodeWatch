"""Reliability tests for the Mist client, alerting and event handling (v0.10.7)."""

from __future__ import annotations

import http.client
import io
import json
from urllib.parse import parse_qs, urlsplit

import pytest

from app.core.config import Settings
from app.services import alerting_service, mist_client as mc
from app.services.condition_explainer import explain_condition
from app.services.event_correlation import correlate_event_states, event_timestamp

ORG = "22222222-2222-2222-2222-222222222222"
SITE = "11111111-1111-1111-1111-111111111111"


class FakeHTTPResponse(io.BytesIO):
    def __init__(self, payload, headers=None, status=200):
        super().__init__(json.dumps(payload).encode())
        self.status = status
        self.headers = http.client.HTTPMessage()
        for k, v in (headers or {}).items():
            self.headers[k] = str(v)

    def getcode(self):
        return self.status

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


@pytest.fixture
def client():
    return mc.MistClient(Settings(org_id=ORG, token="tok", api_host="https://api.mist.com"))


def install(monkeypatch, handler):
    calls = []

    def fake_urlopen(req, timeout=None, context=None):
        calls.append(req.full_url)
        return handler(req.full_url)

    monkeypatch.setattr(mc, "urlopen", fake_urlopen)
    return calls


# ------------------------------------------------------------------- IDs in paths


@pytest.mark.parametrize("bad", ["../../orgs", "all", "", "11111111-1111-1111-1111-11111111111/x"])
def test_invalid_ids_rejected_before_any_request(monkeypatch, client, bad):
    calls = install(monkeypatch, lambda url: FakeHTTPResponse({}))
    with pytest.raises(mc.MistApiError) as err:
        client.get_site_device(bad, "00000000-0000-0000-1000-aabbccddeeff")
    assert err.value.status_code == 400
    assert calls == []


def test_invalid_client_mac_rejected(monkeypatch, client):
    install(monkeypatch, lambda url: FakeHTTPResponse({}))
    with pytest.raises(mc.MistApiError):
        client.get_site_client_stats(SITE, "not-a-mac/../x")


# --------------------------------------------------------------- network errors


@pytest.mark.parametrize(
    "exc",
    [
        TimeoutError("read timed out"),
        ConnectionResetError("reset"),
        http.client.RemoteDisconnected("gone"),
        OSError("network down"),
    ],
)
def test_transport_failures_become_mist_errors(monkeypatch, client, exc):
    def boom(url):
        raise exc

    install(monkeypatch, boom)
    with pytest.raises(mc.MistApiError):
        client.get_org()


# ------------------------------------------------------------------- pagination


def test_list_endpoint_reads_every_page(monkeypatch, client):
    total = 2500

    def handler(url):
        q = parse_qs(urlsplit(url).query)
        page, limit = int(q["page"][0]), int(q["limit"][0])
        start = (page - 1) * limit
        rows = [{"id": f"site-{i}"} for i in range(start, min(start + limit, total))]
        return FakeHTTPResponse(rows, {"X-Page-Total": total, "X-Page-Limit": limit, "X-Page-Page": page})

    calls = install(monkeypatch, handler)
    sites = client.list_sites()
    assert len(sites) == 2500 and sites[-1]["id"] == "site-2499"
    assert len(calls) == 3


def test_search_follows_next_until_limit(monkeypatch, client):
    path = f"/api/v1/orgs/{ORG}/alarms/search"

    def handler(url):
        q = parse_qs(urlsplit(url).query)
        after = int(q.get("search_after", ["0"])[0])
        rows = [{"id": n} for n in range(after, after + 1000)]
        nxt = f"{path}?duration=30d&limit=1000&search_after={after + 1000}" if after < 2000 else None
        return FakeHTTPResponse({"results": rows, "next": nxt})

    install(monkeypatch, handler)
    alarms = client.search_org_alarms(fresh=True)
    assert len(alarms) == 3000


def test_search_never_follows_foreign_next(monkeypatch, client):
    def handler(url):
        assert "evil.example.com" not in url
        return FakeHTTPResponse({"results": [{"id": 1}] * 1000, "next": "https://evil.example.com/api/v1/x"})

    calls = install(monkeypatch, handler)
    assert len(client.search_org_alarms(fresh=True)) == 1000
    assert len(calls) == 1


def test_small_search_limit_is_respected(monkeypatch, client):
    def handler(url):
        q = parse_qs(urlsplit(url).query)
        assert q["limit"] == ["50"]
        return FakeHTTPResponse({"results": [{"mac": str(i)} for i in range(50)], "next": "/x"})

    install(monkeypatch, handler)
    assert len(client.search_org_wireless_clients(text="phone")) == 50


# ------------------------------------------------------------------------ cache


def test_cache_is_bounded(monkeypatch, client):
    install(monkeypatch, lambda url: FakeHTTPResponse({"ok": True}))
    for i in range(mc._CACHE_MAX_ENTRIES + 50):
        client.get(f"/api/v1/orgs/{ORG}/thing", {"n": i})
    assert len(client._cache) == mc._CACHE_MAX_ENTRIES


def test_cache_hit_returns_payload(monkeypatch, client):
    calls = install(monkeypatch, lambda url: FakeHTTPResponse({"name": "org"}))
    assert client.get_org() == {"name": "org"}
    assert client.get_org() == {"name": "org"}
    assert len(calls) == 1


# --------------------------------------------------------------------- alerting


@pytest.fixture
def alerting(monkeypatch):
    state = {}
    monkeypatch.setattr(
        alerting_service, "_load", lambda path, default: json.loads(json.dumps(state.get(str(path), default)))
    )
    monkeypatch.setattr(
        alerting_service, "_save", lambda path, data: state.__setitem__(str(path), json.loads(json.dumps(data)))
    )
    monkeypatch.setattr(
        alerting_service,
        "_settings",
        lambda: {"enabled": True, "webhook_enabled": True, "cooldown_seconds": 1800, "status": "ok"},
    )
    sent = []
    feed = {"value": {"notification_alerts": [], "errors": []}}
    monkeypatch.setattr(alerting_service, "build_alert_feed", lambda fresh=False: feed["value"])
    monkeypatch.setattr(alerting_service, "_send_webhook", lambda alert, cfg: sent.append(alert["id"]))
    return state, sent, feed


def alerts(*ids):
    return [{"id": i, "kind": "device_disconnect"} for i in ids]


def test_failed_poll_keeps_active_alerts(alerting):
    state, sent, feed = alerting
    feed["value"] = {"notification_alerts": alerts("a"), "errors": []}
    alerting_service.poll_and_notify()  # baseline
    feed["value"] = {"notification_alerts": alerts("a", "b"), "errors": []}
    alerting_service.poll_and_notify()
    assert sent == ["b"]
    feed["value"] = {"notification_alerts": [], "errors": ["inventory: Mist API HTTP 503"]}
    result = alerting_service.poll_and_notify()
    assert result["ok"] is False
    feed["value"] = {"notification_alerts": alerts("a", "b"), "errors": []}
    alerting_service.poll_and_notify()
    assert sent == ["b"], "alerts must not be re-sent after a failed poll"


def test_webhook_failure_mid_loop_does_not_resend_delivered(alerting, monkeypatch):
    state, sent, feed = alerting
    feed["value"] = {"notification_alerts": [], "errors": []}
    alerting_service.poll_and_notify()  # baseline

    def flaky(alert, cfg):
        if alert["id"] == "c":
            raise RuntimeError("webhook down")
        sent.append(alert["id"])

    monkeypatch.setattr(alerting_service, "_send_webhook", flaky)
    feed["value"] = {"notification_alerts": alerts("a", "b", "c"), "errors": []}
    with pytest.raises(RuntimeError):
        alerting_service.poll_and_notify()
    assert sent == ["a", "b"]
    monkeypatch.setattr(alerting_service, "_send_webhook", lambda alert, cfg: sent.append(alert["id"]))
    alerting_service.poll_and_notify()
    assert sent == ["a", "b", "c"]


def test_cooldown_default_is_consistent():
    assert alerting_service.DEFAULT_COOLDOWN_SECONDS == 1800


# ------------------------------------------------------------- events/explainer


def test_event_timestamps_accept_iso_ms_and_seconds():
    assert event_timestamp({"timestamp": "2026-10-08T00:00:00Z"}) == 1791417600.0
    assert event_timestamp({"timestamp": 1791417600000}) == 1791417600.0
    assert event_timestamp({"time": 1791417600}) == 1791417600.0
    assert event_timestamp({}) == 0.0


def test_correlation_with_iso_timestamps_does_not_crash():
    events = [
        {"type": "SW_PORT_DOWN", "mac": "aa", "port_id": "ge-0/0/1", "timestamp": "2026-10-08T00:00:00Z"},
        {"type": "SW_PORT_UP", "mac": "aa", "port_id": "ge-0/0/1", "timestamp": "2026-10-08T00:01:00Z"},
        {"type": "SW_PORT_UP", "mac": "bb", "port_id": "ge-0/0/2", "timestamp": 1791417500},
    ]
    open_rows, states = correlate_event_states(events)
    assert open_rows == []
    clears = [r for r in states if r["_state"] == "cleared"]
    assert {r["mac"]: r["_matched_trigger"] for r in clears} == {"aa": True, "bb": False}


@pytest.mark.parametrize("kind", ["AP_CURRENTLY_DOWN", "SWITCH_CURRENTLY_DOWN", "GATEWAY_CURRENTLY_DOWN"])
def test_currently_down_items_get_connectivity_explanation(kind):
    result = explain_condition({"type": kind}, {}, site="HQ", device="sw1")
    assert result["headline"] == "Infrastructure connectivity lost"


def test_unconfigured_client_reports_not_configured_not_bad_org_id():
    unconfigured = mc.MistClient(Settings(org_id="", token="", api_host="https://api.mist.com"))
    with pytest.raises(mc.MistApiError) as err:
        unconfigured.list_sites()
    assert err.value.status_code == 409 and "not configured" in str(err.value)
