"""v0.10.12: Device Finder completeness/IP-prefix search, curated details, strict PA test.

Mist and Palo Alto are replaced with in-process fakes; these tests prove what
NodeWatch asks for and how it filters/presents the answers, not live API behaviour.
"""

from __future__ import annotations

import io
import json
from email.message import Message
from urllib.error import HTTPError

import pytest

from app.integrations.auth import TOKEN_MANAGER
from app.integrations.base import IntegrationError
from app.integrations.config import PaloAltoDeviceSecurityConfig
from app.integrations.providers import palo_alto_device_security as pa
from app.services import detective_service as ds

SITE = "11111111-2222-4333-8444-555555555555"
OTHER_SITE = "99999999-2222-4333-8444-555555555555"


# ----------------------------------------------------------------- fake Mist


class FakeMist:
    configured = True

    def __init__(self, wireless=(), wired=(), inventory=(), nac=()):
        self.data = {"wireless": list(wireless), "wired": list(wired), "inventory": list(inventory), "nac": list(nac)}
        self.calls: list[tuple[str, dict]] = []

    def list_sites(self):
        return [{"id": SITE, "name": "Kendall"}, {"id": OTHER_SITE, "name": "Other"}]

    def _rows(self, source, kw):
        self.calls.append((source, dict(kw)))
        rows = self.data[source]
        if kw.get("site_id"):
            rows = [r for r in rows if r.get("site_id") == kw["site_id"]]
        ip = kw.get("ip")
        if ip:
            # Behave like a loose provider filter: honour a trailing wildcard but also
            # leak one non-matching row, so the local guard is exercised.
            if ip.endswith("*"):
                matched = [r for r in rows if any(str(x).startswith(ip[:-1]) for x in _ips(r))]
                leak = [r for r in rows if r not in matched][:1]
                rows = matched + leak
            else:
                rows = [r for r in rows if ip in _ips(r)]
        text = kw.get("text")
        if text:
            needle = text.rstrip("*").lower()
            prefix = text.endswith("*")
            rows = [
                r
                for r in rows
                if any(
                    (
                        str(r.get(k) or "").lower().startswith(needle)
                        if prefix
                        else str(r.get(k) or "").lower() == needle
                    )
                    for k in ("hostname", "username", "name", "mac")
                )
            ]
        if kw.get("mac"):
            rows = [r for r in rows if r.get("mac") == kw["mac"]]
        return rows[: kw.get("limit", 50)]

    def search_org_wireless_clients(self, **kw):
        return self._rows("wireless", kw)

    def search_org_wired_clients(self, **kw):
        return self._rows("wired", kw)

    def search_org_inventory(self, **kw):
        return self._rows("inventory", kw)

    def search_org_nac_clients(self, **kw):
        return self._rows("nac", kw)


def _ips(row):
    ip = row.get("ip")
    return ip if isinstance(ip, list) else [ip]


def _mac(n: int, prefix: str = "02") -> str:
    return f"{prefix}{n:010x}"


@pytest.fixture
def use_mist(monkeypatch):
    def install(fake):
        monkeypatch.setattr(ds, "get_mist_client", lambda: fake)
        return fake

    return install


# ------------------------------------------------------------ query typing


@pytest.mark.parametrize(
    "query, kind",
    [
        ("10.7", "ip_prefix"),
        ("10.7.", "ip_prefix"),
        ("10.7.12", "ip_prefix"),
        ("10.", "ip_prefix"),
        ("10.7.12.5", "ip"),
        ("10", "text"),
        ("1234", "text"),
        ("10.700", "text"),
        ("kendall-ap", "text"),
        ("aa:bb:cc:dd:ee:ff", "mac"),
    ],
)
def test_query_kind_detects_partial_ipv4(query, kind):
    assert ds._query_kind(query)[0] == kind


def test_ip_prefix_matches_any_ip_in_a_list():
    assert ds._matches_ip_prefix({"ip": ["192.168.1.5", "10.7.3.4"]}, "10.7")
    assert ds._matches_ip_prefix({"device_mac_port": [{"ip": "10.7.9.9"}]}, "10.7.")
    assert not ds._matches_ip_prefix({"ip": "10.8.1.1"}, "10.7")


# ------------------------------------------------------- site IP prefix: 706


def test_site_ip_prefix_returns_every_matching_client(use_mist):
    wireless = [{"mac": _mac(i), "ip": f"10.7.{i // 250}.{i % 250}", "site_id": SITE} for i in range(600)]
    wireless += [{"mac": _mac(1000 + i), "ip": f"10.8.0.{i}", "site_id": SITE} for i in range(200)]
    # Wired clients carry IP history lists; the matching address may not be first.
    wired = [{"mac": _mac(i, "06"), "ip": ["192.168.5.5", f"10.7.50.{i}"], "site_id": SITE} for i in range(106)]
    wired += [{"mac": _mac(500 + i, "06"), "ip": ["172.16.0.1"], "site_id": SITE} for i in range(50)]
    # Same prefix on another site must not leak into a site-scoped search.
    wireless += [{"mac": _mac(i, "0a"), "ip": f"10.7.99.{i}", "site_id": OTHER_SITE} for i in range(30)]
    fake = use_mist(FakeMist(wireless=wireless, wired=wired))

    data = ds.search_detective("10.7", site_id=SITE)

    assert data["query_type"] == "ip_prefix"
    assert data["total"] == 706
    assert all(r["ip"].startswith("10.7") for r in data["results"])
    assert not data["truncated"]
    # The site listing is fetched with the complete-site cap and no text filter.
    for source, kw in fake.calls:
        assert kw.get("limit") == ds.SITE_SOURCE_LIMIT
        assert not kw.get("text") and not kw.get("ip")


def test_org_ip_prefix_uses_wildcard_and_filters_locally(use_mist):
    wireless = [{"mac": _mac(i), "ip": f"10.7.1.{i}", "site_id": SITE} for i in range(20)]
    wireless += [{"mac": _mac(100 + i), "ip": f"10.9.1.{i}", "site_id": SITE} for i in range(5)]
    fake = use_mist(FakeMist(wireless=wireless))

    data = ds.search_detective("10.7")

    assert {kw.get("ip") for s, kw in fake.calls if s == "wireless"} == {"10.7*"}
    assert data["total"] == 20  # the leaked 10.9.x row is removed by the local guard


def test_text_query_also_searches_prefix_and_dedupes(use_mist):
    wireless = [
        {"mac": _mac(1), "hostname": "kendall", "site_id": SITE},
        {"mac": _mac(2), "hostname": "kendall-ipad", "site_id": SITE},
        {"mac": _mac(3), "hostname": "other", "site_id": SITE},
    ]
    fake = use_mist(FakeMist(wireless=wireless))

    data = ds.search_detective("kendall", site_id=SITE)

    texts = sorted(kw.get("text") for s, kw in fake.calls if s == "wireless")
    assert texts == ["kendall", "kendall*"]
    macs = sorted(r["mac"] for r in data["results"])
    assert macs == [_mac(1), _mac(2)]  # exact hit found twice, counted once


def test_dedupe_keeps_distinct_clients_without_mac():
    rows = [
        {"kind": "wired_client", "mac": "", "site_id": SITE, "hostname": "a", "ip": "10.0.0.1"},
        {"kind": "wired_client", "mac": "", "site_id": SITE, "hostname": "b", "ip": "10.0.0.2"},
        {"kind": "wired_client", "mac": "aa", "site_id": SITE},
        {"kind": "wired_client", "mac": "aa", "site_id": SITE},
    ]
    assert len(ds._dedupe(rows)) == 3


# ---------------------------------------------------------- site completeness


def test_site_only_listing_is_not_truncated_at_1000(use_mist):
    wireless = [{"mac": _mac(i), "ip": f"10.1.{i // 250}.{i % 250}", "site_id": SITE} for i in range(2600)]
    wired = [{"mac": _mac(i, "06"), "ip": [f"10.2.{i // 250}.{i % 250}"], "site_id": SITE} for i in range(1400)]
    inventory = [{"mac": _mac(i, "0e"), "type": "ap", "name": f"AP-{i}", "site_id": SITE} for i in range(1200)]
    use_mist(FakeMist(wireless=wireless, wired=wired, inventory=inventory))

    data = ds.search_detective("", site_id=SITE)

    assert data["site_listing"] is True
    assert data["total"] == 2600 + 1400 + 1200
    assert data["truncated"] is False
    assert data["client_lookback"] == "7d"


def test_truncation_is_reported(use_mist, monkeypatch):
    monkeypatch.setattr(ds, "SITE_SOURCE_LIMIT", 100)
    wireless = [{"mac": _mac(i), "site_id": SITE} for i in range(150)]
    use_mist(FakeMist(wireless=wireless))

    data = ds.search_detective("", site_id=SITE)

    assert data["truncated"] is True
    assert data["truncated_sources"] == ["wireless clients"]


# --------------------------------------------------------- curated details


INTERNAL = {
    "id": "00000000-aaaa-4bbb-8ccc-000000000001",
    "org_id": "00000000-aaaa-4bbb-8ccc-000000000002",
    "site_id": SITE,
    "map_id": "00000000-aaaa-4bbb-8ccc-000000000003",
    "wxid": "00000000-aaaa-4bbb-8ccc-000000000004",
    "wlan_id": "00000000-aaaa-4bbb-8ccc-000000000005",
    "nacrule_id": "00000000-aaaa-4bbb-8ccc-000000000006",
}


def _flatten(sections):
    return {(r["label"], r["value"]) for s in sections for r in s["rows"]}


def test_curated_details_are_labelled_and_exclude_ids():
    client = {
        **INTERNAL,
        "hostname": "JSMITH-IPHONE",
        "manufacture": "Apple",
        "os": "iOS",
        "ip": "10.7.1.2",
        "band": "5",
        "channel": 149,
        "rssi": -58,
        "snr": 31,
        "proto": "ax",
        "uptime": 93_784,
        "assoc_time": 1_760_000_000,
        "ssid": "CORP",
        "ap_name": "AP-01",
        "ap_mac": "5c5b35000001",
        "raw_array": [{"x": 1}],
        "empty": "",
    }
    attached = {**INTERNAL, "name": "AP-01", "type": "ap", "model": "AP45", "serial": "A123", "version": "0.14.1"}
    nac = {**INTERNAL, "auth_type": "eap-tls", "nacrule_name": "Corp", "cert_cn": "jsmith", "status": "permitted"}
    sections = ds.curated_details("wireless_client", client=client, attached=attached, access=({}, nac))

    titles = [s["title"] for s in sections]
    assert titles == ["Client", "Wireless", "Access (802.1X / NAC)", "Access point"]
    rows = _flatten(sections)
    for expected in [
        ("Manufacturer", "Apple"),
        ("Band", "5 GHz"),
        ("Signal (RSSI)", "-58 dBm"),
        ("Signal-to-noise (SNR)", "31 dB"),
        ("Wi-Fi standard", "802.11ax"),
        ("Uptime", "1d 2h"),
        ("Access point MAC", "5c:5b:35:00:00:01"),
        ("Authentication", "eap-tls"),
        ("NAC rule", "Corp"),
        ("Model", "AP45"),
        ("Firmware", "0.14.1"),
        ("Type", "Access point"),
    ]:
        assert expected in rows, expected
    labels = {label for label, _ in rows}
    values = {value for _, value in rows}
    assert not set(INTERNAL.values()) & values
    assert not {"id", "org_id", "site_id", "map_id", "wxid", "raw_array", "empty"} & labels
    assert all("{" not in v and "[" not in v for v in values)


def test_simulation_detail_carries_curated_details(monkeypatch):
    class NotConfigured:
        configured = False

    monkeypatch.setattr(ds, "get_mist_client", lambda: NotConfigured())
    data = ds.detective_detail("wired_client", "02ae3f9f208a")
    rows = _flatten(data["details"])
    assert ("Port", "ge-0/0/18") in rows and ("Speed", "1 Gbps") in rows
    assert not any(v == data["identity"]["site_id"] for _, v in rows)


# ------------------------------------------------- Palo Alto Test Connection

TOKEN_URL = "https://auth.apps.paloaltonetworks.com/oauth2/access_token"
CREDS = {"client_id": "svc@123.iam.panserviceaccount.com", "client_secret": "s3cret-value", "tsg_id": "1234567890"}


class FakeResponse(io.BytesIO):
    def __init__(self, payload, status=200):
        super().__init__(payload.encode() if isinstance(payload, str) else json.dumps(payload).encode())
        self.status = status
        self.headers = Message()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def http_error(url, code, payload):
    return HTTPError(url, code, "error", Message(), io.BytesIO(json.dumps(payload).encode()))


class FakeOpener:
    def __init__(self, api, token=None):
        self.api = api
        self.token = token
        self.urls: list[str] = []

    def open(self, req, timeout=None):
        self.urls.append(req.full_url)
        if req.full_url == TOKEN_URL:
            if self.token:
                return self.token(req)
            return FakeResponse({"access_token": f"tok-{len(self.urls)}", "expires_in": 899})
        return self.api(req)


@pytest.fixture(autouse=True)
def _clear_tokens():
    TOKEN_MANAGER.clear()
    yield
    TOKEN_MANAGER.clear()


def make_pa(api, token=None):
    provider = pa.PaloAltoDeviceSecurityProvider(
        config=PaloAltoDeviceSecurityConfig(enabled=True), credentials=dict(CREDS)
    )
    provider._opener = FakeOpener(api, token)
    return provider


def test_pa_empty_object_is_not_a_connection():
    provider = make_pa(lambda req: FakeResponse({}))
    with pytest.raises(IntegrationError) as exc:
        provider.test_connection()
    assert "stage: api" in str(exc.value) and "HTTP 200" in str(exc.value)
    assert "device list" in str(exc.value)


def test_pa_errors_payload_fails_with_excerpt_and_request_id():
    body = {"_errors": [{"code": "E1", "message": "tenant not entitled"}], "_request_id": "req-42"}
    provider = make_pa(lambda req: FakeResponse(body))
    with pytest.raises(IntegrationError) as exc:
        provider.test_connection()
    text = str(exc.value)
    assert "stage: api" in text and "tenant not entitled" in text and "req-42" in text


def test_pa_oauth_401_fails_at_oauth_stage():
    def token(req):
        raise http_error(TOKEN_URL, 401, {"error": "invalid_client"})

    provider = make_pa(lambda req: FakeResponse({"devices": []}), token=token)
    with pytest.raises(IntegrationError) as exc:
        provider.test_connection()
    assert "stage: oauth" in str(exc.value) and "HTTP 401" in str(exc.value)
    assert exc.value.status_code == 401
    assert "s3cret-value" not in str(exc.value)


def test_pa_api_403_fails_at_api_stage():
    provider = make_pa(lambda req: (_ for _ in ()).throw(http_error(req.full_url, 403, {"message": "forbidden"})))
    with pytest.raises(IntegrationError) as exc:
        provider.test_connection()
    assert "stage: api" in str(exc.value) and "HTTP 403" in str(exc.value)


def test_pa_empty_device_list_is_a_verified_connection():
    provider = make_pa(lambda req: FakeResponse({"devices": [], "total": 0}))
    result = provider.test_connection()
    assert result["ok"] is True
    assert result["stage"] == "api"
    assert result["status_code"] == 200
    assert result["endpoint"] == "/iot/pub/v1/device/list"
    assert result["tsg_suffix"] == "7890"
    assert result["devices_returned"] == 0 and result["total"] == 0


def test_pa_test_never_reuses_a_cached_token():
    provider = make_pa(lambda req: FakeResponse({"devices": [{"mac": "x"}]}))
    TOKEN_MANAGER.get(provider._token_key, lambda: ("stale-token", 3600))
    provider.test_connection()
    assert provider._opener.urls[0] == TOKEN_URL  # a fresh sign-in happened first
    result = provider.test_connection()
    assert result["devices_returned"] == 1
    assert provider._opener.urls.count(TOKEN_URL) == 2


def test_pa_test_route_reports_failure(monkeypatch):
    from fastapi.testclient import TestClient

    from app.core.security import WRITE_REQUEST_TOKEN
    from app.main import app

    monkeypatch.setattr(
        pa.PaloAltoDeviceSecurityProvider,
        "test_connection",
        lambda self: (_ for _ in ()).throw(
            IntegrationError("IoT Security API check failed (stage: api)", status_code=502)
        ),
    )
    client = TestClient(app, base_url="http://127.0.0.1")
    resp = client.post(
        "/api/integrations/palo-alto-device-security/test",
        json=CREDS,
        headers={"X-NodeWatch-Request": WRITE_REQUEST_TOKEN},
    )
    assert resp.status_code == 502
    assert "stage: api" in resp.json()["detail"]
