"""Port Toolkit and Power Guard data fixes (v0.10.12), using fake Mist responses."""

from __future__ import annotations

from copy import deepcopy

import pytest
from fastapi.testclient import TestClient

from app.core.security import WRITE_REQUEST_TOKEN
from app.services import operations_service, poe_service
from app.services.mist_client import MistApiError

SITE = "11111111-1111-1111-1111-111111111111"
DEVICE = "00000000-0000-0000-1000-0200031d487f"
SWITCH_MAC = "0200031d487f"


class FakeMist:
    configured = True

    def __init__(self):
        self.config = {
            "id": DEVICE,
            "mac": SWITCH_MAC,
            "name": "idf-1",
            "model": "EX4100-48MP",
            "port_config": {
                "ge-0/2/0": {"usage": "uplink", "aggregated": True, "ae_idx": 0},
                "ge-1/2/0": {"usage": "uplink", "aggregated": True, "ae_idx": 0},
                "ge-0/0/1-3": {"usage": "ap", "description": "APs"},
            },
        }
        self.stats = {
            "mac": SWITCH_MAC,
            "status": "connected",
            "module_stat": [
                {"fpc_idx": 0, "serial": "SER0", "model": "EX4100-48MP", "poe": {"max_power": 740, "power_draw": 41.5}},
                {"fpc_idx": 1, "serial": "SER1", "model": "EX4100-48MP", "poe": {"max_power": 740, "power_draw": 12.5}},
                {"fpc_idx": 2, "serial": "SER2", "model": "EX4100-F-12T"},
            ],
        }
        # Mist port search: ``mac`` is the SWITCH mac, ``port_mac`` the interface mac.
        self.port_rows = [
            {"port_id": "ae0", "mac": SWITCH_MAC, "port_mac": SWITCH_MAC, "up": True, "speed": 20000},
            {"port_id": "bme0", "mac": SWITCH_MAC, "port_mac": SWITCH_MAC, "up": True, "speed": 1000},
            {"port_id": "vme", "mac": SWITCH_MAC, "up": True},
            {
                "port_id": "ge-0/0/1",
                "mac": SWITCH_MAC,
                "port_mac": "0200031d4801",
                "up": True,
                "speed": 1000,
                "rx_bps": 250_000_000,
                "tx_bps": 10_000_000,
                "power_draw": 12.4,
                "poe_mode": "802.3at",
            },
            {"port_id": "ge-0/0/2", "mac": SWITCH_MAC, "up": True, "speed": 2500, "neighbor_mac": "a8537d000001"},
            {"port_id": "ge-0/0/3", "mac": SWITCH_MAC, "up": False, "speed": 100},
            {"port_id": "ge-0/2/0", "mac": SWITCH_MAC, "up": True, "speed": 10000},
            {"port_id": "ge-1/2/0", "mac": SWITCH_MAC, "up": True, "speed": 10000},
        ]
        self.wired = [
            {
                "mac": "001122334455",
                "port_id": ["ge-0/0/1"],
                "device_mac": [SWITCH_MAC],
                "hostname": ["cam-lobby"],
                "manufacture": "Axis",
                "ip": ["10.0.0.5"],
                "vlan": [20],
                "last_seen": 200,
            },
            {"mac": "001122334466", "port_id": "ge-0/0/3", "manufacture": "Polycom", "last_seen": 100},
            {"mac": "001122334477", "port_id": ["ge-0/0/1"], "hostname": "older", "last_seen": 50},
        ]
        self.port_search_error = None
        self.search_calls = []

    def get_site_device(self, site_id, device_id, *, fresh=False):
        return deepcopy(self.config)

    def get_site_device_stats(self, site_id, device_id, *, fresh=False):
        return deepcopy(self.stats)

    def search_switch_port_stats(self, site_id, switch_mac, *, limit=2000, fresh=False):
        self.search_calls.append({"mac": switch_mac, "limit": limit, "fresh": fresh})
        if self.port_search_error:
            raise self.port_search_error
        return deepcopy(self.port_rows)

    def search_org_wired_clients(self, **kwargs):
        assert kwargs["device_mac"] == SWITCH_MAC
        return deepcopy(self.wired)

    def list_site_devices(self, site_id, device_type="all"):
        return [deepcopy(self.config)]


@pytest.fixture
def mist(monkeypatch):
    fake = FakeMist()
    monkeypatch.setattr(operations_service, "get_mist_client", lambda: fake)
    return fake


def ports_by_id(data):
    return {p["port_id"]: p for p in data["ports"]}


def test_mac_column_never_shows_the_switch_mac(mist):
    data = operations_service.get_switch_ports(SITE, DEVICE)
    switch_display = operations_service.display_mac(SWITCH_MAC)
    for port in data["ports"]:
        assert port["mac"] != switch_display
        assert port["neighbor_mac"] != switch_display
        assert port["port_mac"] != switch_display
    ports = ports_by_id(data)
    assert ports["ae0"]["mac"] == "" and ports["bme0"]["mac"] == ""
    assert ports["ge-0/0/2"]["mac"] == operations_service.display_mac("a8537d000001")
    assert ports["ge-0/0/1"]["mac"] == operations_service.display_mac("001122334455")


def test_wired_clients_merged_by_port_including_list_port_id(mist):
    ports = ports_by_id(operations_service.get_switch_ports(SITE, DEVICE))
    p1 = ports["ge-0/0/1"]
    assert p1["client_count"] == 2
    assert p1["client_hostname"] == "cam-lobby"
    assert p1["client_manufacturer"] == "Axis"
    assert p1["client_ip"] == "10.0.0.5"
    assert str(p1["vlan_id"]) == "20"
    assert ports["ge-0/0/3"]["client_manufacturer"] == "Polycom"
    assert ports["ge-0/0/2"]["client_count"] == 0


def test_internal_interfaces_flagged(mist):
    ports = ports_by_id(operations_service.get_switch_ports(SITE, DEVICE))
    assert ports["bme0"]["internal"] and ports["vme"]["internal"]
    assert not ports["ge-0/0/1"]["internal"] and not ports["ae0"]["internal"]
    for name in ("em0", "me0", "jsrv", "lo0", "pfe-0/0/0", "esi", "vtep", "fxp0"):
        assert operations_service.is_internal_port(name), name
    for name in ("ge-0/0/0", "xe-1/2/0", "mge-0/0/3", "et-0/0/48", "ae3", "vcp-255/1/0"):
        assert not operations_service.is_internal_port(name), name


def test_lag_membership_from_port_config(mist):
    data = operations_service.get_switch_ports(SITE, DEVICE)
    ports = ports_by_id(data)
    assert ports["ae0"]["lag_members"] == ["ge-0/2/0", "ge-1/2/0"]
    assert ports["ge-0/2/0"]["lag_parent"] == "ae0"
    assert ports["ge-1/2/0"]["lag_parent"] == "ae0"
    assert ports["ge-0/0/1"]["lag_parent"] == ""
    assert data["lags"] == {"ae0": ["ge-0/2/0", "ge-1/2/0"]}
    # range keys apply profile/description to every port in the range
    assert ports["ge-0/0/2"]["usage"] == "ap" and ports["ge-0/0/3"]["description"] == "APs"


def test_lag_range_key_expansion():
    ports = [operations_service.normalize_port({"port_id": "ae1"})]
    lags = operations_service.apply_lag_membership(ports, {"xe-0/1/0-2": {"aggregated": True, "ae_idx": 1}})
    assert lags["ae1"] == ["xe-0/1/0", "xe-0/1/1", "xe-0/1/2"]
    assert ports[0]["lag_members"] == lags["ae1"]


def test_speed_formatting_and_utilisation(mist):
    ports = ports_by_id(operations_service.get_switch_ports(SITE, DEVICE))
    assert ports["ae0"]["speed"] == "20G" and ports["ae0"]["speed_mbps"] == 20000
    assert ports["ge-0/0/2"]["speed"] == "2.5G"
    assert ports["ge-0/0/3"]["speed"] == "100M"
    assert ports["ge-0/0/1"]["utilisation_pct"] == 25.0
    assert operations_service.format_speed(operations_service.speed_mbps("10Gbps")) == "10G"


def test_port_search_uses_2000_limit_and_failure_surfaces_warning(mist):
    data = operations_service.get_switch_ports(SITE, DEVICE, fresh=True)
    assert mist.search_calls[-1] == {"mac": SWITCH_MAC, "limit": 2000, "fresh": True}
    assert data["warnings"] == []
    mist.port_search_error = MistApiError("Mist API timeout", 504)
    data = operations_service.get_switch_ports(SITE, DEVICE)
    assert len(data["warnings"]) == 1 and "port statistics search failed" in data["warnings"][0]


def test_poe_budget_from_module_stat_across_two_members(mist):
    summary = poe_service.poe_summary(SITE, DEVICE, fresh=True)
    assert summary["budget_watts"] == 1480
    assert summary["budget_source"] == "module_stat"
    assert [m["fpc"] for m in summary["per_member"]] == [0, 1]
    assert summary["per_member"][0]["serial"] == "SER0"
    assert summary["per_member"][1]["power_draw"] == 12.5
    # module draw (54 W) is larger than the per-port sum (12.4 W)
    assert summary["draw_watts"] == 54.0
    assert summary["utilization_pct"] == round(54 / 1480 * 100, 1)
    assert not any("budget unavailable" in r["title"].lower() for r in summary["risks"])


def test_powered_count_uses_power_draw_without_poe_on(mist):
    summary = poe_service.poe_summary(SITE, DEVICE)
    assert summary["powered_ports"] == 1
    assert summary["ports"][0]["port_id"] == "ge-0/0/1"
    assert summary["ports"][0]["mac"] == operations_service.display_mac("001122334455")
    assert summary["notes"] == []


def test_note_when_chassis_draw_but_no_port_rows(mist):
    for row in mist.port_rows:
        row.pop("power_draw", None)
    summary = poe_service.poe_summary(SITE, DEVICE)
    assert summary["powered_ports"] == 0
    assert summary["draw_watts"] == 54.0
    assert len(summary["notes"]) == 1 and "PoE column" in summary["notes"][0]


def test_poe_router_maps_mist_errors(monkeypatch):
    from app.main import app

    def boom(*args, **kwargs):
        raise MistApiError("Mist API rate limited", 429)

    monkeypatch.setattr("app.modules.poe.router.poe_summary", boom)
    client = TestClient(app, base_url="http://127.0.0.1")
    client.headers.update({"X-NodeWatch-Request": WRITE_REQUEST_TOKEN})
    res = client.get("/api/v1/poe/summary", params={"site_id": SITE, "device_id": DEVICE})
    assert res.status_code == 429
    assert "rate limited" in res.json()["detail"]

    def boom_none(*args, **kwargs):
        raise MistApiError("connection reset")

    monkeypatch.setattr("app.modules.poe.router.poe_summary", boom_none)
    res = client.get("/api/v1/poe/summary", params={"site_id": SITE, "device_id": DEVICE})
    assert res.status_code == 502
