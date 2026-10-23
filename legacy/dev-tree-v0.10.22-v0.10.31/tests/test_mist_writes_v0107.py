"""Safety tests for NodeWatch actions that write to production Mist devices (v0.10.7)."""

from __future__ import annotations

from copy import deepcopy

import pytest
from fastapi.testclient import TestClient

from app.core.config import VALIDATION_ROOT
from app.core.security import WRITE_REQUEST_TOKEN
from app.services import backup_service, operations_service, validation_service

SITE = "11111111-1111-1111-1111-111111111111"
DEVICE = "00000000-0000-0000-1000-aabbccddeeff"
SWITCH_MAC = "aabbccddeeff"


class FakeMist:
    configured = True

    def __init__(self):
        self.config = {
            "id": DEVICE,
            "mac": SWITCH_MAC,
            "name": "sw1",
            "model": "EX4100",
            "serial": "S1",
            "modified_time": 1,
            "port_usages": {"cameras": {}},
            "port_config": {"ge-0/0/1": {"usage": "default"}, "ge-0/0/48": {"usage": "uplink"}},
        }
        self.stats = {
            "mac": SWITCH_MAC,
            "status": "connected",
            "ports": [
                {"port_id": "ge-0/0/1", "up": True},
                {"port_id": "ge-0/0/48", "up": True},
                {"port_id": "xe-0/2/0", "up": True, "uplink": True},
                {"port_id": "vcp-255/1/0", "up": True},
            ],
        }
        self.alarms = []
        self.writes = []
        self.port_search_macs = []
        self.derived_usages = {"voip": {}}
        self.vc = None

    # reads
    def get_site_device(self, site_id, device_id, *, fresh=False):
        return deepcopy(self.config)

    def get_site_device_stats(self, site_id, device_id, *, fresh=False):
        return deepcopy(self.stats)

    def search_site_ports(self, site_id, *, device_type="switch", mac=None, port_id=None, limit=50):
        self.port_search_macs.append(mac)
        return []

    def get_site_setting_derived(self, site_id, *, fresh=False):
        return {"port_usages": self.derived_usages}

    def search_org_alarms(self, *, fresh=False, duration=None, limit=10_000):
        return deepcopy(self.alarms)

    def get_site_virtual_chassis(self, site_id, device_id, *, fresh=False):
        return {"status": "ok"}

    def clear_cache_matching(self, *parts):
        pass

    def list_site_devices(self, site_id, device_type="all"):
        return [deepcopy(self.config)]

    # writes
    def update_site_device(self, site_id, device_id, body):
        self.writes.append(("update", deepcopy(body)))
        for key, value in body.items():
            if value is None:
                self.config.pop(key, None)
            else:
                self.config[key] = deepcopy(value)
        return {"ok": True}

    def bounce_device_port(self, site_id, device_id, ports):
        self.writes.append(("bounce", list(ports)))
        return {"ok": True}

    def cable_test_from_switch(self, site_id, device_id, port_id):
        self.writes.append(("cable_test", port_id))
        return {"ok": True}


@pytest.fixture
def mist(monkeypatch):
    fake = FakeMist()
    for module in (operations_service, backup_service, validation_service):
        monkeypatch.setattr(module, "get_mist_client", lambda: fake)
    monkeypatch.setattr(operations_service.time, "sleep", lambda s: None)
    return fake


@pytest.fixture
def api(mist):
    from app.main import app

    client = TestClient(app, base_url="http://127.0.0.1")
    client.headers.update({"X-NodeWatch-Request": WRITE_REQUEST_TOKEN})
    return client


def execute(api, **overrides):
    body = {"site_id": SITE, "device_id": DEVICE, "port_id": "ge-0/0/1", "action": "bounce", "confirmed": True}
    body.update(overrides)
    return api.post("/api/v1/operations/execute", json=body)


# ---------------------------------------------------------------- port actions


def test_bounce_valid_access_port(api, mist):
    r = execute(api)
    assert r.status_code == 200, r.text
    assert mist.writes == [("bounce", ["ge-0/0/1"])]


@pytest.mark.parametrize("confirmed", ["yes", 1, "true", None])
def test_confirmation_must_be_boolean_true(api, mist, confirmed):
    r = execute(api, confirmed=confirmed)
    assert r.status_code == 400
    assert mist.writes == []


@pytest.mark.parametrize("port_id", ["", "ge-0/0/99", "../../x", "ge-0/0/1; rm"])
def test_port_must_exist_on_switch(api, mist, port_id):
    r = execute(api, port_id=port_id)
    assert r.status_code == 400
    assert mist.writes == []


@pytest.mark.parametrize("port_id", ["ge-0/0/48", "xe-0/2/0", "vcp-255/1/0"])
def test_protected_ports_need_override(api, mist, port_id):
    r = execute(api, port_id=port_id)
    assert r.status_code == 400 and "protected" in r.json()["detail"]
    assert mist.writes == []
    r = execute(api, port_id=port_id, payload={"allow_protected_port": True})
    assert r.status_code == 200, r.text
    assert mist.writes == [("bounce", [port_id])]


def test_profile_update_allows_known_usage_only(api, mist):
    r = execute(api, action="profile_update", payload={"usage": "made-up"})
    assert r.status_code == 400 and "Unknown port usage" in r.json()["detail"]
    for usage in ("cameras", "voip", "default", "disabled"):
        r = execute(api, action="profile_update", payload={"usage": usage})
        assert r.status_code == 200, r.text
    last = mist.writes[-1][1]
    assert last["port_config"]["ge-0/0/1"]["usage"] == "disabled"
    assert last["port_config"]["ge-0/0/48"] == {"usage": "uplink"}  # other ports preserved


def test_profile_update_rejects_bad_speed_and_long_description(api, mist):
    assert execute(api, action="profile_update", payload={"speed": "9000g"}).status_code == 400
    assert execute(api, action="profile_update", payload={"description": "x" * 200}).status_code == 400
    assert execute(api, action="profile_update", payload={"disabled": "yes"}).status_code == 400
    assert execute(api, action="profile_update", payload={}).status_code == 400
    assert mist.writes == []


def test_unknown_switch_mac_never_searches_whole_site(api, mist):
    mist.config["mac"] = ""
    mist.stats["mac"] = ""
    data = operations_service.get_switch_ports(SITE, DEVICE)
    assert None not in mist.port_search_macs and mist.port_search_macs == []
    assert {p["port_id"] for p in data["ports"]} == {"ge-0/0/1", "ge-0/0/48", "xe-0/2/0", "vcp-255/1/0"}
    r = execute(api)
    assert r.status_code == 400 and "MAC" in r.json()["detail"]
    assert mist.writes == []


def test_preview_flags_protected_port(api, mist):
    r = api.post(
        "/api/v1/operations/preview",
        json={"site_id": SITE, "device_id": DEVICE, "port_id": "ge-0/0/48", "action": "bounce"},
    )
    assert r.status_code == 200
    assert r.json()["protected"] is True


# --------------------------------------------------------------------- rollback


def test_rollback_clears_added_keys_and_verifies_whole_config(mist):
    snap = backup_service.create_snapshot(SITE, DEVICE)
    mist.config["name"] = "renamed"
    mist.config["dhcp_snooping"] = {"enabled": True}  # added after the snapshot
    mist.config["modified_time"] = 999  # server-managed, must be ignored

    preview = backup_service.restore_preview(snap["snapshot"], DEVICE)
    assert set(preview["changed_keys"]) == {"name", "dhcp_snooping"}
    assert preview["cleared_keys"] == ["dhcp_snooping"]
    assert "id" not in preview["request"] and "mac" not in preview["request"]

    result = backup_service.restore(snap["snapshot"], DEVICE, confirmed=True)
    assert result["verified"] is True
    assert mist.config["name"] == "sw1" and "dhcp_snooping" not in mist.config


def test_rollback_reports_remaining_differences(mist):
    snap = backup_service.create_snapshot(SITE, DEVICE)
    mist.config["name"] = "renamed"
    original_update = mist.update_site_device

    def update_ignoring_nulls_and_name(site_id, device_id, body):
        body = {k: v for k, v in body.items() if k != "name"}
        return original_update(site_id, device_id, body)

    mist.update_site_device = update_ignoring_nulls_and_name
    result = backup_service.restore(snap["snapshot"], DEVICE, confirmed=True)
    assert result["verified"] is False
    assert [d["field"] for d in result["remaining_differences"]] == ["name"]


def test_rollback_requires_strict_confirmation(api, mist):
    snap = backup_service.create_snapshot(SITE, DEVICE)
    r = api.post(
        "/api/v1/config-backup/restore", json={"snapshot_id": snap["snapshot"], "device_id": DEVICE, "confirmed": "yes"}
    )
    assert r.status_code == 400
    assert not [w for w in mist.writes if w[0] == "update"]


def test_drift_ignores_server_managed_fields(mist):
    snap = backup_service.create_snapshot(SITE, DEVICE)
    mist.config["modified_time"] = 12345
    result = backup_service.drift(snap["snapshot"])
    assert result["clean"] == 1 and result["drifted"] == 0
    mist.config["notes"] = "new"
    mist.config.pop("port_usages")
    row = backup_service.drift(snap["snapshot"])["devices"][0]
    kinds = {d["field"]: d["kind"] for d in row["diff"]}
    assert kinds == {"notes": "added", "port_usages": "removed"}


# ------------------------------------------------------------------- validation


def test_unknown_status_does_not_pass(mist):
    mist.stats["status"] = ""
    report = validation_service.run_validation(SITE, DEVICE)
    assert report["ok"] is False
    assert "unknown" in report["checks"][0]["detail"].lower()


def test_only_this_devices_open_config_alarms_block(mist):
    mist.alarms = [
        {"type": "sw_config_failed", "site_id": SITE, "switches": ["001122334455"]},  # other switch, same site
        {"type": "sw_config_failed", "switches": [SWITCH_MAC], "resolved_time": 123},  # resolved
    ]
    assert validation_service.run_validation(SITE, DEVICE)["ok"] is True
    mist.alarms.append({"type": "sw_config_failed", "switches": ["aa:bb:cc:dd:ee:ff"]})
    assert validation_service.run_validation(SITE, DEVICE)["ok"] is False


def test_validation_report_name_cannot_escape_folder(mist):
    report = validation_service.run_validation(SITE, "../../evil", label="../../../x")
    assert "/" not in report["report_file"] and ".." not in report["report_file"]
    assert (VALIDATION_ROOT / report["report_file"]).exists()


# ---------------------------------------------------------------- virtual chassis


@pytest.fixture
def vc_api(monkeypatch):
    from app.modules.virtual_chassis import router as vc_router

    fake = FakeMist()
    fake.config["virtual_chassis"] = {
        "preprovisioned": True,
        "members": [
            {"mac": "aabbccddee01", "member_id": 0, "vc_role": "master", "vc_ports": ["xe-0/2/0"]},
            {"mac": "aabbccddee02", "member_id": 1, "vc_role": "backup"},
        ],
    }
    monkeypatch.setattr(vc_router, "get_mist_client", lambda: fake)
    from app.main import app

    client = TestClient(app, base_url="http://127.0.0.1")
    client.headers.update({"X-NodeWatch-Request": WRITE_REQUEST_TOKEN})
    client.fake = fake
    return client


def vc_body(fake, **overrides):
    members = deepcopy(fake.config["virtual_chassis"]["members"])
    body = {
        "site_id": SITE,
        "device_id": DEVICE,
        "confirmed": True,
        "preprovisioned": True,
        "members": [{k: v for k, v in m.items() if k != "vc_ports"} for m in members],
        "original_members": members,
    }
    body.update(overrides)
    return body


def test_vc_requires_preprovisioned_and_original_members(vc_api):
    fake = vc_api.fake
    body = vc_body(fake)
    body.pop("preprovisioned")
    assert vc_api.post("/api/v1/virtual-chassis/apply", json=body).status_code == 400
    body = vc_body(fake)
    body.pop("original_members")
    assert vc_api.post("/api/v1/virtual-chassis/apply", json=body).status_code == 400
    assert fake.writes == []


def test_vc_bad_member_id_is_400(vc_api):
    body = vc_body(vc_api.fake)
    body["original_members"][0]["member_id"] = "zero"
    assert vc_api.post("/api/v1/virtual-chassis/apply", json=body).status_code == 400


def test_vc_master_backup_swap_detected_by_concurrency_guard(vc_api):
    fake = vc_api.fake
    body = vc_body(fake)
    swapped = deepcopy(body["original_members"])
    swapped[0]["vc_role"], swapped[1]["vc_role"] = "backup", "master"
    body["original_members"] = swapped
    r = vc_api.post("/api/v1/virtual-chassis/apply", json=body)
    assert r.status_code == 409
    assert fake.writes == []


def test_vc_apply_preserves_vc_ports_and_verifies_roles(vc_api):
    fake = vc_api.fake
    r = vc_api.post("/api/v1/virtual-chassis/apply", json=vc_body(fake))
    assert r.status_code == 200, r.text
    written = fake.writes[-1][1]["virtual_chassis"]
    member0 = next(m for m in written["members"] if m["member_id"] == 0)
    assert member0["vc_ports"] == ["xe-0/2/0"]
    assert written["preprovisioned"] is True
    assert r.json()["verified"] is True


def test_vc_routing_engine_reads_are_not_reported_as_verified(vc_api):
    fake = vc_api.fake
    original_update = fake.update_site_device

    def update_and_report_generic_roles(site_id, device_id, body):
        result = original_update(site_id, device_id, body)
        for member in fake.config["virtual_chassis"]["members"]:
            if member["vc_role"] in {"master", "backup"}:
                member["vc_role"] = "routing-engine"
        return result

    fake.update_site_device = update_and_report_generic_roles
    r = vc_api.post("/api/v1/virtual-chassis/apply", json=vc_body(fake))
    assert r.status_code == 200
    assert r.json()["verified"] is False and r.json()["status"] == "accepted_roles_unconfirmed"


# ------------------------------------------------------- review regressions (v0.10.7)


def test_vc_apply_allowed_after_switchover_when_config_says_routing_engine(vc_api):
    fake = vc_api.fake
    # Mist config only says routing-engine; the editor loaded live roles (member 1 is master now).
    for m in fake.config["virtual_chassis"]["members"]:
        m["vc_role"] = "routing-engine"
    body = vc_body(fake)
    body["original_members"] = [
        {"mac": "aabbccddee01", "member_id": 0, "vc_role": "backup"},
        {"mac": "aabbccddee02", "member_id": 1, "vc_role": "master"},
    ]
    body["members"] = [{k: v for k, v in m.items()} for m in body["original_members"]]
    r = vc_api.post("/api/v1/virtual-chassis/apply", json=body)
    assert r.status_code == 200, r.text


def test_vc_membership_change_still_detected_with_routing_engine_roles(vc_api):
    fake = vc_api.fake
    for m in fake.config["virtual_chassis"]["members"]:
        m["vc_role"] = "routing-engine"
    body = vc_body(fake)
    body["original_members"] = [{"mac": "aabbccddee99", "member_id": 0, "vc_role": "master"}]
    assert vc_api.post("/api/v1/virtual-chassis/apply", json=body).status_code == 409


@pytest.mark.parametrize("port_id", ["et-0/0/48:1", "xe-0/0/0:2", "ge-0/0/0.0", "mge-0/0/3"])
def test_valid_junos_names_accepted(port_id):
    assert operations_service._PORT_ID_PATTERN.match(port_id)


def test_uplink_defined_by_range_key_is_protected(api, mist):
    mist.config["port_config"] = {"ge-0/0/0-3": {"usage": "uplink"}}
    r = execute(api, port_id="ge-0/0/1")
    assert r.status_code == 400 and "protected" in r.json()["detail"]
    assert mist.writes == []
