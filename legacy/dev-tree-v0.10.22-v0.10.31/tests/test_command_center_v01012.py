"""v0.10.12 Command Center / UI-wide changes: alert evidence, readable facts, Mist links, no filler
text, searchable site pickers, sortable tables, Chassis Manager cancel fix."""

from __future__ import annotations

import json
import subprocess
import time
from pathlib import Path
from types import SimpleNamespace

from app.services import dashboard_service

ROOT = Path(__file__).resolve().parents[1]
HTML = (ROOT / "app/templates/index.html").read_text(encoding="utf-8")
NOW = time.time()


class FakeClient:
    settings = SimpleNamespace(api_host="https://api.eu.mist.com", org_id="org-1")

    def get_org(self):
        return {"name": "Org"}

    def list_sites(self):
        return [{"id": "s1", "name": "Kendall"}, {"id": "s2", "name": "Doral"}]

    def list_org_site_stats(self):
        return []

    def search_org_inventory(self, limit=0):
        return [
            {
                "id": "dev-sw1",
                "mac": "aabbccddee01",
                "name": "SW-KND-1",
                "type": "switch",
                "site_id": "s1",
                "status": "disconnected",
                "connected": False,
                "last_seen": NOW - 3600,
                "model": "EX4400-48MP",
                "version": "23.4R2",
                "ip": "10.7.0.2",
            },
            {
                "id": "dev-ap1",
                "mac": "aabbccddee02",
                "name": "AP-KND-1",
                "type": "ap",
                "site_id": "s1",
                "status": "disconnected",
                "connected": False,
                "last_seen": NOW - 3500,
            },
            {
                "id": "dev-ap2",
                "mac": "aabbccddee03",
                "name": "AP-DRL-1",
                "type": "ap",
                "site_id": "s2",
                "status": "connected",
                "connected": True,
                "last_seen": NOW,
            },
        ]

    def list_org_inventory(self, **_):
        return []

    def search_org_alarms(self):
        return [
            {
                "id": "al-1",
                "type": "rogue_ap",
                "severity": "warn",
                "site_id": "s2",
                "timestamp": NOW - 600,
                "count": 4,
                "ssid": "FreeWiFi",
                "bssid": "001122334455",
                "org_id": "org-1",
                "group": "security",
            }
        ]

    def search_org_device_events(self):
        return [
            {
                "type": "SW_DISCONNECTED",
                "mac": "aabbccddee01",
                "site_id": "s1",
                "timestamp": NOW - 3600,
                "text": "Switch lost connection to the cloud",
                "reason": "power loss",
            },
        ]

    def list_alarm_definitions(self):
        return [{"key": "rogue_ap", "display": "Rogue AP detected", "description": "An unknown AP is broadcasting."}]


def _dashboard():
    return dashboard_service.build_live_dashboard(FakeClient())


def test_alerts_carry_readable_evidence_and_no_filler_text():
    data = _dashboard()
    for item in data["attention"]:
        assert "Mist reports an active condition requiring review" not in item["detail"]
        assert isinstance(item["facts"], list)
        for fact in item["facts"]:
            assert set(fact) >= {"label", "value", "kind"}
            assert not str(fact["value"]).lstrip().startswith("{"), fact  # never a raw JSON blob
            assert fact["label"].lower() not in {"id", "org id", "site id", "device id"}
    down = next(x for x in data["attention"] if x["device"] == "SW-KND-1")
    labels = {e["label"]: e for e in down["engineer"]["evidence"]}
    assert labels["Device status now"]["value"].startswith("Disconnected")
    assert labels["Device last seen"]["kind"] == "time"
    everything = " ".join(str(e["value"]) for e in down["engineer"]["evidence"])
    assert "power loss" in everything and "lost connection" in everything  # Mist's own reason is shown
    assert "AP-KND-1" in labels["Also down at this site"]["value"]
    rogue = next(x for x in data["attention"] if x["type"] == "rogue_ap")
    fact_labels = {f["label"] for f in rogue["facts"]}
    assert {"Ssid", "Bssid"} & fact_labels or {"SSID", "BSSID"} & fact_labels
    assert "Mist definition" in fact_labels


def test_alerts_and_down_rows_link_to_the_mist_device_page():
    data = _dashboard()
    down = next(x for x in data["attention"] if x["device"] == "SW-KND-1")
    assert down["mist_url"] == "https://manage.eu.mist.com/admin/?org_id=org-1#!switch/detail/dev-sw1/s1"
    rows = data["disconnect_watch"]["devices"]
    ap = next(r for r in rows if r["device"] == "AP-KND-1")
    assert ap["mist_url"].endswith("#!ap/detail/dev-ap1/s1")


def test_no_raw_mist_fields_anywhere_in_the_ui():
    assert "Raw Mist fields" not in HTML
    for js in (ROOT / "app/static").rglob("*.js"):
        assert "Raw Mist fields" not in js.read_text(encoding="utf-8"), js
    explainer = (ROOT / "app/services/condition_explainer.py").read_text(encoding="utf-8")
    assert "raw Mist fields" not in explainer


def test_every_site_select_is_a_searchable_picker():
    for sid in ("nocSiteFilter", "detectiveSite", "siteSelect", "opsSite", "valSite", "backupSite", "poeSite"):
        assert f'<select id="{sid}" data-site-picker>' in HTML, sid
    assert "/static/site-picker.js" in HTML and "/static/table-tools.js" in HTML
    assert 'id="vcSiteSearch"' not in HTML  # the old, unwired search box is gone


def test_chassis_member_dialog_cancel_cannot_save():
    dialog = HTML[
        HTML.index('<dialog id="memberDialog"') : HTML.index("</dialog>", HTML.index('<dialog id="memberDialog"'))
    ]
    assert 'type="button" id="memberDialogCancel"' in dialog
    assert 'type="button" id="memberDialogClose"' in dialog
    assert dialog.count('type="submit"') == 1
    vc = (ROOT / "app/static/modules/virtual-chassis.js").read_text(encoding="utf-8")
    assert "j === 0 ? 'checked'" not in vc  # nothing is pre-selected


def _node(script: str) -> str:
    return subprocess.run(["node", "-e", script], capture_output=True, text=True, check=True).stdout


def test_table_sort_keys_order_numbers_ips_times_and_blanks():
    src = (ROOT / "app/static/table-tools.js").read_text(encoding="utf-8")
    script = (
        "const listeners={};global.window={};global.document={readyState:'complete',addEventListener(){},"
        "querySelectorAll(){return []},body:{}};global.MutationObserver=class{observe(){}};"
        + src
        + ";const {key,compare}=window.NodeWatchTables;"
        "const sort=(a)=>a.map(key).map((k,i)=>({k,v:a[i]})).sort((x,y)=>compare(x.k,y.k)).map(x=>x.v);"
        "console.log(JSON.stringify([sort(['10.7.0.20','10.7.0.3','9.1.1.1']),sort(['15.4 W','4.25 W','4.5 W']),"
        "sort(['ge-0/0/10','ge-0/0/2','—','ge-0/0/1']),sort(['b','A','c'])]))"
    )
    out = json.loads(_node(script))
    assert out[0] == ["9.1.1.1", "10.7.0.3", "10.7.0.20"]
    assert out[1] == ["4.25 W", "4.5 W", "15.4 W"]
    assert out[2] == ["ge-0/0/1", "ge-0/0/2", "ge-0/0/10", "—"]
    assert out[3] == ["A", "b", "c"]


def test_command_center_markup_for_new_controls():
    assert 'id="nocCountdown"' in HTML and "Live attention view" not in HTML
    assert 'id="nocSearchResults"' in HTML and 'id="nocListDialog"' in HTML
    js = (ROOT / "app/static/modules/dashboard.js").read_text(encoding="utf-8")
    for needle in (
        "applyTile(",
        "showDisconnectList(",
        "quickSearch()",
        "setNavBadge?.('dashboard', s.needs_attention",
    ):
        assert needle in js, needle


def test_alarm_without_mac_is_not_listed_as_also_down_at_its_own_site():
    m = "aabbccddee09"
    ev = dashboard_service._evidence(
        {"type": "switch_offline", "switches": [m]},
        {},
        mac="",
        site_id="s1",
        events_by_mac={},
        down_by_site={"s1": [{"device": "SW1", "mac": m}]},
    )
    assert not any(e["label"] == "Also down at this site" for e in ev)
