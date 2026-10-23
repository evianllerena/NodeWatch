"""v0.10.12 Operations Assistant: intent parsing and answer building with fake data (no network)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.services import ai_engineer_service as svc
from app.services.ai_engineer_intents import find_ip, find_mac, looks_like_hostname, match_site, parse

ROOT = Path(__file__).resolve().parents[1]

SITES = [
    {"id": "s-dal", "name": "Dallas Medical Center"},
    {"id": "s-hou", "name": "Houston Medical Center"},
    {"id": "s-aus", "name": "Austin Clinic"},
    {"id": "s-d01", "name": "DAL01"},
    {"id": "s-co", "name": "Central Office"},
]
DEVICE_NAMES = ["SW-CORE-01", "AP-LOBBY-2", "core1", "DAL-GW-1", "SW-IDF-2"]


def p(q):
    return parse(q, SITES, lambda: DEVICE_NAMES)


# --------------------------------------------------------------------------- identifiers


@pytest.mark.parametrize(
    "text,expected",
    [
        ("where is AA:BB:CC:DD:EE:FF", "aa:bb:cc:dd:ee:ff"),
        ("find aa-bb-cc-dd-ee-0f please", "aa:bb:cc:dd:ee:0f"),
        ("aabb.ccdd.eeff", "aa:bb:cc:dd:ee:ff"),
        ("is 5c5b35aa01f2 online", "5c:5b:35:aa:01:f2"),
        ("ticket 123456789012", None),
        ("no mac here", None),
    ],
)
def test_mac_detection(text, expected):
    assert find_mac(text) == expected


def test_ip_detection():
    assert find_ip("find 10.20.30.55?") == "10.20.30.55"
    assert find_ip("999.1.1.1") is None
    assert find_ip("where is fe80::1c2b:3cff:fe4d:5e6f") == "fe80::1c2b:3cff:fe4d:5e6f"
    assert find_ip("mac aa:bb:cc:dd:ee:ff") is None


@pytest.mark.parametrize("token", ["SW-CORE-01", "core1", "ap12", "jdoe-laptop", "lab.host9", "DAL-GW-1"])
def test_hostname_shapes(token):
    assert looks_like_hostname(token)


@pytest.mark.parametrize("token", ["wi-fi", "status", "5ghz", "24h", "ge-0/0/1", "10.1.1.1", "down", "802.1x"])
def test_not_hostnames(token):
    assert not looks_like_hostname(token)


# --------------------------------------------------------------------------- site matching


@pytest.mark.parametrize(
    "q,site",
    [
        ("how is dallas", "Dallas Medical Center"),
        ("how is dalas", "Dallas Medical Center"),  # typo
        ("issues at houstn?", "Houston Medical Center"),  # typo
        ("how's austn doing", "Austin Clinic"),
        ("problems at aus", "Austin Clinic"),  # prefix / partial
        ("Central office", "Central Office"),
        ("issues at DAL01", "DAL01"),  # hostname-shaped site code
        ("what's wrong at dallas medical center", "Dallas Medical Center"),
    ],
)
def test_site_fuzzy_match(q, site):
    intent = p(q)
    assert intent.name == "site_status", (q, intent)
    assert intent.site_name == site


def test_site_ambiguity_is_reported():
    m = match_site("how is medical center", SITES)
    assert m is not None and {x["name"] for x in m.ambiguous} == {"Dallas Medical Center", "Houston Medical Center"}


def test_generic_words_do_not_match_a_site():
    assert match_site("what's broken", SITES) is None
    assert match_site("any issues", SITES) is None


# --------------------------------------------------------------------------- intents


@pytest.mark.parametrize(
    "q,name",
    [
        ("what's broken", "summary"),
        ("whats wrong", "summary"),
        ("any issues?", "summary"),
        ("status", "summary"),
        ("is everything ok", "summary"),
        ("what's down", "down"),
        ("are any aps down", "down"),
        ("is the wi-fi down at dallas", "down"),
        ("what changed today", "changes"),
        ("recent changes this week", "changes"),
        ("virtual chassis problems", "vc"),
        ("top problems", "top"),
        ("busiest sites", "top"),
        ("help", "help"),
        ("what can you do?", "help"),
        ("show me examples", "help"),
        ("", "help"),
        ("critical alarms", "alarms"),
        ("firmware versions", "firmware"),
        ("rogue aps", "security"),
        ("traffic for 10.1.1.1", "traffic"),
        ("PoE on SW-CORE-01", "poe"),
        ("poe at dallas", "poe"),
        ("ports on core1", "ports"),
        ("is ge-0/0/1 up on SW-CORE-01", "ports"),
        ("blorp zzz", "unknown"),
    ],
)
def test_intents(q, name):
    assert p(q).name == name, (q, p(q))


def test_down_kind_and_site():
    i = p("which switches are down at dalas")
    assert (i.name, i.device_kind, i.site_name) == ("down", "switch", "Dallas Medical Center")
    assert p("which gateways are offline").device_kind == "gateway"
    assert p("which APs are down").device_kind == "ap"


@pytest.mark.parametrize(
    "q,target,kind",
    [
        ("is SW-CORE-01 up", "SW-CORE-01", "name"),
        ("where is aa:bb:cc:dd:ee:ff", "aa:bb:cc:dd:ee:ff", "mac"),
        ("find 10.20.30.55", "10.20.30.55", "ip"),
        ("where is jdoe-laptop", "jdoe-laptop", "name"),
        ("where is johns iphone", "johns iphone", "text"),
        ("is core1 up", "core1", "name"),
        ("core 1", "core1", "name"),  # bare (spaced) device name from the inventory vocabulary
    ],
)
def test_locate_targets(q, target, kind):
    i = p(q)
    assert (i.name, i.target, i.target_kind) == ("locate", target, kind)


def test_changes_duration():
    assert p("what changed in the last hour").duration == "1h"
    assert p("what changed today").duration == "1d"
    assert p("changes this week at dallas").site_name == "Dallas Medical Center"


def test_poe_and_ports_targets():
    assert p("PoE on sw-core-01").target == "sw-core-01"
    i = p("is ge-0/0/1 up on SW-CORE-01")
    assert (i.target, i.port_id) == ("SW-CORE-01", "ge-0/0/1")


# --------------------------------------------------------------------------- answers (fake data)


DASH = {
    "mode": "live",
    "errors": [],
    "summary": {"critical": 2, "warning": 1, "devices_down": 3, "vc_degraded": 1},
    "health": [
        {"device_type": "ap", "total": 40, "down": 2},
        {"device_type": "switch", "total": 10, "down": 1},
        {"device_type": "gateway", "total": 2, "down": 0},
        {"device_type": "vc", "total": 4, "down": 0, "warning": 1},
    ],
    "attention": [
        {
            "severity": "critical",
            "type": "SW_ALARM_VIRTUAL_CHASSIS_VERSION_MISMATCH",
            "group": "Virtual Chassis",
            "title": "VC firmware version mismatch",
            "device": "SW-CORE-01",
            "mac": "aabbccddee01",
            "site": "Dallas Medical Center",
            "site_id": "s-dal",
            "age": "7m",
        },
        {
            "severity": "critical",
            "type": "SWITCH_CURRENTLY_DOWN",
            "group": "Connectivity / Availability",
            "title": "Switch disconnected",
            "device": "SW-IDF-2",
            "site": "Dallas Medical Center",
            "site_id": "s-dal",
            "age": "1h 02m",
        },
        {
            "severity": "warning",
            "type": "AP_RADAR",
            "group": "Wireless / RF",
            "title": "Radar detected",
            "device": "AP-LOBBY-2",
            "site": "Houston Medical Center",
            "site_id": "s-hou",
            "age": "3h 00m",
        },
    ],
    "disconnect_watch": {
        "devices": [
            {
                "device": "SW-IDF-2",
                "device_type": "switch",
                "mac": "aabbccddee02",
                "site": "Dallas Medical Center",
                "site_id": "s-dal",
                "age": "1h 02m",
            },
            {
                "device": "AP-3F-1",
                "device_type": "ap",
                "mac": "aabbccddee03",
                "site": "Dallas Medical Center",
                "site_id": "s-dal",
                "age": "1h 01m",
            },
            {
                "device": "AP-ER-4",
                "device_type": "ap",
                "mac": "aabbccddee04",
                "site": "Houston Medical Center",
                "site_id": "s-hou",
                "age": "5m",
            },
        ],
        "clusters": [
            {
                "site_id": "s-dal",
                "site": "Dallas Medical Center",
                "severity": "warning",
                "label": "Multiple devices disconnected",
                "down": 2,
                "total": 20,
                "message": "2 of 20 managed devices are disconnected at this site.",
            }
        ],
        "dismissed_known_down": 1,
    },
    "alarm_groups": [{"name": "Virtual Chassis", "count": 1}, {"name": "Wireless / RF", "count": 1}],
    "sites": [
        {
            "id": "s-dal",
            "name": "Dallas Medical Center",
            "critical": 2,
            "warning": 0,
            "devices_total": 20,
            "devices_connected": 18,
            "availability": 90.0,
            "aps": 15,
            "aps_connected": 14,
            "switches": 4,
            "switches_connected": 3,
            "gateways": 1,
            "gateways_connected": 1,
        },
        {
            "id": "s-hou",
            "name": "Houston Medical Center",
            "critical": 0,
            "warning": 1,
            "devices_total": 20,
            "devices_connected": 19,
            "availability": 95.0,
            "aps": 18,
            "aps_connected": 17,
            "switches": 2,
            "switches_connected": 2,
            "gateways": 0,
            "gateways_connected": 0,
        },
        {
            "id": "s-aus",
            "name": "Austin Clinic",
            "critical": 0,
            "warning": 0,
            "devices_total": 12,
            "devices_connected": 12,
            "availability": 100.0,
            "aps": 10,
            "aps_connected": 10,
            "switches": 2,
            "switches_connected": 2,
            "gateways": 0,
            "gateways_connected": 0,
        },
    ],
}

DEVICES = [
    {
        "name": "SW-CORE-01",
        "type": "switch",
        "mac": "aabbccddee01",
        "site_id": "s-dal",
        "connected": True,
        "model": "EX4400",
        "version": "23.4R2",
    },
    {
        "name": "SW-IDF-2",
        "type": "switch",
        "mac": "aabbccddee02",
        "site_id": "s-dal",
        "connected": False,
        "model": "EX4400",
        "version": "22.4R3",
    },
    {
        "name": "AP-LOBBY-2",
        "type": "ap",
        "mac": "aabbccddee05",
        "site_id": "s-hou",
        "connected": True,
        "model": "AP45",
        "version": "0.14",
    },
]


class FakeSource(svc.AssistantSource):
    def __init__(self):
        self.client = type("C", (), {"configured": True})()
        self._memo = {}
        self.calls = []

    def sites(self):
        return SITES

    def dashboard(self):
        return json.loads(json.dumps(DASH))

    def devices(self):
        return DEVICES

    def search(self, query, site_id=None):
        self.calls.append(("search", query, site_id))
        if "core" in query.lower():
            return {
                "results": [
                    {
                        "kind": "infrastructure",
                        "device_type": "switch",
                        "mac": "aabbccddee01",
                        "title": "SW-CORE-01",
                        "site_id": "s-dal",
                        "site": "Dallas Medical Center",
                        "display_mac": "aa:bb:cc:dd:ee:01",
                    }
                ]
            }
        if query in {"10.20.30.55", "aa:bb:cc:dd:ee:99"}:
            return {
                "results": [
                    {
                        "kind": "wired_client",
                        "mac": "aabbccddee99",
                        "title": "jdoe-laptop",
                        "site_id": "s-dal",
                        "site": "Dallas Medical Center",
                        "attachment": "SW-IDF-2",
                        "attachment_mac": "aabbccddee02",
                        "port_id": "ge-0/0/5",
                        "ip": "10.20.30.55",
                        "display_mac": "aa:bb:cc:dd:ee:99",
                    }
                ]
            }
        return {"results": [], "errors": []}

    def detail(self, kind, mac, site_id=None):
        if kind == "infrastructure":
            return {
                "identity": {
                    "title": "SW-CORE-01",
                    "mac": "aa:bb:cc:dd:ee:01",
                    "ip": "10.0.0.2",
                    "site": "Dallas Medical Center",
                },
                "connection": {"type": "Switch", "status": "Connected", "last_seen": "2026-10-09T10:00:00Z"},
                "device": {"model": "EX4400-48P", "version": "23.4R2", "status": "Connected"},
                "ports_summary": {"total": 48, "up": 30, "down": 18, "poe_on": 12},
                "alarms": [{"type": "SW_ALARM_VIRTUAL_CHASSIS_VERSION_MISMATCH"}],
            }
        return {
            "identity": {
                "title": "jdoe-laptop",
                "mac": "aa:bb:cc:dd:ee:99",
                "ip": "10.20.30.55",
                "site": "Dallas Medical Center",
            },
            "connection": {
                "type": "Wired",
                "status": "Connected",
                "switch": "SW-IDF-2",
                "port_id": "ge-0/0/5",
                "vlan": "20",
            },
            "port": {"up": True, "speed": "1 Gbps"},
        }

    def audit(self, duration):
        self.calls.append(("audit", duration))
        return [
            {
                "admin_name": "Ana",
                "message": "Updated switch SW-CORE-01 port config",
                "site_id": "s-dal",
                "timestamp": 1791215100,
            },
            {"admin_name": "Ben", "message": "Updated WLAN Guest", "site_id": "s-hou", "timestamp": 1791214100},
        ]

    def switches(self, site_id):
        return [{"id": "dev-core", "name": "SW-CORE-01", "mac": "aabbccddee01"}] if site_id == "s-dal" else []

    def switch_ports(self, site_id, device_id):
        return {
            "ports": [
                {
                    "port_id": "ge-0/0/1",
                    "up": True,
                    "speed": "1 Gbps",
                    "poe_on": True,
                    "poe_watts": 12.5,
                    "neighbor_system_name": "AP-3F-2",
                },
                {"port_id": "ge-0/0/2", "up": False, "speed": "—"},
                {"port_id": "ge-0/0/3", "up": True, "speed": "1 Gbps", "rx_errors": 40},
                {"port_id": "vme", "up": True, "internal": True},
            ],
            "warnings": [],
        }

    def poe(self, site_id, device_id):
        return {
            "draw_watts": 450.0,
            "budget_watts": 500.0,
            "utilization_pct": 90.0,
            "powered_ports": 20,
            "risks": [{"severity": "critical", "title": "PoE budget above 90%", "detail": "90.0% used"}],
            "ports": [{"port_id": "ge-0/0/1", "poe_watts": 30.1, "neighbor_system_name": "AP-3F-2"}],
            "per_member": [],
        }


def ask(q):
    return svc.ask(q, FakeSource())


def _texts(ans):
    return " ".join([ans["headline"]] + [f["text"] for f in ans["facts"]])


def test_summary_answer_lists_down_devices_by_type():
    a = ask("what's broken?")
    assert a["intent"] == "summary" and a["tone"] == "critical"
    assert a["headline"] == "3 devices are down and 2 critical conditions are open."
    text = _texts(a)
    assert "Switches down (1): SW-IDF-2 (Dallas Medical Center)" in text
    assert "APs down (2)" in text and "VC firmware version mismatch" in text
    assert "Multiple devices disconnected: Dallas Medical Center, 2 of 20 devices down." in text
    assert any(c["action"] == {"type": "tool", "tool": "dashboard"} for c in a["chips"])
    assert any(c["action"]["type"] == "device" and c["label"] == "SW-IDF-2" for c in a["chips"])
    assert 4 <= len(a["suggestions"]) <= 6
    assert a["spoken"].startswith(a["headline"])


def test_site_status_answer_uses_fuzzy_site():
    a = ask("how is dalas doing")
    assert a["intent"] == "site_status" and a["scope"]["site_id"] == "s-dal"
    assert a["headline"].startswith("Dallas Medical Center: 2 of 20 devices are down")
    assert "Connected: APs 14/15, Switches 3/4, Gateways 1/1 (90.0% available)" in _texts(a)
    assert any(c["action"] == {"type": "site", "site_id": "s-dal"} for c in a["chips"])


def test_healthy_site():
    a = ask("issues at austin")
    assert a["tone"] == "ok" and a["headline"].startswith("Austin Clinic looks healthy")


def test_ambiguous_site_asks_which():
    a = ask("how is medical center")
    assert a["headline"] == "Which site did you mean?"
    assert {c["action"]["question"] for c in a["chips"]} == {
        "How is Dallas Medical Center?",
        "How is Houston Medical Center?",
    }


def test_down_filters_kind_and_site():
    a = ask("which aps are down")
    assert a["headline"] == "2 access points are down."
    a = ask("which switches are down at houston")
    assert a["tone"] == "ok" and a["headline"] == "No switches are down at Houston Medical Center."
    a = ask("what's down")
    assert "1 known-down device hidden" in _texts(a)


def test_locate_infrastructure():
    a = ask("is SW-CORE-01 up?")
    assert a["intent"] == "locate"
    assert a["headline"] == "SW-CORE-01 is up (connected) at Dallas Medical Center."
    text = _texts(a)
    assert "EX4400-48P" in text and "Ports: 30 up, 18 down, 12 delivering PoE." in text
    assert "virtual chassis version mismatch" in text  # alarm type shown in words, not raw codes
    kinds = {c["action"]["type"] for c in a["chips"]}
    assert {"device", "switch"} <= kinds


def test_locate_client_by_ip_and_mac():
    for q in ("where is 10.20.30.55", "where is aa:bb:cc:dd:ee:99"):
        a = ask(q)
        assert (
            "jdoe-laptop is a wired client at Dallas Medical Center, on switch SW-IDF-2 port ge-0/0/5." == a["headline"]
        )
        assert "VLAN 20" in _texts(a)
        assert any(
            c["action"].get("tool") == "operations" and c["action"].get("mac") == "aabbccddee02" for c in a["chips"]
        )


def test_locate_not_found():
    a = ask("where is ghost-box9")
    assert a["tone"] == "warning" and "couldn't find" in a["headline"]


def test_changes_uses_audit_duration_and_site():
    src = FakeSource()
    a = svc.ask("what changed at dallas this week", src)
    assert ("audit", "7d") in src.calls
    assert a["headline"].startswith("1 change recorded in Mist in the last 7 days at Dallas Medical Center")
    assert any(c["action"] == {"type": "tool", "tool": "history"} for c in a["chips"])


def test_poe_on_switch():
    a = ask("PoE on sw-core-01")
    assert a["headline"] == "SW-CORE-01 is delivering 450.0 W of its 500 W PoE budget (90%) to 20 powered ports."
    assert a["tone"] == "critical"
    assert any(
        c["action"]
        == {"type": "switch", "tool": "poe", "site_id": "s-dal", "device_id": "dev-core", "mac": "aabbccddee01"}
        for c in a["chips"]
    )


def test_poe_at_site():
    a = ask("poe at dallas")
    assert a["headline"].startswith("Dallas Medical Center: 450.0 W of PoE across 20 powered ports on 1 switch")


def test_ports_on_switch_and_single_port():
    a = ask("ports on SW-CORE-01")
    assert a["headline"] == "SW-CORE-01: 2 of 3 ports are up, 1 down, 1 delivering PoE."
    assert "ge-0/0/3 (40)" in _texts(a)
    a = ask("is ge-0/0/2 up on SW-CORE-01")
    assert a["headline"] == "Port ge-0/0/2 on SW-CORE-01 is down." and a["tone"] == "critical"


def test_vc_and_top_answers():
    a = ask("virtual chassis problems")
    assert a["intent"] == "vc" and "1 virtual chassis reporting problems" in a["headline"]
    assert any(c["action"] == {"type": "tool", "tool": "virtual-chassis"} for c in a["chips"])
    a = ask("top problems")
    assert a["headline"] == "Dallas Medical Center has the most problems right now."
    assert a["facts"][0]["text"].startswith("Dallas Medical Center: 2 criticals, 2 down")


def test_help_and_unknown_have_examples():
    for q in ("help", "blorp zzz"):
        a = ask(q)
        assert len(a["facts"]) >= 5 and 4 <= len(a["suggestions"]) <= 6


def test_mist_error_becomes_answer_card():
    class Broken(FakeSource):
        def dashboard(self):
            raise svc.MistApiError("Mist API returned 503", 503)

    a = svc.ask("what's broken", Broken())
    assert a["intent"] == "error" and "couldn't read" in a["headline"]


def test_answers_never_contain_raw_json():
    for q in (
        "what's broken",
        "how is dallas",
        "what's down",
        "is SW-CORE-01 up",
        "what changed today",
        "top problems",
    ):
        a = ask(q)
        for f in a["facts"]:
            assert "{" not in f["text"] and "SW_ALARM" not in f["text"]


def test_router_returns_answer_card_on_unexpected_error(monkeypatch):
    from app.modules.ai_engineer import router

    def boom(_q):
        raise RuntimeError("kaput")

    monkeypatch.setattr(router, "ask", boom)
    out = router.ask_q({"question": "status"})
    assert out["intent"] == "error" and out["chips"]


# --------------------------------------------------------------------------- frontend wiring


def test_page_markup_and_script_wiring():
    html = (ROOT / "app/templates/index.html").read_text(encoding="utf-8")
    start = html.index('id="view-ai-engineer"')
    section = html[start : html.index("</section>\n", html.index("ai-shell", start))]
    for needle in ('id="aiThread"', 'id="aiQuestion"', 'id="aiAsk"', 'id="aiMic"', 'id="aiSpeak"', 'id="aiMarvis"'):
        assert needle in section
    assert "style=" not in section
    js = (ROOT / "app/static/modules/ai-engineer.js").read_text(encoding="utf-8")
    for needle in (
        "SpeechRecognition",
        "webkitSpeechRecognition",
        "speechSynthesis",
        "localStorage",
        "openTool",
        "manage",
    ):
        assert needle in js
    assert "innerHTML = d." not in js  # answers are escaped before rendering


def test_site_name_containing_help_words_is_not_help():
    sites = [{"id": "ex", "name": "Example Medical Center"}, {"id": "rc", "name": "Remote Campus"}]
    i = parse("how is example medcal", sites)
    assert (i.name, i.site_name) == ("site_status", "Example Medical Center")


def test_locate_prefers_the_device_itself_over_attached_clients():
    rows = [
        {"kind": "wireless_client", "title": "jsmith-iphone", "attachment": "AP-1", "mac": "aa"},
        {"kind": "infrastructure", "title": "AP-1", "mac": "bb"},
    ]
    assert svc._rank_exact(rows, "ap-1")[0]["title"] == "AP-1"
    assert svc._rank_exact(rows, "nothing")[0]["title"] == "jsmith-iphone"  # otherwise keep search relevance


def test_locate_device_known_only_through_attached_clients():
    class Src(FakeSource):
        def search(self, query, site_id=None):
            return {
                "results": [
                    {
                        "kind": "wireless_client",
                        "title": "jsmith-iphone",
                        "attachment": "AP-3F-1",
                        "site": "Dallas Medical Center",
                        "mac": "cc",
                        "display_mac": "cc",
                    }
                ]
            }

    a = svc.ask("is AP-3F-1 up?", Src())
    assert a["headline"] == "AP-3F-1 is down (disconnected) at Dallas Medical Center."
