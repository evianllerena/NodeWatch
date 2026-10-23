"""v0.10.12: Event Relay detail/labels, Splunk HEC hardening, human-readable Activity Log."""

from __future__ import annotations

import json
import shutil
import socket
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from app.modules.history import activity
from app.modules.history import router as history_router
from app.services import siem_service

ROOT = Path(__file__).resolve().parents[1]
SITE_ID = "11111111-2222-3333-4444-555555555555"
DEVICE_ID = "00000000-0000-0000-1000-aabbccddeeff"


class FakeClient:
    configured = True

    def __init__(self, alarms=None, device_events=None, audits=None):
        self.alarms = alarms or []
        self.device_events = device_events or []
        self.audits = audits or []

    def site_name_map(self):
        return {SITE_ID: "HQ"}

    def device_directory(self):
        entry = {"id": DEVICE_ID, "mac": "aabbccddeeff", "name": "SW-Core-1", "type": "switch", "site_id": SITE_ID}
        return {DEVICE_ID: entry, "aabbccddeeff": entry}

    def search_org_alarms(self):
        return self.alarms

    def search_org_device_events(self):
        return self.device_events

    def search_audit_logs(self, duration="7d"):
        return self.audits

    def clear_cache(self):
        pass


def _strings(value):
    if isinstance(value, dict):
        for v in value.values():
            yield from _strings(v)
    elif isinstance(value, list):
        for v in value:
            yield from _strings(v)
    elif isinstance(value, str):
        yield value


def _assert_no_json_dump(payload):
    for text in _strings(payload):
        stripped = text.strip()
        if stripped[:1] in "{[":
            with pytest.raises(ValueError):
                json.loads(stripped)


# ------------------------------------------------------------------ audit parsing


@pytest.mark.parametrize(
    ("message", "action", "obj", "name", "kind"),
    [
        ('Update Site Settings "HQ"', "Update", "Site Settings", "HQ", "changed"),
        ('Updated WLAN "Guest"', "Update", "WLAN", "Guest", "changed"),
        ('Delete Device Profile "Lobby APs"', "Delete", "Device Profile", "Lobby APs", "removed"),
        ('Assign Device "SW-1" to Site "HQ"', "Assign", "Device", "SW-1", "changed"),
        ("Claim Devices", "Claim", "Devices", "", "added"),
        ('Accessed Org "Acme"', "Access", "Org", "Acme", "neutral"),
        ('Login with Role "Super User"', "Login", "Role", "Super User", "neutral"),
        ("Logged out", "Logout", "", "", "neutral"),
        ("Remove Admin “bob@example.com”", "Remove", "Admin", "bob@example.com", "removed"),
        ("Something unusual", "Activity", "Something unusual", "", "neutral"),
    ],
)
def test_parse_audit_message(message, action, obj, name, kind):
    parsed = activity.parse_audit_message(message)
    assert (parsed["action"], parsed["object_type"], parsed["object_name"], parsed["kind"]) == (
        action,
        obj,
        name,
        kind,
    )


def test_user_agent_label():
    chrome = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0 Safari/537.36"
    )
    edge = chrome + " Edg/129.0"
    safari = "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15"
    assert activity.user_agent_label(chrome) == "Chrome on Windows"
    assert activity.user_agent_label(edge) == "Edge on Windows"
    assert activity.user_agent_label(safari) == "Safari on macOS"
    assert activity.user_agent_label("python-requests/2.31") == "Python script"
    assert activity.user_agent_label("") == ""


def test_humanize_type_and_mac():
    assert activity.humanize_type("SW_DISCONNECTED") == "Switch disconnected"
    assert activity.humanize_type("AP_RESTARTED") == "Access point restarted"
    assert activity.humanize_type("device_down") == "Device down"
    assert activity.format_mac("AABBCCDDEEFF") == "aa:bb:cc:dd:ee:ff"


# ------------------------------------------------------------------ diffs


def test_diff_flattening_with_json_strings_and_redaction():
    before = json.dumps(
        {
            "name": "Guest",
            "auth": {"type": "psk", "psk": "old-secret-123"},
            "vlan_ids": [10, 20],
            "port_config": {"ge-0/0/1": {"usage": "ap"}},
            "radius": [{"host": "10.0.0.1"}],
            "modified_time": 1,
            "legacy": "x",
        }
    )
    after = {
        "name": "Guest WiFi",
        "auth": {"type": "psk", "psk": "new-secret-456"},
        "vlan_ids": [10, 20, 30],
        "port_config": {"ge-0/0/1": {"usage": "iot"}},
        "radius": [{"host": "10.0.0.2"}],
        "modified_time": 2,
        "enabled": True,
    }
    changes = activity.diff_changes(before, after)
    by_path = {c["path"]: c for c in changes}
    assert by_path["name"] == {
        "path": "name",
        "label": "Name",
        "op": "changed",
        "before": "Guest",
        "after": "Guest WiFi",
    }
    assert by_path["vlan_ids"]["after"] == "10, 20, 30"
    assert by_path["port_config.ge-0/0/1.usage"]["label"] == "Port config › ge-0/0/1 › Usage"
    assert by_path["radius[0].host"]["before"] == "10.0.0.1"
    assert by_path["enabled"]["op"] == "added" and by_path["enabled"]["after"] == "Yes"
    assert by_path["legacy"]["op"] == "removed"
    assert "modified_time" not in by_path
    secret = by_path["auth.psk"]
    assert secret["op"] == "changed"
    assert secret["before"] == secret["after"] == activity.HIDDEN
    assert "old-secret-123" not in json.dumps(changes) and "new-secret-456" not in json.dumps(changes)


def test_diff_truncates_long_values():
    changes = activity.diff_changes({"note": "a"}, {"note": "b" * 5000})
    assert len(changes[0]["after"]) <= activity.MAX_VALUE_CHARS


# ------------------------------------------------------------------ history endpoint


def _audit_row():
    return {
        "id": "audit-1",
        "org_id": "org",
        "site_id": SITE_ID,
        "admin_name": "Jane Doe",
        "email": "jane@example.com",
        "src_ip": "10.1.2.3",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/129.0 Safari/537.36",
        "message": 'Update WLAN "Guest"',
        "timestamp": 1791428455.312705,
        "before": json.dumps({"ssid": "Guest", "psk": "abc12345"}),
        "after": {"ssid": "Guest-2", "psk": "zzz99999"},
    }


def test_history_normalizes_mist_audit_and_resolves_site(monkeypatch, tmp_path):
    monkeypatch.setattr(history_router, "get_mist_client", lambda: FakeClient(audits=[_audit_row()]))
    monkeypatch.setattr(history_router, "AUDIT_ROOT", tmp_path)
    (tmp_path / "20261009T003000123456Z_port_bounce.json").write_text(
        json.dumps(
            {
                "tool": "port-operations",
                "action": "profile_update",
                "site_id": SITE_ID,
                "device_id": DEVICE_ID,
                "port_id": "ge-0/0/5",
                "before": {"port": {"usage": "ap", "description": ""}},
                "request": {"port_config": {"ge-0/0/5": {"usage": "iot"}}},
                "after": {"port": {"usage": "iot", "description": ""}},
                "verified": True,
            }
        ),
        encoding="utf-8",
    )
    result = history_router.history(refresh=False, duration="7d")
    row = result["mist_logs"][0]
    assert row["site"] == "HQ"
    assert row["action"] == "Update" and row["action_kind"] == "changed"
    assert row["what"] == "WLAN “Guest”"
    assert row["user_agent"] == "Chrome on Windows"
    assert row["summary"].startswith("Jane Doe updated WLAN “Guest” at HQ from 10.1.2.3 using Chrome on Windows")
    assert {c["path"] for c in row["changes"]} == {"ssid", "psk"}
    assert "details" not in row
    local = result["local_changes"][0]
    assert local["tool"] == "Port Toolkit"
    assert local["verified"] is True
    assert "SW-Core-1" in local["target"] and "HQ" in local["target"] and "ge-0/0/5" in local["target"]
    assert local["changes"] == [
        {
            "path": "port.usage",
            "label": "Port › Usage",
            "op": "changed",
            "before": "ap",
            "after": "iot",
        }
    ]
    assert "payload" not in local
    _assert_no_json_dump(result)
    assert "abc12345" not in json.dumps(result) and "zzz99999" not in json.dumps(result)


# ------------------------------------------------------------------ relay events


def test_severity_normalization_and_cef():
    norm = siem_service.normalize_severity
    assert [norm(x) for x in ("critical", "major", "minor", "warn", "warning", "info", "", "weird")] == [
        "critical",
        "critical",
        "warning",
        "warning",
        "warning",
        "info",
        "info",
        "info",
    ]
    assert "|9|" in siem_service._cef_line({"severity": "major", "event_type": "X"})
    assert "|5|" in siem_service._cef_line({"severity": "minor", "event_type": "X"})
    assert "|2|" in siem_service._cef_line({"severity": "info", "event_type": "X"})


def test_relay_events_are_labelled(monkeypatch):
    client = FakeClient(
        alarms=[
            {
                "id": "a1",
                "org_id": "org",
                "type": "SW_DISCONNECTED",
                "severity": "major",
                "site_id": SITE_ID,
                "timestamp": 1791428455.312705,
                "last_seen": 1791428455.0,
                "macs": ["aabbccddeeff"],
                "count": 2,
            }
        ],
        audits=[_audit_row()],
    )
    monkeypatch.setattr(siem_service, "get_mist_client", lambda: client)
    monkeypatch.setattr(
        siem_service,
        "get_settings",
        lambda: type("S", (), {"api_host": "https://api.eu.mist.com", "org_id": "ORG"})(),
    )
    events = siem_service.display_events(50)
    alarm = next(e for e in events if e["source"] == "alarm")
    assert alarm["severity"] == "critical" and alarm["severity_raw"] == "major"
    assert alarm["title"] == "Switch disconnected"
    assert alarm["site_name"] == "HQ"
    assert alarm["device_name"] == "SW-Core-1"
    assert alarm["epoch_ms"] == 1791428455312
    assert alarm["mist_url"] == f"https://manage.eu.mist.com/admin/?org_id=ORG#!switch/detail/{DEVICE_ID}/{SITE_ID}"
    labels = {d["label"]: d for d in alarm["details"]}
    assert labels["Last seen"]["kind"] == "time"
    assert labels["Count"]["value"] == "2"
    assert "ID" not in labels and "Org ID" not in labels
    audit = next(e for e in events if e["source"] == "audit")
    assert audit["event_type"] == "Update WLAN"
    assert audit["title"] == "Jane Doe updated WLAN “Guest”"
    assert all("raw" not in e for e in events)
    _assert_no_json_dump(events)


@pytest.mark.parametrize(
    ("api", "manage"),
    [
        ("https://api.mist.com", "manage.mist.com"),
        ("https://api.eu.mist.com", "manage.eu.mist.com"),
        ("https://api.gc1.mist.com", "manage.gc1.mist.com"),
        ("https://api.ac2.mist.com", "manage.ac2.mist.com"),
    ],
)
def test_manage_host(api, manage):
    assert activity.manage_host(api) == manage


def test_mist_link_fallbacks():
    url = activity.mist_device_url(
        "https://api.mist.com", "ORG", site_id="S", device_type="ap", mac="aa:bb:cc:dd:ee:ff"
    )
    assert url.endswith("#!ap/detail/00000000-0000-0000-1000-aabbccddeeff/S")
    assert activity.mist_device_url("https://api.mist.com", "ORG", site_id="S").endswith("#!dashboard/insights/S")
    assert activity.mist_device_url("https://api.mist.com", "", site_id="S") == ""


# ------------------------------------------------------------------ Splunk HEC


def test_hec_endpoint_validation():
    norm = siem_service._normalize_splunk_endpoint
    assert (
        norm("https://http-inputs-leonmedical.splunkcloud.com")
        == "https://http-inputs-leonmedical.splunkcloud.com/services/collector/event"
    )
    assert (
        norm("https://http-inputs.leonmedical.splunkcloud.com/")
        == "https://http-inputs.leonmedical.splunkcloud.com/services/collector/event"
    )
    assert norm("https://http-inputs.acme.splunkcloudgc.com").endswith("/services/collector/event")
    assert norm("https://prd-p-abc.splunkcloud.com:8088").endswith(":8088/services/collector/event")
    with pytest.raises(ValueError, match="http-inputs-leonmedical.splunkcloud.com/services/collector/event"):
        norm("https://leonmedical.splunkcloud.com")
    with pytest.raises(ValueError, match="/services/collector/event"):
        norm("https://splunk.example.com:8088/services/collector/raw")
    assert (
        siem_service.suggest_hec_url("https://leonmedical.splunkcloud.com/en-US/app/launcher/home")
        == "https://http-inputs-leonmedical.splunkcloud.com/services/collector/event"
    )
    assert siem_service.suggest_hec_url("https://http-inputs-x.splunkcloud.com") == ""


def test_hec_chunking_respects_limit():
    lines = [b"x" * 100_000 for _ in range(12)]
    chunks = siem_service._chunk_payloads(lines, max_bytes=512 * 1024)
    assert all(len(c) <= 512 * 1024 for c in chunks)
    assert sum(len(c) for c in chunks) == 1_200_000
    assert len(chunks) == 3
    big = siem_service._chunk_payloads([b"y" * 600_000, b"z"], max_bytes=512 * 1024)
    assert [len(c) for c in big] == [600_000, 1]


class _HecHandler(BaseHTTPRequestHandler):
    requests: list = []

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length)
        type(self).requests.append({"path": self.path, "headers": dict(self.headers), "body": body})
        if self.headers.get("Authorization") != "Splunk test-token":
            self.send_response(403)
            payload = b'{"text":"Invalid token","code":4}'
        else:
            self.send_response(200)
            payload = b'{"text":"Success","code":0}'
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):
        pass


@pytest.fixture
def hec_server():
    _HecHandler.requests = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _HecHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server
    server.shutdown()
    server.server_close()


def test_hec_delivery_to_local_emulator(monkeypatch, hec_server):
    monkeypatch.setattr(siem_service, "load_secret", lambda *a, **k: "test-token")
    monkeypatch.setattr(siem_service, "HEC_MAX_POST_BYTES", 2048)
    port = hec_server.server_address[1]
    cfg = {"splunk_url": f"http://127.0.0.1:{port}", "splunk_index": "nodewatchtest", "verify_tls": True}
    events = [
        {"timestamp": 1791428455.3 + i, "source": "alarm", "severity": "info", "message": "m" * 300} for i in range(20)
    ]
    siem_service._send_splunk(events, cfg)
    reqs = _HecHandler.requests
    assert len(reqs) > 1, "batch must be split into several POSTs"
    assert all(r["path"] == "/services/collector/event" for r in reqs)
    channels = {r["headers"].get("X-Splunk-Request-Channel") for r in reqs}
    assert len(channels) == 1 and len(next(iter(channels))) == 36
    delivered = [json.loads(line) for r in reqs for line in r["body"].decode().replace("}{", "}\n{").splitlines()]
    assert len(delivered) == 20
    assert all(e["index"] == "nodewatchtest" for e in delivered)
    assert all(len(r["body"]) <= 2048 for r in reqs)


def test_hec_rejection_is_reported(monkeypatch, hec_server):
    monkeypatch.setattr(siem_service, "load_secret", lambda *a, **k: "wrong-token")
    port = hec_server.server_address[1]
    with pytest.raises(RuntimeError, match="HTTP 403: Invalid token"):
        siem_service._send_splunk([{"timestamp": 1, "message": "x"}], {"splunk_url": f"http://127.0.0.1:{port}"})


def test_hec_timeout_message(monkeypatch):
    monkeypatch.setattr(siem_service, "load_secret", lambda *a, **k: "test-token")
    monkeypatch.setattr(siem_service, "HEC_TIMEOUT_SECONDS", 1)
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)  # accepts the TCP connection but never answers
    port = listener.getsockname()[1]
    try:
        start = time.monotonic()
        with pytest.raises(RuntimeError) as exc:
            siem_service._send_splunk([{"timestamp": 1, "message": "x"}], {"splunk_url": f"http://127.0.0.1:{port}"})
        assert time.monotonic() - start < 10
        assert str(exc.value).startswith(f"Could not reach 127.0.0.1:{port} within 1 s")
        assert "proxy/firewall" in str(exc.value)
    finally:
        listener.close()


def test_high_water_mark_prevents_backlog_resend():
    events = [{"timestamp": 1_000_000.0 + i * 60, "source": "alarm", "code": "X", "message": str(i)} for i in range(10)]
    newest_first = list(reversed(events))
    state: dict = {}
    fresh = siem_service.select_fresh_events(newest_first, state)
    assert len(fresh) == 10 and fresh[0]["message"] == "0"
    siem_service.mark_sent(fresh, state)
    assert state["last_ts"] == 1_000_000.0 + 9 * 60
    # Dedupe keys lost (e.g. state trimmed): the high-water mark alone still blocks the old backlog.
    state_without_keys = {"last_ts": state["last_ts"]}
    assert siem_service.select_fresh_events(newest_first, state_without_keys) == [
        e for e in events if e["timestamp"] >= state["last_ts"] - siem_service.HIGH_WATER_GRACE_SECONDS
    ]
    newer = {"timestamp": state["last_ts"] + 30, "source": "alarm", "code": "X", "message": "new"}
    assert siem_service.select_fresh_events([newer, *newest_first], state) == [newer]
    # Upgrade path: an existing state with sent keys but no last_ts uses the last success time.
    legacy = {"sent_keys": ["abc"], "last_success": "1970-01-12T13:46:40+00:00"}
    assert siem_service._high_water(legacy) == 1_000_000.0


# ------------------------------------------------------------------ frontend rendering

NODE = shutil.which("node")

_JS = r"""
const { createContext, loadModule } = require(process.argv[2] + '/tests/js/dom_stub.cjs');
const { context, elements } = createContext();
context.window.MistTools = {};
loadModule(context, 'app/static/modules/siem.js');
loadModule(context, 'app/static/modules/history.js');
const siem = context.window.MistTools.siem._test;
const hist = context.window.MistTools.history._test;
const ev = {
  timestamp: 1791428455.312705, epoch_ms: 1791428455312, source: 'alarm', severity: 'major', severity_raw: 'major',
  event_type: 'SW_DISCONNECTED', code: 'SW_DISCONNECTED', title: 'Switch disconnected', site_id: 'S1', site_name: 'HQ <b>',
  device_mac: 'aabbccddeeff', device_name: 'SW-1', message: 'Switch removed', mist_url: 'https://manage.mist.com/admin/?org_id=O#!switch/detail/D/S1',
  details: [{ label: 'Last seen', value: 1791428455000, kind: 'time' }, { label: 'Count', value: '2', kind: 'text' }], changes: [],
};
siem.setEvents([ev, { ...ev, severity: 'minor', epoch_ms: 1, site_name: 'Branch', message: 'committed config' }]);
siem.render();
const rows = elements.get('#siemRows').innerHTML;
const detail = siem.eventDetailHtml(ev);
const out = {
  sev: ['critical', 'major', 'minor', 'warn', 'warning', 'info', 'x'].map(siem.sevNorm),
  hec: siem.suggestHecUrl('https://leonmedical.splunkcloud.com'),
  hecNone: siem.suggestHecUrl('https://http-inputs-leonmedical.splunkcloud.com'),
  rows, detail,
};
elements.get('#siemSearch').value = 'branch';
siem.render();
out.searchRows = elements.get('#siemRows').innerHTML;
hist.setData({
  mist_logs: [{ timestamp: 1791428455, admin: 'Jane', action: 'Delete', action_kind: 'removed', what: 'WLAN “Guest”', site: 'HQ',
    src_ip: '10.1.2.3', summary: 'Jane deleted WLAN “Guest”', message: 'Delete WLAN "Guest"',
    changes: [{ path: 'ssid', label: 'SSID', op: 'removed', before: 'Guest', after: '' }] }],
  local_changes: [{ timestamp: 1791428000, tool: 'Port Toolkit', action: 'Bounce', target: 'SW-1 · HQ', verified: false,
    request: [{ label: 'Ports', value: 'ge-0/0/1', kind: 'text' }], result: [], changes: [] }],
  errors: [],
});
hist.render();
out.mistRows = elements.get('#mistAuditRows').innerHTML;
out.localRows = elements.get('#localAuditRows').innerHTML;
out.mistDetail = hist.mistDetailHtml({ timestamp: 1791428455, admin: 'Jane', action: 'Delete', action_kind: 'removed',
  summary: 'Jane deleted WLAN', changes: [{ path: 'ssid', label: 'SSID', op: 'removed', before: 'Guest', after: '' }] });
out.localDetail = hist.localDetailHtml({ timestamp: 1791428000, tool: 'Port Toolkit', verified: true,
  request: [{ label: 'Ports', value: 'ge-0/0/1', kind: 'text' }], result: [{ label: 'Verified', value: 'Yes', kind: 'text' }],
  changes: [{ path: 'port.usage', label: 'Port › Usage', op: 'changed', before: 'ap', after: 'iot' }] });
console.log(JSON.stringify(out));
"""


@pytest.mark.skipif(NODE is None, reason="Node.js not installed")
def test_frontend_renders_labels_not_json(tmp_path):
    script = tmp_path / "relay_activity.cjs"
    script.write_text(_JS, encoding="utf-8")
    result = subprocess.run([NODE, str(script), str(ROOT)], capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stderr
    out = json.loads(result.stdout.strip().splitlines()[-1])
    assert out["sev"] == ["critical", "critical", "warning", "warning", "warning", "info", "info"]
    assert out["hec"] == "https://http-inputs-leonmedical.splunkcloud.com/services/collector/event"
    assert out["hecNone"] == ""
    rows = out["rows"]
    assert 'data-sort="1791428455312"' in rows
    assert "1791428455.312705" not in rows
    assert "nw-sev-critical" in rows and "nw-sev-warning" in rows
    assert "siem-change-deleted" in rows and "nw-change-deleted" in rows
    assert "HQ &lt;b&gt;" in rows and "HQ <b>" not in rows
    assert "Switch disconnected" in rows
    assert "Branch" in out["searchRows"] and "HQ &lt;b&gt;" not in out["searchRows"]
    detail = out["detail"]
    assert 'target="_blank" rel="noopener"' in detail
    assert "aa:bb:cc:dd:ee:ff" in detail and "Last seen" in detail and "Count" in detail
    assert "(Mist: major)" in detail
    assert "nw-action-removed" in out["mistRows"] and "10.1.2.3" in out["mistRows"]
    assert "Not verified" in out["localRows"]
    assert "What changed" in out["mistDetail"] and "nw-op-removed" in out["mistDetail"]
    assert "Requested change" in out["localDetail"] and "nw-op-changed" in out["localDetail"]
    for key in ("rows", "detail", "mistRows", "localRows", "mistDetail", "localDetail"):
        assert '{"' not in out[key] and "&quot;:" not in out[key], f"{key} must not contain a JSON dump"


def test_templates_have_no_json_view_for_relay_or_activity():
    html = (ROOT / "app/templates/index.html").read_text(encoding="utf-8")
    assert '<pre id="auditDetailBody"' not in html
    assert 'id="siemEventDialog"' in html
    js = (ROOT / "app/static/modules/history.js").read_text(encoding="utf-8")
    js += (ROOT / "app/static/modules/siem.js").read_text(encoding="utf-8")
    assert "JSON.stringify(payload, null" not in js and "JSON.stringify(e)" not in js
