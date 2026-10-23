"""Security tests for the local API, redaction, owner sessions, launcher identity and file locking (v0.10.7)."""

from __future__ import annotations

import hmac
import json
import threading
import zipfile

import pytest
from fastapi.testclient import TestClient

from app.core import security
from app.core.config import DATA_ROOT, STATE_ROOT
from app.core.file_utils import append_jsonl_rotating, locked_json_update, write_private_text
from app.core.security import WRITE_REQUEST_TOKEN, contains_secret_material, identity_proof, redact_text


@pytest.fixture
def anon():
    from app.main import app

    return TestClient(app, base_url="http://127.0.0.1")


@pytest.fixture
def api(anon):
    anon.headers.update({"X-NodeWatch-Request": WRITE_REQUEST_TOKEN})
    return anon


# ------------------------------------------------------------------ local API


@pytest.mark.parametrize(
    "path",
    [
        "/api/settings",
        "/api/status",
        "/api/v1/config-backup/snapshots",
        "/api/v1/config-backup/snapshot-detail?snapshot_id=x",
        "/api/integrations",
    ],
)
def test_reads_require_request_token(anon, path):
    assert anon.get(path).status_code == 403


def test_launcher_probe_is_open_but_minimal(anon):
    r = anon.get("/api/status?probe=true")
    assert r.status_code == 200
    body = r.json()
    assert body["version"] and "api_host" not in body and "organization" not in body


def test_cross_site_requests_blocked_even_with_token(api):
    assert api.get("/api/settings", headers={"Sec-Fetch-Site": "cross-site"}).status_code == 403


def test_token_allows_reads(api):
    assert api.get("/api/settings").status_code == 200


def test_status_reports_tls_verification(api):
    assert api.get("/api/status").json()["tls_verification_disabled"] is False


def test_home_page_serves_token_for_the_frontend(anon):
    assert WRITE_REQUEST_TOKEN in anon.get("/").text


# --------------------------------------------------------------- redaction


@pytest.mark.parametrize(
    "text,leak",
    [
        ('{"password": "hunter2"}', "hunter2"),
        ("{'psk': 'wifi-secret'}", "wifi-secret"),
        ('{"client_secret":"abc123xyz"}', "abc123xyz"),
        ('"api_key": "k-123456"', "k-123456"),
        ('{"private_key": "-----BEGIN KEY-----"}', "BEGIN KEY"),
        ("token=abcdef123", "abcdef123"),
        ('passphrase: "my pass phrase"', "my pass phrase"),
    ],
)
def test_redaction_covers_json_and_key_value_forms(text, leak):
    out = redact_text(text)
    assert leak not in out
    assert not contains_secret_material(out)


@pytest.mark.parametrize(
    "text", ['{"token_present": true}', '{"client_secret_present": false}', "SLS_TOKEN_EXCHANGE_FAILED: no"]
)
def test_redaction_leaves_non_secret_fields(text):
    assert redact_text(text) == text


# ------------------------------------------------------------ owner sessions


def test_owner_sessions_expire_when_idle(monkeypatch):
    clock = {"t": 1000.0}
    monkeypatch.setattr(security.time, "monotonic", lambda: clock["t"])
    token = security.create_owner_session()
    assert security.valid_owner_session(token)
    clock["t"] += security.OWNER_SESSION_IDLE_SECONDS - 1
    assert security.valid_owner_session(token)  # use refreshes idle timer
    clock["t"] += security.OWNER_SESSION_IDLE_SECONDS + 1
    assert not security.valid_owner_session(token)


def test_owner_sessions_have_absolute_lifetime(monkeypatch):
    clock = {"t": 0.0}
    monkeypatch.setattr(security.time, "monotonic", lambda: clock["t"])
    token = security.create_owner_session()
    while clock["t"] < security.OWNER_SESSION_MAX_SECONDS:
        clock["t"] += 600
        assert security.valid_owner_session(token)  # active use keeps it alive until the cap
    clock["t"] += 1
    assert not security.valid_owner_session(token)


def test_owner_lockout_is_per_client(api, monkeypatch):
    from app.modules.system import router as system_router

    monkeypatch.setattr(system_router, "_verify_owner_key", lambda key: False)

    system_router._owner_attempts.clear()
    for _ in range(system_router.OWNER_FREE_ATTEMPTS):
        api.post("/api/platform-overview/lock/verify", json={"owner_key": "wrong"}, headers={"User-Agent": "attacker"})
    locked = api.post(
        "/api/platform-overview/lock/verify", json={"owner_key": "wrong"}, headers={"User-Agent": "attacker"}
    )
    assert locked.status_code == 429
    other = api.post(
        "/api/platform-overview/lock/verify", json={"owner_key": "wrong"}, headers={"User-Agent": "owner-browser"}
    )
    assert other.status_code == 403  # not locked out by someone else's failures
    system_router._owner_attempts.clear()


# --------------------------------------------------------- launcher identity


def test_identity_proof_is_hmac_of_challenge_with_install_key():
    challenge = "ab" * 32
    proof = identity_proof(STATE_ROOT, challenge)
    key = bytes.fromhex((STATE_ROOT / security.IDENTITY_KEY_FILENAME).read_text())
    assert proof == hmac.new(key, ("nodewatch-identity:" + challenge).encode(), "sha256").hexdigest()
    assert identity_proof(STATE_ROOT, "not-hex") is None
    assert identity_proof(STATE_ROOT, "ab") is None  # too short


def test_probe_returns_identity_proof(anon):
    challenge = "cd" * 32
    body = anon.get(f"/api/status?probe=true&challenge={challenge}").json()
    assert body["identity_proof"] == identity_proof(STATE_ROOT, challenge)


# ------------------------------------------------------------- file locking


def test_locked_json_update_serializes_concurrent_writers(tmp_path):
    target = tmp_path / "counter.json"

    def bump():
        for _ in range(25):
            locked_json_update(target, lambda cur: {"n": (cur or {}).get("n", 0) + 1}, default={})

    threads = [threading.Thread(target=bump) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert json.loads(target.read_text())["n"] == 200


def test_write_private_text_leaves_no_temp_files(tmp_path):
    target = tmp_path / "settings.json"
    threads = [threading.Thread(target=write_private_text, args=(target, json.dumps({"i": i}))) for i in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert json.loads(target.read_text())["i"] in range(20)
    assert [p.name for p in tmp_path.iterdir() if p.name.endswith(".tmp")] == []


def test_jsonl_rotation(tmp_path):
    log = tmp_path / "timing.jsonl"
    for i in range(50):
        append_jsonl_rotating(log, {"i": i, "pad": "x" * 100}, max_bytes=1000)
    assert (tmp_path / "timing.jsonl.1").exists()
    lines = [json.loads(x) for x in log.read_text().splitlines()]
    assert lines and lines[-1]["i"] == 49


# ---------------------------------------------------------------- diagnostics


def test_diagnostics_export_redacts_summary_and_prunes_old_exports(api, monkeypatch):
    from app.integrations import diagnostics as diag

    diag.record_integration_event(
        provider="strata_logging_service",
        operation="SLS_QUERY_HTTP_403",
        ok=False,
        error='upstream said {"password": "leaky-pass"}',
    )
    for _ in range(7):
        r = api.post("/api/support/diagnostics")
        assert r.status_code == 200
    exports = sorted((DATA_ROOT / "exports").glob("NodeWatch-Diagnostics-*.zip"))
    assert len(exports) <= 5
    with zipfile.ZipFile(exports[-1]) as zf:
        everything = "".join(zf.read(n).decode("utf-8", "replace") for n in zf.namelist())
    assert "leaky-pass" not in everything


def test_owner_lockout_has_a_global_cap(api, monkeypatch):
    from app.modules.system import router as system_router

    monkeypatch.setattr(system_router, "_verify_owner_key", lambda key: False)  # skip 600k-iteration PBKDF2

    system_router._owner_attempts.clear()
    system_router._owner_global_failures.clear()
    system_router._owner_global_locked_until = 0.0
    for i in range(system_router.OWNER_GLOBAL_MAX_FAILURES):
        api.post("/api/platform-overview/lock/verify", json={"owner_key": "wrong"}, headers={"User-Agent": f"ua-{i}"})
    r = api.post("/api/platform-overview/lock/verify", json={"owner_key": "wrong"}, headers={"User-Agent": "fresh-ua"})
    assert r.status_code == 429
    assert len(system_router._owner_attempts) <= system_router.OWNER_MAX_TRACKED_CLIENTS
    system_router._owner_attempts.clear()
    system_router._owner_global_locked_until = 0.0
