"""v0.10.13 Traffic & Sessions: every Palo Alto field reaches the UI, denied/dropped logs are kept,
type/decrypted are mapped, and live mode asks only for the newest minutes."""

from __future__ import annotations

from datetime import datetime, timezone

from app.integrations.query import NodeWatchQuery, QueryFilter
from app.integrations.providers import traffic as traffic_mod
from tests.test_strata_logviewer_v0107 import (  # noqa: F401  (fixture re-used)
    FakeResponse,
    _clean_state,
    logviewer_payload,
    logviewer_row,
    make_provider,
)


def _query():
    return NodeWatchQuery(
        event_type="network.session",
        capability="traffic.sessions",
        filters=(QueryFilter("source_or_destination.ip", "eq", "10.9.166.26"),),
        start_time="2026-10-09T08:00:00+00:00",
        end_time="2026-10-09T09:00:00+00:00",
        page_size=100,
    )


def test_deny_and_drop_logs_are_returned_with_type_decrypted_and_all_fields():
    rows = [
        logviewer_row(
            1,
            "10.9.166.26",
            "10.100.30.142",
            1_791_500_000_000_000,
            action={"id": 1, "value": "deny"},
            sub_type={"id": 4, "value": "drop"},
            rule_matched="interzone-default",
            from_zone="IoT",
            to_zone="Trusted",
            dest_port=8514,
            is_decrypted=False,
            source_location="10.0.0.0-10.255.255.255",
            tunneled_app="untunneled",
            nested={"inner": {"value": "x"}},
        ),
        logviewer_row(2, "10.9.166.26", "45.60.31.181", 1_791_500_000_100_000, is_decrypted=True),
    ]
    provider, _ = make_provider(lambda url, body, headers: FakeResponse(logviewer_payload(rows)))
    sessions = [r.data["traffic"] for r in provider.query(_query()).records]
    deny = next(s for s in sessions if s["action"] == "deny")
    assert deny["type"] == "drop" and deny["decrypted"] == "no" and deny["rule"] == "interzone-default"
    fields = deny["fields"]
    # Fields Palo Alto sends that NodeWatch has no fixed column for are still available as columns.
    assert fields["source_location"] == "10.0.0.0-10.255.255.255" and fields["tunneled_app"] == "untunneled"
    assert fields["action"] == "deny" and fields["dest_port"] == 8514
    assert fields["time_generated"].startswith("2026-10-")  # µs epoch → ISO time
    assert all(not isinstance(v, (dict, list)) for v in fields.values())
    allow = next(s for s in sessions if s["action"] == "allow")
    assert allow["decrypted"] == "yes"


def test_live_mode_queries_only_recent_minutes(monkeypatch):
    seen = {}

    class Engine:
        def execute(self, query, provider_id):
            seen["start"] = query.start_time
            seen["end"] = query.end_time
            seen["fresh"] = query.fresh

            class R:
                public_dict = {"records": []}
                provider_id = "x"
                cursor = next_cursor = total = None
                has_more = False

            return R()

    monkeypatch.setattr(traffic_mod, "QUERY_ENGINE", Engine())
    monkeypatch.setattr(traffic_mod.TrafficSessionsProvider, "configured", property(lambda self: True))
    since = datetime.now(timezone.utc).timestamp() * 1000 - 60_000
    traffic_mod.get_traffic_sessions_provider().search_by_ip("10.9.166.26", window="1h", since_ms=int(since))
    start = datetime.fromisoformat(seen["start"])
    end = datetime.fromisoformat(seen["end"])
    assert 200 <= (end - start).total_seconds() <= 300  # ~1 min since newest row + 3 min overlap
    assert seen["fresh"] is True


def test_traffic_table_markup_and_component():
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    html = (root / "app/templates/index.html").read_text(encoding="utf-8")
    for el in (
        "tlApply",
        "tlClear",
        "tlAddFilter",
        "tlColumns",
        "tlExport",
        "tlLive",
        "tlFullscreen",
        "tlDetailDialog",
    ):
        assert f'id="{el}"' in html, el
    assert 'data-tl-action="deny"' in html and "/static/traffic-log.js" in html
    js = (root / "app/static/traffic-log.js").read_text(encoding="utf-8")
    assert "draggable" in js and "localStorage" in js and "fields" in js
