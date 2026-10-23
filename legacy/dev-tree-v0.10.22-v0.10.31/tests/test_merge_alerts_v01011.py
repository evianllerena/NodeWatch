"""v0.10.11: Notification Hub lives inside Command Center; Change & Config Vault is Config Backups."""

from __future__ import annotations

from pathlib import Path

from app.core.registry import TOOLS, get_tools

ROOT = Path(__file__).resolve().parents[1]
HTML = (ROOT / "app/templates/index.html").read_text(encoding="utf-8")


def test_notification_hub_is_no_longer_a_menu_item():
    ids = [t["id"] for t in get_tools()]
    assert "alerting" not in ids and "dashboard" in ids
    hub = next(t for t in TOOLS if t["id"] == "alerting")
    assert hub["phase"] == "merged" and not hub["enabled"]


def test_alert_controls_live_in_command_center():
    assert 'id="view-alerting"' not in HTML
    dashboard = HTML[HTML.index('id="view-dashboard"') : HTML.index('id="view-detective"')]
    for control in (
        'id="nocAlerts"',
        'id="alertingFeed"',
        'id="alertingBrowser"',
        'id="alertingEnabled"',
        'id="alertingPoll"',
        'id="alertingWebhookUrl"',
        'id="alertingSave"',
        'id="alertingTest"',
    ):
        assert control in dashboard, control
    # alerting.js must load before dashboard.js, which starts it.
    assert HTML.index("modules/alerting.js") < HTML.index("modules/dashboard.js")


def test_old_alerting_links_redirect_to_command_center():
    core = (ROOT / "app/static/core.js").read_text(encoding="utf-8")
    assert "MERGED_TOOLS = { alerting: ['dashboard', '#nocAlerts'] }" in core


def test_config_backups_name():
    backup = next(t for t in TOOLS if t["id"] == "config-backup")
    assert backup["label"] == "Config Backups" and backup["short_label"] == "Backups"
    for where in (HTML, (ROOT / "app/static/core.js").read_text(encoding="utf-8")):
        assert "Config Vault" not in where and "Notification Hub" not in where
