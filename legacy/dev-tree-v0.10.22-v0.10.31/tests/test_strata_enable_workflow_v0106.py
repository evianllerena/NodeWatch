from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_sls_diagnostics_cover_ui_oauth_query_and_persistence():
    settings = (ROOT / "app/static/modules/settings.js").read_text(encoding="utf-8")
    router = (ROOT / "app/modules/integrations/router.py").read_text(encoding="utf-8")
    auth = (ROOT / "app/integrations/providers/strata_logging_auth.py").read_text(encoding="utf-8")
    provider = (ROOT / "app/integrations/providers/strata_logging.py").read_text(encoding="utf-8")
    for event in ("SLS_UI_ENABLE_CLICKED", "SLS_UI_DISABLE_CLICKED", "SLS_UI_VERIFY_CLICKED", "SLS_UI_RESET_CLICKED"):
        assert event in settings and event in router
    for event in ("SLS_OAUTH_STARTED", "SLS_OAUTH_SUCCESS", "SLS_OAUTH_FAILED"):
        assert event in auth
    for event in ("SLS_QUERY_STARTED", "SLS_QUERY_SUCCESS", "SLS_QUERY_FAILED", "SLS_QUERY_HTTP_"):
        assert event in provider
    assert "SLS_VERIFICATION_SAVED" in router


# Verify-before-persist is now tested behaviourally in test_strata_logviewer_v0107.py
# (test_enable_failure_persists_nothing / test_enable_success_persists_verified_with_host).


def test_sls_http_errors_preserve_provider_detail_without_request_body_logging():
    provider = (ROOT / "app/integrations/providers/strata_logging.py").read_text(encoding="utf-8")
    diagnostics = (ROOT / "app/integrations/diagnostics.py").read_text(encoding="utf-8")
    assert "Provider response:" in provider
    assert '"request_body"' not in diagnostics
    assert '"authorization"' not in diagnostics.lower()
    assert "_ALLOWED_META_KEYS" in diagnostics
