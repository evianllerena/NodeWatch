from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_version_shown_in_settings():
    html = (ROOT / "app/templates/index.html").read_text(encoding="utf-8")
    assert "Running version" in html and "{{ app_version }}" in html and "{{ app_build }}" in html


def test_launcher_and_backend_versions_match():
    import re

    version = (ROOT / "app/core/version.py").read_text(encoding="utf-8")
    src = (ROOT / "release/native_launcher.go").read_text(encoding="utf-8")
    assert re.search(r'appVersion\s*=\s*"([^"]+)"', src).group(1) == re.search(
        r'APP_VERSION = "([^"]+)"', version
    ).group(1)
    assert re.search(r'appBuild\s*=\s*"([^"]+)"', src).group(1) == re.search(r'APP_BUILD = "([^"]+)"', version).group(1)


def test_launcher_handles_global_python_venv_redirector():
    src = (ROOT / "release/native_launcher.go").read_text(encoding="utf-8")
    assert 'headerVersion := strings.TrimSpace(resp.Header.Get("X-NodeWatch-Version"))' in src
    assert 'headerBuild := strings.TrimSpace(resp.Header.Get("X-NodeWatch-Build"))' in src
    assert 'pythonHost := base == "python.exe" || base == "pythonw.exe"' in src
    assert 'retired stale NodeWatch backend' in src
    exact = src.split("func (l *launcher) findExistingExactBackend()", 1)[1].split("func probeBackend", 1)[0]
    assert "expectedPy :=" not in exact
    assert "return port, true" in exact
    # v0.10.7: reuse requires the per-install identity proof, not just a version match.
    assert "IdentityProof" in exact and "hmac.Equal" in exact


def test_build_mismatch_warning_is_not_overwritten():
    core = (ROOT / "app/static/core.js").read_text(encoding="utf-8")
    mismatch = core.split("function renderConnectionStatus(status)", 1)[1].split(
        "async function refreshConnectionStatus", 1
    )[0]
    assert "Build mismatch:" in mismatch
    assert "return;" in mismatch
