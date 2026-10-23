from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]


def test_sls_settings_markup():
    html = (ROOT / "app" / "templates" / "index.html").read_text(encoding="utf-8")
    section = html.split(">Strata Logging Service<", 1)[1].split("</section>", 1)[0]
    assert 'id="slsSave"' not in html
    assert "Save Integration" not in section
    assert "Verify Again" in section
    for element_id in ("slsEnabled", "slsTest", "slsReset", "slsQueryHost", "slsTenant"):
        assert f'id="{element_id}"' in section
    # The wiring itself is exercised in tests/js/settings_sls.test.cjs.


def _js_const(source: str, name: str) -> str:
    return re.search(rf"const {name} = [\"']([^\"']+)[\"'];", source).group(1)


def test_frontend_and_backend_version_match():
    version_py = (ROOT / "app" / "core" / "version.py").read_text(encoding="utf-8")
    core_js = (ROOT / "app" / "static" / "core.js").read_text(encoding="utf-8")
    backend_version = re.search(r'APP_VERSION = "([^"]+)"', version_py).group(1)
    backend_build = re.search(r'APP_BUILD = "([^"]+)"', version_py).group(1)
    assert _js_const(core_js, "FRONTEND_VERSION") == backend_version
    assert _js_const(core_js, "FRONTEND_BUILD") == backend_build
