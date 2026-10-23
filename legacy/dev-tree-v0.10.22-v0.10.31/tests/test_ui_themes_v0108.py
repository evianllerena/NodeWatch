"""UI theme system: definitions, generated CSS, preference API and region names."""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.core.security import WRITE_REQUEST_TOKEN
from app.ui.themes import THEMES

ROOT = Path(__file__).resolve().parents[1]
REQUIRED = {
    "label",
    "description",
    "mode",
    "accent_hue",
    "gray_hue",
    "gray_saturation",
    "background",
    "sidebar",
    "nav",
    "radius",
    "density",
    "cards",
    "font",
    "page_description",
    "shell",
    "buttons",
    "primary_button",
    "backdrop",
    "title",
    "labels",
    "font_mono",
    "details",
    "content_width",
    "night_background",
}


@pytest.fixture
def api():
    from app.main import app

    client = TestClient(app, base_url="http://127.0.0.1")
    client.headers.update({"X-NodeWatch-Request": WRITE_REQUEST_TOKEN})
    return client


def test_every_theme_defines_every_setting():
    for key, theme in THEMES.items():
        assert REQUIRED <= set(theme), (key, REQUIRED - set(theme))
        assert theme["nav"] in {"full", "compact", "rail", "top"}
        assert theme["sidebar"] in {"dark", "light", "page", "accent", "glass"}
        assert theme["cards"] in {"shadow", "outline", "flat", "elevated", "glass"}
        assert theme["mode"] in {"light", "dark"}
        assert theme["shell"] in {"classic", "floating", "sheet"}
        assert theme["buttons"] in {"rounded", "pill"}
        assert theme["primary_button"] in {"accent", "ink", "gradient"}
        assert theme["backdrop"] in {"plain", "aurora"}
        assert theme["title"] in {"standard", "display"}
        assert theme["labels"] in {"capitals", "sentence"}
        assert theme["details"] in {"classic", "modern"}


def test_bundled_fonts_exist_and_are_licensed():
    from app.ui.themes import FONTS

    fonts = ROOT / "app/static/fonts"
    licences = (fonts / "LICENSES.txt").read_text(encoding="utf-8")
    assert "SIL Open Font License" in licences
    css = (ROOT / "app/static/themes.css").read_text(encoding="utf-8")
    for name, file in FONTS.items():
        assert (fonts / file).stat().st_size > 5000, file
        if f"'{name}'," in css:
            assert f"url('fonts/{file}')" in css, name


def test_original_keeps_capital_eyebrows():
    style = (ROOT / "app/static/style.css").read_text(encoding="utf-8")
    block = style[style.index(".eyebrow {") : style.index("}", style.index(".eyebrow {"))]
    assert "text-transform: uppercase" in block
    html = (ROOT / "app/templates/index.html").read_text(encoding="utf-8")
    assert '<div class="eyebrow">Outage visibility</div>' in html
    assert '<div class="eyebrow">PoE power safety</div>' in html


def test_generated_files_are_up_to_date(tmp_path):
    css = (ROOT / "app/static/themes.css").read_text(encoding="utf-8")
    data = (ROOT / "app/static/themes.json").read_text(encoding="utf-8")
    subprocess.run([sys.executable, str(ROOT / "tools/build_themes.py")], check=True, capture_output=True)
    assert (ROOT / "app/static/themes.css").read_text(encoding="utf-8") == css, "run tools/build_themes.py"
    assert (ROOT / "app/static/themes.json").read_text(encoding="utf-8") == data


def test_every_non_original_theme_has_css():
    css = (ROOT / "app/static/themes.css").read_text(encoding="utf-8")
    for key in THEMES:
        if key != "original":
            assert f'html[data-theme="{key}"]' in css


def test_original_day_look_adds_no_overrides():
    css = (ROOT / "app/static/themes.css").read_text(encoding="utf-8")
    for line in css.splitlines():
        if 'data-theme="original"' in line:
            assert 'data-night="on"' in line, line  # only its night-mode rules exist


def test_every_light_theme_has_a_night_version():
    css = (ROOT / "app/static/themes.css").read_text(encoding="utf-8")
    for key, theme in THEMES.items():
        night = f'html[data-theme="{key}"][data-night="on"] {{'
        assert (night in css) == (theme["mode"] == "light"), key


def test_theme_preference_round_trip_and_page_render(api):
    assert api.get("/api/ui").json()["theme"] == "aurora"
    r = api.post("/api/ui/theme", json={"theme": "midnight"})
    assert r.status_code == 200 and r.json()["theme"] == "midnight"
    assert 'data-theme="midnight"' in api.get("/").text
    assert api.post("/api/ui/theme", json={"theme": "nope"}).status_code == 400
    api.post("/api/ui/theme", json={"theme": "aurora"})


def test_night_mode_and_menu_preferences(api):
    state = api.get("/api/ui").json()
    assert state["night"] == "off" and state["menu"] == "shown"
    page = api.get("/").text
    assert 'data-night="off"' in page and 'class="menu-hidden"' not in page
    assert '<script src="/static/night.js' in page

    r = api.post("/api/ui/preferences", json={"night": "on", "menu": "hidden"})
    assert r.status_code == 200 and r.json()["night"] == "on" and r.json()["menu"] == "hidden"
    page = api.get("/").text
    assert 'data-night="on"' in page and 'data-night-pref="on"' in page and 'class="menu-hidden"' in page

    api.post("/api/ui/preferences", json={"night": "system"})
    page = api.get("/").text
    assert 'data-night-pref="system"' in page and 'data-night="off"' in page  # night.js resolves it

    for bad in ({"night": "dusk"}, {"menu": "gone"}, {"colour": "red"}, {}):
        assert api.post("/api/ui/preferences", json=bad).status_code == 400, bad
    api.post("/api/ui/preferences", json={"night": "off", "menu": "shown"})


def test_screen_areas_are_named_uniquely():
    html = (ROOT / "app/templates/index.html").read_text(encoding="utf-8")
    names = re.findall(r'data-ui="([^"]+)"', html)
    assert len(names) >= 35
    assert len(names) == len(set(names)), "duplicate screen-area names"
    assert all("›" in n or n in {"Sidebar", "Page header"} for n in names)


def test_ui_map_documents_every_area():
    html = (ROOT / "app/templates/index.html").read_text(encoding="utf-8")
    doc = (ROOT / "docs/UI_MAP.md").read_text(encoding="utf-8")
    for name in re.findall(r'data-ui="([^"]+)"', html):
        assert name.replace("&amp;", "&") in doc, name
    themes = json.loads((ROOT / "app/static/themes.json").read_text())["themes"]
    for key in themes:
        assert f"`{key}`" in doc
