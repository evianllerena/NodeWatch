"""Saved UI preferences (theme, night mode, menu, page layout). Stored in <data root>/ui.json so they survive
upgrades and do not depend on which local port the browser used."""

from __future__ import annotations

from typing import Any

from app.core.config import DATA_ROOT
from app.core.file_utils import locked_json_update, read_json
from app.ui.themes import DEFAULT_THEME, NAV_GROUPS, THEMES

UI_FILE = DATA_ROOT / "ui.json"
NIGHT_CHOICES = ("off", "on", "system")  # system = follow the Windows light/dark setting
MENU_CHOICES = ("shown", "hidden")
# Settings › Look & layout › Layout (v0.10.15). Independent of the colour theme; "aurora" is the default.
LAYOUT_CHOICES = {
    "preset": ("aurora", "dense", "top", "focus", "custom"),
    "nav": ("side", "top"),
    "density": ("comfortable", "compact"),
    "width": ("fixed", "full"),
    "radius": ("theme", "square", "subtle", "rounded", "round"),
    "glass": ("on", "off"),
    "shadows": ("on", "off"),
    "text": ("s", "m", "l", "xl"),
}
DEFAULT_LAYOUT = {
    "preset": "aurora",
    "nav": "side",
    "density": "comfortable",
    "width": "fixed",
    "radius": "theme",
    "glass": "on",
    "shadows": "on",
    "text": "m",
}


def _saved() -> dict:
    data = read_json(UI_FILE, {}) if UI_FILE.exists() else {}
    return data if isinstance(data, dict) else {}


def current_theme() -> str:
    theme = str(_saved().get("theme") or DEFAULT_THEME)
    return theme if theme in THEMES else DEFAULT_THEME


def current_night() -> str:
    night = str(_saved().get("night") or "off")
    return night if night in NIGHT_CHOICES else "off"


def current_menu() -> str:
    menu = str(_saved().get("menu") or "shown")
    return menu if menu in MENU_CHOICES else "shown"


def clean_layout(value: Any) -> dict:
    """Validate a layout object; unknown keys or values are rejected, missing keys use the default."""
    if not isinstance(value, dict):
        raise ValueError("Layout must be an object")
    unknown = set(value) - set(LAYOUT_CHOICES)
    if unknown:
        raise ValueError(f"Unknown layout setting(s): {', '.join(sorted(unknown))}")
    layout = dict(DEFAULT_LAYOUT)
    for key, raw in value.items():
        if str(raw) not in LAYOUT_CHOICES[key]:
            raise ValueError(f"Layout {key} must be one of {', '.join(LAYOUT_CHOICES[key])}")
        layout[key] = str(raw)
    return layout


def current_layout() -> dict:
    try:
        return clean_layout(_saved().get("layout") or {})
    except ValueError:
        return dict(DEFAULT_LAYOUT)


def layout_saved() -> bool:
    return isinstance(_saved().get("layout"), dict)


def set_preferences(
    *, theme: str | None = None, night: str | None = None, menu: str | None = None, layout: Any = None
) -> None:
    if theme is not None and theme not in THEMES:
        raise ValueError(f"Unknown theme: {theme}")
    if night is not None and night not in NIGHT_CHOICES:
        raise ValueError(f"Night mode must be one of {', '.join(NIGHT_CHOICES)}")
    if menu is not None and menu not in MENU_CHOICES:
        raise ValueError(f"Menu must be one of {', '.join(MENU_CHOICES)}")
    changes: dict[str, Any] = {k: v for k, v in (("theme", theme), ("night", night), ("menu", menu)) if v is not None}
    if layout is not None:
        changes["layout"] = clean_layout(layout)

    def apply(cur: Any) -> dict:
        data = dict(cur) if isinstance(cur, dict) else {}
        data.update(changes)
        return data

    DATA_ROOT.mkdir(parents=True, exist_ok=True)
    locked_json_update(UI_FILE, apply, default={})


def set_theme(theme: str) -> str:
    set_preferences(theme=theme)
    return theme


def page_context() -> dict:
    """Values rendered into index.html so the saved look applies before the page draws."""
    theme = current_theme()
    night = current_night()
    layout = current_layout()
    hidden = current_menu() == "hidden"
    nav = THEMES[theme]["nav"]
    # The page layout decides where navigation sits; the theme only decides its colours and style.
    if layout["nav"] == "top":
        effective_nav = "top"
    elif hidden:
        effective_nav = "rail"
    else:
        effective_nav = nav if nav in ("full", "compact") else "compact"
    return {
        "ui_nav_effective": effective_nav,
        "ui_theme": theme,
        "ui_mode": THEMES[theme]["mode"],
        "ui_nav": THEMES[theme]["nav"],
        "ui_night_pref": night,
        "ui_night": "on" if night == "on" else "off",  # "system" is resolved by static/night.js
        "ui_menu_hidden": hidden,
        "ui_layout": layout,
        "ui_layout_saved": layout_saved(),
    }


def public_state() -> dict:
    return {
        "theme": current_theme(),
        "night": current_night(),
        "menu": current_menu(),
        "layout": current_layout(),
        "layout_saved": layout_saved(),
        "default_layout": DEFAULT_LAYOUT,
        "default": DEFAULT_THEME,
        "groups": NAV_GROUPS,
        "themes": [
            {"id": key, "label": t["label"], "description": t["description"], "nav": t["nav"], "mode": t["mode"]}
            for key, t in THEMES.items()
        ],
    }
