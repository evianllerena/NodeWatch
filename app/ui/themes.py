"""NodeWatch UI themes: the single place to change how NodeWatch looks.

Each theme is a short list of plain settings. Run

    python tools/build_themes.py

to regenerate app/static/themes.css and app/static/themes.json from this file.

Settings
--------
label, description  Shown in Settings > Appearance.
mode                "light" or "dark".
accent_hue          Colour wheel angle for buttons, links, highlights (None = original blue).
                    0 red, 25 orange, 45 amber, 140 green, 170 teal, 190 cyan,
                    210 sky blue, 225 indigo (original), 258 violet, 330 pink.
gray_hue            Tint of the neutral greys (None = original cool blue-grey; 30 = warm, 0 = neutral).
gray_saturation     How tinted the greys are (1.0 = original, 0 = pure grey).
background          Optional page background override, e.g. "#f3f3f3".
sidebar             "dark" (original navy) or "light" (more styles below).
nav                 "full"     icon + name + description (original)
                    "compact"  icon + name, grouped by area, description as tooltip
                    "rail"     narrow icon-only strip, name as tooltip
                    "top"      horizontal bar across the top with short names
radius              Corner rounding multiplier (1.0 = original, 0.5 = sharper, 1.5 = rounder).
density             Overall size of the work area (1.0 = original, 0.9 = denser, 1.05 = roomier).
cards               "shadow" (original), "outline" (thin border, no shadow), or "flat".
font                CSS font stack, or None for the original (Inter / Segoe UI).
page_description    Show the one-line description under each page title (True/False).

Added in v0.10.9 (the five "modern" themes use them; the first six keep the classic values):
shell               "classic"   sidebar attached to the window edge (original)
                    "floating"  sidebar (or top bar) floats as a rounded panel with a gap around it
                    "sheet"     the sidebar colour fills the window; pages sit on a rounded sheet
sidebar             also "page" (same colour as the page, no separate panel),
                    "accent" (deep accent colour) and "glass" (frosted, see-through)
cards               also "elevated" (soft layered shadow, no border) and "glass" (frosted)
buttons             "rounded" (original) or "pill" (fully rounded ends)
primary_button      "accent" (original), "ink" (black in light mode, white in dark mode) or
                    "gradient" (accent blending into a neighbouring hue)
backdrop            "plain" (original) or "aurora" (two soft colour glows behind the page)
title               "standard" (original) or "display" (larger, tighter page titles, no rule under them)
labels              "capitals" (original small capital labels) or "sentence" (quiet sentence-case labels)
font, font_mono     A bundled font name from FONTS below, any CSS font stack, or None.
content_width       "standard" (pages up to 1180 px wide, original) or "wide" (up to 1520 px).
night_background    Page colour when night mode is on (None = worked out from the greys).
details             "classic" (original) or "modern": dot-style summary tiles, larger numbers, calmer inputs
                    with an accent focus ring, softer secondary buttons, pill-shaped view switches.
"""

from __future__ import annotations

# Bundled fonts (app/static/fonts, SIL Open Font License; see fonts/LICENSES.txt).
FONTS = {
    "Geist": "geist.woff",
    "Geist Mono": "geist-mono.woff",
    "Manrope": "manrope.woff",
    "Plus Jakarta Sans": "plus-jakarta-sans.woff",
    "Figtree": "figtree.woff",
    "Onest": "onest.woff",
}

# The v0.10.8 values of the settings added in v0.10.9.
CLASSIC = {
    "shell": "classic",
    "buttons": "rounded",
    "primary_button": "accent",
    "backdrop": "plain",
    "title": "standard",
    "labels": "capitals",
    "font_mono": None,
    "details": "classic",
    "content_width": "standard",
    "night_background": None,
}

THEMES: dict[str, dict] = {
    "original": {
        "label": "Original",
        "description": "NodeWatch v0.10.7 as shipped.",
        "mode": "light",
        "accent_hue": None,
        "gray_hue": None,
        "gray_saturation": 1.0,
        "background": None,
        "sidebar": "dark",
        "nav": "full",
        "radius": 1.0,
        "density": 1.0,
        "cards": "shadow",
        "font": None,
        "page_description": True,
        **CLASSIC,
    },
    "refined": {
        "label": "Refined",
        "description": "The current look, tidied: grouped compact sidebar, all tools visible, calmer cards.",
        "mode": "light",
        "accent_hue": None,
        "gray_hue": None,
        "gray_saturation": 1.0,
        "background": None,
        "sidebar": "dark",
        "nav": "compact",
        "radius": 1.0,
        "density": 0.95,
        "cards": "outline",
        "font": None,
        "page_description": False,
        **CLASSIC,
    },
    "midnight": {
        "label": "Midnight NOC",
        "description": "Dark operations-centre theme for wall screens and night shifts; status colours stand out.",
        "mode": "dark",
        "accent_hue": 190,
        "gray_hue": 220,
        "gray_saturation": 0.9,
        "background": None,
        "sidebar": "dark",
        "nav": "compact",
        "radius": 0.8,
        "density": 0.95,
        "cards": "outline",
        "font": None,
        "page_description": False,
        **CLASSIC,
    },
    "compact": {
        "label": "Compact Ops",
        "description": "Data-dense: sharper corners, more rows on screen. Teal accent. Pair with the Compact NOC layout.",
        "mode": "light",
        "accent_hue": 172,
        "gray_hue": 210,
        "gray_saturation": 0.5,
        "background": "#f4f6f7",
        "sidebar": "dark",
        "nav": "rail",
        "radius": 0.5,
        "density": 0.88,
        "cards": "outline",
        "font": None,
        "page_description": False,
        **CLASSIC,
    },
    "workspace": {
        "label": "Top Bar Workspace",
        "description": "Soft violet accent and rounder cards. Pair with the Top navigation layout.",
        "mode": "light",
        "accent_hue": 258,
        "gray_hue": 250,
        "gray_saturation": 0.6,
        "background": "#f7f7fb",
        "sidebar": "light",
        "nav": "top",
        "radius": 1.35,
        "density": 1.0,
        "cards": "shadow",
        "font": None,
        "page_description": True,
        **CLASSIC,
    },
    "fluent": {
        "label": "Windows Fluent",
        "description": "Matches Windows 11: light sidebar, Segoe UI Variable, Windows blue, subtle borders.",
        "mode": "light",
        "accent_hue": 207,
        "gray_hue": 0,
        "gray_saturation": 0.0,
        "background": "#f3f3f3",
        "sidebar": "light",
        "nav": "compact",
        "radius": 0.7,
        "density": 0.95,
        "cards": "outline",
        "font": "'Segoe UI Variable Text', 'Segoe UI', system-ui, sans-serif",
        "page_description": False,
        **CLASSIC,
    },
    # ------------------------------------------------------------ modern set (v0.10.9)
    "aurora": {
        "label": "Aurora Glass",
        "description": "Frosted floating sidebar and cards over a soft violet-and-cyan glow. Plus Jakarta Sans.",
        "mode": "light",
        "accent_hue": 250,
        "gray_hue": 235,
        "gray_saturation": 0.55,
        "background": "#f4f5fb",
        "sidebar": "glass",
        "nav": "compact",
        "radius": 1.3,
        "density": 0.95,
        "cards": "glass",
        "font": "Plus Jakarta Sans",
        "page_description": False,
        "shell": "floating",
        "buttons": "pill",
        "primary_button": "gradient",
        "backdrop": "aurora",
        "title": "display",
        "labels": "sentence",
        "font_mono": "Geist Mono",
        "details": "modern",
        "content_width": "wide",
        "night_background": "#0b0d18",
    },
    "graphite": {
        "label": "Graphite",
        "description": "Modern dark: neutral graphite, hairline borders, violet accent, sidebar blends into the page. Onest.",
        "mode": "dark",
        "accent_hue": 248,
        "gray_hue": 240,
        "gray_saturation": 0.15,
        "background": "#0e0f11",
        "sidebar": "page",
        "nav": "compact",
        "radius": 0.8,
        "density": 0.92,
        "cards": "outline",
        "font": "Onest",
        "page_description": False,
        "shell": "classic",
        "buttons": "rounded",
        "primary_button": "accent",
        "backdrop": "plain",
        "title": "display",
        "labels": "sentence",
        "font_mono": "Geist Mono",
        "details": "modern",
        "content_width": "standard",
        "night_background": None,
    },
    "studio": {
        "label": "Studio",
        "description": "Minimal monochrome: white and near-black, colour only for status. Black buttons. Geist.",
        "mode": "light",
        "accent_hue": 215,
        "gray_hue": 0,
        "gray_saturation": 0.0,
        "background": "#fafafa",
        "sidebar": "page",
        "nav": "compact",
        "radius": 0.65,
        "density": 0.95,
        "cards": "outline",
        "font": "Geist",
        "page_description": False,
        "shell": "classic",
        "buttons": "rounded",
        "primary_button": "ink",
        "backdrop": "plain",
        "title": "display",
        "labels": "sentence",
        "font_mono": "Geist Mono",
        "details": "modern",
        "content_width": "standard",
        "night_background": None,
    },
    "signal": {
        "label": "Signal",
        "description": "Deep teal frame with pages on a rounded light sheet, pill buttons, soft depth. Manrope.",
        "mode": "light",
        "accent_hue": 170,
        "gray_hue": 190,
        "gray_saturation": 0.35,
        "background": "#f5f8f8",
        "sidebar": "accent",
        "nav": "compact",
        "radius": 1.2,
        "density": 0.95,
        "cards": "elevated",
        "font": "Manrope",
        "page_description": False,
        "shell": "sheet",
        "buttons": "pill",
        "primary_button": "accent",
        "backdrop": "plain",
        "title": "display",
        "labels": "sentence",
        "font_mono": "Geist Mono",
        "details": "modern",
        "content_width": "standard",
        "night_background": None,
    },
    "cloud": {
        "label": "Cloud",
        "description": "Very round white cards on cool blue-grey. Figtree. Pair with the Top navigation layout.",
        "mode": "light",
        "accent_hue": 205,
        "gray_hue": 212,
        "gray_saturation": 0.6,
        "background": "#edf2f7",
        "sidebar": "light",
        "nav": "top",
        "radius": 1.6,
        "density": 1.0,
        "cards": "elevated",
        "font": "Figtree",
        "page_description": True,
        "shell": "floating",
        "buttons": "pill",
        "primary_button": "accent",
        "backdrop": "plain",
        "title": "display",
        "labels": "sentence",
        "font_mono": "Geist Mono",
        "details": "modern",
        "content_width": "standard",
        "night_background": None,
    },
}

DEFAULT_THEME = "aurora"

# Sidebar group order for the "compact", "rail" and "top" navigation styles.
NAV_GROUPS = ["Monitor", "Investigate", "Operate", "Govern", "Secure", "Data", "System"]
