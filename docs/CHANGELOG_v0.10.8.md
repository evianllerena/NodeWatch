# NodeWatch v0.10.8 — UI themes and plain-English UI changes

Build: `2026-10-09-v0.10.8-ui-themes`

## Appearance
- Settings & Support → Appearance offers six looks: **Original** (v0.10.7, the default), **Refined**,
  **Midnight NOC**, **Compact Ops**, **Top Bar Workspace** and **Windows Fluent**. The choice is saved in
  `ui.json` in the data folder and applied before the page draws (no flash).
- Preview a look without saving it: open NodeWatch with `?theme=<name>` in the address.
- Compact, rail and top navigation group tools under Monitor / Investigate / Operate / Govern / Secure /
  Data / System, so all 15 tools fit on screen.
- "Show screen-area names" puts an orange label on every named area (`data-ui`), so you can say
  "make `dashboard.kpis` two rows" and the request maps to one place in the code.
- `docs/UI_MAP.md` lists every area name and every theme setting with plain-English examples.

## How it is built
- `style.css` uses 80 colour tokens instead of ~600 hard-coded colours; Original renders pixel-identical to v0.10.7.
- Themes are short settings blocks in `app/ui/themes.py`; `python tools/build_themes.py` generates
  `app/static/themes.css` and `themes.json`.

## Fixes
- Command Center labels sample data as "SAMPLE DATA — Mist not connected" instead of showing it as live.
- Device Finder filters wrap instead of being cut off.
- Port Toolkit and Config Vault say "Mist connection is not configured" instead of "Invalid Mist organization ID" before setup.
- CSS variables that were used but never defined (`--panel-2`, `--surface-2`, `--border`, `--text`) now exist.

## Tests
158 automated tests, including checks that the generated theme files are current, every area name is unique
and documented, and the theme preference round-trips.
