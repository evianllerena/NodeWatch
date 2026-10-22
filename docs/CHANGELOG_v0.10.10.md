# NodeWatch v0.10.10 — Aurora Glass by default, night mode, hideable menu

Build: `2026-10-09-v0.10.10-aurora-night`

## Aurora Glass is the default
New installs and anyone who never picked a look start on Aurora Glass. A look you already chose in
Settings & Support › Appearance is kept. Aurora's pages now use up to 1520 px of width (was 1180).

## Night mode
- ☾ Night / ☀ Day button in the page header; Off / On / Match Windows in Settings & Support › Appearance.
- Works with every light look; each has a generated dark version. Aurora at night is deep indigo-black
  with frosted dark panels and the same violet/cyan glow.
- "Match Windows" follows Windows' light/dark setting (and its schedule) and switches live.
- Applied before the page draws (small `static/night.js` in the page head), so there is no white flash.
- Saved in `ui.json`; preview without saving with `?night=on`.

## Hideable left menu
- « Hide menu at the bottom of the menu, Ctrl+B, or the Appearance checkbox. Pages then use the full window
  width (up to 1520 px), like Cloud. The ☰ button at the top left or Ctrl+B brings it back.
- Remembered between launches. Not shown on looks whose menu runs across the top.

## API
`POST /api/ui/preferences` accepts any of `theme`, `night` (`off` / `on` / `system`), `menu` (`shown` / `hidden`).
`GET /api/ui` returns all three.

## Tests
New checks: every light look has a night version, Original's day look still adds no overrides, night/menu
preferences round-trip and render into the page, bad values are rejected.
