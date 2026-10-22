# NodeWatch v0.10.9 — five modern themes

Build: `2026-10-09-v0.10.9-modern-themes`

## New looks (Settings & Support → Appearance, or `?theme=<name>`)
- **Aurora Glass** (`aurora`): frosted floating sidebar and cards over a soft violet/cyan glow, gradient
  buttons, Plus Jakarta Sans.
- **Graphite** (`graphite`): modern dark, neutral graphite, hairline borders, violet accent, Onest.
- **Studio** (`studio`): minimal monochrome, black buttons, colour only for status, Geist.
- **Signal** (`signal`): deep teal frame with pages on a rounded sheet, pill buttons, Manrope.
- **Cloud** (`cloud`): floating capsule menu across the top, very round cards, Figtree.

Original and the five v0.10.8 looks are unchanged; Original is still the default.

## New theme settings (app/ui/themes.py, documented in docs/UI_MAP.md)
`shell` (classic / floating / sheet), more `sidebar` styles (page / accent / glass), more `cards` styles
(elevated / glass), `buttons` (rounded / pill), `primary_button` (accent / ink / gradient),
`backdrop` (plain / aurora), `title` (standard / display), `labels` (capitals / sentence),
`details` (classic / modern), `font_mono`.

## Fonts
Six fonts are bundled in `app/static/fonts` (Latin subset, ~185 KB total, SIL Open Font License, notices in
`fonts/LICENSES.txt`), so they work offline: Geist, Geist Mono, Manrope, Plus Jakarta Sans, Figtree, Onest.
All IPs, MACs and IDs use Geist Mono in the modern themes.

## Other
- Section labels are now stored in sentence case ("Outage visibility") with acronyms kept (NOC, PoE, VC, NAC).
  Original still shows them in capitals through CSS, so it looks exactly as before (pixel-checked).
- Device Finder's detail label shows "Wired client" instead of "WIRED CLIENT" in sentence-case themes.
