# NodeWatch UI map: how to ask for UI changes in plain English

You never need to know file names or CSS. Describe **where** (a screen-area name or a theme)
and **what** (one of the settings below, or any visual change in your own words).

## 1. Find the name of what you are looking at

Settings & Support › Appearance › tick **"Show screen-area names"**. Every area gets an orange
label such as `Command Center › Disconnect Watch`. Use that name in your request.
Untick it when you are done (it is only remembered in this browser).

## 2. Two kinds of change

**A. Look and layout of the whole app** — one line in `app/ui/themes.py`, then
`python tools/build_themes.py`. Each theme is a short list of settings:

| Setting | What it changes | Plain-English examples |
|---|---|---|
| `mode` | light or dark | "make Fluent dark" |
| `accent_hue` | colour of buttons, links, highlights (0 red, 25 orange, 140 green, 170 teal, 190 cyan, 210 blue, 225 original indigo, 258 violet, 330 pink) | "accent should be green" |
| `gray_hue`, `gray_saturation` | tint of the greys (0 saturation = pure grey) | "less blue in the greys", "warmer greys" |
| `background` | page background colour | "background a bit darker" |
| `sidebar` | `dark` navy, `light` (more below) | "light sidebar in Refined" |
| `nav` | `full` (icon + name + description), `compact` (grouped names), `rail` (icons only), `top` (bar across the top) | "put the menu across the top", "icons only" |
| `radius` | corner rounding (1.0 original, 0.5 sharper, 1.5 rounder) | "sharper corners" |
| `density` | overall size of the work area (0.9 = denser) | "fit more on screen" |
| `cards` | `shadow`, `outline`, `flat` (more below) | "no shadows on cards" |
| `font` | font family | "use Segoe UI everywhere" |
| `page_description` | show the line under the page title | "hide the page descriptions" |
| `shell` | `classic`, `floating` (sidebar or top bar floats as a rounded panel), `sheet` (pages on a rounded sheet inside a coloured frame) | "make the sidebar float", "put the pages on a sheet" |
| `sidebar` (more) | also `page` (same colour as the page), `accent` (deep accent colour), `glass` (frosted) | "sidebar the same colour as the page", "frosted sidebar" |
| `cards` (more) | also `elevated` (soft layered shadow), `glass` (frosted) | "cards should float a bit" |
| `buttons` | `rounded` or `pill` | "pill buttons" |
| `primary_button` | `accent`, `ink` (black/white), `gradient` | "black main buttons", "gradient buttons" |
| `backdrop` | `plain` or `aurora` (soft colour glows behind the page) | "remove the glow" |
| `title` | `standard` or `display` (larger, tighter page titles) | "bigger page titles" |
| `labels` | `capitals` (small capital labels) or `sentence` (quiet sentence case) | "no more all-caps labels" |
| `details` | `classic` or `modern` (dot-style summary tiles, larger numbers, calmer inputs, accent focus ring) | "modern summary tiles in Midnight" |
| `font_mono` | font for IPs, MACs and IDs | "Geist Mono for addresses" |

| `content_width` | `standard` (pages up to 1180 px) or `wide` (up to 1520 px) | "use more of my wide screen" |
| `night_background` | page colour when night mode is on | "make Aurora's night background pure black" |

Bundled fonts (work offline): Geist, Geist Mono, Manrope, Plus Jakarta Sans, Figtree, Onest.

**B. One specific area** — name the area and say what you want, e.g.
"`Command Center › Summary tiles`: make the numbers bigger and put the tiles in one row",
"`Device Finder › Results`: show the IP column first", "`Settings & Support › Mist Connection`:
make the card full width". These become targeted rules on that area.

Good requests are specific about *where*, *what*, and optionally *which theme* (otherwise the
change applies to every theme). A screenshot with a circle on it always works too.

## 3. Night mode and the left menu

- **Night mode** works with every light look (dark looks such as Midnight and Graphite are always dark).
  Switch it with the ☾ Night / ☀ Day button in the page header, or choose Off / On / Match Windows in
  Settings & Support › Appearance. "Match Windows" follows Windows' own light/dark setting, including its schedule.
  Preview without saving: add `?night=on` to the address.
- **Fold the left menu** to an icon rail with the round handle in the middle of the menu's right edge, or
  Ctrl+B. The same handle (or Ctrl+B) opens it again. The choice is remembered.
- **Page layout** (Settings & Support › Page layout) is separate from the colour theme: Aurora glass
  (default), Compact NOC, Top navigation, Focus / wide, or Custom (menu position, density, width, corners,
  glass, shadows). **Text size** scales the whole UI (Small / Default / Large / Extra large).

## 4. The themes

| Name | What it is |
|---|---|
| `original` | NodeWatch v0.10.7 exactly as shipped |
| `refined` | Same look, tidied: compact grouped sidebar so all tools are visible, outline cards, no repeated page descriptions |
| `midnight` | Dark operations-centre theme, cyan accent, for wall screens and night shifts |
| `compact` | Data-dense: icon rail, sharper corners, teal accent, more on screen |
| `workspace` | Navigation across the top, full-width content, violet accent, rounder cards |
| `fluent` | Windows 11 look: light sidebar, Segoe UI, Windows blue, subtle borders |
| `aurora` | **Default.** Aurora Glass: frosted floating sidebar and cards over a soft violet/cyan glow, gradient buttons, Plus Jakarta Sans |
| `graphite` | Modern dark: neutral graphite, hairline borders, violet accent, sidebar blends into the page, Onest |
| `studio` | Minimal monochrome: white and near-black, colour only for status, black buttons, Geist |
| `signal` | Deep teal frame with pages on a rounded light sheet, pill buttons, soft depth, Manrope |
| `cloud` | Floating capsule menu across the top, very round white cards on cool blue-grey, Figtree |

Preview any theme without saving: add `?theme=<name>` to the address, e.g. `http://127.0.0.1:8765/?theme=midnight`.
Choose and save one: Settings & Support › Appearance.

## 5. Screen-area names

**App frame**
- `Sidebar`
- `Sidebar › Navigation`
- `Sidebar › Collapse handle`
- `Page header`
- `Page header › Title`
- `Page header › Status & actions`

**Command Center**
- `Command Center › Filters`
- `Command Center › Search results`
- `Command Center › Summary tiles`
- `Command Center › Disconnect Watch`
- `Command Center › Requires Attention`
- `Command Center › Network Health`
- `Command Center › Issue Categories`
- `Command Center › Site Health`
- `Command Center › Recent Device Events`
- `Command Center › Incident details`
- `Command Center › Incident details › Team`
- `Command Center › Requires Attention › Mine`
- `Command Center › Alerts & Notifications`
- `Command Center › Alert Settings`


**Device Finder**
- `Device Finder › Find a client or device`
- `Device Finder › Results`
- `Device Finder › Device detail`

**Topology**
- `Topology › Toolbar`
- `Topology › Closets options`
- `Topology › Map`
- `Topology › Details`
- `Topology › Data gaps`
- `Topology › Breadcrumbs`
- `Topology › Changes`
- `Topology › Changes since baseline`
- `Topology › Minimap`
- `Topology › Path trace`
- `Topology › Worst right now`
- `Topology › Legend`

**Chassis Manager**
- `Chassis Manager › Stack health`
- `Chassis Manager › Stack detail`
- `Chassis Manager › Virtual Chassis`
- `Chassis Manager › Member editor`

**Port Toolkit**
- `Port Toolkit › Port health overview`
- `Port Toolkit › Filters`
- `Port Toolkit › Switch ports`
- `Port Toolkit › Select a switch`
- `Port Toolkit › Port detail`

**Change Verifier**
- `Change Verifier › Live verification`
- `Change Verifier › Validation history`

**Config Backups**
- `Config Backups › Safety net summary`
- `Config Backups › Changed since last snapshot`
- `Config Backups › Who changed it (Mist audit log)`
- `Config Backups › Snapshot timeline`
- `Config Backups › Compare snapshots`
- `Config Backups › Template drift`
- `Config Backups › Schedule & retention`

**Power Guard**
- `Power Guard › PoE risk overview`
- `Power Guard › Sites needing attention`
- `Power Guard › Switches by PoE budget used`
- `Power Guard › Open PoE issues`
- `Power Guard › Top power-drawing ports`
- `Power Guard › Capacity & risk`
- `Power Guard › Per-port draw`

**Security View**
- `Security View › Evidence-based findings`

**Event Relay**
- `Event Relay › Normalized event stream`
- `Event Relay › SIEM destination`

**Operations Assistant**
- `Operations Assistant › Read-only network investigation`

**Asset Library**
- `Asset Library › Asset Library`

**Activity Log**
- `Activity Log › Provider Audit Activity`
- `Activity Log › Local Tool Changes`

**Settings & Support**
- `Settings & Support › Appearance`
- `Settings & Support › Night mode`
- `Settings & Support › Text size`
- `Settings & Support › Page layout`
- `Settings & Support › Custom layout`
- `Settings & Support › Mist Connection`
- `Settings & Support › Security & Logging Integrations`
- `Settings & Support › Device Intelligence`
- `Settings & Support › Traffic & Sessions`
- `Settings & Support › Connections`
- `Settings & Support › Connections › Data available now`
- `Settings & Support › Connections › Add connection`
- `Settings & Support › Connections › Connected`
- `Settings & Support › Connections › Available`
- `Settings & Support › Team triage`
- `Settings & Support › Team triage › Sync status`
- `Settings & Support › Upgrade-safe storage`
- `Settings & Support › Platform Overview Lock`
- `Settings & Support › Simple support workflow`

**Platform Overview**
- `Platform Overview › Content`

## 5. How a change is made (for whoever implements it)

1. Theme-wide: edit `app/ui/themes.py`, run `python tools/build_themes.py`.
2. Area-specific: add rules to `app/static/ui-tools.css` (or the theme blocks in `tools/build_themes.py`)
   using the area's selector: `[data-ui="Command Center › Summary tiles"]`.
3. Colours come from tokens such as `var(--nw-gray-46, #667085)` in `style.css`; change the token,
   never the hex, so every theme stays consistent.
4. New card in `index.html`: run `python tools/name_ui_regions.py` to give it a name, then add it here.
5. `python -m pytest` checks that generated theme files are current and every area is listed here.
