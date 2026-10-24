const FRONTEND_VERSION = '0.10.57';
const FRONTEND_BUILD = '0.10.57-source';
window.MistTools = window.MistTools || {};

const NODEWATCH_WRITE_TOKEN = document.querySelector('meta[name="nodewatch-write-token"]')?.content || '';
const NODEWATCH_NATIVE_FETCH = window.fetch.bind(window);
window.fetch = function (input, init = {}) {
  let target;
  try {
    target = new URL(typeof input === 'string' ? input : input.url, window.location.href);
  } catch {
    target = null;
  }
  if (target && target.origin === window.location.origin && target.pathname.startsWith('/api/')) {
    // Every same-origin API call carries the per-launch token (reads included).
    const headers = new Headers(init?.headers || (input instanceof Request ? input.headers : undefined));
    headers.set('X-NodeWatch-Request', NODEWATCH_WRITE_TOKEN);
    init = { ...init, headers, credentials: 'same-origin' };
  } else if (target && target.origin === window.location.origin) {
    init = { ...init, credentials: 'same-origin' };
  }
  return NODEWATCH_NATIVE_FETCH(input, init);
};

const nwEscapeHtml = (v) =>
  String(v ?? '').replace(
    /[&<>'"]/g,
    (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' })[c],
  );

const PAGE_META = {
  dashboard: [
    'Operations',
    'Command Center',
    'Live operations overview: prioritized issues, outages, health, and disconnect alerts.',
  ],
  detective: [
    'Investigate',
    'Device Finder',
    'Search one identifier and resolve it into live infrastructure or endpoint context.',
  ],
  topology: [
    'Investigate',
    'Topology',
    'How the network is wired across vendors: physical links, layer 3 and SD-WAN overlays, with data gaps called out.',
  ],
  operations: [
    'Operate',
    'Port Toolkit',
    'Inspect port telemetry, neighbors, link/auth/power state, diagnostics, and controlled changes.',
  ],
  'virtual-chassis': [
    'Operate',
    'Chassis Manager',
    'Inspect and manage chassis membership, roles, ordering, previews, guarded changes, and history.',
  ],
  validator: [
    'Safety',
    'Change Verifier',
    'Re-check configuration and operational state after changes and retain a validation record.',
  ],
  'config-backup': [
    'Govern',
    'Config Backups',
    'Snapshot org and site configuration, see what changed and who changed it, spot template drift, and restore safely.',
  ],
  poe: [
    'Operate',
    'Power Guard',
    'Inspect powered ports, current draw, available capacity, utilization, and endpoint power risk.',
  ],
  security: [
    'Secure',
    'Security Operations',
    'Threats, attackers, countries, vulnerabilities and cases from every connected security source — one vendor-neutral view.',
  ],
  siem: [
    'Integrate',
    'Event Relay',
    'Normalize alerts, events, and audit activity for export or automatic forwarding to external tools.',
  ],
  'ai-engineer': [
    'Investigate',
    'Operations Assistant',
    "Ask what's broken, how a site is doing, or where a device is — by typing or by voice.",
  ],
  inventory: [
    'Shared data',
    'Asset Library',
    'Shared infrastructure inventory, identity, status, and eligibility/reference data.',
  ],
  history: [
    'Audit',
    'Activity Log',
    'Platform activity plus local transaction records created by NodeWatch.',
  ],
  settings: [
    'System',
    'Settings & Support',
    'Manage connections, credentials, persistent data, preferences, and diagnostics.',
  ],
};

let initialized = new Set();
let tools = [];
let activeToolId = 'dashboard';
let autoRefreshBusy = false;
const AUTO_REFRESH_MS = 30000;

// One fetch helper for every page (v0.10.44). JSON in and out; a refusal throws an Error whose message is the
// server's own "detail" (FastAPI), else its "message" or "error", else "HTTP <status>". A body set as a string is sent as JSON.
async function nwFetchJSON(url, opts = {}) {
  const init = opts.body && !opts.headers ? { ...opts, headers: { 'Content-Type': 'application/json' } } : opts;
  const r = await fetch(url, init);
  const text = await r.text();
  let body = {};
  try {
    body = text ? JSON.parse(text) : {};
  } catch {
    body = null;
  }
  if (!r.ok) {
    const d = body?.detail;
    const msg = typeof d === 'string' ? d : d != null ? JSON.stringify(d) : body?.message || body?.error;
    throw new Error(msg || (body === null && text && text.length < 300 ? text : `HTTP ${r.status}`));
  }
  return body ?? {};
}

async function getJSON(url) {
  return nwFetchJSON(url);
}

function setHeader(id) {
  const [eyebrow, title, desc] = PAGE_META[id] || ['Tool', 'NodeWatch', ''];
  document.querySelector('#pageEyebrow').textContent = eyebrow;
  document.querySelector('#pageTitle').textContent = title;
  document.querySelector('#pageDescription').textContent = desc;
  const refresh = document.querySelector('#globalRefresh');
  if (refresh) refresh.classList.toggle('hidden', id !== 'dashboard');
}

let lastStatus = null; // the latest /api/status answer (pages read it via MistApp.lastStatus())

function renderConnectionStatus(status) {
  lastStatus = status;
  const live = status.mist_connected;
  const configured = status.configured; // Mist is configured
  // v0.10.24: without Mist, an install connected to other sources (EdgeConnect, Palo Alto, FortiGate,
  // SNMP …) is not "setup required": the header lists the connected products instead.
  const products = Array.isArray(status.connected_products) ? status.connected_products : [];
  const failing = Array.isArray(status.failing_products) ? status.failing_products : [];
  const othersOnly = !configured && (products.length > 0 || failing.length > 0);
  const othersOk = othersOnly && failing.length === 0;
  const productText = products.length > 2 ? `${products.slice(0, 2).join(', ')} +${products.length - 2}` : products.join(', ');
  const dotClass = live || othersOk ? 'green' : 'amber';
  const text = live
    ? `Connected · ${status.organization || 'Mist'}`
    : configured
      ? 'Configured · connection unavailable'
      : othersOnly
        ? products.length
          ? `Connected · ${productText}${failing.length ? ` · ${failing.length} failing` : ''}`
          : `Connection problem · ${failing.join(', ')}`
        : 'Setup required';
  if (status.organization) (window.MistApp = window.MistApp || {}).orgName = status.organization;
  const pill = document.querySelector('#connectionPill');
  if (
    status.version &&
    (status.version !== FRONTEND_VERSION || (status.build && status.build !== FRONTEND_BUILD))
  ) {
    const msg = `Build mismatch: browser v${FRONTEND_VERSION} (${FRONTEND_BUILD}), backend v${status.version} (${status.build || 'unknown'}). Close older NodeWatch windows/processes and relaunch.`;
    console.error(msg);
    if (pill) {
      pill.className = 'status-pill connection-prominent warning';
      pill.innerHTML = `<span class="dot amber"></span><span>${nwEscapeHtml(msg)}</span>`;
      pill.title = msg;
    }
    return;
  }
  if (pill) {
    pill.className = `status-pill connection-prominent ${live || othersOk ? 'connected' : 'warning'}`;
    pill.innerHTML = `<span class="dot ${dotClass}"></span><span>${nwEscapeHtml(text)}</span>`;
    pill.title =
      status.connection_error ||
      (live
        ? 'Mist API connection verified'
        : configured
          ? 'Mist configuration exists, but the latest API connection check failed'
          : othersOnly
            ? [
                products.length ? `Connected sources: ${products.join(', ')}` : '',
                failing.length ? `Failing (see Settings › Connections): ${failing.join(', ')}` : '',
              ]
                .filter(Boolean)
                .join(' · ')
            : 'No network source is connected yet: add one in Settings & Support');
  }
  renderTlsWarning(status);
  renderApiUsageWarning(status);
}

function renderApiUsageWarning(status) {
  // Mist allows 5,000 API calls per hour per token; NodeWatch slows its refreshes when usage is high.
  const warning = status?.mist_api_usage?.warning || '';
  let note = document.querySelector('#apiUsageWarning');
  if (!warning) {
    note?.remove();
    return;
  }
  if (!note) {
    note = document.createElement('div');
    note.id = 'apiUsageWarning';
    note.className = 'notice warning api-usage-warning';
    note.setAttribute('role', 'status');
    document.querySelector('.workspace, main')?.prepend(note);
  }
  note.textContent = `${warning} NodeWatch is refreshing less often to stay under Mist's limit.`;
}

function renderTlsWarning(status) {
  // Persistent warning while TLS certificate verification is turned off for any connection
  // (Mist, a device connector or Splunk HEC; v0.10.22 lists every one, not only Mist).
  let banner = document.querySelector('#tlsWarningBanner');
  const off = Array.isArray(status?.tls_verification_off)
    ? status.tls_verification_off.map((name) => String(name))
    : status?.tls_verification_disabled
      ? ['Mist']
      : [];
  if (!off.length) {
    banner?.remove();
    return;
  }
  if (!banner) {
    banner = document.createElement('div');
    banner.id = 'tlsWarningBanner';
    banner.className = 'notice warning tls-warning-banner';
    banner.setAttribute('role', 'alert');
    (document.querySelector('main') || document.body).prepend(banner);
  }
  // textContent only: connection names are never parsed as HTML.
  banner.textContent =
    `TLS certificate verification is OFF for: ${off.join(', ')}. Traffic and the credentials for these ` +
    'connections can be intercepted. Turn certificate checks back on in Settings.';
}

async function refreshConnectionStatus(test = false) {
  try {
    const status = await getJSON(`/api/status${test ? '?test=true' : ''}`);
    renderConnectionStatus(status);
    return status;
  } catch (err) {
    console.error(err);
    renderConnectionStatus({ configured: false, mist_connected: false, version: FRONTEND_VERSION });
    return null;
  }
}

// Pages that were merged into another page: old links and bookmarks land on the new spot.
const MERGED_TOOLS = { alerting: ['dashboard', '#nocAlerts'] };

// ---- Lazily loaded pages (v0.10.23) ---------------------------------------------------------------
// Pages listed here are not in index.html: their scripts are downloaded and run the first time the
// page is opened (openTool awaits them before init). Paths are listed WITHOUT a query string; the
// loader appends ?v=<app version> (taken from core.js's own URL) so caches stay per release. Scripts
// of one page run in the listed order. A page's script must register itself on window.MistTools under
// the page's module key (see TOOL_MODULE_KEYS) and must not wait for DOMContentLoaded.
const LAZY_TOOL_SCRIPTS = {
  topology: ['/static/modules/topology.js', '/static/modules/topology-report.js'],
  'config-backup': ['/static/modules/config-backup.js'],
  siem: ['/static/modules/siem.js'],
  'ai-engineer': ['/static/modules/ai-engineer.js'],
  validator: ['/static/modules/validator.js'],
};
const TOOL_MODULE_KEYS = {
  'virtual-chassis': 'virtualChassis',
  'config-backup': 'configBackup',
  'ai-engineer': 'aiEngineer',
};
const NW_ASSET_VERSION = (() => {
  try {
    return new URL(document.currentScript.src).searchParams.get('v') || FRONTEND_BUILD;
  } catch {
    return FRONTEND_BUILD;
  }
})();
const lazyToolLoads = {};

function loadScriptOnce(src) {
  const url = `${src}?v=${encodeURIComponent(NW_ASSET_VERSION)}`;
  return new Promise((resolve, reject) => {
    const s = document.createElement('script');
    s.src = url;
    s.async = false; // download in parallel, run in insertion order
    s.onload = () => resolve();
    s.onerror = () => {
      s.remove();
      reject(new Error(`Could not load ${src}`));
    };
    document.body.appendChild(s);
  });
}

// Resolves when every script of the page has run (immediately for eager pages). A failed load is
// forgotten so the next open retries.
function loadToolScripts(id) {
  const scripts = LAZY_TOOL_SCRIPTS[id];
  if (!scripts?.length) return Promise.resolve();
  if (!lazyToolLoads[id]) {
    lazyToolLoads[id] = Promise.all(scripts.map(loadScriptOnce)).catch((err) => {
      delete lazyToolLoads[id];
      throw err;
    });
  }
  return lazyToolLoads[id];
}

// Re-opening a page refreshes it only when its data is older than this (each page also has its own
// auto-refresh while visible); switching back and forth no longer re-requests everything.
// Only pages whose refresh() just reloads data are skipped; pages whose refresh() also restarts their
// own timers (Power Guard, Topology, ...) are always refreshed on open, as before.
const REVISIT_FRESH_MS = 20000;
const REVISIT_DATA_ONLY = new Set([
  'dashboard',
  'inventory',
  'security',
  'validator',
  'history', // v0.10.40: these too only reload data on refresh()
  'siem',
  'config-backup',
  'detective',
]);
const toolDataAt = {};
const toolInits = {}; // page id → its init() promise while it runs

// ---- Back and forward (v0.10.32) ----------------------------------------------------------------
// Each history entry is { nw: 1, tool, view }: the page and, optionally, a page-defined view (a
// selected site/switch/port, an open detection, ...). Pages report view changes with
// MistApp.pushView(view) and restore them in module.restoreView(view) (view null = the page's start).
let nwRestoring = false; // true while a Back/Forward is being replayed: pages must not push then
let nwLastPopAt = 0;
const nwSameState = (a, b) => {
  try {
    return JSON.stringify(a ?? null) === JSON.stringify(b ?? null);
  } catch {
    return false;
  }
};
function nwHistoryPush(tool, view, { replace = false } = {}) {
  if (nwRestoring) return;
  const cur = history.state;
  const next = { nw: 1, tool, view: view ?? null };
  const url = `#${tool}`;
  if (replace || !cur?.nw || (cur.tool === tool && nwSameState(cur.view, next.view))) {
    history.replaceState(next, '', url);
    return;
  }
  history.pushState(next, '', url);
}
function pushView(view, { replace = false, tool = activeToolId } = {}) {
  nwHistoryPush(tool, view, { replace });
}
async function nwRestoreHistory(state) {
  nwRestoring = true;
  try {
    // Transient dialogs (port details, detection details, confirmations) close on Back.
    document.querySelectorAll('dialog[open]').forEach((d) => d.close());
    const hash = location.hash.replace('#', '');
    const tool = state?.nw ? state.tool : hash || 'dashboard';
    if (tool !== activeToolId || !initialized.has(tool)) await openTool(tool, false);
    const module = window.MistTools[TOOL_MODULE_KEYS[tool] || tool];
    if (module?.restoreView) await module.restoreView(state?.nw ? state.view : null);
  } catch (err) {
    console.warn('Could not restore the previous page', err);
  } finally {
    nwRestoring = false;
  }
}
function wireHistory() {
  window.addEventListener('popstate', (e) => {
    nwLastPopAt = Date.now();
    nwRestoreHistory(e.state);
  });
  // Mouse back/forward buttons (buttons 4 and 5). Chrome and Edge already turn them into Back and
  // Forward; where the browser window does not (some app-mode windows, Macs), do it here once.
  window.addEventListener('mouseup', (e) => {
    if (e.button !== 3 && e.button !== 4) return;
    const at = Date.now();
    const back = e.button === 3;
    setTimeout(() => {
      if (nwLastPopAt >= at) return; // the browser handled it
      if (back) history.back();
      else history.forward();
    }, 160);
  });
}

async function openTool(id, updateHash = true) {
  const merged = MERGED_TOOLS[id];
  if (merged) id = merged[0];
  if (!document.querySelector(`#view-${id}`)) id = 'dashboard';
  activeToolId = id;
  document.querySelectorAll('.tool-view').forEach((v) => v.classList.toggle('hidden', v.id !== `view-${id}`));
  document.querySelectorAll('.nav-item').forEach((n) => n.classList.toggle('active', n.dataset.tool === id));
  setHeader(id);
  // v0.10.32: every page change is a history entry, so Back (browser, Alt+←, the mouse's back
  // button) returns to the previous page; pages add their own entries with MistApp.pushView.
  if (updateHash && !(history.state?.nw && history.state.tool === id)) nwHistoryPush(id, null);

  if (LAZY_TOOL_SCRIPTS[id] && !initialized.has(id)) {
    const view = document.querySelector(`#view-${id}`);
    view?.setAttribute('aria-busy', 'true');
    try {
      await loadToolScripts(id);
    } catch (err) {
      console.error(err);
      if (view && !view.querySelector('.nw-lazy-error')) {
        const box = document.createElement('div');
        box.className = 'notice error nw-lazy-error';
        box.textContent = `This page could not be loaded (${err.message}). Open it again to retry.`;
        view.prepend(box);
      }
      return;
    } finally {
      view?.removeAttribute('aria-busy');
    }
    view?.querySelector('.nw-lazy-error')?.remove();
    if (activeToolId !== id) return; // the user moved on while the page downloaded
  }

  const moduleKey = TOOL_MODULE_KEYS[id] || id;
  const module = window.MistTools[moduleKey];
  if (module?.init && !initialized.has(id)) {
    // v0.10.40: one init per page, even when the page is opened again while it is still starting
    // (it used to run init twice, registering every listener twice). A failed init is retried next open.
    if (!toolInits[id]) {
      toolInits[id] = Promise.resolve()
        .then(() => module.init())
        .then(
          () => {
            initialized.add(id);
            toolDataAt[id] = Date.now();
          },
          (err) => {
            delete toolInits[id];
            throw err;
          },
        );
    }
    await toolInits[id];
  } else if (module?.refresh) {
    const recent = REVISIT_DATA_ONLY.has(id) && Date.now() - (toolDataAt[id] || 0) < REVISIT_FRESH_MS;
    if (!recent) {
      await module.refresh(false);
      toolDataAt[id] = Date.now();
    }
  }
  if (merged?.[1]) document.querySelector(merged[1])?.scrollIntoView({ block: 'start' });
}

async function autoRefreshActiveTool() {
  if (document.visibilityState !== 'visible' || autoRefreshBusy) return;
  if (!initialized.has(activeToolId) && (LAZY_TOOL_SCRIPTS[activeToolId] || toolInits[activeToolId])) return; // still opening
  const toolId = activeToolId;
  const module = window.MistTools[TOOL_MODULE_KEYS[toolId] || toolId];
  const refreshFn = module?.autoRefresh || (module?.refresh ? () => module.refresh(false) : null);
  if (!refreshFn) return;
  autoRefreshBusy = true;
  try {
    await refreshFn();
    if (!module?.autoRefresh) toolDataAt[toolId] = Date.now();
  } catch (err) {
    console.warn(`Automatic refresh failed for ${activeToolId}`, err);
  } finally {
    autoRefreshBusy = false;
  }
}

let uiState = { theme: document.documentElement.dataset.theme || 'original', themes: [], groups: [] };

function themeNavStyle() {
  const theme = uiState.themes.find((t) => t.id === document.documentElement.dataset.theme);
  return theme?.nav || 'full';
}

// The page layout (Settings › Look & layout) decides where the menu sits; the theme styles it.
function effectiveNavStyle() {
  const root = document.documentElement;
  if (root.dataset.lnav === 'top') return 'top';
  if (root.classList.contains('menu-hidden')) return 'rail';
  const nav = themeNavStyle();
  return nav === 'full' || nav === 'compact' ? nav : 'compact';
}

function currentNavStyle() {
  return document.documentElement.dataset.nav || effectiveNavStyle();
}

function navButton(t) {
  return (
    `<button class="nav-item" data-tool="${nwEscapeHtml(t.id)}" title="${nwEscapeHtml(t.label)}: ${nwEscapeHtml(t.description)}">` +
    `<span class="nav-icon-wrap"><span class="nav-icon">${nwEscapeHtml(t.icon)}</span>` +
    `<span class="nav-badge hidden" data-nav-badge="${nwEscapeHtml(t.id)}">0</span></span>` +
    `<span class="nav-short">${nwEscapeHtml(t.short_label || t.label)}</span>` +
    `<span><strong>${nwEscapeHtml(t.label)}</strong><small>${nwEscapeHtml(t.description)}</small></span></button>`
  );
}

function renderNav() {
  const nav = document.querySelector('#toolNav');
  const badges = {};
  nav.querySelectorAll('[data-nav-badge]').forEach((b) => (badges[b.dataset.navBadge] = b.textContent));
  if (currentNavStyle() === 'full') {
    // Original layout: registry order, no group headings.
    nav.innerHTML = tools.map(navButton).join('');
  } else {
    const order = uiState.groups.length ? uiState.groups : [...new Set(tools.map((t) => t.group))];
    const groups = [...order, ...new Set(tools.map((t) => t.group).filter((g) => !order.includes(g)))];
    nav.innerHTML = groups
      .map((g) => {
        const items = tools.filter((t) => (t.group || '') === g);
        return items.length
          ? `<div class="nav-group-label" role="presentation">${nwEscapeHtml(g)}</div>` +
              items.map(navButton).join('')
          : '';
      })
      .join('');
  }
  nav
    .querySelectorAll('.nav-item')
    .forEach((b) => b.addEventListener('click', () => openTool(b.dataset.tool)));
  nav
    .querySelectorAll('.nav-item')
    .forEach((n) => n.classList.toggle('active', n.dataset.tool === activeToolId));
  Object.entries(badges).forEach(([id, count]) => setNavBadge(id, Number(count) || 0));
}

function restoreUiNames() {
  try {
    if (localStorage.getItem('nodewatch.showUiNames') === '1')
      document.documentElement.classList.add('show-ui-names');
  } catch {
    /* storage unavailable */
  }
}

async function loadUiState() {
  restoreUiNames();
  try {
    uiState = await getJSON('/api/ui');
  } catch (err) {
    console.warn('UI preferences unavailable', err);
  }
  restoreLayout();
  // ?theme=<id> previews a theme without saving it.
  const preview = new URLSearchParams(location.search).get('theme');
  if (preview && uiState.themes.some((t) => t.id === preview))
    document.documentElement.dataset.theme = preview;
  else if (uiState.theme) document.documentElement.dataset.theme = uiState.theme;
  // ?night=on|off previews night mode without saving it.
  const nightPreview = new URLSearchParams(location.search).get('night');
  if (['on', 'off', 'system'].includes(nightPreview)) setNight(nightPreview, { save: false });
  syncThemeAttributes();
}

function syncThemeAttributes() {
  const root = document.documentElement;
  const theme = uiState.themes.find((t) => t.id === root.dataset.theme);
  if (theme) {
    root.dataset.mode = theme.mode;
    root.dataset.themeNav = theme.nav;
  }
  root.dataset.nav = effectiveNavStyle();
  updateNightToggle();
}

async function saveUiPreferences(changes) {
  const r = await fetch('/api/ui/preferences', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(changes),
  });
  if (r.ok) uiState = await r.json();
  return r.ok;
}

// Night mode: "off", "on" or "system" (follow the Windows light/dark setting).
function nightIsOn() {
  return document.documentElement.dataset.night === 'on';
}

function updateNightToggle() {
  const btn = document.querySelector('#nightToggle');
  if (!btn) return;
  const on = nightIsOn();
  btn.setAttribute('aria-pressed', String(on));
  btn.title = on ? 'Switch to day mode' : 'Switch to night mode';
  btn.querySelector('.night-icon').textContent = on ? '☀' : '☾';
  btn.querySelector('.night-label').textContent = on ? 'Day' : 'Night';
}

async function setNight(pref, { save = true } = {}) {
  if (!['off', 'on', 'system'].includes(pref)) return;
  const root = document.documentElement;
  root.dataset.nightPref = pref;
  if (pref === 'system') window.NodeWatchNight?.sync();
  else root.dataset.night = pref;
  updateNightToggle();
  document.dispatchEvent(new CustomEvent('nodewatch:ui-changed'));
  if (save) await saveUiPreferences({ night: pref });
}

// Left menu: collapsed shows an icon rail (saved as menu "hidden" for compatibility).
function menuIsHidden() {
  return document.documentElement.classList.contains('menu-hidden');
}

function syncNavStyle() {
  const root = document.documentElement;
  const before = root.dataset.nav;
  root.dataset.nav = effectiveNavStyle();
  if (before !== root.dataset.nav && tools.length) renderNav();
  positionSidebarHandle();
}

// Round handle on the sidebar's right edge, vertically centred in the window.
function positionSidebarHandle() {
  const handle = document.querySelector('#sidebarHandle');
  const side = document.querySelector('.sidebar');
  if (!handle || !side) return;
  const collapsed = menuIsHidden();
  handle.style.setProperty('--nw-handle-x', `${Math.round(side.getBoundingClientRect().right)}px`);
  handle.setAttribute('aria-expanded', String(!collapsed));
  const label = collapsed ? 'Expand menu' : 'Collapse menu to icons';
  handle.setAttribute('aria-label', label);
  handle.dataset.tip = `${collapsed ? 'Expand menu' : 'Collapse menu'} · Ctrl+B`;
  const icon = handle.querySelector('.sidebar-handle-icon');
  if (icon) icon.textContent = collapsed ? '›' : '‹';
}

async function setMenuHidden(hidden, { save = true } = {}) {
  document.documentElement.classList.toggle('menu-hidden', !!hidden);
  syncNavStyle();
  document.dispatchEvent(new CustomEvent('nodewatch:ui-changed'));
  if (save) await saveUiPreferences({ menu: hidden ? 'hidden' : 'shown' });
}

// ------------------------------------------------------------ page layout (v0.10.15)
const LAYOUT_KEY = 'nodewatch.layout';
const LAYOUT_CHOICES = {
  preset: ['aurora', 'dense', 'top', 'focus', 'custom'],
  nav: ['side', 'top'],
  density: ['comfortable', 'compact'],
  width: ['fixed', 'full'],
  radius: ['theme', 'square', 'subtle', 'rounded', 'round'],
  glass: ['on', 'off'],
  shadows: ['on', 'off'],
  text: ['s', 'm', 'l', 'xl'],
};
const LAYOUT_DEFAULT = {
  preset: 'aurora',
  nav: 'side',
  density: 'comfortable',
  width: 'fixed',
  radius: 'theme',
  glass: 'on',
  shadows: 'on',
  text: 'm',
};
// collapsed: whether a preset starts with the menu folded to icons (the handle can still change it).
const LAYOUT_PRESETS = {
  aurora: {
    nav: 'side',
    density: 'comfortable',
    width: 'fixed',
    radius: 'theme',
    glass: 'on',
    shadows: 'on',
    collapsed: false,
  },
  dense: {
    nav: 'side',
    density: 'compact',
    width: 'full',
    radius: 'subtle',
    glass: 'off',
    shadows: 'off',
    collapsed: false,
  },
  top: { nav: 'top', density: 'comfortable', width: 'fixed', radius: 'theme', glass: 'on', shadows: 'on' },
  focus: {
    nav: 'side',
    density: 'comfortable',
    width: 'full',
    radius: 'theme',
    glass: 'on',
    shadows: 'on',
    collapsed: true,
  },
};
const LAYOUT_ATTRS = {
  preset: 'layout',
  nav: 'lnav',
  density: 'ldensity',
  width: 'lwidth',
  radius: 'lradius',
  glass: 'lglass',
  shadows: 'lshadow',
  text: 'text',
};

function cleanLayout(value) {
  const out = { ...LAYOUT_DEFAULT };
  if (value && typeof value === 'object')
    Object.keys(LAYOUT_CHOICES).forEach((k) => {
      if (LAYOUT_CHOICES[k].includes(value[k])) out[k] = value[k];
    });
  return out;
}

function currentLayout() {
  const root = document.documentElement;
  return cleanLayout(Object.fromEntries(Object.entries(LAYOUT_ATTRS).map(([k, a]) => [k, root.dataset[a]])));
}

function writeLayoutAttributes(layout) {
  const root = document.documentElement;
  Object.entries(LAYOUT_ATTRS).forEach(([k, a]) => (root.dataset[a] = layout[k]));
}

function storeLayoutLocally(layout) {
  try {
    localStorage.setItem(LAYOUT_KEY, JSON.stringify(layout));
  } catch {
    /* storage unavailable: the server copy still applies */
  }
}

function readLocalLayout() {
  try {
    const raw = localStorage.getItem(LAYOUT_KEY);
    return raw ? cleanLayout(JSON.parse(raw)) : null;
  } catch {
    return null;
  }
}

// Server copy wins (it does not depend on the local port); an older local-only copy is uploaded once.
function restoreLayout() {
  if (uiState.layout_saved && uiState.layout) {
    const layout = cleanLayout(uiState.layout);
    writeLayoutAttributes(layout);
    storeLayoutLocally(layout);
    return;
  }
  const local = readLocalLayout();
  if (local) {
    writeLayoutAttributes(local);
    saveUiPreferences({ layout: local }).catch(() => {});
  }
}

// changes: any layout keys, plus "collapsed" (menu folded to icons). A preset id applies its values.
async function applyLayout(changes = {}, { save = true } = {}) {
  let next = { ...currentLayout(), ...changes };
  let collapsed = changes.collapsed;
  const preset = LAYOUT_PRESETS[changes.preset];
  if (preset) {
    const { collapsed: presetCollapsed, ...values } = preset;
    next = { ...next, ...values, preset: changes.preset };
    if (collapsed === undefined) collapsed = presetCollapsed;
  }
  const layout = cleanLayout(next);
  writeLayoutAttributes(layout);
  if (collapsed !== undefined && layout.nav === 'side')
    document.documentElement.classList.toggle('menu-hidden', !!collapsed);
  syncNavStyle();
  document.dispatchEvent(new CustomEvent('nodewatch:ui-changed'));
  if (!save) return layout;
  storeLayoutLocally(layout);
  const prefs = { layout };
  if (collapsed !== undefined && layout.nav === 'side') prefs.menu = collapsed ? 'hidden' : 'shown';
  try {
    await saveUiPreferences(prefs);
  } catch (err) {
    console.warn('Layout saved on this computer only', err);
  }
  return layout;
}

function resetLayout() {
  return applyLayout({ ...LAYOUT_DEFAULT, collapsed: false });
}

function wireUiControls() {
  document.querySelector('#sidebarHandle')?.addEventListener('click', () => setMenuHidden(!menuIsHidden()));
  const side = document.querySelector('.sidebar');
  if (side && window.ResizeObserver) new window.ResizeObserver(positionSidebarHandle).observe(side);
  window.addEventListener('resize', positionSidebarHandle);
  positionSidebarHandle();
  document
    .querySelector('#nightToggle')
    ?.addEventListener('click', () => setNight(nightIsOn() ? 'off' : 'on'));
  document.addEventListener('keydown', (e) => {
    if (!(e.ctrlKey || e.metaKey) || e.altKey || e.shiftKey || e.key.toLowerCase() !== 'b') return;
    if (e.target.closest?.('input, textarea, select, [contenteditable="true"]')) return;
    if (document.documentElement.dataset.lnav === 'top') return;
    e.preventDefault();
    setMenuHidden(!menuIsHidden());
  });
  window.matchMedia?.('(prefers-color-scheme: dark)').addEventListener?.('change', () => {
    updateNightToggle();
    document.dispatchEvent(new CustomEvent('nodewatch:ui-changed'));
  });
  updateNightToggle();
}

async function applyTheme(id, { save = true } = {}) {
  if (!uiState.themes.some((t) => t.id === id)) return;
  document.documentElement.dataset.theme = id;
  syncThemeAttributes();
  renderNav();
  if (save) {
    const r = await fetch('/api/ui/theme', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ theme: id }),
    });
    if (r.ok) uiState = await r.json();
  }
}

function setNavBadge(id, count) {
  const e = document.querySelector(`[data-nav-badge="${id}"]`);
  if (!e) return;
  const n = Math.max(0, Number(count) || 0);
  // Show the real count, like an unread badge (abbreviated only beyond 9,999).
  e.textContent = n > 9999 ? `${Math.floor(n / 1000)}k+` : String(n);
  e.title = `${n} alert${n === 1 ? '' : 's'} need attention`;
  e.classList.toggle('hidden', n === 0);
}
window.MistApp = window.MistApp || {};
window.MistApp.setNavBadge = setNavBadge;

function renderDashboardTools() {
  const host = document.querySelector('#dashboardTools');
  if (!host) return;
  host.innerHTML = tools
    .filter((t) => t.id !== 'dashboard')
    .map(
      (t) =>
        `<button class="tool-launch" data-open-tool="${t.id}"><span class="tool-launch-icon">${t.icon}</span><span><strong>${t.label}</strong><small>${t.description}</small></span><b>→</b></button>`,
    )
    .join('');
  host
    .querySelectorAll('[data-open-tool]')
    .forEach((b) => b.addEventListener('click', () => openTool(b.dataset.openTool)));
}

// ---- Close NodeWatch with its last tab (v0.10.15): heartbeat while open, goodbye on close.
const nwNewTabId = () => (window.crypto?.randomUUID?.() || `${Date.now()}-${Math.random()}`).slice(0, 64);
let NW_TAB_ID = nwNewTabId(); // a page restored from the back/forward cache gets a new one
// v0.10.41: the heartbeat is an ordinary request (keepalive only for the goodbye / freeze, which must
// survive the page closing: Chromium allows only a few keepalive requests in flight per page, so a slow
// answer used to make the next heartbeats fail outright), it gives up after 10 s, and the answer says
// how it went: 'ok' (NodeWatch answered), 'busy' (an HTTP error or no answer in time: the server is
// there) or 'down' (no connection at all).
function presence(kind = '', state = document.visibilityState === 'hidden' ? 'hidden' : 'visible', extra = {}) {
  const leaving = kind === '/bye' || state === 'frozen';
  const ctl = !leaving && window.AbortController ? new AbortController() : null;
  const timer = ctl ? setTimeout(() => ctl.abort(), 10000) : null;
  return NODEWATCH_NATIVE_FETCH(`/api/system/presence${kind}`, {
    method: 'POST',
    keepalive: leaving, // still delivered while the tab is closing or freezing
    credentials: 'same-origin',
    cache: 'no-store',
    signal: ctl?.signal,
    headers: { 'Content-Type': 'application/json', 'X-NodeWatch-Request': NODEWATCH_WRITE_TOKEN },
    body: JSON.stringify({ tab: NW_TAB_ID, state, ...extra }),
  })
    .then(
      (r) => (r.ok ? 'ok' : `busy:${r.status}`),
      (err) => (err?.name === 'AbortError' ? 'busy:timeout' : `down:${err?.message || err}`),
    )
    .finally(() => timer && clearTimeout(timer));
}
// Back from the background and NodeWatch does not answer (it stopped while every tab was closed or
// asleep). One failed heartbeat is not proof (a busy backend, a network blip while the PC wakes up), so
// the notice is shown only when NodeWatch could not be reached at all for about 40 s (v0.10.41; it was
// 5.5 s, and a busy or slow answer also counted). While shown it keeps checking and removes itself as
// soon as NodeWatch answers; the page then tells NodeWatch what happened (application.log).
const nwSleep = (ms) => new Promise((r) => setTimeout(r, ms));
let nwAliveCheck = null;
function checkAlive(trigger = 'visible') {
  if (!nwAliveCheck)
    nwAliveCheck = runAliveCheck(trigger).finally(() => {
      nwAliveCheck = null;
    });
  return nwAliveCheck;
}
async function runAliveCheck(trigger) {
  const started = Date.now();
  const attempts = [];
  const answered = async (result) => {
    document.querySelector('#nwStoppedNotice')?.remove();
    if (attempts.length) {
      const seconds = Math.round((Date.now() - started) / 1000);
      presence('', undefined, { report: { trigger, seconds, attempts: attempts.join(', ') } });
    }
    return result;
  };
  for (const wait of [0, 2000, 5000, 10000, 20000]) {
    if (wait) await nwSleep(wait);
    const result = await presence();
    if (result === 'ok') return answered(true);
    attempts.push(result);
    if (result.startsWith('busy')) {
      // The server answered (or is there but slow): it is running. Keep checking quietly.
      await nwSleep(5000);
      const again = await presence();
      if (again === 'ok') return answered(true);
      attempts.push(again);
      if (again.startsWith('busy')) return true;
    }
  }
  showStoppedNotice();
  // Keep checking: a PC waking up can take a while to reach its own loopback again.
  for (;;) {
    await nwSleep(5000);
    if (!document.querySelector('#nwStoppedNotice')) return false; // dismissed or closed
    const result = await presence();
    if (result === 'ok' || result.startsWith('busy')) return answered(true);
    if (attempts.length < 12) attempts.push(result);
  }
}
function showStoppedNotice() {
  if (document.querySelector('#nwStoppedNotice')) return;
  const box = document.createElement('div');
  box.id = 'nwStoppedNotice';
  box.className = 'nw-stopped-notice';
  box.setAttribute('role', 'alert');
  const mac = /Mac/i.test(navigator.userAgent || '');
  const where = mac ? 'from Applications (or the Dock)' : 'from the Start menu or the desktop shortcut';
  const keys = mac ? '⌘W' : 'Alt+F4';
  box.innerHTML =
    '<strong>NodeWatch has stopped</strong>' +
    `<span>To continue, open NodeWatch again ${where} — your settings and data are kept.</span>` +
    '<span class="nw-stopped-actions">' +
    '<button type="button" class="primary" data-nw-stopped="close">Close this window</button>' +
    '<button type="button" class="secondary" data-nw-stopped="dismiss">Dismiss</button></span>';
  box.addEventListener('click', (e) => {
    const act = e.target.closest('[data-nw-stopped]')?.dataset.nwStopped;
    if (act === 'dismiss') box.remove();
    if (act === 'close') {
      window.close();
      // Browsers only let a page close a window it opened; say how when that is refused.
      setTimeout(() => {
        const span = box.querySelector('span');
        if (span) span.textContent = `Close this window with ${keys} or its × button. Open NodeWatch again ${where} to continue.`;
      }, 300);
    }
  });
  document.body.appendChild(box);
}
function startPresence() {
  presence();
  setInterval(() => presence().then((r) => r === 'ok' && document.querySelector('#nwStoppedNotice')?.remove()), 30000);
  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'visible') checkAlive('visible');
    else presence('', 'hidden');
  });
  // Edge sleeping tabs / Chrome Memory Saver freeze background tabs: say so before timers stop.
  document.addEventListener('freeze', () => presence('', 'frozen'));
  document.addEventListener('resume', () => checkAlive('resume'));
  window.addEventListener('pagehide', () => presence('/bye'));
  window.addEventListener('pageshow', (e) => {
    if (!e.persisted) return;
    NW_TAB_ID = nwNewTabId(); // the old id said goodbye on pagehide
    checkAlive('pageshow');
  });
}

async function boot() {
  startPresence();
  // Independent start-up requests run together; the live Mist connection test no longer
  // holds up the first page (it finishes in the background and updates the header).
  // v0.10.24: the quick status answers without contacting Mist (it only says whether Mist is
  // configured); the live check is an ordinary cached organisation read shared with the dashboard, so
  // start-up no longer makes two separate Mist calls before the first page.
  const quickStatus = getJSON('/api/status?quick=true').catch(() => null);
  const liveStatus = refreshConnectionStatus(false);
  [tools] = await Promise.all([getJSON('/api/modules'), loadUiState()]);
  wireUiControls();
  renderNav();
  renderDashboardTools();
  document.querySelector('#brandHome')?.addEventListener('click', () => openTool('dashboard'));
  const status = (await quickStatus) || (await liveStatus);
  const hash = location.hash.replace('#', '');
  const requested = tools.some((t) => t.id === hash) || MERGED_TOOLS[hash] ? hash : 'dashboard';
  // Any connected source (not only Mist) opens the requested page; with none, Settings. Without Mist,
  // Command Center has no data of its own: start on Topology, which every connector feeds.
  if (status && !lastStatus) lastStatus = status;
  const anySource = status?.any_source_configured ?? status?.configured;
  const start = !status?.configured && anySource && requested === 'dashboard' && !hash ? 'topology' : requested;
  const first = anySource ? start : 'settings';
  history.replaceState({ nw: 1, tool: first, view: null }, '', `#${first}`);
  wireHistory();
  await openTool(first, false);
  setInterval(autoRefreshActiveTool, AUTO_REFRESH_MS);
  setInterval(() => {
    if (document.visibilityState === 'visible') refreshConnectionStatus(false);
  }, 60000);
}

// Merge rather than replace: setNavBadge was attached above and modules call it later.
window.MistApp = Object.assign(window.MistApp || {}, {
  refreshConnectionStatus,
  openTool,
  setNavBadge,
  applyTheme,
  setNight,
  setMenuHidden,
  menuIsHidden,
  applyLayout,
  resetLayout,
  currentLayout,
  layoutPresets: () => LAYOUT_PRESETS,
  uiState: () => uiState,
  lastStatus: () => lastStatus,
  pushView,
  isRestoringView: () => nwRestoring,
});
document.addEventListener('DOMContentLoaded', () =>
  boot().catch((err) => {
    console.error(err);
    alert('Failed to load NodeWatch: ' + err.message);
  }),
);
