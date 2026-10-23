// NodeWatch Topology v2 (v0.10.23).
//
// Rewritten from scratch: the v0.10.16–22 map (three layouts per level, force simulation, full SVG
// rebuild on every poll) was slow and hard to read. This version has one deterministic picture per
// level:
//   Organization  a board of site cards, worst first (health rail, devices by role, WAN tunnels)
//   Site          a lane diagram read top to bottom like a single-line drawing:
//                 WAN → edge / firewall → core → distribution → access, APs folded per switch
// One status channel (the bar on each device and the link colour), a right-hand drawer for the
// selected device / issues / path trace, and one search box over the site and the whole org.
// Polling asks the backend whether anything changed (?since=<version>) and redraws only then,
// keeping the viewport and selection. Vanilla JS + SVG, strict CSP (no inline styles/scripts).
(() => {
  'use strict';
  window.MistTools = window.MistTools || {};

  const SVGNS = 'http://www.w3.org/2000/svg';
  const API = '/api/v1/topology';
  const LS = 'nw.topo2.';
  const NODE_W = 190;
  const NODE_H = 56;
  const COL_GAP = 22;
  const ROW_GAP = 30;
  const LANE_PAD = 26;
  const LANE_GAP = 56;
  const RAIL_W = 138;
  const AP_W = 132;
  const AP_H = 34;
  const MAX_PER_ROW = 10;
  const REMOTE_MAX = 12; // more remote sites than this fold into one box in the Wiring view
  const REMOTE_SUMMARY = 'remote:summary';
  const HEALTH_MS = 45000;
  const POLL_FAST_MS = 2500;

  const ROLE = {
    cloud: { label: 'Internet / WAN', short: 'WAN', glyph: 'cloud', lane: 'wan' },
    remote: { label: 'Remote site', short: 'Remote', glyph: 'site', lane: 'wan' },
    circuit: { label: 'Internet circuit', short: 'Circuit', glyph: 'globe', lane: 'wan' },
    sdwan_edge: { label: 'SD-WAN edge', short: 'SD-WAN', glyph: 'sdwan', lane: 'edge' },
    router: { label: 'Router', short: 'Router', glyph: 'router', lane: 'edge' },
    firewall: { label: 'Firewall', short: 'Firewall', glyph: 'firewall', lane: 'edge' },
    load_balancer: { label: 'Load balancer', short: 'LB', glyph: 'router', lane: 'edge' },
    wireless_controller: { label: 'Wireless controller', short: 'WLC', glyph: 'server', lane: 'other' },
    switch: { label: 'Switch', short: 'Switch', glyph: 'switch', lane: 'access' },
    wireless_ap: { label: 'Access point', short: 'AP', glyph: 'ap', lane: 'wireless' },
    server: { label: 'Server', short: 'Server', glyph: 'server', lane: 'other' },
    endpoint: { label: 'Endpoint', short: 'Endpoint', glyph: 'endpoint', lane: 'other' },
    unknown: { label: 'Unidentified device', short: 'Unknown', glyph: 'unknown', lane: 'other' },
    // A cloud security edge (Prisma Access, Zscaler, Cloudflare, Netskope…): no building of its own.
    cloud_gateway: { label: 'Cloud security gateway', short: 'Cloud', glyph: 'cloud', lane: 'cloudsvc' },
  };
  const LANES = [
    { id: 'cloudsvc', label: 'Cloud services' },
    { id: 'remote', label: 'Connected sites' },
    { id: 'wan', label: 'Internet circuits' },
    { id: 'edge', label: 'Edge and firewalls' },
    { id: 'core', label: 'Core' },
    { id: 'distribution', label: 'Distribution' },
    { id: 'access', label: 'Access switches' },
    { id: 'wireless', label: 'Access points without a known uplink' },
    { id: 'other', label: 'Servers, controllers and other devices' },
  ];
  const LAYERS = [
    { id: 'physical', label: 'Cabling', title: 'Physical links, aggregates and layer-2 links (LLDP/CDP)' },
    { id: 'overlay', label: 'Tunnels', title: 'SD-WAN and IPsec tunnels' },
    { id: 'l3', label: 'Routing', title: 'Adds routed links (dotted blue): devices that share a subnet or are each other\'s next hop. The routing tables themselves are in the panel › Routes.' },
  ];
  const SOURCE_LABEL = {
    mist: 'Mist',
    silverpeak_orchestrator: 'Orchestrator',
    paloalto_scm: 'Strata Cloud Manager',
    panorama: 'Panorama',
    fortigate: 'FortiGate',
    snmp: 'SNMP',
  };
  // Product names come from the connectors that answered (sources[].product), so a new vendor's
  // connector is named correctly without changes here; SOURCE_LABEL is only a short-name fallback.
  const srcLabel = (id) => {
    const live = [...(S.graph?.sources || []), ...(S.org?.sources || [])].find((x) => x.source === id);
    return SOURCE_LABEL[id] || live?.product || String(id || '').replace(/_/g, ' ');
  };
  const LAYER_OF = { physical: 'physical', lag: 'physical', l2: 'physical', l3: 'l3', overlay: 'overlay', ha: 'physical' }; // HA pairs show with the cabling

  // ---------------------------------------------------------------- tiny helpers
  const esc = nwEscapeHtml; // one shared escaper (core.js)
  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];
  const store = {
    get(key, fallback) {
      try {
        const raw = localStorage.getItem(LS + key);
        return raw == null ? fallback : JSON.parse(raw);
      } catch {
        return fallback;
      }
    },
    set(key, value) {
      try {
        localStorage.setItem(LS + key, JSON.stringify(value));
      } catch {
        /* private window: per-session only */
      }
    },
  };
  const fmtMac = (m) => {
    const s = String(m || '').replace(/[^0-9a-f]/gi, '').toLowerCase();
    return s.length === 12 ? s.match(/../g).join(':') : String(m || '');
  };
  const plural = (n, one, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;
  const ago = (s) => {
    if (s == null || !Number.isFinite(+s)) return '';
    s = Math.max(0, Math.round(+s));
    if (s < 45) return 'just now';
    if (s < 3600) return `${Math.round(s / 60)} min ago`;
    if (s < 86400) return `${Math.round(s / 3600)} h ago`;
    return `${Math.round(s / 86400)} d ago`;
  };
  const speedText = (mbps) => {
    if (!mbps) return '';
    if (mbps >= 1000) return `${+(mbps / 1000).toFixed(mbps % 1000 ? 1 : 0)} Gb/s`;
    return `${mbps} Mb/s`;
  };
  const truncate = (text, max) => (text.length > max ? `${text.slice(0, max - 1)}…` : text);

  // ---- labels that fit their box (v0.10.27) -------------------------------------------------------
  // Device names are often long and share a long common start (MIST_SW_EX4400_…): keeping the start
  // loses the part that tells devices apart. Labels are measured with the real font, the prefix most
  // devices of the map share is dropped first, and anything still too long is cut in the middle.
  let measureCtx = null;
  function textWidth(text, font) {
    try {
      measureCtx = measureCtx || document.createElement('canvas').getContext('2d');
      measureCtx.font = font;
      return measureCtx.measureText(text).width;
    } catch {
      return text.length * 7.4;
    }
  }
  function nodeFont(kind) {
    const family = nodeFontFamily || (nodeFontFamily = getComputedStyle(document.body).fontFamily || 'sans-serif');
    return kind === 'sub' ? `11.5px ui-monospace, SFMono-Regular, Menlo, monospace` : `650 13.5px ${family}`;
  }
  const fitCache = new Map();
  function fitText(text, maxPx, font) {
    const t = String(text || '');
    const key = `${font}|${Math.round(maxPx)}|${t}`;
    const hit = fitCache.get(key);
    if (hit !== undefined) return hit;
    let out = t;
    if (textWidth(t, font) > maxPx) {
      // Middle ellipsis: keep more of the end (unit numbers, closet, floor) than of the start.
      // Binary search on how many characters to keep (a few measureText calls, not one per character).
      const cut = (keep) => {
        const head = Math.ceil(keep * 0.4);
        return `${t.slice(0, head)}…${t.slice(t.length - (keep - head))}`;
      };
      let lo = 1;
      let hi = t.length - 1;
      out = `${t.slice(0, 3)}…`;
      while (lo <= hi) {
        const mid = (lo + hi) >> 1;
        const cand = cut(mid);
        if (textWidth(cand, font) <= maxPx) {
          out = cand;
          lo = mid + 1;
        } else hi = mid - 1;
      }
    }
    if (fitCache.size > 5000) fitCache.clear();
    fitCache.set(key, out);
    return out;
  }
  let nodeFontFamily = '';
  // The prefix (whole words, split on _ - . space) shared by at least 60% of the map's devices.
  function sharedPrefix(names) {
    const list = names.filter((n) => n && n.length > 12);
    if (list.length < 3) return '';
    const counts = new Map();
    for (const n of list) {
      const parts = n.match(/[^_\-. ]+[_\-. ]?|[_\-. ]/g) || [n]; // words with their separator (no lookbehind: older Safari)
      let acc = '';
      for (let i = 0; i < parts.length - 1; i++) {
        acc += parts[i];
        if (acc.length >= 5) counts.set(acc, (counts.get(acc) || 0) + 1);
      }
    }
    // Only names that start with it lose it, so 3 devices sharing it is enough; pick the prefix that
    // saves the most text (count × length), at least 6 characters.
    let best = '';
    let gain = 0;
    for (const [pre, n] of counts) {
      if (n < 3 || pre.length < 6 || n < list.length * 0.3) continue;
      if (n * pre.length > gain) {
        gain = n * pre.length;
        best = pre;
      }
    }
    return best;
  }
  function displayName(n) {
    if (n.inferred && n.mgmt_ip) return n.mgmt_ip; // "Device at 10.x.x.x": the address is the name
    const name = n.name || '(unnamed)';
    const pre = S.labelPrefix || '';
    return pre && name.startsWith(pre) && name.length > pre.length + 2 ? name.slice(pre.length) : name;
  }

  const api = (path, opts = {}) => nwFetchJSON(path, opts); // shared helper (core.js)

  // ---------------------------------------------------------------- glyphs (24×24 line icons)
  const GLYPH = {
    cloud: 'M7 18h10a4 4 0 0 0 .6-7.95A6 6 0 0 0 6.2 9.1 4.5 4.5 0 0 0 7 18z',
    site: 'M4 20V9l8-5 8 5v11M9 20v-6h6v6',
    sdwan: 'M12 3l9 9-9 9-9-9zM8 12h8M13 9l3 3-3 3',
    router: 'M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18zM8 9l4-3 4 3M8 15l4 3 4-3M12 6v12',
    firewall: 'M3 5h18v14H3zM3 10h18M3 14.5h18M9 5v5M15 5v5M6 10v4.5M12 10v4.5M18 10v4.5M9 14.5V19M15 14.5V19',
    switch: 'M3 8h18v8H3zM6 12h1M9 12h1M12 12h1M15 12h1M18 12h1',
    ap: 'M12 14a1.6 1.6 0 1 0 0 .01M8.5 10.5a5 5 0 0 1 7 0M5.6 7.6a9 9 0 0 1 12.8 0M12 15.5V21',
    server: 'M5 4h14v6H5zM5 14h14v6H5zM8 7h.01M8 17h.01',
    endpoint: 'M4 5h16v11H4zM9 20h6M12 16v4',
    unknown: 'M4 4h16v16H4zM9.5 9.5a2.5 2.5 0 1 1 3.5 2.3c-.6.3-1 .8-1 1.5M12 16.5h.01',
    globe: 'M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18zM3 12h18M12 3c2.6 2.6 3.6 5.6 3.6 9s-1 6.4-3.6 9c-2.6-2.6-3.6-5.6-3.6-9s1-6.4 3.6-9z',
  };
  const glyphPath = (role) => GLYPH[(ROLE[role] || ROLE.unknown).glyph] || GLYPH.unknown;
  const glyphSvg = (role, cls = 'tp-glyph') =>
    `<svg class="${cls}" viewBox="0 0 24 24" aria-hidden="true"><path d="${glyphPath(role)}"/></svg>`;

  // ---------------------------------------------------------------- state
  const S = {
    view: null, // root element
    level: 'org', // 'org' | 'site'
    siteKey: store.get('site', ''),
    sites: [],
    org: null,
    orgVersion: '',
    graph: null,
    graphVersion: '',
    health: null,
    healthOn: store.get('health', true),
    layers: new Set(store.get('layers', ['physical', 'overlay'])),
    selected: null, // node id
    expanded: new Set(), // switch ids whose APs are shown
    drawerTab: 'device',
    drawerOpen: store.get('drawer', true),
    board: { filter: store.get('boardFilter', 'all'), sort: store.get('boardSort', 'worst'), text: '', view: store.get('boardView', 'map') },
    vp: { x: 0, y: 0, k: 1 },
    userMoved: false,
    scene: null,
    pollTimer: 0,
    healthTimer: 0,
    loading: false,
    lastError: '',
    trace: null,
    // v0.10.36: 'layers' (the site from the internet inwards, every box and link clickable) is the default
    mode: store.get('mode2', 'layers'), // 'layers' | 'overview' (plain language) | 'wiring' (lane diagram)
    // v0.10.37: organization views: 'layers' | 'overview' | 'wiring' (one site and everything it connects to)
    orgMode: store.get('orgMode2', 'layers'),
    orgFocus: store.get('orgFocus', ''),
    orgTrail: [],
    stage: null, // overview: the stage or closet whose devices are listed
    circuit: null, // selected circuit key
    siteMap: null,
  };

  // ---------------------------------------------------------------- shell
  function shell() {
    const view = $('#view-topology');
    view.innerHTML = `
      <section class="card tp-shell" data-ui="Topology">
        <header class="tp-bar" data-ui="Topology › Toolbar">
          <nav class="tp-crumbs" aria-label="Map level"></nav>
          <div class="tp-search" role="search">
            <svg class="tp-search-icon" viewBox="0 0 24 24" aria-hidden="true"><path d="M10.5 4a6.5 6.5 0 1 0 0 13 6.5 6.5 0 0 0 0-13zM20 20l-4.8-4.8"/></svg>
            <input id="tpSearch" type="search" placeholder="Find a device or site: name, IP, MAC, serial" autocomplete="off"
              spellcheck="false" role="combobox" aria-autocomplete="list" aria-expanded="false" aria-controls="tpSuggest">
            <kbd class="tp-kbd" aria-hidden="true">/</kbd>
            <ul id="tpSuggest" class="tp-suggest hidden" role="listbox"></ul>
          </div>
          <div class="tp-seg tp-mode hidden" role="group" aria-label="How to show this site">
            <button type="button" data-mode="layers" title="The site from the internet inwards: circuits, routers, firewalls, core, closets - with links, speeds and bundles">Layers</button>
            <button type="button" data-mode="overview" title="Plain-language summary: how this site connects, what is wrong">Overview</button>
            <button type="button" data-mode="wiring" title="Every device and cable, top to bottom">Wiring</button>
          </div>
          <div class="tp-tools">
            <div class="tp-seg tp-layers" role="group" aria-label="Links shown"></div>
            <button type="button" class="tp-toggle" data-act="health" aria-pressed="false" title="Colour devices and links by live health (CPU, memory, errors, tunnel loss and latency)">Live health</button>
            <button type="button" class="tp-btn" data-act="refresh" title="Rebuild the map from every connected source">Refresh</button>
            <button type="button" class="tp-btn" data-act="export" title="Export the topology as a report (PDF) with its data (CSV / JSON)">Export</button>
            <button type="button" class="tp-btn tp-full-btn" data-act="fullscreen" title="Full screen (Shift+F)" aria-pressed="false"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 9V4h5M20 9V4h-5M4 15v5h5M20 15v5h-5"/></svg><span class="tp-full-label">Full screen</span></button>
            <button type="button" class="tp-btn tp-drawer-btn" data-act="drawer" aria-pressed="true" title="Show or hide the side panel">Panel</button>
          </div>
        </header>
        <div class="tp-status" aria-live="polite"></div>
        <div class="tp-body">
          <div class="tp-stage" tabindex="-1">
            <div class="tp-board hidden" data-ui="Topology › Sites"></div>
            <div class="tp-overview hidden" data-ui="Topology › Site overview"></div>
            <div class="tp-layered hidden" data-ui="Topology › Site layers"></div>
            <div class="tp-canvas hidden" data-ui="Topology › Site map">
              <svg class="tp-svg" role="img" aria-label="Site map"><g class="tp-vp"><g class="tp-lanes"></g><g class="tp-links"></g><g class="tp-nodes"></g></g></svg>
              <div class="tp-zoom" role="group" aria-label="Zoom">
                <button type="button" class="tp-btn" data-zoom="in" title="Zoom in (+)">+</button>
                <button type="button" class="tp-btn" data-zoom="out" title="Zoom out (−)">−</button>
                <button type="button" class="tp-btn" data-zoom="fit" title="Fit the map (F)">Fit</button>
                <button type="button" class="tp-btn tp-full-btn" data-zoom="full" title="Full screen (Shift+F)" aria-pressed="false"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 9V4h5M20 9V4h-5M4 15v5h5M20 15v5h-5"/></svg><span class="tp-sr">Full screen</span></button>
                <button type="button" class="tp-btn" data-zoom="aps" title="Show or hide every access point (A)">APs</button>
              </div>
              <div class="tp-legend" aria-hidden="true"></div>
              <div class="tp-tip hidden" role="tooltip"></div>
            </div>
            <div class="tp-empty hidden"></div>
          </div>
          <aside class="tp-drawer" data-ui="Topology › Panel">
            <div class="tp-tabs" role="tablist">
              <button type="button" role="tab" data-tab="device">Device</button>
              <button type="button" role="tab" data-tab="issues">Issues <span class="tp-count" data-count="issues"></span></button>
              <button type="button" role="tab" data-tab="trace">Path trace</button>
              <button type="button" role="tab" data-tab="routes" title="Routing tables of this site's firewalls, routers and SD-WAN edges">Routes</button>
            </div>
            <div class="tp-drawer-body"></div>
          </aside>
        </div>
      </section>`;
    S.view = view;
    sizeShell();
    renderLayerButtons();
    syncToggles();
    wire();
  }

  // The card ends at the bottom of the window (CSS reads --tp-top).
  function sizeShell() {
    const shell = $('.tp-shell', S.view);
    if (!shell || S.view.classList.contains('hidden')) return;
    const top = shell.getBoundingClientRect().top + window.scrollY;
    if (top > 0) shell.style.setProperty('--tp-top', `${Math.round(top)}px`);
  }

  function renderLayerButtons() {
    $('.tp-layers', S.view).innerHTML = LAYERS.map(
      (l) =>
        `<button type="button" data-layer="${l.id}" aria-pressed="${S.layers.has(l.id)}" title="${esc(l.title)}">${esc(l.label)}</button>`,
    ).join('');
  }

  function syncToggles() {
    const h = $('[data-act="health"]', S.view);
    h.setAttribute('aria-pressed', String(!!S.healthOn));
    $$('[data-layer]', S.view).forEach((b) => b.setAttribute('aria-pressed', String(S.layers.has(b.dataset.layer))));
    // v0.10.37: the whole-organization views use the full width; the panel opens there only when asked for
    const panelOpen = S.level === 'site' ? S.drawerOpen : !!S.drawerOrg;
    $('.tp-shell', S.view).classList.toggle('drawer-closed', !panelOpen);
    $('[data-act="drawer"]', S.view).setAttribute('aria-pressed', String(!!panelOpen));
    const site = S.level === 'site';
    // v0.10.32: the organization has its own Overview / Wiring choice (Wiring = how every site connects).
    $('.tp-mode', S.view).classList.toggle('hidden', false);
    const modeNow = site ? S.mode : S.orgMode;
    $$('[data-mode]', S.view).forEach((b) => b.setAttribute('aria-pressed', String(b.dataset.mode === modeNow)));
    const ov = $('.tp-mode [data-mode="overview"]', S.view);
    const wi = $('.tp-mode [data-mode="wiring"]', S.view);
    if (ov) ov.title = site ? 'Plain-language summary: how this site connects, what is wrong' : 'What needs attention, every site worst first, and which system covers each layer';
    if (wi) wi.title = site ? 'Every device and cable, top to bottom' : 'One site and everything it is connected to: hubs, peers, cloud services and overlays';
    const ly = $('.tp-mode [data-mode="layers"]', S.view);
    if (ly) ly.title = site ? 'The site from the internet inwards: circuits, routers, firewalls, core, closets' : 'Every layer of the network for every site: cloud services, WAN overlays, sites grouped by type';
    $('.tp-shell', S.view)?.classList.toggle('is-org-wiring', false);
    $('.tp-layers', S.view).classList.toggle('hidden', !(site && S.mode === 'wiring'));
    $$('.tp-tabs [data-tab]', S.view).forEach((b) => {
      b.setAttribute('aria-selected', String(b.dataset.tab === S.drawerTab));
      b.classList.toggle('is-on', b.dataset.tab === S.drawerTab);
    });
  }

  function setStatus(html, kind = '') {
    const el = $('.tp-status', S.view);
    el.className = `tp-status ${kind}`;
    el.innerHTML = html;
  }

  function showEmpty(html) {
    const el = $('.tp-empty', S.view);
    el.innerHTML = html;
    el.classList.remove('hidden');
    $('.tp-board', S.view).classList.add('hidden');
    $('.tp-canvas', S.view).classList.add('hidden');
    $('.tp-overview', S.view).classList.add('hidden');
    $('.tp-layered', S.view)?.classList.add('hidden');
  }

  // ---------------------------------------------------------------- breadcrumbs + site switcher
  function siteName(key) {
    if (!key) return '';
    const s = S.sites.find((x) => x.key === key || (x.keys || []).includes(key));
    return s?.name || S.graph?.site?.name || key;
  }

  function renderCrumbs() {
    const nav = $('.tp-crumbs', S.view);
    const org = `<button type="button" class="tp-crumb${S.level === 'org' ? ' is-here' : ''}" data-act="org">Organization</button>`;
    if (S.level === 'org') {
      nav.innerHTML = `${org}<button type="button" class="tp-crumb tp-picker-btn" data-act="picker" aria-haspopup="listbox">Open a site ▾</button>`;
    } else {
      nav.innerHTML = `${org}<span class="tp-crumb-sep" aria-hidden="true">/</span><button type="button" class="tp-crumb is-here tp-picker-btn" data-act="picker" aria-haspopup="listbox" title="Switch site">${esc(siteName(S.siteKey))} ▾</button>`;
    }
  }

  function openPicker(anchor) {
    closePopovers();
    const pop = document.createElement('div');
    pop.className = 'tp-pop tp-picker';
    pop.innerHTML = `<input type="search" placeholder="Filter sites" aria-label="Filter sites" spellcheck="false"><ul role="listbox"></ul>`;
    const list = $('ul', pop);
    const draw = (q) => {
      const term = q.trim().toLowerCase();
      const rows = S.sites
        .filter((s) => !term || s.name.toLowerCase().includes(term) || (s.names || []).some((n) => n.toLowerCase().includes(term)))
        .slice(0, 300);
      // "Entire organization" is always the first choice (hidden only when the filter clearly names a site).
      const showOrg = !term || 'entire organization all sites org'.includes(term) || !rows.length;
      const orgRow = showOrg
        ? `<li role="option" tabindex="-1" class="tp-pick-org" data-org="1"${S.level === 'org' ? ' aria-selected="true"' : ''}><span>Entire organization</span><small>${plural((S.org?.sites || S.sites).length, 'site')}</small></li>`
        : '';
      list.innerHTML = orgRow + (rows.length
        ? rows
            .map(
              (s) =>
                `<li role="option" tabindex="-1" data-site="${esc(s.key)}"${s.key === S.siteKey ? ' aria-selected="true"' : ''}><span>${esc(s.name)}</span><small>${esc((s.sources || []).length > 1 ? `${s.sources.length} sources` : s.sources?.[0] || '')}</small></li>`,
            )
            .join('')
        : '<li class="tp-muted">No site matches</li>');
    };
    draw('');
    document.body.appendChild(pop);
    const r = anchor.getBoundingClientRect();
    pop.style.setProperty('--tp-pop-x', `${Math.round(r.left)}px`);
    pop.style.setProperty('--tp-pop-y', `${Math.round(r.bottom + 6)}px`);
    const input = $('input', pop);
    input.focus();
    input.addEventListener('input', () => draw(input.value));
    input.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        const first = $('[data-site], [data-org]', list);
        closePopovers();
        if (first?.dataset.org) openOrg();
        else if (first) openSite(first.dataset.site);
      } else if (e.key === 'Escape') closePopovers();
    });
    list.addEventListener('click', (e) => {
      const li = e.target.closest('[data-site], [data-org]');
      if (!li) return;
      closePopovers();
      if (li.dataset.org) openOrg();
      else openSite(li.dataset.site);
    });
  }

  function closePopovers() {
    $$('.tp-pop').forEach((p) => p.remove());
  }

  // ---------------------------------------------------------------- loading
  async function loadSites() {
    try {
      const data = await api(`${API}/sites`);
      S.sites = (data.sites || []).slice().sort((a, b) => a.name.localeCompare(b.name));
      S.sitesAt = Date.now();
    } catch (err) {
      S.sites = [];
      console.warn('topology sites', err);
    }
  }

  async function loadOrg({ fresh = false, quiet = false } = {}) {
    const q = new URLSearchParams();
    if (fresh) q.set('fresh', 'true');
    if (quiet && S.orgVersion && !fresh) q.set('since', S.orgVersion);
    let data;
    try {
      data = await api(`${API}/org${q.toString() ? `?${q}` : ''}`);
    } catch (err) {
      if (!quiet) showEmpty(`<p><strong>The organization map could not be loaded.</strong></p><p class="tp-muted">${esc(err.message)}</p><button type="button" class="tp-btn" data-act="refresh">Try again</button>`);
      return;
    }
    if (data.unchanged) {
      orgStatus(data);
      return schedulePoll(data);
    }
    S.org = data;
    S.orgVersion = data.version || '';
    renderBoard();
    orgStatus(data);
    schedulePoll(data);
  }

  async function loadSite({ fresh = false, quiet = false } = {}) {
    if (!S.siteKey) return loadOrg({ fresh, quiet });
    const key = S.siteKey;
    const q = new URLSearchParams({ site: key, layers: [...S.layers].join(',') });
    if (S.mode === 'overview') q.set('view', 'overview'); // light payload; device details load on click
    if (fresh) q.set('fresh', 'true');
    if (quiet && S.graphVersion && !fresh) q.set('since', S.graphVersion);
    if (!quiet && !S.graph) showEmpty('<div class="tp-spinner" aria-hidden="true"></div><p>Building the site map…</p>');
    let data;
    try {
      data = await api(`${API}?${q}`);
    } catch (err) {
      if (key !== S.siteKey) return;
      if (!quiet || !S.graph) showEmpty(`<p><strong>This site map could not be loaded.</strong></p><p class="tp-muted">${esc(err.message)}</p><button type="button" class="tp-btn" data-act="refresh">Try again</button>`);
      else setStatus(`Refresh failed: ${esc(err.message)}`, 'is-error');
      return;
    }
    if (key !== S.siteKey) return; // the user switched site meanwhile
    if (S.mode !== 'overview' && data.view === 'overview') return loadSite({ fresh }); // answer for the other view
    if (data.unchanged) {
      siteStatus({ ...S.graph, ...data });
      return schedulePoll(data);
    }
    const first = !S.graph || S.graph.scope !== data.scope;
    S.graph = data;
    S.graphVersion = data.version || '';
    renderCrumbs();
    renderSite({ refit: first && !S.userMoved });
    siteStatus(data);
    schedulePoll(data);
    if (S.healthOn) loadHealth();
    renderDrawer();
    if (S.selected && !/^(circuit|link):/.test(S.selected)) loadNodeDetail(S.selected);
  }

  async function loadHealth() {
    clearTimeout(S.healthTimer);
    if (!S.healthOn || S.level !== 'site' || !S.siteKey) return;
    const key = S.siteKey;
    try {
      const data = await api(`${API}/health?site=${encodeURIComponent(key)}`);
      if (key !== S.siteKey) return;
      S.health = data;
      paintHealth();
      if (S.drawerTab === 'issues' || S.drawerTab === 'device') renderDrawer();
    } catch (err) {
      console.warn('topology health', err);
    } finally {
      if (S.healthOn && S.level === 'site') {
        const tick = () => {
          // Only while Topology is on screen; otherwise check again later without fetching.
          if (document.visibilityState === 'visible' && !$('#view-topology')?.classList.contains('hidden')) loadHealth();
          else S.healthTimer = setTimeout(tick, HEALTH_MS);
        };
        S.healthTimer = setTimeout(tick, HEALTH_MS);
      }
    }
  }

  // While the backend is still building (partial / refreshing) poll quickly, but only with ?since.
  function schedulePoll(data) {
    clearTimeout(S.pollTimer);
    if (!(data?.refreshing || data?.partial)) return;
    S.pollTimer = setTimeout(() => {
      if ($('#view-topology')?.classList.contains('hidden')) return;
      if (S.level === 'site') loadSite({ quiet: true });
      else loadOrg({ quiet: true });
    }, POLL_FAST_MS);
  }

  function freshness(data) {
    const bits = [];
    if (data.refreshing) bits.push('<span class="tp-pulse" aria-hidden="true"></span>Updating…');
    else if (data.age_s != null) bits.push(`Updated ${ago(data.age_s)}`);
    if (data.partial) bits.push('some sources are still loading');
    if (data.refresh_error) bits.push(`<span class="tp-warn-text">last refresh failed: ${esc(truncate(data.refresh_error, 140))}</span>`);
    return bits.join(' · ');
  }

  function sourceNote(sources) {
    const bad = (sources || []).filter((s) => !s.ok || s.stale);
    if (!bad.length) return '';
    return ` · <button type="button" class="tp-link tp-warn-text" data-act="issues">${plural(bad.length, 'source')} not answering</button>`;
  }

  function orgStatus(data) {
    const st = data.stats || S.org?.stats || {};
    const parts = [];
    if (st.sites != null) parts.push(plural(st.sites, 'site'));
    if (st.devices != null) parts.push(plural(st.devices, 'device'));
    if (st.tunnels) parts.push(plural(st.tunnels, 'tunnel'));
    setStatus(`${parts.join(', ')}<span class="tp-status-sep"></span>${freshness(data)}${sourceNote(data.sources || S.org?.sources)}`);
  }

  function siteStatus(data) {
    const st = data.stats || {};
    const parts = [];
    if (st.nodes != null) parts.push(plural(st.nodes, 'device'));
    if (st.links != null) parts.push(plural(st.links, 'link'));
    setStatus(`${parts.join(', ')}<span class="tp-status-sep"></span>${freshness(data)}${sourceNote(data.sources)}`);
  }

  // ---------------------------------------------------------------- organization board
  const SITE_RANK = { critical: 0, down: 0, warning: 1, degraded: 1, unknown: 2, good: 3, healthy: 3, up: 3 };
  function siteState(s) {
    const h = String(s.health || s.status || '').toLowerCase();
    if (s.down > 0 || h === 'critical' || h === 'down') return 'crit';
    if (s.degraded > 0 || s.upstream_down || h === 'warning' || h === 'degraded') return 'warn';
    if (h === 'good' || h === 'healthy' || h === 'up' || s.devices > 0) return 'good';
    return 'none';
  }

  // ---------------------------------------------------------------- whole organization (v0.10.37)
  // Three views of every site, vendor-neutral (roles, overlay kinds and cloud services, never product names):
  // Layers (every layer of the network, sites grouped by type), Overview (what needs attention, coverage by
  // layer) and Wiring (one site and everything it is connected to). The backend's ``insights`` say what each
  // site is, which overlays exist and their shape, and which connected system covers each layer.
  const num = (n) => (n == null || n === '' ? '—' : Number(n).toLocaleString());
  const ORG_TYPE_ORDER = ['hub', 'large', 'branch', 'small', 'onramp', 'standalone', 'staging', 'empty'];
  const ORG_TYPE_RULE = {
    hub: 'main sites of the overlay: most circuits, reached by every site',
    large: '50 or more devices',
    branch: '10 to 49 devices',
    small: 'under 10 devices',
    onramp: 'one WAN edge and no LAN devices',
    standalone: 'not on any site-to-site overlay: their own internet',
    staging: 'every device offline: staging or retired?',
    empty: 'no device assigned',
  };
  const ORG_LAYERS = [
    ['W', 'circuits', (s) => s.circuits_total || 0, (s) => s.circuits_down || 0],
    ['E', 'WAN edges / routers', (s) => (s.by_role?.sdwan_edge || 0) + (s.by_role?.router || 0), (s) => (s.upstream_down ? 1 : 0)],
    ['F', 'firewalls', (s) => s.by_role?.firewall || 0, () => 0],
    ['S', 'switches', (s) => s.by_role?.switch || 0, () => 0],
    ['A', 'access points', (s) => s.by_role?.wireless_ap || 0, () => 0],
  ];
  const orgIns = () => S.org?.insights || { site_types: {}, overlays: [], coverage: [], attention: [], kpis: {}, type_labels: {} };
  const orgSites = () => (S.org?.sites || []).filter((s) => !s.cloud);
  const siteTypeOf = (s) => orgIns().site_types?.[s.key]?.type || (s.peers ? 'branch' : 'standalone');
  function orgCells(s) {
    // the site's own Layers view in five cells; a down device of the site is shown on the layer it belongs to
    const downRoles = new Set((s.down_names || []).map((d) => d.role));
    return ORG_LAYERS.map(([k, label, count, bad]) => {
      const n = count(s);
      const roleBad = { W: bad(s), E: bad(s) || downRoles.has('sdwan_edge') || downRoles.has('router'), F: downRoles.has('firewall'), S: downRoles.has('switch'), A: downRoles.has('wireless_ap') }[k];
      return `<span class="tp-org-cell${n ? '' : ' is-none'}${n && roleBad ? ' is-bad' : ''}" title="${esc(`${n || 'no'} ${label}`)}"><b>${k}</b>${n || '–'}</span>`;
    }).join('');
  }
  function orgTile(s, { focus = false } = {}) {
    const st = siteState(s);
    const t = orgIns().site_types?.[s.key];
    return `<button type="button" class="tp-org-tile ly-${st}${S.orgFocus === s.key && focus ? ' is-sel' : ''}" ${focus ? `data-focus="${esc(s.key)}"` : `data-site="${esc(s.key)}"`} title="${esc(`${s.name} · ${s.devices || 0} devices${s.down ? ` · ${s.down} down` : ''}${t?.why ? ` · ${t.why}` : ''}`)}">
      <span class="tp-org-tile-head"><b>${esc(s.name)}</b>${s.down ? `<small class="tp-org-down">${esc(`${s.down} down`)}</small>` : ''}</span>
      <span class="tp-org-cells">${orgCells(s)}</span>
    </button>`;
  }
  function orgShell(cls, html) {
    const board = $('.tp-board', S.view);
    $('.tp-empty', S.view).classList.add('hidden');
    $('.tp-canvas', S.view).classList.add('hidden');
    $('.tp-overview', S.view).classList.add('hidden');
    $('.tp-layered', S.view)?.classList.add('hidden');
    board.classList.remove('hidden');
    board.className = `tp-board ${cls}`;
    board.innerHTML = html;
    S.scene = null;
  }
  const productList = (arr) => (arr || []).map((x) => `<span class="tp-org-src">${esc(x)}</span>`).join('') || '<span class="tp-org-src is-none">not connected</span>';

  function renderOrgLayers() {
    const ins = orgIns();
    const sites = orgSites();
    const s2s = ins.overlays.filter((o) => o.kind === 'site_to_site');
    const clouds = ins.overlays.filter((o) => o.kind === 'cloud_service');
    const byKey = Object.fromEntries((S.org?.sites || []).map((s) => [s.key, s]));
    const onramps = sites.filter((s) => siteTypeOf(s) === 'onramp');
    const k = ins.kpis || {};
    const svc = [
      ...clouds.map((c) => `<div class="tp-org-svc is-cloud"><small>${esc(c.label)}</small><b>${esc(c.name)}</b><span class="tp-mono">${esc(`${c.gateways} gateways · ${c.sites.length} sites attached · ${c.status}`)}</span></div>`),
      ...onramps.map((s) => {
        const t = ins.site_types[s.key];
        return `<div class="tp-org-svc is-onramp"><small>Cloud on-ramp${t?.suggested ? ' · suggested' : ''}</small><b>${esc(s.name)}</b><span>${esc(t?.why || '')}${t?.suggested ? ` · <button type="button" class="tp-link" data-sitetype="${esc(s.key)}|onramp">Confirm</button> <button type="button" class="tp-link" data-sitetype="${esc(s.key)}|small">It is a site</button>` : ''}</span></div>`;
      }),
      k.circuits ? `<div class="tp-org-svc"><small>Internet circuits</small><b>${esc(`${k.circuits_up} of ${k.circuits} up`)}</b><span class="tp-mono">${esc(`on ${sites.filter((s) => s.circuits_total).length} sites`)}</span></div>` : '',
    ].filter(Boolean);
    const ovl = [...s2s, ...clouds]
      .map((o) => {
        const bad = (o.degraded?.length || 0) + (o.down?.length || 0);
        const line =
          o.kind === 'site_to_site'
            ? `${o.pairs} of ${o.possible} site pairs · ${num(o.tunnels)} tunnels${bad ? ` · ${bad} pair(s) not fully up` : ''}`
            : `${o.sites.map((x) => byKey[x]?.name || x).join(', ')} → ${o.name}`;
        return `<button type="button" class="tp-org-ovl${o.kind === 'site_to_site' ? ' is-s2s' : ''}" data-ovl="${esc(o.id)}"><span class="tp-dot ly-${bad ? 'warn' : 'good'}"></span><span class="tp-org-ovl-name"><b>${esc(o.label)}</b><small>${esc(o.kind === 'site_to_site' ? `${o.shape_label} (detected) · ${o.sites.length} sites` : `site → cloud service · ${o.sites.length} sites`)}</small></span><span class="tp-mono">${esc(line)}</span><small class="tp-org-from">${esc(o.sources?.length ? `from: ${o.sources.join(', ')}` : '')}</small></button>`;
      })
      .join('');
    const groups = ORG_TYPE_ORDER.filter((t) => t !== 'onramp')
      .map((t) => {
        const list = sites.filter((s) => siteTypeOf(s) === t).sort((a, b) => (siteState(a) === 'crit') - (siteState(b) === 'crit') || (b.devices || 0) - (a.devices || 0));
        if (!list.length) return '';
        return `<div class="tp-org-group"><div class="tp-org-group-head"><b>${esc(ins.type_labels?.[t] || t)} · ${list.length}</b><small>${esc(ORG_TYPE_RULE[t] || '')}</small></div><div class="tp-org-tiles">${list.map((s) => orgTile(s)).join('')}</div></div>`;
      })
      .join('');
    orgShell('is-org-layers', `
      <div class="tp-org-main">
        ${svc.length ? `<section class="tp-ly-band"><header class="tp-ly-band-head"><h3>Cloud and internet services</h3><span class="tp-ly-band-sum">what the sites reach outside your own buildings</span></header><div class="tp-org-svcs">${svc.join('')}</div></section><div class="tp-ly-conn is-empty" aria-hidden="true"></div>` : ''}
        ${ovl ? `<section class="tp-ly-band"><header class="tp-ly-band-head"><h3>WAN overlays</h3><span class="tp-ly-band-sum">each tunnel network between sites, whatever product builds it</span></header>${ovl}</section><div class="tp-ly-conn is-empty" aria-hidden="true"></div>` : `<p class="tp-muted">No site-to-site overlay was reported: connect an SD-WAN, VPN or router system to see how sites reach each other.</p>`}
        <section class="tp-ly-band"><header class="tp-ly-band-head"><h3>Sites · ${sites.length}</h3><span class="tp-ly-band-sum">each tile reads like the site's own Layers view: <b>W</b> circuits · <b>E</b> WAN edges · <b>F</b> firewalls · <b>S</b> switches · <b>A</b> access points</span></header>${groups}</section>
      </div>
      <aside class="tp-org-side">${orgAttention(6)}<p class="tp-muted tp-org-legend">Tile edge = site health · grey cell = layer not present · red cell = something down in that layer. Click a site to open its own Layers view.</p></aside>`);
  }

  function orgAttention(max = 12) {
    const items = (orgIns().attention || []).slice(0, max);
    const word = { now: 'Now', today: 'Today', plan: 'Plan', tidy: 'Tidy' };
    return `<section class="tp-org-attn"><h3>Needs attention <small class="tp-muted">${(orgIns().attention || []).length || ''}</small></h3>${
      items.length
        ? items
            .map((a) => `<div class="tp-org-attn-row is-${a.level}"><span class="tp-org-attn-lvl">${esc(word[a.level] || a.level)}</span><span><b>${esc(a.title)}</b><small>${esc(a.detail || '')}</small></span><button type="button" class="tp-btn" ${a.action === 'wiring' ? `data-focus="${esc(a.site)}" data-towiring="1"` : `data-site="${esc(a.site)}"`}>${a.action === 'wiring' ? 'Show in Wiring' : 'Open'}</button></div>`)
            .join('')
        : '<p class="tp-muted">Nothing needs attention.</p>'
    }</section>`;
  }

  function renderOrgOverview() {
    const ins = orgIns();
    const k = ins.kpis || {};
    const sites = orgSites();
    const rank = { crit: 0, warn: 1, none: 2, good: 3 };
    const rows = sites
      .slice()
      .sort((a, b) => rank[siteState(a)] - rank[siteState(b)] || (b.down || 0) - (a.down || 0) || a.name.localeCompare(b.name))
      .slice(0, S.allSitesRows ? 999 : 14);
    const s2sNames = (s) =>
      ins.overlays
        .filter((o) => o.sites.includes(s.key))
        .map((o) => (o.kind === 'site_to_site' ? o.label.replace(/ overlay$/i, '') : 'cloud'))
        .join(' + ') || 'none';
    const counts = { good: 0, warning: 0, critical: 0, unknown: 0 };
    sites.forEach((s) => (counts[s.health in counts ? s.health : 'unknown'] += 1));
    const total = Math.max(1, sites.length);
    orgShell('is-org-overview', `
      <p class="tp-org-sentence">${esc(ins.sentence || '')}</p>
      <div class="tp-org-kpis">
        <div><small>Sites</small><b>${num(k.sites)}</b><span>${esc(`${k.on_overlay || 0} on an overlay · ${k.standalone || 0} standalone`)}</span></div>
        <div><small>Devices online</small><b>${num(k.devices_up)} / ${num(k.devices)}</b><span>${esc(k.staging_down ? `${num(k.staging_down)} offline are in staging sites` : `${num((k.devices || 0) - (k.devices_up || 0))} offline`)}</span></div>
        <div><small>Internet circuits up</small><b>${num(k.circuits_up)} / ${num(k.circuits)}</b><span>${esc(k.circuits - k.circuits_up ? `${k.circuits - k.circuits_up} down` : 'all up')}</span></div>
        <div><small>Overlay site pairs healthy</small><b>${num(k.pairs_ok)} / ${num(k.pairs)}</b><span>${esc(k.pairs - k.pairs_ok ? `${k.pairs - k.pairs_ok} degraded or down` : 'all up')}</span></div>
        <div><small>Firewall HA pairs</small><b>${num(k.firewall_pairs)}</b><span>sites with two firewalls</span></div>
      </div>
      <div class="tp-org-ov-grid">
        <div class="tp-org-ov-col">
          ${orgAttention(8)}
          <section class="tp-org-attn"><h3>Sites <small class="tp-muted">worst first · ${sites.length}</small> <button type="button" class="tp-link" data-act="all-site-rows">${S.allSitesRows ? 'Show fewer' : 'Show all'}</button></h3>
            <div class="tp-table-wrap"><table class="tp-table tp-org-table" data-nofilter><thead><tr><th></th><th>Site</th><th>Type</th><th>Layers</th><th>Down</th><th>Circuits</th><th>Overlay</th></tr></thead><tbody>${rows
              .map((s) => `<tr data-site="${esc(s.key)}" tabindex="0"><td><span class="tp-dot ly-${siteState(s)}"></span></td><td><b>${esc(s.name)}</b></td><td>${esc(ins.type_labels?.[siteTypeOf(s)] || '')}</td><td><span class="tp-org-cells is-row">${orgCells(s)}</span></td><td class="tp-mono${s.down ? ' tp-org-down' : ''}">${num(s.down || 0)}</td><td class="tp-mono">${s.circuits_total ? esc(`${s.circuits_total - (s.circuits_down || 0)}/${s.circuits_total}`) : '—'}</td><td>${esc(s2sNames(s))}</td></tr>`)
              .join('')}</tbody></table></div></section>
        </div>
        <div class="tp-org-ov-col">
          <section class="tp-org-attn"><h3>Coverage by layer <small class="tp-muted">which connected system sees each layer</small></h3>
            ${(ins.coverage || []).map((c) => `<div class="tp-org-cov"><b>${esc(c.layer)}</b><span class="tp-mono">${esc(c.sites ? `${c.sites} sites` : '—')}</span><span class="tp-org-srcs">${productList(c.sources)}</span></div>`).join('')}
            <p class="tp-muted tp-org-legend">Connect another system in Settings › Connections and its layer fills in here; the maps never depend on one vendor.</p></section>
          <section class="tp-org-attn"><h3>Sites by health</h3>
            <div class="tp-org-hbar">${['good', 'warning', 'critical', 'unknown'].map((h) => `<span class="is-${h}" data-w="${((100 * counts[h]) / total).toFixed(1)}"></span>`).join('')}</div>
            <p class="tp-org-hleg"><span>${counts.good} healthy</span><span>${counts.warning} warning</span><span>${counts.critical} critical</span><span>${counts.unknown} no data</span></p></section>
        </div>
      </div>`);
    $$('.tp-org-hbar [data-w]', S.view).forEach((el) => el.style.setProperty('--w', `${el.dataset.w}%`));
  }

  function orgPeers(key) {
    const out = [];
    for (const l of S.org?.links || []) {
      if (l.a !== key && l.b !== key) continue;
      if ((l.kinds || []).includes('cloud')) continue;
      out.push({ key: l.a === key ? l.b : l.a, link: l });
    }
    return out;
  }
  function renderOrgFocus() {
    const ins = orgIns();
    const sites = orgSites();
    const byKey = Object.fromEntries((S.org?.sites || []).map((s) => [s.key, s]));
    if (!S.orgFocus || !byKey[S.orgFocus]) {
      const firstBad = (ins.attention || []).find((a) => a.action === 'wiring' && byKey[a.site])?.site;
      S.orgFocus = firstBad || ins.overlays.find((o) => o.kind === 'site_to_site')?.hubs?.[0] || sites[0]?.key || '';
    }
    const f = byKey[S.orgFocus];
    if (!f) return orgShell('is-org-focus', '<p class="tp-muted">No site to show.</p>');
    const hubs = new Set(ins.overlays.flatMap((o) => o.hubs || []));
    const peers = orgPeers(f.key);
    const state = (l) => (l.state === 'down' ? 'crit' : l.state === 'degraded' ? 'warn' : l.state === 'up' ? 'good' : 'none');
    const tun = (l) => (l.tunnels ? `${l.up ?? '?'} of ${(l.up || 0) + (l.down || 0) || l.tunnels} tunnels up` : stateWord(l.state || 'unknown'));
    const q = (l) => [l.latency_ms != null ? `${l.latency_ms} ms` : '', l.loss_pct ? `${l.loss_pct}% loss` : ''].filter(Boolean).join(' · ');
    const peerRow = (p, role) => {
      const s = byKey[p.key];
      return `<button type="button" class="tp-org-peer ly-${state(p.link)}" data-focus="${esc(p.key)}"><span class="tp-org-peer-role">${esc(role)}</span><span class="tp-org-peer-name"><span class="tp-dot ly-${state(p.link)}"></span><b>${esc(s?.name || p.key)}</b></span><span class="tp-mono">${esc(tun(p.link))}</span><small>${esc(q(p.link) || (p.link.reasons || []).map((r) => r.text).join('; '))}</small></button>`;
    };
    const hubPeers = peers.filter((p) => hubs.has(p.key));
    const bad = peers.filter((p) => !hubs.has(p.key) && p.link.state !== 'up');
    const ok = peers.filter((p) => !hubs.has(p.key) && p.link.state === 'up').sort((a, b) => String(byKey[a.key]?.name || '').localeCompare(String(byKey[b.key]?.name || '')));
    const myOverlays = ins.overlays.filter((o) => o.sites.includes(f.key));
    const s2s = myOverlays.filter((o) => o.kind === 'site_to_site');
    const clouds = myOverlays.filter((o) => o.kind === 'cloud_service');
    // site-to-site overlays this site could be on but is not part of: the "missing pairs" view of a mesh
    const missing = s2s.flatMap((o) => (o.shape === 'full_mesh' ? o.sites.filter((x) => x !== f.key && !peers.some((p) => p.key === x)) : []));
    const t = ins.site_types?.[f.key];
    const cells = ORG_LAYERS.map(([k2, label, count]) => `<span class="tp-org-bigcell${count(f) ? '' : ' is-none'}"><b>${count(f) || '–'}</b><small>${esc(label)}</small></span>`).join('');
    const list = sites
      .slice()
      .sort((a, b) => a.name.localeCompare(b.name))
      .map((s) => `<option value="${esc(s.key)}"${s.key === f.key ? ' selected' : ''}>${esc(s.name)}</option>`)
      .join('');
    const trail = (S.orgTrail || []).filter((x) => byKey[x]).slice(-5);
    orgShell('is-org-focus', `
      <div class="tp-org-focusbar">
        <label class="tp-org-pick">Focus on <select data-focuspick aria-label="Site to focus on">${list}</select></label>
        ${trail.length > 1 ? `<span class="tp-muted">Trail:</span>${trail.map((x) => `<button type="button" class="tp-org-chip${x === f.key ? ' is-on' : ''}" data-focus="${esc(x)}">${esc(byKey[x].name)}</button>`).join('')}` : ''}
        <span class="tp-muted tp-org-hint">One site and everything it is connected to; readable at any size. Click a peer to focus on it.</span>
      </div>
      <div class="tp-org-focus">
        <div class="tp-org-fcol">
          <h3 class="tp-org-h">Outside the site</h3>
          <div class="tp-org-svc"><small>Internet underlay</small><b>${esc(f.circuits_total ? `${f.circuits_total - (f.circuits_down || 0)} of ${f.circuits_total} circuits up` : 'no circuit reported')}</b></div>
          ${clouds.length ? clouds.map((c) => `<div class="tp-org-svc is-cloud"><small>${esc(c.label)}</small><b>${esc(c.name)}</b><span>${esc(`tunnel · service ${c.status}`)}</span></div>`).join('') : '<div class="tp-org-svc is-empty"><small>Cloud services</small><span>none attached</span></div>'}
          ${s2s.length ? s2s.map((o) => `<div class="tp-org-svc is-s2s"><small>Overlay</small><b>${esc(o.label)}</b><span>${esc(`${o.shape_label} · ${o.sites.length} sites`)}</span></div>`).join('') : '<div class="tp-org-svc is-empty"><small>Overlays</small><span>not on any site-to-site overlay: its own internet only</span></div>'}
        </div>
        <div class="tp-org-fcenter">
          <article class="tp-org-fsite ly-${siteState(f)}">
            <small class="tp-org-fkind">${esc(`${ins.type_labels?.[t?.type] || ''}${t?.user ? ' (set by you)' : ''} · ${f.devices || 0} devices${f.down ? ` · ${f.down} down` : ''}`)}</small>
            <h2>${esc(f.name)}</h2>
            <div class="tp-org-bigcells">${cells}</div>
            <p class="tp-muted">${esc(peers.length ? `Reaches ${peers.length} site(s) directly${bad.length ? ` · ${bad.length} pair(s) need a look` : ''}${missing.length ? ` · ${missing.length} pair(s) never built` : ''}` : 'No direct tunnels to other sites')}</p>
            <div class="tp-actions"><button type="button" class="tp-btn primary" data-site="${esc(f.key)}">Open site layers</button>
              <select class="tp-org-typesel" data-sitetypesel="${esc(f.key)}" aria-label="Site type">${ORG_TYPE_ORDER.map((x) => `<option value="${x}"${t?.type === x ? ' selected' : ''}>${esc(ins.type_labels?.[x] || x)}</option>`).join('')}${t?.user ? '<option value="">Detected type</option>' : ''}</select></div>
          </article>
        </div>
        <div class="tp-org-fcol is-wide">
          <h3 class="tp-org-h">Connected to <small class="tp-muted">${peers.length}</small></h3>
          ${hubPeers.length ? `<div class="tp-org-pgroup"><h4>Hubs and data centers · ${hubPeers.length}</h4>${hubPeers.map((p) => peerRow(p, 'Hub')).join('')}</div>` : ''}
          ${bad.length ? `<div class="tp-org-pgroup is-bad"><h4>Needs a look · ${bad.length}</h4>${bad.map((p) => peerRow(p, 'Peer')).join('')}</div>` : ''}
          ${missing.length ? `<div class="tp-org-pgroup is-missing"><h4>No tunnel to · ${missing.length}</h4><p>${missing.map((x) => `<button type="button" class="tp-link" data-focus="${esc(x)}">${esc(byKey[x]?.name || x)}</button>`).join(', ')}</p></div>` : ''}
          ${ok.length ? `<div class="tp-org-pgroup is-ok">${S.orgShowAll ? ok.map((p) => peerRow(p, 'Peer')).join('') : `<button type="button" class="tp-org-fold" data-act="org-all-peers"><span class="tp-dot ly-good"></span><b>${ok.length} other site(s) · every tunnel up</b><small>${esc(ok.slice(0, 5).map((p) => byKey[p.key]?.name || p.key).join(', '))}${ok.length > 5 ? ` +${ok.length - 5}` : ''}</small><span class="tp-link">Show all</span></button>`}</div>` : ''}
          ${!peers.length ? '<p class="tp-muted">This site has no tunnels to other sites. Its traffic goes straight to the internet.</p>' : ''}
        </div>
      </div>`);
  }

  async function setSiteType(key, type) {
    try {
      await api(`${API}/site-type`, { method: 'PUT', body: JSON.stringify({ site: key, type }) });
      setStatus(type ? 'Site type saved.' : 'Back to the detected site type.', '');
      S.orgVersion = '';
      await loadOrg();
    } catch (err) {
      setStatus(`Not saved: ${esc(err.message)}`, 'is-error');
    }
  }
  function renderBoard() {
    if (S.level === 'org' || !S.siteKey) {
      if (S.orgMode === 'wiring') return renderOrgFocus();
      if (S.orgMode === 'overview') return renderOrgOverview();
      return renderOrgLayers();
    }
    const board = $('.tp-board', S.view);
    $('.tp-empty', S.view).classList.add('hidden');
    $('.tp-canvas', S.view).classList.add('hidden');
    $('.tp-overview', S.view).classList.add('hidden');
    $('.tp-layered', S.view)?.classList.add('hidden');
    board.classList.remove('hidden');
    const org = S.org || { sites: [], links: [] };
    const sites = org.sites || [];
    const counts = { crit: 0, warn: 0, good: 0, none: 0 };
    sites.forEach((s) => counts[siteState(s)]++);
    const term = S.board.text.trim().toLowerCase();
    let rows = sites.filter((s) => {
      const st = siteState(s);
      if (S.board.filter === 'attention' && !(st === 'crit' || st === 'warn')) return false;
      if (S.board.filter === 'healthy' && st !== 'good') return false;
      if (term && !`${s.name} ${(s.names || []).join(' ')}`.toLowerCase().includes(term)) return false;
      return true;
    });
    const rank = { crit: 0, warn: 1, none: 2, good: 3 };
    rows.sort((a, b) => {
      if (S.board.sort === 'name') return a.name.localeCompare(b.name);
      if (S.board.sort === 'devices') return (b.devices || 0) - (a.devices || 0) || a.name.localeCompare(b.name);
      return rank[siteState(a)] - rank[siteState(b)] || (b.down || 0) - (a.down || 0) || a.name.localeCompare(b.name);
    });
    const hubs = rows.filter((s) => s.hub);
    const others = rows.filter((s) => !s.hub);
    const unassigned = org.unassigned || org.stats?.unassigned || 0;
    board.innerHTML = `
      <div class="tp-board-head">
        <div class="tp-tally" role="group" aria-label="Sites by state">
          ${[
            ['all', 'All sites', sites.length, ''],
            ['attention', 'Need attention', counts.crit + counts.warn, counts.crit ? 'crit' : counts.warn ? 'warn' : ''],
            ['healthy', 'Healthy', counts.good, 'good'],
          ]
            .map(
              ([id, label, n, tone]) =>
                `<button type="button" class="tp-tally-btn${S.board.filter === id ? ' is-on' : ''}" data-filter="${id}" aria-pressed="${S.board.filter === id}"><strong class="tone-${tone}">${n}</strong><span>${label}</span></button>`,
            )
            .join('')}
        </div>
        <div class="tp-board-tools">
          <div class="tp-seg" role="group" aria-label="Organization view">
            <button type="button" data-boardview="map" aria-pressed="${S.board.view === 'map'}" class="${S.board.view === 'map' ? 'is-on' : ''}">Map</button>
            <button type="button" data-boardview="cards" aria-pressed="${S.board.view !== 'map'}" class="${S.board.view !== 'map' ? 'is-on' : ''}">Cards</button>
          </div>
          <input type="search" class="tp-board-filter" placeholder="Filter sites" aria-label="Filter sites" value="${esc(S.board.text)}" spellcheck="false">
          <label class="tp-sort">Sort <select data-act="sort">
            <option value="worst"${S.board.sort === 'worst' ? ' selected' : ''}>Worst first</option>
            <option value="name"${S.board.sort === 'name' ? ' selected' : ''}>Name</option>
            <option value="devices"${S.board.sort === 'devices' ? ' selected' : ''}>Most devices</option>
          </select></label>
        </div>
      </div>
      ${unassigned ? `<div class="tp-callout"><strong>${plural(unassigned, 'device')} could not be placed in a site.</strong> They are not on any site map until you assign them. <button type="button" class="tp-btn" data-act="sitemap">Assign sites</button></div>` : ''}
      ${firewallHint(org)}
      ${
        S.board.view === 'map'
          ? orgMapMarkup(sites, rows, org)
          : `${hubs.length ? `<h3 class="tp-board-title">Hubs and data centers</h3><div class="tp-grid">${hubs.map(siteCard).join('')}</div>` : ''}
      ${hubs.length && others.length ? '<h3 class="tp-board-title">Sites</h3>' : ''}
      <div class="tp-grid">${others.map(siteCard).join('')}</div>`
      }
      ${!rows.length ? `<p class="tp-muted tp-board-none">${sites.length ? 'No site matches this filter.' : 'No sites yet. Connect a network source (a cloud controller, SD-WAN orchestrator, firewall manager or SNMP) in Settings › Connections.'}</p>` : ''}
      ${!unassigned ? '<p class="tp-board-foot"><button type="button" class="tp-link" data-act="sitemap">Review how sources are matched to sites</button></p>' : ''}`;
    renderCrumbs();
    renderDrawer();
  }

  // ---------------------------------------------------------------- organization wiring (v0.10.32)
  // How everything is interconnected: cloud services on top, hubs / data centers, then every other site
  // grouped by the hubs it reaches; one line per pair of sites with SD-WAN / VPN tunnels between them
  // (colour = tunnel health, label = tunnel count). Pan, zoom and full screen like a site's Wiring map;
  // click a site to open it, hover to light up its tunnels.
  function orgSiteNode(s, kind) {
    const st = siteState(s);
    const tone = { crit: 'crit', warn: 'warn', good: 'good', none: 'none' }[st];
    const bits = [plural(s.devices || 0, 'device')];
    if (s.circuits_total) bits.push(plural(s.circuits_total, 'circuit'));
    if (s.down) bits.push(`${s.down} down`);
    return { id: s.key, key: s.key, name: s.name, tone, sub: bits.join(' · '), kind, edges: s.edges || [], site: s };
  }
  function buildOrgScene() {
    const org = S.org || { sites: [], links: [] };
    const sites = org.sites || [];
    const { hubs, groups } = orgGroups(sites, sites, org);
    const lanes = [];
    const cloud = (org.cloud || []).map((c) => ({ id: c.key, key: c.key, name: c.name, tone: c.status === 'down' ? 'crit' : 'good', sub: plural(c.gateways || 0, 'gateway'), kind: 'cloud' }));
    if (cloud.length) lanes.push({ id: 'cloudsvc', label: 'Cloud services', members: cloud });
    if (hubs.length) lanes.push({ id: 'hubs', label: 'Hubs and data centers', members: hubs.map((h) => orgSiteNode(h, 'hub')) });
    const hubName = new Map(hubs.map((h) => [h.key, h.name]));
    groups.forEach((g, i) => {
      const label =
        g.id === '-'
          ? hubs.length
            ? 'Not linked to a hub'
            : 'Sites'
          : g.hubs.length === hubs.length
            ? 'Linked to every hub'
            : g.hubs.length === 1
              ? `Linked to ${hubName.get(g.hubs[0]) || 'one hub'}`
              : `Linked to ${g.hubs.length} hubs`;
      lanes.push({ id: `g${i}`, label, members: g.sites.map((s) => orgSiteNode(s, 'site')) });
    });
    const pos = new Map();
    const nodes = new Map();
    const laneBoxes = [];
    let y = 20;
    let rowSerial = 0;
    const perRowMax = rowCapacity();
    for (const lane of lanes) {
      if (!lane.members.length) continue;
      const top = y;
      y += LANE_PAD;
      const perRow = Math.min(perRowMax, lane.members.length);
      const rows = Math.ceil(lane.members.length / perRow);
      for (let r = 0; r < rows; r++) {
        rowSerial += 1;
        lane.members.slice(r * perRow, (r + 1) * perRow).forEach((n, i) => {
          const x = RAIL_W + 24 + i * (NODE_W + COL_GAP);
          pos.set(n.id, { x, y, w: NODE_W, h: NODE_H, lane: lane.id, row: rowSerial });
          nodes.set(n.id, n);
        });
        y += NODE_H + (r < rows - 1 ? ROW_GAP : 0);
      }
      y += LANE_PAD;
      laneBoxes.push({ id: lane.id, label: lane.label, top, bottom: y, count: lane.members.length });
      y += LANE_GAP;
    }
    const links = (org.links || [])
      .filter((l) => pos.has(l.a) && pos.has(l.b))
      .map((l) => ({
        key: l.id || `site:${l.a}|${l.b}`,
        a_device: l.a,
        b_device: l.b,
        layer: 'overlay',
        state: l.state === 'down' ? 'down' : l.state === 'degraded' ? 'degraded' : 'up',
        health: l.health,
        label: l.tunnels ? `${l.tunnels} tunnel${l.tunnels > 1 ? 's' : ''}${l.down ? `, ${l.down} down` : ''}` : '',
        a_interface: '',
        b_interface: '',
        org: l,
      }));
    const width = Math.max(RAIL_W + 24 + NODE_W, ...[...pos.values()].map((p) => p.x + p.w)) + 40;
    return { nodes, pos, apsOf: new Map(), laneBoxes, links, width, height: y, org: true };
  }
  // A lane label on up to two lines inside the rail (long group names no longer get cut).
  function laneLabel(b) {
    const font = `650 13px ${nodeFontFamily || getComputedStyle(document.body).fontFamily || 'sans-serif'}`;
    const words = String(b.label).split(' ');
    const lines = [''];
    for (const w of words) {
      const cand = lines[lines.length - 1] ? `${lines[lines.length - 1]} ${w}` : w;
      if (textWidth(cand, font) <= RAIL_W - 26 || !lines[lines.length - 1]) lines[lines.length - 1] = cand;
      else if (lines.length < 2) lines.push(w);
      else lines[1] = fitText(`${lines[1]} ${w}`, RAIL_W - 26, font);
    }
    const tsp = lines.map((t, i) => `<tspan x="18" dy="${i ? 16 : 0}">${esc(fitText(t, RAIL_W - 26, font))}</tspan>`).join('');
    return `<text class="tp-lane-label" x="18" y="${b.top + 30}">${tsp}<title>${esc(b.label)}</title></text><text class="tp-lane-count" x="18" y="${b.top + 48 + (lines.length - 1) * 16}">${b.count}</text>`;
  }

  // ---------------------------------------------------------------- organization map
  // One picture of the whole organization: hubs / data centers on top, every other site grouped by
  // the hubs it reaches over SD-WAN, one line per group and hub (thicker = more sites, colour = worst
  // tunnel health). Sites with no SD-WAN link to a hub are listed on their own.
  const LINK_TONE = { critical: 'crit', warning: 'warn', good: 'good' };
  const TONE_RANK = { crit: 3, warn: 2, good: 1, none: 0 };

  function firewallHint(org) {
    const h = org.firewall_hint;
    if (!h || !h.text) return '';
    const missing = (h.unplaced || []).slice(0, 6).map((f) => f.name || f.serial).filter(Boolean);
    return `<div class="tp-callout tp-callout-info"><strong>Palo Alto firewalls.</strong> ${esc(h.text)}${
      missing.length ? ` <span class="tp-muted">Not placed yet: ${esc(missing.join(', '))}${(h.unplaced || []).length > missing.length ? '…' : ''}.</span>` : ''
    }${(h.unplaced || []).length ? ' <button type="button" class="tp-btn" data-act="sitemap">Assign sites</button>' : ''}</div>`;
  }

  function orgGroups(sites, rows, org) {
    const hubs = sites.filter((s) => s.hub && !s.cloud).sort((a, b) => a.name.localeCompare(b.name));
    const hubKeys = new Set(hubs.map((h) => h.key));
    const visible = new Set(rows.map((s) => s.key));
    const reach = new Map(); // site key → Map(hub key → tone)
    for (const l of org.links || []) {
      const pairs = [
        [l.a, l.b],
        [l.b, l.a],
      ];
      for (const [site, hub] of pairs) {
        if (!hubKeys.has(hub) || hubKeys.has(site)) continue;
        const m = reach.get(site) || new Map();
        const tone = LINK_TONE[l.health] || (l.state === 'down' ? 'crit' : 'none');
        const was = m.get(hub);
        if (!was || TONE_RANK[tone] > TONE_RANK[was]) m.set(hub, tone);
        reach.set(site, m);
      }
    }
    const groups = new Map();
    for (const s of sites) {
      if (s.hub || s.cloud || !visible.has(s.key)) continue;
      const m = reach.get(s.key) || new Map();
      const keys = [...m.keys()].sort();
      const id = keys.join('|') || '-';
      const g = groups.get(id) || { id, hubs: keys, sites: [], tones: new Map() };
      g.sites.push(s);
      for (const [hk, tone] of m) {
        const was = g.tones.get(hk);
        if (!was || TONE_RANK[tone] > TONE_RANK[was]) g.tones.set(hk, tone);
      }
      groups.set(id, g);
    }
    const rank = { crit: 0, warn: 1, none: 2, good: 3 };
    const list = [...groups.values()];
    list.forEach((g) => g.sites.sort((a, b) => rank[siteState(a)] - rank[siteState(b)] || a.name.localeCompare(b.name)));
    // Connected groups first (most hubs, then most sites); the unconnected group last.
    list.sort((a, b) => (a.id === '-') - (b.id === '-') || b.hubs.length - a.hubs.length || b.sites.length - a.sites.length);
    return { hubs, groups: list }; // hubs stay on the map whatever the filter: they anchor the lines
  }

  function orgMapMarkup(sites, rows, org) {
    const { hubs, groups } = orgGroups(sites, rows, org);
    if (!sites.length) return '';
    const hubName = new Map(hubs.map((h) => [h.key, h.name]));
    const TONE_TEXT = { good: 'tunnels healthy', warn: 'some tunnels slow or lossy', crit: 'tunnels down', none: 'no live tunnel data' };
    const chip = (s) => {
      const st = siteState(s);
      const note = s.badge || (s.down ? `${s.down} down` : '');
      return `<button type="button" class="tp-om-site st-${st}" data-site="${esc(s.key)}" title="Open ${esc(s.name)}"><span class="tp-om-dot" aria-hidden="true"></span><span class="tp-om-name">${esc(s.name)}</span>${note ? `<span class="tp-om-note">${esc(note)}</span>` : ''}</button>`;
    };
    const hubTile = (h) => {
      const st = siteState(h);
      return `<button type="button" class="tp-om-hub st-${st}" data-site="${esc(h.key)}" data-hub="${esc(h.key)}" title="Open ${esc(h.name)}">
        <span class="tp-om-hub-name">${esc(h.name)}</span>
        <span class="tp-om-hub-meta">${plural(h.devices || 0, 'device')}${h.down ? ` · <span class="tone-crit">${h.down} down</span>` : ''}${h.circuits_total ? ` · ${plural(h.circuits_total, 'circuit')}` : ''}</span>
      </button>`;
    };
    const pills = (g) =>
      g.hubs
        .map((k) => {
          const tone = g.tones.get(k) || 'none';
          return `<span class="tp-om-pill tone-${tone}" title="${esc(`${hubName.get(k) || 'Hub'}: ${TONE_TEXT[tone]}`)}"><span class="tp-om-dot" aria-hidden="true"></span>${esc(hubName.get(k) || 'Hub')}</span>`;
        })
        .join('');
    const groupTitle = (g) => {
      if (g.id === '-') return hubs.length ? 'Not linked to a hub over SD-WAN' : 'Sites';
      if (g.hubs.length === 1) return `Linked to ${hubName.get(g.hubs[0]) || 'one hub'} only`;
      if (g.hubs.length === hubs.length) return 'Linked to every hub';
      return `Linked to ${g.hubs.length} hubs`;
    };
    const tunnels = org.stats?.tunnels || 0;
    const siteName = new Map(sites.map((x) => [x.key, x.name]));
    const KIND_WORD = { mobile_users: 'remote-user gateway', service_connection: 'data-center link', remote_network: 'branch link' };
    const cloud = (org.cloud || []).map((c) => {
      const kinds = Object.entries(c.by_kind || {})
        .filter(([, n]) => n)
        .map(([k, n]) => `${n} ${KIND_WORD[k] || 'gateway'}${n > 1 ? 's' : ''}`)
        .join(' · ');
      const reach = (c.reaches || []).map((k) => siteName.get(k)).filter(Boolean);
      return `<button type="button" class="tp-om-hub tp-om-cloud st-${c.status === 'down' ? 'crit' : 'good'}" data-site="${esc(c.key)}" title="${esc(`${c.name}: security services in the provider's cloud`)}">
        <span class="tp-om-hub-name">${glyphSvg('cloud', 'tp-glyph-sm')} ${esc(c.name)}</span>
        <span class="tp-om-hub-meta">${esc(kinds || plural(c.gateways || 0, 'gateway'))}${reach.length ? ` · reaches ${esc(reach.slice(0, 3).join(', '))}${reach.length > 3 ? ` +${reach.length - 3}` : ''}` : ''}</span>
      </button>`;
    });
    return `<div class="tp-om">
      ${cloud.length ? `<div class="tp-om-tier tp-om-cloudtier"><span class="tp-om-tier-label">Cloud services (no building: remote users and cloud links)</span><div class="tp-om-hubs">${cloud.join('')}</div></div>` : ''}
      ${
        hubs.length
          ? `<div class="tp-om-tier"><span class="tp-om-tier-label">Hubs and data centers</span><div class="tp-om-hubs">${hubs.map(hubTile).join('')}</div></div>
      <div class="tp-om-bus" role="presentation"><span>SD-WAN${tunnels ? ` · ${plural(tunnels, 'tunnel')} between sites` : ''}</span></div>`
          : ''
      }
      <div class="tp-om-groups">
        ${groups
          .map(
            (g) => `<section class="tp-om-group${g.id === '-' ? ' is-alone' : ''}" data-group="${esc(g.id)}" data-hubs="${esc(g.hubs.join('|'))}">
            <header><strong>${esc(groupTitle(g))}</strong><span class="tp-muted">${plural(g.sites.length, 'site')}</span></header>
            ${g.hubs.length ? `<div class="tp-om-pills">${pills(g)}</div>` : ''}
            <div class="tp-om-sites">${g.sites.map(chip).join('')}</div>
          </section>`,
          )
          .join('')}
      </div>
      ${
        hubs.length
          ? '<p class="tp-om-legend">The coloured dot on each hub name shows the health of the SD-WAN tunnels to that hub: <span class="tp-om-key tone-good"></span>healthy <span class="tp-om-key tone-warn"></span>slow or lossy <span class="tp-om-key tone-crit"></span>down. Hover a group to see its hubs. Click any site to see how it is wired.</p>'
          : ''
      }
    </div>`;
  }

  function siteCard(s) {
    const st = siteState(s);
    const roles = Object.entries(s.by_role || {})
      .filter(([, n]) => n > 0)
      .sort((a, b) => roleOrder(a[0]) - roleOrder(b[0]))
      .slice(0, 5)
      .map(([role, n]) => `<span class="tp-rolecount" title="${esc((ROLE[role] || ROLE.unknown).label)}">${glyphSvg(role, 'tp-glyph-sm')}${n}</span>`)
      .join('');
    const circuits = s.circuits_total
      ? `<span class="tp-card-wan${s.circuits_down ? ' tone-crit' : ''}" title="Internet circuits">${glyphSvg('circuit', 'tp-glyph-sm')}${s.circuits_total} circuit${s.circuits_total > 1 ? 's' : ''}${s.circuits_down ? `, ${s.circuits_down} down` : ''}</span>`
      : '';
    const tunnels = s.tunnels
      ? `<span class="tp-card-wan${s.down_tunnels || s.tunnels_down ? ' tone-crit' : ''}">${glyphSvg('sdwan_edge', 'tp-glyph-sm')}${s.tunnels} tunnels${s.tunnels_down ? `, ${s.tunnels_down} down` : ''}</span>`
      : '';
    const reasons = (s.reasons || []).slice(0, 2);
    const downNames = (s.down_names || []).slice(0, 3).map((d) => d.name);
    const lines = reasons.length
      ? reasons.map((r) => `<li class="tone-${r.state === 'critical' ? 'crit' : r.state === 'warning' ? 'warn' : 'none'}">${esc(r.text)}</li>`).join('')
      : downNames.length
        ? `<li class="tone-crit">Down: ${esc(downNames.join(', '))}${s.down > downNames.length ? ` and ${s.down - downNames.length} more` : ''}</li>`
        : '';
    return `<button type="button" class="tp-card st-${st}" data-site="${esc(s.key)}" title="Open ${esc(s.name)}">
      <span class="tp-card-rail" aria-hidden="true"></span>
      <span class="tp-card-main">
        <span class="tp-card-name">${esc(s.name)}</span>
        <span class="tp-card-meta">${plural(s.devices || 0, 'device')}${s.down ? `, <span class="tone-crit">${s.down} down</span>` : ''}${(s.sources || []).length > 1 ? ` · ${s.sources.length} sources` : ''}</span>
        <span class="tp-card-roles">${roles}${circuits}${tunnels}</span>
        ${lines ? `<ul class="tp-card-reasons">${lines}</ul>` : ''}
      </span>
    </button>`;
  }

  function roleOrder(role) {
    return ['sdwan_edge', 'firewall', 'router', 'switch', 'wireless_ap', 'server', 'endpoint', 'unknown'].indexOf(role) + 1 || 99;
  }

  // ---------------------------------------------------------------- site scene (deterministic lanes)
  function laneOf(n, tierIds) {
    if (n.cloud || n.role === 'cloud_gateway') return 'cloudsvc';
    if (n.summaryRemote) return 'remote';
    if (n.remote || n.synthetic === 'remote') return S.remoteCollapsed ? 'skip' : 'remote'; // own lane, apart from the circuits
    if (n.role === 'circuit') return 'wan';
    if (n.role === 'cloud' && S.graph?.wan?.circuits?.length) return 'skip'; // circuits replace the generic Internet box
    const role = ROLE[n.role] ? n.role : 'unknown';
    // Found from a router's routes: it sits right behind the edge (usually a core switch or a firewall).
    if (n.inferred && (role === 'unknown' || role === 'switch')) return 'core';
    if (role === 'switch') {
      const t = String(tierIds[n.tier] || n.tier_label || '').toLowerCase();
      if (t.includes('core')) return 'core';
      if (t.includes('distribution') || t.includes('aggregation')) return 'distribution';
      return 'access';
    }
    if (role === 'wireless_ap') return n.uplink ? null : 'wireless';
    return ROLE[role].lane;
  }

  // Devices per row: as many as fit the visible map at a readable zoom (≥ 0.8).
  function rowCapacity() {
    const svg = S.view && $('.tp-svg', S.view);
    const w = svg?.getBoundingClientRect().width || 1100;
    const fit = Math.floor((w / 0.74 - RAIL_W - 64) / (NODE_W + COL_GAP));
    return Math.max(3, Math.min(MAX_PER_ROW, fit));
  }

  function buildScene() {
    const g = S.graph;
    const nodes = new Map((g.nodes || []).map((n) => [n.id, n]));
    const tierIds = {};
    (g.tiers || []).forEach((t) => {
      tierIds[t.tier] = `${t.id || ''} ${t.label || ''}`;
    });
    // Remote sites: their own lane; more than REMOTE_MAX fold into one "N connected sites" box.
    const remotes = [...nodes.values()].filter((n) => n.remote || n.synthetic === 'remote');
    S.remoteCollapsed = remotes.length > REMOTE_MAX;
    // Links found from routes are the only tie of an unmanaged device to the map: shown with cabling too.
    let linksShown = (g.links || []).filter((l) => S.layers.has(LAYER_OF[l.layer] || 'physical') || (l.inferred && S.layers.has('physical')));
    if (S.remoteCollapsed) {
      const remoteIds = new Set(remotes.map((n) => n.id));
      const list = g.wan?.remote_sites || [];
      const down = list.filter((r) => r.state === 'down').length;
      const bad = list.filter((r) => r.state !== 'up').length;
      nodes.set(REMOTE_SUMMARY, {
        id: REMOTE_SUMMARY,
        role: 'remote',
        name: `${list.length || remotes.length} connected sites`,
        status: down ? 'down' : bad ? 'degraded' : 'up',
        model: bad ? `${bad} with tunnel problems` : 'All tunnels up',
        summaryRemote: true,
      });
      const seen = new Set();
      const folded = [];
      for (const l of linksShown) {
        const aR = remoteIds.has(l.a_device);
        const bR = remoteIds.has(l.b_device);
        if (!aR && !bR) {
          folded.push(l);
          continue;
        }
        const local = aR ? l.b_device : l.a_device;
        if (remoteIds.has(local) || seen.has(local)) continue;
        seen.add(local);
        folded.push({ ...l, key: `rs:${local}`, a_device: local, b_device: REMOTE_SUMMARY });
      }
      linksShown = folded;
    }
    // APs fold under their uplink switch.
    const apsOf = new Map();
    const lanes = new Map(LANES.map((l) => [l.id, []]));
    // WAN circuits become their own boxes on the top lane, each cabled to its SD-WAN router.
    const circuitLinks = [];
    for (const c of S.graph.wan?.circuits || []) {
      // One box per line; a line both units of an HA pair use (v0.10.32: merged by the backend) is cabled
      // to each of them.
      const routers = (c.node_ids?.length ? c.node_ids : [c.node_id]).filter((x) => x && nodes.has(x));
      if (!routers.length) continue;
      const id = `circuit:${c.key}`;
      nodes.set(id, {
        id,
        role: 'circuit',
        name: c.label && c.carrier && c.carrier !== c.label ? `${c.label} · ${c.carrier}` : c.carrier || c.label || c.interface,
        status: c.state === 'up' ? 'up' : c.state === 'down' ? 'down' : c.state === 'degraded' ? 'degraded' : 'unknown',
        mgmt_ip: c.public_ip || c.ip,
        model: bwText(c),
        circuit: c,
      });
      routers.forEach((nid, i) => {
        const r = (c.routers || []).find((x) => x.node_id === nid);
        const down = (r?.state || c.state) === 'down';
        circuitLinks.push({ key: `cl:${c.key}${i ? `:${i}` : ''}`, a_device: id, b_device: nid, layer: 'physical', state: down ? 'down' : 'up', a_interface: '', b_interface: r?.interface || c.interface });
      });
    }
    linksShown.push(...circuitLinks);
    for (const n of nodes.values()) {
      const lane = laneOf(n, tierIds);
      if (lane === 'skip') continue;
      if (lane === null) {
        const up = nodes.get(n.uplink) ? n.uplink : null;
        if (up) {
          if (!apsOf.has(up)) apsOf.set(up, []);
          apsOf.get(up).push(n);
          continue;
        }
        lanes.get('wireless').push(n);
        continue;
      }
      lanes.get(lane).push(n);
    }
    // A lane holding only switches but no core: keep "access" as the only switch lane.
    // Adjacency for ordering (physical links only, parents above children).
    const adj = new Map();
    for (const l of g.links || []) {
      if ((LAYER_OF[l.layer] || 'physical') !== 'physical') continue;
      if (!adj.has(l.a_device)) adj.set(l.a_device, new Set());
      if (!adj.has(l.b_device)) adj.set(l.b_device, new Set());
      adj.get(l.a_device).add(l.b_device);
      adj.get(l.b_device).add(l.a_device);
    }
    for (const [sw, aps] of apsOf) aps.sort((a, b) => a.name.localeCompare(b.name));

    const pos = new Map(); // id -> {x,y,w,h}
    const laneBoxes = [];
    let y = 20;
    const placedX = new Map();
    let rowSerial = 0;
    const stateRank = (n) => (n.status === 'down' ? 0 : n.status === 'degraded' ? 1 : 2);
    for (const lane of LANES) {
      const members = lanes.get(lane.id);
      if (!members.length) continue;
      // Order: barycentre of already placed neighbours, then role, then name.
      members.forEach((n) => {
        const xs = [...(adj.get(n.id) || [])].map((id) => placedX.get(id)).filter((x) => x != null);
        n._bary = xs.length ? xs.reduce((a, b) => a + b, 0) / xs.length : null;
      });
      members.sort((a, b) => {
        if (a._bary != null && b._bary != null && a._bary !== b._bary) return a._bary - b._bary;
        if ((a._bary == null) !== (b._bary == null)) return a._bary == null ? 1 : -1;
        return roleOrder(a.role) - roleOrder(b.role) || stateRank(a) - stateRank(b) || a.name.localeCompare(b.name, undefined, { numeric: true });
      });
      // HA partners sit next to each other (unit 1 then unit 2), whatever their neighbours say.
      for (let i = 0; i < members.length; i++) {
        const peer = members[i].ha_peer;
        const j = peer ? members.findIndex((m, k) => k > i && m.id === peer) : -1;
        if (j > i + 1) members.splice(i + 1, 0, members.splice(j, 1)[0]);
      }
      const top = y;
      y += LANE_PAD;
      const perRow = Math.min(rowCapacity(), Math.max(1, members.length));
      const rows = Math.ceil(members.length / perRow);
      for (let r = 0; r < rows; r++) {
        rowSerial += 1;
        const rowMembers = members.slice(r * perRow, (r + 1) * perRow);
        let rowH = NODE_H;
        rowMembers.forEach((n, i) => {
          const x = RAIL_W + 24 + i * (NODE_W + COL_GAP);
          pos.set(n.id, { x, y, w: NODE_W, h: NODE_H, lane: lane.id, row: rowSerial });
          placedX.set(n.id, x + NODE_W / 2);
          const aps = apsOf.get(n.id);
          if (aps?.length) {
            const chipH = 26;
            let extra = 8 + chipH;
            if (S.expanded.has(n.id)) {
              aps.forEach((ap, k) => {
                pos.set(ap.id, { x: x + 12, y: y + NODE_H + 8 + chipH + 6 + k * (AP_H + 6), w: NODE_W - 12, h: AP_H, ap: true });
              });
              extra += 6 + aps.length * (AP_H + 6);
            }
            rowH = Math.max(rowH, NODE_H + extra);
          }
        });
        y += rowH + (r < rows - 1 ? ROW_GAP : 0);
      }
      y += LANE_PAD;
      laneBoxes.push({ id: lane.id, label: lane.label, top, bottom: y, count: members.length });
      y += LANE_GAP;
    }
    const width = Math.max(
      RAIL_W + 24 + NODE_W,
      ...[...pos.values()].map((p) => p.x + p.w),
    ) + 40;
    return { nodes, pos, apsOf, laneBoxes, links: linksShown, width, height: y };
  }


  // ---------------------------------------------------------------- site overview (plain language)
  const STAGE_INFO = {
    internet: ['circuit', 'Internet circuits', 'The lines from internet and private-network providers into the building.'],
    sdwan: ['sdwan_edge', 'SD-WAN routers', 'Send traffic over the circuits to the internet and to the other sites.'],
    firewall: ['firewall', 'Firewalls', 'Inspect and allow or block traffic going in and out.'],
    core: ['switch', 'Core switches', 'The centre of the building network; everything else hangs off them.'],
    distribution: ['switch', 'Distribution switches', 'Link the core to the closets on each floor or wing.'],
    access: ['switch', 'Closet switches', 'Where computers, phones, printers and access points plug in.'],
    wireless: ['wireless_ap', 'Wi-Fi access points', 'Give laptops, phones and tablets their Wi-Fi.'],
    unmanaged: [
      'unknown',
      'Devices behind the router',
      'Switches, firewalls or routers the SD-WAN router sends traffic to. Found from its routes; no connected system manages them, so only their address is known.',
    ],
    other: ['server', 'Other devices', 'Servers, controllers and devices NodeWatch could not classify.'],
  };
  const bps = (v) => {
    if (v == null || !Number.isFinite(+v)) return '';
    v = +v;
    if (v >= 1e9) return `${(v / 1e9).toFixed(1)} Gb/s`;
    if (v >= 1e6) return `${(v / 1e6).toFixed(v >= 1e8 ? 0 : 1)} Mb/s`;
    if (v >= 1e3) return `${Math.round(v / 1e3)} kb/s`;
    return `${Math.round(v)} b/s`;
  };
  function bwText(c) {
    const d = c.bandwidth_down_kbps;
    const u = c.bandwidth_up_kbps;
    if (d && u) return `${bps(d * 1000)} down / ${bps(u * 1000)} up`;
    if (d) return `${bps(d * 1000)} down`;
    return c.speed_mbps ? `${speedText(c.speed_mbps)} port` : '';
  }
  const stateWord = (st) =>
    ({ up: 'Working', down: 'Down', degraded: 'Up, but no traffic flowing', unknown: 'Unknown' })[st] || st || 'Unknown';
  const cap = (t) => String(t || '').charAt(0).toUpperCase() + String(t || '').slice(1);
  const toneOf = (st) => (st === 'down' ? 'crit' : st === 'degraded' ? 'warn' : st === 'up' ? 'good' : 'none');

  function stagesFor() {
    const g = S.graph;
    if (g.overview?.stages?.length) return g.overview.stages;
    // Older backends: derive the stages from the nodes.
    const tierIds = {};
    (g.tiers || []).forEach((t) => (tierIds[t.tier] = `${t.id || ''} ${t.label || ''}`));
    const by = {};
    for (const n of g.nodes || []) {
      if (n.remote || n.role === 'cloud') continue;
      let st = { sdwan_edge: 'sdwan', router: 'sdwan', firewall: 'firewall', wireless_ap: 'wireless' }[n.role];
      if (!st && n.role === 'switch') st = laneOf(n, tierIds);
      st = st || 'other';
      (by[st] = by[st] || []).push(n);
    }
    const circuits = g.wan?.circuits || [];
    const out = [];
    if (circuits.length)
      out.push({ id: 'internet', count: circuits.length, up: circuits.filter((c) => c.state === 'up').length, down: circuits.filter((c) => c.state === 'down').length, degraded: circuits.filter((c) => c.state === 'degraded').length, node_ids: [] });
    for (const id of ['sdwan', 'firewall', 'core', 'distribution', 'access', 'wireless', 'other']) {
      const ns = by[id] || [];
      if (ns.length)
        out.push({ id, count: ns.length, up: ns.filter((n) => n.status === 'up').length, down: ns.filter((n) => n.status === 'down').length, degraded: ns.filter((n) => n.status === 'degraded').length, node_ids: ns.map((n) => n.id) });
    }
    return out;
  }

  function stageStatus(st) {
    if (st.down) return [`${st.down} of ${st.count} down`, 'crit'];
    if (st.degraded) return [`${st.degraded} of ${st.count} with problems`, 'warn'];
    if (st.id === 'unmanaged') return ['Found from routes', 'none'];
    // Nothing reports up either (no live status for these devices): never claim they work.
    if (st.up != null && st.up === 0 && st.count) return ['Status unknown', 'none'];
    if (st.up != null && st.up < st.count) return [`${st.up} of ${st.count} confirmed working`, 'good'];
    return [st.count === 1 ? 'Working' : 'All working', 'good'];
  }

  function siteSentence(stages) {
    const g = S.graph;
    if (g.overview?.sentence) return g.overview.sentence;
    const get = (id) => stages.find((x) => x.id === id);
    const parts = [];
    const net = get('internet');
    if (net) parts.push(`reaches the internet over ${plural(net.count, 'circuit')} (${net.up} working)`);
    const sd = get('sdwan');
    if (sd) parts.push(`${net ? 'through' : 'through'} ${plural(sd.count, 'SD-WAN router')}`);
    const fw = get('firewall');
    if (fw) parts.push(`then ${plural(fw.count, 'firewall')}`);
    const core = get('core');
    const acc = get('access');
    const wifi = get('wireless');
    if (core || acc) parts.push(`then ${core ? `${plural(core.count, 'core switch', 'core switches')} feeding ` : ''}${acc ? plural(acc.count, 'closet switch', 'closet switches') : ''}${wifi ? ` and ${plural(wifi.count, 'Wi-Fi access point')}` : ''}`);
    return `${siteName(S.siteKey)} ${parts.join(', ')}.`;
  }

  function problemsLine(stages) {
    const bad = [];
    for (const st of stages) {
      const info = STAGE_INFO[st.id];
      const one = { internet: 'internet circuit', sdwan: 'SD-WAN router', firewall: 'firewall', core: 'core switch', distribution: 'distribution switch', access: 'closet switch', wireless: 'Wi-Fi access point', other: 'other device' }[st.id] || st.id;
      const many = one.endsWith('switch') ? `${one}es` : `${one}s`;
      if (st.down) bad.push(`${st.down} ${st.down === 1 ? one : many} down`);
      else if (st.degraded) bad.push(`${st.degraded} ${st.degraded === 1 ? one : many} with problems`);
    }
    return bad.length ? `Needs attention: ${bad.join(', ')}.` : 'Everything NodeWatch can see here is working.';
  }

  // ---------------------------------------------------------------- Layers view (v0.10.36)
  // The site from the internet inwards, one band per layer: circuits grouped by the router they plug into,
  // SD-WAN edges, firewalls (HA pairs side by side), core / distribution, then every closet with its uplink
  // bundle, port strip and access points. Every box and every link is clickable; details open in the panel.
  const LY_TIERS = ['sdwan', 'firewall', 'core', 'distribution'];
  const LY_CABLE = new Set(['physical', 'lag', 'l2']);
  function lyNode(id) {
    return (S.graph?.nodes || []).find((n) => n.id === id);
  }
  function lyLinksBetween(aIds, bIds) {
    const A = new Set(aIds);
    const B = new Set(bIds);
    const all = (S.graph?.links || []).filter((l) => (A.has(l.a_device) && B.has(l.b_device)) || (B.has(l.a_device) && A.has(l.b_device)));
    const cables = all.filter((l) => LY_CABLE.has(l.layer));
    const pick = cables.length ? cables : all.filter((l) => l.layer === 'l3');
    const seen = new Set();
    return pick.filter((l) => {
      const k = [l.a_device, l.b_device].sort().join('|');
      if (seen.has(k)) return false;
      seen.add(k);
      return true;
    });
  }
  function lyMembers(l) {
    const m = l.members || [];
    if (m.length < 2) return '';
    const up = m.filter((x) => x.state === 'up').length;
    return `${up}/${m.length} up`;
  }
  function lyLinkPill(l) {
    const a = lyNode(l.a_device);
    const b = lyNode(l.b_device);
    const name = l.layer === 'lag' ? (l.a_interface || l.b_interface || 'bundle').split(',')[0] : '';
    const n = (l.members || []).length;
    const ends = l.layer !== 'lag' && (l.a_interface || l.b_interface) ? truncate(`${l.a_interface || '?'} ⇄ ${l.b_interface || '?'}`, 30) : '';
    const parts = [
      name || ends,
      n > 1 ? `${n} × ${speedText((l.speed_mbps || 0) / n) || '?'}` : speedText(l.speed_mbps),
      lyMembers(l),
      l.layer === 'l3' ? 'routed' : '',
    ].filter(Boolean);
    const tone = l.state === 'down' ? 'crit' : l.state === 'degraded' || (n > 1 && lyMembers(l).split('/')[0] !== String(n)) ? 'warn' : 'good';
    const sel = S.selected === `link:${l.key}` ? ' is-sel' : '';
    return `<button type="button" class="tp-ly-link ly-${tone}${l.layer === 'lag' ? ' is-lag' : ''}${sel}" data-pick="link:${esc(l.key)}" title="${esc(`${a?.name || '?'} ${l.a_interface || ''} ⇄ ${b?.name || '?'} ${l.b_interface || ''}`)}">${esc(parts.join(' · ') || 'link')}</button>`;
  }
  function lyConnector(links, note = '') {
    if (!links.length) return note ? `<div class="tp-ly-conn"><span class="tp-ly-conn-note">${esc(note)}</span></div>` : '<div class="tp-ly-conn is-empty" aria-hidden="true"></div>';
    const shown = links.slice(0, 8);
    return `<div class="tp-ly-conn">${shown.map(lyLinkPill).join('')}${links.length > shown.length ? `<span class="tp-ly-conn-note">+${links.length - shown.length} more</span>` : ''}</div>`;
  }
  function lyFacts(n) {
    const h = S.health?.nodes?.[n.id];
    const bits = [];
    if (n.model) bits.push(n.model);
    if (n.os_version) bits.push(n.os_version);
    if (n.sessions != null) bits.push(`${n.sessions} sessions`);
    if (n.clients != null) bits.push(`${n.clients} clients`);
    if (h?.cpu_pct != null) bits.push(`CPU ${Math.round(h.cpu_pct)}%`);
    return bits.join(' · ');
  }
  function lyBox(n) {
    if (!n) return '';
    const ha = haRole(n);
    const st = String(n.ha_state || '').replace(' (inferred)', '');
    const sel = S.selected === n.id ? ' is-sel' : '';
    const assumed = n.evidence === 'ha-user' || n.evidence === 'ha-inferred';
    return `<button type="button" class="tp-ly-box ly-${assumed ? 'info' : nodeTone(n)}${ha ? ` is-ha-${ha}` : ''}${assumed ? ' is-assumed' : ''}${sel}" data-pick="${esc(n.id)}">
      <span class="tp-ly-box-head">${glyphSvg(n.role, 'tp-glyph-sm')}<strong>${esc(n.name)}</strong>${ha ? `<span class="tp-ha-pip is-${ha}" title="${esc(HA_DOT_TEXT[ha])}"></span>` : ''}</span>
      <span class="tp-ly-box-sub">${esc([st && st !== 'ha-pair' ? st : '', assumed ? 'not reported by any system' : cap(n.status || 'unknown')].filter(Boolean).join(' · '))}</span>
      ${lyFacts(n) ? `<span class="tp-ly-box-facts">${esc(lyFacts(n))}</span>` : ''}
    </button>`;
  }
  function lyRow(ids) {
    // HA partners side by side with the HA link between them; everything else in order.
    const done = new Set();
    const out = [];
    for (const id of ids) {
      if (done.has(id)) continue;
      const n = lyNode(id);
      if (!n) continue;
      done.add(id);
      const peer = n.ha_peer && ids.includes(n.ha_peer) && !done.has(n.ha_peer) ? lyNode(n.ha_peer) : null;
      if (peer) {
        done.add(peer.id);
        const [first, second] = haRole(n) === 'passive' ? [peer, n] : [n, peer];
        const hal = (S.graph.links || []).find((l) => l.layer === 'ha' && [l.a_device, l.b_device].sort().join('|') === [n.id, peer.id].sort().join('|'));
        out.push(`<div class="tp-ly-pair">${lyBox(first)}<span class="tp-ly-ha" title="High-availability pair">${hal ? `<button type="button" class="tp-ly-link is-ha${S.selected === `link:${hal.key}` ? ' is-sel' : ''}" data-pick="link:${esc(hal.key)}">HA</button>` : '<span class="tp-ly-ha-word">HA</span>'}</span>${lyBox(second)}</div>`);
      } else out.push(lyBox(n));
    }
    return `<div class="tp-ly-row">${out.join('')}</div>`;
  }
  function lyCircuitRow(c) {
    const down = c.bandwidth_down_kbps ? c.bandwidth_down_kbps * 1000 : null;
    const util = down && c.rx_bps != null ? Math.min(100, Math.round((100 * c.rx_bps) / down)) : null;
    const sel = S.selected === `circuit:${c.key}` ? ' is-sel' : '';
    const q =
      [c.latency_ms != null ? `${Math.round(c.latency_ms)} ms` : '', c.loss_pct ? `${c.loss_pct}% loss` : ''].filter(Boolean).join(' · ') ||
      (c.tunnels_total ? `${c.tunnels_up ?? 0}/${c.tunnels_total} tunnels up` : '') ||
      c.public_ip ||
      c.interface ||
      '';
    return `<button type="button" class="tp-ly-circ ly-${toneOf(c.state)}${sel}" data-pick="circuit:${esc(c.key)}">
      <span class="tp-dot"></span>
      <strong>${esc(c.label || c.interface || 'circuit')}</strong>
      <span class="tp-ly-circ-isp">${esc([c.carrier && c.carrier !== c.label ? c.carrier : '', c.kind && c.kind !== 'unknown' ? c.kind : '', bwText(c)].filter(Boolean).join(' · ') || c.interface || '')}</span>
      <span class="tp-ly-util" title="${util != null ? `${util}% of the contracted download in use` : 'No traffic figure from the source'}">${util != null ? `<span class="tp-ly-util-bar"><span class="tp-ly-util-fill${util >= 80 ? ' is-hot' : util >= 60 ? ' is-warm' : ''}" data-w="${util}"></span></span><small>${util}%</small>` : c.rx_bps != null ? `<small>${esc(bps(c.rx_bps) || '0')}</small>` : '<small class="tp-muted">no traffic figure</small>'}</span>
      <span class="tp-ly-circ-q tp-mono" title="${esc([c.public_ip ? `Public IP ${c.public_ip}` : '', c.interface ? `Port ${c.interface}` : '', c.tunnels_total ? `${c.tunnels_up ?? 0} of ${c.tunnels_total} tunnels up` : ''].filter(Boolean).join(' · '))}">${esc(q)}</span>
    </button>`;
  }
  function renderLayered() {
    const box = $('.tp-layered', S.view);
    box.classList.remove('hidden');
    const g = S.graph;
    const stages = Object.fromEntries((g.overview?.stages || []).map((s) => [s.id, s]));
    const circuits = g.wan?.circuits || [];
    const remote = g.wan?.remote_sites || [];
    const nodes = g.nodes || [];
    const down = nodes.filter((n) => n.status === 'down').length;
    // circuits grouped by the router(s) they plug into
    const groups = new Map();
    for (const c of circuits) {
      const ids = (c.routers || []).map((r) => r.node_id).filter(Boolean);
      const key = (ids.length ? ids : [c.node_id || '']).slice().sort().join('+');
      if (!groups.has(key)) groups.set(key, { ids: ids.length ? ids : [c.node_id], list: [] });
      groups.get(key).list.push(c);
    }
    const order = ['down', 'degraded', 'unknown', 'up'];
    const up = circuits.filter((c) => c.state === 'up').length;
    const rx = circuits.reduce((s, c) => s + (c.rx_bps || 0), 0);
    const capBps = circuits.reduce((s, c) => s + (c.bandwidth_down_kbps || 0) * 1000, 0);
    const wan = circuits.length
      ? `<section class="tp-ly-band tp-ly-wan">
          <header class="tp-ly-band-head"><h3>Internet <small class="tp-muted">${plural(circuits.length, 'circuit')}</small></h3>
            <span class="tp-ly-band-sum">${esc(`${up} up${circuits.length - up ? ` · ${circuits.length - up} not up` : ''}${capBps ? ` · ${bps(rx)} in use of ${bps(capBps)}` : ''}`)}</span></header>
          <div class="tp-ly-groups cols-${Math.min(3, groups.size)}">${[...groups.values()]
            .map((grp) => {
              const names = grp.ids.map((id) => lyNode(id)?.name || id).filter(Boolean);
              return `<div class="tp-ly-group"><div class="tp-ly-group-head">→ ${esc(names.join(' + ') || 'router')}</div>${grp.list
                .sort((a, b) => order.indexOf(a.state) - order.indexOf(b.state) || String(a.label).localeCompare(String(b.label), undefined, { numeric: true }))
                .map(lyCircuitRow)
                .join('')}</div>`;
            })
            .join('')}</div>
        </section>`
      : '';
    // tiers
    const bands = [];
    let prev = null; // node ids of the band above
    for (const id of LY_TIERS) {
      const st = stages[id];
      if (!st?.node_ids?.length) continue;
      const [, label, hint] = STAGE_INFO[id] || ['', st.label || id, ''];
      const pairs = nodes.filter((n) => st.node_ids.includes(n.id) && n.ha_peer && st.node_ids.includes(n.ha_peer)).length / 2;
      const conn = prev ? lyConnector(lyLinksBetween(prev, st.node_ids)) : '';
      bands.push(`${conn}<section class="tp-ly-band" data-tier="${esc(id)}">
        <header class="tp-ly-band-head"><h3 title="${esc(hint)}">${esc(id === 'sdwan' ? st.label || label : label)} <small class="tp-muted">${st.count}</small></h3>
          <span class="tp-ly-band-sum">${esc([pairs ? plural(pairs, 'HA pair') : '', id === 'sdwan' && remote.length ? `${remote.filter((r) => r.state === 'up').length}/${remote.length} fabric peers up` : '', st.down ? `${st.down} down` : ''].filter(Boolean).join(' · '))}</span></header>
        ${lyRow(st.node_ids)}
      </section>`);
      prev = st.node_ids;
    }
    // closets
    const closets = g.overview?.closets || [];
    const closetHtml = closets.length
      ? `<section class="tp-ly-band tp-ly-closets">
          <header class="tp-ly-band-head"><h3>Closets <small class="tp-muted">${closets.length}</small></h3>
            <span class="tp-ly-band-sum">${esc(`${closets.reduce((s, c) => s + (c.switch_ids || []).length, 0)} switches · ${closets.reduce((s, c) => s + (c.ap_count || 0), 0)} access points`)}</span></header>
          <div class="tp-ly-closet-grid">${closets
            .map((c) => {
              const ups = lyLinksBetween(c.switch_ids || [], c.uplink_ids || []);
              const sws = (c.switch_ids || []).map(lyNode).filter(Boolean);
              const strip = sws
                .map((sw) => {
                  const pm = String(sw.port_map || '');
                  const ports = pm
                    ? `<span class="tp-ly-ports" aria-label="${esc(`${pm.split('u').length - 1} of ${pm.length} ports up`)}">${[...pm.slice(0, 96)].map((ch) => `<i class="p-${ch}"></i>`).join('')}</span>`
                    : '';
                  return `<button type="button" class="tp-ly-sw ly-${nodeTone(sw)}${S.selected === sw.id ? ' is-sel' : ''}" data-pick="${esc(sw.id)}"><span class="tp-ly-sw-name">${esc(sw.name)}</span>${ports}<small class="tp-muted">${esc([sw.model, sw.ports_total != null ? `${sw.ports_up ?? 0}/${sw.ports_total} ports up` : '', sw.poe_draw_w != null ? `PoE ${Math.round(sw.poe_draw_w)} W` : ''].filter(Boolean).join(' · '))}</small></button>`;
                })
                .join('');
              const aps = (c.ap_ids || []).map(lyNode).filter(Boolean);
              const apDots = aps
                .slice(0, 60)
                .map((a) => `<button type="button" class="tp-ly-ap ly-${nodeTone(a)}${S.selected === a.id ? ' is-sel' : ''}" data-pick="${esc(a.id)}" title="${esc(`${a.name} · ${cap(a.status || 'unknown')}${a.clients != null ? ` · ${a.clients} clients` : ''}`)}" aria-label="${esc(a.name)}"></button>`)
                .join('');
              const tone = c.switches_down ? 'crit' : c.aps_down ? 'warn' : 'good';
              return `<article class="tp-ly-closet ly-${tone}">
                <div class="tp-ly-closet-up">${ups.length ? ups.map(lyLinkPill).join('') : '<span class="tp-muted">uplink not seen</span>'}</div>
                <header><span class="tp-dot"></span><strong>${esc(c.name)}</strong><span class="tp-muted">${esc([c.clients != null ? `${c.clients} clients` : '', c.aps_down ? `${c.aps_down} AP down` : '', c.switches_down ? `${c.switches_down} switch down` : ''].filter(Boolean).join(' · '))}</span></header>
                ${strip}
                ${aps.length ? `<div class="tp-ly-aps" aria-label="${esc(`${aps.length} access points`)}">${apDots}${aps.length > 60 ? `<small>+${aps.length - 60}</small>` : ''}</div><small class="tp-muted">${plural(aps.length, 'access point')}</small>` : ''}
              </article>`;
            })
            .join('')}</div>
        </section>`
      : '';
    const others = [...(stages.other?.node_ids || []), ...(stages.unmanaged?.node_ids || [])];
    const otherHtml = others.length
      ? `<section class="tp-ly-band tp-ly-other"><header class="tp-ly-band-head"><h3>Other devices <small class="tp-muted">${others.length}</small></h3><span class="tp-ly-band-sum">servers, controllers and devices found only from routes</span></header>${lyRow(others.slice(0, 24))}</section>`
      : '';
    const lead = circuits.length && prevFirst(stages) ? `<div class="tp-ly-conn"><span class="tp-ly-conn-note">${esc(handoffNote(circuits))}</span></div>` : '';
    box.innerHTML = `
      <section class="tp-ly-head">
        <p class="tp-ov-sentence">${esc(siteSentence(stagesFor()))}</p>
        <div class="tp-ly-chips">
          <span class="tp-pill ly-${down ? 'crit' : 'good'}">${esc(`${nodes.length} devices · ${down} down`)}</span>
          ${remote.length ? `<span class="tp-pill tone-info">${esc(`${remote.length} fabric peers`)}</span>` : ''}
          <button type="button" class="tp-btn primary" data-act="export">Export…</button>
        </div>
      </section>
      ${wan}${lead}${bands.join('')}${closetHtml}${otherHtml}
      <p class="tp-ov-foot tp-muted">Click any box or link for its details. <button type="button" class="tp-link" data-mode="wiring">See every cable (Wiring)</button></p>`;
    // CSP: no inline style attributes; widths are set through the CSSOM.
    $$('[data-w]', box).forEach((el) => el.style.setProperty('--w', `${el.dataset.w}%`));
  }
  function prevFirst(stages) {
    return LY_TIERS.some((id) => stages[id]?.node_ids?.length);
  }
  function handoffNote(circuits) {
    const tunnels = circuits.reduce((s, c) => s + (c.tunnels_total || 0), 0);
    const tup = circuits.reduce((s, c) => s + (c.tunnels_up || 0), 0);
    return tunnels ? `${tup} of ${tunnels} SD-WAN tunnels up over these circuits` : 'circuits terminate on the routers below';
  }
  function linkMarkup(l) {
    const a = lyNode(l.a_device);
    const b = lyNode(l.b_device);
    const m = l.members || [];
    const kind = l.layer === 'lag' ? 'Aggregated link (LAG / AE bundle)' : l.layer === 'ha' ? 'High-availability link' : l.layer === 'l3' ? 'Routed link' : LAYER_OF[l.layer] === 'overlay' ? 'Tunnel' : 'Cable';
    const ev = (l.evidence || []).map((e) => e.detail || e.kind).filter(Boolean);
    return `<article class="tp-device tone-${linkTone(l)}">
      <header class="tp-dev-head">${glyphSvg('circuit', 'tp-glyph-lg')}<div><h3 class="tp-dh">${esc(l.label || (l.layer === 'lag' ? l.a_interface : `${a?.name || '?'} ⇄ ${b?.name || '?'}`))}</h3><p class="tp-muted">${esc(kind)}</p></div>
        <span class="tp-pill tone-${linkTone(l)}">${esc(stateWord(l.state || 'unknown'))}</span></header>
      <dl class="tp-facts">
        ${fact('From', `${a?.name || l.a_device}${l.a_interface ? ` · ${l.a_interface}` : ''}`)}
        ${fact('To', `${b?.name || l.b_device}${l.b_interface ? ` · ${l.b_interface}` : ''}`)}
        ${fact('Speed', l.speed_mbps ? (m.length > 1 ? `${m.length} × ${speedText(l.speed_mbps / m.length)} = ${speedText(l.speed_mbps)}` : speedText(l.speed_mbps)) : '')}
        ${fact('Members up', m.length > 1 ? lyMembers(l) : '')}
        ${fact('Found by', ev.length ? ev.slice(0, 3) : (l.sources || []).map(srcLabel))}
      </dl>
      ${m.length > 1 ? `<h4 class="tp-dsub">Members</h4><table class="tp-table tp-ly-members"><thead><tr><th>${esc(a?.name || 'A')}</th><th>${esc(b?.name || 'B')}</th><th>Speed</th><th>State</th></tr></thead><tbody>${m.map((x) => `<tr><td class="tp-mono">${esc(x.a_interface || '—')}</td><td class="tp-mono">${esc(x.b_interface || '—')}</td><td>${esc(speedText(x.speed_mbps) || '—')}</td><td>${esc(stateWord(x.state || 'unknown'))}</td></tr>`).join('')}</tbody></table>` : ''}
      <div class="tp-actions">${a ? `<button type="button" class="tp-btn" data-pick="${esc(a.id)}">${esc(a.name)}</button>` : ''}${b ? `<button type="button" class="tp-btn" data-pick="${esc(b.id)}">${esc(b.name)}</button>` : ''}</div>
    </article>`;
  }

  function renderOverview() {
    const box = $('.tp-overview', S.view);
    box.classList.remove('hidden');
    const g = S.graph;
    const stages = stagesFor();
    const circuits = (g.wan?.circuits || []).slice().sort((a, b) => ['down', 'degraded', 'unknown', 'up'].indexOf(a.state) - ['down', 'degraded', 'unknown', 'up'].indexOf(b.state) || String(a.device_name || a.appliance).localeCompare(String(b.device_name || b.appliance)));
    const remote = g.wan?.remote_sites || [];
    const closets = g.overview?.closets || [];
    const anyBad = stages.some((x) => x.down || x.degraded);
    const flow = stages
      .map((st) => {
        const [glyph, label, hint] = STAGE_INFO[st.id] || ['unknown', st.label || st.id, ''];
        const [status, tone] = stageStatus(st);
        const open = S.stage === `stage:${st.id}`;
        return `<li class="tp-flow-step tone-${tone}${open ? ' is-open' : ''}">
          <button type="button" data-stage="stage:${esc(st.id)}" aria-expanded="${open}" title="${esc(hint)}">
            <span class="tp-flow-icon">${glyphSvg(glyph, 'tp-glyph')}</span>
            <strong class="tp-flow-count">${st.count}</strong>
            <span class="tp-flow-label">${esc(st.label && st.id !== 'internet' && !STAGE_INFO[st.id] ? st.label : label)}</span>
            <span class="tp-flow-status">${esc(status)}</span>
          </button></li>`;
      })
      .join('<li class="tp-flow-arrow" aria-hidden="true"></li>');
    box.innerHTML = `
      <section class="tp-ov-head">
        <p class="tp-ov-sentence">${esc(siteSentence(stages))}</p>
        ${g.overview?.sentence ? '' : `<p class="tp-ov-problems tone-${anyBad ? 'crit' : 'good'}">${esc(problemsLine(stages))}</p>`}
      </section>
      <ol class="tp-flow" aria-label="How traffic flows through this site, from the internet inwards">${flow}</ol>
      <div class="tp-ov-detail">${stageDetail(stages)}</div>
      ${circuits.length ? `<section class="tp-ov-sec"><h3>Internet circuits <small class="tp-muted">${circuits.length}</small></h3>
        <div class="tp-table-wrap"><table class="tp-table tp-circuits"><thead><tr><th>Circuit</th><th>Status</th><th>Router</th><th>WAN address</th><th>Bandwidth</th><th>Now</th><th>Quality</th><th>Tunnels</th></tr></thead><tbody>
        ${circuits
          .map(
            (c) => `<tr class="tone-${toneOf(c.state)}" data-circuit="${esc(c.key)}" tabindex="0"><td><strong>${esc(c.label || c.interface)}</strong>${c.carrier && c.carrier !== c.label ? `<br><small class="tp-muted">${esc(c.carrier)}</small>` : ''}</td>
              <td><span class="tp-pill tone-${toneOf(c.state)}">${esc(stateWord(c.state))}</span></td>
              <td>${circuitRouters(c)}</td>
              <td class="tp-mono">${esc(wanAddress(c).text)}${wanAddress(c).note ? `<br><small class="tp-muted">${esc(wanAddress(c).note)}</small>` : ''}${c.dhcp ? '<br><small class="tp-muted">DHCP</small>' : ''}</td>
              <td>${esc(bwText(c) || '—')}</td>
              <td>${c.rx_bps != null || c.tx_bps != null ? `${esc(bps(c.rx_bps) || '0')} in<br><small class="tp-muted">${esc(bps(c.tx_bps) || '0')} out</small>` : '<span class="tp-muted">—</span>'}</td>
              <td>${c.latency_ms != null ? `${esc(c.latency_ms)} ms` : '<span class="tp-muted">—</span>'}${c.loss_pct ? `<br><small class="tone-warn-text">${esc(c.loss_pct)} % loss</small>` : ''}</td>
              <td>${c.tunnels_total ? `${esc(c.tunnels_up)} of ${esc(c.tunnels_total)} up` : '<span class="tp-muted">none</span>'}</td></tr>`,
          )
          .join('')}</tbody></table></div></section>` : ''}
      ${remote.length ? `<section class="tp-ov-sec"><h3>Connected sites <small class="tp-muted">${remote.length}</small></h3>
        <p class="tp-muted tp-ov-hint">Other locations this site reaches over SD-WAN tunnels (not internet circuits).</p>
        <ul class="tp-remote">${(S.allRemote || remote.length <= 12 ? remote : remote.filter((r, i) => r.state !== 'up' || i < 9))
          .map(
            (r) => `<li class="tone-${toneOf(r.state)}"><button type="button" ${r.site_key ? `data-site="${esc(r.site_key)}"` : 'disabled'} title="${r.site_key ? 'Open this site' : ''}"><span class="tp-dot"></span><span class="tp-remote-name">${esc(r.name)}${r.hub ? ' <small class="tp-muted">hub</small>' : ''}</span><small>${esc(`${r.tunnels_up} of ${r.tunnels_total} tunnels up`)}${r.latency_ms != null ? `, ${esc(r.latency_ms)} ms` : ''}${r.loss_pct ? `, ${esc(r.loss_pct)} % loss` : ''}</small></button></li>`,
          )
          .join('')}</ul>${remote.length > 12 ? `<p><button type="button" class="tp-link" data-act="all-remote">${S.allRemote ? 'Show fewer' : `Show all ${remote.length} connected sites`}</button></p>` : ''}</section>` : ''}
      ${closets.length ? `<section class="tp-ov-sec"><h3>Closets <small class="tp-muted">${closets.length}</small></h3>
        <p class="tp-muted tp-ov-hint">Each wiring closet with its switches and the Wi-Fi access points plugged into them.</p>
        <div class="tp-closets">${closets
          .map((c) => {
            const bad = c.switches_down || c.aps_down;
            const open = S.stage === `closet:${c.id}`;
            return `<button type="button" class="tp-closet tone-${c.switches_down ? 'crit' : c.aps_down ? 'warn' : 'good'}${open ? ' is-open' : ''}" data-stage="closet:${esc(c.id)}" aria-expanded="${open}">
              <span class="tp-closet-name">${esc(c.name)}</span>
              <span class="tp-closet-facts">${glyphSvg('switch', 'tp-glyph-sm')}${(c.switch_ids || []).length}${c.ap_count ? ` ${glyphSvg('wireless_ap', 'tp-glyph-sm')}${c.ap_count}` : ''}${c.clients ? ` <span class="tp-muted">${esc(`${c.clients} clients`)}</span>` : ''}</span>
              <span class="tp-closet-status">${bad ? esc([c.switches_down ? `${c.switches_down} switch${c.switches_down > 1 ? 'es' : ''} down` : '', c.aps_down ? `${c.aps_down} AP${c.aps_down > 1 ? 's' : ''} down` : ''].filter(Boolean).join(', ')) : 'All working'}</span>
            </button>`;
          })
          .join('')}</div></section>` : ''}
      <p class="tp-ov-foot"><button type="button" class="tp-link" data-mode="wiring">See every device and cable (Wiring)</button></p>`;
  }

  function stageDetail(stages) {
    if (!S.stage) return '';
    const cut = S.stage.indexOf(':');
    const kind = S.stage.slice(0, cut);
    const id = S.stage.slice(cut + 1); // closet ids may contain ':' themselves
    const g = S.graph;
    let ids = [];
    let title = '';
    if (kind === 'stage') {
      const st = stages.find((x) => x.id === id);
      if (!st) return '';
      title = (STAGE_INFO[id] || [])[1] || st.label || id;
      if (id === 'internet') return '';
      ids = st.node_ids || [];
    } else {
      const c = (g.overview?.closets || []).find((x) => x.id === id);
      if (!c) return '';
      title = c.name;
      const sw = new Set(c.switch_ids || []);
      ids = [...sw, ...(g.nodes || []).filter((n) => n.role === 'wireless_ap' && sw.has(n.uplink)).map((n) => n.id)];
    }
    const byId = new Map((g.nodes || []).map((n) => [n.id, n]));
    const rows = ids
      .map((x) => byId.get(x))
      .filter(Boolean)
      .sort((a, b) => (a.status === 'down' ? 0 : 1) - (b.status === 'down' ? 0 : 1) || roleOrder(a.role) - roleOrder(b.role) || a.name.localeCompare(b.name, undefined, { numeric: true }));
    const shown = rows.slice(0, 300);
    return `<section class="tp-ov-sec tp-ov-list"><h3>${esc(title)} <small class="tp-muted">${rows.length}</small><button type="button" class="tp-link tp-ov-close" data-stage="">Close</button></h3>
      <div class="tp-devgrid">${shown
        .map(
          (n) => `<button type="button" class="tp-devcard tone-${nodeTone(n)}" data-pick="${esc(n.id)}"><span class="tp-devcard-bar"></span>${glyphSvg(n.role, 'tp-glyph-sm')}<span class="tp-devcard-name">${esc(n.name)}${haRole(n) ? ` <span class="tp-ha-pip is-${haRole(n)}" title="${esc(HA_DOT_TEXT[haRole(n)])}"></span>` : ''}</span><small class="tp-muted">${esc([n.status === 'down' ? 'Down' : '', n.model, n.mgmt_ip].filter(Boolean).join('  '))}</small></button>`,
        )
        .join('')}</div>${rows.length > shown.length ? `<p class="tp-muted">${rows.length - shown.length} more — use search or the Wiring view.</p>` : ''}</section>`;
  }

  // Router column of the circuits table: every router using the line (HA pairs share one).
  function circuitRouters(c) {
    const list = c.routers?.length ? c.routers : [{ node_id: c.node_id, device_name: c.device_name || c.appliance, interface: c.interface }];
    return list
      .map(
        (r) =>
          `${r.node_id ? `<button type="button" class="tp-link" data-pick="${esc(r.node_id)}">${esc(r.device_name || '')}</button>` : esc(r.device_name || '')}<br><small class="tp-muted tp-mono">${esc(r.interface || '')}</small>`,
      )
      .join('<br>') + (list.length > 1 ? '<br><small class="tp-muted">shared by the HA pair</small>' : '');
  }

  // RFC 1918 / CGNAT / ULA: a "public" address in this range means another router or firewall sits
  // between this port and the internet (the provider's modem, or a firewall in front of the SD-WAN).
  function privateIp(ip) {
    const t = String(ip || '').trim();
    if (/^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.)/.test(t)) return true;
    return /^f[cd][0-9a-f]{2}:/i.test(t);
  }
  function wanAddress(c) {
    const ip = c.public_ip || '';
    if (!ip) return { text: '—', note: '' };
    return privateIp(ip) ? { text: ip, note: 'private · behind another router' } : { text: ip, note: '' };
  }

  const HA_CAPABLE = new Set(['firewall', 'sdwan_edge', 'router', 'load_balancer', 'wireless_controller']);
  function unitKey(n) {
    const r = (n.records || [])[0];
    return r ? `${r.source}:${r.key}` : n.id;
  }
  function haLine(n) {
    // The operator knows the site has a pair even when no source names the passive unit (it passes no traffic,
    // so it writes no traffic logs): one click draws it; a real partner found later replaces it.
    if (n.evidence === 'ha-user' || n.evidence === 'ha-inferred') return ''; // partnerCard() explains these
    if (n.ha_user_found) {
      return `<p class="tp-ha-line"><strong>High availability:</strong> the partner you confirmed is now reported: <button type="button" class="tp-link" data-pick="${esc(n.ha_peer)}">${esc(n.ha_user_found.name)}</button> <span class="tp-muted">(${esc((n.ha_user_found.sources || []).map(srcLabel).join(', ') || 'a connected system')})</span>.</p>`;
    }
    if (!n.ha_peer && !n.ha_state) {
      if (!HA_CAPABLE.has(n.role) || n.inferred || n.cloud) return '';
      return `<p class="tp-ha-line tp-muted">Is this one unit of an HA pair? <button type="button" class="tp-link" data-ha-add="${esc(unitKey(n))}">It has a passive HA partner</button></p>`;
    }
    const peer = (S.graph?.nodes || []).find((x) => x.id === n.ha_peer);
    const st = String(n.ha_state || '').replace(' (inferred)', '');
    const guess = String(n.ha_state || '').includes('inferred') || n.ha_inferred;
    const dot = haRole(n) ? `<span class="tp-ha-pip is-${haRole(n)}" aria-hidden="true"></span> ` : '';
    return `<p class="tp-ha-line">${dot}<strong>High availability:</strong> ${st && st !== 'ha-pair' ? `this unit is <strong>${esc(st)}</strong>` : 'one of a pair'}${peer ? `, partner <button type="button" class="tp-link" data-pick="${esc(peer.id)}">${esc(peer.name)}</button>` : ''}${guess ? ' <span class="tp-muted">(inferred from names and logs)</span>' : !guess && peer?.evidence === 'ha-inferred' ? ' <span class="tp-muted">(found automatically: no system lists the partner, it passes no traffic)</span>' : ''}${n.ha_user && peer?.evidence === 'ha-user' ? ' <span class="tp-muted">(you confirmed it)</span>' : ''}.</p>`;
  }
  // v0.10.30: the card of an HA unit NodeWatch draws without a system naming it — the one the user confirmed
  // ("ha-user") or the one naming suggests ("ha-inferred"). It reasons from what this build actually knows:
  // the confirmation, the naming convention across the organisation, the partner's state, which systems were
  // asked, and records that could be this unit. Vendor-neutral: names, roles and states only.
  function partnerWhen(epoch) {
    if (!epoch) return '';
    const d = new Date(epoch * 1000);
    return d.toLocaleString(undefined, { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' });
  }
  function partnerCard(n) {
    const b = n.ha_brief || {};
    const p = b.partner || {};
    const confirmed = n.evidence === 'ha-user';
    const name = n.name;
    const partnerBtn = p.id ? `<button type="button" class="tp-link" data-pick="${esc(p.id)}">${esc(p.name)}</button>` : esc(p.name || 'its partner');
    const asked = (b.asked || []).map(srcLabel).join(', ') || 'the connected systems';
    const nm = b.naming || {};
    const rows = [];
    // 1. who says it exists
    if (confirmed) {
      const when = partnerWhen(b.confirmed_at);
      rows.push(['yes', `You confirmed that ${esc(p.name)} has a passive partner${when ? ` <span class="tp-muted">· ${esc(when)}</span>` : ''}.`]);
    } else {
      rows.push(['open', `Nobody has confirmed it yet: NodeWatch drew it because the names say so. <button type="button" class="tp-link" data-ha-add="${esc((p.id && (S.graph?.nodes || []).find((x) => x.id === p.id) && unitKey((S.graph.nodes || []).find((x) => x.id === p.id))) || '')}">Confirm the pair</button>`]);
    }
    // 2. the naming convention
    if (b.expected_name) {
      const share = nm.paired_sites ? ` ${plural(nm.paired_sites, 'other site')} in your organization show both units this way${nm.share ? ` (${Math.round(nm.share * 100)}% of sites with this naming)` : ''}.` : '';
      rows.push(['yes', `The pair's naming puts it here: <strong>${esc(p.name)}</strong> is unit ${esc(b.unit || '1')}, so its partner is <strong>${esc(b.expected_name)}</strong>.${share}`]);
    }
    // 3. what the partner itself shows
    const st = String(p.ha_state || '').replace(' (inferred)', '');
    if (p.status === 'up') {
      rows.push(['yes', `${partnerBtn} is up and writing logs${st ? ` as the <strong>${esc(st)}</strong> unit` : ''}. In an active/passive pair the other unit waits silently, which is why nothing reports it.`]);
    } else if (p.status === 'down') {
      rows.push(['warn', `${partnerBtn} is reported <strong>down</strong>. If the pair failed over, this unit should be carrying the traffic now and would start writing traffic logs — none have arrived yet.`]);
    } else {
      rows.push(['open', `${partnerBtn}'s own state is not known right now, so NodeWatch cannot tell which unit is active.`]);
    }
    // 4. did any system name it?
    const cands = b.candidates || [];
    if (cands.length) {
      rows.push(['warn', `${plural(cands.length, 'record')} in your systems could be this unit — see below.`]);
    } else {
      rows.push(['open', `No connected system has reported ${esc(b.expected_name || 'this unit')} yet (asked: ${esc(asked)}). A passive unit forwards no traffic, so it writes no traffic logs; its system or HA logs, or the system that manages the pair, would name it. When one does, the real unit replaces this one by itself.`]);
    }
    const icon = { yes: '✓', warn: '!', open: '○' };
    const ladder = `<ol class="tp-why">${rows.map(([k, html]) => `<li class="tp-why-${k}"><span class="tp-why-mark" aria-hidden="true">${icon[k]}</span><span>${html}</span></li>`).join('')}</ol>`;
    const candList = cands.length
      ? `<h4 class="tp-dsub">Could this be it?</h4><ul class="tp-cands">${cands
          .map(
            (c) => `<li><div><strong>${esc(c.name)}</strong>${c.serial ? ` <small class="tp-mono">serial …${esc(String(c.serial).slice(-4))}</small>` : ''}<small class="tp-muted">${esc([srcLabel(c.source), c.model, (c.labels || []).join(', ')].filter(Boolean).join(' · '))}</small><small>${esc(c.why || '')}</small></div>${c.placeable && c.record_key && n.site_key ? `<button type="button" class="tp-btn" data-ha-place="${esc(c.record_key)}" data-ha-site="${esc(n.site_key)}">Place it here</button>` : ''}</li>`,
          )
          .join('')}</ul><p class="tp-muted tp-dsub-help">Placing a record here pairs it with ${esc(p.name)} and removes the assumed unit. Undo it any time under Site mapping.</p>`
      : '';
    const expect = `<dl class="tp-facts">
        ${fact('Expected name', b.expected_name || name)}
        ${fact('Role in the pair', confirmed ? 'Passive (standby)' : 'Passive (standby), assumed')}
        ${fact('Model', p.model ? `${p.model} — same as ${p.name}` : '')}
        ${fact('Software', p.os_version ? `${p.os_version} — pairs run the same version` : '')}
        ${fact('Site', n.site_name ? `${n.site_name}, with ${p.name}` : '')}
        ${fact('Evidence', confirmed ? 'Your confirmation + naming' : 'Naming only')}
      </dl>`;
    const actions = `<div class="tp-actions">
        ${p.id ? `<button type="button" class="tp-btn primary" data-pick="${esc(p.id)}">Open ${esc(p.name)}</button>` : ''}
        <button type="button" class="tp-btn" data-finder="${esc(b.expected_name || name)}">Look up ${esc(b.expected_name || name)}</button>
        ${confirmed ? `<button type="button" class="tp-btn" data-ha-remove="${esc(String(n.id).replace(/^ha-user:/, ''))}">Remove</button>` : ''}
      </div>`;
    return `<div class="tp-partner">
      <p class="tp-partner-lead">${confirmed ? 'Standby unit you confirmed.' : 'Probable standby unit.'} NodeWatch shows it so the site's firewall pair is complete; it is not reported by any system yet.</p>
      <h4 class="tp-dsub">Why it is on the map</h4>${ladder}${candList}
      <h4 class="tp-dsub">What NodeWatch expects</h4>${expect}${actions}</div>`;
  }

  function cloudLine(n) {
    if (!n.cloud) return '';
    const what = {
      mobile_users: 'Where remote users (GlobalProtect / VPN clients) connect. It runs in the provider’s cloud, so it has no building.',
      service_connection: 'The link between the provider’s cloud and one of your data centers.',
      remote_network: 'The link between the provider’s cloud and a branch.',
    }[n.cloud_kind] || 'A security service that runs in the provider’s cloud, not in one of your buildings.';
    return `<p class="tp-ha-line"><strong>Cloud service.</strong> ${esc(what)}</p>`;
  }

  function circuitMarkup(c) {
    return `<article class="tp-device tone-${toneOf(c.state)}">
      <header class="tp-dev-head">${glyphSvg('circuit', 'tp-glyph-lg')}<div><h3 class="tp-dh">${esc(c.label || c.interface)}</h3><p class="tp-muted">${esc(c.carrier && c.carrier !== c.label ? c.carrier : 'Internet circuit')}</p></div>
        <span class="tp-pill tone-${toneOf(c.state)}">${esc(stateWord(c.state))}</span></header>
      <dl class="tp-facts">
        ${fact('Router', (c.routers?.length > 1 ? c.routers.map((r) => `${r.device_name} (${r.interface})`) : c.device_name || c.appliance))}
        ${c.routers?.length > 1 ? '' : fact('Port', c.interface, true)}
        ${fact(privateIp(c.public_ip) ? 'WAN address' : 'Public IP', c.public_ip, true)}
        ${privateIp(c.public_ip) ? fact('Note', 'This is a private address: another router or firewall sits between this port and the internet.') : ''}
        ${fact('Address', c.ip ? `${c.ip}${c.prefix_len ? `/${c.prefix_len}` : ''}` : '', true)}
        ${fact('Gateway', c.gateway, true)}
        ${fact('Addressing', c.dhcp ? 'DHCP (from the provider)' : c.ip ? 'Static' : '')}
        ${fact('Behind NAT', c.behind_nat ? 'Yes' : '')}
        ${fact('Bandwidth', bwText(c))}
        ${fact('Port speed', c.speed_mbps ? speedText(c.speed_mbps) : '')}
        ${fact('Traffic now', c.rx_bps != null || c.tx_bps != null ? `${bps(c.rx_bps) || '0'} in, ${bps(c.tx_bps) || '0'} out` : '')}
        ${fact('Latency', c.latency_ms != null ? `${c.latency_ms} ms` : '')}
        ${fact('Packet loss', c.loss_pct != null ? `${c.loss_pct} %` : '')}
        ${fact('Jitter', c.jitter_ms != null ? `${c.jitter_ms} ms` : '')}
        ${fact('Tunnels over it', c.tunnels_total ? `${esc(c.tunnels_up)} of ${esc(c.tunnels_total)} up` : 'None')}
        ${fact('Note', c.comment && c.comment !== c.carrier ? c.comment : '')}
      </dl>
      ${c.state === 'degraded' ? '<p class="tp-muted">The link is up, but none of the SD-WAN tunnels over it is: the provider may be dropping traffic upstream.</p>' : ''}
      ${c.node_id ? `<div class="tp-actions"><button type="button" class="tp-btn" data-pick="${esc(c.node_id)}">Show the router</button></div>` : ''}
    </article>`;
  }

  // ---------------------------------------------------------------- site rendering
  function nodeTone(n) {
    const h = S.healthOn ? S.health?.nodes?.[n.id] : null;
    if (h?.state === 'critical') return 'crit';
    if (h?.state === 'warning') return 'warn';
    if (n.status === 'down') return 'crit';
    if (n.status === 'degraded') return 'warn';
    if (h?.state === 'good' || n.status === 'up' || n.status === 'connected') return 'good';
    return 'none';
  }

  function linkTone(l) {
    const h = S.healthOn ? S.health?.links?.[l.key] : null;
    if (l.state === 'down' || h?.state === 'critical') return 'crit';
    if (l.state === 'degraded' || h?.state === 'warning') return 'warn';
    return '';
  }

  // Second line of a box: model and management IP when both fit, else the IP alone.
  function nodeSub(n) {
    const ip = n.mgmt_ip || n.ips?.[0] || '';
    const model = n.model || '';
    if (ip && model && model.length + ip.length <= 18) return `${model}  ${ip}`;
    return ip || model;
  }

  function renderSite({ refit = false } = {}) {
    S.level = 'site';
    S.labelPrefix = sharedPrefix((S.graph?.nodes || []).filter((x) => x.role !== 'wireless_ap').map((x) => x.name || ''));
    syncToggles();
    $('.tp-board', S.view).classList.add('hidden');
    $('.tp-empty', S.view).classList.add('hidden');
    if (S.mode === 'overview' && S.graph?.nodes?.length) {
      $('.tp-canvas', S.view).classList.add('hidden');
      $('.tp-layered', S.view).classList.add('hidden');
      return renderOverview();
    }
    if (S.mode === 'layers' && S.graph?.nodes?.length) {
      $('.tp-canvas', S.view).classList.add('hidden');
      $('.tp-overview', S.view).classList.add('hidden');
      return renderLayered();
    }
    $('.tp-overview', S.view).classList.add('hidden');
    $('.tp-layered', S.view)?.classList.add('hidden');
    const canvas = $('.tp-canvas', S.view);
    canvas.classList.remove('hidden');
    if (!S.graph?.nodes?.length) {
      const gaps = (S.graph?.gaps || []).slice(0, 4).map((x) => `<li>${esc(x)}</li>`).join('');
      showEmpty(`<p><strong>No devices were found for this site.</strong></p>${gaps ? `<ul class="tp-gap-list">${gaps}</ul>` : '<p class="tp-muted">Check that a source is connected for this site in Settings › Connections.</p>'}<button type="button" class="tp-btn" data-act="sitemap">Review site matching</button>`);
      return;
    }
    const sc = buildScene();
    S.scene = sc;
    const lanesG = $('.tp-lanes', canvas);
    const linksG = $('.tp-links', canvas);
    const nodesG = $('.tp-nodes', canvas);
    // Lanes: a band and a rail label.
    lanesG.innerHTML = sc.laneBoxes
      .map(
        (b, i) =>
          `<g class="tp-lane${i % 2 ? ' alt' : ''}"><rect x="0" y="${b.top}" width="${sc.width}" height="${b.bottom - b.top}" rx="10"/><line class="tp-rail" x1="${RAIL_W}" x2="${RAIL_W}" y1="${b.top + 12}" y2="${b.bottom - 12}"/><text class="tp-lane-label" x="18" y="${b.top + 30}">${esc(b.label)}</text><text class="tp-lane-count" x="18" y="${b.top + 48}">${b.count}</text></g>`,
      )
      .join('');
    // Links.
    const out = [];
    const drawn = new Set();
    const busSlot = new Map();
    for (const l of sc.links) {
      const a = sc.pos.get(l.a_device);
      const b = sc.pos.get(l.b_device);
      if (!a || !b) continue;
      const pairKey = [l.a_device, l.b_device].sort().join('|') + (LAYER_OF[l.layer] || '');
      if (drawn.has(pairKey)) continue;
      drawn.add(pairKey);
      const kind = LAYER_OF[l.layer] || 'physical';
      const tone = linkTone(l);
      const w = kind !== 'physical' ? 1.5 : l.speed_mbps >= 40000 ? 3.2 : l.speed_mbps >= 10000 ? 2.3 : 1.5;
      const upper = a.y <= b.y ? l.a_device : l.b_device;
      if (!busSlot.has(upper)) busSlot.set(upper, busSlot.size % 4);
      out.push(
        `<path class="tp-link k-${kind}${tone ? ` tone-${tone}` : ''}${l.layer === 'lag' ? ' is-lag' : ''}${l.inferred ? ' is-inferred' : ''}${l.layer === 'ha' ? ' is-ha' : ''}" data-link="${esc(l.key)}" d="${linkPath(a, b, busSlot.get(upper) * 5)}" stroke-width="${l.layer === 'ha' ? 2.4 : w}">${linkTitle(l)}</path>`,
      );
    }
    // AP stubs: switch → each expanded AP.
    for (const [sw, aps] of sc.apsOf) {
      if (!S.expanded.has(sw)) continue;
      const p = sc.pos.get(sw);
      if (!p) continue;
      const x = p.x + 6;
      const last = sc.pos.get(aps[aps.length - 1].id);
      out.push(`<path class="tp-link k-physical tp-ap-trunk" d="M${x} ${p.y + p.h} V${last.y + AP_H / 2}"/>`);
      aps.forEach((ap) => {
        const q = sc.pos.get(ap.id);
        out.push(`<path class="tp-link k-physical tp-ap-stub" d="M${x} ${q.y + AP_H / 2} H${q.x}"/>`);
      });
    }
    linksG.innerHTML = out.join('');
    // Nodes.
    const parts = [];
    for (const [id, p] of sc.pos) {
      const n = sc.nodes.get(id);
      if (!n) continue;
      parts.push(p.ap ? apMarkup(n, p) : nodeMarkup(n, p, sc.apsOf.get(id)));
    }
    nodesG.innerHTML = parts.join('');
    renderLegend();
    if (refit) fit();
    else applyViewport();
    markSelection();
  }

  // Orthogonal routing: down from the upper device to a bus in the gap above the lower device's row,
  // along the bus, then down into the lower device. A lower device in a wrapped row is reached
  // through the gutter left of its column, so lines never cross the boxes of the rows above it.
  // Each upper device gets its own bus height (a few px apart) so buses read separately.
  function linkPath(a, b, busOffset = 0) {
    const ax = a.x + a.w / 2;
    const bx = b.x + b.w / 2;
    const R = 6;
    if (Math.abs(a.y - b.y) < 4) {
      const [l, r] = ax < bx ? [a, b] : [b, a];
      const x1 = l.x + l.w * 0.72;
      const x2 = r.x + r.w * 0.28;
      const lift = Math.min(44, 14 + Math.abs(x2 - x1) * 0.06);
      return `M${x1} ${l.y} V${l.y - lift + R} Q${x1} ${l.y - lift} ${x1 + R} ${l.y - lift} H${x2 - R} Q${x2} ${l.y - lift} ${x2} ${l.y - lift + R} V${r.y}`;
    }
    const [top, bot] = a.y < b.y ? [a, b] : [b, a];
    const tx = top.x + top.w / 2;
    const bxx = bot.x + bot.w / 2;
    const y1 = top.y + top.h;
    const y2 = bot.y;
    const busY = Math.max(y1 + 12, y2 - 16 - busOffset);
    const turn = (x0, y0, x1, y1d) => {
      // a corner from vertical (x0) to horizontal at y0 heading to x1
      const dir = x1 > x0 ? 1 : -1;
      return Math.abs(x1 - x0) < 2 ? `V${y1d}` : `V${y0 - R} Q${x0} ${y0} ${x0 + dir * R} ${y0} H${x1 - dir * R} Q${x1} ${y0} ${x1} ${y0 + R} V${y1d}`;
    };
    // Is there a row of the lower device's own lane between the bus and the device? Use the gutter.
    const directBlocked = S.scene && bot.row != null && [...S.scene.pos.values()].some(
      (p) => !p.ap && p.lane === bot.lane && p.row < bot.row && p.row > (top.lane === bot.lane ? top.row : -1) && Math.abs(p.x - bot.x) < 2,
    );
    if (!directBlocked) return `M${tx} ${y1} ${turn(tx, busY, bxx, y2)}`;
    const gx = bot.x - COL_GAP / 2;
    const firstRowTop = Math.min(...[...S.scene.pos.values()].filter((p) => !p.ap && p.lane === bot.lane).map((p) => p.y));
    const bus1 = Math.max(y1 + 12, firstRowTop - 16 - busOffset);
    const dir = bxx > gx ? 1 : -1;
    return `M${tx} ${y1} ${turn(tx, bus1, gx, y2 - 14 - R)} Q${gx} ${y2 - 14} ${gx + dir * R} ${y2 - 14} H${bxx - dir * R} Q${bxx} ${y2 - 14} ${bxx} ${y2 - 14 + R} V${y2}`;
  }

  const CLOUD_WORD = {
    mobile_users: 'remote users connect here',
    service_connection: 'cloud ↔ data center link',
    remote_network: 'cloud ↔ branch link',
  };
  const HA_WORD = {
    active: 'HA active',
    passive: 'HA passive',
    primary: 'HA primary',
    secondary: 'HA secondary',
    'ha-pair (inferred)': 'HA pair?',
    'active (inferred)': 'HA active?',
    'passive (inferred)': 'HA passive?',
  };
  function linkTitle(l) {
    const parts = [];
    if (l.layer === 'ha') parts.push(l.inferred ? 'HA pair (inferred from names)' : 'HA pair');
    const ends = [l.a_interface, l.b_interface].filter(Boolean);
    if (ends.length && l.layer !== 'ha') parts.push(`Ports: ${l.a_interface || '?'} ↔ ${l.b_interface || '?'}`);
    if (l.zone) parts.push(`Zone ${l.zone}`);
    for (const ev of (l.evidence || []).slice(0, 2)) if (ev?.detail) parts.push(ev.detail);
    return parts.length ? `<title>${esc(parts.join('\n'))}</title>` : '';
  }

  // HA role of a unit (v0.10.32): 'primary' (active / primary / master: green dot) or 'passive'
  // (passive / secondary / backup / standby: yellow dot); '' when it is not part of a known pair.
  function haRole(n) {
    const st = String(n?.ha_state || '').toLowerCase();
    if (/passive|secondary|backup|standby/.test(st)) return 'passive';
    if (/active|primary|master/.test(st)) return 'primary';
    if (n?.evidence === 'ha-user' || n?.evidence === 'ha-inferred') return 'passive';
    return '';
  }
  const HA_DOT_TEXT = { primary: 'HA primary (active)', passive: 'HA passive (standby)' };

  function nodeMarkup(n, p, aps) {
    const tone = nodeTone(n);
    const role = ROLE[n.role] ? n.role : 'unknown';
    const textX = p.x + 46;
    const haTag = { active: 'ACTIVE', passive: 'PASSIVE', primary: 'PRIMARY', secondary: 'SECONDARY' }[String(n.ha_state || '').replace(' (inferred)', '')] || (n.ha_peer ? 'HA' : '');
    const ha = haRole(n);
    const haTagW = haTag ? haTag.length * 6.4 + 10 + (ha ? 12 : 0) : ha ? 14 : 0;
    const name = fitText(displayName(n), p.x + p.w - 10 - textX - haTagW, nodeFont('name'));
    const memberText = (n.members || []).length > 1 ? `${n.members.length}×` : '';
    const subRoom = p.x + p.w - 10 - textX - (memberText ? 26 : 0);
    const subText = n.evidence === 'ha-inferred' ? 'standby · assumed' : n.evidence === 'ha-user' ? 'standby · confirmed' : n.evidence === 'route-next-hop' ? 'found from routes' : n.inferred ? 'not reported' : n.cloud ? (CLOUD_WORD[n.cloud_kind] || 'cloud service') : nodeSub(n);
    const sub = fitText(subText, subRoom, nodeFont('sub'));
    const members = memberText
      ? `<text class="tp-node-badge" x="${p.x + p.w - 10}" y="${p.y + 42}" text-anchor="end">${memberText}<title>${esc(`${n.members.length} units (stack / chassis / HA)`)}</title></text>`
      : '';
    const isNew = S.graph.changes?.new_nodes?.includes(n.id);
    let chip = '';
    if (aps?.length) {
      const down = aps.filter((a) => a.status === 'down').length;
      const open = S.expanded.has(n.id);
      const label = `${plural(aps.length, 'AP')}${down ? `, ${down} down` : ''}`;
      const cw = Math.min(p.w - 12, 30 + label.length * 6.6);
      chip = `<g class="tp-chip${down ? ' tone-crit' : ''}${open ? ' is-open' : ''}" data-expand="${esc(n.id)}" role="button" tabindex="0" aria-expanded="${open}" aria-label="${esc(label)} on ${esc(n.name)}"><rect x="${p.x + 12}" y="${p.y + p.h + 8}" width="${cw}" height="24" rx="12"/><path class="tp-chip-glyph" transform="translate(${p.x + 18} ${p.y + p.h + 12}) scale(.67)" d="${GLYPH.ap}"/><text x="${p.x + 38}" y="${p.y + p.h + 24}">${esc(label)} ${open ? '▴' : '▾'}</text></g>`;
    }
    return `<g class="tp-node r-${role} tone-${tone}${n.discovered ? ' is-discovered' : ''}${n.inferred ? ' is-inferred' : ''}${isNew ? ' is-new' : ''}" data-node="${esc(n.id)}" tabindex="0" role="button" aria-label="${esc(`${(ROLE[role] || ROLE.unknown).label} ${n.name}, ${n.status || 'status unknown'}`)}">
      <rect class="tp-node-box" x="${p.x}" y="${p.y}" width="${p.w}" height="${p.h}" rx="9"/>
      <rect class="tp-node-bar" x="${p.x}" y="${p.y}" width="5" height="${p.h}" rx="2.5"/>
      <path class="tp-node-glyph" transform="translate(${p.x + 14} ${p.y + 16})" d="${glyphPath(role)}"/>
      <text class="tp-node-name" x="${p.x + 46}" y="${p.y + 24}">${esc(name)}<title>${esc(n.name)}</title></text>
      <text class="tp-node-sub" x="${p.x + 46}" y="${p.y + 42}">${esc(sub || (ROLE[role] || ROLE.unknown).label)}</text>
      ${haTag ? `<text class="tp-node-ha${String(n.ha_state || '').includes('passive') ? ' is-passive' : ''}" x="${p.x + p.w - 10 - (ha ? 12 : 0)}" y="${p.y + 22}" text-anchor="end">${haTag}${String(n.ha_state || '').includes('inferred') || n.ha_inferred ? '?' : ''}<title>${esc(`High availability: ${n.ha_state || 'pair'}`)}</title></text>` : ''}
      ${ha ? `<circle class="tp-ha-dot is-${ha}" cx="${p.x + p.w - 12}" cy="${p.y + 18}" r="5"><title>${esc(HA_DOT_TEXT[ha])}</title></circle>` : ''}
      ${members}${isNew ? `<text class="tp-node-new" x="${p.x + p.w - 10}" y="${p.y + p.h - 9}" text-anchor="end">new</text>` : ''}
    </g>${chip}`;
  }

  function apMarkup(n, p) {
    const tone = nodeTone(n);
    return `<g class="tp-node tp-ap r-wireless_ap tone-${tone}" data-node="${esc(n.id)}" tabindex="0" role="button" aria-label="${esc(`Access point ${n.name}, ${n.status || 'status unknown'}`)}">
      <rect class="tp-node-box" x="${p.x}" y="${p.y}" width="${p.w}" height="${p.h}" rx="7"/>
      <rect class="tp-node-bar" x="${p.x}" y="${p.y}" width="4" height="${p.h}" rx="2"/>
      <path class="tp-node-glyph" transform="translate(${p.x + 10} ${p.y + 9}) scale(.67)" d="${GLYPH.ap}"/>
      <text class="tp-node-name tp-ap-name" x="${p.x + 32}" y="${p.y + 21}">${esc(truncate(n.name, 22))}<title>${esc(n.name)}</title></text>
    </g>`;
  }

  function renderLegend() {
    const shown = new Set((S.scene?.links || []).map((l) => LAYER_OF[l.layer] || 'physical'));
    const items = [
      ['good', 'Up / healthy'],
      ['warn', S.healthOn ? 'Degraded / over threshold' : 'Degraded'],
      ['crit', 'Down / critical'],
    ]
      .map(([t, label]) => `<span class="tp-leg tone-${t}"><i></i>${label}</span>`)
      .join('');
    const lines = [
      shown.has('physical') ? '<span class="tp-leg-line k-physical"><i></i>Cable</span>' : '',
      shown.has('overlay') ? '<span class="tp-leg-line k-overlay"><i></i>Tunnel</span>' : '',
      shown.has('l3') ? '<span class="tp-leg-line k-l3"><i></i>Routed</span>' : '',
      (S.scene?.links || []).some((l) => l.layer === 'ha') ? '<span class="tp-leg-line k-ha"><i></i>HA pair</span>' : '',
      [...(S.scene?.nodes?.values() || [])].some((n) => haRole(n))
        ? '<span class="tp-leg-ha"><i class="is-primary"></i>HA primary</span><span class="tp-leg-ha"><i class="is-passive"></i>HA passive</span>'
        : '',
      (S.scene?.links || []).some((l) => l.inferred) ? '<span class="tp-leg-line k-inferred"><i></i>Found from routes / logs</span>' : '',
    ].join('');
    const shortened = S.labelPrefix ? `<span class="tp-leg-note" title="Most device names here start with ${esc(S.labelPrefix)}; it is left out so the rest fits. Full names are in the panel.">Names shown without “${esc(S.labelPrefix)}”</span>` : '';
    $('.tp-legend', S.view).innerHTML = items + lines + shortened;
  }

  function paintHealth() {
    if (!S.scene) return;
    $$('.tp-node', S.view).forEach((el) => {
      const n = S.scene.nodes.get(el.dataset.node);
      if (!n) return;
      el.classList.remove('tone-good', 'tone-warn', 'tone-crit', 'tone-none');
      el.classList.add(`tone-${nodeTone(n)}`);
    });
    const byKey = new Map(S.scene.links.map((l) => [l.key, l]));
    $$('.tp-link[data-link]', S.view).forEach((el) => {
      const l = byKey.get(el.dataset.link);
      if (!l) return;
      el.classList.remove('tone-warn', 'tone-crit');
      const t = linkTone(l);
      if (t) el.classList.add(`tone-${t}`);
    });
    renderLegend();
  }

  // ---------------------------------------------------------------- viewport (pan / zoom)
  function applyViewport() {
    const vp = $('.tp-vp', S.view);
    if (!vp) return;
    vp.setAttribute('transform', `translate(${S.vp.x} ${S.vp.y}) scale(${S.vp.k})`);
    $('.tp-svg', S.view)?.classList.toggle('is-far', S.vp.k < 0.55);
  }

  function fit() {
    const svg = $('.tp-svg', S.view);
    if (!svg || !S.scene) return;
    const r = svg.getBoundingClientRect();
    const w = r.width || 1000;
    const h = r.height || 600;
    // Whole map when it is small enough to stay readable; otherwise fit the width and start at the top.
    const whole = Math.min((w - 40) / S.scene.width, (h - 30) / S.scene.height);
    const k = Math.max(0.6, Math.min(1.1, whole >= 0.6 ? whole : (w - 40) / S.scene.width));
    S.vp = { k, x: Math.max(20, (w - S.scene.width * k) / 2), y: 14 };
    S.userMoved = false;
    applyViewport();
  }

  function zoomBy(f, cx, cy) {
    const svg = $('.tp-svg', S.view);
    const r = svg.getBoundingClientRect();
    cx = cx ?? r.width / 2;
    cy = cy ?? r.height / 2;
    const k = Math.max(0.15, Math.min(2.5, S.vp.k * f));
    S.vp.x = cx - ((cx - S.vp.x) * k) / S.vp.k;
    S.vp.y = cy - ((cy - S.vp.y) * k) / S.vp.k;
    S.vp.k = k;
    S.userMoved = true;
    applyViewport();
  }

  function centerOn(id) {
    const p = S.scene?.pos.get(id);
    const svg = $('.tp-svg', S.view);
    if (!p || !svg) return;
    const r = svg.getBoundingClientRect();
    const k = Math.max(S.vp.k, 0.8);
    S.vp = { k, x: r.width / 2 - (p.x + p.w / 2) * k, y: r.height / 2 - (p.y + p.h / 2) * k };
    S.userMoved = true;
    applyViewport();
  }

  // ---------------------------------------------------------------- selection
  function select(id, { center = false, openDrawer = true } = {}) {
    if (id === REMOTE_SUMMARY) {
      S.mode = 'overview';
      store.set('mode2', S.mode);
      S.allRemote = true;
      renderSite();
      setTimeout(() => $('.tp-remote', S.view)?.closest('section')?.scrollIntoView({ block: 'start', behavior: 'smooth' }), 50);
      return;
    }
    S.selected = id;
    if (id && S.scene && !S.scene.pos.has(id)) {
      // An AP folded under its switch: unfold it so it can be shown.
      for (const [sw, aps] of S.scene.apsOf) {
        if (aps.some((a) => a.id === id)) {
          S.expanded.add(sw);
          renderSite();
          break;
        }
      }
    }
    if (id && openDrawer) {
      S.drawerTab = 'device';
      if (!S.drawerOpen) {
        S.drawerOpen = true;
        if (S.level !== 'site') S.drawerOrg = true;
        store.set('drawer', true);
      }
      syncToggles();
    }
    markSelection();
    renderDrawer();
    if (id && center && S.mode === 'wiring') centerOn(id);
    if (id && !/^(circuit|link):/.test(id)) loadNodeDetail(id);
    if (S.mode === 'layers' && S.level === 'site') markLayered();
  }

  // Light (overview) maps carry no per-source records: fetch them for the selected device.
  async function loadNodeDetail(id) {
    const n = (S.graph?.nodes || []).find((x) => x.id === id);
    if (!n || n.records || n._detailLoading) return;
    n._detailLoading = true;
    try {
      const d = await api(`${API}/node/${encodeURIComponent(id)}?site=${encodeURIComponent(S.siteKey)}`);
      Object.assign(n, d.node || {});
      if (S.selected === id) renderDrawer();
    } catch (err) {
      console.warn('topology node detail', err);
    } finally {
      n._detailLoading = false;
    }
  }

  function markLayered() {
    $$('.tp-layered [data-pick]', S.view).forEach((el) => el.classList.toggle('is-sel', el.dataset.pick === S.selected));
  }
  function markSelection() {
    if (!S.scene) return;
    const sel = S.selected;
    const near = new Set();
    if (sel) {
      for (const l of S.scene.links) {
        if (l.a_device === sel) near.add(l.b_device);
        if (l.b_device === sel) near.add(l.a_device);
      }
    }
    const svg = $('.tp-svg', S.view);
    svg?.classList.toggle('has-selection', !!sel);
    $$('.tp-node', S.view).forEach((el) => {
      el.classList.toggle('is-selected', el.dataset.node === sel);
      el.classList.toggle('is-near', near.has(el.dataset.node));
    });
    const byKey = new Map(S.scene.links.map((l) => [l.key, l]));
    $$('.tp-link[data-link]', S.view).forEach((el) => {
      const l = byKey.get(el.dataset.link);
      el.classList.toggle('is-near', !!(l && sel && (l.a_device === sel || l.b_device === sel)));
    });
    const tr = S.trace && !S.trace.error ? S.trace : null;
    svg?.classList.toggle('has-trace', !!tr?.path_nodes?.length);
    $$('.tp-node', S.view).forEach((el) => el.classList.toggle('is-path', !!tr?.path_nodes?.includes(el.dataset.node)));
    // Links of the path: the ones the trace names, plus any drawn link joining two consecutive hops.
    const pathPairs = new Set();
    const pn = tr?.path_nodes || [];
    for (let i = 1; i < pn.length; i++) pathPairs.add([pn[i - 1], pn[i]].sort().join('|'));
    $$('.tp-link[data-link]', S.view).forEach((el) => {
      const l = byKey.get(el.dataset.link);
      const on = !!tr && (tr.path_links?.includes(el.dataset.link) || (l && pathPairs.has([l.a_device, l.b_device].sort().join('|'))));
      el.classList.toggle('is-path', on);
    });
    // Hop numbers next to the devices of the path.
    $$('.tp-hop-badge', S.view).forEach((x) => x.remove());
    if (tr && S.scene) {
      const nodesG = $('.tp-nodes', S.view);
      const firstHop = new Map();
      (tr.hops || []).forEach((h) => h.node && !firstHop.has(h.node) && firstHop.set(h.node, h));
      const marks = [];
      for (const [id, h] of firstHop) {
        const p = S.scene.pos.get(id);
        if (!p) continue;
        const bad = hopProblems(h).length || h.action === 'deny' || h.action === 'drop';
        marks.push(`<g class="tp-hop-badge${bad ? ' is-bad' : ''}" aria-hidden="true"><circle cx="${p.x}" cy="${p.y}" r="11"/><text x="${p.x}" y="${p.y + 4}" text-anchor="middle">${esc(h.n)}</text></g>`);
      }
      const f = tr.focus;
      const fp = f?.port && S.scene.pos.get(f.node);
      if (fp) {
        const label = `port ${f.port}`;
        const w = 16 + label.length * 6.6;
        marks.push(`<g class="tp-port-flag" aria-hidden="true"><rect x="${fp.x + fp.w - w}" y="${fp.y + fp.h + 6}" width="${w}" height="22" rx="11"/><text x="${fp.x + fp.w - w / 2}" y="${fp.y + fp.h + 21}" text-anchor="middle">${esc(label)}</text></g>`);
      }
      nodesG?.insertAdjacentHTML('beforeend', marks.join(''));
    }
  }

  // ---------------------------------------------------------------- drawer
  function renderDrawer() {
    if (!S.view) return;
    const body = $('.tp-drawer-body', S.view);
    const issues = issueCount();
    const c = $('[data-count="issues"]', S.view);
    if (c) c.textContent = issues ? String(issues) : '';
    $('.tp-shell', S.view)?.classList.toggle('drawer-wide', S.drawerTab === 'routes');
    if (S.drawerTab === 'routes') {
      renderRoutes(body);
      return syncToggles();
    }
    if (S.drawerTab === 'trace') body.innerHTML = traceMarkup();
    else if (S.drawerTab === 'issues') body.innerHTML = issuesMarkup();
    else body.innerHTML = deviceMarkup();
    syncToggles();
  }

  function currentSources() {
    return (S.level === 'site' ? S.graph?.sources : S.org?.sources) || [];
  }
  function currentGaps() {
    return (S.level === 'site' ? S.graph?.gaps : S.org?.gaps) || [];
  }
  function issueCount() {
    const bad = currentSources().filter((s) => !s.ok || s.stale).length;
    const worst = S.level === 'site' && S.healthOn ? (S.health?.worst || []).filter((w) => w.state === 'critical').length : 0;
    return bad + currentGaps().length + worst;
  }

  function fact(label, value, mono = false) {
    if (value == null || value === '' || (Array.isArray(value) && !value.length)) return '';
    return `<div class="tp-fact"><dt>${esc(label)}</dt><dd${mono ? ' class="tp-mono"' : ''}>${Array.isArray(value) ? value.map(esc).join('<br>') : esc(value)}</dd></div>`;
  }

  function deviceMarkup() {
    if (S.level !== 'site' || !S.graph) {
      return `<div class="tp-drawer-empty"><p>Open a site to see how it is wired.</p><p class="tp-muted">Sites that need attention are listed first. Search finds any device in the organization by name, IP, MAC or serial.</p></div>`;
    }
    if (S.selected?.startsWith('link:')) {
      const l = (S.graph.links || []).find((x) => x.key === S.selected.slice(5));
      if (l) return linkMarkup(l);
    }
    if (S.selected?.startsWith('circuit:')) {
      const key = S.selected.slice(8);
      const c = (S.graph.wan?.circuits || []).find((x) => x.key === key);
      if (c) return circuitMarkup(c);
    }
    const n = S.selected ? (S.graph.nodes || []).find((x) => x.id === S.selected) : null;
    if (!n) {
      const roles = {};
      (S.graph.nodes || []).forEach((x) => {
        roles[x.role] = (roles[x.role] || 0) + 1;
      });
      const down = (S.graph.nodes || []).filter((x) => x.status === 'down');
      return `<div class="tp-drawer-empty">
        <h3 class="tp-dh">${esc(siteName(S.siteKey))}</h3>
        <ul class="tp-role-list">${Object.entries(roles)
          .sort((a, b) => roleOrder(a[0]) - roleOrder(b[0]))
          .map(([r, k]) => `<li>${glyphSvg(r, 'tp-glyph-sm')}<span>${esc((ROLE[r] || ROLE.unknown).label)}</span><strong>${k}</strong></li>`)
          .join('')}</ul>
        ${down.length ? `<h4 class="tp-dsub">Down</h4><ul class="tp-pick-list">${down.slice(0, 30).map((d) => `<li><button type="button" class="tp-link" data-pick="${esc(d.id)}">${esc(d.name)}</button></li>`).join('')}</ul>` : ''}
        <p class="tp-muted">Select a device for its details.</p></div>`;
    }
    const role = ROLE[n.role] || ROLE.unknown;
    const isPartner = n.evidence === 'ha-user' || n.evidence === 'ha-inferred';
    const h = S.health?.nodes?.[n.id];
    const neighbours = [];
    for (const l of S.graph.links || []) {
      if (l.a_device !== n.id && l.b_device !== n.id) continue;
      const mine = l.a_device === n.id;
      const other = (S.graph.nodes || []).find((x) => x.id === (mine ? l.b_device : l.a_device));
      neighbours.push({ l, other, local: mine ? l.a_interface : l.b_interface, remote: mine ? l.b_interface : l.a_interface });
    }
    // The same neighbour on the same port by two kinds of evidence (cable + routed, logs + LLDP) is listed once.
    const seenNb = new Set();
    for (let i = neighbours.length - 1; i >= 0; i--) {
      const x = neighbours[i];
      const k = `${x.other?.id || '?'}|${String(x.local || '').toLowerCase()}|${String(x.remote || '').toLowerCase()}`;
      if (seenNb.has(k)) neighbours.splice(i, 1);
      else seenNb.add(k);
    }
    neighbours.sort((a, b) => String(a.local || '').localeCompare(String(b.local || ''), undefined, { numeric: true }));
    // Port Toolkit currently works on Mist-managed switches only; other vendors get it when their
    // connector supplies a port-tools target (record.vendor.*_site_id / *_device_id for Mist today).
    const mist = (n.records || []).find((r) => r.vendor?.mist_site_id && r.vendor?.mist_device_id);
    const consoles = (n.records || []).filter((r) => r.console_url).map((r) => ({ url: r.console_url, src: r.source }));
    const members = (n.members || []).filter((m) => m.serial || m.name || m.model);
    const reasons = (h?.reasons || []).filter((r) => r.state && r.state !== 'good');
    const portIssues = h?.port_issues || [];
    return `<article class="tp-device tone-${nodeTone(n)}">
      <header class="tp-dev-head">${glyphSvg(n.role, 'tp-glyph-lg')}<div><h3 class="tp-dh">${esc(n.name)}</h3><p class="tp-muted">${esc(role.label)}${n.vendor_name ? `, ${esc(n.vendor_name)}` : ''}${n.discovered ? ' · seen only by neighbours' : ''}${isPartner ? ` · standby unit of ${esc(n.ha_brief?.partner?.name || 'its pair')}` : n.inferred ? ' · not managed by a connected system' : ''}</p></div>
        <span class="tp-pill tone-${isPartner ? 'info' : nodeTone(n)}">${isPartner ? (n.evidence === 'ha-user' ? 'Standby · confirmed' : 'Standby · assumed') : esc(cap(n.status || 'unknown'))}</span></header>
      ${
        isPartner
          ? partnerCard(n)
          : n.inferred && n.evidence === 'route-next-hop'
            ? `<div class="tp-callout tp-callout-info tp-inferred-note"><p><strong>Found from the router's routes.</strong> ${esc(n.inferred_reason || '')}.</p><p class="tp-muted">Something at ${esc(n.mgmt_ip || 'this address')} (often a core switch or a firewall) carries these networks. NodeWatch knows only its address. To see its name, model and ports, connect the system that manages it, or assign it under Site mapping if it belongs elsewhere.</p></div>`
            : n.inferred
              ? `<div class="tp-callout tp-callout-info tp-inferred-note"><p><strong>Not reported by a connected system.</strong> ${esc(n.inferred_reason || '')}</p></div>`
              : ''
      }
      ${haLine(n)}${cloudLine(n)}
      ${reasons.length ? `<ul class="tp-reasons">${reasons.map((r) => `<li class="tone-${r.state === 'critical' ? 'crit' : 'warn'}">${esc(r.text)}</li>`).join('')}</ul>` : ''}
      ${isPartner ? '' : `<div class="tp-actions">
        ${mist ? `<button type="button" class="tp-btn primary" data-toolkit="${esc(mist.vendor.mist_site_id)}|${esc(mist.vendor.mist_device_id)}">Port Toolkit</button>` : ''}
        <button type="button" class="tp-btn" data-finder="${esc(n.mac ? fmtMac(n.mac) : n.mgmt_ip || n.name)}">Device Finder</button>
        <button type="button" class="tp-btn" data-trace-from="${esc(n.mgmt_ip || n.name)}">Trace from here</button>
        ${consoles.slice(0, 2).map((c) => `<a class="tp-btn" href="${esc(c.url)}" target="_blank" rel="noopener noreferrer">Open in ${esc(srcLabel(c.src))}</a>`).join('')}
      </div>`}
      ${isPartner ? '' : `<dl class="tp-facts">
        ${fact('Model', n.model)}
        ${fact('Management IP', n.mgmt_ip, true)}
        ${fact('Other IPs', (n.ips || []).filter((ip) => ip !== n.mgmt_ip).slice(0, 6), true)}
        ${fact('MAC', n.mac ? fmtMac(n.mac) : '', true)}
        ${fact('Serial', n.serial, true)}
        ${fact('Software', n.os_version)}
        ${fact('Ports', n.ports_total ? `${n.ports_up ?? '?'} of ${n.ports_total} up${n.ports_warn ? `, ${n.ports_warn} with problems` : ''}` : '')}
        ${fact('PoE draw', n.poe_draw_w ? `${Math.round(n.poe_draw_w)} W` : '')}
        ${fact('Clients', n.clients)}
        ${fact('CPU', h?.metrics?.cpu_pct != null ? `${Math.round(h.metrics.cpu_pct)} %` : '')}
        ${fact('Memory', h?.metrics?.memory_pct != null ? `${Math.round(h.metrics.memory_pct)} %` : '')}
        ${fact('HA state', h?.metrics?.ha_state)}
        ${fact('Seen by', (n.sources || []).map(srcLabel).join(', '))}
        ${fact('Placed here by', { lldp: 'its LLDP neighbours', hostname: 'its host name', manual: 'you (site matching)', name: 'site name match', ha_peer: 'its HA partner', ha_name: 'its HA partner’s name (unit 1/2, A/B)' }[n.site_via] || '')}
      </dl>`}
      ${members.length > 1 ? `<h4 class="tp-dsub">${n.role === 'switch' ? 'Stack members' : 'HA pair / members'}</h4><ul class="tp-members">${members.map((m) => `<li><span>${esc(m.name || m.role || `Member ${m.index ?? ''}`)}</span><small class="tp-mono">${esc([m.model, m.serial].filter(Boolean).join('  '))}</small>${m.status ? `<span class="tp-pill tone-${m.status === 'down' ? 'crit' : 'good'}">${esc(cap(m.status))}</span>` : ''}</li>`).join('')}</ul>` : ''}
      ${portIssues.length ? `<h4 class="tp-dsub">Ports with problems</h4><ul class="tp-ports">${portIssues.slice(0, 20).map((p) => `<li class="tone-${p.state === 'critical' ? 'crit' : 'warn'}"><span class="tp-mono">${esc(p.interface)}</span><small>${esc((p.reasons || []).map((r) => r.text || r).join('; '))}</small></li>`).join('')}</ul>` : ''}
      <h4 class="tp-dsub">Connections <small class="tp-muted">${neighbours.length}</small></h4>
      ${neighbours.length ? `<ul class="tp-neigh">${neighbours.map(({ l, other, local, remote }) => `<li class="${l.state === 'down' ? 'tone-crit' : ''}"><span class="tp-mono">${esc(local || '—')}</span><button type="button" class="tp-link" data-pick="${esc(other?.id || '')}">${esc(other?.name || 'unknown')}</button><small class="tp-mono">${esc(remote || '')}</small><small>${esc([LAYER_OF[l.layer] === 'overlay' ? 'tunnel' : LAYER_OF[l.layer] === 'l3' ? 'routed' : speedText(l.speed_mbps), l.layer === 'lag' ? 'aggregate' : ''].filter(Boolean).join(', '))}</small></li>`).join('')}</ul>` : '<p class="tp-muted">No known connections. LLDP may be off on this device or its neighbours.</p>'}
    </article>`;
  }

  function issuesMarkup() {
    const sources = currentSources();
    const gaps = currentGaps();
    const worst = S.level === 'site' && S.healthOn ? S.health?.worst || [] : [];
    const changes = S.level === 'site' ? S.graph?.changes : null;
    const srcRows = sources
      .map((s) => {
        const tone = !s.ok ? 'crit' : s.stale ? 'warn' : 'good';
        const note = !s.ok ? s.error || 'not answering' : s.stale ? `showing data from ${ago(s.stale_age_s ?? (s.stale_since ? Date.now() / 1000 - s.stale_since : null)) || 'earlier'}` : `${s.records ?? ''} records`;
        return `<li class="tone-${tone}"><span class="tp-dot"></span><span>${esc(s.product || s.source)}</span><small>${esc(truncate(String(note), 160))}</small></li>`;
      })
      .join('');
    return `<div class="tp-issues">
      ${worst.length ? `<h4 class="tp-dsub">Worst right now</h4><ul class="tp-worst">${worst.slice(0, 12).map((w) => `<li class="tone-${w.state === 'critical' ? 'crit' : 'warn'}">${w.type === 'node' ? `<button type="button" class="tp-link" data-pick="${esc(w.id)}">${esc(w.name)}</button>` : `<span>${esc(w.name)}</span>`}<small>${esc(w.text)}</small></li>`).join('')}</ul>` : ''}
      ${changes?.total ? `<h4 class="tp-dsub">Changed since the baseline</h4><p class="tp-muted">${plural((changes.new_nodes || []).length, 'new device')}, ${plural((changes.missing_nodes || []).length, 'missing device')}, ${plural((changes.new_links || []).length + (changes.missing_links || []).length, 'link change')}.</p>${(changes.missing_nodes || []).length ? `<ul class="tp-pick-list">${changes.missing_nodes.slice(0, 15).map((m) => `<li class="tone-warn">Missing: ${esc(m.name)}</li>`).join('')}</ul>` : ''}<button type="button" class="tp-btn" data-act="baseline">Accept as the new baseline</button>` : ''}
      <h4 class="tp-dsub">Sources</h4>
      ${srcRows ? `<ul class="tp-sources">${srcRows}</ul>` : '<p class="tp-muted">No source has answered yet.</p>'}
      <h4 class="tp-dsub">What the map cannot see <small class="tp-muted">${gaps.length || ''}</small></h4>
      ${gaps.length ? `<ul class="tp-gap-list">${gaps.map((g) => `<li>${esc(g)}</li>`).join('')}</ul>` : '<p class="tp-muted">No known gaps.</p>'}
      <p><button type="button" class="tp-link" data-act="sitemap">Review how sources are matched to sites</button></p>
    </div>`;
  }

  // ---------------------------------------------------------------- routing tables (v0.10.32)
  // Every route of the site's routed devices: search (prefix, next hop, interface, device, peer), filter by
  // device and protocol, sort by any column. Read on demand and kept for a minute per site.
  const ROUTE_COLS = [
    ['device', 'Device'],
    ['prefix', 'Destination'],
    ['next_hop', 'Next hop'],
    ['interface', 'Interface'],
    ['protocol', 'Protocol'],
  ];
  S.routes = { site: '', at: 0, data: null, busy: false, error: '', q: '', device: '', proto: '', sort: 'prefix', dir: 1, limit: 300 };
  function ipKey(prefix) {
    const [ip, len] = String(prefix || '').split('/');
    const parts = ip.split('.');
    if (parts.length === 4 && parts.every((x) => /^\d+$/.test(x)))
      return parts.map((x) => x.padStart(3, '0')).join('.') + '/' + String(len || '32').padStart(3, '0');
    return `z${String(prefix || '').toLowerCase()}`;
  }
  async function loadRoutes(force = false) {
    const R = S.routes;
    if (S.level !== 'site' || !S.siteKey) return;
    if (!force && R.site === S.siteKey && (R.data || R.busy) && Date.now() - R.at < 60000) return;
    R.site = S.siteKey;
    R.busy = true;
    R.error = '';
    try {
      const data = await api(`${API}/routes?site=${encodeURIComponent(S.siteKey)}`);
      if (R.site !== S.siteKey) return;
      R.data = data;
      R.at = Date.now();
    } catch (err) {
      R.error = err.message;
      R.data = null;
    } finally {
      R.busy = false;
    }
    if (S.drawerTab === 'routes') renderDrawer();
  }
  function filteredRoutes() {
    const R = S.routes;
    const term = R.q.trim().toLowerCase();
    let rows = (R.data?.routes || []).filter(
      (r) =>
        (!R.device || r.node_id === R.device) &&
        (!R.proto || (r.protocol || 'other') === R.proto) &&
        (!term || `${r.device} ${r.prefix} ${r.next_hop} ${r.interface} ${r.protocol} ${r.peer} ${r.vrf}`.toLowerCase().includes(term)),
    );
    const key = R.sort;
    const val = (r) => (key === 'prefix' ? ipKey(r.prefix) : key === 'next_hop' ? ipKey(r.next_hop || r.peer) : String(r[key] || '').toLowerCase());
    rows = rows.slice().sort((a, b) => (val(a) < val(b) ? -1 : val(a) > val(b) ? 1 : 0) * R.dir || ipKey(a.prefix).localeCompare(ipKey(b.prefix)));
    return rows;
  }
  function routesTableMarkup() {
    const R = S.routes;
    const all = R.data?.routes || [];
    const rows = filteredRoutes();
    const shown = rows.slice(0, R.limit);
    const head = ROUTE_COLS.map(
      ([k, label]) =>
        `<th scope="col" aria-sort="${R.sort === k ? (R.dir > 0 ? 'ascending' : 'descending') : 'none'}"><button type="button" class="tp-th" data-route-sort="${k}">${esc(label)}${R.sort === k ? (R.dir > 0 ? ' ▲' : ' ▼') : ''}</button></th>`,
    ).join('');
    const body = shown
      .map(
        (r) => `<tr class="${r.local ? 'is-local' : ''}"><td><button type="button" class="tp-link" data-pick="${esc(r.node_id)}">${esc(r.device)}</button></td><td class="tp-mono">${esc(r.prefix)}${r.vrf ? ` <small class="tp-muted">${esc(r.vrf)}</small>` : ''}</td><td class="tp-mono">${esc(r.next_hop || (r.peer ? '' : '—'))}${r.peer ? `<br><small class="tp-muted">${esc(r.peer)}</small>` : ''}</td><td class="tp-mono">${esc(r.interface || '—')}</td><td>${esc(r.protocol || '—')}${r.local ? ' <small class="tp-muted">local</small>' : ''}</td></tr>`,
      )
      .join('');
    return `<p class="tp-muted tp-routes-count">${rows.length === all.length ? plural(all.length, 'route') : `${rows.length} of ${plural(all.length, 'route')}`}${R.data?.truncated ? ' (first 20,000)' : ''}</p>
      ${rows.length ? `<div class="tp-table-wrap tp-routes-wrap"><table class="tp-table tp-routes-table"><thead><tr>${head}</tr></thead><tbody>${body}</tbody></table></div>` : `<p class="tp-muted">${all.length ? 'No route matches the filter.' : 'No routes.'}</p>`}
      ${rows.length > shown.length ? `<button type="button" class="tp-link" data-route-more="1">Show ${Math.min(rows.length - shown.length, 1000)} more</button>` : ''}`;
  }
  function renderRoutes(body) {
    const R = S.routes;
    if (S.level !== 'site' || !S.graph) {
      body.innerHTML = '<div class="tp-drawer-empty"><p>Open a site to see the routing tables of its firewalls, routers and SD-WAN edges.</p></div>';
      return;
    }
    if (R.site !== S.siteKey || (!R.data && !R.busy && !R.error) || Date.now() - R.at > 60000) loadRoutes();
    const existing = $('.tp-routes', body);
    if (existing && existing.dataset.site === S.siteKey && R.data && existing.dataset.ready === '1') {
      $('.tp-routes-result', body).innerHTML = routesTableMarkup();
      return;
    }
    let inner;
    if (R.busy && !R.data) inner = '<p class="tp-muted"><span class="tp-pulse"></span> Reading the routing tables…</p>';
    else if (R.error) inner = `<p class="tone-crit">The routing tables could not be read: ${esc(R.error)}</p><button type="button" class="tp-btn" data-route-reload="1">Try again</button>`;
    else if (R.data?.no_source) inner = '<p class="tp-muted">No connected source reads routing tables (EdgeConnect Orchestrator, Panorama, FortiGate and SNMP do). Connect one in Settings › Connections.</p>';
    else if (R.data && !R.data.devices?.length) inner = '<p class="tp-muted">This site has no firewall, router or SD-WAN edge whose routes a connected source can read.</p>';
    if (inner) {
      body.innerHTML = `<div class="tp-routes" data-site="${esc(S.siteKey)}">${inner}</div>`;
      return;
    }
    const protos = [...new Set((R.data.routes || []).map((r) => r.protocol || 'other'))].sort();
    if (R.device && !R.data.devices.some((d) => d.node_id === R.device)) R.device = '';
    if (R.proto && !protos.includes(R.proto)) R.proto = '';
    body.innerHTML = `<div class="tp-routes" data-site="${esc(S.siteKey)}" data-ready="1">
      <p class="tp-muted tp-routes-help">Where each routed device sends traffic for each network. Search a prefix, next hop or interface; click a column to sort.</p>
      <div class="tp-routes-tools">
        <input type="search" class="tp-routes-q" placeholder="Search: 10.20., wan0, bgp…" aria-label="Search routes" value="${esc(R.q)}" spellcheck="false">
        <select class="tp-routes-dev" aria-label="Device"><option value="">All devices (${R.data.devices.length})</option>${R.data.devices.map((d) => `<option value="${esc(d.node_id)}"${R.device === d.node_id ? ' selected' : ''}>${esc(d.name)}</option>`).join('')}</select>
        <select class="tp-routes-proto" aria-label="Protocol"><option value="">All protocols</option>${protos.map((x) => `<option value="${esc(x)}"${R.proto === x ? ' selected' : ''}>${esc(x)}</option>`).join('')}</select>
        <button type="button" class="tp-btn" data-route-reload="1" title="Read the routing tables again">Reload</button>
      </div>
      ${(R.data.errors || []).length ? `<p class="tp-warn-text tp-routes-err">Some tables could not be read: ${esc(R.data.errors.slice(0, 2).join('; '))}</p>` : ''}
      <div class="tp-routes-result">${routesTableMarkup()}</div>
    </div>`;
  }

  function traceMarkup() {
    const t = S.trace;
    const from = S.traceForm?.from || '';
    const to = S.traceForm?.to || '';
    let result = '';
    if (S.traceBusy) result = '<p class="tp-muted"><span class="tp-pulse"></span> Tracing…</p>';
    else if (t?.error) result = `<p class="tone-crit">${esc(t.error)}</p>`;
    else if (t) {
      // v0.10.32: the verdict says plainly whether traffic gets through; every hop shows what it does and
      // any problem on it (device down / over threshold, link errors, a deny); the map paints the path.
      const v = t.verdict || {};
      const tone = TRACE_TONE[v.status] || 'warn';
      const issues = traceIssues(t);
      const known = (id) => /^(circuit|link):/.test(String(id)) || (S.graph?.nodes || []).some((n) => n.id === id);
      const onMap = (t.path_nodes || []).filter(known).length;
      const offMap = t.synthetic ? 0 : (t.path_nodes || []).length - onMap;
      result = `<div class="tp-verdict tone-${tone}"><span class="tp-verdict-word">${esc(TRACE_WORD[v.status] || 'Result')}</span> ${esc(v.text || v.status || '')}</div>
        ${issues.length ? `<div class="tp-trace-issues tone-crit"><strong>${plural(issues.length, 'problem')} on this path</strong><ul>${issues.map((x) => `<li class="tone-${x.tone}">${x.node ? `<button type="button" class="tp-link" data-pick="${esc(x.node)}">${esc(x.where)}</button>` : `<strong>${esc(x.where)}</strong>`}: ${esc(x.text)}</li>`).join('')}</ul></div>` : (t.hops || []).length ? '<p class="tp-trace-ok tone-good">No problems reported on the devices and links of this path.</p>' : ''}
        ${S.level === 'site' && onMap ? `<p class="tp-muted tp-trace-map">The path is drawn in blue on the map${offMap ? `; ${plural(offMap, 'hop')} at other sites are listed below only` : ''}. <button type="button" class="tp-link" data-act="trace-show">Show it on the map</button></p>` : (t.hops || []).length ? '<p class="tp-muted tp-trace-map">Open the site of the first hop to see the path drawn on its map.</p>' : ''}
        <ol class="tp-hops">${(t.hops || [])
          .map((h) => {
            const bad = hopProblems(h);
            const htone = h.action === 'deny' || h.action === 'drop' || bad.some((x) => x.tone === 'crit') ? 'crit' : bad.length || h.action === 'unknown' ? 'warn' : 'good';
            return `<li class="tp-hop tone-${htone}"><span class="tp-hop-n">${esc(h.n || '')}</span><div class="tp-hop-main"><div>${h.node ? `<button type="button" class="tp-link" data-pick="${esc(h.node)}">${esc(h.name)}</button>` : `<strong>${esc(h.name)}</strong>`}${h.site_name ? ` <small class="tp-muted">${esc(h.site_name)}</small>` : ''}${h.action && h.action !== 'forward' ? ` <span class="tp-pill tone-${htone}">${esc(HOP_ACTION[h.action] || h.action)}</span>` : ''}</div><small>${esc(h.decision || '')}${h.ingress || h.egress ? ` <span class="tp-mono">${esc([h.ingress, h.egress].filter(Boolean).join(' → '))}</span>` : ''}</small>${bad.length ? `<ul class="tp-hop-bad">${bad.map((x) => `<li class="tone-${x.tone}">${esc(x.text)}</li>`).join('')}</ul>` : ''}</div></li>`;
          })
          .join('')}</ol>
        ${(t.gaps || []).length ? `<h4 class="tp-dsub">What the trace could not see</h4><ul class="tp-gap-list">${t.gaps.map((g) => `<li>${esc(g)}</li>`).join('')}</ul>` : ''}
        <button type="button" class="tp-link" data-act="trace-clear">Clear the trace</button>`;
    }
    return `<form class="tp-trace" autocomplete="off" novalidate>
      <label>From<input name="from" type="text" value="${esc(from)}" placeholder="IP, MAC or host name" maxlength="253" spellcheck="false" required></label>
      <label>To<input name="to" type="text" value="${esc(to)}" placeholder="IP, MAC or host name" maxlength="253" spellcheck="false" required></label>
      <div class="tp-trace-row"><label>Port<input name="port" type="number" min="1" max="65535" placeholder="any" value="${esc(S.traceForm?.port || '')}"></label>
      <label>Protocol<select name="proto">${['tcp', 'udp', 'icmp', 'any'].map((p) => `<option value="${p}"${(S.traceForm?.proto || 'tcp') === p ? ' selected' : ''}>${p.toUpperCase()}</option>`).join('')}</select></label></div>
      <button type="submit" class="tp-btn primary">Trace the path</button>
    </form><div class="tp-trace-result" aria-live="polite">${result}</div>`;
  }

  const TRACE_TONE = { uplink: 'good', allowed: 'good', ok: 'good', denied: 'crit', blocked: 'crit', no_route: 'crit', loop: 'crit', broken: 'crit', partial: 'warn', unknown: 'warn' };
  const TRACE_WORD = { uplink: 'Current path.', allowed: 'Gets through.', ok: 'Gets through.', denied: 'Blocked.', blocked: 'Blocked.', no_route: 'No route.', loop: 'Routing loop.', broken: 'Broken.', partial: 'Partly traced.', unknown: 'Unknown.' };
  const HOP_ACTION = { deny: 'denied', drop: 'dropped', deliver: 'delivered', originate: 'start', unknown: 'unclear' };
  // Problems on one hop: the device's and the link's live health (state + reasons) and a deny / drop.
  function hopProblems(h) {
    const out = [];
    const toneOfState = (st) => (st === 'critical' || st === 'down' ? 'crit' : 'warn');
    const add = (hh, what) => {
      if (!hh?.state || hh.state === 'good' || hh.state === 'unknown') return;
      const reasons = (hh.reasons || []).map((r) => r?.text || r).filter(Boolean);
      (reasons.length ? reasons : [hh.badge || hh.state]).slice(0, 3).forEach((text) => out.push({ tone: toneOfState(hh.state), text: what ? `${what}: ${text}` : String(text) }));
    };
    add(h.health, '');
    add(h.link_health, 'link');
    if (h.action === 'deny') out.unshift({ tone: 'crit', text: 'a rule denies this traffic' });
    if (h.action === 'drop') out.unshift({ tone: 'crit', text: 'traffic is dropped here' });
    const node = h.node && (S.graph?.nodes || []).find((n) => n.id === h.node);
    if (node?.status === 'down') out.unshift({ tone: 'crit', text: 'the device is down' });
    return out;
  }
  function traceIssues(t) {
    const out = [];
    for (const h of t.hops || []) for (const x of hopProblems(h)) out.push({ ...x, where: h.name, node: h.node });
    return out.slice(0, 12);
  }
  // Paint the traced path: switch the site to its Wiring map, dim everything else and fit the path.
  function showTraceOnMap() {
    const t = S.trace;
    if (!t || S.level !== 'site' || !S.graph) return;
    const ids = (t.path_nodes || []).filter((id) => (S.graph.nodes || []).some((n) => n.id === id));
    if (!ids.length) return;
    if (S.mode !== 'wiring') {
      S.mode = 'wiring';
      store.set('mode2', S.mode);
      if (S.graph.view === 'overview') {
        S.graphVersion = '';
        return loadSite().then(() => showTraceOnMap());
      }
      renderSite({ refit: false });
    }
    markSelection();
    fitTo(ids);
  }
  function fitTo(ids) {
    const svg = $('.tp-svg', S.view);
    const boxes = ids.map((id) => S.scene?.pos.get(id)).filter(Boolean);
    if (!svg || !boxes.length) return;
    const r = svg.getBoundingClientRect();
    const x0 = Math.min(...boxes.map((b) => b.x)) - 40;
    const y0 = Math.min(...boxes.map((b) => b.y)) - 50;
    const x1 = Math.max(...boxes.map((b) => b.x + b.w)) + 40;
    const y1 = Math.max(...boxes.map((b) => b.y + b.h)) + 110; // room for the legend and the port flag
    const k = Math.max(0.35, Math.min(1.2, Math.min((r.width || 900) / (x1 - x0), (r.height || 600) / (y1 - y0))));
    S.vp = { k, x: (r.width - (x1 - x0) * k) / 2 - x0 * k, y: (r.height - (y1 - y0) * k) / 2 - y0 * k };
    S.userMoved = true;
    applyViewport();
  }

  // ---- path a device's traffic takes now (v0.10.32: "Show in Topology" from Device Finder) ------------
  // From the device (and the port the condition names) up the cabling to the first WAN edge / firewall
  // and its internet circuits, painted like a path trace. Built from the map itself: no extra reads.
  const normIf = (x) => String(x || '').trim().toLowerCase().replace(/\s+/g, '').replace(/^gigabitethernet/, 'gi').replace(/^tengigabitethernet/, 'te').replace(/\.0$/, '');
  function linkPort(l, nid) {
    return l.a_device === nid ? l.a_interface : l.b_interface;
  }
  function uplinkPath(startId, port) {
    const g = S.graph;
    if (!g) return null;
    const byId = new Map((g.nodes || []).map((n) => [n.id, n]));
    const start = byId.get(startId);
    if (!start) return null;
    const UP = new Set(['sdwan_edge', 'router', 'firewall']);
    const phys = (g.links || []).filter((l) => (LAYER_OF[l.layer] || 'physical') === 'physical' || l.inferred);
    const adj = new Map();
    for (const l of phys) {
      if (!adj.has(l.a_device)) adj.set(l.a_device, []);
      if (!adj.has(l.b_device)) adj.set(l.b_device, []);
      adj.get(l.a_device).push([l.b_device, l]);
      adj.get(l.b_device).push([l.a_device, l]);
    }
    const p = normIf(port);
    const portLinks = p ? (adj.get(startId) || []).filter(([, l]) => String(linkPort(l, startId) || '').split(/,\s*/).some((x) => normIf(x) === p)) : [];
    const below = portLinks.length ? portLinks[0] : null; // what the port connects to (often down the tree)
    const tierOf = (n) => (UP.has(n?.role) ? 0 : Number.isFinite(+n?.tier) ? +n.tier : 5);
    // Breadth-first up the cabling, preferring neighbours closer to the edge.
    // The goal is the nearest router that carries internet circuits (the traffic leaves there), else the
    // nearest firewall / router / SD-WAN edge. Past the first edge device only edge devices are followed.
    const withCircuits = new Set();
    for (const c of g.wan?.circuits || []) for (const x of c.node_ids?.length ? c.node_ids : [c.node_id]) if (x) withCircuits.add(x);
    const prev = new Map([[startId, null]]);
    const queue = [startId];
    let firstUp = UP.has(start.role) ? startId : null;
    let goal = withCircuits.has(startId) ? startId : null;
    while (queue.length && !goal) {
      const cur = queue.shift();
      const curUp = UP.has(byId.get(cur)?.role);
      const next = (adj.get(cur) || [])
        .filter(([nb]) => !prev.has(nb) && !(below && nb === below[0] && cur === startId && !UP.has(byId.get(nb)?.role)))
        .filter(([nb]) => !curUp || cur === startId || UP.has(byId.get(nb)?.role))
        .sort((a, b) => tierOf(byId.get(a[0])) - tierOf(byId.get(b[0])) || (b[1].state === 'up') - (a[1].state === 'up'));
      for (const [nb, l] of next) {
        prev.set(nb, [cur, l]);
        if (UP.has(byId.get(nb)?.role) && !firstUp) firstUp = nb;
        if (withCircuits.has(nb)) {
          goal = nb;
          break;
        }
        queue.push(nb);
      }
    }
    goal = goal || firstUp;
    const chain = [];
    let at = goal;
    while (at && at !== startId) {
      const [from, l] = prev.get(at);
      chain.unshift({ id: at, via: l, from });
      at = from;
    }
    const hops = [];
    const nodesOnPath = [];
    const linksOnPath = [];
    const hop = (n, extra = {}) => {
      hops.push({ n: hops.length + 1, node: n.id, name: n.name, site_name: '', action: 'forward', health: S.healthOn ? S.health?.nodes?.[n.id] || {} : {}, ...extra });
      nodesOnPath.push(n.id);
    };
    if (below) {
      const nb = byId.get(below[0]);
      if (nb) {
        hop(nb, { decision: `Connected to ${start.name} port ${port}`, egress: linkPort(below[1], nb.id) });
        linksOnPath.push(below[1].key);
      }
    }
    hop(start, { decision: port ? `This device · port ${port}` : 'This device', ingress: port || '', egress: chain[0] ? linkPort(chain[0].via, startId) : '' });
    chain.forEach((c, i) => {
      const n = byId.get(c.id);
      linksOnPath.push(c.via.key);
      const role = (ROLE[n.role] || ROLE.unknown).label;
      hop(n, { decision: i === chain.length - 1 && UP.has(n.role) ? `${role}: leaves the site here` : role, ingress: linkPort(c.via, c.id), egress: chain[i + 1] ? linkPort(chain[i + 1].via, c.id) : '' });
    });
    const edge = goal ? byId.get(goal) : null;
    const circuits = edge ? (g.wan?.circuits || []).filter((c) => (c.node_ids?.length ? c.node_ids : [c.node_id]).includes(edge.id)) : [];
    circuits.forEach((c) => {
      nodesOnPath.push(`circuit:${c.key}`);
      hops.push({ n: hops.length + 1, node: `circuit:${c.key}`, name: c.label || c.carrier || c.interface, action: c.state === 'down' ? 'drop' : 'forward', decision: `Internet circuit · ${stateWord(c.state)}${c.public_ip ? ` · ${c.public_ip}` : ''}`, health: {} });
    });
    const text = edge
      ? `${start.name}${port ? ` (port ${port})` : ''} reaches the internet through ${chain.length ? `${plural(chain.length, 'hop')} to ` : ''}${edge.name}${circuits.length ? ` and ${plural(circuits.length, 'circuit')}` : ''}.`
      : `${start.name}${port ? ` (port ${port})` : ''}: no cabled path to a WAN edge or firewall is known on this map (LLDP may be off upstream).`;
    return { synthetic: true, path_nodes: nodesOnPath, path_links: linksOnPath, hops, verdict: { status: edge ? 'uplink' : 'partial', text }, gaps: [], focus: { node: startId, port } };
  }
  async function showDevicePath(nodeId, port) {
    if (!nodeId || S.level !== 'site') return;
    if (S.mode !== 'wiring') {
      S.mode = 'wiring';
      store.set('mode2', S.mode);
      if (S.graph?.view === 'overview') {
        S.graphVersion = '';
        await loadSite();
      } else renderSite({ refit: false });
    }
    const path = uplinkPath(nodeId, port);
    if (!path) return;
    // Access points on the path are folded under their switch: unfold them so the whole path shows.
    const folded = (S.graph.nodes || []).filter((n) => path.path_nodes.includes(n.id) && n.role === 'wireless_ap' && n.uplink);
    if (folded.length) {
      folded.forEach((n) => S.expanded.add(n.uplink));
      renderSite({ refit: false });
    }
    S.trace = path;
    const n = (S.graph.nodes || []).find((x) => x.id === nodeId);
    S.traceForm = { ...(S.traceForm || {}), from: n?.mgmt_ip || n?.name || '' };
    S.selected = nodeId;
    S.drawerTab = 'trace';
    S.drawerOpen = true;
    if (S.level !== 'site') S.drawerOrg = true;
    renderDrawer();
    markSelection();
    fitTo(path.path_nodes);
  }

  async function runTrace(form) {
    const fd = new FormData(form);
    S.traceForm = { from: String(fd.get('from') || '').trim(), to: String(fd.get('to') || '').trim(), port: fd.get('port'), proto: fd.get('proto') };
    if (!S.traceForm.from || !S.traceForm.to) return;
    S.traceBusy = true;
    renderDrawer();
    try {
      S.trace = await api(`${API}/trace`, {
        method: 'POST',
        body: JSON.stringify({
          src: S.traceForm.from,
          dst: S.traceForm.to,
          dst_port: S.traceForm.port ? Number(S.traceForm.port) : null,
          protocol: S.traceForm.proto || 'tcp',
          site: S.level === 'site' ? S.siteKey : null,
        }),
      });
    } catch (err) {
      S.trace = { error: err.message };
    } finally {
      S.traceBusy = false;
    }
    renderDrawer();
    markSelection();
    if (S.trace && !S.trace.error) showTraceOnMap();
  }

  // ---------------------------------------------------------------- search
  let searchSeq = 0;
  let searchTimer = 0;
  function localMatches(q) {
    const term = q.toLowerCase();
    const bare = term.replace(/[^0-9a-f]/g, '');
    const out = [];
    if (S.level === 'site' && S.graph) {
      for (const n of S.graph.nodes || []) {
        const hay = [n.name, n.mgmt_ip, ...(n.ips || []), n.serial, n.model, ...(n.records || []).map((r) => r.name), ...(n.members || []).map((m) => `${m.name || ''} ${m.serial || ''}`)]
          .filter(Boolean)
          .join(' ')
          .toLowerCase();
        const macHit = bare.length >= 4 && (n.macs || [n.mac]).some((m) => String(m || '').includes(bare));
        if (hay.includes(term) || macHit) out.push({ node_id: n.id, name: n.name, role: n.role, status: n.status, mgmt_ip: n.mgmt_ip, site_key: S.siteKey, site_name: siteName(S.siteKey), here: true });
        if (out.length >= 8) break;
      }
    }
    for (const s of S.sites) {
      if (out.length >= 14) break;
      if (s.name.toLowerCase().includes(term)) out.push({ site_only: true, site_key: s.key, name: s.name });
    }
    return out;
  }

  function drawSuggest(items, pending) {
    const ul = $('#tpSuggest', S.view);
    const input = $('#tpSearch', S.view);
    if (!items.length && !pending) {
      ul.innerHTML = input.value.trim() ? '<li class="tp-muted tp-suggest-none">Nothing found</li>' : '';
    } else {
      ul.innerHTML =
        items
          .map(
            (r, i) =>
              `<li role="option" id="tpOpt${i}" data-i="${i}">${r.site_only ? glyphSvg('remote', 'tp-glyph-sm') : glyphSvg(r.role, 'tp-glyph-sm')}<span class="tp-sg-name">${esc(r.name)}</span><small>${esc(r.site_only ? 'Site' : [r.here ? 'This site' : r.site_name || 'No site', r.mgmt_ip, r.match_field && r.match_field !== 'name' ? `${r.match_field}: ${r.match_value}` : ''].filter(Boolean).join('  '))}</small></li>`,
          )
          .join('') + (pending ? '<li class="tp-muted tp-suggest-none">Searching all sites…</li>' : '');
    }
    ul._items = items;
    const open = !!ul.innerHTML;
    ul.classList.toggle('hidden', !open);
    input.setAttribute('aria-expanded', String(open));
  }

  function onSearchInput() {
    const q = $('#tpSearch', S.view).value.trim();
    clearTimeout(searchTimer);
    if (S.level === 'org') {
      S.board.text = '';
    }
    if (q.length < 2) {
      drawSuggest(q ? localMatches(q) : [], false);
      return;
    }
    const local = localMatches(q);
    drawSuggest(local, true);
    const seq = ++searchSeq;
    searchTimer = setTimeout(async () => {
      let remote = [];
      try {
        const data = await api(`${API}/search?q=${encodeURIComponent(q)}&limit=30`);
        remote = data.results || [];
      } catch {
        remote = [];
      }
      if (seq !== searchSeq) return;
      const seen = new Set(local.filter((r) => r.node_id).map((r) => r.node_id));
      drawSuggest([...local, ...remote.filter((r) => !seen.has(r.node_id))].slice(0, 30), false);
    }, 220);
  }

  async function chooseResult(r) {
    $('#tpSuggest', S.view).classList.add('hidden');
    $('#tpSearch', S.view).value = '';
    if (r.site_only) return openSite(r.site_key);
    if (!r.site_key) {
      S.drawerTab = 'issues';
      setStatus(`${esc(r.name)} is not in any site yet. <button type="button" class="tp-link" data-act="sitemap">Assign it to a site</button>`, 'is-warn');
      return;
    }
    if (S.level !== 'site' || (S.siteKey !== r.site_key && !(S.graph?.site?.keys || []).includes(r.site_key))) {
      await openSite(r.site_key, { select: r.node_id });
    } else {
      select(r.node_id, { center: true });
    }
  }

  // ---------------------------------------------------------------- site matching dialog
  async function openSiteMap() {
    closePopovers();
    const layer = document.createElement('div');
    layer.className = 'tp-modal-layer';
    layer.innerHTML = `<div class="tp-modal" role="dialog" aria-modal="true" aria-labelledby="tpMapTitle">
      <header><h3 id="tpMapTitle">Match sources to sites</h3><button type="button" class="tp-btn" data-close>Close</button></header>
      <div class="tp-modal-body"><p class="tp-muted"><span class="tp-pulse"></span> Loading…</p></div></div>`;
    document.body.appendChild(layer);
    const onKey = (e) => {
      if (e.key === 'Escape') close();
    };
    const close = () => {
      layer.remove();
      document.removeEventListener('keydown', onKey, true);
    };
    document.addEventListener('keydown', onKey, true);
    setTimeout(() => $('[data-close]', layer)?.focus(), 0);
    layer.addEventListener('click', (e) => {
      if (e.target === layer || e.target.closest('[data-close]')) close();
    });
    let data;
    try {
      data = await api(`${API}/site-map`);
    } catch (err) {
      $('.tp-modal-body', layer).innerHTML = `<p class="tone-crit">The site matching could not be loaded: ${esc(err.message)}</p>`;
      return;
    }
    S.siteMap = data;
    const canon = (data.canonical_sites || []).slice().sort((a, b) => String(a.name).localeCompare(String(b.name)));
    const nameOfSite = (key) => canon.find((c) => c.key === key)?.name || key;
    const options = (current, autoText, ownKey) =>
      `<option value="">${esc(autoText)}</option>${ownKey ? `<option value="${esc(ownKey)}"${current === ownKey ? ' selected' : ''}>Keep as its own site</option>` : ''}${canon
        .filter((c) => c.key !== ownKey)
        .map((c) => `<option value="${esc(c.key)}"${c.key === current ? ' selected' : ''}>${esc(c.name)}</option>`)
        .join('')}`;
    const rows = (data.connector_sites || []).slice().sort((a, b) => {
      const rank = (r) => (r.mapping === 'none' ? 0 : r.mapping === 'auto' ? 1 : r.mapping === 'manual' ? 2 : 3);
      return rank(a) - rank(b) || String(a.name).localeCompare(String(b.name));
    });
    const devices = data.unassigned_devices || [];
    const how = (r) => {
      if (r.mapping === 'manual') return 'Set by you';
      if (r.mapping === 'own') return 'Its own site';
      if (r.mapping === 'auto') return `Matched by name${r.confidence != null ? ` (${Math.round(r.confidence * 100)} %)` : ''}`;
      return r.suggested ? `Suggested: ${r.suggested.name} (${Math.round((r.suggested.confidence || 0) * 100)} %)` : 'Not matched';
    };
    $('.tp-modal-body', layer).innerHTML = `
      <p class="tp-muted">Each source names sites its own way, so NodeWatch matches them by name. Check the matches below and correct any that are wrong; leave "Automatic" to keep NodeWatch's choice. Devices that could not be placed are listed after the sites.</p>
      <table class="tp-table"><thead><tr><th>Site in the source</th><th>Source</th><th>Show it in</th><th>Now</th></tr></thead><tbody>
      ${rows
        .map((r) => {
          const current = r.mapping === 'manual' ? r.mapped_to || '' : '';
          const autoText = r.mapping === 'auto' || r.mapping === 'own' ? `Automatic (${r.mapped_name || nameOfSite(r.mapped_to)})` : r.suggested ? `Automatic (not matched; suggestion: ${r.suggested.name})` : 'Automatic (not matched)';
          return `<tr${r.mapping === 'none' ? ' class="tp-row-attn"' : ''}><td>${esc(r.name)}${r.kind && r.kind !== 'site' ? ` <small class="tp-muted">${esc(r.kind)}</small>` : ''}</td><td>${esc(r.product || r.source || '')}</td><td><select data-map="${esc(r.key)}" data-initial="${esc(current)}">${options(current, autoText, r.key)}</select></td><td class="tp-muted">${esc(how(r))}</td></tr>`;
        })
        .join('')}
      </tbody></table>
      ${devices.length ? `<h4 class="tp-dsub">Devices without a site <small class="tp-muted">${devices.length}</small></h4><p class="tp-muted tp-dsub-help">NodeWatch could not tell which building these are in. Each row says what the device is and why; pick its site, or leave it if it does not belong to a building.</p><table class="tp-table tp-unplaced"><thead><tr><th>Device</th><th>Source</th><th>Site</th></tr></thead><tbody>${devices.slice(0, 500).map((d) => `<tr><td><strong>${esc(d.name)}</strong> <small class="tp-muted tp-mono">${esc([d.model, d.mgmt_ip, d.serial ? `serial …${String(d.serial).slice(-4)}` : ''].filter(Boolean).join('  '))}</small>${d.what || d.role ? `<div class="tp-unplaced-what">${esc(d.what || (ROLE[d.role] || ROLE.unknown).label)}</div>` : ''}${d.why ? `<div class="tp-muted tp-unplaced-why">Why it is not placed: ${esc(d.why)}</div>` : ''}</td><td>${esc(srcLabel(d.source))}</td><td><select data-device="${esc(d.record_key)}" data-initial="">${options('', d.suggested ? `Not placed (suggestion: ${d.suggested.name})` : 'Not placed', null)}</select></td></tr>`).join('')}</tbody></table>` : ''}
      <footer class="tp-modal-foot"><span class="tp-muted tp-save-note"></span><button type="button" class="tp-btn primary" data-save>Save and rebuild the maps</button></footer>`;
    $('[data-save]', layer).addEventListener('click', async (e) => {
      const btn = e.currentTarget;
      const mappings = {};
      const device_sites = {};
      // Only what the user changed: untouched rows stay automatic.
      $$('[data-map]', layer).forEach((s) => {
        if (s.value !== s.dataset.initial) mappings[s.dataset.map] = s.value;
      });
      $$('[data-device]', layer).forEach((s) => {
        if (s.value) device_sites[s.dataset.device] = s.value;
      });
      if (!Object.keys(mappings).length && !Object.keys(device_sites).length) {
        close();
        return;
      }
      btn.disabled = true;
      $('.tp-save-note', layer).textContent = 'Saving…';
      try {
        await api(`${API}/site-map`, { method: 'PUT', body: JSON.stringify({ mappings, device_sites }) });
        close();
        S.graph = null;
        S.graphVersion = '';
        S.orgVersion = '';
        await loadSites();
        if (S.level === 'site') await loadSite({ fresh: true });
        else await loadOrg({ fresh: true });
      } catch (err) {
        btn.disabled = false;
        $('.tp-save-note', layer).textContent = `Not saved: ${err.message}`;
      }
    });
  }

  // ---------------------------------------------------------------- navigation
  async function openSite(key, { select: selectId = null, nav = true } = {}) {
    if (!key) return openOrg({ nav });
    const changed = key !== S.siteKey || S.level !== 'site';
    S.siteKey = key;
    store.set('site', key);
    S.level = 'site';
    if (changed) {
      S.graph = null;
      S.graphVersion = '';
      S.health = null;
      S.selected = selectId;
      S.expanded = new Set();
      S.userMoved = false;
      S.trace = null;
    }
    renderCrumbs();
    if (nav && changed) {
      S.level = 'site';
      navPush();
    }
    await loadSite();
    if (selectId) select(selectId, { center: true });
  }

  async function openOrg({ nav = true } = {}) {
    const was = S.level;
    S.level = 'org';
    if (nav && was !== 'org') navPush();
    S.siteKey = '';
    store.set('site', '');
    S.selected = null;
    S.graph = null;
    S.scene = null;
    clearTimeout(S.healthTimer);
    renderCrumbs();
    if (S.org) renderBoard();
    else showEmpty('<div class="tp-spinner" aria-hidden="true"></div><p>Loading every site…</p>');
    await loadOrg({ quiet: !!S.org });
  }

  // ---------------------------------------------------------------- events
  function wire() {
    const v = S.view;
    // Organization map: hovering a group highlights the hubs it is linked to.
    const hot = (g) => {
      const keys = new Set(g ? (g.dataset.hubs || '').split('|').filter(Boolean) : []);
      $$('.tp-om-hub', v).forEach((h) => h.classList.toggle('is-hot', keys.has(h.dataset.hub)));
      $$('.tp-om-group', v).forEach((x) => x.classList.toggle('is-hot', x === g));
    };
    v.addEventListener('mouseover', (e) => hot(e.target.closest?.('.tp-om-group')));
    v.addEventListener('focusin', (e) => hot(e.target.closest?.('.tp-om-group')));
    v.addEventListener('click', async (e) => {
      if (S.suppressClickUntil && Date.now() < S.suppressClickUntil && e.target.closest?.('.tp-svg')) {
        S.suppressClickUntil = 0;
        return; // the end of a pan, not a click on what was under the pointer
      }
      const row = e.target.closest('tr[data-circuit]');
      if (row && !e.target.closest('button, a')) return select(`circuit:${row.dataset.circuit}`);
      const t = e.target.closest('button, [data-node], [data-expand], [data-site], a');
      if (!t || !v.contains(t)) {
        return;
      }
      if (t.dataset.layer) {
        const id = t.dataset.layer;
        if (S.layers.has(id)) S.layers.delete(id);
        else S.layers.add(id);
        if (!S.layers.size) S.layers.add('physical');
        store.set('layers', [...S.layers]);
        syncToggles();
        if (id === 'l3' && S.layers.has('l3') && S.level === 'site') {
          // v0.10.32: say what the switch does and show the routing tables next to the map.
          S.drawerTab = 'routes';
          S.drawerOpen = true;
          if (S.level !== 'site') S.drawerOrg = true;
          store.set('drawer', true);
          renderDrawer();
          await loadSite({ fresh: false });
          setStatus('Routing on: dotted blue lines are routed links (shared subnets and next hops). The routing tables are in the panel on the right (Routes).');
          return;
        }
        if (S.level === 'site' && S.graph) renderSite();
        return;
      }
      if (t.dataset.zoom) {
        if (t.dataset.zoom === 'in') zoomBy(1.25);
        else if (t.dataset.zoom === 'out') zoomBy(0.8);
        else if (t.dataset.zoom === 'fit') fit();
        else if (t.dataset.zoom === 'aps') toggleAllAps();
        else if (t.dataset.zoom === 'full') toggleFullscreen();
        return;
      }
      if (t.dataset.routeSort) {
        const k = t.dataset.routeSort;
        S.routes.dir = S.routes.sort === k ? -S.routes.dir : 1;
        S.routes.sort = k;
        return renderDrawer();
      }
      if (t.dataset.routeMore) {
        S.routes.limit += 1000;
        return renderDrawer();
      }
      if (t.dataset.routeReload) {
        S.routes.data = null;
        S.routes.at = 0;
        $('.tp-routes', S.view)?.removeAttribute('data-ready');
        renderDrawer();
        return loadRoutes(true);
      }
      if (t.dataset.tab) {
        S.drawerTab = t.dataset.tab;
        if (!S.drawerOpen) S.drawerOpen = true;
        if (S.level !== 'site') S.drawerOrg = true;
        return renderDrawer();
      }
      if (t.dataset.haPlace) {
        // v0.10.30: "Place it here" — a record that is probably the missing unit joins this site (Site mapping)
        t.disabled = true;
        try {
          await api(`${API}/site-map`, {
            method: 'PUT',
            body: JSON.stringify({ device_sites: { [t.dataset.haPlace]: t.dataset.haSite } }),
          });
          S.graphVersion = '';
          await loadSite({ fresh: true });
          setStatus('Placed on this site. The assumed unit is replaced by the real one.');
        } catch (err) {
          t.disabled = false;
          setStatus(`Not saved: ${esc(err.message)}`, 'is-error');
        }
        return;
      }
      if (t.dataset.haAdd || t.dataset.haRemove) {
        const key = t.dataset.haAdd || t.dataset.haRemove;
        t.disabled = true;
        try {
          await api(`${API}/site-map`, {
            method: 'PUT',
            body: JSON.stringify({ ha_partners: { [key]: t.dataset.haAdd ? { state: 'passive' } : null } }),
          });
          S.graphVersion = '';
          await loadSite({ fresh: false });
          setStatus(t.dataset.haAdd ? 'Passive HA partner added to the map.' : 'Confirmed HA partner removed.');
        } catch (err) {
          t.disabled = false;
          setStatus(`Not saved: ${esc(err.message)}`, 'is-error');
        }
        return;
      }
      if (t.dataset.boardview) {
        S.board.view = t.dataset.boardview === 'map' ? 'map' : 'cards';
        store.set('boardView', S.board.view);
        return renderBoard();
      }
      if (t.dataset.filter) {
        S.board.filter = t.dataset.filter;
        store.set('boardFilter', S.board.filter);
        return renderBoard();
      }
      if (t.dataset.focus) {
        S.orgFocus = t.dataset.focus;
        store.set('orgFocus', S.orgFocus);
        S.orgShowAll = false;
        S.orgTrail = [...(S.orgTrail || []).filter((x) => x !== S.orgFocus), S.orgFocus].slice(-6);
        if (S.orgMode !== 'wiring') {
          S.orgMode = 'wiring';
          store.set('orgMode2', S.orgMode);
          syncToggles();
        }
        navPush();
        renderOrgFocus();
        $('.tp-board', S.view)?.scrollTo?.({ top: 0 });
        return;
      }
      if (t.dataset.sitetype) {
        const [key, type] = t.dataset.sitetype.split('|');
        return setSiteType(key, type);
      }
      if (t.dataset.ovl && S.level === 'org') {
        const o = (S.org?.insights?.overlays || []).find((x) => x.id === t.dataset.ovl);
        const target = o?.hubs?.[0] || o?.sites?.[0];
        if (target) {
          S.orgFocus = target;
          S.orgMode = 'wiring';
          store.set('orgMode2', S.orgMode);
          syncToggles();
          navPush();
          return renderOrgFocus();
        }
        return;
      }
      if (t.dataset.mode && S.level === 'org') {
        S.orgMode = ['layers', 'overview', 'wiring'].includes(t.dataset.mode) ? t.dataset.mode : 'layers';
        store.set('orgMode2', S.orgMode);
        S.userMoved = false;
        S.scene = null;
        syncToggles();
        renderBoard();
        navPush(); // after rendering: Wiring picks its focus site while rendering, and Back returns to it
        return;
      }
      if (t.dataset.mode) {
        const was = S.mode;
        S.mode = t.dataset.mode;
        store.set('mode2', S.mode);
        if (was !== S.mode) navPush();
        S.userMoved = false;
        if (was !== S.mode && S.graph?.view === 'overview' && S.mode !== 'overview') {
          S.graphVersion = '';
          await loadSite();
        }
        renderSite({ refit: true });
        if (S.mode === 'wiring' && S.selected) setTimeout(() => centerOn(S.selected), 50);
        return;
      }
      if (t.dataset.stage !== undefined && t.closest('.tp-overview')) {
        S.stage = !t.dataset.stage || S.stage === t.dataset.stage ? null : t.dataset.stage;
        renderOverview();
        if (S.stage) $('.tp-ov-detail', S.view)?.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
        return;
      }
      if (t.dataset.site) return openSite(t.dataset.site);
      if (t.dataset.expand) {
        const id = t.dataset.expand;
        if (S.expanded.has(id)) S.expanded.delete(id);
        else S.expanded.add(id);
        return renderSite();
      }
      if (t.dataset.node) return select(t.dataset.node);
      if (t.dataset.pick) return select(t.dataset.pick, { center: true });
      if (t.dataset.toolkit) {
        const [site, dev] = t.dataset.toolkit.split('|');
        const n = (S.graph?.nodes || []).find((x) => x.id === S.selected);
        await window.MistApp?.openTool('operations');
        return window.MistTools.operations?.openPort?.(site, dev, '', n?.name || '');
      }
      if (t.dataset.finder) {
        await window.MistApp?.openTool('detective');
        const input = document.querySelector('#detectiveQuery');
        if (!input) return;
        input.value = t.dataset.finder;
        const form = document.querySelector('#detectiveSearchForm');
        if (form?.requestSubmit) form.requestSubmit();
        else document.querySelector('#detectiveSearchBtn')?.click();
        return;
      }
      if (t.dataset.traceFrom) {
        S.traceForm = { ...(S.traceForm || {}), from: t.dataset.traceFrom };
        S.drawerTab = 'trace';
        renderDrawer();
        $('.tp-trace [name="to"]', v)?.focus();
        return;
      }
      switch (t.dataset.act) {
        case 'org':
          return openOrg();
        case 'fullscreen':
          return toggleFullscreen();
        case 'picker':
          return openPicker(t);
        case 'health':
          S.healthOn = !S.healthOn;
          store.set('health', S.healthOn);
          syncToggles();
          if (S.healthOn) loadHealth();
          else {
            clearTimeout(S.healthTimer);
            paintHealth();
          }
          return renderDrawer();
        case 'refresh':
          return S.level === 'site' ? loadSite({ fresh: true }) : loadOrg({ fresh: true });
        case 'export':
          return window.MistTools.topoReport?.open({
            siteKey: S.level === 'site' ? S.siteKey : '',
            siteName: S.level === 'site' ? siteName(S.siteKey) : '',
            sites: (S.org?.sites || []).filter((x) => !x.cloud).map((x) => ({ key: x.key, name: x.name, devices: x.devices || 0, fabric: !!x.peers })),
          });
        case 'drawer':
          if (S.level !== 'site') {
            S.drawerOrg = !S.drawerOrg;
            return syncToggles();
          }
          S.drawerOpen = !S.drawerOpen;
          store.set('drawer', S.drawerOpen);
          syncToggles();
          if (S.level === 'site' && !S.userMoved) setTimeout(fit, 220);
          return;
        case 'issues':
          S.drawerTab = 'issues';
          S.drawerOpen = true;
          if (S.level !== 'site') S.drawerOrg = true;
          return renderDrawer();
        case 'org-all-peers':
          S.orgShowAll = true;
          return renderOrgFocus();
        case 'all-site-rows':
          S.allSitesRows = !S.allSitesRows;
          return renderOrgOverview();
        case 'all-remote':
          S.allRemote = !S.allRemote;
          return renderOverview();
        case 'sitemap':
          return openSiteMap();
        case 'trace-show':
          return showTraceOnMap();
        case 'trace-clear':
          S.trace = null;
          renderDrawer();
          return markSelection();
        case 'baseline':
          try {
            await api(`${API}/baseline`, { method: 'POST', body: JSON.stringify({ site: S.siteKey }) });
            return loadSite({ fresh: true });
          } catch (err) {
            return setStatus(`Baseline not saved: ${esc(err.message)}`, 'is-error');
          }
        default:
      }
    });
    v.addEventListener('keydown', (e) => {
      const t = e.target;
      if ((e.key === 'Enter' || e.key === ' ') && t.closest?.('[data-node],[data-expand]') && t.tagName !== 'BUTTON') {
        e.preventDefault();
        t.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      }
    });
    v.addEventListener('submit', (e) => {
      if (e.target.classList.contains('tp-trace')) {
        e.preventDefault();
        runTrace(e.target);
      }
    });
    v.addEventListener('input', (e) => {
      if (e.target.classList.contains('tp-routes-q')) {
        S.routes.q = e.target.value;
        S.routes.limit = 300;
        const box = $('.tp-routes-result', v);
        if (box) box.innerHTML = routesTableMarkup();
        return;
      }
      if (e.target.classList.contains('tp-board-filter')) {
        S.board.text = e.target.value;
        const pos = e.target.selectionStart;
        renderBoard();
        const again = $('.tp-board-filter', v);
        again.focus();
        again.setSelectionRange(pos, pos);
      }
    });
    v.addEventListener('change', (e) => {
      if (e.target.matches?.('[data-focuspick]')) {
        S.orgFocus = e.target.value;
        store.set('orgFocus', S.orgFocus);
        S.orgShowAll = false;
        S.orgTrail = [...(S.orgTrail || []).filter((x) => x !== S.orgFocus), S.orgFocus].slice(-6);
        navPush();
        return renderOrgFocus();
      }
      if (e.target.matches?.('[data-sitetypesel]')) return setSiteType(e.target.dataset.sitetypesel, e.target.value);
      if (e.target.classList.contains('tp-routes-dev') || e.target.classList.contains('tp-routes-proto')) {
        if (e.target.classList.contains('tp-routes-dev')) S.routes.device = e.target.value;
        else S.routes.proto = e.target.value;
        S.routes.limit = 300;
        const box = $('.tp-routes-result', v);
        if (box) box.innerHTML = routesTableMarkup();
        return;
      }
      if (e.target.dataset.act === 'sort') {
        S.board.sort = e.target.value;
        store.set('boardSort', S.board.sort);
        renderBoard();
      }
    });
    // Search box.
    const input = $('#tpSearch', v);
    let active = -1;
    input.addEventListener('input', () => {
      active = -1;
      onSearchInput();
    });
    input.addEventListener('focus', () => input.value.trim() && onSearchInput());
    input.addEventListener('keydown', (e) => {
      const ul = $('#tpSuggest', v);
      const items = ul._items || [];
      if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
        e.preventDefault();
        if (!items.length) return;
        active = (active + (e.key === 'ArrowDown' ? 1 : -1) + items.length) % items.length;
        $$('[data-i]', ul).forEach((li) => li.classList.toggle('is-active', +li.dataset.i === active));
        input.setAttribute('aria-activedescendant', `tpOpt${active}`);
      } else if (e.key === 'Enter') {
        e.preventDefault();
        const pick = items[active >= 0 ? active : 0];
        if (pick) chooseResult(pick);
      } else if (e.key === 'Escape') {
        ul.classList.add('hidden');
        input.blur();
      }
    });
    $('#tpSuggest', v).addEventListener('mousedown', (e) => {
      const li = e.target.closest('[data-i]');
      if (!li) return;
      e.preventDefault();
      chooseResult($('#tpSuggest', v)._items[+li.dataset.i]);
    });
    input.addEventListener('blur', () => setTimeout(() => $('#tpSuggest', v)?.classList.add('hidden'), 120));
    // Pan / zoom on the map.
    const svg = $('.tp-svg', v);
    // Pan (v0.10.32): the map can be grabbed anywhere, devices included (a drag never opens the device);
    // a drag always ends - on release, cancel, lost capture, or a move with no button held (a release
    // outside the window) - so the map no longer stays stuck to the pointer or refuses to move.
    let drag = null;
    const endDrag = () => {
      if (!drag) return;
      if (drag.moved) S.suppressClickUntil = Date.now() + 250;
      try {
        if (svg.hasPointerCapture?.(drag.id)) svg.releasePointerCapture(drag.id);
      } catch {
        /* capture already gone */
      }
      drag = null;
      svg.classList.remove('is-panning');
    };
    svg.addEventListener('pointerdown', (e) => {
      if (e.button !== 0 && e.button !== 1) return;
      if (e.target.closest('[data-expand]')) return;
      endDrag();
      e.preventDefault(); // no text selection / native drag of labels, which cancelled the pan
      // Pointer capture starts only once it is a drag: capturing on press would retarget the click of a
      // device to the map itself.
      drag = { id: e.pointerId, x: e.clientX, y: e.clientY, vx: S.vp.x, vy: S.vp.y, moved: false, onNode: !!e.target.closest('[data-node]') };
    });
    svg.addEventListener('pointermove', (e) => {
      if (drag) {
        if (e.buttons === 0) return endDrag(); // the release happened where we could not see it
        const dx = e.clientX - drag.x;
        const dy = e.clientY - drag.y;
        if (!drag.moved && Math.abs(dx) + Math.abs(dy) <= 4) return;
        if (!drag.moved) {
          drag.moved = true;
          try {
            svg.setPointerCapture(drag.id);
          } catch {
            /* pointer already released */
          }
          svg.classList.add('is-panning');
          $('.tp-tip', v).classList.add('hidden');
        }
        S.vp.x = drag.vx + dx;
        S.vp.y = drag.vy + dy;
        S.userMoved = true;
        applyViewport();
        return;
      }
      tooltip(e);
    });
    svg.addEventListener('pointerup', (e) => {
      if (drag && !drag.moved && !drag.onNode && !e.target.closest('[data-node],[data-expand]')) select(null);
      endDrag();
    });
    svg.addEventListener('pointercancel', endDrag);
    svg.addEventListener('lostpointercapture', endDrag);
    window.addEventListener('blur', endDrag);
    svg.addEventListener('pointerleave', () => $('.tp-tip', v).classList.add('hidden'));
    svg.addEventListener(
      'wheel',
      (e) => {
        e.preventDefault();
        const r = svg.getBoundingClientRect();
        zoomBy(e.deltaY < 0 ? 1.12 : 1 / 1.12, e.clientX - r.left, e.clientY - r.top);
      },
      { passive: false },
    );
    document.addEventListener('keydown', (e) => {
      if ($('#view-topology')?.classList.contains('hidden')) return;
      const typing = /^(INPUT|SELECT|TEXTAREA)$/.test(document.activeElement?.tagName || '');
      if (e.key === '/' && !typing) {
        e.preventDefault();
        $('#tpSearch', v).focus();
      } else if ((e.key === 'F' && e.shiftKey) && !typing) {
        e.preventDefault();
        toggleFullscreen();
      } else if (e.key === 'Escape' && isFullscreen() && !$('.tp-pop') && !$('.tp-modal-layer')) {
        toggleFullscreen(false);
      } else if (e.key === 'Escape' && !typing) {
        closePopovers();
        if (S.selected) select(null, { openDrawer: false });
      } else if (!typing && (S.level === 'site' || (S.orgMode === 'wiring' && S.scene))) {
        if (e.key === 'f') fit();
        else if (e.key === '+' || e.key === '=') zoomBy(1.25);
        else if (e.key === '-') zoomBy(0.8);
        else if (e.key === 'a' || e.key === 'A') toggleAllAps();
        else if (e.key === 'Backspace' && S.level === 'site') openOrg();
      }
    });
    document.addEventListener('click', (e) => {
      if (!e.target.closest('.tp-pop, .tp-picker-btn')) closePopovers();
    });
    window.addEventListener('resize', () => {
      sizeShell();
      if ((S.level === 'site' || S.orgMode === 'wiring') && S.scene && !S.userMoved) fit();
    });
    // Organization wiring: hovering a site lights up its tunnels and the sites at their other end.
    v.addEventListener('mouseover', (e) => {
      if (S.level !== 'org' || S.orgMode !== 'wiring' || !S.scene) return;
      const g = e.target.closest?.('.tp-org-node');
      const key = g?.dataset.site || '';
      if (key === S.orgHot) return;
      S.orgHot = key;
      const near = new Set();
      $$('.tp-link[data-link]', v).forEach((el) => {
        const l = S.scene.links.find((x) => x.key === el.dataset.link);
        const on = !!key && !!l && (l.a_device === key || l.b_device === key);
        if (on) near.add(l.a_device === key ? l.b_device : l.a_device);
        el.classList.toggle('is-near', on);
      });
      $('.tp-svg', v)?.classList.toggle('has-selection', !!key);
      $$('.tp-org-node', v).forEach((el) => {
        el.classList.toggle('is-selected', el.dataset.site === key);
        el.classList.toggle('is-near', near.has(el.dataset.site));
      });
    });
  }

  // ---------------------------------------------------------------- full screen (v0.10.32)
  // The map card covers the whole window (and the browser goes full screen when it allows it). Pop-ups
  // stay on <body>, above it. Esc, the button or Shift+F return.
  function isFullscreen() {
    return !!$('.tp-shell', S.view)?.classList.contains('is-fullscreen');
  }
  function toggleFullscreen(on = !isFullscreen()) {
    const shell = $('.tp-shell', S.view);
    if (!shell) return;
    shell.classList.toggle('is-fullscreen', on);
    document.documentElement.classList.toggle('nw-topo-fullscreen', on);
    $$('.tp-full-btn', S.view).forEach((b) => {
      b.setAttribute('aria-pressed', String(on));
      b.title = on ? 'Leave full screen (Esc)' : 'Full screen (Shift+F)';
      const label = $('.tp-full-label', b);
      if (label) label.textContent = on ? 'Exit full screen' : 'Full screen';
    });
    try {
      if (on && !document.fullscreenElement) document.documentElement.requestFullscreen?.().catch(() => {});
      else if (!on && document.fullscreenElement) document.exitFullscreen?.().catch(() => {});
    } catch {
      /* the window stays as it is; the map still fills it */
    }
    if (!on) sizeShell();
    setTimeout(() => {
      if (S.level === 'site' && !S.userMoved && S.mode === 'wiring') fit();
    }, 120);
  }
  document.addEventListener('fullscreenchange', () => {
    if (!document.fullscreenElement && isFullscreen()) toggleFullscreen(false);
  });

  function toggleAllAps() {
    if (!S.scene) return;
    const all = [...S.scene.apsOf.keys()];
    const anyClosed = all.some((id) => !S.expanded.has(id));
    S.expanded = anyClosed ? new Set(all) : new Set();
    renderSite();
  }

  function tooltip(e) {
    const tip = $('.tp-tip', S.view);
    const linkEl = e.target.closest?.('.tp-link[data-link]');
    if (!linkEl || !S.scene) {
      tip.classList.add('hidden');
      return;
    }
    const l = S.scene.links.find((x) => x.key === linkEl.dataset.link);
    if (!l) return tip.classList.add('hidden');
    const a = S.scene.nodes.get(l.a_device);
    const b = S.scene.nodes.get(l.b_device);
    const h = S.health?.links?.[l.key];
    const kind = LAYER_OF[l.layer] || 'physical';
    const lines = [
      `<strong>${esc(a?.name || '?')}</strong> <span class="tp-mono">${esc(l.a_interface || '')}</span>`,
      `<strong>${esc(b?.name || '?')}</strong> <span class="tp-mono">${esc(l.b_interface || '')}</span>`,
      [kind === 'overlay' ? 'Tunnel' : kind === 'l3' ? 'Routed' : 'Cable', l.label || speedText(l.speed_mbps), l.state && l.state !== 'up' ? l.state : '']
        .filter(Boolean)
        .join(', '),
    ];
    (h?.reasons || []).slice(0, 2).forEach((r) => lines.push(`<span class="tone-${r.state === 'critical' ? 'crit' : 'warn'}">${esc(r.text)}</span>`));
    tip.innerHTML = lines.join('<br>');
    const r = $('.tp-canvas', S.view).getBoundingClientRect();
    tip.style.setProperty('--tp-tip-x', `${Math.round(e.clientX - r.left + 14)}px`);
    tip.style.setProperty('--tp-tip-y', `${Math.round(e.clientY - r.top + 14)}px`);
    tip.classList.remove('hidden');
  }

  // ---------------------------------------------------------------- module API (core.js)
  async function init() {
    shell();
    renderCrumbs();
    renderDrawer();
    showEmpty('<div class="tp-spinner" aria-hidden="true"></div><p>Loading the map…</p>');
    // Sites list and the first map load in parallel.
    const sitesP = loadSites();
    if (S.siteKey) {
      S.level = 'site';
      renderCrumbs();
      await Promise.all([sitesP, loadSite()]);
      renderCrumbs();
    } else {
      await Promise.all([sitesP, loadOrg()]);
    }
    // The history entry that opened Topology now describes what it shows (Back returns here exactly).
    const view = S.level === 'site' && S.siteKey ? { site: S.siteKey, mode: S.mode } : { org: S.orgMode, ...(S.orgMode === 'wiring' && S.orgFocus ? { focus: S.orgFocus } : {}) };
    if (!window.MistApp?.isRestoringView?.()) window.MistApp?.pushView?.(view, { replace: true });
  }

  // The site list answers from cache (it may be stale after a restart); re-read it in the background
  // every few minutes so new or renamed sites appear without reopening the page.
  const SITES_MAX_AGE_MS = 5 * 60 * 1000;
  function refreshSitesIfOld(force = false) {
    if (!force && S.sitesAt && Date.now() - S.sitesAt < SITES_MAX_AGE_MS) return;
    if (S.sitesLoading) return;
    S.sitesLoading = true;
    loadSites()
      .then(() => renderCrumbs())
      .catch(() => {})
      .finally(() => {
        S.sitesLoading = false;
      });
  }

  // Revisit / 30 s tick: ask whether anything changed; redraw only if it did.
  async function refresh(fresh = false) {
    if (!S.view) return init();
    sizeShell();
    refreshSitesIfOld(fresh);
    if (S.level === 'site') await loadSite({ fresh, quiet: !fresh });
    else await loadOrg({ fresh, quiet: !fresh });
  }
  async function autoRefresh() {
    if (!S.view) return;
    refreshSitesIfOld();
    if (S.level === 'site') await loadSite({ quiet: true });
    else await loadOrg({ quiet: true });
  }

  // Called by other pages (Device Finder "Show in Topology"): open the device's site with it selected.
  async function focusDevice({ mac = '', name = '', ip = '', port = '' } = {}) {
    if (!S.view) await init();
    for (const q of [mac, ip, name].filter((x) => x && String(x).trim().length >= 2)) {
      let results = [];
      try {
        results = (await api(`${API}/search?q=${encodeURIComponent(q)}&limit=5`)).results || [];
      } catch {
        results = [];
      }
      const hit = results.find((r) => r.node_id && r.site_key) || results[0];
      if (hit) {
        await chooseResult(hit);
        // v0.10.32: show where it is and the path its traffic takes, with the port highlighted.
        if (hit.node_id && S.level === 'site') await showDevicePath(hit.node_id, port);
        return hit;
      }
    }
    setStatus(`${esc(name || mac || ip)} was not found on the map.`, 'is-warn');
    return null;
  }

  // Back / forward (v0.10.32): the organization, a site and its Overview / Wiring view are history entries.
  function navPush() {
    if (window.MistApp?.isRestoringView?.()) return;
    const view = S.level === 'site' && S.siteKey ? { site: S.siteKey, mode: S.mode } : { org: S.orgMode, ...(S.orgMode === 'wiring' && S.orgFocus ? { focus: S.orgFocus } : {}) };
    window.MistApp?.pushView?.(view);
  }
  async function restoreView(view) {
    if (!S.view) return;
    if (view?.site) {
      if (view.mode && view.mode !== S.mode) {
        S.mode = view.mode;
        store.set('mode2', S.mode);
      }
      if (S.level !== 'site' || S.siteKey !== view.site) await openSite(view.site, { nav: false });
      else if (S.graph?.view === 'overview' && S.mode !== 'overview') {
        S.graphVersion = '';
        await loadSite();
      } else renderSite({ refit: true });
      return;
    }
    if (view?.focus) S.orgFocus = view.focus;
    if (view?.org && view.org !== S.orgMode) {
      S.orgMode = view.org;
      store.set('orgMode2', S.orgMode);
    }
    if (S.level !== 'org') await openOrg({ nav: false });
    else renderBoard();
  }

  window.MistTools.topology = { init, refresh, autoRefresh, focusDevice, restoreView, _state: S };
})();
