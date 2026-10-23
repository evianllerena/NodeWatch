// NodeWatch Security Operations (v0.10.30).
//
// Three renditions of one vendor-neutral SOC — Watch floor, Case desk, Atlas — plus Detections,
// Vulnerabilities, Coverage and Posture. Every number comes from /api/v1/security/soc*, which is built
// only from capability records (security.events / security.exposures / security.incidents): this page
// never names a vendor except the product names the API reports for its sources.
//
// CSP: no inline styles. Bars and meters are SVG (width/height attributes), colours come from classes.

window.MistTools.security = (() => {
  const API = '/api/v1/security';
  const LS = 'nw.soc.';
  const VIEWS = [
    ['watch', 'Watch floor', 'The whole picture at a glance — made for a wall screen.'],
    ['cases', 'Case desk', 'Work the cases NodeWatch correlated, one story at a time.'],
    ['atlas', 'Atlas', 'Where attacks come from, what they hit and where callouts go.'],
  ];
  const TABS = [
    ['detections', 'Detections'],
    ['vulns', 'Vulnerabilities'],
    ['coverage', 'Coverage'],
    ['posture', 'Posture'],
  ];
  const WINDOWS = [
    ['1h', '1 hour'],
    ['6h', '6 hours'],
    ['24h', '24 hours'],
    ['3d', '3 days'],
    ['7d', '7 days'],
  ];
  const STATES = [
    ['new', 'New'],
    ['investigating', 'Investigating'],
    ['contained', 'Contained'],
    ['resolved', 'Resolved'],
    ['dismissed', 'Dismissed'],
  ];
  const OUTCOME = { blocked: 'Blocked', contained: 'Contained', alerted: 'Alerted only', allowed: 'Allowed', unknown: 'Unknown' };
  const SEV = { critical: 'Critical', major: 'High', warning: 'Medium', info: 'Low' };
  const RULE = {
    compromise: 'Compromise suspected',
    lateral: 'Spreading inside',
    breach: 'Got through',
    campaign: 'Campaign',
    wireless: 'Wireless intrusion',
    vendor: 'Raised by your security platform',
  };

  // v0.10.32: plain-language explanations used by the detail pages.
  const KIND_INFO = {
    exploit: ['Someone tried to use a software weakness (often a published CVE) to run code or get access on the target.', 'Patch or upgrade the target, keep the blocking profile on this rule, and if it was not blocked check the target for signs of compromise.'],
    malware: ['A file or download matched known or suspected malware.', 'If it was not blocked, isolate the host, run a full endpoint scan and find where the file came from.'],
    command_control: ['An inside host tried to contact an address known to control infected machines (command-and-control, malware or DNS tunnelling). Even when blocked, the host is likely infected.', 'Find the host (Device Finder), isolate it, scan it with your endpoint tool and reset credentials used on it.'],
    reconnaissance: ['Scanning or probing: someone mapping which addresses and ports answer.', 'Usually nothing to do when it is blocked at the edge. Repeated scans from the inside point at an infected or misused host.'],
    flood: ['A flood of packets or connections meant to overload a device or link.', 'Check the zone-protection / DoS profile thresholds and the affected link utilisation.'],
    web: ['A request to a malicious or phishing web destination.', 'If it was allowed, check the user and host; reset credentials if the page was a phishing login.'],
    data_loss: ['Data matching a sensitive pattern or file type tried to leave.', 'Confirm with the user/owner whether the transfer was legitimate; tighten the data-filtering profile if not.'],
    credential: ['Repeated logins or brute force against a service.', 'Lock or rotate the account, enforce MFA, and block the source if it keeps trying.'],
    wireless: ['A rogue or impersonating access point / SSID near your sites.', 'Locate it with the access points that heard it and remove it, or mark it as a known neighbour.'],
    policy: ['A request your policy refuses or flags, such as a DNS lookup of a proxy / anonymizer (e.g. iCloud Private Relay), grayware, ad-tracking, parked or newly registered domain. Network hygiene, not an attack.', 'No incident response needed. If it is noisy, decide whether the category should be blocked quietly or allowed.'],
    other: ['A detection the source did not classify further.', 'Open it in the source system for details.'],
  };
  const OUTCOME_INFO = {
    blocked: 'The security control stopped it (dropped, reset or blocked).',
    contained: 'The control redirected or quarantined it (for example a DNS sinkhole).',
    alerted: 'The control only reported it: the traffic went through.',
    allowed: 'Nothing stopped it: the traffic went through.',
    unknown: 'The source did not say what happened.',
  };
  const KPI_INFO = {
    detections: ['Every detection', 'All security detections in this window, newest first.'],
    stopped: ['Stopped detections', 'Detections a control blocked or contained (sinkholed, quarantined). The percentage is their share of all detections.'],
    through: ['Detections that got through', 'Attack attempts that reached Reach 3 or further (got through, calling out, spreading inside) and were NOT blocked or contained: the control only alerted, or allowed them.'],
    callout: ['Hosts calling out', 'Inside hosts that tried to reach command-and-control or malware destinations. Proxy, grayware and ad-tracking lookups are not counted. Each host is very likely infected, even when the callout was blocked.'],
    cases: ['Open cases', 'Cases NodeWatch correlated from the detections and that are not resolved or dismissed.'],
    countries: ['Attacking countries', 'Countries named by the source for attacks coming from outside. NodeWatch does not look addresses up: countries appear only when the source reports them.'],
  };
  const PRESSURE_INFO =
    'Pressure says how hard a site is being pushed compared with the others: every detection adds its severity weight (critical 10, high 6, medium 3, low 1) × how far it got (Reach 1 → 1, 2 → 1.5, 3 → 4, 4 → 6, 5 → 8) × √repeats. The most pressed site is 100 and the others are scaled to it, so 50 means half the pressure of the top site.';

  const store = {
    get(k, d) {
      try {
        const v = localStorage.getItem(LS + k);
        return v == null ? d : JSON.parse(v);
      } catch {
        return d;
      }
    },
    set(k, v) {
      try {
        localStorage.setItem(LS + k, JSON.stringify(v));
      } catch {
        /* private window */
      }
    },
  };

  const S = {
    view: store.get('view', 'watch'),
    window: store.get('window', '24h'),
    site: '',
    sample: false,
    data: null,
    loading: false,
    error: '',
    caseId: '',
    caseDetail: null,
    caseFilter: store.get('caseFilter', 'open'),
    caseQuery: '',
    atlasMode: 'in',
    atlasPick: '',
    det: { q: '', kind: '', outcome: '', reach: '', country: '', offset: 0 },
    detData: null,
    vulns: null,
    posture: null,
    wall: store.get('wall', false),
    loadedAt: 0,
  };
  let root = null;
  let initd = false;

  // ---------------------------------------------------------------- helpers
  const esc = nwEscapeHtml; // one shared escaper (core.js)
  const num = (n) => (n == null ? '—' : Number(n).toLocaleString());
  const plural = (n, one, many = `${one}s`) => `${num(n)} ${Number(n) === 1 ? one : many}`;
  const ago = (t) => {
    if (!t) return '';
    const s = Math.max(0, Date.now() / 1000 - t);
    if (s < 60) return 'just now';
    if (s < 3600) return `${Math.round(s / 60)} min ago`;
    if (s < 86400) return `${Math.round(s / 3600)} h ago`;
    return `${Math.round(s / 86400)} d ago`;
  };
  const clock = (t) =>
    t ? new Date(t * 1000).toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }) : '';
  const hhmm = (t) => (t ? new Date(t * 1000).toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' }) : '');
  const product = (src) => S.data?.products?.[src] || src || '';
  const q = (params) => {
    const u = new URLSearchParams();
    Object.entries(params).forEach(([k, v]) => {
      if (v !== '' && v != null && v !== false) u.set(k, v);
    });
    if (S.sample) u.set('sample', 'true');
    return u.toString();
  };
  const api = (path, opts = {}) => nwFetchJSON(path, opts); // shared helper (core.js)
  const reachChip = (r, label) => (r ? `<span class="soc-reach r${r}" title="Reach ${r}: ${esc(label || reachLabel(r))}"><b>${r}</b>${label === false ? '' : esc(label || reachLabel(r))}</span>` : '');
  const reachLabel = (r) => (S.data?.reach_scale || []).find((x) => x.level === r)?.label || '';
  const sevChip = (s) => `<span class="soc-sev s-${esc(s)}">${esc(SEV[s] || s)}</span>`;
  const outChip = (o) => `<span class="soc-out o-${esc(o)}">${esc(OUTCOME[o] || o)}</span>`;
  const meter = (pct, cls = '') =>
    `<svg class="soc-meter ${cls}" viewBox="0 0 100 8" preserveAspectRatio="none" aria-hidden="true"><rect class="soc-meter-bg" x="0" y="0" width="100" height="8" rx="4"/><rect class="soc-meter-fg" x="0" y="0" width="${Math.max(pct > 0 ? 2 : 0, Math.min(100, pct))}" height="8" rx="4"/></svg>`;
  const cc = (code, name) => (code ? `<span class="soc-cc" title="${esc(name || code)}">${esc(code)}</span>` : '');
  const card = (title, body, { eyebrow = '', cls = '', action = '', ui = '' } = {}) =>
    `<section class="soc-card ${cls}"${ui ? ` data-ui="Security Operations › ${esc(ui)}"` : ''}><header class="soc-card-head"><div>${eyebrow ? `<div class="soc-eyebrow">${esc(eyebrow)}</div>` : ''}<h3>${title}</h3></div>${action}</header>${body}</section>`;

  // ---------------------------------------------------------------- load
  async function load({ quiet = false } = {}) {
    if (!root) return;
    if (S.loading) return;
    S.loading = true;
    if (!quiet && !S.data) paint('<div class="soc-loading"><span class="soc-pulse"></span> Reading security detections…</div>');
    try {
      S.data = await api(`${API}/soc?${q({ window: S.window, site: S.site })}`);
      S.error = '';
      S.loadedAt = Date.now();
    } catch (err) {
      S.error = err.message;
    } finally {
      S.loading = false;
    }
    render();
    if (S.view === 'cases' && S.caseId) loadCase(S.caseId, true);
    if (S.view === 'detections') loadDetections(true);
    if (S.view === 'vulns' && !S.vulns) loadVulns();
  }

  async function loadCase(id, quiet = false) {
    S.caseId = id;
    if (!quiet) {
      S.caseDetail = null;
      render();
    }
    try {
      S.caseDetail = await api(`${API}/soc/cases/${encodeURIComponent(id)}?${q({ window: '7d' })}`);
    } catch (err) {
      S.caseDetail = { error: err.message };
    }
    if (S.view === 'cases') render();
  }

  async function loadDetections(quiet = false) {
    const f = S.det;
    try {
      S.detData = await api(
        `${API}/soc/events?${q({ window: S.window, q: f.q, kind: f.kind, outcome: f.outcome, reach: f.reach, country: f.country, site: S.site, through: f.through ? 'true' : '', limit: 100, offset: f.offset })}`,
      );
    } catch (err) {
      S.detData = { error: err.message, rows: [] };
    }
    if (S.view === 'detections') render();
    else if (!quiet) render();
  }

  async function loadVulns() {
    try {
      S.vulns = await api(`${API}/soc/vulnerabilities?${q({ window: S.window === '1h' || S.window === '6h' ? '24h' : S.window })}`);
    } catch (err) {
      S.vulns = { error: err.message };
    }
    if (S.view === 'vulns') render();
  }

  async function loadPosture() {
    try {
      S.posture = await api(`${API}/posture`);
    } catch (err) {
      S.posture = { error: err.message };
    }
    if (S.view === 'posture') render();
  }

  // ---------------------------------------------------------------- frame
  // v0.10.42: a repaint (every data refresh) keeps the page where it was: the scroll position of the page,
  // of the wall screen and of every scrolling panel inside it.
  function scrollState() {
    const out = { page: document.scrollingElement?.scrollTop || 0, root: root.scrollTop, panes: {} };
    const seen = {};
    root.querySelectorAll('*').forEach((el) => {
      if (el.scrollHeight <= el.clientHeight && el.scrollWidth <= el.clientWidth) return;
      const key = `${el.tagName}.${el.className}`;
      seen[key] = (seen[key] || 0) + 1;
      if (el.scrollTop || el.scrollLeft) out.panes[`${key}#${seen[key]}`] = [el.scrollTop, el.scrollLeft];
    });
    return out;
  }
  function restoreScroll(st) {
    const seen = {};
    root.querySelectorAll('*').forEach((el) => {
      if (el.scrollHeight <= el.clientHeight && el.scrollWidth <= el.clientWidth) return;
      const key = `${el.tagName}.${el.className}`;
      seen[key] = (seen[key] || 0) + 1;
      const pos = st.panes[`${key}#${seen[key]}`];
      if (pos) [el.scrollTop, el.scrollLeft] = pos;
    });
    root.scrollTop = st.root;
    if (document.scrollingElement) document.scrollingElement.scrollTop = st.page;
  }
  function paint(html) {
    if (!root) return;
    const st = root.firstElementChild ? scrollState() : null;
    root.innerHTML = html;
    if (st) restoreScroll(st);
  }

  function bar() {
    const d = S.data || {};
    const views = VIEWS.map(([id, label, help]) => `<button type="button" class="${S.view === id ? 'is-on' : ''}" data-view="${id}" title="${esc(help)}">${esc(label)}</button>`).join('');
    const tabs = TABS.map(([id, label]) => `<button type="button" class="${S.view === id ? 'is-on' : ''}" data-view="${id}">${esc(label)}</button>`).join('');
    const sites = d.sites || [];
    const status = S.error
      ? `<span class="soc-status is-error">${esc(S.error)}</span>`
      : d.first_read_pending || d.collecting
        ? `<span class="soc-status"><span class="soc-pulse"></span> Reading detections from ${esc((d.coverage || []).filter((c) => c.connected).map((c) => c.product).join(', ') || 'your sources')}…</span>`
        : d.generated_at
          ? `<span class="soc-status">Updated ${esc(ago(d.generated_at))}${d.last_collect ? ` · sources read ${esc(ago(d.last_collect))}` : ''}</span>`
          : '';
    return `<div class="soc-bar" data-ui="Security Operations › Toolbar">
      <div class="soc-seg soc-views" role="tablist" aria-label="Rendition">${views}</div>
      <div class="soc-seg soc-tabs" role="tablist" aria-label="Data">${tabs}</div>
      <div class="soc-bar-right">
        <label class="soc-field"><span>Window</span><select data-set="window">${WINDOWS.map(([v, l]) => `<option value="${v}"${S.window === v ? ' selected' : ''}>${l}</option>`).join('')}</select></label>
        <label class="soc-field"><span>Site</span><select data-set="site"><option value="">All sites</option>${sites.map((s) => `<option value="${esc(s.key)}"${S.site === s.key ? ' selected' : ''}>${esc(s.name)}</option>`).join('')}</select></label>
        <button type="button" class="soc-btn" data-act="refresh" title="Read the sources again now">Refresh</button>
        <button type="button" class="soc-btn${S.wall ? ' is-on' : ''}" data-act="wall" title="Full screen and dark for a wall screen: stays on this page and refreshes its data every 30 s">${S.wall ? 'Exit wall display' : 'Wall display'}</button>
      </div>
      <div class="soc-bar-status">${status}</div>
    </div>`;
  }

  function sampleBanner() {
    if (!S.sample) return '';
    return `<div class="soc-sample" role="note"><strong>Sample data.</strong> A fictitious organization, so you can try the renditions before a source is connected. Nothing here is from your network. <button type="button" class="soc-link" data-act="leave-sample">Leave the preview</button></div>`;
  }

  function render() {
    if (!root) return;
    const d = S.data;
    root.classList.toggle('soc-wall', S.wall);
    if (d && d.available === false && !S.sample && !['coverage', 'posture'].includes(S.view)) {
      return paint(bar() + emptyState());
    }
    if (!d) return paint(bar() + (S.error ? `<div class="soc-empty"><p><strong>Security Operations could not be loaded.</strong></p><p class="soc-muted">${esc(S.error)}</p><button type="button" class="soc-btn" data-act="refresh">Try again</button></div>` : ''));
    let body = '';
    if (S.view === 'watch') body = watchFloor();
    else if (S.view === 'cases') body = caseDesk();
    else if (S.view === 'atlas') body = atlas();
    else if (S.view === 'detections') body = detections();
    else if (S.view === 'vulns') body = vulns();
    else if (S.view === 'coverage') body = coverageView();
    else if (S.view === 'posture') body = postureView();
    else if (S.view === 'detail') body = detailView();
    paint(bar() + sampleBanner() + firstReadNote() + body);
  }

  function firstReadNote() {
    const d = S.data || {};
    if (S.sample || !d.first_read_pending) return '';
    return `<div class="soc-note"><span class="soc-pulse"></span> First read: NodeWatch is collecting the last 24 hours of detections from ${esc((d.coverage || []).filter((c) => c.connected).map((c) => c.product).join(', '))}. This page fills in by itself.</div>`;
  }

  function emptyState() {
    const cov = S.data?.coverage || [];
    return `<div class="soc-empty soc-welcome">
      <div class="soc-eyebrow">Security Operations</div>
      <h2>No source of security detections is connected yet</h2>
      <p>This page is built from any system that reports threats, malware, attacks, vulnerabilities or incidents. NodeWatch translates each one into the same records, so the views below work the same whichever vendors you use — and keep working when you add or replace one.</p>
      ${cov.length ? `<h4>Systems NodeWatch can read for this page</h4><ul class="soc-covlist">${cov.map((c) => `<li><strong>${esc(c.product)}</strong> <span class="soc-muted">${esc(c.vendor)}</span><span>${c.capabilities.map((x) => `<span class="soc-chip">${esc(x.label)}</span>`).join('')}</span><small class="soc-muted">${esc(c.state_label || '')} · set up in ${esc(c.settings_location)}</small></li>`).join('')}</ul>` : ''}
      <div class="soc-actions"><button type="button" class="soc-btn primary" data-act="sample">Preview with sample data</button><button type="button" class="soc-btn" data-act="connections">Open Settings › Connections</button></div>
    </div>`;
  }

  // ---------------------------------------------------------------- shared pieces
  function kpis() {
    const k = S.data.kpis || {};
    const c = S.data.cases || {};
    const tl = S.data.timeline?.buckets || [];
    const spark = sparkline(tl.map((b) => b.total));
    // v0.10.32: every tile opens what it counts (and says what the number means).
    const tiles = [
      ['detections', 'Detections', num(k.detections), spark, '', `in the last ${esc(WINDOWS.find((w) => w[0] === S.window)?.[1] || S.window)}`],
      ['stopped', 'Stopped', k.stopped_pct == null ? '—' : `${k.stopped_pct}%`, meter(k.stopped_pct || 0, 'm-good'), '', `${num(k.stopped)} blocked or contained`],
      ['through', 'Got through', num(k.through), '', k.through ? 'is-warn' : '', 'Reach 3+ and not stopped'],
      ['callout', 'Hosts calling out', num(k.calling_out_hosts), '', k.calling_out_hosts ? 'is-crit' : '', 'inside hosts contacting attackers'],
      ['cases', 'Open cases', num(c.open), '', c.critical ? 'is-crit' : '', `${num(c.new)} new · ${num(c.critical)} critical`],
      ['countries', 'Attacking countries', num(k.countries), '', '', `${plural(k.attackers || 0, 'attacker address', 'attacker addresses')}`],
    ];
    return `<div class="soc-kpis" data-ui="Security Operations › Headline numbers">${tiles
      .map(([id, label, value, viz, tone, sub]) => `<button type="button" class="soc-kpi ${tone}" data-kpi="${id}" title="${esc(KPI_INFO[id]?.[1] || '')}"><span class="soc-kpi-label">${esc(label)} <span class="soc-kpi-go" aria-hidden="true">›</span></span><strong>${value}</strong>${viz}<small>${sub}</small></button>`)
      .join('')}</div>`;
  }

  function sparkline(vals) {
    if (!vals.length) return '';
    const max = Math.max(1, ...vals);
    const w = 100;
    const h = 24;
    const step = w / Math.max(1, vals.length - 1);
    const pts = vals.map((v, i) => `${(i * step).toFixed(1)},${(h - 2 - (v / max) * (h - 4)).toFixed(1)}`).join(' ');
    return `<svg class="soc-spark" viewBox="0 0 ${w} ${h}" preserveAspectRatio="none" aria-hidden="true"><polyline points="${pts}"/></svg>`;
  }

  function reachLadder(compact = false) {
    const rows = S.data.reach || [];
    const max = Math.max(1, ...rows.map((r) => r.count));
    return `<ol class="soc-ladder${compact ? ' is-compact' : ''}">${rows
      .map(
        (r) => `<li class="r${r.level}"><button type="button" data-reach="${r.level}" title="Show these detections">
          <span class="soc-ladder-step">${r.level}</span>
          <span class="soc-ladder-text"><strong>${esc(r.label)}</strong>${compact ? '' : `<small>${esc(r.help)}</small>`}</span>
          <span class="soc-ladder-bar"><svg viewBox="0 0 100 10" preserveAspectRatio="none" aria-hidden="true"><rect class="soc-ladder-fill" x="0" y="0" width="${r.count ? Math.max(1.5, (100 * r.count) / max) : 0}" height="10" rx="3"/></svg></span>
          <span class="soc-ladder-n">${num(r.count)}</span></button></li>`,
      )
      .join('')}</ol>`;
  }

  function timeline(tl, { height = 150, compact = false } = {}) {
    const b = tl?.buckets || [];
    if (!b.length) return '<p class="soc-muted">No detections in this window.</p>';
    const W = 600;
    const H = height;
    const pad = { l: 34, r: 6, t: 8, b: 20 };
    const max = Math.max(1, ...b.map((x) => x.total));
    const bw = (W - pad.l - pad.r) / b.length;
    const y = (v) => pad.t + (H - pad.t - pad.b) * (1 - v / max);
    let bars = '';
    b.forEach((x, i) => {
      let acc = 0;
      const x0 = pad.l + i * bw + 1;
      [1, 2, 3, 4, 5].forEach((r) => {
        const v = x.reach[r] || x.reach[String(r)] || 0;
        if (!v) return;
        const y1 = y(acc + v);
        const y0 = y(acc);
        bars += `<rect class="soc-tl-r${r}" x="${x0.toFixed(1)}" y="${y1.toFixed(1)}" width="${Math.max(1, bw - 2).toFixed(1)}" height="${Math.max(0.8, y0 - y1 - 1).toFixed(1)}" rx="1.5"><title>${esc(hhmm(x.t))} · ${esc(reachLabel(r))}: ${num(v)}</title></rect>`;
        acc += v;
      });
      bars += `<rect class="soc-tl-hit" x="${x0.toFixed(1)}" y="${pad.t}" width="${bw.toFixed(1)}" height="${H - pad.t - pad.b}"><title>${esc(clock(x.t))}: ${num(x.total)} detections</title></rect>`;
    });
    const ticks = [0, 0.5, 1].map((f) => `<g class="soc-tl-grid"><line x1="${pad.l}" x2="${W - pad.r}" y1="${y(max * f).toFixed(1)}" y2="${y(max * f).toFixed(1)}"/><text x="${pad.l - 6}" y="${(y(max * f) + 4).toFixed(1)}" text-anchor="end">${num(Math.round(max * f))}</text></g>`).join('');
    const labels = [0, Math.floor(b.length / 2), b.length - 1].map((i, j) => `<text class="soc-tl-x" x="${(j === 0 ? pad.l : j === 2 ? W - pad.r : pad.l + i * bw + bw / 2).toFixed(1)}" y="${H - 4}" text-anchor="${['start', 'middle', 'end'][j]}">${esc(S.window === '3d' || S.window === '7d' ? clock(b[i].t) : hhmm(b[i].t))}</text>`).join('');
    const legend = compact ? '' : `<div class="soc-legend">${[1, 2, 3, 4, 5].map((r) => `<span><i class="soc-key r${r}"></i>${esc(reachLabel(r))}</span>`).join('')}</div>`;
    return `<svg class="soc-tl" viewBox="0 0 ${W} ${H}" preserveAspectRatio="none" role="img" aria-label="Detections over time by reach">${ticks}${bars}${labels}</svg>${legend}`;
  }

  // Origins map: every country NodeWatch knows is a faint point at its centre (the world's shape emerges from
  // them); countries with detections become rings sized by volume and coloured by how far they got.
  function originMap({ height = 300, mode = S.atlasMode, interactive = true } = {}) {
    const W = 1000;
    const H = 470;
    const lat0 = 78;
    const lat1 = -58;
    const px = (lon) => ((lon + 180) / 360) * W;
    const py = (lat) => ((lat0 - lat) / (lat0 - lat1)) * H;
    const rows = (mode === 'out' ? S.data.callouts : mode === 'dest' ? S.data.destinations : S.data.countries) || [];
    const max = Math.max(1, ...rows.map((r) => r.events));
    let g = '';
    for (let lon = -150; lon <= 150; lon += 30) g += `<line class="soc-grat" x1="${px(lon)}" x2="${px(lon)}" y1="0" y2="${H}"/>`;
    for (let lat = -30; lat <= 60; lat += 30) g += `<line class="soc-grat${lat === 0 ? ' is-eq' : ''}" x1="0" x2="${W}" y1="${py(lat)}" y2="${py(lat)}"/>`;
    const dots = (S.data.world || []).map(([, lat, lon]) => `<circle class="soc-wdot" cx="${px(lon).toFixed(1)}" cy="${py(lat).toFixed(1)}" r="3.2"/>`).join('');
    const regions = [
      ['North America', -100, 58],
      ['South America', -60, -42],
      ['Europe', 12, 66],
      ['Africa', 18, -24],
      ['Asia', 95, 58],
      ['Oceania', 140, -40],
    ]
      .map(([t, lon, lat]) => `<text class="soc-region" x="${px(lon)}" y="${py(lat)}" text-anchor="middle">${esc(t)}</text>`)
      .join('');
    const sorted = [...rows].filter((r) => r.lat != null).sort((a, b) => b.events - a.events);
    const marks = sorted
      .map((r) => {
        const rad = 6 + 26 * Math.sqrt(r.events / max);
        const pick = S.atlasPick === r.code ? ' is-picked' : '';
        return `<g class="soc-orig r${Math.max(1, r.reach || 1)}${pick}"${interactive ? ` data-country="${esc(r.code)}" tabindex="0" role="button"` : ''}><circle class="soc-orig-halo" cx="${px(r.lon).toFixed(1)}" cy="${py(r.lat).toFixed(1)}" r="${(rad + 6).toFixed(1)}"/><circle class="soc-orig-dot" cx="${px(r.lon).toFixed(1)}" cy="${py(r.lat).toFixed(1)}" r="${rad.toFixed(1)}"/>${rad > 13 ? `<text x="${px(r.lon).toFixed(1)}" y="${(py(r.lat) + 4).toFixed(1)}" text-anchor="middle">${esc(r.code)}</text>` : ''}<title>${esc(r.name)}: ${num(r.events)} ${mode === 'out' ? 'callouts' : 'detections'}, ${num(r.through)} got through</title></g>`;
      })
      .join('');
    return `<svg class="soc-map" viewBox="0 0 ${W} ${H}" preserveAspectRatio="xMidYMid meet" role="img" aria-label="${mode === 'out' ? 'Countries inside hosts called out to' : 'Countries attacks came from'}" data-h="${height}"><rect class="soc-map-bg" x="0" y="0" width="${W}" height="${H}" rx="14"/>${g}${dots}${regions}${marks}</svg>`;
  }

  function rankList(rows, { label = (r) => esc(r.label), sub = () => '', key = 'events', pick = null, empty = 'Nothing in this window.' } = {}) {
    if (!rows?.length) return `<p class="soc-muted">${esc(empty)}</p>`;
    const max = Math.max(1, ...rows.map((r) => r[key] || 0));
    return `<ul class="soc-rank">${rows
      .map((r) => `<li${pick ? ` ${pick(r)}` : ''}><div class="soc-rank-main"><span class="soc-rank-label">${label(r)}</span><span class="soc-rank-n">${num(r[key])}</span></div>${meter((100 * (r[key] || 0)) / max, `r${Math.max(1, r.reach || 1)}`)}<small>${sub(r)}</small></li>`)
      .join('')}</ul>`;
  }

  function caseCard(c, compact = false) {
    return `<button type="button" class="soc-case sev-${esc(c.severity)}${S.caseId === c.id ? ' is-on' : ''}" data-case="${esc(c.id)}">
      <span class="soc-score" title="Case score">${num(c.score)}</span>
      <span class="soc-case-body"><strong>${esc(c.title)}</strong><small>${esc(c.summary || '')}</small>
      <span class="soc-case-meta">${reachChip(c.reach, c.reach_label)}<span class="soc-chip">${esc(RULE[c.rule] || c.rule)}</span>${c.site ? `<span class="soc-chip soc-chip-plain">${esc(c.site)}</span>` : ''}${compact ? '' : `<span class="soc-chip soc-chip-plain st-${esc(c.state)}">${esc(STATES.find((s) => s[0] === c.state)?.[1] || c.state)}</span>`}${c.reopened ? '<span class="soc-chip is-warn">Reopened</span>' : ''}<span class="soc-muted">${esc(ago(c.last_seen))}</span></span></span></button>`;
  }

  function feed(rows, n = 14) {
    if (!rows?.length) return '<p class="soc-muted">No detections in this window.</p>';
    return `<ul class="soc-feed">${rows
      .slice(0, n)
      .map(
        (e) => `<li class="r${e.reach}" data-event="${esc(e.key)}" tabindex="0" role="button" title="Open this detection"><time>${esc(hhmm(e.t))}</time>${reachChip(e.reach, false)}<span class="soc-feed-main"><strong>${esc(e.name || e.kind_label)}</strong><small>${e.attacker ? `${cc(e.country, e.country_name)} ${esc(e.attacker)} → ` : ''}${esc(e.target || e.dst || '')}${e.site ? ` · ${esc(e.site)}` : ''}${e.sensor ? ` · seen by ${esc(e.sensor)}` : ''}</small></span>${outChip(e.outcome)}</li>`,
      )
      .join('')}</ul>`;
  }

  // ---------------------------------------------------------------- rendition A: Watch floor
  function watchFloor() {
    const d = S.data;
    const open = (d.cases?.items || []).filter((c) => !['resolved', 'dismissed'].includes(c.state)).slice(0, 6);
    return `<div class="soc-watch">
      ${kpis()}
      <div class="soc-grid g-2-3">
        ${card('How far attacks got', reachLadder(), { eyebrow: 'NodeWatch Reach', ui: 'Reach ladder', action: '<span class="soc-muted soc-card-note">Click a step to list its detections</span>' })}
        ${card('Detections over time', timeline(d.timeline), { eyebrow: 'By reach', ui: 'Timeline' })}
      </div>
      <div class="soc-grid g-3-2">
        ${originsCard(d)}
        ${card(`Open cases <small class="soc-muted">${num(d.cases?.open)}</small>`, open.length ? `<div class="soc-cases">${open.map((c) => caseCard(c, true)).join('')}</div>` : '<p class="soc-muted">No open cases. NodeWatch opens one when an attack gets through, a host calls out, something spreads inside, or one attacker targets several systems.</p>', { eyebrow: 'Correlated by NodeWatch', ui: 'Open cases', action: '<button type="button" class="soc-link" data-view="cases">Case desk</button>' })}
      </div>
      <div class="soc-grid g-3">
        ${card('Latest detections', feed(d.feed, 12), { eyebrow: 'Live', ui: 'Live feed', action: '<button type="button" class="soc-link" data-view="detections">All detections</button>' })}
        ${card('Sites under pressure', rankList(d.pressure, { key: 'pressure', pick: (r) => `data-sitedetail="${esc(r.key)}" tabindex="0" role="button" title="What is hitting ${esc(r.label)}"`, sub: (r) => `${plural(r.events, 'detection')}${r.through ? ` · ${num(r.through)} got through` : ''}`, empty: 'No detection is tied to a site yet.' }), { eyebrow: 'Pressure (most pressed = 100)', ui: 'Site pressure', action: '<button type="button" class="soc-link" data-act="pressure-help">What is pressure?</button>' })}
        ${card('What is being tried', rankList((d.signatures || []).slice(0, 8), { pick: (r) => `data-threat="${esc(r.key)}" tabindex="0" role="button" title="What this threat is and what it hit"`, label: (r) => `${esc(r.label)}${(r.cves || []).length ? ` <small class="soc-mono">${esc(r.cves.join(', '))}</small>` : ''}`, sub: (r) => `${(r.kinds || []).map((k) => esc(k.label)).join(', ')}${r.through ? ` · <b>${num(r.through)} past the door</b>` : ''}` }), { eyebrow: 'Top threats', ui: 'Top threats', action: '<span class="soc-muted soc-card-note">Click one for details</span>' })}
      </div>
    </div>`;
  }

  // ---------------------------------------------------------------- rendition B: Case desk
  function caseDesk() {
    const items = S.data.cases?.items || [];
    const f = S.caseFilter;
    const needle = S.caseQuery.trim().toLowerCase();
    const shown = items.filter((c) => (f === 'all' ? true : f === 'open' ? !['resolved', 'dismissed'].includes(c.state) : c.state === f)).filter((c) => !needle || `${c.title} ${c.summary} ${c.site} ${c.id}`.toLowerCase().includes(needle));
    if (!S.caseId && shown[0]) {
      S.caseId = shown[0].id;
      loadCase(S.caseId, true);
    }
    const filters = [['open', 'Open'], ...STATES, ['all', 'All']]
      .map(([id, l]) => `<button type="button" class="${f === id ? 'is-on' : ''}" data-casefilter="${id}">${esc(l)} <small>${id === 'all' ? items.length : id === 'open' ? items.filter((c) => !['resolved', 'dismissed'].includes(c.state)).length : items.filter((c) => c.state === id).length}</small></button>`)
      .join('');
    return `<div class="soc-desk">
      <aside class="soc-queue" data-ui="Security Operations › Case queue">
        <div class="soc-seg soc-seg-wrap">${filters}</div>
        <input class="soc-input" type="search" placeholder="Find a case: host, site, attacker…" value="${esc(S.caseQuery)}" data-casequery>
        <div class="soc-cases">${shown.map((c) => caseCard(c)).join('') || '<p class="soc-muted">No case matches.</p>'}</div>
      </aside>
      <section class="soc-story" data-ui="Security Operations › Case story">${caseStory()}</section>
    </div>`;
  }

  function caseStory() {
    const c = S.caseDetail;
    if (!S.caseId) return '<div class="soc-empty"><p>Select a case.</p></div>';
    if (!c) return '<div class="soc-loading"><span class="soc-pulse"></span> Opening the case…</div>';
    if (c.error) return `<div class="soc-empty"><p>${esc(c.error)}</p></div>`;
    const sp = c.score_parts || {};
    const reachSteps = [1, 2, 3, 4, 5]
      .map((r) => `<li class="r${r}${r <= c.reach ? ' is-reached' : ''}${r === c.reach ? ' is-top' : ''}"><b>${r}</b><span>${esc(reachLabel(r))}</span></li>`)
      .join('');
    const ent = (title, rows, fmt) => (rows?.length ? `<div class="soc-ent"><h4>${esc(title)}</h4><ul>${rows.map(fmt).join('')}</ul></div>` : '');
    const stateSel = `<select data-casestate="${esc(c.id)}">${STATES.map(([v, l]) => `<option value="${v}"${c.state === v ? ' selected' : ''}>${l}</option>`).join('')}</select>`;
    const scoreRows = sp.reach_points != null
      ? `<ul class="soc-scoreparts"><li><span>How far it got (Reach ${sp.reach})</span><b>${sp.reach_points}</b></li><li><span>Worst severity (${esc(SEV[sp.severity] || sp.severity)})</span><b>${sp.severity_points >= 0 ? '+' : ''}${sp.severity_points}</b></li><li><span>Volume (${num(sp.volume)})</span><b>+${sp.volume_points}</b></li>${sp.unstopped_points ? `<li><span>Furthest step not stopped</span><b>+${sp.unstopped_points}</b></li>` : ''}</ul>`
      : '';
    return `<article class="soc-casefile sev-${esc(c.severity)}">
      <header class="soc-casehead">
        <div class="soc-casehead-main"><div class="soc-eyebrow">${esc(c.id)} · ${esc(RULE[c.rule] || c.rule)}${c.sources?.length ? ` · from ${esc(c.sources.map(product).join(', '))}` : ''}</div><h2>${esc(c.title)}</h2><p>${esc(c.summary || '')}${c.users?.length ? ` · user ${esc(c.users.join(', '))}` : ''}</p>
          <p class="soc-muted">First seen ${esc(clock(c.first_seen))} · last ${esc(clock(c.last_seen))} (${esc(ago(c.last_seen))})${c.site ? ` · ${esc(c.site)}` : ''}</p></div>
        <div class="soc-casescore"><span class="soc-score big">${num(c.score)}</span>${sevChip(c.severity)}</div>
      </header>
      <div class="soc-casecontrols"><label>State ${stateSel}</label><label>Owner <input class="soc-input" data-caseowner="${esc(c.id)}" value="${esc(c.owner || '')}" placeholder="Unassigned" maxlength="120"></label>${c.console_url ? `<a class="soc-btn" href="${esc(c.console_url)}" target="_blank" rel="noopener noreferrer">Open in ${esc(product(c.sources?.[0]))}</a>` : ''}</div>
      ${c.reach ? `<ol class="soc-reachpath">${reachSteps}</ol>` : ''}
      <div class="soc-grid g-2-1 tight">
        <div>
          ${c.recommended?.length ? `<h4 class="soc-h4">What to do</h4><ol class="soc-todo">${c.recommended.map((t) => `<li>${esc(t)}</li>`).join('')}</ol>` : ''}
          <h4 class="soc-h4">Activity</h4>${timeline(c.timeline, { height: 110, compact: true })}
        </div>
        <div><h4 class="soc-h4">Why it scores ${num(c.score)}</h4>${scoreRows}</div>
      </div>
      <div class="soc-ents">
        ${ent('Targets', c.targets, (t) => `<li><strong>${esc(t.name || t.ip)}</strong>${t.site_name ? ` <small>${esc(t.site_name)}</small>` : ''}<span class="soc-entacts">${t.ip ? `<button type="button" class="soc-link" data-finder="${esc(t.ip)}">Device Finder</button>` : ''}${t.managed ? `<button type="button" class="soc-link" data-topo="${esc(t.name)}" data-topo-ip="${esc(t.ip || '')}">Topology</button>` : ''}</span></li>`)}
        ${ent(c.rule === 'compromise' ? 'Destinations' : 'Attackers', c.attackers, (a) => `<li>${cc(a.country, a.country_name)} <span class="soc-mono">${esc(a.ip)}</span>${a.country_name ? ` <small>${esc(a.country_name)}</small>` : ''}${a.inside ? ' <small>(inside)</small>' : ''}</li>`)}
        ${ent('Threats', c.signatures, (s) => `<li>${esc(s)}</li>`)}
        ${ent('Vulnerabilities', c.cves, (v) => `<li class="soc-mono">${esc(v)}</li>`)}
        ${ent('Seen by', c.sensors, (s) => `<li>${esc(s)}</li>`)}
        ${ent('Policy rules', c.rules, (s) => `<li class="soc-mono">${esc(s)}</li>`)}
      </div>
      <h4 class="soc-h4">Notes</h4>
      <div class="soc-notes">${(c.notes || []).map((n) => `<div class="soc-noteitem"><small>${esc(n.by)} · ${esc(clock(n.at))}</small><p>${esc(n.text)}</p></div>`).join('') || '<p class="soc-muted">No notes yet.</p>'}
        <form class="soc-noteform" data-noteform="${esc(c.id)}"><textarea class="soc-input" name="note" rows="2" maxlength="2000" placeholder="What did you check or decide?"></textarea><button class="soc-btn" type="submit">Add note</button></form>
        ${(c.history || []).length ? `<details class="soc-history"><summary>History</summary><ul>${c.history.map((h) => `<li><small>${esc(clock(h.at))} · ${esc(h.by)}</small> ${esc(h.what)}</li>`).join('')}</ul></details>` : ''}
      </div>
      <h4 class="soc-h4">Detections <small class="soc-muted">${num(c.events)}</small>${(c.events_list || []).length > 20 ? ` <button type="button" class="soc-link" data-caseevents="${esc(c.rule === 'wireless' ? '' : c.subject || '')}"${c.rule === 'wireless' ? ` data-casesite="${esc(c.subject || '')}"` : ''}>See all in Detections</button>` : ''}</h4>
      ${eventTable(c.events_list || [], 20)}
      <p class="soc-muted soc-fine">Case state, owner and notes are kept on this computer for your team's triage; nothing is changed in ${esc((c.sources || []).map(product).join(', ') || 'the source system')}.</p>
    </article>`;
  }

  function eventTable(rows, limit = 100) {
    if (!rows.length) return '<p class="soc-muted">No detections.</p>';
    return `<div class="soc-tablewrap"><table class="soc-table"><thead><tr><th>Time</th><th>Reach</th><th>Threat</th><th>From</th><th>To</th><th>Site · seen by</th><th>Result</th></tr></thead><tbody>${rows
      .slice(0, limit)
      .map(
        (e) => `<tr class="r${e.reach} soc-row-link" data-event="${esc(e.key)}" tabindex="0" title="Open this detection"><td class="soc-mono">${esc(clock(e.t))}</td><td>${reachChip(e.reach, false)}</td><td><strong>${esc(e.name || e.kind_label)}</strong><br><small class="soc-muted">${esc(e.kind_label)}${e.cves?.length ? ` · ${esc(e.cves.join(', '))}` : ''}${e.count > 1 ? ` · ×${num(e.count)}` : ''}</small></td><td>${cc(e.country, e.country_name)} <span class="soc-mono">${esc(e.src || '')}</span>${e.user ? `<br><small>${esc(e.user)}</small>` : ''}</td><td>${e.target && e.target !== e.dst ? `<strong>${esc(e.target)}</strong><br>` : ''}<span class="soc-mono">${esc(e.dst || '')}${e.dst_port ? `:${esc(e.dst_port)}` : ''}</span>${e.host ? `<br><small>${esc(e.host)}</small>` : ''}</td><td>${esc(e.site || '')}${e.sensor ? `<br><small class="soc-muted">${esc(e.sensor)}</small>` : ''}</td><td>${outChip(e.outcome)}${e.rule ? `<br><small class="soc-muted soc-mono">${esc(e.rule)}</small>` : ''}</td></tr>`,
      )
      .join('')}</tbody></table></div>`;
  }

  // ---------------------------------------------------------------- rendition C: Atlas
  function atlas() {
    const d = S.data;
    const rows = (S.atlasMode === 'out' ? d.callouts : S.atlasMode === 'dest' ? d.destinations : d.countries) || [];
    const pick = rows.find((r) => r.code === S.atlasPick) || rows[0];
    const modeSeg = `<div class="soc-seg"><button type="button" class="${S.atlasMode === 'in' ? 'is-on' : ''}" data-atlas="in">Attacks coming in</button><button type="button" class="${S.atlasMode === 'out' ? 'is-on' : ''}" data-atlas="out">Callouts going out</button><button type="button" class="${S.atlasMode === 'dest' ? 'is-on' : ''}" data-atlas="dest">All flagged traffic out</button></div>`;
    const detail = pick
      ? `<div class="soc-atlas-detail"><div class="soc-eyebrow">${esc(pick.region || '')}</div><h3>${cc(pick.code, pick.name)} ${esc(pick.name)}</h3>
        <dl class="soc-dl"><div><dt>${S.atlasMode === 'out' ? 'Callouts' : 'Detections'}</dt><dd>${num(pick.events)}</dd></div><div><dt>Stopped</dt><dd>${num(pick.stopped)}</dd></div><div><dt>Got through</dt><dd>${num(pick.through)}</dd></div><div><dt>${S.atlasMode === 'out' ? 'Destinations' : 'Attacker addresses'}</dt><dd>${num(pick.attackers)}</dd></div><div><dt>Furthest</dt><dd>${reachChip(pick.reach)}</dd></div><div><dt>Last seen</dt><dd>${esc(ago(pick.last_seen))}</dd></div></dl>
        ${pick.kinds?.length ? `<h4 class="soc-h4">What</h4><p>${pick.kinds.map((k) => `<span class="soc-chip">${esc(k.label)} ${num(k.count)}</span>`).join(' ')}</p>` : ''}
        ${pick.targets?.length ? `<h4 class="soc-h4">${S.atlasMode === 'out' ? 'Inside hosts calling' : 'Targets'}</h4><ul class="soc-mini">${pick.targets.map((t) => `<li><span>${esc(t.name)}</span><b>${num(t.count)}</b></li>`).join('')}</ul>` : ''}
        ${pick.sites?.length ? `<h4 class="soc-h4">Sites</h4><ul class="soc-mini">${pick.sites.map((t) => `<li><span>${esc(t.name)}</span><b>${num(t.count)}</b></li>`).join('')}</ul>` : ''}
        ${pick.sensors?.length ? `<h4 class="soc-h4">Seen by</h4><ul class="soc-mini">${pick.sensors.map((t) => `<li><span>${esc(t.name)}</span><b>${num(t.count)}</b></li>`).join('')}</ul>` : ''}
        <button type="button" class="soc-btn" data-countrylist="${esc(pick.code)}">List these detections</button></div>`
      : `<p class="soc-muted">${S.atlasMode === 'out' ? 'No inside host called out to a known country in this window.' : S.atlasMode === 'dest' ? 'No flagged outbound traffic names a country in this window.' : 'No detection names a source country in this window. Countries come from the source system; NodeWatch does not look addresses up.'}</p>`;
    const table = rows.length
      ? `<table class="soc-table soc-countries"><thead><tr><th>Country</th><th>${S.atlasMode === 'out' ? 'Callouts' : 'Detections'}</th><th>Stopped vs through</th><th>Furthest</th><th>Top target</th><th>Last</th></tr></thead><tbody>${rows
          .map((r) => {
            const tot = Math.max(1, r.events);
            return `<tr data-country="${esc(r.code)}" class="${S.atlasPick === r.code ? 'is-on' : ''}"><td>${cc(r.code, r.name)} ${esc(r.name)}</td><td>${num(r.events)}</td><td><svg class="soc-split" viewBox="0 0 100 8" preserveAspectRatio="none" aria-label="${num(r.stopped)} stopped, ${num(r.through)} got through"><rect class="soc-split-stop" x="0" y="0" width="${(100 * r.stopped) / tot}" height="8"/><rect class="soc-split-thru" x="${(100 * r.stopped) / tot}" y="0" width="${(100 * r.through) / tot}" height="8"/></svg></td><td>${reachChip(r.reach)}</td><td>${esc(r.targets?.[0]?.name || '')}</td><td>${esc(ago(r.last_seen))}</td></tr>`;
          })
          .join('')}</tbody></table>`
      : '';
    return `<div class="soc-atlas">
      <div class="soc-grid g-atlas">
        <div class="soc-stack">
          ${card(S.atlasMode === 'out' ? 'Where inside hosts call out to' : S.atlasMode === 'dest' ? 'Where flagged outbound traffic went' : 'Where attacks come from', originMap({ height: 460 }), { eyebrow: 'Atlas', ui: 'Atlas map', action: modeSeg })}
          ${card('Countries', table || '<p class="soc-muted">Nothing to rank.</p>', { eyebrow: 'Ranked by pressure · click a row', ui: 'Atlas countries' })}
        </div>
        <div class="soc-stack">
          ${card('Country', detail, { eyebrow: 'Selected', ui: 'Atlas country' })}
          ${card('Most targeted', rankList((S.data.targets || []).slice(0, 8), { sub: (r) => `${esc(r.site || '')}${r.through ? ` · <b>${num(r.through)} past the door</b>` : ''}` }), { eyebrow: 'Your systems', ui: 'Atlas targets' })}
          ${card('Busiest attackers', rankList((S.data.attackers || []).slice(0, 8), { label: (r) => `${cc(r.country, r.country_name)} <span class="soc-mono">${esc(r.label)}</span>`, sub: (r) => (r.kinds || []).map((k) => esc(k.label)).join(', ') }), { eyebrow: 'Outside addresses', ui: 'Atlas attackers' })}
        </div>
      </div>
    </div>`;
  }

  // ---------------------------------------------------------------- Detections
  function detections() {
    const f = S.det;
    const dd = S.detData;
    if (!dd) loadDetections(true);
    const kinds = (S.data.kinds || []).map((k) => `<option value="${esc(k.kind)}"${f.kind === k.kind ? ' selected' : ''}>${esc(k.label)} (${num(k.count)})</option>`).join('');
    const countries = (S.data.countries || []).map((c) => `<option value="${esc(c.code)}"${f.country === c.code ? ' selected' : ''}>${esc(c.name)}</option>`).join('');
    const total = dd?.total || 0;
    return `<div class="soc-det">
      ${f.note ? `<div class="soc-note soc-kpi-note"><strong>${esc(f.note[0])}.</strong> ${esc(f.note[1])}</div>` : ''}
      ${f.through ? '<div class="soc-note">Showing only detections that got through (not blocked or contained). <button type="button" class="soc-link" data-act="clear-det">Show all</button></div>' : ''}
      <form class="soc-filters" data-detform data-ui="Security Operations › Detection filters">
        <input class="soc-input" type="search" name="q" value="${esc(f.q)}" placeholder="Search: address, host, user, threat, CVE, rule…">
        <select name="kind"><option value="">Every kind</option>${kinds}</select>
        <select name="reach"><option value="">Any reach</option>${[1, 2, 3, 4, 5].map((r) => `<option value="${r}"${String(f.reach) === String(r) ? ' selected' : ''}>${r} · ${esc(reachLabel(r))}</option>`).join('')}</select>
        <select name="outcome"><option value="">Any result</option>${Object.entries(OUTCOME).map(([k, v]) => `<option value="${k}"${f.outcome === k ? ' selected' : ''}>${esc(v)}</option>`).join('')}</select>
        <select name="country"><option value="">Any country</option>${countries}</select>
        <button class="soc-btn" type="submit">Apply</button>${f.q || f.kind || f.reach || f.outcome || f.country ? '<button class="soc-link" type="button" data-act="clear-det">Clear</button>' : ''}
      </form>
      ${dd?.error ? `<div class="soc-note is-error">${esc(dd.error)}</div>` : ''}
      <div class="soc-det-head"><span>${dd ? `${plural(total, 'detection')}` : 'Loading…'}</span>${total > 100 ? `<span class="soc-pager"><button type="button" class="soc-btn" data-page="-1"${f.offset <= 0 ? ' disabled' : ''}>Newer</button><span>${num(f.offset + 1)}–${num(Math.min(total, f.offset + 100))}</span><button type="button" class="soc-btn" data-page="1"${f.offset + 100 >= total ? ' disabled' : ''}>Older</button></span>` : ''}</div>
      ${dd ? eventTable(dd.rows || [], 100) : ''}
    </div>`;
  }

  // ---------------------------------------------------------------- Vulnerabilities
  function vulns() {
    const v = S.vulns;
    if (!v) {
      loadVulns();
      return '<div class="soc-loading"><span class="soc-pulse"></span> Gathering vulnerabilities…</div>';
    }
    if (v.error) return `<div class="soc-note is-error">${esc(v.error)}</div>`;
    const cves = v.cves || [];
    const cveTable = cves.length
      ? `<table class="soc-table"><thead><tr><th>Vulnerability</th><th>Attempts</th><th>Got through</th><th>Aimed at</th><th>Seen</th></tr></thead><tbody>${cves
          .map((c) => `<tr class="${c.through ? 'is-hot' : ''} soc-row-link" data-cvedetail="${esc(c.cve)}" tabindex="0" role="button" title="What ${esc(c.cve)} is, who tried it and what to do"><td><strong class="soc-mono">${esc(c.cve)}</strong> ${sevChip(c.worst)}<br><small class="soc-muted">${esc((c.signatures || []).join('; '))}</small></td><td>${num(c.events)}<br><small class="soc-muted">${plural(c.attackers, 'attacker')}</small></td><td>${c.through ? `<b class="soc-hot">${num(c.through)}</b>` : '0'}</td><td>${(c.targets || []).slice(0, 4).map((t) => `${esc(t.name)} <small class="soc-muted">×${num(t.count)}</small>`).join('<br>')}</td><td><small>${esc(clock(c.first_seen))} → ${esc(ago(c.last_seen))}</small></td></tr>`)
          .join('')}</tbody></table>`
      : '<p class="soc-muted">No detection in this window names a CVE.</p>';
    const exp = v.exposures || [];
    const expBody = exp.length
      ? `<table class="soc-table"><thead><tr><th>Asset</th><th>Weakness</th><th>Severity</th><th>Fixed in</th><th>Source</th></tr></thead><tbody>${exp
          .map((x) => `<tr><td><strong>${esc(x.asset_name || x.asset_ip)}</strong><br><small class="soc-muted">${esc(x.asset_ip || '')}</small></td><td>${x.cve ? `<span class="soc-mono">${esc(x.cve)}</span> ` : ''}${esc(x.title)}${x.exploited_in_wild ? ' <span class="soc-chip is-crit">Exploited in the wild</span>' : ''}</td><td>${sevChip(x.severity)}${x.cvss != null ? ` <small>CVSS ${esc(x.cvss)}</small>` : ''}</td><td>${esc(x.fixed_in || '')}</td><td>${esc(product(x.source))}</td></tr>`)
          .join('')}</tbody></table>`
      : `<p class="soc-muted">No connected system reports vulnerabilities on your assets yet. Any scanner, endpoint or IoT security platform, or vendor advisory service that offers <em>Vulnerabilities &amp; exposures</em> fills this table.${(v.exposure_sources || []).length ? ` Available but not connected: ${esc(v.exposure_sources.map((c) => c.product).join(', '))}.` : ''}</p>`;
    const sw = v.software || [];
    const swBody = sw.length
      ? `<ul class="soc-sw">${sw
          .map((m) => {
            const tot = Math.max(1, m.devices);
            let x = 0;
            const segs = m.versions
              .map((ver, i) => {
                const w = (100 * ver.count) / tot;
                const seg = `<rect class="soc-sw-seg v${Math.min(i, 4)}" x="${x}" y="0" width="${Math.max(0.5, w - 0.6)}" height="10"><title>${esc(ver.version)}: ${num(ver.count)}</title></rect>`;
                x += w;
                return seg;
              })
              .join('');
            return `<li class="${m.versions.length > 1 ? 'is-spread' : ''}"><div><strong>${esc(m.model)}</strong> <small class="soc-muted">${esc(m.vendor)} · ${plural(m.devices, 'device')}</small>${m.targeted ? ` <span class="soc-chip is-warn">${`${num(m.targeted)} targeted`}</span>` : ''}</div><svg class="soc-sw-bar" viewBox="0 0 100 10" preserveAspectRatio="none">${segs}</svg><small>${m.versions.map((ver) => `${esc(ver.version)} ×${num(ver.count)}`).join(' · ')}</small></li>`;
          })
          .join('')}</ul>`
      : '<p class="soc-muted">The device list has not been read yet — open Topology once, or wait for the next organization read.</p>';
    return `<div class="soc-vulns">
      <div class="soc-grid g-2">
        ${card('Vulnerabilities attackers are trying on you', cveTable, { eyebrow: 'From detections that name a CVE', ui: 'CVEs aimed at you', action: cves.length ? '<span class="soc-muted soc-card-note">Click one for details</span>' : '' })}
        ${card('Software spread', `${swBody}<p class="soc-muted soc-fine">One model on several releases is the first thing to fix before the next advisory: every extra release is another patch to track.</p>`, { eyebrow: 'From your inventory', ui: 'Software spread' })}
      </div>
      ${card('Known weaknesses on your assets', expBody, { eyebrow: 'From your security platforms', ui: 'Exposures' })}
    </div>`;
  }

  // ---------------------------------------------------------------- Coverage
  function coverageView() {
    const cov = S.data?.coverage || [];
    return `<div class="soc-coverage">
      <p class="soc-lead">Security Operations reads three kinds of records — <strong>security detections</strong>, <strong>vulnerabilities &amp; exposures</strong> and <strong>security incidents</strong>. Any connected system that provides one of them feeds these pages; nothing here is tied to a vendor. Adding a firewall, IDS, EDR, DNS-security, scanner or SIEM is a matter of connecting it.</p>
      <div class="soc-covgrid">${cov
        .map(
          (c) => `<div class="soc-cov ${c.connected ? 'is-on' : ''}"><div class="soc-cov-head"><strong>${esc(c.product)}</strong><span class="soc-chip ${c.connected ? 'is-good' : ''}">${esc(c.connected ? 'Feeding Security Operations' : c.state_label || 'Not connected')}</span></div><small class="soc-muted">${esc(c.vendor)}</small><p>${c.capabilities.map((x) => `<span class="soc-chip soc-chip-plain">${esc(x.label)}</span>`).join(' ')}</p>
          <dl class="soc-dl small"><div><dt>Kept here</dt><dd>${num(c.stored)}</dd></div><div><dt>Last read</dt><dd>${esc(c.last_read ? ago(c.last_read) : '—')}</dd></div><div><dt>New last read</dt><dd>${c.last_new == null ? '—' : num(c.last_new)}</dd></div><div><dt>Took</dt><dd>${c.read_ms ? `${(c.read_ms / 1000).toFixed(1)} s` : '—'}</dd></div></dl>
          ${c.last_error ? `<p class="soc-note is-error">${esc(c.last_error)}</p>` : ''}${c.connected ? '' : `<small class="soc-muted">Set up in ${esc(c.settings_location)}</small>`}</div>`,
        )
        .join('')}</div>
      <p class="soc-muted soc-fine">Detections are kept on this computer for 7 days (at most 30,000), as NodeWatch's own records — never the vendor's raw logs — and are not included in diagnostics exports.</p>
    </div>`;
  }

  // ---------------------------------------------------------------- Posture (pre-v0.10.30 findings)
  function postureView() {
    const p = S.posture;
    if (!p) {
      loadPosture();
      return '<div class="soc-loading"><span class="soc-pulse"></span> Checking posture…</div>';
    }
    if (p.error) return `<div class="soc-note is-error">${esc(p.error)}</div>`;
    const s = p.summary || {};
    return `<div class="soc-posture">${card(
      'Posture findings',
      `<p class="soc-muted">Evidence-based findings from the network management system: active alarms, disconnected infrastructure, firmware consistency, access denials and recent changes. No synthetic score.</p>
      <div class="soc-kpis small"><div class="soc-kpi"><span class="soc-kpi-label">Critical groups</span><strong>${num(s.critical)}</strong></div><div class="soc-kpi"><span class="soc-kpi-label">Warning groups</span><strong>${num(s.warning)}</strong></div><div class="soc-kpi"><span class="soc-kpi-label">Disconnected</span><strong>${num(s.disconnected_devices)}</strong></div><div class="soc-kpi"><span class="soc-kpi-label">Access denials</span><strong>${num(s.nac_denials)}</strong></div></div>
      ${(p.findings || [])
        .map(
          (f) => `<details class="soc-finding sev-${esc(f.severity)}"><summary><b>${esc(f.title)}</b><span>${plural(f.count, 'item')}</span></summary><ul class="soc-mini">${(f.items || [])
            .slice(0, 12)
            .map((x) => `<li><span>${esc(x.name || x.type || x.type_code || x.model || x.admin_name || 'Finding')}</span><small>${esc(x.message || x.version || x.site_name || x.status || '')}</small></li>`)
            .join('')}</ul></details>`,
        )
        .join('') || '<p class="soc-muted">No posture rule produced a finding.</p>'}`,
      { eyebrow: 'Network hygiene', ui: 'Posture' },
    )}</div>`;
  }

  // ---------------------------------------------------------------- detail pages (v0.10.32)
  // A detection, a threat, a site's pressure or a headline number opens a page of its own (Back returns).
  // v0.10.35: with no attack coming in, Origins shows where inside hosts' flagged traffic went instead of
  // an empty map, and says so plainly.
  function originsCard(d) {
    const inbound = d.countries || [];
    const dest = d.destinations || [];
    const useDest = !inbound.length && dest.length > 0;
    const rows = useDest ? dest : inbound;
    const foot = rows
      .slice(0, 6)
      .map((c) => `<span>${cc(c.code, c.name)} ${esc(c.name)} <b>${num(c.events)}</b></span>`)
      .join('');
    const note = useDest
      ? `<p class="soc-muted soc-origins-note">No attack came in from outside in this window. Shown instead: the ${plural(dest.length, 'country', 'countries')} your inside hosts' flagged traffic went to (blocked web categories, threats on outbound sessions).</p>`
      : '';
    return card(
      useDest ? 'Where flagged traffic went' : 'Where attacks come from',
      `${note}${originMap({ height: 280, mode: useDest ? 'dest' : 'in', interactive: false })}<div class="soc-map-foot">${foot || `<span class="soc-muted">${esc(originsGap())}</span>`}</div>`,
      { eyebrow: useDest ? 'Origins · outbound' : 'Origins', ui: 'Origins', action: '<button type="button" class="soc-link" data-view="atlas">Open Atlas</button>' },
    );
  }
  function originsGap() {
    const cov = S.data?.country_coverage || {};
    if (!cov.outside_events) return 'No attack from outside your network in this window, so there is nothing to place on the map (detections between inside hosts or to your own DNS have no country).';
    if (!cov.with_country)
      return `${plural(cov.outside_attackers || 0, 'outside attacker address', 'outside attacker addresses')} in this window, but the source sent no country for any of them. This is a data gap, not a quiet network: check that the firewall logs carry the source location.`;
    return 'The outside addresses in this window carry no country the map can place (private, reserved or unrecognised locations).';
  }
  function openDetail(detail) {
    S.detail = { ...detail, data: null };
    setView('detail');
    loadDetail();
  }
  async function loadDetail() {
    const dt = S.detail;
    if (!dt) return;
    const params = { window: S.window, limit: 200 };
    if (dt.type === 'event') Object.assign(params, { key: dt.key, window: '7d', limit: 1 });
    if (dt.type === 'threat') params.signature = dt.key;
    if (dt.type === 'site') params.site = dt.key;
    if (dt.type === 'cve') Object.assign(params, { cve: dt.key, window: S.window === '1h' || S.window === '6h' ? '24h' : S.window });
    try {
      if (dt.type === 'cve' && !S.vulns) await loadVulns();
      const data = await api(`${API}/soc/events?${q(params)}`);
      if (S.detail !== dt) return;
      dt.data = data;
      if (dt.type === 'event' && data.rows?.[0]) {
        const e = data.rows[0];
        const more = await api(`${API}/soc/events?${q({ window: S.window, signature: e.signature_id || e.name, limit: 1 })}`).catch(() => null);
        dt.similar = more?.total || 0;
        const fromSrc = e.attacker ? await api(`${API}/soc/events?${q({ window: S.window, q: e.attacker, limit: 1 })}`).catch(() => null) : null;
        dt.fromAttacker = fromSrc?.total || 0;
      }
    } catch (err) {
      dt.data = { error: err.message, rows: [] };
    }
    if (S.view === 'detail') render();
  }
  const fact = (label, value, mono = false) =>
    value == null || value === '' ? '' : `<div><dt>${esc(label)}</dt><dd${mono ? ' class="soc-mono"' : ''}>${value}</dd></div>`;
  function split(rows) {
    const out = { blocked: 0, contained: 0, alerted: 0, allowed: 0, unknown: 0 };
    rows.forEach((e) => (out[e.outcome || 'unknown'] = (out[e.outcome || 'unknown'] || 0) + (e.count || 1)));
    return out;
  }
  function tally(rows, get, n = 6) {
    const m = new Map();
    rows.forEach((e) => {
      const k = get(e);
      if (k) m.set(k, (m.get(k) || 0) + (e.count || 1));
    });
    return [...m.entries()].sort((a, b) => b[1] - a[1]).slice(0, n);
  }
  function miniList(title, pairs, attr = '') {
    if (!pairs.length) return '';
    return `<div class="soc-ent"><h4>${esc(title)}</h4><ul>${pairs.map(([k, v]) => `<li${attr ? ` ${attr(k)}` : ''}><span>${esc(k)}</span> <b>${num(v)}</b></li>`).join('')}</ul></div>`;
  }
  function outcomeBar(o) {
    const tot = Math.max(1, Object.values(o).reduce((a, b) => a + b, 0));
    let x = 0;
    const segs = ['blocked', 'contained', 'alerted', 'allowed', 'unknown']
      .filter((k) => o[k])
      .map((k) => {
        const w = (100 * o[k]) / tot;
        const seg = `<rect class="soc-ob o-${k}" x="${x}" y="0" width="${w}" height="10"><title>${esc(OUTCOME[k])}: ${num(o[k])}</title></rect>`;
        x += w;
        return seg;
      })
      .join('');
    return `<svg class="soc-obar" viewBox="0 0 100 10" preserveAspectRatio="none" aria-hidden="true">${segs}</svg><p class="soc-obar-legend">${['blocked', 'contained', 'alerted', 'allowed', 'unknown'].filter((k) => o[k]).map((k) => `${outChip(k)} ${num(o[k])}`).join(' · ')}</p>`;
  }
  function detailView() {
    const dt = S.detail;
    const back = '<button type="button" class="soc-btn soc-back" data-act="back">← Back</button>';
    if (!dt) return `<div class="soc-detail">${back}<p class="soc-muted">Nothing selected.</p></div>`;
    const d = dt.data;
    const loading = !d ? '<div class="soc-loading"><span class="soc-pulse"></span> Loading…</div>' : d.error ? `<div class="soc-note is-error">${esc(d.error)}</div>` : '';
    let body = '';
    if (dt.type === 'event') body = loading || eventPage(d.rows?.[0], dt);
    else if (dt.type === 'threat') body = loading || threatPage(dt, d);
    else if (dt.type === 'site') body = loading || sitePage(dt, d);
    else if (dt.type === 'cve') body = loading || cvePage(dt, d);
    return `<div class="soc-detail" data-ui="Security Operations › Detail">${back}${body}</div>`;
  }
  function eventPage(e, dt) {
    if (!e) return '<p class="soc-muted">This detection is no longer in the last 7 days kept on this computer.</p>';
    const [what, todo] = KIND_INFO[e.kind] || KIND_INFO.other;
    const reach = (S.data?.reach_scale || []).find((r) => r.level === e.reach);
    return `<article class="soc-casefile soc-eventpage">
      <header class="soc-casehead"><div class="soc-casehead-main"><div class="soc-eyebrow">${esc(e.kind_label)} · ${esc(clock(e.t))} (${esc(ago(e.t))})</div><h2>${esc(e.name || e.kind_label)}</h2>
        <p>${e.attacker ? `${cc(e.country, e.country_name)} <span class="soc-mono">${esc(e.attacker)}</span> → ` : e.src ? `<span class="soc-mono">${esc(e.src)}</span> → ` : ''}<strong>${esc(e.target || e.dst || '')}</strong>${e.dst_port ? ` <span class="soc-mono">port ${esc(e.dst_port)}</span>` : ''}${e.site ? ` · ${esc(e.site)}` : ''}</p></div>
        <div class="soc-casescore">${outChip(e.outcome)} ${sevChip(e.severity)}</div></header>
      <div class="soc-grid g-2 tight">
        <div><h4 class="soc-h4">What it is</h4><p>${esc(what)}</p>
          <h4 class="soc-h4">What happened</h4><p>${outChip(e.outcome)} ${esc(OUTCOME_INFO[e.outcome] || '')}${e.action ? ` <small class="soc-muted">(action: ${esc(e.action)})</small>` : ''}</p>
          ${reach ? `<p>${reachChip(e.reach)} ${esc(reach.help)}${e.through ? ' <b>It got through.</b>' : ''}</p>` : ''}
          <h4 class="soc-h4">What to do</h4><p>${esc(todo)}</p></div>
        <div><h4 class="soc-h4">Details</h4><dl class="soc-dl soc-dl-rows">
          ${fact('Threat', esc(e.name))}${fact('Threat ID', esc(e.signature_id), true)}${fact('Category', esc(e.category || e.sub_type))}
          ${fact('Severity', sevChip(e.severity))}${fact('Direction', esc(e.direction))}
          ${fact('Source', `${esc(e.src || '')}${e.src_port ? `:${esc(e.src_port)}` : ''}${e.src_zone ? ` <small class="soc-muted">zone ${esc(e.src_zone)}</small>` : ''}`, true)}
          ${fact('Destination', `${esc(e.dst || '')}${e.dst_port ? `:${esc(e.dst_port)}` : ''}${e.dst_zone ? ` <small class="soc-muted">zone ${esc(e.dst_zone)}</small>` : ''}`, true)}
          ${fact('Country', e.country ? `${cc(e.country, e.country_name)} ${esc(e.country_name)}` : '')}
          ${fact('Host / domain', esc(e.host), true)}${fact('URL', esc(e.url), true)}${fact('User', esc(e.user))}
          ${fact('Application', esc(e.app))}${fact('Protocol', esc(e.protocol))}
          ${fact('File', esc(e.file))}${fact('File hash', esc(e.file_hash), true)}${fact('CVEs', esc((e.cves || []).join(', ')), true)}
          ${fact('Site', esc(e.site))}${fact('Seen by', esc(e.sensor))}${fact('Policy rule', esc(e.rule), true)}
          ${fact('Repeats', e.count > 1 ? num(e.count) : '')}${fact('Reported by', esc(product(e.source)))}${fact('Log ID', esc(e.native_id), true)}
        </dl></div>
      </div>
      <div class="soc-actions">
        ${e.target_ip ? `<button type="button" class="soc-btn" data-finder="${esc(e.target_ip)}">Find ${esc(e.target || e.target_ip)} in Device Finder</button>` : ''}
        ${e.target_managed ? `<button type="button" class="soc-btn" data-topo="${esc(e.target)}" data-topo-ip="${esc(e.target_ip)}">Show in Topology</button>` : ''}
        <button type="button" class="soc-btn" data-threat="${esc(e.signature_id || e.name)}">About this threat${dt.similar > 1 ? ` (${num(dt.similar)} in this window)` : ''}</button>
        ${e.attacker ? `<button type="button" class="soc-btn" data-detq="${esc(e.attacker)}">Everything from ${esc(e.attacker)}${dt.fromAttacker ? ` (${num(dt.fromAttacker)})` : ''}</button>` : ''}
        ${e.site_key ? `<button type="button" class="soc-btn" data-sitedetail="${esc(e.site_key)}">${esc(e.site)} pressure</button>` : ''}
      </div>
    </article>`;
  }
  function threatPage(dt, d) {
    const rows = d.rows || [];
    const sig = (S.data?.signatures || []).find((x) => x.key === dt.key);
    const first = rows[0] || {};
    const kind = sig?.kind || first.kind || 'other';
    const [what, todo] = KIND_INFO[kind] || KIND_INFO.other;
    const o = split(rows);
    const cves = sig?.cves || first.cves || [];
    return `<article class="soc-casefile">
      <header class="soc-casehead"><div class="soc-casehead-main"><div class="soc-eyebrow">Threat · ${esc((sig?.kinds || []).map((k) => k.label).join(', ') || first.kind_label || '')}</div><h2>${esc(sig?.label || first.name || dt.key)}</h2>
        <p>${plural(d.total || 0, 'detection')} in the last ${esc(WINDOWS.find((w) => w[0] === S.window)?.[1] || S.window)}${sig?.last_seen ? ` · last ${esc(ago(sig.last_seen))}` : ''}${cves.length ? ` · <span class="soc-mono">${esc(cves.join(', '))}</span>` : ''}</p></div>
        <div class="soc-casescore">${sig ? reachChip(sig.reach) : ''} ${sevChip(sig?.worst || first.severity || 'info')}</div></header>
      <div class="soc-grid g-2 tight">
        <div><h4 class="soc-h4">What it is and what it does</h4><p>${esc(what)}</p>${first.category ? `<p class="soc-muted">Category reported by the source: ${esc(first.category)}</p>` : ''}
          <h4 class="soc-h4">Was it stopped?</h4>${outcomeBar(o)}${sig?.through ? `<p><b class="soc-hot">${num(sig.through)} got through</b> (not blocked or contained).</p>` : '<p>None of them got through.</p>'}
          <h4 class="soc-h4">What to do</h4><p>${esc(todo)}</p></div>
        <div class="soc-ents">
          ${miniList('Targets', tally(rows, (e) => e.target))}
          ${miniList('From', tally(rows, (e) => e.attacker || e.src))}
          ${miniList('Sites', tally(rows, (e) => e.site))}
          ${miniList('Seen by', tally(rows, (e) => e.sensor))}
        </div>
      </div>
      <h4 class="soc-h4">Detections <small class="soc-muted">${num(d.total)}</small></h4>${eventTable(rows, 25)}
    </article>`;
  }
  // v0.10.35: a CVE attackers tried opens a page: what it is, who tried it, whether anything is exposed, what to do.
  function cvePage(dt, d) {
    const rows = d.rows || [];
    const id = dt.key;
    const c = (S.vulns?.cves || []).find((x) => x.cve === id) || {};
    const exposed = (S.vulns?.exposures || []).filter((x) => String(x.cve || '').toUpperCase() === id.toUpperCase());
    const o = split(rows);
    const through = c.through || rows.filter((e) => e.through).reduce((n, e) => n + (e.count || 1), 0);
    const year = (id.match(/CVE-(\d{4})-/i) || [])[1];
    const nvd = `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(id)}`;
    const kev = 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog';
    const verdict = through
      ? `<p><b class="soc-hot">${num(through)} attempt${through === 1 ? '' : 's'} got through</b> (the firewall alerted or allowed instead of blocking). Treat the targets below as possibly compromised until they are checked.</p>`
      : '<p>Every attempt was blocked or reset by the firewall. Nothing got through.</p>';
    const exposure = exposed.length
      ? `<p><b class="soc-hot">${plural(exposed.length, 'asset')} reported vulnerable to this CVE</b> by a connected scanner:</p><ul class="soc-mini">${exposed.map((x) => `<li><span>${esc(x.asset_name || x.asset_ip)}</span><b>${esc(x.fixed_in ? `fix: ${x.fixed_in}` : '')}</b></li>`).join('')}</ul>`
      : `<p class="soc-muted">${(S.vulns?.exposure_sources || []).length || (S.vulns?.exposures || []).length ? 'No connected scanner reports any of your assets as vulnerable to it.' : 'No vulnerability scanner is connected, so NodeWatch cannot tell whether the targets actually run the affected software.'}</p>`;
    return `<article class="soc-casefile">
      <header class="soc-casehead"><div class="soc-casehead-main"><div class="soc-eyebrow">Vulnerability attackers tried${year ? ` · published ${esc(year)}` : ''}</div><h2 class="soc-mono">${esc(id)}</h2>
        <p>${plural(c.events || d.total || 0, 'attempt')} from ${plural(c.attackers || tally(rows, (e) => e.attacker || e.src, 999).length, 'address', 'addresses')}${c.last_seen ? ` · last ${esc(ago(c.last_seen))}` : ''}${c.first_seen ? ` · first ${esc(clock(c.first_seen))}` : ''}</p></div>
        <div class="soc-casescore">${sevChip(c.worst || rows[0]?.severity || 'info')}</div></header>
      <div class="soc-grid g-2 tight">
        <div>
          <h4 class="soc-h4">What it is</h4>
          <p>A published software flaw. The firewall recognised traffic trying to exploit it${(c.signatures || []).length ? ` with the signature${c.signatures.length === 1 ? '' : 's'} <strong>${esc(c.signatures.join('; '))}</strong>` : ''}. Attackers scan the internet for flaws like this; an attempt does not mean you run the affected product.</p>
          <p><a href="${nvd}" target="_blank" rel="noopener noreferrer">Full description, affected versions and CVSS score (NVD) ↗</a><br><a href="${kev}" target="_blank" rel="noopener noreferrer">Is it on CISA's actively-exploited list? ↗</a></p>
          <h4 class="soc-h4">Was it stopped?</h4>${outcomeBar(o)}${verdict}
          <h4 class="soc-h4">Are you exposed?</h4>${exposure}
          <h4 class="soc-h4">What to do</h4>
          <ol class="soc-steps">
            <li>Check whether the targets below run the affected product and version (see the NVD link).</li>
            <li>If they do, patch or apply the vendor workaround first${through ? ' — and investigate them, since attempts got through' : ''}.</li>
            <li>Make sure the security profile on the matching rule blocks (reset/drop) this threat rather than only alerting.</li>
            <li>If the attempts come from a few addresses, consider blocking them at the edge.</li>
          </ol>
        </div>
        <div class="soc-ents">
          ${miniList('Aimed at', tally(rows, (e) => e.target))}
          ${miniList('From', tally(rows, (e) => e.attacker || e.src))}
          ${miniList('Countries', tally(rows, (e) => e.country_name || e.country))}
          ${miniList('Sites', tally(rows, (e) => e.site))}
          ${miniList('Seen by', tally(rows, (e) => e.sensor))}
        </div>
      </div>
      <h4 class="soc-h4">Attempts <small class="soc-muted">${num(d.total || 0)}</small></h4>${eventTable(rows, 25)}
    </article>`;
  }
  function sitePage(dt, d) {
    const rows = d.rows || [];
    const p = (S.data?.pressure || []).find((x) => x.key === dt.key);
    const name = p?.label || rows[0]?.site || dt.key;
    const o = split(rows);
    const kinds = tally(rows, (e) => e.kind_label, 8);
    return `<article class="soc-casefile">
      <header class="soc-casehead"><div class="soc-casehead-main"><div class="soc-eyebrow">Site under pressure</div><h2>${esc(name)}</h2>
        <p>${plural(d.total || 0, 'detection')}${p?.through ? ` · <b class="soc-hot">${num(p.through)} got through</b>` : ''}${p?.last_seen ? ` · last ${esc(ago(p.last_seen))}` : ''}</p></div>
        <div class="soc-casescore"><span class="soc-score big" title="Pressure (most pressed site = 100)">${num(p?.pressure ?? 0)}</span><small class="soc-muted">pressure</small></div></header>
      <p class="soc-muted">${esc(PRESSURE_INFO)}</p>
      <div class="soc-grid g-2 tight">
        <div><h4 class="soc-h4">What is hitting it</h4>${kinds.length ? `<ul class="soc-mini">${kinds.map(([k, v]) => `<li><span>${esc(k)}</span><b>${num(v)}</b></li>`).join('')}</ul>` : '<p class="soc-muted">Nothing.</p>'}
          <h4 class="soc-h4">Was it stopped?</h4>${outcomeBar(o)}</div>
        <div class="soc-ents">
          ${miniList('Top threats', tally(rows, (e) => e.name), (k) => `data-threat="${esc(k)}" class="soc-row-link" tabindex="0" role="button"`)}
          ${miniList('Most targeted here', tally(rows, (e) => e.target))}
          ${miniList('From', tally(rows, (e) => e.attacker || e.src))}
        </div>
      </div>
      <div class="soc-actions"><button type="button" class="soc-btn" data-sitefilter="${esc(dt.key)}">Show the whole page for ${esc(name)} only</button></div>
      <h4 class="soc-h4">Latest detections <small class="soc-muted">${num(d.total)}</small></h4>${eventTable(rows, 25)}
    </article>`;
  }

  // Back / forward: views and detail pages are history entries.
  function navPush() {
    if (window.MistApp?.isRestoringView?.()) return;
    const view = S.view === 'detail' && S.detail ? { soc: 'detail', type: S.detail.type, key: S.detail.key } : { soc: S.view };
    window.MistApp?.pushView?.(view);
  }
  async function restoreView(view) {
    if (!root) return;
    if (view?.soc === 'detail' && view.key) {
      S.detail = { type: view.type, key: view.key, data: null };
      setView('detail', { push: false });
      return loadDetail();
    }
    setView(view?.soc && view.soc !== 'detail' ? view.soc : store.get('view', 'watch') === 'detail' ? 'watch' : store.get('view', 'watch'), { push: false });
  }

  // ---------------------------------------------------------------- events
  function setView(v, { push = true } = {}) {
    S.view = v;
    if (v !== 'detail') store.set('view', v);
    if (push) navPush();
    if (v === 'detections') loadDetections(true);
    if (v === 'vulns' && !S.vulns) loadVulns();
    if (v === 'posture' && !S.posture) loadPosture();
    render();
  }

  async function onClick(ev) {
    const t = ev.target.closest('button, [data-country], a, [data-event], [data-threat], [data-cvedetail], [data-sitedetail]');
    if (!t || !root.contains(t)) return;
    if (t.dataset.view) return setView(t.dataset.view);
    if (t.dataset.event && !ev.target.closest('a, button:not([data-event])')) return openDetail({ type: 'event', key: t.dataset.event });
    if (t.dataset.threat) return openDetail({ type: 'threat', key: t.dataset.threat });
    if (t.dataset.cvedetail) return openDetail({ type: 'cve', key: t.dataset.cvedetail });
    if (t.dataset.sitedetail) return openDetail({ type: 'site', key: t.dataset.sitedetail });
    if (t.dataset.kpi) {
      const k = t.dataset.kpi;
      if (k === 'cases') return setView('cases');
      if (k === 'countries') return setView('atlas');
      S.det = { q: '', kind: k === 'callout' ? 'command_control' : '', outcome: k === 'stopped' ? 'blocked' : '', reach: k === 'callout' ? '4' : '', country: '', offset: 0, through: k === 'through', note: KPI_INFO[k] };
      return setView('detections');
    }
    if (t.dataset.detq) {
      S.det = { q: t.dataset.detq, kind: '', outcome: '', reach: '', country: '', offset: 0 };
      return setView('detections');
    }
    if (t.dataset.sitefilter) {
      S.site = t.dataset.sitefilter;
      S.detData = null;
      setView('watch');
      return load();
    }
    if (t.dataset.case) {
      S.view = 'cases';
      store.set('view', 'cases');
      return loadCase(t.dataset.case);
    }
    if (t.dataset.casefilter) {
      S.caseFilter = t.dataset.casefilter;
      store.set('caseFilter', S.caseFilter);
      return render();
    }
    if (t.dataset.atlas) {
      S.atlasMode = t.dataset.atlas;
      S.atlasPick = '';
      return render();
    }
    if (t.dataset.country && !t.dataset.countrylist) {
      if (S.view !== 'atlas') {
        S.view = 'atlas';
        store.set('view', 'atlas');
      }
      S.atlasPick = t.dataset.country;
      return render();
    }
    if (t.dataset.countrylist) {
      S.det = { q: '', kind: '', outcome: '', reach: S.atlasMode === 'out' ? '4' : '', country: S.atlasMode === 'out' ? '' : t.dataset.countrylist, offset: 0 };
      if (S.atlasMode === 'out') S.det.q = '';
      return setView('detections');
    }
    if ('caseevents' in t.dataset) {
      S.det = { q: t.dataset.caseevents, kind: t.dataset.casesite ? 'wireless' : '', outcome: '', reach: '', country: '', offset: 0 };
      if (t.dataset.casesite) S.site = t.dataset.casesite;
      return setView('detections');
    }
    if (t.dataset.reach) {
      S.det = { q: '', kind: '', outcome: '', reach: t.dataset.reach, country: '', offset: 0 };
      return setView('detections');
    }
    if (t.dataset.page) {
      S.det.offset = Math.max(0, S.det.offset + Number(t.dataset.page) * 100);
      return loadDetections();
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
    if (t.dataset.topo) {
      await window.MistApp?.openTool('topology');
      window.MistTools.topology?.focusDevice?.({ name: t.dataset.topo, ip: t.dataset.topoIp || '' });
      return;
    }
    const act = t.dataset.act;
    if (act === 'refresh') {
      try {
        if (!S.sample) await api(`${API}/soc/refresh`, { method: 'POST' });
      } catch {
        /* the reload below still shows what is there */
      }
      S.vulns = null;
      S.detData = null;
      return load();
    }
    if (act === 'sample') {
      S.sample = true;
      S.data = null;
      S.caseId = '';
      S.caseDetail = null;
      S.vulns = null;
      S.detData = null;
      if (S.view === 'coverage' || S.view === 'posture') S.view = 'watch';
      return load();
    }
    if (act === 'leave-sample') {
      S.sample = false;
      S.data = null;
      S.caseId = '';
      S.caseDetail = null;
      S.vulns = null;
      S.detData = null;
      return load();
    }
    if (act === 'connections') {
      await window.MistApp?.openTool('settings');
      return;
    }
    if (act === 'clear-det') {
      S.det = { q: '', kind: '', outcome: '', reach: '', country: '', offset: 0 };
      return loadDetections();
    }
    if (act === 'wall') return toggleWall();
    if (act === 'back') return history.length > 1 ? history.back() : setView('watch');
    if (act === 'pressure-help') {
      const box = t.closest('.soc-card')?.querySelector('.soc-help');
      if (box) return box.remove();
      t.closest('.soc-card-head')?.insertAdjacentHTML('afterend', `<p class="soc-help soc-muted">${esc(PRESSURE_INFO)}</p>`);
    }
  }

  async function onChange(ev) {
    const t = ev.target;
    if (t.dataset.set === 'window') {
      S.window = t.value;
      store.set('window', S.window);
      S.vulns = null;
      S.detData = null;
      return load();
    }
    if (t.dataset.set === 'site') {
      S.site = t.value;
      S.detData = null;
      return load();
    }
    if (t.dataset.casestate) return saveCase(t.dataset.casestate, { state: t.value });
    if (t.dataset.caseowner) return saveCase(t.dataset.caseowner, { owner: t.value });
  }

  function onInput(ev) {
    const t = ev.target;
    if (t.matches('[data-casequery]')) {
      S.caseQuery = t.value;
      const pos = t.selectionStart;
      render();
      const again = root.querySelector('[data-casequery]');
      if (again) {
        again.focus();
        again.setSelectionRange(pos, pos);
      }
    }
  }

  async function onSubmit(ev) {
    const form = ev.target;
    if (form.matches('[data-detform]')) {
      ev.preventDefault();
      const fd = new FormData(form);
      S.det = { q: String(fd.get('q') || ''), kind: String(fd.get('kind') || ''), outcome: String(fd.get('outcome') || ''), reach: String(fd.get('reach') || ''), country: String(fd.get('country') || ''), offset: 0, through: S.det.through };
      return loadDetections();
    }
    if (form.matches('[data-noteform]')) {
      ev.preventDefault();
      const note = String(new FormData(form).get('note') || '').trim();
      if (note) await saveCase(form.dataset.noteform, { note });
    }
  }

  async function saveCase(id, body) {
    if (S.sample) {
      // the preview keeps changes in this page only
      const c = S.caseDetail;
      if (c && c.id === id) {
        if (body.state) c.state = body.state;
        if (body.owner != null) c.owner = body.owner;
        if (body.note) c.notes = [...(c.notes || []), { at: Date.now() / 1000, by: 'you (preview)', text: body.note }];
        render();
      }
      return;
    }
    try {
      await api(`${API}/soc/cases/${encodeURIComponent(id)}`, { method: 'POST', body: JSON.stringify(body) });
      await load({ quiet: true });
      await loadCase(id, true);
    } catch (err) {
      S.error = `Not saved: ${err.message}`;
      render();
    }
  }

  // ---------------------------------------------------------------- wall display
  // v0.10.42: the wall display stays on whatever page it shows (a rendition, a tab, a case or a detail)
  // and only its data refreshes, in place, every 30 s. It no longer rotates. It is remembered, so the
  // screen comes back in wall mode on the same page after NodeWatch restarts, and it does not depend on
  // the browser's full screen (leaving full screen keeps the wall; "Exit wall display" ends it).
  function toggleWall() {
    S.wall = !S.wall;
    store.set('wall', S.wall);
    if (S.wall) root.requestFullscreen?.().catch(() => {});
    else if (document.fullscreenElement) document.exitFullscreen?.().catch(() => {});
    render();
  }

  // ---------------------------------------------------------------- lifecycle
  function init() {
    root = document.querySelector('#socRoot');
    if (!root) return;
    if (!initd) {
      initd = true;
      root.addEventListener('click', onClick);
      root.addEventListener('change', onChange);
      root.addEventListener('input', onInput);
      root.addEventListener('submit', onSubmit);
      root.addEventListener('keydown', (ev) => {
        if ((ev.key === 'Enter' || ev.key === ' ') && (ev.target.dataset?.country || ev.target.dataset?.event || ev.target.dataset?.threat || ev.target.dataset?.cvedetail || ev.target.dataset?.sitedetail)) {
          ev.preventDefault();
          onClick(ev);
        }
      });
    }
    if (!window.MistApp?.isRestoringView?.()) window.MistApp?.pushView?.({ soc: S.view }, { replace: true });
    return load();
  }

  async function autoRefresh() {
    if (!root || S.loading) return;
    // Never under someone typing (a site/window list that merely kept the focus does not stop it: a wall
    // display would otherwise never refresh again after one choice).
    if (root.querySelector('textarea:focus, input:not([type=checkbox]):not([type=radio]):focus')) return;
    await load({ quiet: true });
  }

  return { init, refresh: () => load(), autoRefresh, restoreView, _state: S };
})();
