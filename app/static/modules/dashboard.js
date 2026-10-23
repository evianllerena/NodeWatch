window.MistTools = window.MistTools || {};

// Command Center. v0.10.16: "Requires Attention" lists incidents built server-side from the
// vendor-neutral alerts of every connected source (see app/services/attention_service.py).
window.MistTools.dashboard = (() => {
  let data = null;
  let inc = { incidents: [], counts: {}, noisy_types: [], sources: [], dismiss_reasons: [], team: {} };
  let groupFilter = '';
  let deviceTypeFilter = '';
  let attentionView = 'needs';
  let attentionSort = 'priority';
  let nocRefreshBusy = false;
  let nocAutoTimer = null;
  const NOC_AUTO_REFRESH_MS = 20000;
  let nextAutoAt = Date.now() + NOC_AUTO_REFRESH_MS;
  let lastLoadedAt = 0; // when the last refresh finished (focus refreshes skip fresher data)
  let countdownTimer = null;
  let specialFilter = ''; // 'down' = device-offline incidents only (Devices Down tile)
  let activeTile = '';
  let showAllDown = false;
  let quickSearchSeq = 0;
  let quickSearchTimer = null;
  let mistSettings = null;
  let suppressedData = null;
  const drawer = { id: '', detail: null, members: [], offset: 0, loading: false };
  const severityRank = { critical: 0, major: 1, warning: 2, info: 3 };
  const escapeHtml = (v = '') =>
    String(v).replace(
      /[&<>'"]/g,
      (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' })[c],
    );
  const DEVICE_LABEL = { ap: 'Access point', switch: 'Switch', gateway: 'Gateway' };
  const ROLE_LABEL = {
    wireless_ap: 'AP',
    switch: 'Switch',
    sdwan_edge: 'Gateway',
    firewall: 'Firewall',
    router: 'Router',
  };
  const typeLabel = (t) => DEVICE_LABEL[String(t || '').toLowerCase()] || (t ? String(t) : 'Device');
  const fmtN = (n) => Number(n || 0).toLocaleString();
  const rowFor = (id) => [...document.querySelectorAll('.inc-row')].find((el) => el.dataset.id === id);
  function ago(ms) {
    const s = Math.max(0, Math.round((Date.now() - Number(ms || 0)) / 1000));
    if (!ms) return '';
    if (s < 60) return `${s}s`;
    if (s < 3600) return `${Math.floor(s / 60)}m`;
    if (s < 86400) return `${Math.floor(s / 3600)}h ${Math.floor((s % 3600) / 60)}m`;
    return `${Math.floor(s / 86400)}d ${Math.floor((s % 86400) / 3600)}h`;
  }
  // Deep link into the Mist portal (api.* host → manage.* host) for a device, or its site.
  async function mistUrl({ type = '', mac = '', deviceId = '', siteId = '' } = {}) {
    try {
      if (!mistSettings) mistSettings = await getJSON('/api/settings');
      const u = new URL(mistSettings.api_host || 'https://api.mist.com');
      u.hostname = u.hostname.replace(/^api(?=[.-]|$)/, 'manage');
      u.pathname = '/admin/';
      u.search = `?org_id=${encodeURIComponent(mistSettings.org_id || '')}`;
      const kind = { ap: 'ap', switch: 'switch', gateway: 'gateway' }[String(type).toLowerCase()];
      const bare = String(mac || '')
        .toLowerCase()
        .replace(/[^0-9a-f]/g, '');
      const id = deviceId || (bare.length === 12 ? `00000000-0000-0000-1000-${bare}` : '');
      u.hash =
        kind && id && siteId
          ? `!${kind}/detail/${id}/${siteId}`
          : siteId
            ? `!dashboard/insights/${encodeURIComponent(siteId)}`
            : '';
      return u.toString();
    } catch {
      return 'https://manage.mist.com/';
    }
  }
  function wireMistLinks(root) {
    root.querySelectorAll('[data-mist-link]:not([data-mist-wired])').forEach((a) => {
      a.dataset.mistWired = '1';
      a.addEventListener('click', async (e) => {
        e.preventDefault();
        e.stopPropagation();
        const url =
          a.dataset.url ||
          (await mistUrl({
            type: a.dataset.type,
            mac: a.dataset.mac,
            deviceId: a.dataset.deviceId,
            siteId: a.dataset.siteId,
          }));
        window.open(url, '_blank', 'noopener');
      });
    });
  }
  function mistLinkHtml(x, label = 'Mist ↗') {
    return `<a href="#" class="btn ghost small mist-link" data-mist-link data-url="${escapeHtml(x.mist_url || '')}" data-type="${escapeHtml(x.device_type || '')}" data-mac="${escapeHtml(x.mac || '')}" data-device-id="${escapeHtml(x.device_id || '')}" data-site-id="${escapeHtml(x.site_id || '')}" title="Open this device in the Mist portal">${escapeHtml(label)}</a>`;
  }
  async function findInDeviceFinder(query, siteId = '') {
    await window.MistApp?.openTool('detective');
    const input = document.querySelector('#detectiveQuery');
    if (!input) return;
    const site = document.querySelector('#detectiveSite');
    if (site) site.value = [...site.options].some((o) => o.value === siteId) ? siteId : '';
    input.value = query;
    const form = document.querySelector('#detectiveSearchForm');
    if (form?.requestSubmit) form.requestSubmit();
    else document.querySelector('#detectiveSearchBtn')?.click();
  }
  // Values used as CSS class names: lower-case letters, digits, '_' and '-' only.
  const cssToken = (v = '') =>
    String(v ?? '')
      .toLowerCase()
      .replace(/[^a-z0-9_-]/g, '');

  async function postJSON(url, body = {}) {
    const r = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    if (!r.ok) {
      let msg = await r.text();
      try {
        const j = JSON.parse(msg);
        msg = j.detail || msg;
      } catch {}
      throw new Error(typeof msg === 'string' ? msg : JSON.stringify(msg));
    }
    return r.json();
  }

  // ------------------------------------------------------------------ summary tiles
  function summaryCards() {
    const s = data.summary || {};
    const c = inc.counts || {};
    const ic = c.incidents || {};
    const open = (inc.incidents || []).filter((i) => i.bucket === 'open');
    const critInc = open.filter((i) => i.severity === 'critical' || i.severity === 'major').length;
    const warnInc = open.length - critInc;
    const cards = [
      [
        'critical',
        'Critical',
        c.critical ?? s.critical ?? 0,
        `open alerts in ${critInc} incident${critInc === 1 ? '' : 's'}`,
      ],
      [
        'warning',
        'Warnings',
        c.warning ?? s.warning ?? 0,
        `open alerts in ${warnInc} incident${warnInc === 1 ? '' : 's'}`,
      ],
      [
        'down',
        'Devices Down',
        s.devices_down ?? 0,
        `${s.aps_down ?? 0} AP · ${s.switches_down ?? 0} switch · ${s.gateways_down ?? 0} gateway${
          (s.devices_down_raw ?? s.devices_down) !== s.devices_down
            ? ` · ${(s.devices_down_raw ?? 0) - (s.devices_down ?? 0)} known/snoozed`
            : ''
        }`,
      ],
      ['vc', 'VC Degraded', s.vc_degraded ?? 0, 'Virtual Chassis requiring attention'],
      [
        'issues',
        'Needs Attention',
        c.new ?? s.needs_attention ?? 0,
        `${ic.needs ?? 0} incidents · ${fmtN(c.acknowledged)} acknowledged · ${fmtN(c.suppressed)} snoozed/muted`,
      ],
    ];
    const host = document.querySelector('#nocSummary');
    host.innerHTML = cards
      .map(
        ([kind, label, value, sub]) => `
      <button type="button" class="noc-summary-card card ${kind}${activeTile === kind ? ' active' : ''}" data-tile="${kind}" aria-pressed="${activeTile === kind}" title="Show ${escapeHtml(label.toLowerCase())} in Requires Attention"><span>${label}</span><strong>${fmtN(value)}</strong><small>${escapeHtml(sub)}</small></button>`,
      )
      .join('');
    host
      .querySelectorAll('[data-tile]')
      .forEach((b) => b.addEventListener('click', () => applyTile(b.dataset.tile)));
    // Menu badge = alerts that still need attention (like an unread count).
    window.MistApp?.setNavBadge?.('dashboard', s.needs_attention ?? s.open_issues ?? 0);
  }

  // Summary tiles filter the incident list; clicking the active tile clears it.
  function applyTile(kind) {
    const clear = activeTile === kind;
    groupFilter = '';
    deviceTypeFilter = '';
    specialFilter = '';
    activeTile = clear ? '' : kind;
    attentionView = 'needs';
    if (!clear) {
      if (kind === 'down') {
        specialFilter = 'down';
        attentionView = 'all';
      } else if (kind === 'vc') {
        deviceTypeFilter = 'vc';
        attentionView = 'all';
      } else if (kind === 'critical' || kind === 'warning') attentionView = 'all';
    }
    summaryCards();
    renderAttention();
    scrollAttentionTop();
    document.querySelector('.noc-attention-card')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  // ------------------------------------------------------------------ incident list
  const isCrit = (i) => i.severity === 'critical' || i.severity === 'major';
  const viewState = () =>
    attentionView === 'needs' ? 'new' : attentionView === 'acknowledged' ? 'acknowledged' : '';

  function inView(i, view = attentionView) {
    if (view === 'possibly_resolved') return i.bucket === 'possibly_resolved';
    if (i.bucket !== 'open') return false;
    if (view === 'mine') return Boolean(i.mine);
    if (view === 'needs') return (i.states?.new || 0) > 0;
    if (view === 'acknowledged') return (i.states?.acknowledged || 0) > 0;
    return view === 'all';
  }

  function viewCount(i, view = attentionView) {
    if (view === 'needs') return i.states?.new || 0;
    if (view === 'acknowledged') return i.states?.acknowledged || 0;
    if (view === 'possibly_resolved') return i.count || 0;
    return (i.states?.new || 0) + (i.states?.acknowledged || 0);
  }

  function baseFiltered() {
    const sev = (document.querySelector('#nocSeverityFilter')?.value || '').toLowerCase();
    const site = document.querySelector('#nocSiteFilter')?.value || 'All Sites';
    const q = (document.querySelector('#nocSearch')?.value || '').trim().toLowerCase();
    let list = [...(inc.incidents || [])];
    if (sev.startsWith('critical') || activeTile === 'critical') list = list.filter(isCrit);
    if (sev.startsWith('warning') || activeTile === 'warning') list = list.filter((i) => !isCrit(i));
    if (site !== 'All Sites')
      list = list.filter(
        (i) => (i.sites || []).some((s) => s.name === site) || i.search.includes(site.toLowerCase()),
      );
    if (groupFilter) list = list.filter((i) => i.group === groupFilter);
    if (specialFilter === 'down') list = list.filter((i) => String(i.kind).startsWith('offline'));
    if (deviceTypeFilter === 'vc') list = list.filter((i) => i.group === 'Virtual Chassis');
    else if (deviceTypeFilter) {
      const role = { ap: 'wireless_ap', switch: 'switch', gateway: 'sdwan_edge' }[deviceTypeFilter];
      list = list.filter((i) => (i.roles || {})[role] > 0);
    }
    if (q) list = list.filter((i) => i.search.includes(q));
    return list;
  }

  function sortIncidents(list) {
    const rows = [...list];
    const byPriority = (a, b) =>
      (a.bucket !== 'open') - (b.bucket !== 'open') ||
      (severityRank[a.severity] ?? 9) - (severityRank[b.severity] ?? 9) ||
      viewCount(b) - viewCount(a) ||
      (b.last_seen || 0) - (a.last_seen || 0);
    if (attentionSort === 'largest')
      return rows.sort((a, b) => viewCount(b) - viewCount(a) || byPriority(a, b));
    if (attentionSort === 'newest') return rows.sort((a, b) => (b.last_seen || 0) - (a.last_seen || 0));
    if (attentionSort === 'oldest') return rows.sort((a, b) => (a.first_seen || 0) - (b.first_seen || 0));
    if (attentionSort === 'site')
      return rows.sort(
        (a, b) =>
          String(a.sites?.[0]?.name || '').localeCompare(String(b.sites?.[0]?.name || '')) ||
          byPriority(a, b),
      );
    return rows.sort(byPriority);
  }

  function visibleIncidents() {
    return sortIncidents(baseFiltered().filter((i) => inView(i)));
  }

  function setAttentionView(view) {
    attentionView = view || 'needs';
    renderAttention();
  }

  function scrollAttentionTop() {
    const viewport = document.querySelector('.attention-viewport');
    if (viewport) viewport.scrollTop = 0;
  }

  function categoryFor(type = '') {
    const t = String(type).toUpperCase();
    if (/VIRTUAL_CHASSIS|SW_VC_|VC_/.test(t)) return 'Virtual Chassis';
    if (/DISCONNECTED|OFFLINE|CONNECTED|ONLINE|TUNNEL|VPN_|WAN_|UPLINK/.test(t))
      return 'Connectivity / Availability';
    return '';
  }

  function filtering() {
    return Boolean(
      groupFilter ||
      specialFilter ||
      deviceTypeFilter ||
      activeTile ||
      !/^all/i.test(document.querySelector('#nocSeverityFilter')?.value || 'All') ||
      (document.querySelector('#nocSiteFilter')?.value || 'All Sites') !== 'All Sites' ||
      (document.querySelector('#nocSearch')?.value || '').trim(),
    );
  }

  function renderFilterState() {
    const box = document.querySelector('#activeIssueFilter');
    const parts = [];
    if (specialFilter === 'down') parts.push('Devices offline');
    if (activeTile === 'critical') parts.push('Critical');
    if (activeTile === 'warning') parts.push('Warnings');
    if (groupFilter) parts.push(`Category: ${groupFilter}`);
    if (deviceTypeFilter)
      parts.push(`Device: ${deviceTypeFilter === 'vc' ? 'Virtual Chassis' : typeLabel(deviceTypeFilter)}`);
    const site = document.querySelector('#nocSiteFilter')?.value || 'All Sites';
    if (site !== 'All Sites') parts.push(`Site: ${site}`);
    if (!box) return;
    if (parts.length) {
      box.classList.remove('hidden');
      box.innerHTML = `Filtering incidents — <strong>${escapeHtml(parts.join(' · '))}</strong> <button id="clearIssueFilterInline" class="link-btn">Clear</button>`;
      document.querySelector('#clearIssueFilterInline')?.addEventListener('click', clearDrillFilter);
    } else box.classList.add('hidden');
  }

  function renderTabs() {
    const base = baseFiltered();
    const c = inc.counts || {};
    const mineAlerts = (inc.incidents || [])
      .filter((i) => inView(i, 'mine'))
      .reduce((n, i) => n + viewCount(i, 'mine'), 0);
    const views = {
      needs: ['tabNeedsCount', c.new],
      mine: ['tabMineCount', mineAlerts],
      acknowledged: ['tabAckCount', c.acknowledged],
      all: ['tabAllCount', c.open],
      possibly_resolved: ['tabResolvedCount', c.possibly_resolved],
    };
    Object.entries(views).forEach(([view, [id, alerts]]) => {
      const list = base.filter((i) => inView(i, view));
      const el = document.querySelector(`#${id}`);
      if (el) el.textContent = fmtN(list.length);
      const btn = el?.closest('button');
      if (btn) {
        const shown = list.reduce((n, i) => n + viewCount(i, view), 0);
        btn.title = `${fmtN(list.length)} incident${list.length === 1 ? '' : 's'} · ${fmtN(filtering() ? shown : alerts)} alerts`;
      }
    });
    // "Mine" appears once something is assigned to you or triage is shared with the team.
    const mineTab = document.querySelector('[data-attention-view="mine"]');
    if (mineTab)
      mineTab.classList.toggle(
        'hidden',
        !(mineAlerts || (inc.counts?.incidents?.mine ?? 0) || inc.team?.shared || attentionView === 'mine'),
      );
    const sup = document.querySelector('#tabSuppressedCount');
    if (sup) sup.textContent = fmtN(c.suppressed);
    document.querySelectorAll('[data-attention-view]').forEach((b) => {
      const on = b.dataset.attentionView === attentionView;
      b.classList.toggle('active', on);
      b.setAttribute('aria-selected', String(on));
    });
  }

  function renderNoisy() {
    const host = document.querySelector('#attentionNoisy');
    if (!host) return;
    const rows = inc.noisy_types || [];
    if (!rows.length || attentionView === 'suppressed') {
      host.classList.add('hidden');
      host.innerHTML = '';
      return;
    }
    host.classList.remove('hidden');
    host.innerHTML = `<span class="attn-noisy-label">Noisiest alert types</span>${rows
      .map(
        (r) =>
          `<span class="attn-chip"><button type="button" class="attn-chip-filter" data-noisy-q="${escapeHtml(r.label)}" title="Show only ${escapeHtml(r.label)}">${escapeHtml(r.label)} <b>${fmtN(r.count)}</b></button><button type="button" class="attn-chip-mute" data-mute-type="${escapeHtml(r.type)}" data-mute-source="${escapeHtml(r.source)}" data-mute-label="${escapeHtml(r.label)}" title="Mute ${escapeHtml(r.label)} everywhere (undo available)">Mute</button></span>`,
      )
      .join('')}`;
    host.querySelectorAll('[data-noisy-q]').forEach((b) =>
      b.addEventListener('click', () => {
        const input = document.querySelector('#nocSearch');
        if (input) input.value = b.dataset.noisyQ;
        renderAttention();
      }),
    );
    host
      .querySelectorAll('[data-mute-type]')
      .forEach((b) =>
        b.addEventListener('click', () =>
          muteType({ type: b.dataset.muteType, source: b.dataset.muteSource, label: b.dataset.muteLabel }),
        ),
      );
  }

  function sitesText(i) {
    const sites = i.sites || [];
    if (!sites.length) return 'Site not reported';
    if (i.site_count === 1) return sites[0].name;
    const top = sites.slice(0, 3).map((s) => `${s.name} (${fmtN(s.count)})`);
    return `${top.join(' · ')}${i.site_count > 3 ? ` +${i.site_count - 3} more sites` : ''}`;
  }

  function sourceChips(list = []) {
    return list
      .map(
        (s) =>
          `<span class="attn-source" title="Reported by ${escapeHtml(s.label)}">${escapeHtml(s.label)}</span>`,
      )
      .join('');
  }

  // ------------------------------------------------------------------ team triage (v0.10.18)
  const isMeName = (name, me = inc.team?.me || {}) => {
    const n = String(name || '').toLowerCase();
    return (
      Boolean(n) &&
      (n === String(me.user || '').toLowerCase() || n === String(me.display || '').toLowerCase())
    );
  };

  function teamStatusText() {
    const t = inc.team || {};
    if (!t.shared) return '';
    if (t.mode === 'offline') return `Team triage offline — ${fmtN(t.pending)} waiting to sync`;
    if (t.mode === 'read_only') return 'Team triage: read-only for you';
    return `Team triage: ${t.label || 'shared'}${t.last_sync ? ` · synced ${ago(t.last_sync * 1000)} ago` : ''}${t.owner_check === 'unavailable' ? ' · names not verified' : ''}`;
  }

  function assigneeChip(i) {
    const list = i.assignees || [];
    if (!list.length) return '';
    const names = list.map((a) => a.display || a.name).join(', ');
    const label = i.mine ? 'Assigned to you' : `Assigned · ${list[0].display || list[0].name}`;
    return `<span class="attn-flag assignee${i.mine ? ' mine' : ''}" title="Assigned to ${escapeHtml(names)}">${escapeHtml(label)}${list.length > 1 ? ` +${list.length - 1}` : ''}</span>`;
  }

  const ACTION_WORD = {
    ack: 'acknowledged',
    unack: 'cleared the acknowledgement of',
    snooze: 'snoozed',
    unsnooze: 'unsnoozed',
    dismiss: 'dismissed',
    restore: 'restored',
    unassign: 'unassigned',
  };

  function activityText(a) {
    const what = a.count > 1 ? `${fmtN(a.count)} alerts` : a.count === 1 ? '1 alert' : 'this incident';
    if (a.action === 'assign')
      return `assigned ${what} to ${isMeName(a.assignee) ? 'you' : a.assignee_display || a.assignee}`;
    let extra = '';
    if (a.action === 'snooze')
      extra =
        a.duration === 'change'
          ? ' until it changes'
          : a.until
            ? ` until ${new Date(a.until * 1000).toLocaleString()}`
            : '';
    if (a.action === 'dismiss' && a.reason) extra = ` — ${a.reason}`;
    // "in Mist" is a fact only for this PC's own events; anyone else's is shown as their claim.
    if (a.action === 'ack' && a.via) extra = a.via_trusted ? ` (${a.via})` : ` (says “${a.via}”)`;
    return `${ACTION_WORD[a.action] || a.action} ${what}${extra}`;
  }

  // Display names are free text: always show user@machine next to them, and flag look-alikes.
  function whoHtml(x) {
    return `<span class="attn-team-who">${escapeHtml(x.mine ? 'You' : x.who)}</span> <span class="attn-team-ident" title="Windows user @ computer that wrote this">${escapeHtml(x.ident || '')}</span>${x.conflict ? '<span class="attn-flag bad" title="Another user uses the same display name — check the user@computer">Same name as another user</span>' : ''}`;
  }

  function teamHtml(t, i) {
    if (!t) return '';
    const store = t.store || {};
    const when = (ts) =>
      `<time title="${escapeHtml(new Date(ts * 1000).toLocaleString())}">${escapeHtml(ago(ts * 1000))} ago</time>`;
    const assignees = (t.assignees || [])
      .map(
        (a) =>
          `<span class="attn-flag assignee${isMeName(a.name, t.me) ? ' mine' : ''}">${escapeHtml(isMeName(a.name, t.me) ? 'You' : a.display || a.name)}${(t.assignees || []).length > 1 || a.count !== i.count ? ` · ${fmtN(a.count)}` : ''}</span>`,
      )
      .join('');
    const activity = (t.activity || [])
      .map((a) => `<li>${whoHtml(a)} <span>${escapeHtml(activityText(a))}</span> ${when(a.ts)}</li>`)
      .join('');
    const notes = (t.notes || [])
      .map(
        (n) =>
          `<li class="attn-note${n.mine ? ' mine' : ''}"><div class="attn-note-head"><span>${whoHtml(n)}</span>${when(n.ts)}</div><p>${escapeHtml(n.note)}</p></li>`,
      )
      .join('');
    const where = store.shared
      ? `${store.label || 'Shared'}${store.mode === 'offline' ? ' · offline, will sync' : ''}`
      : 'only on this PC';
    return `<section class="attn-sec attn-team" data-ui="Command Center › Incident details › Team">
      <h4>Team <small>${escapeHtml(where)}</small></h4>
      ${store.writable === false ? '<div class="notice warning">The shared triage folder is read-only for you: you see your team’s triage, but your own actions cannot be saved. See Settings › Team triage.</div>' : ''}
      ${store.shared && store.owner_check === 'unavailable' ? '<div class="notice warning">This shared folder does not keep Windows file owners, so who wrote each entry below cannot be verified. See Settings › Team triage.</div>' : ''}
      ${!store.shared ? '<p class="muted attn-team-hint">Assignments and notes stay on this PC. Share them with your team under Settings › Team triage.</p>' : ''}
      <div class="attn-team-assign"><span class="attn-team-label">Assigned</span><div class="attn-team-chips">${assignees || '<span class="muted">Nobody yet</span>'}</div>
        <div class="attn-team-btns"><button type="button" class="btn ghost small" data-team="assign-me">Assign to me</button><button type="button" class="btn ghost small" data-team="assign-menu" aria-haspopup="menu">Assign… ▾</button>${(t.assignees || []).length ? '<button type="button" class="btn ghost small" data-team="unassign">Unassign</button>' : ''}</div></div>
      <form class="attn-team-other hidden" data-team-form="assign"><label class="attn-sr-only" for="attnAssignOther">Assign to</label><input id="attnAssignOther" type="text" maxlength="80" autocomplete="off" placeholder="Name or Windows user name"><button type="submit" class="btn secondary small">Assign</button></form>
      <div class="attn-team-cols">
        <div><h5>Who did what</h5>${activity ? `<ul class="attn-activity">${activity}</ul>` : '<p class="muted">Nobody has acknowledged, snoozed, dismissed or assigned these alerts in NodeWatch yet.</p>'}</div>
        <div><h5>Notes <small>${fmtN((t.notes || []).length)}</small></h5><ul class="attn-notes">${notes || '<li class="muted">No notes yet.</li>'}</ul>
          <form class="attn-note-form" data-team-form="note"><label class="attn-sr-only" for="attnNoteText">Note</label><textarea id="attnNoteText" maxlength="500" rows="2" placeholder="Add a short note for the team"></textarea><div class="attn-note-actions"><small id="attnNoteCount" class="muted">0 / 500</small><button type="submit" class="btn primary small">Add note</button></div></form>
        </div>
      </div>
    </section>`;
  }

  async function teamPost(body, done) {
    const id = drawer.id;
    try {
      const res = await postJSON('/api/dashboard/triage', { incident_id: id, ...body });
      applyPayload(res);
      toast(done);
      if (drawer.id === id) loadDrawer(id, true);
      return true;
    } catch (err) {
      toast(`Could not save: ${err.message}`, { kind: 'error' });
      return false;
    }
  }

  function wireTeam(root, t) {
    const sec = root.querySelector('.attn-team');
    if (!sec || !t) return;
    const assign = (who, label) => teamPost({ action: 'assign', assignee: who }, `Assigned to ${label}.`);
    sec.querySelector('[data-team="assign-me"]')?.addEventListener('click', () => assign('me', 'you'));
    sec
      .querySelector('[data-team="unassign"]')
      ?.addEventListener('click', () => teamPost({ action: 'unassign' }, 'Assignment cleared.'));
    const other = sec.querySelector('[data-team-form="assign"]');
    sec.querySelector('[data-team="assign-menu"]')?.addEventListener('click', (e) => {
      e.stopPropagation();
      const items = (t.actors || [])
        .filter((a) => !isMeName(a.user, t.me))
        .map((a) => [`u:${a.user}`, `Assign to ${a.display || a.user}`]);
      items.unshift(['me', 'Assign to me']);
      items.push(['other', 'Someone else…']);
      openMenu(e.currentTarget, items, (v) => {
        if (v === 'me') assign('me', 'you');
        else if (v === 'other') {
          other?.classList.remove('hidden');
          other?.querySelector('input')?.focus();
        } else {
          const a = (t.actors || []).find((x) => `u:${x.user}` === v);
          if (a) assign(a.user, a.display || a.user);
        }
      });
    });
    other?.addEventListener('submit', (e) => {
      e.preventDefault();
      const who = other.querySelector('input').value.trim();
      if (who) assign(who, who);
    });
    const form = sec.querySelector('[data-team-form="note"]');
    const text = form?.querySelector('textarea');
    const count = sec.querySelector('#attnNoteCount');
    text?.addEventListener('input', () => {
      if (count) count.textContent = `${text.value.length} / 500`;
    });
    form?.addEventListener('submit', async (e) => {
      e.preventDefault();
      const note = text.value.trim();
      if (!note) return;
      const btn = form.querySelector('button');
      btn.disabled = true;
      if (await teamPost({ action: 'note', note }, 'Note added.')) text.value = '';
      btn.disabled = false;
    });
  }

  function incidentRowHtml(i) {
    const n = viewCount(i);
    const ack = i.states?.acknowledged || 0;
    const since = i.first_seen ? ago(i.first_seen * 1000) : '';
    const last = i.last_seen ? ago(i.last_seen * 1000) : '';
    const preview = (i.preview || []).filter(Boolean);
    const devicesText =
      i.device_count > 0
        ? `${fmtN(i.device_count)} device${i.device_count === 1 ? '' : 's'}${preview.length ? `: ${preview.slice(0, 3).join(', ')}${i.device_count > 3 ? '…' : ''}` : ''}`
        : '';
    return `<article class="inc-row ${cssToken(i.severity)}${drawer.id === i.id ? ' selected' : ''}" data-id="${escapeHtml(i.id)}" tabindex="0" role="button" aria-label="Open ${escapeHtml(i.title)}">
      <span class="inc-rail" aria-hidden="true"></span>
      <div class="inc-main">
        <div class="inc-title"><strong>${escapeHtml(i.title)}</strong><span class="severity-badge ${cssToken(i.severity)}">${escapeHtml(i.severity)}</span>${sourceChips(i.sources)}${i.flapping ? `<span class="attn-flag flap" title="Went down and up 3+ times recently">Flapping ×${fmtN(i.flapping)}</span>` : ''}${attentionView !== 'acknowledged' && ack ? `<span class="attn-flag ack">${fmtN(ack)} acknowledged</span>` : ''}${assigneeChip(i)}</div>
        <div class="inc-summary">${escapeHtml(i.summary || '')}</div>
      </div>
      <div class="inc-count" title="${fmtN(n)} alert${n === 1 ? '' : 's'} in this view"><strong>${fmtN(n)}</strong><small>alert${n === 1 ? '' : 's'}</small></div>
      <div class="inc-meta"><span>${escapeHtml(sitesText(i))}</span>${devicesText ? `<span>${escapeHtml(devicesText)}</span>` : ''}${since ? `<span>since ${escapeHtml(since)} ago</span>` : ''}${last && last !== since ? `<span>last ${escapeHtml(last)} ago</span>` : ''}</div>
      <div class="inc-actions">${actionButtonsHtml(i, true)}</div>
    </article>`;
  }

  // Buttons shared by incident rows and the drawer.
  function actionButtonsHtml(i, compact = false) {
    const view = attentionView;
    const canAck = view !== 'acknowledged' && (i.states?.new || 0) > 0;
    return `${canAck ? `<button type="button" class="btn ghost small" data-act="ack" title="${i.ackable ? 'Acknowledge — writes to the source after you confirm' : 'Acknowledge in NodeWatch'}">Acknowledge</button>` : ''}<button type="button" class="btn ghost small" data-act="snooze-menu" aria-haspopup="menu">Snooze ▾</button><button type="button" class="btn ghost small" data-act="dismiss-menu" aria-haspopup="menu">Dismiss ▾</button>${compact ? '' : `<button type="button" class="btn ghost small" data-act="mute-menu" aria-haspopup="menu">Mute type ▾</button>`}`;
  }

  function wireActionButtons(root, scope) {
    root.querySelectorAll('[data-act]').forEach((b) =>
      b.addEventListener('click', (e) => {
        e.stopPropagation();
        const s = typeof scope === 'function' ? scope(b) : scope;
        if (!s) return;
        const act = b.dataset.act;
        if (act === 'ack') startAck(s);
        else if (act === 'snooze-menu')
          openMenu(b, snoozeMenu(), (v) => runAction(s, 'snooze', { duration: v }));
        else if (act === 'dismiss-menu')
          openMenu(b, dismissMenu(), (v) => runAction(s, 'dismiss', { reason: v }));
        else if (act === 'mute-menu')
          openMenu(b, muteMenu(s.incident), (v) => muteFromIncident(s.incident, v));
      }),
    );
  }

  function renderAttention() {
    if (!data) return;
    renderTabs();
    renderNoisy();
    renderFilterState();
    const c = inc.counts || {};
    const ic = c.incidents || {};
    const sortCtl = document.querySelector('#attentionSort');
    if (sortCtl) sortCtl.disabled = attentionView === 'suppressed';
    const sourceNames = (inc.sources || []).map((s) => s.label).join(', ');
    const pageInfo = document.querySelector('#attentionPageInfo');
    if (pageInfo)
      pageInfo.textContent = `${sourceNames ? `Sources: ${sourceNames} · ` : ''}${fmtN(c.source_alarms)} source alarms → ${fmtN(c.alerts_total)} alerts → ${fmtN((ic.all || 0) + (ic.possibly_resolved || 0))} incidents${teamStatusText() ? ` · ${teamStatusText()}` : ''}`;
    if (attentionView === 'suppressed') {
      document.querySelector('#attentionCount').textContent =
        `${fmtN(c.snoozed)} snoozed · ${fmtN(c.dismissed)} dismissed · ${fmtN(c.muted)} muted`;
      renderSuppressed();
      return;
    }
    const list = visibleIncidents();
    const alerts = list.reduce((n, i) => n + viewCount(i), 0);
    document.querySelector('#attentionCount').textContent = filtering()
      ? `${fmtN(list.length)} incident${list.length === 1 ? '' : 's'} · ${fmtN(alerts)} alerts match the filter`
      : `${fmtN(c.new)} need attention · ${fmtN(c.acknowledged)} acknowledged · ${fmtN(c.possibly_resolved)} possibly resolved · ${fmtN(c.suppressed)} snoozed/muted`;
    const empty = {
      needs: 'Nothing needs attention. New alerts from any connected source will appear here as incidents.',
      mine: 'Nothing is assigned to you. Open an incident and choose “Assign to me”.',
      acknowledged: 'No acknowledged incidents.',
      all: 'No open incidents.',
      possibly_resolved: 'Nothing looks resolved-but-still-open.',
    }[attentionView];
    const host = document.querySelector('#attentionList');
    host.innerHTML = list.length
      ? list.map(incidentRowHtml).join('')
      : `<div class="noc-empty">${escapeHtml(filtering() ? 'No incidents match the filter in this view.' : empty)}</div>`;
    const byId = new Map((inc.incidents || []).map((x) => [x.id, x])); // v0.10.40: was a find() per row
    host.querySelectorAll('.inc-row').forEach((el) => {
      const open = () => openDrawer(el.dataset.id);
      el.addEventListener('click', open);
      el.addEventListener('keydown', (e) => {
        if (e.target !== el) return;
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          open();
        } else if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
          e.preventDefault();
          const sib = e.key === 'ArrowDown' ? el.nextElementSibling : el.previousElementSibling;
          sib?.focus?.();
        }
      });
      wireActionButtons(el, { incidentId: el.dataset.id, incident: byId.get(el.dataset.id), state: viewState() });
    });
  }

  // ------------------------------------------------------------------ popover menus (on <body>)
  function snoozeMenu() {
    return [
      ['1h', 'For 1 hour'],
      ['4h', 'For 4 hours'],
      ['24h', 'For 24 hours'],
      ['change', 'Until it changes (severity or count)'],
    ];
  }
  function dismissMenu() {
    return (inc.dismiss_reasons?.length ? inc.dismiss_reasons : ['Known issue', 'Not actionable']).map(
      (r) => [r, r],
    );
  }
  function muteMenu(i) {
    if (!i) return [];
    const items = [['all', `Mute “${i.type_label}” everywhere`]];
    if (i.site_key)
      items.push(['site', `Mute “${i.type_label}” at ${i.sites?.[0]?.name || 'this site'} only`]);
    items.push(['all24', 'Mute everywhere for 24 hours']);
    return items;
  }

  let popoverPick = null;
  function openMenu(anchor, items, onPick) {
    const pop = document.querySelector('#attnPopover');
    if (!pop || !items.length) return;
    popoverPick = onPick;
    pop.innerHTML = items
      .map(
        ([v, label]) =>
          `<button type="button" role="menuitem" data-v="${escapeHtml(v)}">${escapeHtml(label)}</button>`,
      )
      .join('');
    pop.classList.remove('hidden');
    const r = anchor.getBoundingClientRect();
    const w = Math.max(220, pop.offsetWidth);
    const left = Math.min(window.innerWidth - w - 8, Math.max(8, r.right - w));
    const below = r.bottom + 4 + pop.offsetHeight < window.innerHeight;
    pop.style.setProperty('left', `${left}px`);
    pop.style.setProperty('top', `${below ? r.bottom + 4 : Math.max(8, r.top - pop.offsetHeight - 4)}px`);
    pop.querySelectorAll('[data-v]').forEach((b) =>
      b.addEventListener('click', (e) => {
        e.stopPropagation();
        const pick = popoverPick;
        closeMenu();
        pick?.(b.dataset.v);
      }),
    );
    pop.querySelector('button')?.focus();
  }
  function closeMenu() {
    const pop = document.querySelector('#attnPopover');
    if (pop) pop.classList.add('hidden');
    popoverPick = null;
  }
  const menuOpen = () => !document.querySelector('#attnPopover')?.classList.contains('hidden');

  // ------------------------------------------------------------------ toasts
  function toast(message, { undo = '', kind = 'ok', note = '' } = {}) {
    const host = document.querySelector('#attnToasts');
    if (!host) return;
    const el = document.createElement('div');
    el.className = `attn-toast ${cssToken(kind)}`;
    el.setAttribute('role', kind === 'error' ? 'alert' : 'status');
    el.innerHTML = `<span>${escapeHtml(message)}${note ? `<small>${escapeHtml(note)}</small>` : ''}</span>${undo ? '<button type="button" class="btn ghost small">Undo</button>' : ''}<button type="button" class="icon-btn" aria-label="Close">×</button>`;
    const remove = () => {
      el.classList.add('leaving');
      setTimeout(() => el.remove(), 200);
    };
    el.querySelector('.icon-btn').addEventListener('click', remove);
    el.querySelector('.btn')?.addEventListener('click', async () => {
      remove();
      try {
        applyPayload(await postJSON('/api/dashboard/triage/undo', { token: undo }));
        toast('Undone.');
        if (drawer.id) loadDrawer(drawer.id, true);
      } catch (err) {
        toast(`Undo failed: ${err.message}`, { kind: 'error' });
      }
    });
    host.appendChild(el);
    while (host.children.length > 3) host.firstElementChild.remove();
    setTimeout(remove, undo ? 10000 : 5000);
  }

  // ------------------------------------------------------------------ actions
  function applyPayload(p) {
    if (!p || !p.incidents) return;
    inc = {
      incidents: p.incidents,
      counts: p.counts,
      noisy_types: p.noisy_types,
      sources: p.sources,
      dismiss_reasons: p.dismiss_reasons,
      source_errors: p.source_errors,
      team: p.team || inc.team || {},
    };
    if (data) {
      data.incidents = inc;
      const s = data.summary || (data.summary = {});
      Object.assign(s, {
        critical: inc.counts.critical,
        warning: inc.counts.warning,
        needs_attention: inc.counts.new,
        acknowledged: inc.counts.acknowledged,
        unresolved_total: inc.counts.open,
        open_issues: inc.counts.open,
        dismissed: inc.counts.suppressed,
      });
    }
    summaryCards();
    renderAttention();
    renderGroups();
    if (attentionView === 'suppressed') renderSuppressed(true);
  }

  // Optimistic: move the affected alerts between counters at once; the server reply reconciles.
  function optimistic(scope, action) {
    const i = scope.incident;
    const c = inc.counts || {};
    let moved = 0;
    if (scope.keys) moved = scope.keys.length;
    else if (i) moved = viewCount(i);
    if (!moved) return 0;
    const from = scope.state || (i && i.bucket === 'possibly_resolved' ? 'possibly_resolved' : 'mixed');
    const take = (field) => {
      c[field] = Math.max(0, (c[field] || 0) - moved);
    };
    if (from === 'possibly_resolved') take('possibly_resolved');
    else if (from === 'acknowledged') take('acknowledged');
    else if (from === 'new') take('new');
    else if (i) {
      c.new = Math.max(0, (c.new || 0) - (i.states?.new || 0));
      c.acknowledged = Math.max(0, (c.acknowledged || 0) - (i.states?.acknowledged || 0));
    }
    if (action === 'snooze' || action === 'dismiss') {
      c.suppressed = (c.suppressed || 0) + moved;
      c[action === 'snooze' ? 'snoozed' : 'dismissed'] =
        (c[action === 'snooze' ? 'snoozed' : 'dismissed'] || 0) + moved;
      if (from !== 'possibly_resolved') c.open = Math.max(0, (c.open || 0) - moved);
    } else if (action.startsWith('ack')) c.acknowledged = (c.acknowledged || 0) + moved;
    if (i && !scope.keys) {
      if (action.startsWith('ack')) {
        i.states.acknowledged = (i.states.acknowledged || 0) + (i.states.new || 0);
        i.states.new = 0;
      } else if (from === 'new') i.states.new = 0;
      else if (from === 'acknowledged') i.states.acknowledged = 0;
      else i.states = { ...i.states, new: 0, acknowledged: 0 };
      if (!action.startsWith('ack')) i.count = Math.max(0, i.count - moved);
      const row = rowFor(i.id);
      if (row && !inView(i)) row.classList.add('attn-leaving');
    }
    if (scope.keys)
      scope.keys.forEach((k) =>
        [...document.querySelectorAll('.attn-member')]
          .find((el) => el.dataset.key === k)
          ?.classList.add('attn-leaving'),
      );
    summaryCards();
    renderTabs();
    return moved;
  }

  const ACTION_TEXT = {
    snooze: (n, o) =>
      `Snoozed ${fmtN(n)} alert${n === 1 ? '' : 's'} ${o.duration === 'change' ? 'until they change' : `for ${o.duration.replace('h', ' h')}`}.`,
    dismiss: (n, o) => `Dismissed ${fmtN(n)} alert${n === 1 ? '' : 's'} (${o.reason}).`,
    ack_local: (n) => `Acknowledged ${fmtN(n)} alert${n === 1 ? '' : 's'} in NodeWatch.`,
    restore: (n) => `Restored ${fmtN(n)} alert${n === 1 ? '' : 's'}.`,
  };

  async function runAction(scope, action, opts = {}) {
    const moved = optimistic(scope, action);
    const body = { action, ...opts };
    if (scope.keys) body.keys = scope.keys;
    else body.incident_id = scope.incidentId;
    if (scope.state) body.state = scope.state;
    try {
      const res = await postJSON('/api/dashboard/triage', body);
      setTimeout(() => applyPayload(res), moved ? 220 : 0);
      const n = res.changed ?? moved;
      toast(ACTION_TEXT[action] ? ACTION_TEXT[action](n, opts) : 'Done.', { undo: res.undo });
      if (drawer.id) setTimeout(() => loadDrawer(drawer.id, true), 240);
    } catch (err) {
      toast(`${action} failed: ${err.message}`, { kind: 'error' });
      refresh(false, true).catch(() => {});
    }
  }

  // Acknowledge: if the source can take it (Mist), ask first — this writes to Mist and is audited.
  // The Mist write is bound to exactly what the dialog showed: explicit alert keys, or the incident's
  // membership version + count fetched right now. The server answers 409 if anything changed.
  async function startAck(scope) {
    const i = scope.incident;
    const ackable = scope.keys ? scope.ackable : i?.ackable;
    if (!ackable) {
      runAction(scope, 'ack_local');
      return;
    }
    let n = scope.keys ? scope.keys.length : 0;
    let bound = null;
    if (!scope.keys) {
      try {
        const d = await getJSON(
          `/api/dashboard/incidents/${encodeURIComponent(scope.incidentId)}?${new URLSearchParams({ state: 'new', limit: 1 })}`,
        );
        bound = { version: d.version, count: d.total };
        n = d.total;
      } catch (err) {
        toast(`This incident changed — ${err.message}`, { kind: 'error' });
        refresh(false, true).catch(() => {});
        return;
      }
    }
    const dlg = document.querySelector('#attnAckDialog');
    const sources = (i?.sources || []).map((s) => s.label).join(', ') || 'the source';
    document.querySelector('#attnAckTitle').textContent =
      `Acknowledge ${fmtN(n)} alert${n === 1 ? '' : 's'} in ${sources}?`;
    document.querySelector('#attnAckText').textContent =
      `This writes an acknowledgement to ${sources} for every alarm behind ${n === 1 ? 'this alert' : `these ${fmtN(n)} alerts`} and is recorded in the NodeWatch audit log. Acknowledged alarms stay open until the source clears them. Alerts that have no alarm in ${sources} (for example a device that is only reported offline) are acknowledged in NodeWatch only.`;
    const go = async (inSource) => {
      dlg.close();
      if (!inSource) return runAction(scope, 'ack_local');
      optimistic(scope, 'ack_source');
      const body = {
        action: 'ack_source',
        confirmed: true,
        note: document.querySelector('#attnAckNote').value,
      };
      if (scope.keys) body.keys = scope.keys;
      else Object.assign(body, { incident_id: scope.incidentId, ...bound });
      try {
        const res = await postJSON('/api/dashboard/triage', body);
        setTimeout(() => applyPayload(res), 220);
        const failed = (res.failed || []).length;
        toast(
          `Acknowledged ${fmtN(res.acknowledged_in_source)} in ${sources}${res.acknowledged_locally ? ` · ${fmtN(res.acknowledged_locally)} in NodeWatch only` : ''}${failed ? ` · ${failed} failed${res.partially_acknowledged ? ` (${res.partially_acknowledged} only partly)` : ''} — still listed as new` : ''}.`,
          { undo: res.undo, kind: failed ? 'warn' : 'ok', note: res.undo_note || '' },
        );
        if (drawer.id) setTimeout(() => loadDrawer(drawer.id, true), 240);
      } catch (err) {
        toast(`Acknowledge failed: ${err.message}`, { kind: 'error' });
        refresh(false, true).catch(() => {});
      }
    };
    document.querySelector('#attnAckConfirm').textContent = `Acknowledge in ${sources}`;
    document.querySelector('#attnAckConfirm').onclick = () => go(true);
    document.querySelector('#attnAckLocal').onclick = () => go(false);
    dlg.showModal();
  }

  async function muteType({ type, source, label, siteKey = '', siteName = '', hours = null }) {
    try {
      const res = await postJSON('/api/dashboard/mutes', {
        type,
        source,
        label,
        site_key: siteKey,
        site_name: siteName,
        hours,
        reason: 'Muted from Command Center',
      });
      applyPayload(res);
      toast(
        `Muted “${label}”${siteName ? ` at ${siteName}` : ' everywhere'}${hours ? ` for ${hours} h` : ''}. Find it under Snoozed & muted.`,
        { undo: res.undo },
      );
      if (drawer.id && !(inc.incidents || []).some((x) => x.id === drawer.id)) closeDrawer();
    } catch (err) {
      toast(`Mute failed: ${err.message}`, { kind: 'error' });
    }
  }

  function muteFromIncident(i, how) {
    if (!i) return;
    const source = i.sources?.[0]?.id || '';
    muteType({
      type: i.mute_type,
      source,
      label: i.type_label,
      siteKey: how === 'site' ? i.site_key : '',
      siteName: how === 'site' ? i.sites?.[0]?.name || '' : '',
      hours: how === 'all24' ? 24 : null,
    });
  }

  // ------------------------------------------------------------------ Snoozed & muted view
  async function renderSuppressed(force = false) {
    const host = document.querySelector('#attentionList');
    if (!host) return;
    if (!suppressedData || force) {
      host.innerHTML = suppressedData ? host.innerHTML : '<div class="noc-empty">Loading…</div>';
      try {
        suppressedData = await getJSON('/api/dashboard/suppressed?limit=500');
      } catch (err) {
        host.innerHTML = `<div class="noc-empty">Could not load: ${escapeHtml(err.message)}</div>`;
        return;
      }
    }
    if (attentionView !== 'suppressed') return;
    const d = suppressedData;
    const when = (ts) => (ts ? new Date(ts * 1000).toLocaleString() : '');
    const mutes = (d.mutes || [])
      .map(
        (m) =>
          `<li class="attn-sup-row"><div><strong>${escapeHtml(m.label || m.type)}</strong><small>${escapeHtml(m.site_name ? `at ${m.site_name}` : 'everywhere')}${m.until ? ` · until ${escapeHtml(when(m.until))}` : ''} · ${fmtN(m.matching)} alert${m.matching === 1 ? '' : 's'} hidden${m.reason ? ` · ${escapeHtml(m.reason)}` : ''}${m.by ? ` · by ${escapeHtml(m.by)}` : ''}</small></div><button type="button" class="btn ghost small" data-unmute="${escapeHtml(m.id)}">Unmute</button></li>`,
      )
      .join('');
    const items = (d.items || [])
      .map(
        (x) =>
          `<li class="attn-sup-row attn-member" data-key="${escapeHtml(x.key)}"><div><strong>${escapeHtml(x.title)}</strong><small>${escapeHtml([x.device, x.site].filter(Boolean).join(' · '))} · ${
            x.state === 'snoozed'
              ? escapeHtml(x.until_change ? 'snoozed until it changes' : `snoozed until ${when(x.until)}`)
              : `dismissed — ${escapeHtml(x.reason || 'no reason')}`
          }${x.by ? ` · by ${escapeHtml(x.by)}${x.at ? ` ${escapeHtml(ago(x.at * 1000))} ago` : ''}` : ''}</small></div><button type="button" class="btn ghost small" data-restore="${escapeHtml(x.key)}">${x.state === 'snoozed' ? 'Unsnooze' : 'Restore'}</button></li>`,
      )
      .join('');
    host.innerHTML = `<section class="attn-sup"><h4>Mute rules <small>${fmtN((d.mutes || []).length)}</small></h4>${mutes ? `<ul class="attn-sup-list">${mutes}</ul>` : '<div class="noc-empty">No mute rules. Use “Mute type” on an incident or the Noisiest alert types chips.</div>'}</section>
      <section class="attn-sup"><h4>Snoozed &amp; dismissed alerts <small>${fmtN(d.counts?.snoozed)} snoozed · ${fmtN(d.counts?.dismissed)} dismissed</small></h4>${items ? `<ul class="attn-sup-list">${items}</ul>${d.total > (d.items || []).length ? `<div class="muted">Showing ${fmtN((d.items || []).length)} of ${fmtN(d.total)}.</div>` : ''}` : '<div class="noc-empty">Nothing is snoozed or dismissed.</div>'}</section>`;
    host.querySelectorAll('[data-unmute]').forEach((b) =>
      b.addEventListener('click', async () => {
        b.closest('li')?.classList.add('attn-leaving');
        try {
          applyPayload(await postJSON(`/api/dashboard/mutes/${encodeURIComponent(b.dataset.unmute)}/remove`));
          toast('Unmuted — matching alerts are back in the list.');
          renderSuppressed(true);
        } catch (err) {
          toast(`Unmute failed: ${err.message}`, { kind: 'error' });
        }
      }),
    );
    host.querySelectorAll('[data-restore]').forEach((b) =>
      b.addEventListener('click', async () => {
        b.closest('li')?.classList.add('attn-leaving');
        try {
          const res = await postJSON('/api/dashboard/triage', {
            action: 'restore',
            keys: [b.dataset.restore],
          });
          applyPayload(res);
          toast('Restored to the list.', { undo: res.undo });
          renderSuppressed(true);
        } catch (err) {
          toast(`Restore failed: ${err.message}`, { kind: 'error' });
        }
      }),
    );
  }

  // ------------------------------------------------------------------ incident drawer
  function drawerEl() {
    return document.querySelector('#attnDrawer');
  }
  const drawerOpen = () => !drawerEl()?.classList.contains('hidden');

  function openDrawer(id) {
    const el = drawerEl();
    if (!el) return;
    drawer.id = id;
    drawer.detail = null;
    drawer.members = [];
    drawer.offset = 0;
    el.classList.remove('hidden');
    document.querySelector('#attnDrawerBackdrop')?.classList.remove('hidden');
    document.body.classList.add('attn-drawer-open');
    document.querySelectorAll('.inc-row').forEach((r) => r.classList.toggle('selected', r.dataset.id === id));
    const i = (inc.incidents || []).find((x) => x.id === id);
    if (i) {
      document.querySelector('#attnDrawerTitle').textContent = i.title;
      document.querySelector('#attnDrawerBody').innerHTML = '<div class="noc-empty">Loading details…</div>';
    }
    loadDrawer(id);
    el.focus({ preventScroll: true });
  }

  function closeDrawer() {
    drawerEl()?.classList.add('hidden');
    document.querySelector('#attnDrawerBackdrop')?.classList.add('hidden');
    document.body.classList.remove('attn-drawer-open');
    const id = drawer.id;
    drawer.id = '';
    const row = id && rowFor(id);
    document.querySelectorAll('.inc-row.selected').forEach((r) => r.classList.remove('selected'));
    row?.focus?.({ preventScroll: true });
  }

  function moveDrawer(delta) {
    const list = visibleIncidents();
    if (!list.length) return;
    const at = list.findIndex((x) => x.id === drawer.id);
    const next = list[Math.min(list.length - 1, Math.max(0, (at < 0 ? 0 : at) + delta))];
    if (next && next.id !== drawer.id) {
      openDrawer(next.id);
      rowFor(next.id)?.scrollIntoView({ block: 'nearest' });
    }
  }

  async function loadDrawer(id, keepMembers = false) {
    const state = attentionView === 'possibly_resolved' || attentionView === 'all' ? '' : viewState();
    const limit = keepMembers ? Math.max(50, drawer.members.length) : 50;
    try {
      const d = await getJSON(
        `/api/dashboard/incidents/${encodeURIComponent(id)}?${new URLSearchParams({ offset: 0, limit, state })}`,
      );
      if (drawer.id !== id) return;
      drawer.detail = d;
      drawer.members = d.members || [];
      renderDrawer();
    } catch (err) {
      if (drawer.id !== id) return;
      if (/no longer open/i.test(err.message)) {
        document.querySelector('#attnDrawerBody').innerHTML =
          '<div class="noc-empty">This incident has no alerts left in this view — it was acknowledged, snoozed, dismissed, muted or resolved.</div>';
        document.querySelector('#attnDrawerActions').innerHTML = '';
      } else
        document.querySelector('#attnDrawerBody').innerHTML =
          `<div class="noc-empty">Could not load details: ${escapeHtml(err.message)}</div>`;
    }
  }

  async function loadMoreMembers() {
    const d = drawer.detail;
    if (!d || drawer.loading) return;
    drawer.loading = true;
    const state = attentionView === 'possibly_resolved' || attentionView === 'all' ? '' : viewState();
    try {
      const more = await getJSON(
        `/api/dashboard/incidents/${encodeURIComponent(drawer.id)}?${new URLSearchParams({ offset: drawer.members.length, limit: 100, state })}`,
      );
      drawer.members = drawer.members.concat(more.members || []);
      renderDrawer();
    } finally {
      drawer.loading = false;
    }
  }

  function factRows(list = []) {
    return list
      .map(
        (f) =>
          `<div class="attn-fact"><span>${escapeHtml(f.label)}</span><b>${escapeHtml(factValue(f))}</b></div>`,
      )
      .join('');
  }

  function memberHtml(m) {
    const role = ROLE_LABEL[m.role] || typeLabel(m.device_type) || '';
    const where = [role, m.site, m.interface ? `port ${m.interface}` : ''].filter(Boolean).join(' · ');
    const stateChip = {
      new: '',
      acknowledged: `<span class="attn-flag ack" title="${escapeHtml(m.acknowledged_by || '')}">Acknowledged${m.acknowledged_by ? ` · ${escapeHtml(m.acknowledged_by)}` : ''}</span>`,
    }[m.state];
    const live =
      m.connected_now === true
        ? '<span class="attn-flag ok">Connected now</span>'
        : m.connected_now === false
          ? '<span class="attn-flag bad">Offline now</span>'
          : '';
    const times = [
      m.first_seen ? `since ${ago(m.first_seen * 1000)} ago` : '',
      m.last_seen && m.last_seen !== m.first_seen ? `last ${ago(m.last_seen * 1000)} ago` : '',
      m.device_last_seen && m.connected_now === false
        ? `device last seen ${ago(m.device_last_seen * 1000)} ago`
        : '',
      m.count > 1 ? `reported ${fmtN(m.count)}×` : '',
    ]
      .filter(Boolean)
      .join(' · ');
    const ports = m.device_type === 'switch' && m.site_id && m.device_id;
    const assigned = m.assignee
      ? `<span class="attn-flag assignee${isMeName(m.assignee) ? ' mine' : ''}">${escapeHtml(isMeName(m.assignee) ? 'Assigned to you' : `Assigned · ${m.assignee_display || m.assignee}`)}</span>`
      : '';
    const evidence = factRows(m.evidence) + factRows(m.reported);
    return `<li class="attn-member ${cssToken(m.state)}" data-key="${escapeHtml(m.key)}">
      <div class="attn-m-main"><div class="attn-m-title"><strong>${escapeHtml(m.device || m.site || m.title)}</strong>${stateChip || ''}${live}${m.flaps ? `<span class="attn-flag flap">Flapping ×${fmtN(m.flaps)}</span>` : ''}${m.possibly_resolved ? '<span class="attn-flag ok">Possibly resolved</span>' : ''}${assigned}</div>
        <small>${escapeHtml(where)}${m.title && m.device ? ` · ${escapeHtml(m.title)}` : ''}</small><small>${escapeHtml(times)}</small>
        ${m.detail ? `<p>${escapeHtml(m.detail)}</p>` : ''}
        ${evidence ? `<details><summary>Evidence &amp; details</summary><div class="attn-facts">${evidence}</div></details>` : ''}</div>
      <div class="attn-m-links">${m.console_url ? `<a href="#" class="btn ghost small" data-mist-link data-url="${escapeHtml(m.console_url)}" title="Open in ${escapeHtml(m.source_label)}">${escapeHtml(m.source_label)} ↗</a>` : ''}${m.mac || m.device ? `<button type="button" class="btn ghost small" data-find="${escapeHtml(m.mac || m.device)}" data-site-id="${escapeHtml(m.site_id || '')}" title="Find in Device Finder">Find</button>` : ''}${ports ? `<button type="button" class="btn ghost small" data-ports="1" data-site-id="${escapeHtml(m.site_id)}" data-device-id="${escapeHtml(m.device_id)}" data-port="${escapeHtml(m.interface || '')}" data-name="${escapeHtml(m.device || '')}" title="Open in Port Toolkit">Ports</button>` : ''}<button type="button" class="btn ghost small" data-member-menu="1" aria-haspopup="menu">Act ▾</button></div>
    </li>`;
  }

  function timelineHtml(t) {
    if (!t) return '';
    const hours = t.hours || [];
    const max = Math.max(1, ...hours);
    const bars = hours
      .map(
        (n, k) =>
          `<span class="attn-bar" data-h="${Math.round((n / max) * 100)}" title="${n} alert${n === 1 ? '' : 's'} first seen ${23 - k === 0 ? 'in the last hour' : `${23 - k}–${24 - k} h ago`}"></span>`,
      )
      .join('');
    const marks = (t.marks || [])
      .map(
        (m) =>
          `<li><b>${escapeHtml(m.label)}</b><span>${escapeHtml(new Date(m.time * 1000).toLocaleString())} (${escapeHtml(ago(m.time * 1000))} ago)</span><small>${escapeHtml(m.text)}</small></li>`,
      )
      .join('');
    return `<section class="attn-sec"><h4>Timeline <small>alerts first seen per hour, last 24 h${t.older ? ` · ${fmtN(t.older)} older` : ''}</small></h4><div class="attn-bars" role="img" aria-label="Alerts per hour over the last 24 hours">${bars}</div><div class="attn-bars-axis"><span>24 h ago</span><span>now</span></div><ul class="attn-marks">${marks}</ul></section>`;
  }

  function renderDrawer() {
    const d = drawer.detail;
    if (!d) return;
    // Auto-refresh re-renders the drawer: keep a half-written note.
    const draftEl = document.querySelector('#attnNoteText');
    const draft = draftEl?.value || '';
    const draftFocused = draftEl && document.activeElement === draftEl;
    const i = d.incident;
    const ex = d.explanation || {};
    const list = visibleIncidents();
    const at = list.findIndex((x) => x.id === i.id);
    document.querySelector('#attnDrawerTitle').textContent = i.title;
    document.querySelector('#attnDrawerPos').textContent =
      at >= 0 ? `Incident ${at + 1} of ${list.length} in this view` : '';
    document.querySelector('#attnDrawerMeta').innerHTML =
      `<span class="severity-badge ${cssToken(i.severity)}">${escapeHtml(i.severity)}</span>${sourceChips(i.sources)}<span class="attn-drawer-type">${escapeHtml(i.type_label)}</span>`;
    const actions = document.querySelector('#attnDrawerActions');
    const scopeState = attentionView === 'all' || attentionView === 'possibly_resolved' ? '' : viewState();
    const local = (inc.incidents || []).find((x) => x.id === i.id) || i;
    actions.innerHTML =
      actionButtonsHtml(local) +
      // The site deep link exists for Mist sites only; it is labelled with the source's own name.
      (i.site_id && (i.sources || []).some((s) => s.id === 'mist')
        ? `<a href="#" class="btn ghost small" data-mist-link data-site-id="${escapeHtml(i.site_id)}" title="Open the site in ${escapeHtml((i.sources || []).find((s) => s.id === 'mist')?.label || 'Mist')}">Site in ${escapeHtml((i.sources || []).find((s) => s.id === 'mist')?.label || 'Mist')} ↗</a>`
        : '');
    wireActionButtons(actions, { incidentId: i.id, incident: local, state: scopeState });
    wireMistLinks(actions);
    const sev =
      { critical: 'Critical', major: 'Major', warning: 'Warning', info: 'Info' }[i.severity] || i.severity;
    const facts = [
      ['What', ex.headline || i.type_label],
      ['Where', sitesText(i)],
      [
        'How many',
        `${fmtN(i.count)} alert${i.count === 1 ? '' : 's'}${i.device_count ? ` on ${fmtN(i.device_count)} device${i.device_count === 1 ? '' : 's'}` : ''}${i.site_count > 1 ? ` at ${fmtN(i.site_count)} sites` : ''}`,
      ],
      [
        'Since',
        i.first_seen
          ? `${new Date(i.first_seen * 1000).toLocaleString()} (${ago(i.first_seen * 1000)} ago)`
          : 'Not reported',
      ],
      ['Last reported', i.last_seen ? `${ago(i.last_seen * 1000)} ago` : 'Not reported'],
      ['How bad', `${sev}${i.flapping ? ` · ${fmtN(i.flapping)} flapping` : ''}`],
      ['State', `${fmtN(i.states?.new)} new · ${fmtN(i.states?.acknowledged)} acknowledged`],
    ]
      .map(([k, v]) => `<div class="attn-kv"><span>${escapeHtml(k)}</span><b>${escapeHtml(v)}</b></div>`)
      .join('');
    const causes = (ex.likely_causes || []).map((x) => `<li>${escapeHtml(x)}</li>`).join('');
    const steps = (ex.next_steps || []).map((x) => `<li>${escapeHtml(x)}</li>`).join('');
    const sites =
      i.site_count > 1
        ? `<section class="attn-sec"><h4>Per site <small>${fmtN(i.site_count)} sites</small></h4><ul class="attn-sites">${(
            i.sites || []
          )
            .map(
              (s) =>
                `<li><button type="button" class="link-btn" data-site-filter="${escapeHtml(s.name)}" title="Filter Command Center to this site">${escapeHtml(s.name)}</button><b>${fmtN(s.count)}</b></li>`,
            )
            .join('')}</ul></section>`
        : '';
    const remaining = d.total - drawer.members.length;
    document.querySelector('#attnDrawerBody').innerHTML = `
      <section class="attn-sec attn-summary"><p class="attn-lede">${escapeHtml(ex.summary || i.summary)}</p>${ex.rollup ? `<p class="attn-rollup">${escapeHtml(ex.rollup)}</p>` : ''}${ex.impact ? `<p class="muted"><b>Why it matters:</b> ${escapeHtml(ex.impact)}</p>` : ''}<div class="attn-kvs">${facts}</div></section>
      ${teamHtml(d.team, i)}
      ${steps ? `<section class="attn-sec"><h4>What to do</h4><ol class="attn-steps">${steps}</ol></section>` : ''}
      ${causes ? `<section class="attn-sec"><h4>Likely causes</h4><ul class="attn-causes">${causes}</ul></section>` : ''}
      <section class="attn-sec"><h4>Affected ${i.device_count ? 'devices' : 'alerts'} <small>${fmtN(d.total)} in this view${remaining > 0 ? ` · showing ${fmtN(drawer.members.length)}` : ''}</small></h4><ul class="attn-members">${drawer.members.map(memberHtml).join('') || '<li class="noc-empty">No alerts in this view.</li>'}</ul>${remaining > 0 ? `<button type="button" class="btn ghost small" id="attnMoreMembers">Show ${fmtN(Math.min(100, remaining))} more</button>` : ''}</section>
      ${timelineHtml(d.timeline)}
      ${sites}
      ${ex.mist_definition ? `<section class="attn-sec"><h4>Source definition</h4><p class="muted">${escapeHtml(ex.mist_definition)}</p></section>` : ''}`;
    const body = document.querySelector('#attnDrawerBody');
    body.querySelectorAll('.attn-bar').forEach((b) => b.style.setProperty('--h', `${b.dataset.h}%`));
    wireMistLinks(body);
    body.querySelector('#attnMoreMembers')?.addEventListener('click', loadMoreMembers);
    wireTeam(body, d.team);
    const noteEl = body.querySelector('#attnNoteText');
    if (noteEl && draft) {
      noteEl.value = draft;
      noteEl.dispatchEvent(new Event('input'));
      if (draftFocused) noteEl.focus({ preventScroll: true });
    }
    body.querySelectorAll('[data-find]').forEach((b) =>
      b.addEventListener('click', () => {
        closeDrawer();
        findInDeviceFinder(b.dataset.find, b.dataset.siteId);
      }),
    );
    body.querySelectorAll('[data-ports]').forEach((b) =>
      b.addEventListener('click', async () => {
        closeDrawer();
        await window.MistApp?.openTool('operations');
        window.MistTools.operations?.openPort?.(
          b.dataset.siteId,
          b.dataset.deviceId,
          b.dataset.port,
          b.dataset.name,
        );
      }),
    );
    body.querySelectorAll('[data-site-filter]').forEach((b) =>
      b.addEventListener('click', () => {
        closeDrawer();
        showSiteAlerts(b.dataset.siteFilter);
      }),
    );
    body.querySelectorAll('[data-member-menu]').forEach((b) =>
      b.addEventListener('click', (e) => {
        e.stopPropagation();
        const li = b.closest('.attn-member');
        const m = drawer.members.find((x) => x.key === li?.dataset.key);
        if (!m) return;
        const scope = { keys: [m.key], ackable: m.ackable, incident: local, state: m.state };
        const items = [];
        if (m.state === 'new')
          items.push(['ack', m.ackable ? 'Acknowledge… (asks first)' : 'Acknowledge in NodeWatch']);
        snoozeMenu().forEach(([v, l]) => items.push([`snooze:${v}`, `Snooze ${l.toLowerCase()}`]));
        dismissMenu().forEach(([v]) => items.push([`dismiss:${v}`, `Dismiss — ${v}`]));
        if (m.state === 'acknowledged') items.push(['restore', 'Clear NodeWatch acknowledgement']);
        openMenu(b, items, (v) => {
          if (v === 'ack') startAck({ ...scope, state: 'new' });
          else if (v === 'restore') runAction(scope, 'restore');
          else if (v.startsWith('snooze:')) runAction(scope, 'snooze', { duration: v.slice(7) });
          else if (v.startsWith('dismiss:')) runAction(scope, 'dismiss', { reason: v.slice(8) });
        });
      }),
    );
  }

  // ------------------------------------------------------------------ side panels
  function renderHealth() {
    const rows = data.health || [];
    document.querySelector('#healthList').innerHTML =
      rows
        .map((x) => {
          const pct = x.total ? Math.round((x.up / x.total) * 100) : 0;
          return `<button class="health-row health-button" data-type="${escapeHtml(x.device_type)}">
        <div class="health-head"><strong>${escapeHtml(x.type)}</strong><span>${x.total ? `${x.up}/${x.total} up` : 'No devices returned'}</span></div>
        <progress class="health-progress" max="100" value="${pct}" aria-label="${pct}% healthy"></progress>
        <div class="health-foot"><span class="ok-text">${x.up} up</span><span class="warn-text">${x.warning} warning</span><span class="bad-text">${x.down} down</span></div>
      </button>`;
        })
        .join('') || '<div class="noc-empty">No device statistics returned.</div>';
    document.querySelectorAll('.health-button').forEach((b) =>
      b.addEventListener('click', () => {
        deviceTypeFilter = b.dataset.type;
        groupFilter = '';
        attentionView = 'all';
        renderAttention();
        document.querySelector('.noc-attention-card')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
      }),
    );
  }

  // Issue Categories: built from the same open incidents as the list, so the numbers always match.
  function renderGroups() {
    const open = (inc.incidents || []).filter((i) => i.bucket === 'open');
    const byGroup = new Map();
    open.forEach((i) => {
      const g = i.group || categoryFor(i.type) || 'Other';
      if (!byGroup.has(g)) byGroup.set(g, []);
      byGroup.get(g).push(i);
    });
    const rows = [...byGroup.entries()]
      .map(([name, items]) => ({
        name,
        items,
        count: items.reduce((n, i) => n + i.count, 0),
        crit: items.filter(isCrit).reduce((n, i) => n + i.count, 0),
      }))
      .sort((a, b) => b.count - a.count || a.name.localeCompare(b.name));
    document.querySelector('#alarmGroups').innerHTML = rows.length
      ? rows
          .map((x) => {
            const warn = x.count - x.crit;
            const top = [...x.items]
              .sort((a, b) => b.count - a.count)
              .slice(0, 2)
              .map((i) => `${i.type_label} (${fmtN(i.count)})`)
              .join(' · ');
            const active = groupFilter === x.name;
            return `<button class="alarm-group-row group-button${active ? ' active' : ''}" data-group="${escapeHtml(x.name)}" aria-pressed="${active}" data-crit="${x.crit}" data-total="${Math.max(x.count, 1)}">
        <span class="group-dot ${x.crit ? 'critical' : 'warning'}"></span>
        <span class="group-copy"><span class="group-name">${escapeHtml(x.name)}</span><small>${x.crit ? `${fmtN(x.crit)} critical` : ''}${x.crit && warn ? ' · ' : ''}${warn ? `${fmtN(warn)} warning` : ''}${top ? ` — ${escapeHtml(top)}` : ''}</small><span class="group-bar"><span></span></span></span>
        <strong>${fmtN(x.count)}</strong><b>${active ? '×' : '›'}</b></button>`;
          })
          .join('')
      : '<div class="noc-empty">No active categories.</div>';
    document.querySelectorAll('.group-button').forEach((b) => {
      const pct = Math.round((Number(b.dataset.crit) / Number(b.dataset.total)) * 100);
      b.querySelector('.group-bar')?.style.setProperty('--crit', `${pct}%`);
      b.addEventListener('click', () => {
        const clear = groupFilter === b.dataset.group;
        groupFilter = clear ? '' : b.dataset.group;
        deviceTypeFilter = '';
        specialFilter = '';
        activeTile = '';
        attentionView = clear ? 'needs' : 'all';
        summaryCards();
        renderGroups();
        renderAttention();
        if (!clear)
          document
            .querySelector('.noc-attention-card')
            ?.scrollIntoView({ behavior: 'smooth', block: 'start' });
      });
    });
  }

  function renderSites() {
    const rows = data.sites || [];
    document.querySelector('#siteHealth').innerHTML = rows.length
      ? rows
          .map((x) => {
            const metric =
              x.availability === null || x.availability === undefined ? x.health : x.availability;
            const avail = metric === null || metric === undefined ? '—' : `${metric}%`;
            const cls = metric !== null && metric !== undefined && metric < 98.5 ? 'warning' : '';
            const deviceText =
              x.devices_total !== undefined
                ? `${x.devices_connected}/${x.devices_total} devices connected`
                : 'Connectivity summary';
            return `<button class="site-health-row site-button" data-site="${escapeHtml(x.name)}">
        <div><strong>${escapeHtml(x.name)}</strong><small>${deviceText} · ${x.critical ?? 0} critical · ${x.warning ?? 0} warning</small></div>
        <div class="site-score ${cls}" title="Current managed-device connectivity from Mist site stats"><span>${avail}</span><small>Availability</small></div>
      </button>`;
          })
          .join('')
      : '<div class="noc-empty">No sites returned.</div>';
    document
      .querySelectorAll('.site-button')
      .forEach((b) => b.addEventListener('click', () => showSiteAlerts(b.dataset.site)));
  }

  function renderEvents() {
    const rows = data.recent_events || [];
    document.querySelector('#recentEvents').innerHTML = rows.length
      ? rows
          .map(
            (x) => `
      <div class="event-row ${cssToken(x.state)}"><time>${escapeHtml(x.time)}</time><span class="event-state-dot"></span><div><strong>${escapeHtml(x.type)}</strong><small>${escapeHtml(x.device)} · ${escapeHtml(x.site)}</small></div><span class="event-state ${cssToken(x.state)}">${escapeHtml(x.state)}</span></div>`,
          )
          .join('')
      : '<div class="noc-empty">No recent device events returned.</div>';
  }

  function populateFilters() {
    const select = document.querySelector('#nocSiteFilter');
    if (!select) return;
    const current = select.value;
    select.innerHTML =
      '<option>All Sites</option>' +
      (data.sites || []).map((x) => `<option>${escapeHtml(x.name)}</option>`).join('');
    if ([...select.options].some((o) => o.value === current)) select.value = current;
  }

  function factValue(f) {
    if (f.kind === 'time') {
      const d = new Date(Number(f.value));
      return Number.isNaN(d.getTime()) ? String(f.value) : `${d.toLocaleString()} (${ago(f.value)} ago)`;
    }
    return String(f.value ?? '');
  }

  function disconnectPayload(x) {
    return {
      key: x.dismiss_key || '',
      device: x.device || 'Known-down device',
      device_type: x.device_type || 'device',
      mac: x.mac || '',
      site: x.site || '',
      note: 'Known down / intentionally suppressed by engineer',
    };
  }

  async function markDisconnectsKnown(items) {
    const clean = (items || []).filter((x) => x?.dismiss_key);
    if (!clean.length) return;
    try {
      await postJSON('/api/dashboard/disconnects/dismiss/bulk', { items: clean.map(disconnectPayload) });
      await refresh(false, true);
    } catch (err) {
      alert('Unable to mark disconnects as known: ' + err.message);
    }
  }

  function renderDisconnectWatch() {
    const w = data?.disconnect_watch || {};
    const state = document.querySelector('#disconnectWatchState');
    const summary = document.querySelector('#disconnectWatchSummary');
    const clusters = document.querySelector('#disconnectClusters');
    const devices = document.querySelector('#disconnectDevices');
    if (!state || !summary || !clusters || !devices) return;
    const allDevices = w.devices || [];
    const critical = (w.clusters || []).some((x) => x.severity === 'critical');
    state.textContent = critical
      ? 'Possible outage detected'
      : w.active_down
        ? `${w.active_down} currently down`
        : 'No active disconnects';
    state.className = `count ${critical ? 'critical-text' : ''}`;
    summary.innerHTML = [
      ['down', 'Currently down', w.active_down || 0],
      ['new', 'New · 15 min', w.new_last_15m || 0],
      ['recovered', 'Recovered · 15 min', w.recovered_last_15m || 0],
      ['sites', 'Sites affected', w.sites_impacted || 0],
    ]
      .map(
        ([k, l, v]) =>
          `<button type="button" class="dw-tile" data-dw="${k}" title="Show ${escapeHtml(l.toLowerCase())}"><strong>${escapeHtml(v)}</strong><span>${escapeHtml(l)}</span></button>`,
      )
      .join('');
    summary
      .querySelectorAll('[data-dw]')
      .forEach((b) => b.addEventListener('click', () => showDisconnectList(b.dataset.dw)));
    clusters.innerHTML = (w.clusters || []).length
      ? (w.clusters || [])
          .map(
            (c) =>
              `<article class="disconnect-cluster ${escapeHtml(c.severity)}"><div><strong>${escapeHtml(c.label)}</strong><span>${escapeHtml(c.site)}</span></div><b>${escapeHtml(c.down)} / ${escapeHtml(c.total || '?')} down${c.percent_down !== null && c.percent_down !== undefined ? ` · ${escapeHtml(c.percent_down)}%` : ''}</b><p>${escapeHtml(c.message)}</p><button class="btn ghost small mark-site-known" data-site-id="${escapeHtml(c.site_id || '')}" data-site-name="${escapeHtml(c.site || 'site')}">Mark site losses known</button></article>`,
          )
          .join('')
      : '<div class="disconnect-clear"><span>✓</span><div><strong>No multi-device outage cluster detected</strong><small>Individual disconnects are listed below.</small></div></div>';
    const knownDown = w.dismissed_known_down || 0;
    const knownBtn = `<button id="knownDownBtn" class="btn ghost small" title="Devices you marked as known down">Known down · ${knownDown}</button>`;
    if (allDevices.length) {
      const LIMIT = 6;
      const shown = showAllDown ? allDevices : allDevices.slice(0, LIMIT);
      devices.innerHTML = `<div class="dw-head"><div><strong>Currently down</strong><span>${allDevices.length} device${allDevices.length === 1 ? '' : 's'} need review</span></div><div class="dw-head-actions">${knownBtn}<button id="disconnectMarkAllKnown" class="btn ghost small">Mark all as known</button></div></div>
        <ul class="dw-list">${shown.map((x) => downRowHtml(x, true)).join('')}</ul>
        ${allDevices.length > LIMIT ? `<button type="button" class="link-btn dw-more" id="dwShowAll">${showAllDown ? 'Show fewer' : `Show all ${allDevices.length}`}</button>` : ''}`;
    } else {
      devices.innerHTML = `<div class="dw-head"><div><strong>No current losses</strong><span>Nothing needs review right now.</span></div><div class="dw-head-actions">${knownBtn}</div></div>`;
    }
    document.querySelector('#dwShowAll')?.addEventListener('click', () => {
      showAllDown = !showAllDown;
      renderDisconnectWatch();
    });
    wireMistLinks(devices);
    document
      .querySelector('#disconnectMarkAllKnown')
      ?.addEventListener('click', () => markDisconnectsKnown(allDevices));
    document
      .querySelectorAll('.mark-site-known')
      .forEach((b) =>
        b.addEventListener('click', () =>
          markDisconnectsKnown(
            allDevices.filter((x) => String(x.site_id || '') === String(b.dataset.siteId || '')),
          ),
        ),
      );
    devices
      .querySelectorAll('[data-disconnect-site]')
      .forEach((b) => b.addEventListener('click', () => showSiteAlerts(b.dataset.disconnectSite)));
    document.querySelectorAll('.mark-known').forEach((b) =>
      b.addEventListener('click', async (e) => {
        e.stopPropagation();
        if (!b.dataset.disconnectKey) return;
        b.disabled = true;
        b.textContent = 'Saving...';
        try {
          await postJSON('/api/dashboard/disconnects/dismiss', {
            key: b.dataset.disconnectKey,
            device: b.dataset.device,
            device_type: b.dataset.deviceType,
            mac: b.dataset.mac,
            site: b.dataset.site,
          });
          await refresh(false, true);
        } catch (err) {
          alert('Unable to mark disconnect as known: ' + err.message);
        } finally {
          b.disabled = false;
        }
      }),
    );
    document.querySelector('#knownDownBtn')?.addEventListener('click', showKnownDown);
  }

  // One row in a "down devices" list: status dot · name + type/site · how long down · actions.
  function downRowHtml(x, withMarkKnown = false, ageLabel = 'Down') {
    const age = x.last_seen
      ? ago(Number(x.last_seen) * 1000)
      : x.timestamp
        ? ago(Number(x.timestamp) * 1000)
        : x.age;
    const major = x.device_type === 'switch' || x.device_type === 'gateway';
    return `<li class="dw-row">
      <span class="dw-dot ${major ? 'critical' : ''}" aria-hidden="true"></span>
      <button type="button" class="dw-name" data-disconnect-site="${escapeHtml(x.site)}" title="Show this site's alerts"><strong>${escapeHtml(x.device || 'Unknown device')}</strong><small>${escapeHtml(typeLabel(x.device_type))} · ${escapeHtml(x.site || 'Unknown site')}</small></button>
      <span class="dw-age">${age && age !== 'unknown' ? `${escapeHtml(ageLabel)} ${escapeHtml(age)}` : ''}</span>
      <span class="dw-row-actions">${x.mac || x.mist_url ? mistLinkHtml(x) : ''}${
        withMarkKnown
          ? `<button class="btn ghost small mark-known" data-disconnect-key="${escapeHtml(x.dismiss_key || '')}" data-device="${escapeHtml(x.device)}" data-device-type="${escapeHtml(x.device_type)}" data-mac="${escapeHtml(x.mac || '')}" data-site="${escapeHtml(x.site)}">Mark known</button>`
          : `<button class="btn ghost small dw-find" data-mac="${escapeHtml(x.mac || x.device || '')}" data-site-id="${escapeHtml(x.site_id || '')}">Find</button>`
      }</span>
    </li>`;
  }

  // Disconnect Watch tiles open the matching list.
  function showDisconnectList(kind) {
    const w = data?.disconnect_watch || {};
    const dlg = document.querySelector('#nocListDialog');
    const body = document.querySelector('#nocListBody');
    if (!dlg || !body) return;
    const now = Date.now() / 1000;
    const recent = (rows) => (rows || []).filter((x) => now - Number(x.timestamp || 0) <= 900);
    let title = '';
    let help = '';
    let html = '';
    if (kind === 'down') {
      title = `Currently down (${(w.devices || []).length})`;
      help = 'Access points, switches and gateways Mist reports as disconnected right now.';
      html = (w.devices || []).map((x) => downRowHtml(x)).join('');
    } else if (kind === 'new') {
      const rows = recent(w.recent_disconnects);
      title = `Disconnected in the last 15 minutes (${rows.length})`;
      help = 'Devices whose disconnect event Mist reported in the last 15 minutes.';
      html = rows.map((x) => downRowHtml(x, false, 'Dropped')).join('');
    } else if (kind === 'recovered') {
      const rows = recent(w.recent_recoveries);
      title = `Recovered in the last 15 minutes (${rows.length})`;
      help = 'Devices that reconnected to Mist in the last 15 minutes.';
      html = rows.map((x) => downRowHtml(x, false, 'Back')).join('');
    } else if (kind === 'sites') {
      const bySite = new Map();
      (w.devices || []).forEach((x) => {
        const k = x.site || 'Unknown site';
        if (!bySite.has(k)) bySite.set(k, []);
        bySite.get(k).push(x);
      });
      const sites = [...bySite.entries()].sort(
        (a, b) => b[1].length - a[1].length || a[0].localeCompare(b[0]),
      );
      title = `Sites affected (${sites.length})`;
      help = 'Sites with at least one device down. Choose a site to see its alerts.';
      html = sites
        .map(
          ([site, rows]) =>
            `<li class="dw-row site"><span class="dw-dot ${rows.length > 1 ? 'critical' : ''}" aria-hidden="true"></span><button type="button" class="dw-name" data-disconnect-site="${escapeHtml(site)}"><strong>${escapeHtml(site)}</strong><small>${escapeHtml(
              rows
                .slice(0, 4)
                .map((r) => r.device)
                .join(', ') + (rows.length > 4 ? ` +${rows.length - 4} more` : ''),
            )}</small></button><span class="dw-age">${rows.length} down</span><span class="dw-row-actions"><button type="button" class="btn ghost small" data-disconnect-site="${escapeHtml(site)}">Show alerts</button></span></li>`,
        )
        .join('');
    }
    document.querySelector('#nocListTitle').textContent = title;
    document.querySelector('#nocListHelp').textContent = help;
    body.innerHTML = html
      ? `<ul class="dw-list">${html}</ul>`
      : '<div class="noc-empty">Nothing in this list right now.</div>';
    wireMistLinks(body);
    body.querySelectorAll('.dw-find').forEach((b) =>
      b.addEventListener('click', () => {
        dlg.close();
        findInDeviceFinder(b.dataset.mac, b.dataset.siteId);
      }),
    );
    body.querySelectorAll('[data-disconnect-site]').forEach((b) =>
      b.addEventListener('click', () => {
        dlg.close();
        showSiteAlerts(b.dataset.disconnectSite);
      }),
    );
    if (!dlg.open) dlg.showModal();
  }

  function showKnownDown() {
    const dlg = document.querySelector('#knownDownDialog');
    const rows = data?.disconnect_watch?.dismissed_devices || [];
    const host = document.querySelector('#knownDownList');
    const restoreAll = document.querySelector('#restoreAllKnownDown');
    if (!dlg || !host) return;
    host.innerHTML = rows.length
      ? rows
          .map(
            (x) =>
              `<div class="dismissed-row"><div><strong>${escapeHtml(x.device || 'Known-down device')}</strong><small>${escapeHtml(x.device_type || 'device')} · ${escapeHtml(x.site || '')} ${x.mac ? `· ${escapeHtml(x.mac)}` : ''}</small></div><button class="btn ghost restore-known-down" data-key="${escapeHtml(x.key || '')}">Restore</button></div>`,
          )
          .join('')
      : '<div class="noc-empty">No locally suppressed known-down devices.</div>';
    if (restoreAll) {
      restoreAll.classList.toggle('hidden', !rows.length);
      restoreAll.onclick = async () => {
        restoreAll.disabled = true;
        try {
          await postJSON('/api/dashboard/disconnects/dismiss/restore-all');
          dlg.close();
          await refresh(false, true);
        } catch (err) {
          alert('Unable to restore known-down devices: ' + err.message);
        } finally {
          restoreAll.disabled = false;
        }
      };
    }
    document.querySelectorAll('.restore-known-down').forEach((b) =>
      b.addEventListener('click', async () => {
        await postJSON(
          `/api/dashboard/disconnects/dismiss/${encodeURIComponent(b.dataset.key).replaceAll('%2F', '/')}/restore`,
        );
        await refresh(false, true);
        showKnownDown();
      }),
    );
    if (!dlg.open) dlg.showModal();
  }

  function showSiteAlerts(site) {
    const sel = document.querySelector('#nocSiteFilter');
    if (sel && [...sel.options].some((o) => o.value === site)) {
      sel.value = site;
      sel.dispatchEvent(new Event('change'));
    }
    attentionView = 'all';
    groupFilter = '';
    specialFilter = '';
    activeTile = '';
    deviceTypeFilter = '';
    summaryCards();
    renderAttention();
    document.querySelector('.noc-attention-card')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  function clearDrillFilter() {
    specialFilter = '';
    activeTile = '';
    groupFilter = '';
    deviceTypeFilter = '';
    const site = document.querySelector('#nocSiteFilter');
    if (site && site.value !== 'All Sites') {
      site.value = 'All Sites';
      site.dispatchEvent(new Event('change'));
    }
    const sev = document.querySelector('#nocSeverityFilter');
    if (sev) sev.selectedIndex = 0;
    const q = document.querySelector('#nocSearch');
    if (q) q.value = '';
    summaryCards();
    renderGroups();
    renderAttention();
  }

  async function refresh(force = false, silent = false) {
    if (nocRefreshBusy) return;
    nocRefreshBusy = true;
    const btn = document.querySelector('#globalRefresh');
    if (btn && !silent) {
      btn.disabled = true;
      btn.textContent = 'Refreshing...';
    }
    try {
      data = await getJSON(`/api/dashboard${force ? '?refresh=true' : ''}`);
      // v0.10.24: Command Center's health panels read Mist. With only other vendors connected, the
      // backend's sample data must not look like the real network: show an empty state instead (the
      // Alerts & Notifications feed below still carries every connected source's alerts).
      const otherSourcesOnly =
        String(data.mode || '').startsWith('simulation') &&
        !!window.MistApp?.lastStatus?.()?.any_source_configured;
      showOtherSourcesState(otherSourcesOnly);
      if (otherSourcesOnly) {
        lastLoadedAt = Date.now();
        return;
      }
      if (data.incidents) applyPayloadQuiet(data.incidents);
      summaryCards();
      populateFilters();
      renderDisconnectWatch();
      renderAttention();
      renderHealth();
      renderGroups();
      renderSites();
      renderEvents();
      if (attentionView === 'suppressed') renderSuppressed(true);
      if (drawer.id && drawerOpen()) loadDrawer(drawer.id, true);
      const d = new Date(data.last_updated);
      const sample = String(data.mode || '').startsWith('simulation');
      const modeLabel = document.querySelector('#nocModeLabel');
      if (modeLabel) {
        modeLabel.textContent = sample ? 'SAMPLE DATA — Mist not connected' : '';
        modeLabel.classList.toggle('hidden', !sample);
      }
      document.querySelector('.noc-refresh-meta')?.classList.toggle('sample-mode', sample);
      document.querySelector('#nocUpdated').textContent = sample
        ? 'Example numbers only. Connect Mist in Settings & Support to see your network.'
        : `Updated ${Number.isNaN(d.getTime()) ? data.last_updated : d.toLocaleString()}`;
      lastLoadedAt = Date.now();
      updateCountdown();
      if (force) {
        // Alerts & Notifications lives on this page; Refresh NOC re-checks it too.
        window.MistTools.alerting
          ?.refresh?.(true, true)
          .catch((e) => console.warn('Alert refresh failed', e));
        if (window.MistApp?.refreshConnectionStatus) await window.MistApp.refreshConnectionStatus(true);
      }
    } finally {
      nocRefreshBusy = false;
      if (btn && !silent) {
        btn.disabled = false;
        btn.textContent = 'Refresh NOC';
      }
    }
  }

  function showOtherSourcesState(on) {
    const view = document.querySelector('#view-dashboard');
    if (!view) return;
    const keep = document.querySelector('#nocAlerts')?.closest('#view-dashboard > *');
    let box = document.querySelector('#nocOtherSources');
    if (on && !box) {
      box = document.createElement('section');
      box.id = 'nocOtherSources';
      box.className = 'card content-card';
      view.prepend(box);
    }
    if (box) {
      box.classList.toggle('hidden', !on);
      if (on) {
        const products = window.MistApp?.lastStatus?.()?.connected_products || [];
        box.innerHTML =
          '<div class="eyebrow">Command Center</div><h3>Site health and Disconnect Watch need Juniper Mist</h3>' +
          `<p class="muted">Connected: ${escapeHtml(products.join(', ') || 'other network sources')}. ` +
          'Their devices, links and tunnels are on the Topology page; their alerts are in Alerts &amp; Notifications below. ' +
          'Connect Mist in Settings &amp; Support to fill the rest of this page.</p>' +
          '<div class="editor-actions left"><button type="button" class="btn primary" data-open-topology>Open Topology</button></div>';
        box.querySelector('[data-open-topology]')?.addEventListener('click', () => window.MistApp?.openTool?.('topology'));
      }
    }
    [...view.children].forEach((child) => {
      if (child === box || child === keep) return;
      if (on) {
        if (!child.classList.contains('hidden')) {
          child.dataset.otherSourcesHidden = '1';
          child.classList.add('hidden');
        }
      } else if (child.dataset.otherSourcesHidden) {
        delete child.dataset.otherSourcesHidden;
        child.classList.remove('hidden');
      }
    });
  }

  function applyPayloadQuiet(p) {
    inc = {
      incidents: p.incidents || [],
      counts: p.counts || {},
      noisy_types: p.noisy_types || [],
      sources: p.sources || [],
      dismiss_reasons: p.dismiss_reasons || [],
      source_errors: p.source_errors || [],
      team: p.team || {},
    };
  }

  function updateCountdown() {
    const el = document.querySelector('#nocCountdown');
    if (!el) return;
    if (nocRefreshBusy) {
      el.textContent = 'Refreshing…';
      return;
    }
    const secs = Math.max(0, Math.ceil((nextAutoAt - Date.now()) / 1000));
    el.textContent = `Refresh in ${secs}s`;
  }

  // Quick search: finds any device or client anywhere (Device Finder search) and shows it first.
  function quickSearch() {
    const q = (document.querySelector('#nocSearch')?.value || '').trim();
    const panel = document.querySelector('#nocSearchResults');
    if (!panel) return;
    clearTimeout(quickSearchTimer);
    if (q.length < 2) {
      panel.classList.add('hidden');
      panel.innerHTML = '';
      return;
    }
    quickSearchTimer = setTimeout(async () => {
      const seq = ++quickSearchSeq;
      panel.classList.remove('hidden');
      panel.innerHTML = `<div class="noc-search-head"><strong>Searching devices and clients for “${escapeHtml(q)}”…</strong></div>`;
      let results = [];
      let failed = '';
      try {
        const res = await getJSON(`/api/detective/search?${new URLSearchParams({ q })}`);
        results = res.results || [];
      } catch (err) {
        failed = err.message;
      }
      if (seq !== quickSearchSeq) return;
      // Open incidents mentioning this device (name or MAC) — same data as the list below.
      const alertsFor = (r) => {
        const needles = [
          r.title,
          String(r.mac || '')
            .toLowerCase()
            .replace(/[^0-9a-f]/g, ''),
        ]
          .filter((x) => x && String(x).length > 2)
          .map((x) => String(x).toLowerCase());
        return (inc.incidents || []).filter(
          (i) => i.bucket === 'open' && needles.some((n) => i.search.includes(n)),
        ).length;
      };
      const top = results.slice(0, 8);
      const alertsMatching = visibleIncidents().length;
      panel.innerHTML = `<div class="noc-search-head"><div><strong>${results.length ? `${results.length} device${results.length === 1 ? '' : 's'} or client${results.length === 1 ? '' : 's'} found for “${escapeHtml(q)}”` : failed ? 'Search failed' : `No devices or clients found for “${escapeHtml(q)}”`}</strong><small>${failed ? escapeHtml(failed) : alertsMatching ? `${alertsMatching} matching incident${alertsMatching === 1 ? ' is' : 's are'} listed below · Enter opens Device Finder` : 'Choose a result to open it in Device Finder · Enter searches there'}</small></div><div class="noc-search-actions">${results.length > top.length ? `<button type="button" class="btn ghost small" id="nocSearchAll">See all ${results.length} in Device Finder</button>` : ''}<button type="button" class="icon-btn" id="nocSearchClose" aria-label="Clear search">×</button></div></div>
        ${
          top.length
            ? `<div class="noc-search-grid">${top
                .map((r, i) => {
                  const n = alertsFor(r);
                  const where = [
                    r.ip,
                    r.site,
                    r.attachment ? `${r.attachment}${r.port_id ? ` · ${r.port_id}` : ''}` : '',
                  ]
                    .filter(Boolean)
                    .join(' · ');
                  return `<button type="button" class="noc-search-hit" data-i="${i}"><span class="noc-hit-kind">${escapeHtml(r.kind_label || r.kind || 'Device')}</span><strong>${escapeHtml(r.title || r.display_mac || r.mac)}</strong><small>${escapeHtml(where || r.subtitle || '')}</small><span class="noc-hit-foot">${escapeHtml(r.display_mac || '')}${r.last_seen ? ` · seen ${escapeHtml(r.last_seen)}` : ''}${n ? ` · <b class="bad-text">${n} incident${n === 1 ? '' : 's'}</b>` : ''}</span></button>`;
                })
                .join('')}</div>`
            : ''
        }`;
      panel.querySelector('#nocSearchClose')?.addEventListener('click', () => {
        document.querySelector('#nocSearch').value = '';
        quickSearch();
        renderAttention();
      });
      panel.querySelector('#nocSearchAll')?.addEventListener('click', () => findInDeviceFinder(q));
      panel.querySelectorAll('.noc-search-hit').forEach((b) =>
        b.addEventListener('click', () => {
          const r = top[Number(b.dataset.i)];
          findInDeviceFinder(r.display_mac || r.mac || r.title, r.site_id || '');
        }),
      );
    }, 350);
  }

  async function renderRoadmap() {
    const host = document.querySelector('#platformOverviewContent');
    if (!host) return;
    const content = await getJSON('/api/platform-overview/content');
    const roadmap = content.roadmap || [];
    const core = content.shared_core || {};
    const steps = content.write_safety || [];
    host.innerHTML = `
      <div class="card content-card">
        <div class="section-heading compact"><div><div class="eyebrow">Product roadmap</div><h3>Network Operations Platform</h3></div><span class="roadmap-principle">${escapeHtml(content.principle || '')}</span></div>
        <p class="muted">Shared operational modules use one normalized data model, cache, transaction safety layer, and audit service.</p>
        <div class="roadmap-grid">${roadmap.map((x, i) => `<article class="roadmap-card"><div class="roadmap-top"><span class="roadmap-icon">${x.icon}</span><span class="roadmap-status">${escapeHtml(x.status)}</span></div><strong>${i + 2}. ${escapeHtml(x.label)}</strong><span class="roadmap-category">${escapeHtml(x.category)}</span><p>${escapeHtml(x.description)}</p></article>`).join('')}</div>
      </div>
      <div class="architecture-grid">
        <section class="card noc-panel"><div class="eyebrow">Shared core</div><h3>One data layer for every tool</h3><div class="architecture-flow"><div class="arch-node primary-node">${escapeHtml(core.source || 'Provider APIs / Webhooks')}</div><div class="arch-arrow">↓</div><div class="arch-node">${escapeHtml(core.data_layer || 'Shared Client + Cache')}</div><div class="arch-arrow">↓</div><div class="arch-row">${(core.services || []).map((x) => `<span>${escapeHtml(x)}</span>`).join('')}</div><div class="arch-arrow">↓</div><div class="arch-row">${(core.consumers || []).map((x) => `<span>${escapeHtml(x)}</span>`).join('')}</div></div></section>
        <section class="card noc-panel"><div class="eyebrow">Write safety</div><h3>All changes become transactions</h3><ol class="transaction-list">${steps.map((x) => `<li>${escapeHtml(x)}</li>`).join('')}</ol></section>
      </div>`;
  }

  async function init() {
    // v0.10.40: the data request starts first and the alerts panel loads alongside it (it used to wait
    // for the Command Center data); the controls are wired straight away and init settles when the
    // first data has been drawn.
    const firstLoad = refresh(false);
    // Alerts & Notifications (formerly Notification Hub) starts with Command Center, so browser
    // alerts work from launch instead of only after visiting a separate page.
    window.MistTools.alerting?.init?.().catch((e) => {
      console.warn('Alerts & Notifications unavailable', e);
      const state = document.querySelector('#alertingState');
      if (state) state.textContent = 'Unavailable';
    });
    document.querySelector('#nocSiteFilter')?.addEventListener('change', () => {
      groupFilter = '';
      deviceTypeFilter = '';
      renderAttention();
      scrollAttentionTop();
    });
    document.querySelector('#nocSeverityFilter')?.addEventListener('change', () => {
      renderAttention();
      scrollAttentionTop();
    });
    document.querySelector('#nocSearch')?.addEventListener('input', () => {
      renderAttention();
      scrollAttentionTop();
      quickSearch();
    });
    document.querySelector('#nocSearch')?.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') {
        e.target.value = '';
        quickSearch();
        renderAttention();
      } else if (e.key === 'Enter') {
        e.preventDefault();
        clearTimeout(quickSearchTimer);
        const q = e.target.value.trim();
        if (q.length >= 2) findInDeviceFinder(q);
      }
    });
    document.querySelectorAll('[data-attention-view]').forEach((b) =>
      b.addEventListener('click', () => {
        setAttentionView(b.dataset.attentionView);
        scrollAttentionTop();
      }),
    );
    document.querySelector('#attentionSort')?.addEventListener('change', (e) => {
      attentionSort = e.target.value;
      renderAttention();
      scrollAttentionTop();
    });
    document.querySelector('#globalRefresh')?.addEventListener('click', () => refresh(true));
    document.querySelector('#clearIssueFilter')?.addEventListener('click', clearDrillFilter);
    document
      .querySelector('#openAlertingCenter')
      ?.addEventListener('click', () =>
        document.querySelector('#nocAlerts')?.scrollIntoView({ behavior: 'smooth', block: 'start' }),
      );
    // Incident drawer + menus: close / keyboard navigation.
    document.querySelector('#attnDrawerClose')?.addEventListener('click', closeDrawer);
    document.querySelector('#attnDrawerBackdrop')?.addEventListener('click', closeDrawer);
    document.querySelector('#attnDrawerPrev')?.addEventListener('click', () => moveDrawer(-1));
    document.querySelector('#attnDrawerNext')?.addEventListener('click', () => moveDrawer(1));
    document.addEventListener('click', (e) => {
      if (menuOpen() && !e.target.closest('#attnPopover')) closeMenu();
    });
    window.addEventListener('resize', closeMenu);
    document.addEventListener(
      'scroll',
      (e) => {
        if (menuOpen() && !e.target?.closest?.('#attnPopover')) closeMenu();
      },
      true,
    );
    document.addEventListener('keydown', (e) => {
      if (document.querySelector('#attnAckDialog')?.open) return;
      if (e.key === 'Escape' && menuOpen()) {
        e.preventDefault();
        closeMenu();
        return;
      }
      if (!drawerOpen()) return;
      const typing = /^(INPUT|SELECT|TEXTAREA)$/.test(e.target?.tagName || '');
      if (e.key === 'Escape') {
        e.preventDefault();
        closeDrawer();
      } else if (!typing && !menuOpen() && (e.key === 'ArrowDown' || e.key === 'ArrowUp')) {
        e.preventDefault();
        moveDrawer(e.key === 'ArrowDown' ? 1 : -1);
      }
    });
    if (!nocAutoTimer)
      nocAutoTimer = setInterval(() => {
        nextAutoAt = Date.now() + NOC_AUTO_REFRESH_MS;
        const view = document.querySelector('#view-dashboard');
        if (document.visibilityState === 'visible' && view && !view.classList.contains('hidden'))
          refresh(false, true).catch((e) => console.warn('NOC auto-refresh failed', e));
      }, NOC_AUTO_REFRESH_MS);
    nextAutoAt = Date.now() + NOC_AUTO_REFRESH_MS;
    if (!countdownTimer) countdownTimer = setInterval(updateCountdown, 1000);
    document.addEventListener('visibilitychange', () => {
      const view = document.querySelector('#view-dashboard');
      // Back in view: refresh only if the data is older than one auto-refresh period (every focus
      // switch used to rebuild the whole Command Center).
      if (
        document.visibilityState === 'visible' &&
        view &&
        !view.classList.contains('hidden') &&
        Date.now() - lastLoadedAt >= NOC_AUTO_REFRESH_MS
      )
        refresh(false, true).catch(() => {});
    });
    // A failed first load is reported by refresh() and retried by the 20 s cycle; it must not fail init
    // (the shell would run init again and register every control a second time).
    await firstLoad.catch((e) => console.warn('Command Center first load failed', e));
  }

  // Dashboard owns its tighter 20-second refresh cadence; avoid a duplicate global refresh.
  return { init, refresh, autoRefresh: async () => {}, renderRoadmap };
})();

window.MistTools['future-tools'] = {
  init: async () => {
    const m = window.MistTools.dashboard;
    if (m?.renderRoadmap) await m.renderRoadmap();
  },
};
