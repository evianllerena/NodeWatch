// NodeWatch v0.10.15 – Config Backups: configuration safety net for Mist.
// Landing view answers: when was config last captured, what changed since, who changed it,
// and can it be rolled back. Every Mist write goes through a preview + explicit confirmation.
const backupEsc = (v) =>
  String(v ?? '').replace(
    /[&<>"']/g,
    (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c],
  );

window.MistTools.configBackup = (() => {
  const API = '/api/v1/config-backup';
  const TRIGGERS = {
    scheduled: 'Scheduled',
    manual: 'Manual',
    'pre-change': 'Before change',
    baseline: 'Baseline',
    import: 'Imported',
    legacy: 'Earlier backup',
    live: 'Live Mist',
  };
  const state = {
    siteId: '',
    sites: [],
    overview: null,
    snapshots: [],
    a: '',
    b: 'live',
    tab: 'changes',
    driftFor: null,
    loading: false,
    seq: 0,
  };
  let initd = false;
  const $ = (sel) => document.querySelector(sel);

  async function j(url, opts) {
    const r = await fetch(url, opts);
    const d = await r.json().catch(() => ({ detail: r.statusText }));
    if (!r.ok) throw new Error(typeof d.detail === 'string' ? d.detail : r.statusText);
    return d;
  }
  const post = (url, body) =>
    j(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
  const qs = (o) =>
    Object.entries(o)
      .filter(([, v]) => v !== '' && v != null && v !== false)
      .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`)
      .join('&');

  // ------------------------------------------------------------------ formatting
  function when(iso) {
    if (!iso) return '';
    const d = new Date(iso);
    return Number.isNaN(d.getTime())
      ? ''
      : d.toLocaleString(undefined, { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' });
  }
  function ago(iso) {
    if (!iso) return 'never';
    const s = (Date.now() - new Date(iso).getTime()) / 1000;
    if (!Number.isFinite(s)) return '';
    if (s < 0) {
      const f = -s;
      if (f < 3600) return `in ${Math.max(1, Math.round(f / 60))} min`;
      if (f < 172800) return `in ${Math.round(f / 3600)} h`;
      return `in ${Math.round(f / 86400)} days`;
    }
    if (s < 60) return 'just now';
    if (s < 3600) return `${Math.round(s / 60)} min ago`;
    if (s < 172800) return `${Math.round(s / 3600)} h ago`;
    return `${Math.round(s / 86400)} days ago`;
  }
  const plural = (n, word, many) => `${n} ${n === 1 ? word : many || `${word}s`}`;
  const isSecret = (v) => typeof v === 'string' && v.startsWith('***REDACTED');
  // ``limit`` truncates long values (one-line headlines); the expanded change list shows them in full.
  function val(v, limit = 90) {
    if (v === null || v === undefined || v === '') return '—';
    if (isSecret(v)) return 'hidden';
    if (typeof v === 'boolean') return v ? 'on' : 'off';
    if (Array.isArray(v)) {
      if (!v.length) return '(none)';
      if (v.every((x) => typeof x !== 'object' || x === null)) {
        const t = v.map((x) => (isSecret(x) ? 'hidden' : String(x))).join(', ');
        return t.length > limit ? `${t.slice(0, limit - 2)}…` : t;
      }
      return plural(v.length, 'item');
    }
    if (typeof v === 'object') {
      const keys = Object.keys(v);
      if (!keys.length) return '(empty)';
      const t = keys.slice(0, 4).join(', ') + (keys.length > 4 ? ` +${keys.length - 4}` : '');
      return `{ ${t} }`;
    }
    const t = String(v);
    return t.length > limit ? `${t.slice(0, limit - 2)}…` : t;
  }
  function changeText(c, limit = 90) {
    if (c.secret) return 'secret changed (values are never stored)';
    if (c.items_added || c.items_removed) {
      const parts = [];
      if (c.items_added?.length) parts.push(`+ ${c.items_added.map(String).join(', ')}`);
      if (c.items_removed?.length) parts.push(`− ${c.items_removed.map(String).join(', ')}`);
      if (parts.length) return parts.join('  ');
    }
    if (c.kind === 'added') return `added: ${val(c.after, limit)}`;
    if (c.kind === 'removed') return `removed (was ${val(c.before, limit)})`;
    return `${val(c.before, limit)} → ${val(c.after, limit)}`;
  }
  const scopeLabel = (m) => {
    const s = m.scope || {};
    if (s.imported) return 'Imported file';
    if (s.objects?.length) return 'One object';
    const siteNames = (s.site_ids || []).map((id) => siteName(id, m.site_names));
    if (s.org && !siteNames.length) return 'Org-wide';
    if (s.device_ids?.length) return `${siteNames.join(', ')} · ${plural(s.device_ids.length, 'device')}`;
    return (s.org ? 'Org + ' : '') + (siteNames.join(', ') || 'Site');
  };
  function siteName(id, extra) {
    if (!id) return 'Organization';
    return (
      extra?.[id] ||
      state.overview?.site_names?.[id] ||
      state.sites.find((s) => s.id === id)?.name ||
      id.slice(0, 8)
    );
  }
  // The configuration source's product name from the API ("Juniper Mist Cloud"), not hard-coded.
  const sourceName = () => state.overview?.source_label || 'Mist';
  const chip = (text, cls = '') => `<span class="cb-chip ${cls}">${backupEsc(text)}</span>`;
  const stateChip = (st) =>
    chip({ changed: 'Changed', added: 'New', removed: 'Deleted' }[st] || st, `cb-state-${st}`);

  // ------------------------------------------------------------------ init
  async function init() {
    if (initd) return;
    initd = true;
    document.querySelectorAll('[data-cb-tab]').forEach((b) => (b.onclick = () => showTab(b.dataset.cbTab)));
    $('#backupSite').onchange = () => {
      state.siteId = $('#backupSite').value;
      state.a = '';
      state.b = 'live';
      state.driftFor = null;
      loadAll();
    };
    $('#cbRefresh').onclick = () => loadOverview({ refresh: true });
    $('#backupCreate').onclick = createSnapshot;
    $('#backupPolicySave').onclick = savePolicy;
    $('#cbChangeSearch').oninput = () => renderChanges();
    $('#cbCompareRun').onclick = runCompare;
    $('#cbDriftRefresh').onclick = () => loadDrift(true);
    $('#cbImport').onclick = () => $('#cbImportFile').click();
    $('#cbImportFile').onchange = importFile;
    const all = loadAll(); // v0.10.40: org-wide first view loads together with the site list
    try {
      state.sites = (await j('/api/v1/operations/sites')).sort((a, b) =>
        String(a.name || '').localeCompare(String(b.name || '')),
      );
    } catch {
      state.sites = [];
    }
    $('#backupSite').innerHTML =
      '<option value="">All sites (org-wide)</option>' +
      state.sites.map((x) => `<option value="${backupEsc(x.id)}">${backupEsc(x.name)}</option>`).join('');
    await all;
  }

  function loadAll() {
    return Promise.all([loadOverview(), loadSnapshots(), loadPolicy()]).then(() => {
      if (state.tab === 'drift') loadDrift();
    });
  }

  function showTab(tab) {
    state.tab = tab;
    document.querySelectorAll('[data-cb-tab]').forEach((b) => {
      const on = b.dataset.cbTab === tab;
      b.classList.toggle('active', on);
      b.setAttribute('aria-selected', on ? 'true' : 'false');
    });
    document
      .querySelectorAll('[data-cb-panel]')
      .forEach((p) => p.classList.toggle('hidden', p.dataset.cbPanel !== tab));
    if (tab === 'drift') loadDrift();
    if (tab === 'timeline') renderTimeline();
  }

  // ------------------------------------------------------------------ landing / overview
  function setTile(id, value, sub, tone = '') {
    const el = $(id);
    el.querySelector('.cb-tile-value').textContent = value;
    el.querySelector('.cb-tile-sub').textContent = sub;
    el.classList.remove('tone-good', 'tone-warn', 'tone-bad', 'tone-busy');
    if (tone) el.classList.add(`tone-${tone}`);
  }

  async function loadOverview({ refresh = false, full = false } = {}) {
    const seq = ++state.seq;
    state.loading = true;
    $('#cbLiveStatus').textContent = 'Reading the live configuration…';
    ['#cbTileChanged', '#cbTileWho', '#cbTileRollback'].forEach((id) => $(id).classList.add('tone-busy'));
    if (!state.overview)
      $('#cbChanges').innerHTML = '<div class="cb-empty">Comparing the live configuration with the last snapshot…</div>';
    try {
      const d = await j(`${API}/overview?${qs({ site_id: state.siteId, refresh, full })}`);
      if (seq !== state.seq) return;
      state.overview = d;
      renderOverview();
      if (d.baseline_created) loadSnapshots();
    } catch (err) {
      if (seq !== state.seq) return;
      state.overview = { error: err.message };
      renderOverview();
    } finally {
      if (seq === state.seq) state.loading = false;
    }
  }

  function renderOverview() {
    renderTiles();
    const d = state.overview || {};
    if (d.error) {
      $('#cbChangesNote').innerHTML = `<div class="notice warning">${backupEsc(d.error)}</div>`;
      $('#cbChanges').innerHTML = '';
      $('#cbAudit').innerHTML = '<div class="cb-empty">—</div>';
      return;
    }
    const last = d.last_snapshot;
    const scopeName = state.siteId ? siteName(state.siteId) : 'the whole org';
    const notes = [];
    if (d.baseline_created)
      notes.push(
        `<div class="notice info">First visit for ${backupEsc(scopeName)}: a baseline snapshot was captured. Changes made in ${backupEsc(sourceName())} from now on will show up here.</div>`,
      );
    if (d.check === 'quick')
      notes.push(
        `<div class="cb-note-line">Quick check: org objects plus ${plural(d.sites_checked || 0, 'site')} with ${backupEsc(sourceName())} audit activity since the snapshot (of ${d.sites_total || 0}). <button type="button" class="link-btn" id="cbFullCheck">Check every site</button></div>`,
      );
    if (d.errors?.length)
      notes.push(
        `<div class="cb-note-line warn">Some configuration could not be read: ${backupEsc(
          d.errors
            .slice(0, 3)
            .map((e) => e.collection)
            .join(', '),
        )}${d.errors.length > 3 ? '…' : ''}</div>`,
      );
    $('#cbChangesEyebrow').textContent = last
      ? `Live vs ${(TRIGGERS[last.trigger] || '').toLowerCase()} snapshot · ${when(last.created_at)}`
      : 'Live vs last snapshot';
    $('#cbAuditEyebrow').textContent = `${sourceName()} audit log`;
    $('#cbChangesNote').innerHTML = notes.join('');
    const full = $('#cbFullCheck');
    if (full) full.onclick = () => loadOverview({ refresh: true, full: true });
    renderChanges();
    renderAudit($('#cbAudit'), d.audit || [], d.audit_error, d.audit_reads || []);
  }

  function renderTiles() {
    const d = state.overview || {};
    const last = d.last_snapshot;
    const sched = d.schedule || {};
    const scopeName = state.siteId ? siteName(state.siteId) : 'the whole org';
    if (last) {
      setTile(
        '#cbTileCaptured',
        ago(last.created_at),
        `${TRIGGERS[last.trigger] || last.trigger} · ${when(last.created_at)} · ${plural(last.object_count || 0, 'object')}`,
        '',
      );
    } else {
      setTile('#cbTileCaptured', 'Never', `No snapshot covers ${scopeName} yet`, 'warn');
    }
    const status = [];
    if (d.live_at) status.push(`Live ${sourceName()} read ${when(d.live_at)}`);
    if (sched.enabled)
      status.push(
        sched.next_run ? `next scheduled snapshot ${ago(sched.next_run)}` : 'scheduled snapshots on',
      );
    else status.push('scheduled snapshots off');
    $('#cbLiveStatus').textContent = status.join(' · ');

    if (d.error) {
      setTile('#cbTileChanged', '—', 'Live check unavailable', 'warn');
      setTile('#cbTileWho', '—', '', '');
      setTile('#cbTileRollback', '—', '', '');
      $('#cbTabChangesCount').textContent = '';
      return;
    }
    const sum = d.summary || {};
    const n = sum.objects_changed || 0;
    setTile(
      '#cbTileChanged',
      n ? plural(n, 'object') : 'No changes',
      n
        ? [
            plural(sum.settings_changed || 0, 'setting'),
            sum.changed ? `${sum.changed} changed` : '',
            sum.added ? `${sum.added} new` : '',
            sum.removed ? `${sum.removed} deleted` : '',
          ]
            .filter(Boolean)
            .join(' · ')
        : d.baseline_created
          ? 'Baseline captured just now'
          : 'No changes since the last snapshot',
      n ? 'warn' : 'good',
    );
    // "Changed by" counts change actions only (people and API tokens first); read-only access such as
    // an automatic assistant reading the org never makes someone the author of a change.
    const admins = d.admins || [];
    const events = (d.audit || []).length;
    const reads = (d.audit_reads || []).reduce((t, g) => t + (g.count || 0), 0);
    setTile(
      '#cbTileWho',
      admins.length ? admins[0].admin : n ? 'Unknown' : 'No one',
      admins.length
        ? [
            // "Network admin (can make changes) – Whole organization" → "Network admin"
            String(admins[0].role || '').split(/\s[–(]/)[0] || (admins[0].kind === 'api_token' ? 'API token' : ''),
            admins.length > 1 ? `+${plural(admins.length - 1, 'other')}` : '',
            plural(events, 'change'),
          ]
            .filter(Boolean)
            .join(' · ')
        : d.audit_error
          ? `${sourceName()} audit log unavailable`
          : n
            ? 'No audit entry matched (API or automation?)'
            : reads
              ? `No changes recorded · ${plural(reads, 'read-only access', 'read-only accesses')}`
              : 'No admin activity since the snapshot',
      '',
    );
    const rs = d.restore_summary || {};
    setTile(
      '#cbTileRollback',
      !n ? 'Nothing to roll back' : rs.restore ? `Yes · ${plural(rs.restore, 'object')}` : 'Export only',
      !n
        ? 'Snapshots are ready if something changes'
        : [rs.export ? `${rs.export} export-only` : '', rs.none ? `${rs.none} created since` : '']
            .filter(Boolean)
            .join(' · ') || 'Preview each change before writing',
      !n ? 'good' : rs.restore ? 'good' : 'warn',
    );
    $('#cbTabChangesCount').textContent = n ? String(n) : '';
  }

  function renderChanges() {
    const d = state.overview || {};
    if (d.error) return;
    const q = ($('#cbChangeSearch').value || '').trim().toLowerCase();
    let rows = d.objects || [];
    if (q)
      rows = rows.filter((r) =>
        [r.name, r.kind_label, r.site_name, ...(r.changes || []).map((c) => c.label)]
          .join(' ')
          .toLowerCase()
          .includes(q),
      );
    const snapId = d.last_snapshot?.id;
    renderObjects($('#cbChanges'), rows, {
      snapshotId: snapId,
      empty: q
        ? 'No changed object matches the filter.'
        : d.last_snapshot
          ? 'No changes since the last snapshot.'
          : 'No snapshot yet.',
    });
  }

  function whoHtml(who) {
    if (!who?.length) return '';
    const first = who[0];
    return `<span class="cb-who" title="${backupEsc(first.message)}">by <b>${backupEsc(first.actor_name || first.admin)}</b> · ${backupEsc(ago(first.when))}${who.length > 1 ? ` · +${who.length - 1}` : ''}</span>`;
  }

  function headline(r) {
    if (r.state === 'added') return 'created since the snapshot';
    if (r.state === 'removed') return 'deleted since the snapshot';
    const c = (r.changes || [])[0];
    if (!c) return '';
    return `${c.label}: ${changeText(c)}`;
  }

  function renderObjects(host, rows, { snapshotId, empty, compare } = {}) {
    if (!rows.length) {
      host.innerHTML = `<div class="cb-empty">${backupEsc(empty || 'No differences.')}</div>`;
      return;
    }
    const groups = new Map();
    rows.forEach((r) => {
      const g = r.kind === 'device' ? 'Devices' : r.kind_label || r.kind;
      if (!groups.has(g)) groups.set(g, []);
      groups.get(g).push(r);
    });
    host.innerHTML = [...groups.entries()]
      .map(
        ([g, items]) =>
          `<div class="cb-group"><div class="cb-group-head">${backupEsc(g)} <span>${items.length}</span></div>${items
            .map((r) => objectCard(r, snapshotId, compare))
            .join('')}</div>`,
      )
      .join('');
    host.querySelectorAll('[data-cb-act]').forEach((b) => {
      b.onclick = (ev) => {
        ev.preventDefault();
        const { cbAct, key, snap } = b.dataset;
        if (cbAct === 'restore') openRestore(snap, key);
        else if (cbAct === 'json') openJson(snap, key);
        else if (cbAct === 'download') downloadObject(snap, key);
      };
    });
  }

  function objectCard(r, snapshotId, compare) {
    const changes = r.changes || [];
    const site = r.site_id ? r.site_name || siteName(r.site_id) : 'Organization';
    const kindName = r.kind === 'device' ? r.kind_label : r.kind_label || '';
    const list = changes.length
      ? `<ul class="cb-changes">${changes
          .slice(0, 60)
          .map(
            (c) =>
              `<li class="cb-chg cb-chg-${backupEsc(c.kind)}${c.secret ? ' cb-chg-secret' : ''}"><span class="cb-chg-label">${backupEsc(c.label)}</span><span class="cb-chg-val">${backupEsc(changeText(c, 2000))}</span></li>`,
          )
          .join(
            '',
          )}${changes.length > 60 ? `<li class="cb-more">+${changes.length - 60} more settings</li>` : ''}</ul>`
      : `<div class="cb-empty small">${r.state === 'added' ? 'This object did not exist when the snapshot was taken.' : 'This object existed in the snapshot and is gone now.'}</div>`;
    const who = (r.who || [])
      .map(
        (w) =>
          `<li><b>${backupEsc(w.actor_name || w.admin)}</b> ${backupEsc(w.message)} <span class="muted">· ${backupEsc(when(w.when))}</span></li>`,
      )
      .join('');
    const mode = r.restore?.mode;
    let snap = snapshotId;
    if (compare) snap = compare.restoreSnap(r);
    const actions = [];
    if (snap && (mode === 'restore' || mode === 'preview') && !(compare && !compare.inA(r)))
      actions.push(
        `<button type="button" class="btn small primary" data-cb-act="restore" data-key="${backupEsc(r.key)}" data-snap="${backupEsc(snap)}">Preview restore…</button>`,
      );
    const jsonSnap = compare ? compare.jsonSnap(r) : r.state === 'added' ? '' : snap;
    if (jsonSnap) {
      actions.push(
        `<button type="button" class="btn small secondary" data-cb-act="json" data-key="${backupEsc(r.key)}" data-snap="${backupEsc(jsonSnap)}">View saved JSON</button>`,
      );
      actions.push(
        `<button type="button" class="btn small ghost" data-cb-act="download" data-key="${backupEsc(r.key)}" data-snap="${backupEsc(jsonSnap)}">Download JSON</button>`,
      );
    }
    const reason = r.restore?.reason
      ? `<div class="cb-restore-reason">${backupEsc(r.restore.reason)}</div>`
      : '';
    return `<details class="cb-obj cb-obj-${backupEsc(r.state)}" data-obj-key="${backupEsc(r.key)}"><summary><span class="cb-obj-main"><span class="cb-obj-title">${stateChip(r.state)}<span class="cb-obj-kind">${backupEsc(kindName)}</span><strong>${backupEsc(r.name || r.key)}</strong>${site !== r.name ? `<span class="cb-obj-site">${backupEsc(site)}</span>` : ''}</span><span class="cb-obj-head">${backupEsc(headline(r))}</span></span><span class="cb-obj-meta">${r.state === 'changed' ? `<span class="cb-count">${plural(r.change_count, 'setting')}</span>` : ''}${whoHtml(r.who)}</span></summary><div class="cb-obj-body">${list}${who ? `<div class="cb-sub-h">${backupEsc(sourceName())} audit log</div><ul class="cb-who-list">${who}</ul>` : ''}${reason}<div class="cb-obj-actions">${actions.join('')}</div></div></details>`;
  }

  // "Who changed it": change actions only, newest first - person (role / email), what, when; a row that
  // maps to a changed object jumps to it. Read-only access (sign-ins, an assistant reading the org) is
  // collapsed into one summary line per who + what, hidden until asked for.
  function renderAudit(host, rows, error, reads = []) {
    if (error) {
      host.innerHTML = `<div class="cb-empty">${backupEsc(sourceName())} audit log unavailable: ${backupEsc(error)}</div>`;
      return;
    }
    const changeRows = rows
      .slice(0, 40)
      .map((e) => {
        const who = e.actor_name || e.admin;
        const sub = [e.actor_role, e.actor_kind === 'api_token' ? 'API token' : ''].filter(Boolean).join(' · ');
        const what = backupEsc(e.message);
        const target = e.object_key
          ? `<button type="button" class="link-btn cb-audit-target" data-jump-key="${backupEsc(e.object_key)}" title="Show the changed object">${what}</button>`
          : `<span>${what}</span>`;
        return `<div class="cb-audit-row"><div class="cb-audit-top"><b title="${backupEsc(e.actor_email || who)}">${backupEsc(who)}</b><time title="${backupEsc(when(e.when))}">${backupEsc(ago(e.when))}</time></div>${sub || e.actor_email ? `<div class="cb-audit-meta">${backupEsc(sub || e.actor_email)}</div>` : ''}<div class="cb-audit-msg">${target}</div><div class="cb-audit-meta">${backupEsc(e.site_name || (e.site_id ? siteName(e.site_id) : 'Organization'))} · ${backupEsc(when(e.when))}</div></div>`;
      })
      .join('');
    const total = reads.reduce((t, g) => t + (g.count || 0), 0);
    const readBlock = total
      ? `<details class="cb-audit-reads"><summary>${backupEsc(
          reads.length === 1
            ? `${reads[0].actor}: ${reads[0].message} · ${plural(reads[0].count, 'time')}`
            : `${plural(total, 'read-only access', 'read-only accesses')} (sign-ins, views)`,
        )} <span class="link-btn">show</span></summary><ul>${reads
          .map(
            (g) =>
              `<li><b>${backupEsc(g.actor)}</b> ${backupEsc(g.message)} <span class="muted">· ${plural(g.count, 'time')} · last ${backupEsc(ago(g.last))}</span></li>`,
          )
          .join('')}</ul></details>`
      : '';
    host.innerHTML =
      (changeRows || '<div class="cb-empty">No configuration changes recorded since the snapshot.</div>') + readBlock;
    host.querySelectorAll('[data-jump-key]').forEach((b) => {
      b.onclick = () => {
        const el = [...document.querySelectorAll('#cbChanges [data-obj-key]')].find(
          (x) => x.dataset.objKey === b.dataset.jumpKey,
        );
        if (!el) return;
        el.open = true;
        el.scrollIntoView({ behavior: 'smooth', block: 'center' });
        el.classList.add('cb-obj-flash');
        setTimeout(() => el.classList.remove('cb-obj-flash'), 1600);
      };
    });
  }

  // ------------------------------------------------------------------ snapshots / timeline
  async function createSnapshot() {
    const btn = $('#backupCreate');
    btn.disabled = true;
    const old = btn.textContent;
    btn.textContent = 'Capturing…';
    try {
      const d = await post(`${API}/snapshot`, { site_id: state.siteId });
      toast(`Snapshot saved · ${plural(d.meta?.object_count || 0, 'object')}`);
      await Promise.all([loadSnapshots(), loadOverview({ refresh: true })]);
    } catch (err) {
      toast(`Snapshot failed: ${err.message}`, true);
    } finally {
      btn.disabled = false;
      btn.textContent = old;
    }
  }

  async function loadSnapshots() {
    try {
      const d = await j(`${API}/snapshots?${qs({ site_id: state.siteId })}`);
      state.snapshots = d.snapshots || [];
    } catch {
      state.snapshots = [];
    }
    $('#cbTabTimelineCount').textContent = state.snapshots.length ? String(state.snapshots.length) : '';
    renderTimeline();
  }

  function renderTimeline() {
    const host = $('#cbTimeline');
    if (!host) return;
    const live = `<div class="cb-tl-row cb-tl-live ${state.b === 'live' ? 'is-b' : ''}"><div class="cb-tl-pick"><span class="cb-pick-spacer"></span><button type="button" class="cb-pick ${state.b === 'live' ? 'on' : ''}" data-pick="b" data-id="live" aria-pressed="${state.b === 'live'}">B</button></div><div class="cb-tl-dot"></div><div class="cb-tl-body"><div class="cb-tl-top"><strong>Live ${backupEsc(sourceName())} (now)</strong></div><div class="cb-tl-meta">Current configuration, read on demand</div></div></div>`;
    if (!state.snapshots.length) {
      host.innerHTML = `${live}<div class="cb-empty">No snapshots yet. Use “Snapshot now”, or wait for the scheduled capture.</div>`;
      bindTimeline(host);
      return;
    }
    host.innerHTML =
      live +
      state.snapshots
        .map((m) => {
          const changed = m.changes_from_previous;
          const delta =
            changed === 0
              ? '<span class="cb-delta none">No changes</span>'
              : changed
                ? `<span class="cb-delta">${plural(changed, 'object')} changed</span>`
                : '<span class="cb-delta first">First of its scope</span>';
          const isA = state.a === m.id,
            isB = state.b === m.id;
          return `<div class="cb-tl-row ${isA ? 'is-a' : ''} ${isB ? 'is-b' : ''}"><div class="cb-tl-pick"><button type="button" class="cb-pick ${isA ? 'on' : ''}" data-pick="a" data-id="${backupEsc(m.id)}" aria-pressed="${isA}">A</button><button type="button" class="cb-pick ${isB ? 'on' : ''}" data-pick="b" data-id="${backupEsc(m.id)}" aria-pressed="${isB}">B</button></div><div class="cb-tl-dot cb-trig-${backupEsc(m.trigger)}"></div><div class="cb-tl-body"><div class="cb-tl-top"><strong>${backupEsc(when(m.created_at))}</strong>${chip(TRIGGERS[m.trigger] || m.trigger, `cb-trig-chip cb-trig-${m.trigger}`)}${m.pinned ? chip('Pinned', 'cb-pinned') : ''}<span class="cb-tl-ago">${backupEsc(ago(m.created_at))}</span></div><div class="cb-tl-meta">${backupEsc(scopeLabel(m))} · ${plural(m.object_count || 0, 'object')}${m.errors ? ` · ${m.errors} unread` : ''} · ${delta}${m.reason && m.trigger !== 'scheduled' ? ` · <span class="cb-reason">${backupEsc(m.reason)}</span>` : ''}</div><div class="cb-tl-actions"><button type="button" class="link-btn" data-tl="pin" data-id="${backupEsc(m.id)}">${m.pinned ? 'Unpin' : 'Pin'}</button><button type="button" class="link-btn" data-tl="zip" data-id="${backupEsc(m.id)}">Export .zip</button><button type="button" class="link-btn" data-tl="json" data-id="${backupEsc(m.id)}">.json</button><button type="button" class="link-btn danger-link" data-tl="delete" data-id="${backupEsc(m.id)}">Delete</button></div></div></div>`;
        })
        .join('');
    bindTimeline(host);
  }

  function bindTimeline(host) {
    host.querySelectorAll('[data-pick]').forEach((b) => {
      b.onclick = () => {
        const id = b.dataset.id;
        if (b.dataset.pick === 'a') state.a = state.a === id ? '' : id;
        else state.b = state.b === id ? 'live' : id;
        if (state.a && state.a === state.b) state.b = 'live';
        renderTimeline();
        updateCompareHead();
      };
    });
    host.querySelectorAll('[data-tl]').forEach((b) => {
      b.onclick = () => timelineAction(b.dataset.tl, b.dataset.id);
    });
    updateCompareHead();
  }

  function metaOf(id) {
    if (id === 'live') return { id: 'live', trigger: 'live', created_at: null };
    return state.snapshots.find((m) => m.id === id) || { id };
  }

  function updateCompareHead() {
    const btn = $('#cbCompareRun');
    btn.disabled = !state.a;
    const a = state.a ? metaOf(state.a) : null;
    const b = metaOf(state.b);
    $('#cbCompareTitle').textContent = a
      ? `${when(a.created_at)} → ${b.id === 'live' ? `live ${sourceName()}` : when(b.created_at)}`
      : 'Choose two points in time';
  }

  async function timelineAction(act, id) {
    try {
      if (act === 'pin') {
        const m = metaOf(id);
        await post(`${API}/snapshots/pin`, { snapshot_id: id, pinned: !m.pinned });
        await loadSnapshots();
      } else if (act === 'zip' || act === 'json') {
        await download(`${API}/export?${qs({ snapshot_id: id, fmt: act })}`, `nodewatch-config-${id}.${act}`);
      } else if (act === 'delete') {
        if (!confirm('Delete this snapshot from this computer? This cannot be undone.')) return;
        await post(`${API}/snapshots/delete`, { snapshot_id: id, confirmed: true });
        if (state.a === id) state.a = '';
        if (state.b === id) state.b = 'live';
        await loadSnapshots();
      }
    } catch (err) {
      toast(err.message, true);
    }
  }

  async function runCompare() {
    if (!state.a) return;
    const host = $('#cbCompare');
    host.innerHTML = '<div class="cb-empty">Comparing…</div>';
    $('#cbCompareNote').innerHTML = '';
    try {
      const d = await j(`${API}/compare?${qs({ a: state.a, b: state.b, site_id: state.siteId })}`);
      const s = d.summary || {};
      const toLive = d.to?.id === 'live';
      $('#cbCompareEyebrow').textContent =
        `Compare · ${TRIGGERS[d.from?.trigger] || 'Snapshot'} snapshot → ${toLive ? `live ${sourceName()}` : `${TRIGGERS[d.to?.trigger] || ''} snapshot`}`;
      $('#cbCompareTitle').textContent =
        `${when(d.from?.created_at)} → ${toLive ? `live ${sourceName()}` : when(d.to?.created_at)}`;
      const notes = [
        `<div class="cb-note-line"><b>${plural(s.objects_changed || 0, 'object')}</b> differ · ${plural(s.settings_changed || 0, 'setting')} · ${s.added || 0} new · ${s.removed || 0} deleted (of ${s.compared_objects || 0} compared)</div>`,
      ];
      if (d.coverage_note) notes.push(`<div class="cb-note-line warn">${backupEsc(d.coverage_note)}.</div>`);
      $('#cbCompareNote').innerHTML = notes.join('');
      const aIsFrom = d.from?.id === state.a;
      const compare = {
        inA: (r) => (aIsFrom ? r.state !== 'added' : r.state !== 'removed'),
        restoreSnap: () => state.a,
        jsonSnap: (r) => {
          if (compare.inA(r)) return state.a;
          return state.b !== 'live' ? state.b : '';
        },
      };
      renderObjects(host, d.objects || [], {
        snapshotId: state.a,
        compare,
        empty: 'No differences between these two points in time.',
      });
    } catch (err) {
      host.innerHTML = `<div class="notice warning">${backupEsc(err.message)}</div>`;
    }
  }

  async function importFile() {
    const input = $('#cbImportFile');
    const file = input.files?.[0];
    input.value = '';
    if (!file) return;
    if (file.size > 50 * 1024 * 1024) {
      toast('Import is limited to 50 MB. Use the .zip export, which is compressed.', true);
      return;
    }
    try {
      const buf = await file.arrayBuffer();
      const d = await j(`${API}/import?${qs({ filename: file.name })}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/octet-stream' },
        body: buf,
      });
      toast(`Imported ${file.name} · ${plural(d.meta?.object_count || 0, 'object')}. Selected as A.`);
      state.a = d.snapshot;
      await loadSnapshots();
      showTab('timeline');
    } catch (err) {
      toast(`Import failed: ${err.message}`, true);
    }
  }

  // ------------------------------------------------------------------ template drift
  async function loadDrift(force = false) {
    if (!force && state.driftFor === state.siteId) return;
    state.driftFor = state.siteId;
    const host = $('#cbDrift');
    host.innerHTML = '<div class="cb-empty">Checking devices against their templates…</div>';
    try {
      const d = await j(`${API}/template-drift?${qs({ site_id: state.siteId })}`);
      const src = d.source;
      $('#cbDriftEyebrow').textContent = !src
        ? 'Device vs template / profile'
        : src.type === 'live'
          ? `Live ${sourceName()} · ${siteName(state.siteId)}`
          : `From org snapshot · ${when(src.at)} (pick a site for a live check)`;
      $('#cbTabDriftCount').textContent = d.devices_with_overrides ? String(d.devices_with_overrides) : '';
      if (d.message) {
        host.innerHTML = `<div class="cb-empty">${backupEsc(d.message)}</div>`;
        return;
      }
      const rows = (d.devices || []).filter((r) => r.override_count);
      const clean = (d.devices_checked || 0) - rows.length;
      const head = `<div class="cb-note-line"><b>${plural(rows.length, 'device')}</b> override their template · ${clean} follow it exactly (${d.devices_checked || 0} checked)</div>`;
      if (!rows.length) {
        host.innerHTML = `${head}<div class="cb-empty">Every checked device follows its template or profile.</div>`;
        return;
      }
      host.innerHTML =
        head +
        rows
          .map(
            (r) =>
              `<details class="cb-obj cb-obj-changed"><summary><span class="cb-obj-main"><span class="cb-obj-title">${chip('Override', 'cb-state-changed')}<span class="cb-obj-kind">${backupEsc(r.kind_label || 'Device')}</span><strong>${backupEsc(r.name)}</strong><span class="cb-obj-site">${backupEsc(r.site_name || siteName(r.site_id))}</span></span><span class="cb-obj-head">overrides ${backupEsc(r.overrides.map((o) => o.label).join(', '))} from ${backupEsc(r.parent)}</span></span><span class="cb-obj-meta"><span class="cb-count">${plural(r.override_count, 'setting group')}</span></span></summary><div class="cb-obj-body">${r.overrides
                .map(
                  (o) =>
                    `<div class="cb-sub-h">${backupEsc(o.label)} <span class="muted">· template → device</span></div><ul class="cb-changes">${o.changes
                      .map(
                        (c) =>
                          `<li class="cb-chg cb-chg-${backupEsc(c.kind)}"><span class="cb-chg-label">${backupEsc(c.label)}</span><span class="cb-chg-val">${backupEsc(c.kind === 'added' ? `device adds ${val(c.after)}` : c.kind === 'removed' ? `device drops ${val(c.before)}` : `${val(c.before)} → ${val(c.after)}`)}</span></li>`,
                      )
                      .join('')}</ul>`,
                )
                .join('')}</div></details>`,
          )
          .join('');
    } catch (err) {
      state.driftFor = null;
      host.innerHTML = `<div class="notice warning">${backupEsc(err.message)}</div>`;
    }
  }

  // ------------------------------------------------------------------ policy
  async function loadPolicy() {
    try {
      const p = await j(`${API}/policy`);
      const setSel = (id, v) => {
        const el = $(id);
        const s = String(v);
        if (![...el.options].some((o) => o.value === s)) el.add(new window.Option(s, s));
        el.value = s;
      };
      setSel('#backupRetention', p.retention_days || 30);
      setSel('#cbInterval', p.interval_hours || 24);
      setSel('#cbKeepMin', p.keep_min || 5);
      $('#backupDaily').checked = !!p.daily_enabled;
      $('#cbPreChange').checked = !!p.pre_change_enabled;
      renderSchedule(p.schedule || {});
    } catch {
      /* policy is optional */
    }
  }
  function renderSchedule(s) {
    const bits = [];
    bits.push(
      s.last_run
        ? `Last scheduled snapshot ${when(s.last_run)} (${ago(s.last_run)})`
        : 'No scheduled snapshot yet',
    );
    if (s.enabled)
      bits.push(s.next_run ? `next ${ago(s.next_run)}` : 'first one runs a few minutes after start-up');
    if (s.last_error) bits.push(`last attempt failed: ${s.last_error}`);
    $('#cbScheduleInfo').textContent = bits.join(' · ');
  }
  async function savePolicy() {
    try {
      const d = await post(`${API}/policy`, {
        retention_days: Number($('#backupRetention').value || 30),
        interval_hours: Number($('#cbInterval').value || 24),
        keep_min: Number($('#cbKeepMin').value || 5),
        daily_enabled: $('#backupDaily').checked,
        pre_change_enabled: $('#cbPreChange').checked,
      });
      $('#backupStatus').textContent =
        `Saved · keep ${d.retention_days} days${d.daily_enabled ? ` · every ${d.interval_hours} h` : ' · schedule off'}`;
      await Promise.all([loadPolicy(), loadSnapshots()]);
    } catch (err) {
      $('#backupStatus').textContent = err.message;
    }
  }

  // ------------------------------------------------------------------ dialogs (on <body>)
  function dialog() {
    let dlg = document.getElementById('cbDialog');
    if (dlg) return dlg;
    dlg = document.createElement('dialog');
    dlg.id = 'cbDialog';
    dlg.className = 'dialog wide cb-dialog';
    dlg.innerHTML =
      '<form method="dialog"><div class="dialog-head"><div><div class="eyebrow" id="cbDlgEyebrow"></div><h3 id="cbDlgTitle"></h3></div><button class="icon-btn" aria-label="Close">×</button></div><div id="cbDlgBody" class="cb-dlg-body"></div><div class="dialog-actions" id="cbDlgActions"></div></form>';
    document.body.appendChild(dlg);
    return dlg;
  }
  function openDialog(eyebrow, title, body, actions) {
    const dlg = dialog();
    dlg.querySelector('#cbDlgEyebrow').textContent = eyebrow;
    dlg.querySelector('#cbDlgTitle').textContent = title;
    dlg.querySelector('#cbDlgBody').innerHTML = body;
    dlg.querySelector('#cbDlgActions').innerHTML = actions;
    if (!dlg.open) dlg.showModal();
    return dlg;
  }

  async function openJson(snap, key) {
    openDialog('Saved configuration', 'Loading…', '<div class="cb-empty">Loading…</div>', '');
    try {
      const o = await j(`${API}/object?${qs({ snapshot_id: snap, key })}`);
      const dlg = openDialog(
        `${o.kind_label || ''} · saved ${when(o.snapshot_created_at)}`,
        o.name || key,
        `<p class="muted cb-small">Exactly what the snapshot holds. Secrets show as <code>***REDACTED:…***</code> fingerprints.</p><pre class="cb-json">${backupEsc(JSON.stringify(o.data, null, 2))}</pre>`,
        `<button type="button" class="btn secondary" id="cbDlgDownload">Download JSON</button><button class="btn primary">Close</button>`,
      );
      dlg.querySelector('#cbDlgDownload').onclick = () => downloadObject(snap, key);
    } catch (err) {
      openDialog(
        'Saved configuration',
        'Not available',
        `<div class="notice warning">${backupEsc(err.message)}</div>`,
        '<button class="btn primary">Close</button>',
      );
    }
  }

  async function openRestore(snap, key) {
    openDialog(
      'Restore preview',
      'Reading live Mist…',
      '<div class="cb-empty">Comparing live configuration with the snapshot…</div>',
      '',
    );
    let p;
    try {
      p = await post(`${API}/restore-preview`, { snapshot_id: snap, key });
    } catch (err) {
      openDialog(
        'Restore preview',
        'Not available',
        `<div class="notice warning">${backupEsc(err.message)}</div>`,
        '<button class="btn primary">Close</button>',
      );
      return;
    }
    const title = `${p.kind_label || ''} ${p.name || ''}`.trim();
    const eyebrow = `Restore to snapshot · ${when(p.snapshot_created_at)}`;
    if (!p.supported) {
      const dlg = openDialog(
        eyebrow,
        title,
        `<div class="notice warning">${backupEsc(p.reason || 'This object cannot be restored from NodeWatch.')}</div><p class="muted cb-small">Saved configuration (secrets redacted):</p><pre class="cb-json">${backupEsc(JSON.stringify(p.saved, null, 2))}</pre>`,
        `<button type="button" class="btn primary" id="cbDlgDownload">Download JSON</button><button class="btn ghost">Close</button>`,
      );
      dlg.querySelector('#cbDlgDownload').onclick = () => downloadObject(snap, key);
      return;
    }
    const changes = p.changes || [];
    const list = changes.length
      ? `<ul class="cb-changes">${changes
          .map(
            (c) =>
              `<li class="cb-chg cb-chg-${backupEsc(c.kind)}${c.secret ? ' cb-chg-secret' : ''}"><span class="cb-chg-label">${backupEsc(c.label)}</span><span class="cb-chg-val">${backupEsc(c.secret ? 'secret differs: the current Mist value is kept' : c.kind === 'added' ? `will be set to ${val(c.after)}` : c.kind === 'removed' ? `will be cleared (now ${val(c.before)})` : `${val(c.before)} → ${val(c.after)}`)}</span></li>`,
          )
          .join('')}</ul>`
      : '<div class="cb-empty">Live Mist already matches the snapshot. Nothing to write.</div>';
    const secrets = (p.secrets_kept_from_live || []).length
      ? `<div class="cb-note-line">Secrets are not stored in snapshots; these keep their current Mist value: ${backupEsc(p.secrets_kept_from_live.join(', '))}.${p.secrets_changed_since_snapshot?.length ? ` <b>Changed since the snapshot:</b> ${backupEsc(p.secrets_changed_since_snapshot.join(', '))} (set them in Mist if needed).` : ''}</div>`
      : '';
    const body = `<div class="cb-restore-grid"><div><div class="cb-sub-h">What changes in Mist <span class="muted">· current → snapshot</span></div>${list}${secrets}</div><aside><div class="notice warning">${backupEsc(p.warning || '')}</div><details class="cb-json-details"><summary>Request NodeWatch will send (secrets hidden)</summary><pre class="cb-json">${backupEsc(JSON.stringify(p.request, null, 2))}</pre></details><details class="cb-json-details"><summary>Saved JSON from the snapshot</summary><pre class="cb-json">${backupEsc(JSON.stringify(p.proposed, null, 2))}</pre></details><label class="apply-confirm"><input id="cbRestoreConfirm" type="checkbox" ${changes.length ? '' : 'disabled'}> I reviewed these changes and want to write them to Mist. A safety snapshot of the current configuration is taken first and the change is recorded in the audit log.</label></aside></div>`;
    const dlg = openDialog(
      eyebrow,
      title,
      body,
      `<button type="button" class="btn ghost" id="cbDlgDownload">Download JSON</button><button class="btn secondary">Cancel</button><button type="button" class="btn danger" id="cbRestoreGo" disabled>Restore to Mist</button>`,
    );
    dlg.querySelector('#cbDlgDownload').onclick = () => downloadObject(snap, key);
    const box = dlg.querySelector('#cbRestoreConfirm');
    const go = dlg.querySelector('#cbRestoreGo');
    box.onchange = () => (go.disabled = !box.checked);
    go.onclick = async () => {
      if (!box.checked) return;
      go.disabled = true;
      go.textContent = 'Writing…';
      try {
        const r = await post(`${API}/restore`, { snapshot_id: snap, key, confirmed: true });
        openDialog(
          'Restore result',
          title,
          `<div class="notice ${r.verified ? 'success' : 'warning'}">${backupEsc(r.message)}</div><div class="cb-note-line">Audit record: ${backupEsc(r.audit_file)}${r.pre_change_snapshot ? ` · safety snapshot ${backupEsc(r.pre_change_snapshot)}` : ''}</div>${(r.remaining_differences || []).length ? `<div class="cb-sub-h">Still different</div><ul class="cb-changes">${r.remaining_differences.map((x) => `<li class="cb-chg cb-chg-changed"><span class="cb-chg-label">${backupEsc(x.field)}</span></li>`).join('')}</ul>` : ''}`,
          '<button class="btn primary">Done</button>',
        );
        await Promise.all([loadOverview({ refresh: true }), loadSnapshots()]);
      } catch (err) {
        go.textContent = 'Restore to Mist';
        go.disabled = !box.checked;
        dlg
          .querySelector('#cbDlgBody')
          .insertAdjacentHTML('afterbegin', `<div class="notice warning">${backupEsc(err.message)}</div>`);
      }
    };
  }

  // ------------------------------------------------------------------ downloads / toast
  async function download(url, fallbackName) {
    const r = await fetch(url);
    if (!r.ok) {
      let msg = await r.text();
      try {
        msg = JSON.parse(msg).detail || msg;
      } catch {
        /* plain text */
      }
      throw new Error(msg || `HTTP ${r.status}`);
    }
    const blob = await r.blob();
    const disp = r.headers.get('content-disposition') || '';
    const name = disp.match(/filename="?([^";]+)"?/i)?.[1] || fallbackName;
    const href = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = href;
    a.download = name;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(href), 1000);
  }
  function downloadObject(snap, key) {
    return download(`${API}/object?${qs({ snapshot_id: snap, key, download: true })}`, 'object.json').catch(
      (err) => toast(err.message, true),
    );
  }
  function toast(msg, bad = false) {
    let el = document.getElementById('cbToast');
    if (!el) {
      el = document.createElement('div');
      el.id = 'cbToast';
      el.className = 'cb-toast';
      el.setAttribute('role', 'status');
      document.body.appendChild(el);
    }
    el.textContent = msg;
    el.classList.toggle('bad', bad);
    el.classList.add('show');
    clearTimeout(toast.t);
    toast.t = setTimeout(() => el.classList.remove('show'), 4200);
  }

  return {
    init,
    // Re-opening the tool re-reads (server caches live Mist for two minutes).
    refresh: () => Promise.all([loadOverview(), loadSnapshots()]),
    // The 30 s auto-refresh only refreshes relative times; live reads stay user-driven.
    autoRefresh: async () => {
      if (state.overview && !state.loading) renderTiles();
    },
  };
})();
