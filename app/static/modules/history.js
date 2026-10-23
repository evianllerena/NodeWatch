window.MistTools = window.MistTools || {};
window.MistTools.history = (() => {
  const esc = nwEscapeHtml; // one shared escaper (core.js)
  // v0.10.24: provider activity comes from every connected source in vendor-neutral shapes
  // (/api/v1/history → audit_entries + actors, see app/services/audit_people.py).
  let current = { audit_entries: [], actors: {}, local_changes: [], errors: [] };
  let providerRows = [];
  // One display row per entry: the neutral entry plus its resolved actor and readable aliases.
  function toRow(e, actors) {
    const actor = actors[e.actor_ref] || { name: e.actor_name || 'System', email: e.actor_email || '' };
    return {
      ...e,
      actor,
      admin: actor.name || e.actor_name || 'System',
      admin_email: actor.email || e.actor_email || '',
      action: e.verb || 'Activity',
      action_kind: e.verb_kind || 'neutral',
      site: e.site_name || 'Organization',
      device: (e.device_names || []).join(', '),
    };
  }
  let shownMist = [],
    shownLocal = [];
  const timeVal = (x) => {
    const n = Number(x?.timestamp);
    if (Number.isFinite(n) && n > 0) return n < 1e11 ? n * 1000 : n;
    const d = new Date(x?.time || 0);
    return Number.isNaN(d.getTime()) ? 0 : d.getTime();
  };
  const fmtTime = (ms) => (ms ? new Date(ms).toLocaleString() : '—');
  const ACTION_KIND_CLASS = { removed: 'removed', added: 'added', changed: 'changed', neutral: 'neutral' };
  const actionChip = (x) =>
    `<span class="nw-chip nw-action-${ACTION_KIND_CLASS[x.action_kind] || 'neutral'}">${esc(x.action || 'Activity')}</span>`;
  const resultCell = (v) =>
    v === true
      ? '<span class="nw-chip nw-action-added">✓ Verified</span>'
      : v === false
        ? '<span class="nw-chip nw-action-removed">✗ Not verified</span>'
        : '<span class="muted">—</span>';
  const mistSearchText = (x) =>
    [
      fmtTime(timeVal(x)),
      x.admin,
      x.admin_email,
      x.actor?.name,
      x.source_label,
      x.action,
      x.what,
      x.device,
      x.message,
      x.site,
      x.src_ip,
      x.user_agent,
    ]
      .join(' ')
      .toLowerCase();
  const localSearchText = (x) =>
    [
      fmtTime(timeVal(x)),
      x.tool,
      x.action,
      x.target,
      x.site,
      x.device,
      x.status,
      x.verified === true ? 'verified' : x.verified === false ? 'not verified' : '',
    ]
      .join(' ')
      .toLowerCase();

  function render() {
    const q = (document.querySelector('#auditSearch')?.value || '').trim().toLowerCase(),
      sort = document.querySelector('#auditSort')?.value || 'newest';
    let mist = [...providerRows],
      local = [...(current.local_changes || [])];
    if (q) {
      mist = mist.filter((x) => mistSearchText(x).includes(q));
      local = local.filter((x) => localSearchText(x).includes(q));
    }
    const sorter = (a, b) => {
      if (sort === 'oldest') return timeVal(a) - timeVal(b);
      if (sort === 'admin')
        return String(a.admin || a.tool || '').localeCompare(String(b.admin || b.tool || ''));
      if (sort === 'site') return String(a.site || '').localeCompare(String(b.site || ''));
      return timeVal(b) - timeVal(a);
    };
    mist.sort(sorter);
    local.sort(sorter);
    shownMist = mist;
    shownLocal = local;
    document.querySelector('#mistAuditRows').innerHTML = mist.length
      ? mist
          .map(
            (x, i) =>
              `<tr class="clickable-row activity-row activity-${ACTION_KIND_CLASS[x.action_kind] || 'neutral'}" data-audit-index="${i}" tabindex="0">` +
              `<td data-sort="${timeVal(x)}">${esc(fmtTime(timeVal(x)))}</td>` +
              `<td title="${esc([x.actor?.kind_label, x.actor?.role_text, x.source_label].filter(Boolean).join(' · '))}">${esc(x.actor?.name || x.admin)}${x.actor?.kind === 'api_token' ? ' <span class="muted">(API token)</span>' : ''}</td><td>${actionChip(x)}</td>` +
              `<td>${esc(x.what || x.message)}</td><td>${esc(x.site || 'Organization')}</td>` +
              `<td>${esc(x.src_ip || '—')}</td></tr>`,
          )
          .join('')
      : '<tr><td colspan="6" class="muted">No provider activity matches the current search.</td></tr>';
    document.querySelector('#mistAuditCount').textContent =
      `${mist.length} of ${providerRows.length} records`;
    document.querySelector('#localAuditRows').innerHTML = local.length
      ? local
          .map(
            (x, i) =>
              `<tr class="clickable-row" data-local-index="${i}" tabindex="0">` +
              `<td data-sort="${timeVal(x)}">${esc(fmtTime(timeVal(x)))}</td>` +
              `<td>${esc(x.tool)}${x.action ? ` <span class="muted">· ${esc(x.action)}</span>` : ''}</td>` +
              `<td>${esc(x.target || '—')}</td>` +
              `<td data-sort="${x.verified === true ? 1 : x.verified === false ? 0 : -1}">${resultCell(x.verified)}</td></tr>`,
          )
          .join('')
      : '<tr><td colspan="4" class="muted">No local activity matches the current search.</td></tr>';
    document.querySelector('#localAuditCount').textContent =
      `${local.length} of ${(current.local_changes || []).length} records`;
    const warn = document.querySelector('#auditWarning');
    if ((current.errors || []).length) {
      warn.classList.remove('hidden');
      warn.textContent = current.errors.join(' | ');
    } else warn.classList.add('hidden');
  }

  function changesTable(changes, emptyText) {
    if (!changes?.length) return `<p class="muted">${esc(emptyText)}</p>`;
    const opLabel = { added: 'Added', removed: 'Removed', changed: 'Changed' };
    return (
      '<div class="table-wrap"><table class="nw-change-table"><thead><tr><th>Field</th><th>Before</th><th>After</th></tr></thead><tbody>' +
      changes
        .map(
          (c) =>
            `<tr class="nw-op-${esc(c.op)}"><td><span class="nw-chip nw-op-chip-${esc(c.op)}">${esc(opLabel[c.op] || c.op)}</span> ${esc(c.field || c.label)}</td>` +
            `<td>${esc(c.before || '—')}</td><td>${esc(c.after || '—')}</td></tr>`,
        )
        .join('') +
      '</tbody></table></div>'
    );
  }
  function fieldList(rows, emptyText) {
    if (!rows?.length) return `<p class="muted">${esc(emptyText)}</p>`;
    return (
      '<dl class="nw-detail-list">' +
      rows
        .map(
          (r) =>
            `<dt>${esc(r.label)}</dt><dd>${esc(r.kind === 'time' ? fmtTime(Number(r.value)) : r.value)}</dd>`,
        )
        .join('') +
      '</dl>'
    );
  }
  // Who made the change (v0.10.24): the audit row's actor enriched from the org's administrator and
  // API-token lists of its source (audit_people.py). Every fact is optional.
  function actorHtml(x) {
    const a = x.actor || {};
    const epochMs = (v) => (Number(v) > 1e11 ? Number(v) : Number(v) * 1000);
    // Counts come from the range that was read: a 60-minute range cannot say "in the last 7 days".
    const count = (n, period) => (n !== null && n !== undefined && Number.isFinite(Number(n)) ? `${Number(n)} in the ${period}` : '');
    const rangeText = (h) =>
      !h ? 'shown period' : h < 24 ? `last ${h < 2 ? '60 minutes' : `${h} hours`}` : `last ${Math.round(h / 24)} days`;
    const rows = [
      { label: 'Name', value: a.name || x.admin },
      { label: 'Email', value: a.email || x.admin_email },
      { label: 'Account type', value: a.kind_label },
      { label: 'Token created by', value: a.created_by },
      { label: 'Role and scope', value: a.role_text },
      { label: 'Recorded by', value: x.source_label },
      { label: 'Two-step login', value: a.two_factor === true ? 'On' : a.two_factor === false ? 'Off' : '' },
      { label: 'Last login', value: a.last_login ? fmtTime(epochMs(a.last_login)) : '' },
      { label: 'Token last used', value: a.last_used ? fmtTime(epochMs(a.last_used)) : '' },
      {
        label: 'Changes by them',
        value: [
          count(a.changes_24h, 'last 24 hours'),
          count(a.changes_7d, 'last 7 days'),
          a.range_hours && a.range_hours !== 24 && a.range_hours !== 168
            ? count(a.changes_in_range, rangeText(a.range_hours))
            : '',
        ]
          .filter(Boolean)
          .join(' · '),
      },
      { label: 'Source IP', value: x.src_ip },
      { label: 'Browser / client', value: x.user_agent },
    ].filter((r) => r.value);
    return '<h4>Who made the change</h4>' + fieldList(rows, `${x.source_label || 'The source'} did not record who made this change.`);
  }
  function mistDetailHtml(x) {
    const when = fmtTime(timeVal(x));
    return (
      `<p class="nw-detail-summary">${actionChip(x)} ${esc(x.summary || x.message)} · ${esc(when)}</p>` +
      fieldList(
        [
          { label: 'Action', value: x.action },
          { label: 'What', value: x.what },
          { label: 'Device', value: x.device },
          { label: 'Site', value: x.site || 'Organization' },
          { label: x.source_label ? `${x.source_label} message` : 'Message', value: x.message },
        ].filter((r) => r.value),
        '',
      ) +
      actorHtml(x) +
      '<h4>What changed</h4>' +
      changesTable(
        x.changes,
        `${x.source_label || 'The source'} did not record field-level changes for this activity.`,
      )
    );
  }
  function localDetailHtml(x) {
    return (
      `<p class="nw-detail-summary">${resultCell(x.verified)} ${esc(x.tool)}${x.action ? ` · ${esc(x.action)}` : ''} · ${esc(x.target || '')} · ${esc(fmtTime(timeVal(x)))}</p>` +
      '<h4>Requested change</h4>' +
      fieldList(x.request, 'No request body was recorded.') +
      '<h4>Result</h4>' +
      fieldList(x.result, 'No result was recorded.') +
      '<h4>Before → After</h4>' +
      changesTable(x.changes, 'No differences between the recorded before and after state.')
    );
  }
  function openDetails(title, html) {
    document.querySelector('#auditDetailTitle').textContent = title;
    document.querySelector('#auditDetailBody').innerHTML = html;
    const dlg = document.querySelector('#auditDetailDialog');
    if (dlg.showModal) dlg.showModal();
  }
  function onRowActivate(ev) {
    const mistRow = ev.target?.closest?.('[data-audit-index]');
    if (mistRow) {
      const x = shownMist[Number(mistRow.dataset.auditIndex)];
      if (x) openDetails(x.what || x.message || 'Activity', mistDetailHtml(x));
      return;
    }
    const localRow = ev.target?.closest?.('[data-local-index]');
    if (localRow) {
      const x = shownLocal[Number(localRow.dataset.localIndex)];
      if (x) openDetails(`${x.tool}${x.action ? ` · ${x.action}` : ''}`, localDetailHtml(x));
    }
  }
  async function load(force = false) {
    const duration = document.querySelector('#auditDuration')?.value || '7d';
    const r = await fetch(
      `/api/v1/history?duration=${encodeURIComponent(duration)}${force ? '&refresh=true' : ''}`,
    );
    if (!r.ok) throw new Error(await r.text());
    current = await r.json();
    providerRows = (current.audit_entries || []).map((e) => toRow(e, current.actors || {}));
    render();
  }
  let initd = false;
  async function init() {
    if (initd) return load(false);
    initd = true;
    document.querySelector('#auditRefresh')?.addEventListener('click', () => load(true));
    document.querySelector('#auditDuration')?.addEventListener('change', () => load(false));
    document.querySelector('#auditSearch')?.addEventListener('input', render);
    document.querySelector('#auditSort')?.addEventListener('change', render);
    ['#mistAuditRows', '#localAuditRows'].forEach((sel) => {
      const el = document.querySelector(sel);
      el?.addEventListener('click', onRowActivate);
      el?.addEventListener('keydown', (ev) => {
        if (ev.key === 'Enter') onRowActivate(ev);
      });
    });
    await load(false);
  }
  // v0.10.40: the audit log is re-read every 2 minutes while open (its sources cache it that long),
  // not rebuilt on every 30 s page tick.
  let autoAt = Date.now();
  function autoRefresh() {
    if (Date.now() - autoAt < 120000) return Promise.resolve();
    autoAt = Date.now();
    return load(false);
  }
  return {
    init,
    refresh: load,
    autoRefresh,
    _test: {
      render,
      mistDetailHtml,
      localDetailHtml,
      setData: (d) => {
        current = d;
        providerRows = (d.audit_entries || []).map((e) => toRow(e, d.actors || {}));
      },
    },
  };
})();
