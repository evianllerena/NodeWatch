// NodeWatch traffic log table (v0.10.13; paged rendering + full-screen fixes v0.10.15), modelled on the firewall Monitor › Traffic view.
//  - Columns: any field Palo Alto returns can be shown; drag headers to reorder; choose in "Columns".
//  - Filter bar: free text plus field filters (action:deny, port:443, app:ssl, -dns, rule:"Permit all");
//    click a value in the table to add it as a filter; ⊕ builds a filter; → applies; × clears.
//  - Click a header to sort; denied / dropped traffic is tinted; ⬇ exports the visible rows as CSV.
// Layout (columns + order) is remembered per browser. Rendering is plain innerHTML with escaping.
(function () {
  const STORE = 'nodewatch.trafficLog.v1';
  const esc = (v = '') =>
    String(v ?? '').replace(
      /[&<>'"]/g,
      (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' })[c],
    );

  function fmtBytes(n) {
    const v = Number(n);
    if (!Number.isFinite(v)) return '';
    if (v < 1000) return `${v}`;
    const units = ['k', 'M', 'G', 'T'];
    let x = v;
    let i = -1;
    while (x >= 1000 && i < units.length - 1) {
      x /= 1000;
      i++;
    }
    return `${x >= 10 ? x.toFixed(0) : x.toFixed(1)}${units[i]}`;
  }
  function epoch(v) {
    if (v === null || v === undefined || v === '') return NaN;
    const n = Number(v);
    if (Number.isFinite(n)) return n > 1e14 ? n / 1000 : n > 1e11 ? n : n * 1000;
    // Safari (the Mac app without Chrome/Edge) cannot parse more than 3 fractional digits or a space
    // instead of "T": trim to milliseconds and normalise first (v0.10.32).
    const t = Date.parse(
      String(v)
        .trim()
        .replace(/^(\d{4}-\d{2}-\d{2}) (\d)/, '$1T$2')
        .replace(/(\.\d{3})\d+/, '$1')
        .replace(/([+-]\d{2})(\d{2})$/, '$1:$2'),
    );
    return Number.isFinite(t) ? t : Date.parse(v);
  }
  function fmtTime(v) {
    const t = epoch(v);
    if (!Number.isFinite(t)) return String(v ?? '');
    const d = new Date(t);
    const p = (x) => String(x).padStart(2, '0');
    return `${p(d.getMonth() + 1)}/${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
  }
  const humanize = (key) =>
    String(key)
      .replace(/\./g, ' › ')
      .replace(/_/g, ' ')
      .replace(/\bip\b/gi, 'IP')
      .replace(/\bid\b/gi, 'ID')
      .replace(/\b\w/g, (c) => c.toUpperCase());

  // Built-in columns (first eleven shown by default, in the firewall's order).
  const BUILTIN = [
    ['receive_time', 'Receive Time', (r) => r.receive_time, 'time'],
    ['type', 'Type', (r) => r.type ?? r.fields?.sub_type],
    ['from_zone', 'From Zone', (r) => r.from_zone],
    ['to_zone', 'To Zone', (r) => r.to_zone],
    ['source', 'Source', (r) => r.source],
    ['destination', 'Destination', (r) => r.destination],
    ['source_user', 'Source User', (r) => r.source_user],
    ['destination_port', 'To Port', (r) => r.destination_port, 'num'],
    ['application', 'Application', (r) => r.application],
    ['action', 'Action', (r) => r.action],
    ['rule', 'Rule', (r) => r.rule],
    ['decrypted', 'Decrypted', (r) => r.decrypted],
    ['bytes_received', 'Bytes Received', (r) => r.bytes_received, 'bytes'],
    ['bytes_sent', 'Bytes Sent', (r) => r.bytes_sent, 'bytes'],
    ['source_port', 'Source Port', (r) => r.source_port, 'num'],
    ['protocol', 'Protocol', (r) => r.protocol],
    ['bytes_total', 'Bytes', (r) => r.bytes_total ?? r.bytes, 'bytes'],
    ['packets_total', 'Packets', (r) => r.packets_total, 'num'],
    ['session_end_reason', 'Session End Reason', (r) => r.session_end_reason],
    ['elapsed_time', 'Elapsed (s)', (r) => r.elapsed_time, 'num'],
    ['application_category', 'App Category', (r) => r.application_category],
    ['application_risk', 'App Risk', (r) => r.application_risk, 'num'],
    ['url_category', 'URL Category', (r) => r.url_category],
    ['nat_source', 'NAT Source', (r) => r.nat_source],
    ['nat_destination', 'NAT Destination', (r) => r.nat_destination],
    ['firewall', 'Firewall', (r) => r.firewall],
    ['session_id', 'Session ID', (r) => r.session_id, 'num'],
  ];
  const DEFAULT_VISIBLE = BUILTIN.slice(0, 14).map((c) => c[0]);
  // Palo Alto field names already covered by a built-in column (not offered twice).
  const COVERED = new Set([
    'time_generated',
    'receive_time',
    'sub_type',
    'from_zone',
    'to_zone',
    'source_ip',
    'dest_ip',
    'source_user',
    'dest_port',
    'app',
    'action',
    'rule_matched',
    'is_decrypted',
    'bytes_received',
    'bytes_sent',
    'source_port',
    'protocol',
    'bytes_total',
    'packets_total',
    'session_end_reason',
    'total_time_elapsed',
    'app_category',
    'risk_of_app',
    'url_category',
    'nat_source',
    'nat_dest',
    'log_source_name',
    'session_id',
  ]);
  const ALIASES = {
    port: 'destination_port',
    to_port: 'destination_port',
    dport: 'destination_port',
    sport: 'source_port',
    app: 'application',
    src: 'source',
    source_ip: 'source',
    dst: 'destination',
    dest: 'destination',
    user: 'source_user',
    zone: ['from_zone', 'to_zone'],
    from: 'from_zone',
    to: 'to_zone',
    fw: 'firewall',
    time: 'receive_time',
  };
  const DENY = /^(deny|drop|reset|block|reset-both|reset-client|reset-server|drop-icmp)/i;

  // v0.10.15: rows are rendered in pages of PAGE (more are appended as the table is scrolled or
  // "Show more" is clicked), so 2,000+ logs never mean 30,000 cells in the DOM at once. Cell values
  // are light role="button" spans (Enter/Space work) rather than <button>s, which lay out ~3x slower.
  const PAGE = 100;
  const AUTO_ROWS = 1000;
  const state = {
    rows: [],
    visible: [...DEFAULT_VISIBLE],
    sort: { key: 'receive_time', dir: -1 },
    action: 'all',
    applied: '',
    newIds: new Set(),
    index: new Map(), // row -> position in state.rows (for the 🔍 detail button)
    view: [], // filtered + sorted rows
    limit: PAGE, // how many of state.view are in the DOM
    cols: null, // cached column catalog (rebuilt when rows change)
  };
  try {
    const saved = JSON.parse(localStorage.getItem(STORE) || '{}');
    if (Array.isArray(saved.visible) && saved.visible.length) state.visible = saved.visible;
  } catch {
    /* storage unavailable */
  }
  const save = () => {
    try {
      localStorage.setItem(STORE, JSON.stringify({ visible: state.visible }));
    } catch {
      /* ignore */
    }
  };

  function catalog() {
    if (state.cols) return state.cols;
    const cols = new Map(BUILTIN.map(([key, label, get, kind]) => [key, { key, label, get, kind }]));
    state.rows.forEach((r) =>
      Object.keys(r.fields || {}).forEach((k) => {
        if (COVERED.has(k) || cols.has(`f:${k}`)) return;
        cols.set(`f:${k}`, {
          key: `f:${k}`,
          label: humanize(k),
          get: (row) => row.fields?.[k],
          kind: /time$/.test(k) ? 'time' : /bytes/.test(k) ? 'bytes' : '',
        });
      }),
    );
    state.cols = cols;
    return cols;
  }
  function reindex() {
    state.index = new Map(state.rows.map((r, i) => [r, i]));
    state.cols = null;
  }

  function display(col, row) {
    const v = col.get(row);
    if (v === null || v === undefined || v === '') return '';
    if (col.kind === 'time') return fmtTime(v);
    if (col.kind === 'bytes') return fmtBytes(v);
    return String(v);
  }
  function sortValue(col, row) {
    const v = col.get(row);
    if (col.kind === 'time') return epoch(v);
    if (col.kind === 'bytes' || col.kind === 'num') return Number(v);
    return v === null || v === undefined ? '' : String(v).toLowerCase();
  }

  // "action:deny port:443 -dns rule:"Permit all" app!=ssl" → predicates
  function parseFilter(text, cols) {
    const tokens = String(text || '').match(/-?[\w.:!=]+?"[^"]*"|-?"[^"]*"|\S+/g) || [];
    const byLabel = new Map();
    cols.forEach((c) => {
      byLabel.set(c.key.toLowerCase(), c);
      byLabel.set(c.label.toLowerCase().replace(/[^a-z0-9]+/g, '_'), c);
      if (c.key.startsWith('f:')) byLabel.set(c.key.slice(2).toLowerCase(), c);
    });
    return tokens.map((tok) => {
      let negate = tok.startsWith('-');
      if (negate) tok = tok.slice(1);
      const m = tok.match(/^([\w.]+)(!=|:|=)(.*)$/);
      if (!m) {
        const needle = tok.replace(/^"|"$/g, '').toLowerCase();
        return (row) => {
          const hay = (row._text ||= JSON.stringify(row).toLowerCase());
          return hay.includes(needle) !== negate;
        };
      }
      const [, rawKey, op, rawVal] = m;
      if (op === '!=') negate = !negate;
      const val = rawVal.replace(/^"|"$/g, '').toLowerCase();
      const alias = ALIASES[rawKey.toLowerCase()];
      const keys = Array.isArray(alias) ? alias : [alias || rawKey.toLowerCase()];
      const targets = keys.map((k) => byLabel.get(k)).filter(Boolean);
      return (row) => {
        const hit = targets.length
          ? targets.some((c) => {
              const v = String(display(c, row)).toLowerCase();
              return op === ':' ? v.includes(val) : v === val;
            })
          : false;
        return hit !== negate;
      };
    });
  }

  function filtered(cols) {
    let rows = state.rows;
    if (state.action === 'allow') rows = rows.filter((r) => !DENY.test(String(r.action || '')));
    if (state.action === 'deny') rows = rows.filter((r) => DENY.test(String(r.action || '')));
    const preds = parseFilter(state.applied, cols);
    if (preds.length) rows = rows.filter((r) => preds.every((p) => p(r)));
    const col = cols.get(state.sort.key);
    if (col) {
      // Sort keys are computed once per row (not once per comparison).
      const empty = (v) => v === '' || (typeof v === 'number' && !Number.isFinite(v));
      rows = rows
        .map((r, i) => ({ r, i, v: sortValue(col, r) }))
        .sort((a, b) => {
          const x = a.v;
          const y = b.v;
          if (empty(x) || empty(y)) return empty(x) === empty(y) ? a.i - b.i : empty(x) ? 1 : -1;
          return (x < y ? -1 : x > y ? 1 : 0) * state.sort.dir || a.i - b.i;
        })
        .map((d) => d.r);
    }
    return rows;
  }

  function $(id) {
    return document.querySelector(id);
  }

  function rowHtml(r, visible) {
    const idx = state.index.get(r) ?? -1;
    const deny = DENY.test(String(r.action || ''));
    const cls = [deny ? 'tl-deny' : '', state.newIds.has(r.record_id) ? 'tl-new' : ''].join(' ').trim();
    return `<tr class="${cls}" data-i="${idx}"><td class="tl-icon-col"><button type="button" class="tl-detail" data-i="${idx}" title="Log details" aria-label="Log details">🔍</button></td>${visible
      .map((c) => {
        const text = display(c, r);
        return `<td>${text === '' ? '' : `<span class="tl-cell" role="button" tabindex="0" data-col="${esc(c.key)}" data-val="${esc(text)}" title="Filter on this value">${esc(text)}</span>`}</td>`;
      })
      .join('')}</tr>`;
  }
  function visibleCols() {
    const cols = catalog();
    return state.visible.map((k) => cols.get(k)).filter(Boolean);
  }
  function moreRowHtml(colspan) {
    const hidden = state.view.length - state.limit;
    if (hidden <= 0) return '';
    const next = Math.min(PAGE, hidden);
    return `<tr class="tl-more-row"><td colspan="${colspan}"><button type="button" class="tl-more">Show ${next.toLocaleString()} more</button><span class="muted"> · ${hidden.toLocaleString()} not shown yet</span></td></tr>`;
  }

  // keepLimit: keep the rows the user already scrolled into view (live updates, re-sorts).
  function render({ keepLimit = false } = {}) {
    const head = $('#detectiveTrafficHead');
    const body = $('#detectiveTrafficRows');
    if (!body) return { shown: 0, total: state.rows.length };
    const cols = catalog();
    const input = $('#detectiveTrafficSearch');
    if (input) state.applied = input.value;
    const visible = visibleCols();
    state.view = filtered(cols);
    state.limit = keepLimit ? Math.max(PAGE, state.limit) : PAGE;
    if (head)
      head.innerHTML = `<tr><th class="tl-icon-col" aria-label="Details"></th>${visible
        .map((c) => {
          const sorted = state.sort.key === c.key ? (state.sort.dir === 1 ? 'asc' : 'desc') : '';
          return `<th draggable="true" data-col="${esc(c.key)}" class="${sorted ? `tl-sorted-${sorted}` : ''}" aria-sort="${sorted ? (sorted === 'asc' ? 'ascending' : 'descending') : 'none'}" tabindex="0" title="Click to sort · drag to move">${esc(c.label)}</th>`;
        })
        .join('')}</tr>`;
    body.innerHTML = state.view.length
      ? state.view
          .slice(0, state.limit)
          .map((r) => rowHtml(r, visible))
          .join('') + moreRowHtml(visible.length + 1)
      : `<tr><td colspan="${visible.length + 1}" class="muted">No log entries match the filter.</td></tr>`;
    return { shown: state.view.length, total: state.rows.length };
  }

  // Append the next page of rows without touching the ones already in the DOM.
  function showMore() {
    const body = $('#detectiveTrafficRows');
    if (!body || state.limit >= state.view.length) return;
    const visible = visibleCols();
    const from = state.limit;
    state.limit = Math.min(state.view.length, state.limit + PAGE);
    body.querySelector('.tl-more-row')?.remove();
    body.insertAdjacentHTML(
      'beforeend',
      state.view
        .slice(from, state.limit)
        .map((r) => rowHtml(r, visible))
        .join('') + moreRowHtml(visible.length + 1),
    );
  }

  function addFilterToken(key, value) {
    const input = $('#detectiveTrafficSearch');
    const col = catalog().get(key);
    const name = col ? col.label.toLowerCase().replace(/[^a-z0-9]+/g, '_') : key;
    const val = /\s/.test(value) ? `"${value}"` : value;
    const token = `${name}=${val}`;
    if (input && !input.value.includes(token)) input.value = `${input.value.trim()} ${token}`.trim();
    apply();
  }

  function apply() {
    state.applied = $('#detectiveTrafficSearch')?.value || '';
    const r = render();
    document.dispatchEvent(new CustomEvent('nodewatch:traffic-filtered', { detail: r }));
  }

  function renderColumnsPop() {
    const pop = $('#tlColumnsPop');
    if (!pop) return;
    const cols = [...catalog().values()];
    const q = (pop.querySelector('input[type="search"]')?.value || '').toLowerCase();
    const list = cols.filter((c) => !q || c.label.toLowerCase().includes(q));
    pop.querySelector('.tl-col-list').innerHTML = list
      .map(
        (c) =>
          `<label class="tl-col-option"><input type="checkbox" data-col="${esc(c.key)}" ${state.visible.includes(c.key) ? 'checked' : ''}> ${esc(c.label)}</label>`,
      )
      .join('');
    pop.querySelector('.tl-col-count').textContent =
      `${cols.length} fields available from Palo Alto · ${state.visible.length} shown`;
  }

  function renderAddPop() {
    const sel = $('#tlAddField');
    if (!sel) return;
    sel.innerHTML = [...catalog().values()]
      .map((c) => `<option value="${esc(c.key)}">${esc(c.label)}</option>`)
      .join('');
  }

  function exportCsv() {
    const cols = catalog();
    const visible = state.visible.map((k) => cols.get(k)).filter(Boolean);
    const rows = filtered(cols);
    const cell = (v) => `"${String(v ?? '').replace(/"/g, '""')}"`;
    const csv = [visible.map((c) => cell(c.label)).join(',')]
      .concat(rows.map((r) => visible.map((c) => cell(display(c, r))).join(',')))
      .join('\r\n');
    const url = URL.createObjectURL(new Blob([csv], { type: 'text/csv' }));
    const a = document.createElement('a');
    a.href = url;
    a.download = `traffic-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-')}.csv`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  function showDetail(i) {
    const row = state.rows[Number(i)];
    const dlg = $('#tlDetailDialog');
    if (!row || !dlg) return;
    const cols = [...catalog().values()];
    $('#tlDetailTitle').textContent =
      `${row.source || '?'} → ${row.destination || '?'}${row.destination_port ? `:${row.destination_port}` : ''}`;
    $('#tlDetailBody').innerHTML = cols
      .map((c) => [c.label, display(c, row)])
      .filter(([, v]) => v !== '')
      .map(([l, v]) => `<div class="detail-row"><strong>${esc(l)}</strong><span>${esc(v)}</span></div>`)
      .join('');
    if (!dlg.open) dlg.showModal();
  }

  function togglePop(id) {
    ['#tlColumnsPop', '#tlAddFilterPop'].forEach((p) => {
      const el = $(p);
      if (el) el.classList.toggle('hidden', p !== id || !el.classList.contains('hidden'));
    });
    if (id === '#tlColumnsPop') renderColumnsPop();
    if (id === '#tlAddFilterPop') renderAddPop();
  }

  // Full screen moves the log view onto <body> (frosted cards would otherwise clip a fixed element)
  // and puts it back where it was afterwards. Exit with the ✕ button in its header (always visible:
  // the header and toolbar do not scroll, only the table does), the toolbar toggle, or Esc.
  // The page behind is covered by a solid scrim (no blur) and stops scrolling, which keeps
  // scrolling the table smooth.
  let placeholder = null;
  let scrim = null;
  function isFullscreen() {
    return !!$('#detectiveTrafficShell')?.classList.contains('tl-fullscreen');
  }
  function setFullscreen(shell, on) {
    if (!shell || on === shell.classList.contains('tl-fullscreen')) return;
    const btn = $('#tlFullscreen');
    if (on) {
      placeholder = document.createComment('traffic-log');
      shell.parentNode.insertBefore(placeholder, shell);
      scrim = document.createElement('div');
      scrim.className = 'tl-fs-scrim';
      scrim.addEventListener('click', () => setFullscreen(shell, false));
      document.body.appendChild(scrim);
      document.body.appendChild(shell);
      shell.classList.add('tl-fullscreen');
      shell.setAttribute('role', 'dialog');
      shell.setAttribute('aria-label', 'Traffic & Sessions (full screen)');
      document.body.classList.add('tl-fs-open');
      if (btn) {
        btn.textContent = '⤡ Restore';
        btn.setAttribute('aria-pressed', 'true');
      }
      $('#tlExitFullscreen')?.focus({ preventScroll: true });
    } else {
      shell.classList.remove('tl-fullscreen');
      shell.removeAttribute('role');
      shell.removeAttribute('aria-label');
      document.body.classList.remove('tl-fs-open');
      scrim?.remove();
      scrim = null;
      if (placeholder?.parentNode) placeholder.parentNode.replaceChild(shell, placeholder);
      placeholder = null;
      if (btn) {
        btn.textContent = '⤢ Full screen';
        btn.setAttribute('aria-pressed', 'false');
        btn.focus({ preventScroll: true });
      }
      shell.scrollIntoView({ block: 'nearest' });
    }
  }
  function toggleFullscreen(shell) {
    setFullscreen(shell, !shell.classList.contains('tl-fullscreen'));
  }
  // Capture phase on document, so no input or widget inside the table can swallow Esc.
  document.addEventListener(
    'keydown',
    (e) => {
      if (e.key !== 'Escape' || !isFullscreen() || document.querySelector('dialog[open]')) return;
      const open = ['#tlColumnsPop', '#tlAddFilterPop']
        .map($)
        .find((p) => p && !p.classList.contains('hidden'));
      e.preventDefault();
      e.stopPropagation();
      if (open) open.classList.add('hidden');
      else setFullscreen($('#detectiveTrafficShell'), false);
    },
    true,
  );

  let dragKey = null;
  function wire() {
    const shell = $('#detectiveTrafficShell');
    if (!shell || shell.dataset.tlWired) return;
    shell.dataset.tlWired = '1';
    shell.addEventListener('click', (e) => {
      const t = e.target;
      const th = t.closest?.('th[data-col]');
      if (th) {
        const key = th.dataset.col;
        state.sort = { key, dir: state.sort.key === key ? -state.sort.dir : key === 'receive_time' ? -1 : 1 };
        render();
        return;
      }
      if (t.closest?.('.tl-detail')) return showDetail(t.closest('.tl-detail').dataset.i);
      const cell = t.closest?.('.tl-cell');
      if (cell) return addFilterToken(cell.dataset.col, cell.dataset.val);
      if (t.closest?.('#tlApply')) return apply();
      if (t.closest?.('#tlClear')) {
        const input = $('#detectiveTrafficSearch');
        if (input) input.value = '';
        return apply();
      }
      if (t.closest?.('#tlColumns')) return togglePop('#tlColumnsPop');
      if (t.closest?.('#tlAddFilter')) return togglePop('#tlAddFilterPop');
      if (t.closest?.('#tlExport')) return exportCsv();
      if (t.closest?.('#tlFullscreen')) return toggleFullscreen(shell);
      if (t.closest?.('#tlExitFullscreen')) return setFullscreen(shell, false);
      if (t.closest?.('.tl-more')) return showMore();
      if (t.closest?.('#tlColReset')) {
        state.visible = [...DEFAULT_VISIBLE];
        save();
        renderColumnsPop();
        return render();
      }
      if (t.closest?.('#tlAddGo')) {
        const key = $('#tlAddField')?.value;
        const op = $('#tlAddOp')?.value || '=';
        const val = ($('#tlAddValue')?.value || '').trim();
        if (!key || !val) return;
        const col = catalog().get(key);
        const name = col ? col.label.toLowerCase().replace(/[^a-z0-9]+/g, '_') : key;
        const input = $('#detectiveTrafficSearch');
        const v = /\s/.test(val) ? `"${val}"` : val;
        if (input)
          input.value =
            `${input.value.trim()} ${op === 'not' ? `${name}!=${v}` : op === 'has' ? `${name}:${v}` : `${name}=${v}`}`.trim();
        $('#tlAddFilterPop')?.classList.add('hidden');
        return apply();
      }
      const act = t.closest?.('[data-tl-action]');
      if (act) {
        state.action = act.dataset.tlAction;
        shell
          .querySelectorAll('[data-tl-action]')
          .forEach((b) => b.setAttribute('aria-checked', String(b === act)));
        apply();
      }
    });
    // Load the next page of rows shortly before the end of the table is reached.
    const wrap = $('#detectiveTrafficTableWrap');
    let ticking = false;
    wrap?.addEventListener(
      'scroll',
      () => {
        if (ticking) return;
        ticking = true;
        requestAnimationFrame(() => {
          ticking = false;
          // Automatically up to AUTO_ROWS; beyond that the "Show more" row loads further pages.
          if (state.limit < AUTO_ROWS && wrap.scrollTop + wrap.clientHeight > wrap.scrollHeight - 900)
            showMore();
        });
      },
      { passive: true },
    );
    shell.addEventListener('change', (e) => {
      const box = e.target.closest?.('.tl-col-option input');
      if (!box) return;
      const key = box.dataset.col;
      state.visible = box.checked ? [...state.visible, key] : state.visible.filter((k) => k !== key);
      save();
      renderColumnsPop();
      render();
    });
    shell.addEventListener('input', (e) => {
      if (e.target.closest?.('#tlColumnsPop input[type="search"]')) renderColumnsPop();
    });
    shell.addEventListener('keydown', (e) => {
      if (e.target.id === 'detectiveTrafficSearch' && e.key === 'Enter') {
        e.preventDefault();
        apply();
      }
      const th = e.target.closest?.('th[data-col], .tl-cell');
      if (th && (e.key === 'Enter' || e.key === ' ')) {
        e.preventDefault();
        th.click();
      }
    });
    shell.addEventListener('dragstart', (e) => {
      const th = e.target.closest?.('th[data-col]');
      if (!th) return;
      dragKey = th.dataset.col;
      e.dataTransfer?.setData('text/plain', dragKey);
    });
    shell.addEventListener('dragover', (e) => {
      if (dragKey && e.target.closest?.('th[data-col]')) e.preventDefault();
    });
    shell.addEventListener('drop', (e) => {
      const th = e.target.closest?.('th[data-col]');
      if (!th || !dragKey || th.dataset.col === dragKey) return;
      e.preventDefault();
      const order = state.visible.filter((k) => k !== dragKey);
      order.splice(order.indexOf(th.dataset.col), 0, dragKey);
      state.visible = order;
      dragKey = null;
      save();
      render();
    });
  }

  // rows: normalized sessions (with .fields). merge=true adds only new rows (live mode): when the
  // table is in time order they are put on top of the rows already shown instead of re-rendering.
  function setRows(rows, { merge = false } = {}) {
    wire();
    const incoming = (rows || []).filter(Boolean);
    state.applied = $('#detectiveTrafficSearch')?.value || state.applied;
    if (!merge) {
      state.newIds = new Set();
      state.rows = incoming;
      reindex();
      return render();
    }
    const known = new Set(state.rows.map((r) => r.record_id));
    const fresh = incoming.filter((r) => !r.record_id || !known.has(r.record_id));
    if (!fresh.length) return { shown: state.view.length, total: state.rows.length, added: 0 };
    const before = state.cols ? state.cols.size : 0;
    state.newIds = new Set(fresh.map((r) => r.record_id));
    state.rows = [...fresh, ...state.rows].slice(0, 5000);
    reindex();
    setTimeout(() => {
      state.newIds = new Set();
    }, 4000);
    const body = $('#detectiveTrafficRows');
    const cols = catalog();
    const timeOrder = state.sort.key === 'receive_time' && state.sort.dir === -1;
    if (!body || !timeOrder || cols.size !== before || !state.view.length || state.rows.length >= 5000)
      return { ...render({ keepLimit: true }), added: fresh.length };
    const preds = parseFilter(state.applied, cols);
    const pass = (r) =>
      (state.action === 'all' || (state.action === 'deny') === DENY.test(String(r.action || ''))) &&
      preds.every((p) => p(r));
    const add = fresh
      .filter(pass)
      .sort((a, b) => (epoch(b.receive_time) || 0) - (epoch(a.receive_time) || 0));
    if (add.length) {
      const visible = visibleCols();
      state.view = [...add, ...state.view];
      state.limit += add.length;
      body.insertAdjacentHTML('afterbegin', add.map((r) => rowHtml(r, visible)).join(''));
    }
    return { shown: state.view.length, total: state.rows.length, added: fresh.length };
  }

  function newestEpoch() {
    return state.rows.reduce((m, r) => {
      const t = epoch(r.receive_time);
      return Number.isFinite(t) ? Math.max(m, t) : m;
    }, 0);
  }

  window.NodeWatchTrafficLog = {
    setRows,
    render,
    showMore,
    newestEpoch,
    isFullscreen,
    setFullscreen: (on) => setFullscreen($('#detectiveTrafficShell'), on),
    rows: () => state.rows,
    _parseFilter: parseFilter,
    _catalog: catalog,
  };
})();
