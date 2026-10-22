// NodeWatch table tools (v0.10.12): every data table in the app gets
//  - click-to-sort column headers (click again to reverse; keyboard: Enter/Space on the header)
//  - a quick filter box when its card has no search box of its own
// Modules keep rendering their <tbody> with innerHTML; a MutationObserver re-applies the
// active sort and filter after each re-render. Cells may carry data-sort="<value>" when their
// display text does not sort naturally (times, speeds, watts). Tables opt out with data-nosort.
(function () {
  const NO_SORT = 'table[data-nosort], table:has(#memberRows)';
  const EMPTY = new Set(['', '—', '-', '–', 'n/a', 'none', 'unknown']);
  const IPV4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?:\/\d+)?$/;
  const NUMBER = /^[-+]?\(?[\d,]*\.?\d+\)?\s*(%|w|mw|kw|ms|s|m|h|d|g|m?bps|[kmg]b?|dbm)?$/i;
  const DATE = /\d{1,4}[/-]\d{1,2}[/-]\d{2,4}/;
  const state = new WeakMap(); // table -> { col, dir, query, observer }

  function cellValue(row, col) {
    const cell = row.cells[col];
    if (!cell) return '';
    return cell.dataset.sort ?? cell.textContent.replace(/\s+/g, ' ').trim();
  }

  function key(raw) {
    const text = String(raw).trim();
    if (EMPTY.has(text.toLowerCase())) return { empty: true };
    const ip = text.match(IPV4);
    if (ip) return { num: ip.slice(1, 5).reduce((acc, octet) => acc * 256 + Number(octet), 0) };
    if (NUMBER.test(text)) {
      const n = parseFloat(text.replace(/[,()]/g, ''));
      if (Number.isFinite(n)) return { num: n };
    }
    if (DATE.test(text)) {
      const t = Date.parse(text);
      if (Number.isFinite(t)) return { num: t };
    }
    return { text };
  }

  function compare(a, b) {
    if (a.empty || b.empty) return a.empty === b.empty ? 0 : a.empty ? 1 : -1; // blanks last
    if (a.num !== undefined && b.num !== undefined) return a.num - b.num;
    if (a.num !== undefined) return -1;
    if (b.num !== undefined) return 1;
    return a.text.localeCompare(b.text, undefined, { numeric: true, sensitivity: 'base' });
  }

  function dataRows(tbody) {
    // Placeholder rows ("No results", "Loading…") are a single cell spanning the table.
    return [...tbody.rows].filter((r) => !(r.cells.length === 1 && r.cells[0].colSpan > 1));
  }

  function apply(table) {
    const s = state.get(table);
    const tbody = table.tBodies[0];
    if (!s || !tbody) return;
    s.observer?.disconnect();
    if (s.col !== null) {
      const rows = dataRows(tbody);
      const keyed = rows.map((row, i) => ({ row, i, k: key(cellValue(row, s.col)) }));
      keyed.sort((x, y) => {
        const blank = (x.k.empty ? 1 : 0) - (y.k.empty ? 1 : 0);
        if (blank) return blank;
        return compare(x.k, y.k) * s.dir || x.i - y.i;
      });
      keyed.forEach(({ row }) => tbody.appendChild(row));
    }
    if (s.query !== undefined) {
      const q = s.query.trim().toLowerCase();
      let shown = 0;
      dataRows(tbody).forEach((row) => {
        const match = !q || row.textContent.toLowerCase().includes(q);
        row.classList.toggle('nw-filter-hidden', !match);
        if (match) shown++;
      });
      if (s.countEl) s.countEl.textContent = q ? `${shown} match${shown === 1 ? '' : 'es'}` : '';
    }
    s.observer?.observe(tbody, { childList: true });
  }

  function ensure(table) {
    let s = state.get(table);
    if (!s) {
      s = { col: null, dir: 1 };
      state.set(table, s);
    }
    const tbody = table.tBodies[0];
    if (tbody && !s.observer) {
      s.observer = new MutationObserver(() => apply(table));
      s.observer.observe(tbody, { childList: true });
    }
    return s;
  }

  function markHeaders(table) {
    if (table.matches(NO_SORT) || table.dataset.nwSortReady) return;
    table.dataset.nwSortReady = '1';
    table.classList.add('nw-sortable');
    table.querySelectorAll('thead th').forEach((th) => {
      if (!th.textContent.trim()) return; // action columns have no title
      th.tabIndex = 0;
      th.setAttribute('aria-sort', 'none');
      th.title = `Sort by ${th.textContent.trim()}`;
    });
  }

  function sortBy(th) {
    const table = th.closest('table');
    if (!table || table.matches(NO_SORT) || !th.textContent.trim()) return;
    const col = [...th.parentElement.children].indexOf(th);
    const s = ensure(table);
    s.dir = s.col === col ? -s.dir : 1;
    s.col = col;
    table.querySelectorAll('thead th').forEach((h) => {
      const active = h === th;
      h.classList.toggle('nw-sorted-asc', active && s.dir === 1);
      h.classList.toggle('nw-sorted-desc', active && s.dir === -1);
      if (h.hasAttribute('aria-sort'))
        h.setAttribute('aria-sort', active ? (s.dir === 1 ? 'ascending' : 'descending') : 'none');
    });
    apply(table);
  }

  function clearSort(table) {
    const s = state.get(table);
    if (!s || s.col === null) return;
    s.col = null;
    table.querySelectorAll('thead th').forEach((h) => {
      h.classList.remove('nw-sorted-asc', 'nw-sorted-desc');
      if (h.hasAttribute('aria-sort')) h.setAttribute('aria-sort', 'none');
    });
  }

  // A card that already has its own search box (e.g. #inventorySearch) keeps it.
  function hasOwnSearch(table) {
    const scope = table.closest('dialog, .tool-view') || table.parentElement;
    return [...scope.querySelectorAll('input')].some(
      (i) => i.type === 'search' || /search|filter/i.test(i.id + ' ' + (i.placeholder || '')),
    );
  }

  function addFilter(table) {
    if (table.dataset.nwFilterReady || table.closest('dialog') || table.dataset.nofilter !== undefined)
      return;
    table.dataset.nwFilterReady = '1';
    if (hasOwnSearch(table)) return;
    const wrap = table.closest('.table-wrap') || table;
    const bar = document.createElement('div');
    bar.className = 'nw-table-filter';
    const input = document.createElement('input');
    input.type = 'search';
    input.placeholder = 'Filter this table…';
    input.setAttribute('aria-label', 'Filter this table');
    const count = document.createElement('small');
    count.className = 'muted';
    bar.append(input, count);
    wrap.parentElement.insertBefore(bar, wrap);
    const s = ensure(table);
    s.query = '';
    s.countEl = count;
    input.addEventListener('input', () => {
      s.query = input.value;
      apply(table);
    });
  }

  function scan(root = document) {
    root.querySelectorAll('table').forEach((table) => {
      if (!table.tHead) return;
      markHeaders(table);
      addFilter(table);
    });
  }

  document.addEventListener('click', (e) => {
    const th = e.target.closest?.('thead th');
    if (th) sortBy(th);
  });
  document.addEventListener('keydown', (e) => {
    if (e.key !== 'Enter' && e.key !== ' ') return;
    const th = e.target.closest?.('thead th');
    if (!th || !th.closest('table.nw-sortable')) return;
    e.preventDefault();
    sortBy(th);
  });
  // A module's own sort dropdown takes over again when it is changed.
  document.addEventListener('change', (e) => {
    const sel = e.target;
    if (!(sel instanceof HTMLElement) || !/sort/i.test(sel.id || '')) return;
    const scope = sel.closest('.tool-view') || document;
    scope.querySelectorAll('table').forEach(clearSort);
  });
  // Tables rendered later (dialogs, module-built tables) are picked up as they appear.
  const LEAF_TAGS = new Set(['TR', 'TD', 'TH', 'TBODY', 'THEAD', 'OPTION', 'SPAN', 'B', 'I', 'A', 'BUTTON', 'svg']);
  const watcher = new MutationObserver((records) => {
    for (const r of records)
      r.addedNodes.forEach((n) => {
        if (n.nodeType !== 1 || LEAF_TAGS.has(n.tagName)) return; // rows/cells of a re-rendered table
        if (n.tagName === 'TABLE' || n.querySelector?.('table'))
          scan(n.tagName === 'TABLE' ? n.parentElement : n);
      });
  });
  function start() {
    scan();
    watcher.observe(document.body, { childList: true, subtree: true });
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start);
  else start();

  window.NodeWatchTables = { scan, sortBy, key, compare };
})();
