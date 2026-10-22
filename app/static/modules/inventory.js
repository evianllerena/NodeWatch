(function () {
  const esc = (s) =>
    String(s ?? '').replace(
      /[&<>'"]/g,
      (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' })[c],
    );
  let items = [];
  async function getJSON(url) {
    const r = await fetch(url);
    if (!r.ok) throw new Error(await r.text());
    return r.json();
  }
  function render() {
    let rows = [...items];
    const q = (document.querySelector('#inventorySearch')?.value || '').trim().toLowerCase();
    if (q)
      rows = rows.filter((i) =>
        [i.mac, i.serial, i.model, i.status, i.site].join(' ').toLowerCase().includes(q),
      );
    const sort = document.querySelector('#inventorySort')?.value || 'site';
    rows.sort((a, b) =>
      String(a[sort] || '').localeCompare(String(b[sort] || ''), undefined, { numeric: true }),
    );
    const body = document.querySelector('#inventoryRows');
    if (!body) return;
    const sampleNote = items.some((i) => i && i.sample)
      ? '<tr><td colspan="5" class="muted"><strong>Sample data</strong> — Mist is not connected. These rows are examples, not your inventory.</td></tr>'
      : '';
    body.innerHTML =
      sampleNote +
      (rows.length
        ? rows
            .map(
              (i) =>
                `<tr><td class="mono">${esc(i.mac)}</td><td>${esc(i.serial)}</td><td>${esc(i.model)}</td><td><span class="availability">${esc(i.status)}</span></td><td>${esc(i.site)}</td></tr>`,
            )
            .join('')
        : '<tr><td colspan="5">No assets match the current search.</td></tr>');
  }
  async function load(force = false) {
    items = await getJSON(`/api/v1/inventory${force ? '?refresh=true' : ''}`);
    render();
  }
  document.addEventListener('DOMContentLoaded', () => {
    document.querySelector('#inventoryRefresh')?.addEventListener('click', () => load(true));
    document.querySelector('#inventorySearch')?.addEventListener('input', render);
    document.querySelector('#inventorySort')?.addEventListener('change', render);
  });
  window.MistTools = window.MistTools || {};
  window.MistTools.inventory = { init: () => load(false), refresh: (force = false) => load(force) };
})();
