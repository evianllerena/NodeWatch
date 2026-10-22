const valEsc = (v) =>
  String(v ?? '').replace(
    /[&<>"']/g,
    (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c],
  );

window.MistTools.validator = (() => {
  let initd = false;
  async function j(u, o) {
    const r = await fetch(u, o);
    if (!r.ok)
      throw new Error((await r.json().catch(() => ({ detail: r.statusText }))).detail || r.statusText);
    return r.json();
  }
  async function init() {
    if (initd) return;
    initd = true;
    const reportsLoaded = reports(); // v0.10.40: together with the site list
    const sites = await j('/api/v1/operations/sites');
    const s = document.querySelector('#valSite');
    s.innerHTML =
      '<option value="">Select site</option>' +
      sites.map((x) => `<option value="${valEsc(x.id)}">${valEsc(x.name)}</option>`).join('');
    s.onchange = async () => {
      const rows = await j(`/api/v1/operations/switches?site_id=${encodeURIComponent(s.value)}`);
      document.querySelector('#valSwitch').innerHTML =
        '<option value="">Select switch</option>' +
        rows.map((x) => `<option value="${valEsc(x.id)}">${valEsc(x.name)}</option>`).join('');
    };
    document.querySelector('#valRun').onclick = run;
    await reportsLoaded;
  }
  async function run() {
    const site = document.querySelector('#valSite').value,
      device = document.querySelector('#valSwitch').value;
    if (!site || !device) return;
    document.querySelector('#valResult').innerHTML =
      '<div class="notice info">Running live post-change checks…</div>';
    const d = await j('/api/v1/validator/run', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ site_id: site, device_id: device, label: 'manual' }),
    });
    document.querySelector('#valResult').innerHTML =
      `<div class="validation-summary ${d.ok ? 'pass' : 'fail'}"><strong>${d.ok ? 'Validation passed' : 'Validation has blockers'}</strong> · ${d.warnings} warning(s)</div>` +
      d.checks
        .map(
          (c) =>
            `<div class="validation-row ${valEsc(c.severity)}"><b>${c.ok ? '✓' : c.severity === 'warning' ? '⚠' : '✕'} ${valEsc(c.label)}</b><span>${valEsc(c.detail)}</span></div>`,
        )
        .join('');
    await reports();
  }
  async function reports() {
    const d = await j('/api/v1/validator/reports');
    document.querySelector('#valReports').innerHTML =
      (d.reports || [])
        .slice(0, 12)
        .map((r) => {
          let when = r.timestamp || '';
          try {
            when = when ? new Date(when).toLocaleString() : '';
          } catch {}
          return `<div class="mini-row"><b title="${valEsc(r.device || r.file)}">${valEsc(r.device || r.file)}</b><span>${r.ok ? 'Passed' : 'Needs review'}${when ? ' · ' + valEsc(when) : ''}</span></div>`;
        })
        .join('') || '<div class="muted">No validation reports yet.</div>';
  }
  return { init, refresh: reports };
})();
