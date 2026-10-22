// Topology › Export (v0.10.36): one report, sections picked per audience, saved as PDF by the browser's
// print dialog ("Save as PDF"), plus the same data as CSV + JSON files. Read-only.
(function () {
  const API = '/api/v1/topology';
  const esc = (v) =>
    String(v ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
  const num = (n) => (n == null || n === '' ? '—' : Number(n).toLocaleString());
  const plural = (n, one, many = `${one}s`) => `${num(n)} ${Number(n) === 1 ? one : many}`;
  const bps = (v) => {
    if (v == null || !Number.isFinite(+v)) return '';
    v = +v;
    if (v >= 1e9) return `${(v / 1e9).toFixed(1)} Gb/s`;
    if (v >= 1e6) return `${(v / 1e6).toFixed(v >= 1e8 ? 0 : 1)} Mb/s`;
    if (v >= 1e3) return `${Math.round(v / 1e3)} kb/s`;
    return `${Math.round(v)} b/s`;
  };
  const speed = (mbps) => (!mbps ? '' : mbps >= 1000 ? `${+(mbps / 1000).toFixed(mbps % 1000 ? 1 : 0)} Gb/s` : `${mbps} Mb/s`);
  const ROLE = { sdwan_edge: 'SD-WAN edge', router: 'Router', firewall: 'Firewall', switch: 'Switch', wireless_ap: 'Access point', wireless_controller: 'Wireless controller', cloud_gateway: 'Cloud gateway', load_balancer: 'Load balancer', server: 'Server', unknown: 'Other' };
  const ROLE_ORDER = ['sdwan_edge', 'router', 'firewall', 'load_balancer', 'switch', 'wireless_controller', 'wireless_ap'];
  const STAGE = { internet: 'Internet', sdwan: 'SD-WAN / WAN routers', firewall: 'Firewalls', core: 'Core switches', distribution: 'Distribution switches', access: 'Closet switches', wireless: 'Wi-Fi access points', other: 'Other devices', unmanaged: 'Devices behind the router' };

  const SECTIONS = [
    ['cover', 'Cover and contents', 'scope, time, systems read'],
    ['summary', 'Executive summary', 'health, KPIs, decisions'],
    ['orgmap', 'Organization map', 'WAN shape (detected), every site'],
    ['risks', 'Resilience and risk register', 'single points of failure, ranked'],
    ['sites', 'Site pages', 'layers diagram + HA, circuits, links, closets'],
    ['circuits', 'Circuits register', 'every WAN circuit'],
    ['inventory', 'Device inventory', 'model, serial, firmware, IP, status'],
    ['fabric', 'Fabric links', 'every site pair with tunnels'],
    ['routes', 'Routing tables', 'per router (slow for many sites)'],
    ['gaps', 'Data gaps', 'what could not be seen, and why'],
  ];
  const AUDIENCE = {
    executive: { label: 'Executive', desc: 'CEO / board: health, risk, decisions', sections: ['cover', 'summary', 'orgmap', 'risks'] },
    leadership: { label: 'IT leadership', desc: 'CIO: adds site pages and circuits', sections: ['cover', 'summary', 'orgmap', 'risks', 'sites', 'circuits', 'gaps'] },
    engineer: { label: 'Engineer', desc: 'Everything except routing tables', sections: ['cover', 'summary', 'orgmap', 'risks', 'sites', 'circuits', 'inventory', 'fabric', 'gaps'] },
    custom: { label: 'Custom', desc: 'Your own choice of sections', sections: null },
  };
  const LS = 'nodewatch.topoReport.';
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

  async function api(path, opts = {}) {
    const res = await fetch(path, opts.body ? { ...opts, headers: { 'Content-Type': 'application/json' } } : opts);
    if (!res.ok) {
      let detail = `${res.status} ${res.statusText}`;
      try {
        const b = await res.json();
        if (b?.detail) detail = typeof b.detail === 'string' ? b.detail : JSON.stringify(b.detail);
      } catch {
        /* not JSON */
      }
      throw new Error(detail);
    }
    return res.json();
  }

  // ---------------------------------------------------------------- dialog
  const D = { audience: store.get('audience', 'engineer'), sections: null, scope: 'org', picked: new Set(), skipEmpty: true, mask: false, data: true, ctx: null, job: null };

  async function open(ctx = {}) {
    D.ctx = ctx;
    D.scope = ctx.siteKey ? 'site' : 'org';
    D.sections = new Set(AUDIENCE[D.audience]?.sections || store.get('custom', AUDIENCE.engineer.sections));
    if (!ctx.sites?.length) {
      try {
        const org = await api(`${API}/org`);
        ctx.sites = (org.sites || []).filter((x) => !x.cloud).map((x) => ({ key: x.key, name: x.name, devices: x.devices || 0, fabric: !!x.peers }));
      } catch {
        ctx.sites = [];
      }
    }
    if (!D.picked.size) ctx.sites.forEach((s) => s.devices && D.picked.add(s.key));
    let dlg = document.querySelector('#nwReportDialog');
    if (!dlg) {
      dlg = document.createElement('dialog');
      dlg.id = 'nwReportDialog';
      dlg.className = 'rp-dialog';
      dlg.setAttribute('aria-label', 'Export topology report');
      document.body.appendChild(dlg);
      dlg.addEventListener('click', onDialogClick);
      dlg.addEventListener('change', onDialogChange);
      dlg.addEventListener('close', () => {
        D.job = null;
      });
    }
    renderDialog();
    if (!dlg.open) dlg.showModal();
  }

  function pagesEstimate() {
    const n = D.scope === 'site' ? 1 : D.scope === 'pick' ? D.picked.size : (D.ctx.sites || []).filter((s) => (D.scope === 'fabric' ? s.fabric : true) && (!D.skipEmpty || s.devices)).length;
    let p = 0;
    if (D.sections.has('cover')) p += 1;
    if (D.sections.has('summary')) p += 1;
    if (D.sections.has('orgmap')) p += 1;
    if (D.sections.has('risks')) p += 1;
    if (D.sections.has('sites')) p += 2 * n;
    if (D.sections.has('circuits')) p += Math.max(1, Math.ceil(n / 6));
    if (D.sections.has('inventory')) p += Math.max(1, Math.ceil(n * 1.2));
    if (D.sections.has('fabric')) p += 3;
    if (D.sections.has('routes')) p += n * 2;
    if (D.sections.has('gaps')) p += 1;
    return p;
  }

  function renderDialog() {
    const dlg = document.querySelector('#nwReportDialog');
    const sites = D.ctx.sites || [];
    const running = D.job && D.job.state === 'running';
    dlg.innerHTML = `
      <form method="dialog" class="rp-dlg">
        <header class="rp-dlg-head"><div><h2>Export topology report</h2><p class="muted">One PDF. Pick who it is for; every section can be turned on or off.</p></div>
          <button type="button" class="rp-x" data-rp="close" aria-label="Close">×</button></header>
        <div class="rp-dlg-body">
          <fieldset class="rp-fs"><legend>1 · Who is it for?</legend>
            <div class="rp-aud">${Object.entries(AUDIENCE)
              .map(([id, a]) => `<label class="rp-aud-card${D.audience === id ? ' is-on' : ''}"><input type="radio" name="rpAudience" value="${id}"${D.audience === id ? ' checked' : ''}><strong>${esc(a.label)}</strong><small>${esc(a.desc)}</small></label>`)
              .join('')}</div></fieldset>
          <fieldset class="rp-fs"><legend>2 · Which sites?</legend>
            <div class="rp-scope">
              <label><input type="radio" name="rpScope" value="org"${D.scope === 'org' ? ' checked' : ''}> Whole organization (${sites.length})</label>
              <label><input type="radio" name="rpScope" value="fabric"${D.scope === 'fabric' ? ' checked' : ''}> SD-WAN sites only (${sites.filter((s) => s.fabric).length})</label>
              ${D.ctx.siteKey ? `<label><input type="radio" name="rpScope" value="site"${D.scope === 'site' ? ' checked' : ''}> This site (${esc(D.ctx.siteName)})</label>` : ''}
              <label><input type="radio" name="rpScope" value="pick"${D.scope === 'pick' ? ' checked' : ''}> Pick sites…</label>
            </div>
            ${D.scope === 'pick' ? `<div class="rp-pick">${sites
              .slice()
              .sort((a, b) => a.name.localeCompare(b.name))
              .map((s) => `<label><input type="checkbox" data-rp-site="${esc(s.key)}"${D.picked.has(s.key) ? ' checked' : ''}> ${esc(s.name)} <small class="muted">${num(s.devices)}</small></label>`)
              .join('')}</div>` : ''}
            ${D.scope === 'org' || D.scope === 'fabric' ? `<label class="rp-check"><input type="checkbox" name="rpSkip"${D.skipEmpty ? ' checked' : ''}> Leave out empty sites and sites where every device is offline (staging)</label>` : ''}
          </fieldset>
          <fieldset class="rp-fs"><legend>3 · Sections</legend>
            <div class="rp-sections">${SECTIONS.map(([id, label, desc]) => `<label><input type="checkbox" data-rp-section="${id}"${D.sections.has(id) ? ' checked' : ''}> <strong>${esc(label)}</strong> <span class="muted">— ${esc(desc)}</span></label>`).join('')}</div>
          </fieldset>
          <fieldset class="rp-fs rp-opts"><legend>Options</legend>
            <label class="rp-check"><input type="checkbox" name="rpMask"${D.mask ? ' checked' : ''}> Mask public IPs, MACs and serial numbers</label>
            <label class="rp-check"><input type="checkbox" name="rpData"${D.data ? ' checked' : ''}> Also download the data (CSV + JSON)</label>
          </fieldset>
        </div>
        <footer class="rp-dlg-foot">
          <span class="rp-est">${running ? `<span class="rp-progress"><span class="rp-bar"><span class="rp-fill" data-rp-w="${D.job.total ? Math.round((100 * D.job.done) / D.job.total) : 5}"></span></span> Reading site ${num(D.job.done)} of ${num(D.job.total || '…')}</span>` : D.error ? `<span class="rp-err">${esc(D.error)}</span>` : `About ${plural(pagesEstimate(), 'page')} · letter`}</span>
          <button type="button" class="btn secondary" data-rp="close">Cancel</button>
          <button type="button" class="btn primary" data-rp="go"${running || !D.sections.size ? ' disabled' : ''}>${running ? 'Building…' : 'Build report'}</button>
        </footer>
      </form>`;
    dlg.querySelectorAll('[data-rp-w]').forEach((el) => el.style.setProperty('--w', `${el.dataset.rpW}%`));
  }

  function onDialogChange(e) {
    const t = e.target;
    if (t.name === 'rpAudience') {
      D.audience = t.value;
      store.set('audience', D.audience);
      D.sections = new Set(AUDIENCE[D.audience].sections || store.get('custom', AUDIENCE.engineer.sections));
    } else if (t.name === 'rpScope') D.scope = t.value;
    else if (t.name === 'rpSkip') D.skipEmpty = t.checked;
    else if (t.name === 'rpMask') D.mask = t.checked;
    else if (t.name === 'rpData') D.data = t.checked;
    else if (t.dataset.rpSite) t.checked ? D.picked.add(t.dataset.rpSite) : D.picked.delete(t.dataset.rpSite);
    else if (t.dataset.rpSection) {
      t.checked ? D.sections.add(t.dataset.rpSection) : D.sections.delete(t.dataset.rpSection);
      D.audience = 'custom';
      store.set('audience', 'custom');
      store.set('custom', [...D.sections]);
    }
    D.error = '';
    renderDialog();
  }

  async function onDialogClick(e) {
    const t = e.target.closest('[data-rp]');
    if (!t) return;
    e.preventDefault();
    if (t.dataset.rp === 'close') return document.querySelector('#nwReportDialog')?.close();
    if (t.dataset.rp === 'go') return build();
  }

  async function build() {
    D.error = '';
    const body = {
      scope: D.scope,
      site: D.ctx.siteKey || '',
      sites: D.scope === 'pick' ? [...D.picked] : [],
      sections: [...D.sections],
      skip_empty: D.skipEmpty,
      mask: D.mask,
      audience: D.audience,
    };
    try {
      let job = await api(`${API}/report`, { method: 'POST', body: JSON.stringify(body) });
      D.job = job;
      renderDialog();
      while (job.state === 'running') {
        await new Promise((r) => setTimeout(r, 700));
        if (!D.job) return; // dialog closed
        job = await api(`${API}/report/${job.id}`);
        D.job = job;
        if (job.state === 'running') renderDialog();
      }
      if (job.state === 'error') throw new Error(job.error || 'The report could not be built');
      document.querySelector('#nwReportDialog')?.close();
      show(job.report, job.id);
      if (D.data) downloadData(job.id);
    } catch (err) {
      D.job = null;
      D.error = err.message;
      renderDialog();
    }
  }

  async function downloadData(id) {
    try {
      const r = await fetch(`${API}/report/${id}/data.zip`);
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const blob = await r.blob();
      const m = (r.headers.get('content-disposition') || '').match(/filename="?([^";]+)"?/i);
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = m?.[1] || 'NodeWatch-Topology.zip';
      document.body.appendChild(a);
      a.click();
      a.remove();
      setTimeout(() => URL.revokeObjectURL(a.href), 2000);
    } catch (err) {
      console.warn('report data', err);
    }
  }

  // ---------------------------------------------------------------- the report
  const when = (t) => new Date(t * 1000).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
  const tone = (h) => ({ good: 'good', up: 'good', warning: 'warn', degraded: 'warn', critical: 'crit', down: 'crit' })[h] || 'none';
  const stateWord = (s) => ({ up: 'Up', down: 'Down', degraded: 'Degraded', unknown: 'Unknown' })[s] || s || 'Unknown';

  function page(cls, title, eyebrow, body, rep) {
    return `<section class="rp-page ${cls}">
      <header class="rp-head"><div><div class="rp-eyebrow">${esc(eyebrow)}</div><h2>${esc(title)}</h2></div><div class="rp-head-r">${esc(rep.org)} · ${esc(when(rep.generated_at))}</div></header>
      ${body}
    </section>`;
  }

  function coverPage(rep, toc) {
    const scope = rep.params.scope === 'site' ? (rep.sites[0]?.name || 'One site') : rep.params.scope === 'fabric' ? 'SD-WAN sites' : rep.params.scope === 'pick' ? `${rep.chosen.length} selected sites` : 'Whole organization';
    return `<section class="rp-page rp-cover">
      <div class="rp-cover-band">
        <div class="rp-cover-top"><span class="rp-brand">NodeWatch</span><span>Confidential</span></div>
        <div class="rp-eyebrow rp-on-dark">Network topology report</div>
        <h1>${esc(rep.org)}</h1>
        <p>${esc(scope)} · ${esc(AUDIENCE[rep.params.audience]?.label || 'Engineer')} edition${rep.params.mask ? ' · addresses masked' : ''}</p>
        <dl class="rp-cover-facts"><div><dt>Data as of</dt><dd>${esc(when(rep.generated_at))}</dd></div><div><dt>Prepared with</dt><dd>NodeWatch ${esc(rep.app_version)}</dd></div><div><dt>Systems read</dt><dd>${esc(rep.sources.join(' · ') || '—')}</dd></div></dl>
      </div>
      <div class="rp-cover-toc"><h3>Contents</h3><ol>${toc.map((x) => `<li><span>${esc(x)}</span></li>`).join('')}</ol>
        <p class="rp-fine">Every number comes from the systems listed above at the time shown. Anything not reported by a system is marked “assumed” or “inferred”.</p></div>
    </section>`;
  }

  function summaryPage(rep) {
    const k = rep.kpis;
    const h = k.health || {};
    const total = Math.max(1, k.sites);
    const highs = rep.risks.filter((r) => r.impact === 'High');
    const lead = [
      `${plural(k.sites, 'site')} and ${plural(k.devices, 'device')} are in scope.`,
      k.circuits ? `${num(k.circuits_up)} of ${num(k.circuits)} internet circuits are up.` : '',
      k.devices_down ? `${num(k.devices_down)} devices are offline${k.most_down && k.most_down.down > k.devices_down / 2 ? `, ${num(k.most_down.down)} of them at ${k.most_down.name}` : ''}.` : 'Every device is online.',
      highs.length ? `${plural(highs.reduce((n, r) => n + r.where.length, 0), 'high-impact finding')} need a decision (below).` : 'No high-impact risk was found.',
    ].filter(Boolean).join(' ');
    const bar = ['good', 'warning', 'critical', 'unknown'].map((x) => `<span class="rp-hb is-${x}" data-rp-w="${((100 * (h[x] || 0)) / total).toFixed(1)}"></span>`).join('');
    return page('rp-summary', 'Executive summary', '1 · Summary', `
      <p class="rp-lead">${esc(lead)}</p>
      <div class="rp-kpis">
        <div><b>${num(k.sites)}</b><span>Sites</span><small>${num(k.sites_fabric)} on SD-WAN${k.sites_empty ? ` · ${num(k.sites_empty)} empty` : ''}</small></div>
        <div><b>${num(k.devices)}</b><span>Devices</span><small>${num(k.devices - k.devices_down)} up · ${num(k.devices_down)} offline</small></div>
        <div><b>${num(k.circuits_up)}/${num(k.circuits)}</b><span>Circuits up</span><small>internet / WAN lines</small></div>
        <div><b>${num(k.ha_pairs)}</b><span>HA pairs</span><small>firewalls and edges in pairs</small></div>
        <div><b>${num(k.fabric_links_ok)}/${num(k.fabric_links)}</b><span>Fabric links healthy</span><small>${k.tunnels ? `${num(k.tunnels)} tunnels` : ''}</small></div>
      </div>
      <h3 class="rp-h3">Sites by health</h3>
      <div class="rp-healthbar">${bar}</div>
      <p class="rp-legend"><span class="is-good">■ ${num(h.good || 0)} healthy</span><span class="is-warning">■ ${num(h.warning || 0)} warning</span><span class="is-critical">■ ${num(h.critical || 0)} critical</span><span class="is-unknown">■ ${num(h.unknown || 0)} no data</span></p>
      <h3 class="rp-h3">How the WAN is built</h3>
      <p>${esc(rep.shape.label)}: ${esc(rep.shape.why)}${rep.shape.hubs.length ? ` Main sites: ${esc(rep.shape.hubs.map((x) => x.name).join(', '))}.` : ''}${rep.cloud.length ? ` Cloud: ${esc(rep.cloud.map((c) => `${c.name} (${c.gateways} gateways)`).join(', '))}.` : ''}</p>
      <h3 class="rp-h3">Decisions and recommended actions</h3>
      <table data-nosort data-nofilter class="rp-table"><thead><tr><th>Priority</th><th>Finding</th><th>Where</th><th>Recommendation</th><th>Owner</th></tr></thead><tbody>${rep.risks
        .slice(0, 7)
        .map((r) => `<tr><td class="rp-imp is-${r.impact.toLowerCase()}">${esc(r.impact)}</td><td><b>${esc(r.risk)}</b></td><td>${esc(r.where.slice(0, 4).join(', '))}${r.where.length > 4 ? ` +${r.where.length - 4}` : ''}</td><td>${esc(r.fix)}</td><td class="rp-owner"></td></tr>`)
        .join('') || '<tr><td colspan="5">Nothing to decide.</td></tr>'}</tbody></table>`, rep);
  }

  function orgPage(rep) {
    const sites = rep.sites.filter((s) => !s.cloud);
    const hubKeys = new Set(rep.shape.hubs.map((x) => x.key));
    const chain = (s) => [s.circuits ? `${s.circuits} circ` : '', s.edges ? `${s.edges} edge` : '', s.firewalls ? (s.firewalls === 2 ? 'FW HA' : `${s.firewalls} FW`) : '', s.switches ? `${s.switches} sw` : '', s.aps ? `${s.aps} AP` : ''].filter(Boolean).join(' › ');
    const card = (s) => `<div class="rp-site is-${s.health}"><b>${esc(s.name)}</b><span>${esc(chain(s) || 'no devices')}</span>${s.down ? `<small>${num(s.down)} down</small>` : ''}</div>`;
    const fabric = sites.filter((s) => s.fabric && !hubKeys.has(s.key)).sort((a, b) => b.devices - a.devices);
    const alone = sites.filter((s) => !s.fabric).sort((a, b) => b.devices - a.devices);
    const half = Math.ceil(fabric.length / 2);
    return page('rp-landscape rp-orgmap', 'Organization map', `2 · ${rep.shape.label}`, `
      <p class="rp-note">${esc(rep.shape.why)} Drawn as one fabric bar rather than ${num(rep.shape.pairs)} crossing lines; read each site left to right: circuits › edges › firewalls › switches › access points.</p>
      ${rep.cloud.length || rep.shape.hubs.length ? `<div class="rp-top">${rep.cloud.map((c) => `<div class="rp-site is-cloud"><b>${esc(c.name)}</b><span>${num(c.gateways)} gateways · reaches ${num(c.reaches)} sites</span></div>`).join('')}${sites.filter((s) => hubKeys.has(s.key)).map((s) => `<div class="rp-site is-main"><b>${esc(s.name)}</b><span>${esc(chain(s))}</span></div>`).join('')}</div>` : ''}
      ${fabric.length ? `<div class="rp-fabric"><div class="rp-col">${fabric.slice(0, half).map(card).join('')}</div><div class="rp-bus"><span>SD-WAN fabric · ${esc(rep.shape.label.toLowerCase())}</span></div><div class="rp-col">${fabric.slice(half).map(card).join('')}</div></div>` : ''}
      ${alone.length ? `<h3 class="rp-h3">Standalone sites (own internet, not on the SD-WAN) · ${num(alone.length)}</h3><div class="rp-alone">${alone.map((s) => `<span class="is-${s.health}">● ${esc(s.name)} <small>${num(s.devices)}</small></span>`).join('')}</div>` : ''}`, rep);
  }

  function risksPage(rep) {
    return page('rp-risks', 'Resilience and risk register', '3 · Risks', `
      <p class="rp-note">Found from the maps and ranked by impact. High: a whole site can go offline. Medium: reduced capacity or no backup. Low: housekeeping.</p>
      <table data-nosort data-nofilter class="rp-table"><thead><tr><th>#</th><th>Risk</th><th>Impact</th><th>Where</th><th>Recommendation</th><th>Owner</th></tr></thead><tbody>${rep.risks
        .map((r, i) => `<tr><td>${i + 1}</td><td><b>${esc(r.risk)}</b></td><td class="rp-imp is-${r.impact.toLowerCase()}">${esc(r.impact)}</td><td>${esc(r.where.join(', '))}</td><td>${esc(r.fix)}</td><td class="rp-owner"></td></tr>`)
        .join('') || '<tr><td colspan="6">No risk found.</td></tr>'}</tbody></table>`, rep);
  }

  function siteDiagram(d) {
    const st = Object.fromEntries((d.stages || []).map((s) => [s.id, s]));
    const pairsOf = (names) => {
      const set = new Set(names);
      const out = [];
      const done = new Set();
      for (const n of names) {
        if (done.has(n)) continue;
        const p = (d.ha_pairs || []).find((x) => (x.a === n && set.has(x.b)) || (x.b === n && set.has(x.a)));
        if (p) {
          done.add(p.a);
          done.add(p.b);
          out.push(`<div class="rp-pair"><span class="rp-box is-active">● ${esc(p.a)}<small>${esc(p.a_state || 'unit 1')}</small></span><span class="rp-ha">HA</span><span class="rp-box is-passive${p.assumed ? ' is-assumed' : ''}">● ${esc(p.b)}<small>${esc(p.b_state || 'unit 2')}${p.assumed ? ' · assumed' : ''}</small></span></div>`);
        } else {
          done.add(n);
          out.push(`<span class="rp-box">● ${esc(n)}</span>`);
        }
      }
      return out.join('');
    };
    const linkPills = (fromId, toId) => {
      const A = new Set(st[fromId]?.devices || []);
      const B = new Set(st[toId]?.devices || []);
      const ls = (d.links || []).filter((l) => l.layer !== 'ha' && ((A.has(l.a) && B.has(l.b)) || (A.has(l.b) && B.has(l.a))));
      if (!ls.length) return '<div class="rp-conn"><span>│</span></div>';
      return `<div class="rp-conn">${ls
        .slice(0, 6)
        .map((l) => `<span class="${l.members > 1 ? 'is-lag' : ''}">${esc([l.members > 1 ? `${(l.a_if || '').split(',')[0]} · ${l.members} × ${speed(l.speed_mbps / l.members)} · ${l.members_up}/${l.members} up` : `${l.a_if || '?'} ⇄ ${l.b_if || '?'}`, l.members > 1 ? '' : speed(l.speed_mbps)].filter(Boolean).join(' · '))}</span>`)
        .join('')}${ls.length > 6 ? `<span>+${ls.length - 6}</span>` : ''}</div>`;
    };
    const tiers = ['sdwan', 'firewall', 'core', 'distribution'].filter((id) => st[id]?.devices?.length);
    const groups = new Map();
    (d.circuits || []).forEach((c) => {
      const k = c.routers.join(' + ');
      if (!groups.has(k)) groups.set(k, []);
      groups.get(k).push(c);
    });
    let html = d.circuits?.length
      ? `<div class="rp-tier"><div class="rp-tier-label">Internet · ${plural(d.circuits.length, 'circuit')}</div><div class="rp-wan">${[...groups.entries()]
          .map(([k, cs]) => `<div class="rp-wan-group"><small>→ ${esc(k)}</small>${cs.map((c) => `<span class="rp-circ is-${tone(c.state)}">● ${esc(c.label)}<small>${esc([c.carrier, c.down_kbps ? bps(c.down_kbps * 1000) : ''].filter(Boolean).join(' · '))}</small></span>`).join('')}</div>`)
          .join('')}</div></div><div class="rp-conn"><span>│</span></div>`
      : '';
    tiers.forEach((id, i) => {
      if (i > 0) html += linkPills(tiers[i - 1], id);
      html += `<div class="rp-tier"><div class="rp-tier-label">${esc(STAGE[id])} · ${num(st[id].count)}</div><div class="rp-row">${pairsOf(st[id].devices)}</div></div>`;
    });
    if (d.closets?.length) {
      html += `<div class="rp-conn"><span>│</span></div><div class="rp-tier"><div class="rp-tier-label">Closets · ${num(d.closets.length)}</div><div class="rp-closets">${d.closets
        .slice(0, 16)
        .map((c) => `<span class="rp-closet${c.switches_down ? ' is-crit' : c.aps_down ? ' is-warn' : ''}"><b>${esc(c.name)}</b><small>${plural(c.switches.length, 'switch', 'switches')} · ${plural(c.aps, 'AP')}${c.clients != null ? ` · ${num(c.clients)} clients` : ''}</small></span>`)
        .join('')}${d.closets.length > 16 ? `<span>+${d.closets.length - 16} more</span>` : ''}</div></div>`;
    }
    return html || '<p class="rp-note">No layered view: this site has no routers, firewalls or switches NodeWatch can see.</p>';
  }

  function sitePages(rep, s, n) {
    const d = rep.details[s.key] || {};
    if (d.error) return page('', s.name, `4.${n} · Site`, `<p class="rp-note">This site could not be read: ${esc(d.error)}</p>`, rep);
    const caps = [];
    const twoEdges = (d.stages || []).find((x) => x.id === 'sdwan')?.count >= 2;
    if (d.circuits?.length) caps.push(`${d.circuits.filter((c) => c.state === 'up').length} of ${d.circuits.length} circuits up`);
    if (twoEdges) caps.push('two WAN routers / edges');
    if (d.ha_pairs?.length) caps.push(plural(d.ha_pairs.length, 'HA pair'));
    const lags = (d.links || []).filter((l) => l.members > 1);
    if (lags.length) caps.push(`${plural(lags.length, 'aggregated link')} (${lags.filter((l) => l.members_up === l.members).length} complete)`);
    const diagram = page('rp-landscape rp-sitemap', s.name, `4.${n} · Site map`, `
      <div class="rp-site-grid"><div class="rp-diagram">${siteDiagram(d)}</div>
        <aside class="rp-site-side"><p class="rp-sentence">${esc(d.sentence || '')}</p>
          <dl class="rp-dl"><div><dt>Devices</dt><dd>${num(s.devices)} · ${num(s.down)} down</dd></div><div><dt>Health</dt><dd>${esc(s.health)}</dd></div>${d.fabric_peers ? `<div><dt>Fabric peers</dt><dd>${num(d.fabric_peers_up)}/${num(d.fabric_peers)} up</dd></div>` : ''}</dl>
          ${caps.length ? `<h4>Resilience</h4><ul>${caps.map((c) => `<li>${esc(c)}</li>`).join('')}</ul>` : ''}
          ${d.gaps?.length ? `<h4>Could not see</h4><ul>${d.gaps.slice(0, 4).map((g) => `<li>${esc(g)}</li>`).join('')}</ul>` : ''}
        </aside></div>`, rep);
    const infra = (d.links || []).filter((l) => l.layer !== 'ha');
    const tables = page('rp-site-tables', `${s.name} — detail`, `4.${n} · Site tables`, `
      ${d.ha_pairs?.length ? `<h3 class="rp-h3">High-availability pairs</h3><table data-nosort data-nofilter class="rp-table"><thead><tr><th>Role</th><th>Unit</th><th>State</th><th>Partner</th><th>State</th></tr></thead><tbody>${d.ha_pairs.map((p) => `<tr><td>${esc(ROLE[p.role] || p.role)}</td><td>${esc(p.a)}</td><td>${esc(p.a_state)} · ${esc(p.a_status)}</td><td>${esc(p.b)}${p.assumed ? ' <small>(assumed)</small>' : ''}</td><td>${esc(p.b_state)} · ${esc(p.b_status)}</td></tr>`).join('')}</tbody></table>` : ''}
      ${d.circuits?.length ? `<h3 class="rp-h3">Internet circuits</h3><table data-nosort data-nofilter class="rp-table rp-small"><thead><tr><th>Circuit</th><th>State</th><th>Router · port</th><th>Address</th><th>Bandwidth</th><th>In use</th><th>Quality</th><th>Tunnels</th></tr></thead><tbody>${d.circuits.map((c) => `<tr><td><b>${esc(c.label)}</b>${c.carrier && c.carrier !== c.label ? `<br><small>${esc(c.carrier)}</small>` : ''}</td><td class="is-${tone(c.state)}">${esc(stateWord(c.state))}</td><td>${esc(c.routers.join(' + '))}<br><small>${esc(c.interface)}</small></td><td class="rp-mono">${esc(c.public_ip || '—')}</td><td>${esc(c.down_kbps ? `${bps(c.down_kbps * 1000)}${c.up_kbps ? ` / ${bps(c.up_kbps * 1000)}` : ''}` : speed(c.speed_mbps) || '—')}</td><td>${esc(c.rx_bps != null ? `${bps(c.rx_bps) || 0} in · ${bps(c.tx_bps) || 0} out` : '—')}</td><td>${esc([c.latency_ms != null ? `${c.latency_ms} ms` : '', c.loss_pct ? `${c.loss_pct}% loss` : '', c.jitter_ms != null ? `${c.jitter_ms} ms jitter` : ''].filter(Boolean).join(' · ') || '—')}</td><td>${c.tunnels_total ? `${num(c.tunnels_up)}/${num(c.tunnels_total)}` : '—'}</td></tr>`).join('')}</tbody></table>` : ''}
      ${infra.length ? `<h3 class="rp-h3">Links between network devices</h3><table data-nosort data-nofilter class="rp-table rp-small"><thead><tr><th>From</th><th>Port</th><th>To</th><th>Port</th><th>Kind</th><th>Speed</th><th>State</th></tr></thead><tbody>${infra.slice(0, 80).map((l) => `<tr><td>${esc(l.a)}</td><td class="rp-mono">${esc(l.a_if)}</td><td>${esc(l.b)}</td><td class="rp-mono">${esc(l.b_if)}</td><td>${l.members > 1 ? `bundle ${l.members_up}/${l.members} up<br><small class="rp-mono">${esc(l.member_ports.join(', '))}</small>` : esc(l.layer === 'l2' ? 'L2' : 'cable')}${l.inferred ? ' <small>(inferred)</small>' : ''}</td><td>${esc(speed(l.speed_mbps) || '—')}</td><td class="is-${tone(l.state)}">${esc(stateWord(l.state))}</td></tr>`).join('')}</tbody></table>${infra.length > 80 ? `<p class="rp-fine">+${infra.length - 80} more in links.csv</p>` : ''}` : ''}
      ${d.closets?.length ? `<h3 class="rp-h3">Closets</h3><table data-nosort data-nofilter class="rp-table rp-small"><thead><tr><th>Closet</th><th>Switches</th><th>Uplink to</th><th>APs</th><th>Clients</th><th>Down</th></tr></thead><tbody>${d.closets.map((c) => `<tr><td><b>${esc(c.name)}</b></td><td>${esc(c.switches.join(', '))}</td><td>${esc(c.uplinks.join(', ') || '—')}</td><td>${num(c.aps)}</td><td>${c.clients != null ? num(c.clients) : '—'}</td><td>${c.switches_down || c.aps_down ? esc([c.switches_down ? `${c.switches_down} switch` : '', c.aps_down ? `${c.aps_down} AP` : ''].filter(Boolean).join(', ')) : '—'}</td></tr>`).join('')}</tbody></table>` : ''}
      ${d.routes?.length ? `<h3 class="rp-h3">Routing table (first ${num(d.routes.length)} routes)</h3><table data-nosort data-nofilter class="rp-table rp-small"><thead><tr><th>Device</th><th>Prefix</th><th>Next hop</th><th>Interface</th><th>Protocol</th><th>VRF</th></tr></thead><tbody>${d.routes.map((r) => `<tr><td>${esc(r.device)}</td><td class="rp-mono">${esc(r.prefix)}</td><td class="rp-mono">${esc(r.next_hop)}</td><td class="rp-mono">${esc(r.interface)}</td><td>${esc(r.protocol)}</td><td>${esc(r.vrf)}</td></tr>`).join('')}</tbody></table>` : ''}`, rep);
    return diagram + tables;
  }

  function circuitsPage(rep, sites) {
    const rows = [];
    sites.forEach((s) => (rep.details[s.key]?.circuits || []).forEach((c) => rows.push({ site: s.name, ...c })));
    return page('rp-circuits', 'Circuits register', '5 · Circuits', `
      <p class="rp-note">${plural(rows.length, 'circuit')}, ${num(rows.filter((c) => c.state === 'up').length)} up.</p>
      <table data-nosort data-nofilter class="rp-table rp-small"><thead><tr><th>Site</th><th>Circuit</th><th>Provider</th><th>State</th><th>Router · port</th><th>Address</th><th>Bandwidth</th><th>Latency / loss</th></tr></thead><tbody>${rows
        .map((c) => `<tr><td>${esc(c.site)}</td><td><b>${esc(c.label)}</b></td><td>${esc(c.carrier || '—')}</td><td class="is-${tone(c.state)}">${esc(stateWord(c.state))}</td><td>${esc(c.routers.join(' + '))} · ${esc(c.interface)}</td><td class="rp-mono">${esc(c.public_ip || '—')}</td><td>${esc(c.down_kbps ? bps(c.down_kbps * 1000) : speed(c.speed_mbps) || '—')}</td><td>${esc([c.latency_ms != null ? `${c.latency_ms} ms` : '', c.loss_pct ? `${c.loss_pct}%` : ''].filter(Boolean).join(' · ') || '—')}</td></tr>`)
        .join('') || '<tr><td colspan="8">No circuit was reported.</td></tr>'}</tbody></table>`, rep);
  }

  function inventoryPage(rep, sites) {
    const rows = [];
    sites.forEach((s) => (rep.details[s.key]?.devices || []).forEach((d) => rows.push({ site: s.name, ...d })));
    const rank = (r) => (ROLE_ORDER.indexOf(r) + 1 || 99);
    rows.sort((a, b) => a.site.localeCompare(b.site) || rank(a.role) - rank(b.role) || a.name.localeCompare(b.name, undefined, { numeric: true }));
    return page('rp-inventory', 'Device inventory', '6 · Inventory', `
      <p class="rp-note">${plural(rows.length, 'device')} · ${num(rows.filter((d) => d.status === 'down').length)} offline.</p>
      <table data-nosort data-nofilter class="rp-table rp-tiny"><thead><tr><th>Site</th><th>Name</th><th>Role</th><th>Model</th><th>Serial</th><th>Firmware</th><th>Mgmt IP</th><th>Status</th><th>HA</th></tr></thead><tbody>${rows
        .map((d) => `<tr><td>${esc(d.site)}</td><td>${esc(d.name)}${d.inferred ? ' <small>(inferred)</small>' : ''}</td><td>${esc(ROLE[d.role] || d.role)}</td><td>${esc(d.model)}</td><td class="rp-mono">${esc(d.serial)}</td><td>${esc(d.os_version)}</td><td class="rp-mono">${esc(d.mgmt_ip)}</td><td class="is-${tone(d.status)}">${esc(stateWord(d.status))}</td><td>${esc(d.ha_state ? `${d.ha_state}${d.ha_peer ? ` ⇄ ${d.ha_peer}` : ''}` : '')}</td></tr>`)
        .join('')}</tbody></table>`, rep);
  }

  function fabricPage(rep) {
    const rows = rep.fabric_links.slice().sort((a, b) => ['down', 'degraded', 'unknown', 'up'].indexOf(a.state) - ['down', 'degraded', 'unknown', 'up'].indexOf(b.state) || String(a.a).localeCompare(String(b.a)));
    return page('rp-fabric-links', 'Fabric links', '7 · Fabric', `
      <p class="rp-note">${plural(rows.length, 'site pair')} with tunnels; ${num(rows.filter((l) => l.state !== 'up').length)} not fully up are listed first.</p>
      <table data-nosort data-nofilter class="rp-table rp-tiny"><thead><tr><th>Site</th><th>Site</th><th>Tunnels up</th><th>State</th><th>Latency</th><th>Loss</th><th>Kind</th></tr></thead><tbody>${rows
        .map((l) => `<tr><td>${esc(l.a)}</td><td>${esc(l.b)}</td><td>${num(l.up)}/${num(l.tunnels)}</td><td class="is-${tone(l.state)}">${esc(stateWord(l.state))}</td><td>${l.latency_ms != null ? `${esc(l.latency_ms)} ms` : '—'}</td><td>${l.loss_pct != null ? `${esc(l.loss_pct)}%` : '—'}</td><td>${esc((l.kinds || []).join(', '))}</td></tr>`)
        .join('')}</tbody></table>`, rep);
  }

  function gapsPage(rep, sites) {
    const rows = [...rep.gaps.map((g) => ['Organization', g])];
    sites.forEach((s) => (rep.details[s.key]?.gaps || []).forEach((g) => rows.push([s.name, g])));
    return page('rp-gaps', 'Data gaps', '8 · What NodeWatch could not see', `
      <p class="rp-note">Missing data is not the same as a problem: these are the places where the report relies on fewer systems than it could.</p>
      <table data-nosort data-nofilter class="rp-table rp-small"><thead><tr><th>Where</th><th>Gap</th></tr></thead><tbody>${rows.map(([w, g]) => `<tr><td>${esc(w)}</td><td>${esc(g)}</td></tr>`).join('') || '<tr><td colspan="2">None.</td></tr>'}</tbody></table>`, rep);
  }

  function renderReport(rep) {
    const sec = new Set(rep.params.sections);
    const chosen = rep.sites.filter((s) => rep.chosen.includes(s.key)).sort((a, b) => (a.health === 'critical') - (b.health === 'critical') || b.devices - a.devices);
    const toc = [];
    if (sec.has('summary')) toc.push('1 · Executive summary');
    if (sec.has('orgmap')) toc.push('2 · Organization map');
    if (sec.has('risks')) toc.push('3 · Resilience and risk register');
    if (sec.has('sites')) toc.push(`4 · Site pages (${chosen.length})`);
    if (sec.has('circuits')) toc.push('5 · Circuits register');
    if (sec.has('inventory')) toc.push('6 · Device inventory');
    if (sec.has('fabric')) toc.push('7 · Fabric links');
    if (sec.has('gaps')) toc.push('8 · Data gaps');
    let html = '';
    if (sec.has('cover')) html += coverPage(rep, toc);
    if (sec.has('summary')) html += summaryPage(rep);
    if (sec.has('orgmap') && rep.params.scope !== 'site') html += orgPage(rep);
    if (sec.has('risks')) html += risksPage(rep);
    if (sec.has('sites') || sec.has('routes')) chosen.forEach((s, i) => (html += sitePages(rep, s, i + 1)));
    if (sec.has('circuits')) html += circuitsPage(rep, chosen);
    if (sec.has('inventory')) html += inventoryPage(rep, chosen);
    if (sec.has('fabric') && rep.fabric_links.length) html += fabricPage(rep);
    if (sec.has('gaps')) html += gapsPage(rep, chosen);
    return html;
  }

  function show(rep, id) {
    rep.org = window.MistApp?.orgName || document.querySelector('#connectionPill')?.textContent?.replace(/^\s*Connected\s*·\s*/, '').trim() || 'Your organization';
    let box = document.querySelector('#nwReport');
    if (!box) {
      box = document.createElement('div');
      box.id = 'nwReport';
      box.className = 'rp-root';
      box.setAttribute('role', 'dialog');
      box.setAttribute('aria-label', 'Topology report preview');
      document.body.appendChild(box);
      box.addEventListener('click', (e) => {
        const t = e.target.closest('[data-rpv]');
        if (!t) return;
        if (t.dataset.rpv === 'print') window.print();
        if (t.dataset.rpv === 'data') downloadData(box.dataset.job);
        if (t.dataset.rpv === 'close') closePreview();
      });
      document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape' && document.body.classList.contains('rp-showing')) closePreview();
      });
    }
    box.dataset.job = id;
    box.innerHTML = `<div class="rp-toolbar"><strong>Topology report</strong><span class="muted">${esc(plural(rep.chosen.length, 'site'))} · built in ${esc(rep.build_s)} s</span>
        <span class="rp-tip">In the print window choose <b>Save as PDF</b> as the destination.</span>
        <button type="button" class="btn primary" data-rpv="print">Save as PDF / Print</button>
        <button type="button" class="btn secondary" data-rpv="data">Download data (CSV + JSON)</button>
        <button type="button" class="btn ghost" data-rpv="close">Close</button></div>
      <div class="rp-pages">${renderReport(rep)}</div>`;
    box.querySelectorAll('[data-rp-w]').forEach((el) => el.style.setProperty('--w', `${el.dataset.rpW}%`));
    document.body.classList.add('rp-showing');
    box.scrollTop = 0;
    box.querySelector('[data-rpv="print"]')?.focus();
    if (!box.dataset.title) box.dataset.title = document.title;
    document.title = `NodeWatch topology report · ${rep.org}`;
  }
  function closePreview() {
    document.body.classList.remove('rp-showing');
    const box = document.querySelector('#nwReport');
    if (box) {
      box.innerHTML = '';
      if (box.dataset.title) document.title = box.dataset.title;
    }
  }

  window.MistTools = window.MistTools || {};
  window.MistTools.topoReport = { open, show, _renderReport: renderReport };
})();
