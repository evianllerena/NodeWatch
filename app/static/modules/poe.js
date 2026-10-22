const poeEsc = (v) =>
  String(v ?? '').replace(
    /[&<>"']/g,
    (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c],
  );
window.MistTools.poe = (() => {
  // Power Guard has two modes:
  //  * overview (no switch selected): org-wide PoE risk (no site) or site-wide (site selected),
  //    ranked switches, sites, open PoE issues and top power-drawing ports; rows drill down.
  //  * switch: capacity, risk and per-port draw of one switch.
  // Both refresh themselves every 30 s while the page is open. Automatic refreshes are quiet:
  // data is fetched in the background and only the parts that changed are re-rendered, so
  // search, filters, sort, scroll and open dialogs are kept.
  const POE_AUTO_REFRESH_MS = 30000;
  let initd = false,
    loadSeq = 0,
    ports = [],
    nextAutoAt = 0,
    tickTimer = null,
    quietBusy = false,
    lastError = false,
    lastUpdated = null,
    pendingPort = null,
    ov = null,
    ovKey = null,
    tileFilter = '',
    showAllSwitches = false,
    showAllSites = false;
  const ovCache = new Map(); // site id ('' = org) → last overview, shown instantly when returning
  const switchLists = new Map(); // site id → switches, so drilling back and forth is instant
  const rendered = { summary: '', risks: '', ports: '' };
  const $ = (sel) => document.querySelector(sel);
  async function j(u) {
    const r = await fetch(u);
    if (!r.ok)
      throw new Error((await r.json().catch(() => ({ detail: r.statusText }))).detail || r.statusText);
    return r.json();
  }
  const selection = () => ({ site: $('#poeSite')?.value || '', dev: $('#poeSwitch')?.value || '' });
  const viewVisible = () =>
    document.visibilityState === 'visible' && !$('#view-poe')?.classList.contains('hidden');
  function setHtml(sel, key, html) {
    if (rendered[key] === html) return false;
    rendered[key] = html;
    const el = $(sel);
    if (el) el.innerHTML = html;
    return true;
  }
  function clearView(message = 'Select a switch.') {
    setHtml('#poeSummary', 'summary', `<div class="muted">${poeEsc(message)}</div>`);
    setHtml('#poeRisks', 'risks', '');
    setHtml('#poePorts', 'ports', '');
    ports = [];
    lastUpdated = null;
    lastError = false;
    const count = $('#poePortCount');
    if (count) count.textContent = '';
    updateCountdown();
  }
  const watts = (p) => Number(p.poe_watts) || 0;
  function poeModeKey(mode) {
    const m = String(mode || '').toLowerCase();
    if (m.includes('bt')) return 'bt';
    if (m.includes('at')) return 'at';
    if (m.includes('af')) return 'af';
    return '';
  }
  const firstClient = (p) => (Array.isArray(p.clients) && p.clients.length ? p.clients[0] : {});
  const deviceOf = (p) =>
    p.neighbor_system_name ||
    p.client_hostname ||
    firstClient(p).hostname ||
    p.client_manufacturer ||
    p.manufacturer ||
    '';
  const macOf = (p) => p.mac || p.client_mac || firstClient(p).mac || '';
  const ipOf = (p) => p.client_ip || firstClient(p).ip || '';
  function deviceDetail(p) {
    const name = deviceOf(p);
    const parts = [
      p.neighbor_port_desc,
      p.manufacturer && p.manufacturer !== name ? p.manufacturer : '',
      (p.clients || []).length > 1 ? `${p.clients.length} clients` : '',
    ].filter(Boolean);
    return parts.join(' · ');
  }
  function drawClass(w) {
    if (w >= 30) return 'poe-draw-high';
    if (w >= 15) return 'poe-draw-mid';
    return '';
  }
  // Cell with ellipsis: the full text is always available as a tooltip.
  const cell = (text, cls = '', sort) =>
    `<td class="${cls}" title="${poeEsc(text)}"${sort == null ? '' : ` data-sort="${poeEsc(sort)}"`}>${poeEsc(text || '—')}</td>`;
  function portRow(p) {
    const w = watts(p);
    const name = deviceOf(p),
      sub = deviceDetail(p);
    const vlan = p.vlan_id || firstClient(p).vlan || '';
    const ip = ipOf(p);
    const ipVlan = [ip, vlan ? `VLAN ${vlan}` : ''].filter(Boolean).join(' · ');
    const link = p.up ? p.speed || 'Up' : 'Down';
    const portTitle = [p.port_id, p.description].filter(Boolean).join(' — ');
    const deviceTitle = [name, sub].filter(Boolean).join(' — ');
    return (
      `<tr class="poe-row" data-port="${poeEsc(p.port_id)}" tabindex="0" role="button" aria-label="Show all details for port ${poeEsc(p.port_id)}">` +
      `<td class="poe-port-cell" data-sort="${poeEsc(p.port_id)}" title="${poeEsc(portTitle)}"><strong>${poeEsc(p.port_id)}</strong>${p.description ? `<small class="muted poe-sub">${poeEsc(p.description)}</small>` : ''}</td>` +
      `<td class="poe-draw ${drawClass(w)}" data-sort="${w}">${poeEsc(w.toFixed(1))} W</td>` +
      cell(p.poe_mode, 'poe-ellipsis') +
      cell(p.poe_priority, 'poe-ellipsis') +
      `<td class="poe-ellipsis${p.up ? '' : ' poe-link-down'}" data-sort="${p.up ? Number(p.speed_mbps) || 1 : -1}" title="${poeEsc(link)}">${poeEsc(link)}</td>` +
      `<td class="poe-device-cell" title="${poeEsc(deviceTitle)}"><span class="poe-ellipsis-line">${poeEsc(name || '—')}</span>${sub ? `<small class="muted poe-sub">${poeEsc(sub)}</small>` : ''}</td>` +
      cell(macOf(p), 'mono poe-ellipsis') +
      `<td class="poe-ip-cell" data-sort="${poeEsc(ip || (vlan ? `~${vlan}` : ''))}" title="${poeEsc(ipVlan)}"><span class="mono poe-ellipsis-line">${poeEsc(ip || (vlan ? '' : '—'))}</span>${vlan ? `<small class="muted poe-sub">VLAN ${poeEsc(vlan)}</small>` : ''}</td>` +
      '</tr>'
    );
  }
  function filteredRows() {
    let rows = [...ports];
    const q = ($('#poeSearch')?.value || '').trim().toLowerCase();
    if (q)
      rows = rows.filter((p) =>
        [
          p.port_id,
          p.description,
          deviceOf(p),
          p.neighbor_port_desc,
          p.neighbor_mac,
          p.client_mac,
          p.mac,
          ipOf(p),
          p.poe_mode,
          p.poe_priority,
          ...(p.clients || []).flatMap((c) => [c.mac, c.hostname, c.ip]),
        ]
          .join(' ')
          .toLowerCase()
          .includes(q),
      );
    const mode = $('#poeModeFilter')?.value || '';
    if (mode) rows = rows.filter((p) => poeModeKey(p.poe_mode) === mode);
    if ($('#poeHighDraw')?.checked) rows = rows.filter((p) => watts(p) >= 15);
    const sort = $('#poeSort')?.value || 'port';
    if (sort === 'draw_desc') rows.sort((a, b) => watts(b) - watts(a));
    else if (sort === 'draw_asc') rows.sort((a, b) => watts(a) - watts(b));
    else
      rows.sort((a, b) =>
        String(a.port_id || '').localeCompare(String(b.port_id || ''), undefined, { numeric: true }),
      );
    return rows;
  }
  function renderPorts() {
    const rows = filteredRows();
    const html =
      rows.map(portRow).join('') ||
      `<tr><td colspan="8" class="muted">${ports.length ? 'No powered ports match the filter.' : 'No powered ports on this switch.'}</td></tr>`;
    const count = $('#poePortCount');
    if (count)
      count.textContent = ports.length
        ? rows.length === ports.length
          ? `${ports.length} powered ports`
          : `${rows.length} of ${ports.length} powered ports`
        : '';
    if (rendered.ports === html) return;
    // Keep the reader where they were: scroll position and the focused row survive a re-render.
    const wrap = $('#poePortsWrap');
    const scroll = wrap ? [wrap.scrollTop, wrap.scrollLeft] : null;
    const pageY = window.scrollY;
    const focused = document.activeElement?.closest?.('#poePorts tr[data-port]')?.dataset.port;
    setHtml('#poePorts', 'ports', html);
    if (wrap && scroll) [wrap.scrollTop, wrap.scrollLeft] = scroll;
    if (window.scrollY !== pageY) window.scrollTo({ top: pageY, behavior: 'instant' });
    if (focused)
      [...document.querySelectorAll('#poePorts tr[data-port]')]
        .find((r) => r.dataset.port === focused)
        ?.focus({ preventScroll: true });
  }
  const fmtW = (v) => (v == null ? '—' : `${Number(v).toFixed(1)} W`);
  function memberTable(members) {
    if (!members || !members.length) return '';
    return `<div class="table-wrap top-gap poe-members"><table><thead><tr><th>Member (FPC)</th><th>Model</th><th>Serial</th><th>Budget</th><th>Draw</th><th>Used</th></tr></thead><tbody>${members
      .map(
        (m) =>
          `<tr><td data-sort="${poeEsc(m.fpc)}">FPC ${poeEsc(m.fpc)}${m.vc_role ? ` · ${poeEsc(m.vc_role)}` : ''}</td><td>${poeEsc(m.model || '—')}</td><td class="mono">${poeEsc(m.serial || '—')}</td><td data-sort="${Number(m.max_power) || 0}">${poeEsc(fmtW(m.max_power))}</td><td data-sort="${Number(m.power_draw) || 0}">${poeEsc(fmtW(m.power_draw))}</td><td data-sort="${m.utilization_pct ?? -1}">${m.utilization_pct == null ? '—' : `${poeEsc(m.utilization_pct)}%`}</td></tr>`,
      )
      .join('')}</tbody></table></div>`;
  }
  function renderSummary(d) {
    const budgetLabel =
      d.budget_watts == null
        ? d.derived_budget_watts != null
          ? `${d.derived_budget_watts} W derived minimum`
          : 'Unavailable from Mist'
        : `${d.budget_watts} W`;
    const util =
      d.utilization_pct == null
        ? d.derived_utilization_pct == null
          ? '—'
          : `${d.derived_utilization_pct}% derived`
        : `${d.utilization_pct}%`;
    setHtml(
      '#poeSummary',
      'summary',
      `<div class="metric-grid"><div><span>Powered ports</span><strong>${poeEsc(d.powered_ports)}</strong></div><div><span>Current draw</span><strong>${poeEsc(fmtW(d.draw_watts))}</strong></div><div><span>Chassis budget</span><strong>${poeEsc(budgetLabel)}</strong></div><div><span>Utilization</span><strong>${poeEsc(util)}</strong></div></div>` +
        memberTable(d.per_member),
    );
    const notices = [
      ...(d.warnings || []).map((w) => `<div class="notice warning">${poeEsc(w)}</div>`),
      ...(d.notes || []).map((n) => `<div class="notice info">${poeEsc(n)}</div>`),
    ].join('');
    setHtml(
      '#poeRisks',
      'risks',
      notices +
        ((d.risks || [])
          .map(
            (r) =>
              `<div class="finding ${poeEsc(r.severity)}"><b>${poeEsc(r.title)}</b><span>${poeEsc(r.detail)}</span></div>`,
          )
          .join('') || '<div class="notice success">No PoE risk rules triggered.</div>'),
    );
    ports = d.ports || [];
    renderPorts();
  }
  // fresh: Refresh-now only; the 30 s cycle reads Mist's statistics at the rate Mist updates them (~1/min).
  const summaryUrl = ({ site, dev }, fresh = false) =>
    `/api/v1/poe/summary?site_id=${encodeURIComponent(site)}&device_id=${encodeURIComponent(dev)}${fresh ? '&fresh=1' : ''}`;
  const overviewUrl = (site, fresh) =>
    `/api/v1/poe/overview?site_id=${encodeURIComponent(site || '')}${fresh ? '&fresh=1' : ''}`;

  // ======================================================================= overview mode
  const SEV_RANK = { critical: 3, warning: 2, info: 1, ok: 0 };
  const sevClass = (sev) => (sev === 'critical' ? 'sev-crit' : sev === 'warning' ? 'sev-warn' : 'sev-ok');
  const utilSev = (pct) => (pct == null ? 'none' : pct >= 90 ? 'critical' : pct >= 80 ? 'warning' : 'ok');
  const fmtPct = (v) => (v == null ? '—' : `${Math.round(Number(v))}%`);
  const fmtWatts = (v) => (v == null ? '—' : `${Math.round(Number(v)).toLocaleString()} W`);
  const drawOf = (draw, budget) =>
    budget
      ? `${Math.round(Number(draw) || 0).toLocaleString()} / ${Math.round(Number(budget)).toLocaleString()} W`
      : fmtWatts(draw);
  const plural = (n, one, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;
  function ago(ts) {
    const t = Number(ts);
    if (!t) return '';
    const s = Math.max(0, Date.now() / 1000 - (t > 1e12 ? t / 1000 : t));
    if (s < 90) return 'just now';
    if (s < 5400) return `${Math.round(s / 60)} min ago`;
    if (s < 129600) return `${Math.round(s / 3600)} h ago`;
    return `${Math.round(s / 86400)} d ago`;
  }
  const prettyType = (t) => {
    const words = String(t || 'alarm')
      .replace(/^sw_alarm_/i, '')
      .replace(/_/g, ' ')
      .trim()
      .replace(/\bpoe\b/gi, 'PoE')
      .replace(/\b(psu|pem)\b/gi, (m) => m.toUpperCase());
    return words.charAt(0).toUpperCase() + words.slice(1);
  };
  const drillAttrs = (site, dev, port) =>
    `data-site="${poeEsc(site || '')}" data-dev="${poeEsc(dev || '')}"${port ? ` data-port="${poeEsc(port)}"` : ''}`;
  // Bars get their width from data-pct (CSP forbids inline style attributes).
  function applyBars(root) {
    root?.querySelectorAll('[data-pct]').forEach((el) => {
      const pct = Math.max(0, Math.min(100, Number(el.dataset.pct) || 0));
      el.style.setProperty('--pg-pct', `${pct}%`);
    });
  }
  // Replace a region only when its HTML changed; keep page and list scroll positions.
  function swap(sel, key, html) {
    const el = $(sel);
    if (!el || rendered[key] === html) return false;
    const scroller = el.closest('.pg-scroll') || (el.classList.contains('pg-scroll') ? el : null);
    const top = scroller ? scroller.scrollTop : 0;
    const pageY = window.scrollY;
    rendered[key] = html;
    el.innerHTML = html;
    applyBars(el);
    if (scroller) scroller.scrollTop = top;
    if (window.scrollY !== pageY) window.scrollTo({ top: pageY, behavior: 'instant' });
    return true;
  }

  const TILE_DEFS = [
    { key: 'over90', label: 'Switches ≥ 90% budget', sev: 'critical' },
    { key: 'over80', label: 'Switches 80–90% budget', sev: 'warning' },
    { key: 'members', label: 'VC members ≥ 80%', sev: 'warning' },
    { key: 'psu', label: 'PSU problems', sev: 'critical' },
    { key: 'faults', label: 'PoE faults & alarms', sev: 'critical' },
    { key: 'apoff', label: 'PoE APs offline', sev: 'warning' },
    { key: 'apweak', label: 'APs on reduced power', sev: 'warning' },
  ];
  function tileValues(d) {
    const t = d.totals || {};
    return {
      over90: [t.over_90 || 0, 'Highest PoE risk'],
      over80: [t.over_80 || 0, 'Approaching the limit'],
      members: [t.hot_members || 0, 'Single member near its budget'],
      psu: [
        t.psu_problems || 0,
        t.psu_alarms ? `+ ${plural(t.psu_alarms, 'PSU alarm')}` : 'Lower PoE budget',
      ],
      faults: [
        (t.fault_ports || 0) + (t.poe_alarms || 0),
        `${plural(t.fault_ports || 0, 'port')} · ${plural(t.poe_alarms || 0, 'alarm')}`,
      ],
      apoff: [t.aps_offline || 0, `of ${t.aps_total || 0} APs`],
      apweak: [t.aps_constrained || 0, 'Less PoE than requested'],
    };
  }
  function renderTiles(d) {
    const t = d.totals || {};
    const vals = tileValues(d);
    const util = t.utilization_pct;
    let html =
      `<div class="pg-tile pg-tile-total ${sevClass(utilSev(util) === 'none' ? 'ok' : utilSev(util))}"><span class="pg-tile-label">PoE in use</span>` +
      `<strong>${poeEsc(fmtWatts(t.draw_watts))}</strong><small>${t.budget_watts ? `of ${poeEsc(fmtWatts(t.budget_watts))} · ${poeEsc(fmtPct(util))}` : 'No budget reported'} · ${poeEsc(plural(t.powered_ports || 0, 'powered port'))}</small>` +
      `<span class="pg-bar"><i data-pct="${util ?? 0}"></i></span></div>`;
    if (d.scope === 'org')
      html += `<div class="pg-tile ${t.sites_at_risk ? 'sev-warn' : 'sev-ok'}"><span class="pg-tile-label">Sites at risk</span><strong>${poeEsc(t.sites_at_risk || 0)}</strong><small>of ${poeEsc(plural((d.sites || []).length, 'site'))} with PoE switches</small></div>`;
    html += TILE_DEFS.map(({ key, label, sev }) => {
      const [n, sub] = vals[key];
      const cls = n ? sevClass(sev) : 'sev-ok is-zero';
      return `<button type="button" class="pg-tile pg-tile-btn ${cls}${tileFilter === key ? ' is-active' : ''}" data-tile="${key}" aria-pressed="${tileFilter === key}" title="Show only: ${poeEsc(label)}"><span class="pg-tile-label">${poeEsc(label)}</span><strong>${poeEsc(n)}</strong><small>${poeEsc(sub)}</small></button>`;
    }).join('');
    swap('#pgTiles', 'pgTiles', html);
  }

  function switchMatches(sw, key, apSets) {
    const u = sw.utilization_pct;
    switch (key) {
      case 'over90':
        return u != null && u >= 90;
      case 'over80':
        return u != null && u >= 80 && u < 90;
      case 'members':
        return (sw.hot_members || []).length > 0;
      case 'psu':
        return (sw.psu_problems || []).length > 0 || (sw.alarms || []).some((a) => a.kind === 'psu');
      case 'faults':
        return (sw.fault_ports || []).length > 0 || (sw.alarms || []).some((a) => a.kind === 'poe');
      case 'apoff':
        return apSets.off.has(sw.id);
      case 'apweak':
        return apSets.weak.has(sw.id);
      default:
        return true;
    }
  }
  function switchRow(sw, org) {
    const u = sw.utilization_pct;
    const us = utilSev(u);
    const issues = sw.issues || [];
    const chips = issues
      .slice(0, 2)
      .map((i) => `<span class="pg-chip ${sevClass(sw.severity)}" title="${poeEsc(i)}">${poeEsc(i)}</span>`)
      .join('');
    const more =
      issues.length > 2
        ? `<span class="pg-chip" title="${poeEsc(issues.slice(2).join(' · '))}">+${issues.length - 2}</span>`
        : '';
    const offline = sw.status !== 'connected' && sw.status !== 'unknown';
    return (
      `<tr class="pg-row" ${drillAttrs(sw.site_id, sw.id)} tabindex="0" role="button" aria-label="Open PoE details for ${poeEsc(sw.name)}">` +
      `<td class="pg-name-cell" data-sort="${poeEsc(sw.name)}" title="${poeEsc([sw.name, sw.model].filter(Boolean).join(' — '))}"><span class="pg-sev-dot ${sevClass(sw.severity)}" aria-hidden="true"></span><span class="pg-name"><strong>${poeEsc(sw.name)}</strong><small class="muted">${poeEsc(sw.model || '')}${offline ? ' · offline' : ''}</small></span></td>` +
      `<td class="pg-site-col pg-ellipsis" title="${poeEsc(sw.site_name)}">${poeEsc(org ? sw.site_name || '—' : '')}</td>` +
      `<td class="pg-util-cell" data-sort="${u ?? -1}"><span class="pg-util ${sevClass(us)}"><span class="pg-bar"><i data-pct="${u ?? 0}"></i></span><b>${poeEsc(fmtPct(u))}</b></span></td>` +
      `<td class="pg-num" data-sort="${Number(sw.draw_watts) || 0}" title="${poeEsc(`${fmtWatts(sw.draw_watts)} of ${sw.budget_watts ? fmtWatts(sw.budget_watts) : 'no reported budget'}`)}">${poeEsc(drawOf(sw.draw_watts, sw.budget_watts))}</td>` +
      `<td class="pg-num" data-sort="${sw.powered_ports || 0}">${poeEsc(sw.powered_ports || 0)}</td>` +
      `<td class="pg-chips" data-sort="${SEV_RANK[sw.severity] || 0}${String(issues.length).padStart(3, '0')}">${chips + more || '<span class="muted">No issues</span>'}</td>` +
      '</tr>'
    );
  }
  function renderSwitches(d) {
    const org = d.scope === 'org';
    $('#view-poe .pg-switch-table')?.classList.toggle('pg-no-site', !org);
    const apSets = {
      off: new Set((d.aps_offline || []).map((a) => a.switch_id).filter(Boolean)),
      weak: new Set((d.aps_constrained || []).map((a) => a.switch_id).filter(Boolean)),
    };
    const all = d.switches || [];
    const rows = tileFilter ? all.filter((s) => switchMatches(s, tileFilter, apSets)) : all;
    const limit = showAllSwitches ? rows.length : 25;
    const html =
      rows
        .slice(0, limit)
        .map((s) => switchRow(s, org))
        .join('') ||
      `<tr><td colspan="6" class="muted">${all.length ? 'No switches match this filter — see Open PoE issues.' : 'No switches were returned for this scope.'}</td></tr>`;
    swap('#pgSwitches', 'pgSwitches', html);
    const count = $('#pgSwitchCount');
    if (count)
      count.textContent = tileFilter
        ? `${rows.length} of ${plural(all.length, 'switch', 'switches')}`
        : plural(all.length, 'switch', 'switches');
    $('#pgClearFilter')?.classList.toggle('hidden', !tileFilter);
    const more = $('#pgSwitchesMore');
    if (more) {
      more.classList.toggle('hidden', rows.length <= 25);
      more.textContent = showAllSwitches ? 'Show top 25 only' : `Show all ${rows.length} switches`;
    }
  }
  function renderSites(d) {
    const block = $('#pgSitesBlock');
    block?.classList.toggle('hidden', d.scope !== 'org');
    if (d.scope !== 'org') return;
    const all = d.sites || [];
    const limit = showAllSites ? all.length : 8;
    const html =
      all
        .slice(0, limit)
        .map((r) => {
          const chips = [
            r.over_90 ? [`${r.over_90} ≥ 90%`, 'critical'] : null,
            r.over_80 ? [`${r.over_80} at 80–90%`, 'warning'] : null,
            r.psu_problems ? [plural(r.psu_problems, 'PSU problem'), 'critical'] : null,
            r.fault_ports ? [plural(r.fault_ports, 'fault port'), 'critical'] : null,
            r.alarms ? [plural(r.alarms, 'PoE/PSU alarm'), 'warning'] : null,
            r.aps_offline
              ? [`${r.aps_offline} AP${r.aps_offline === 1 ? '' : 's'} offline`, 'warning']
              : null,
            r.aps_constrained
              ? [`${r.aps_constrained} AP${r.aps_constrained === 1 ? '' : 's'} low power`, 'warning']
              : null,
          ].filter(Boolean);
          const u = r.max_utilization_pct;
          return (
            `<tr class="pg-row" ${drillAttrs(r.site_id, '')} tabindex="0" role="button" aria-label="Open the PoE overview for ${poeEsc(r.site_name)}">` +
            `<td class="pg-name-cell" data-sort="${poeEsc(r.site_name)}" title="${poeEsc(r.site_name)}"><span class="pg-sev-dot ${sevClass(r.severity)}" aria-hidden="true"></span><span class="pg-name"><strong>${poeEsc(r.site_name)}</strong></span></td>` +
            `<td class="pg-util-cell" data-sort="${u ?? -1}" title="${poeEsc(r.worst_switch_name || '')}"><span class="pg-util ${sevClass(utilSev(u))}"><span class="pg-bar"><i data-pct="${u ?? 0}"></i></span><b>${poeEsc(fmtPct(u))}</b></span><small class="muted pg-sub">${poeEsc(r.worst_switch_name || '')}</small></td>` +
            `<td class="pg-num" data-sort="${r.switches}">${poeEsc(r.switches)}</td>` +
            `<td class="pg-num" data-sort="${Number(r.draw_watts) || 0}" title="${poeEsc(`${fmtWatts(r.draw_watts)} of ${r.budget_watts ? fmtWatts(r.budget_watts) : 'no reported budget'}`)}">${poeEsc(drawOf(r.draw_watts, r.budget_watts))}</td>` +
            `<td class="pg-chips" data-sort="${SEV_RANK[r.severity] || 0}${String(chips.length).padStart(2, '0')}">${chips.map(([t, s]) => `<span class="pg-chip ${sevClass(s)}">${poeEsc(t)}</span>`).join('') || '<span class="muted">No issues</span>'}</td>` +
            '</tr>'
          );
        })
        .join('') || '<tr><td colspan="5" class="muted">No sites with switches were returned.</td></tr>';
    swap('#pgSites', 'pgSites', html);
    const atRisk = all.filter((r) => r.severity === 'critical' || r.severity === 'warning').length;
    const count = $('#pgSitesCount');
    if (count) count.textContent = `${atRisk} of ${plural(all.length, 'site')} need attention`;
    const more = $('#pgSitesMore');
    if (more) {
      more.classList.toggle('hidden', all.length <= 8);
      more.textContent = showAllSites ? 'Show top 8 only' : `Show all ${all.length} sites`;
    }
  }
  function buildIssues(d) {
    const out = [];
    const org = d.scope === 'org';
    const where = (x) => (org && x.site_name ? ` · ${x.site_name}` : '');
    for (const sw of d.switches || []) {
      const u = sw.utilization_pct;
      if (u != null && u >= 80)
        out.push({
          kind: u >= 90 ? 'over90' : 'over80',
          sev: u >= 90 ? 'critical' : 'warning',
          title: `${sw.name}: PoE budget ${fmtPct(u)} used`,
          detail: `${fmtWatts(sw.draw_watts)} of ${fmtWatts(sw.budget_watts)}${where(sw)}`,
          site: sw.site_id,
          dev: sw.id,
        });
      for (const m of (sw.hot_members || []).filter((x) => u == null || u < 80 || x.utilization_pct >= u + 5))
        out.push({
          kind: 'members',
          sev: m.utilization_pct >= 90 ? 'critical' : 'warning',
          title: `${sw.name}: member FPC ${m.fpc} at ${fmtPct(m.utilization_pct)}`,
          detail: `${fmtWatts(m.power_draw)} of ${fmtWatts(m.max_power)} on this member${where(sw)}`,
          site: sw.site_id,
          dev: sw.id,
        });
      for (const psu of sw.psu_problems || [])
        out.push({
          kind: 'psu',
          sev: 'critical',
          title: `${sw.name}: ${psu.name} ${psu.status} (FPC ${psu.fpc})`,
          detail: `A failed PSU lowers this member's PoE budget${where(sw)}`,
          site: sw.site_id,
          dev: sw.id,
        });
      for (const p of sw.fault_ports || [])
        out.push({
          kind: 'faults',
          sev: 'critical',
          title: `${sw.name} ${p.port_id}: PoE ${p.fault}`,
          detail: [fmtW(p.watts), p.neighbor].filter(Boolean).join(' · ') + where(sw),
          site: sw.site_id,
          dev: sw.id,
          port: p.port_id,
        });
      if (sw.status !== 'connected' && sw.status !== 'unknown')
        out.push({
          kind: 'offline',
          sev: 'warning',
          title: `${sw.name} is ${sw.status}`,
          detail: `PoE values are the last ones Mist received${where(sw)}`,
          site: sw.site_id,
          dev: sw.id,
        });
    }
    for (const a of d.alarms || [])
      out.push({
        kind: a.kind === 'psu' ? 'psu' : 'faults',
        sev: a.severity === 'critical' ? 'critical' : 'warning',
        title: `${prettyType(a.type)} alarm${a.count > 1 ? ` ×${a.count}` : ''}`,
        detail: [a.switch_name, org ? a.site_name : '', ago(a.last_seen)].filter(Boolean).join(' · '),
        site: a.site_id,
        dev: a.switch_id,
      });
    for (const ap of d.aps_offline || [])
      out.push({
        kind: 'apoff',
        sev: 'warning',
        title: `AP ${ap.name} offline`,
        detail:
          (ap.switch_name
            ? `Powered from ${ap.switch_name}${ap.switch_port ? ` ${ap.switch_port}` : ''}`
            : 'Upstream switch not reported') + where(ap),
        site: ap.site_id,
        dev: ap.switch_id,
        port: ap.switch_id ? ap.switch_port : '',
      });
    for (const ap of d.aps_constrained || [])
      out.push({
        kind: 'apweak',
        sev: 'warning',
        title: `AP ${ap.name}: ${ap.reason}`,
        detail:
          (ap.switch_name
            ? `${ap.switch_name}${ap.switch_port ? ` ${ap.switch_port}` : ''}`
            : 'Upstream switch not reported') + where(ap),
        site: ap.site_id,
        dev: ap.switch_id,
        port: ap.switch_id ? ap.switch_port : '',
      });
    return out
      .map((x, i) => ({ ...x, i }))
      .sort((a, b) => (SEV_RANK[b.sev] || 0) - (SEV_RANK[a.sev] || 0) || a.i - b.i);
  }
  function renderIssues(d) {
    const all = buildIssues(d);
    const items = tileFilter ? all.filter((x) => x.kind === tileFilter) : all;
    const shown = items.slice(0, 60);
    const html = shown.length
      ? shown
          .map(
            (x) =>
              `<button type="button" class="pg-issue ${sevClass(x.sev)}" ${drillAttrs(x.site, x.dev, x.port)} title="${poeEsc(x.dev ? 'Open this switch' : 'Open this site')}"><span class="pg-sev-dot ${sevClass(x.sev)}" aria-hidden="true"></span><span class="pg-issue-text"><b>${poeEsc(x.title)}</b><small>${poeEsc(x.detail)}</small></span><span class="pg-go" aria-hidden="true">›</span></button>`,
          )
          .join('') +
        (items.length > shown.length
          ? `<div class="muted pg-more-note">${items.length - shown.length} more — filter with the tiles above or drill into a site.</div>`
          : '')
      : `<div class="notice success">${tileFilter ? 'Nothing open for this filter.' : 'No PoE issues are open in this scope.'}</div>`;
    swap('#pgIssues', 'pgIssues', html);
    const count = $('#pgIssueCount');
    if (count) {
      const crit = items.filter((x) => x.sev === 'critical').length;
      count.textContent = items.length ? `${items.length} open${crit ? ` · ${crit} critical` : ''}` : '';
    }
  }
  function renderTopPorts(d) {
    const rows = d.top_ports || [];
    const max = Math.max(1, ...rows.map((p) => Number(p.watts) || 0));
    const org = d.scope === 'org';
    const html =
      rows
        .map(
          (p) =>
            `<button type="button" class="pg-port" ${drillAttrs(p.site_id, p.switch_id, p.port_id)} title="Open port ${poeEsc(p.port_id)} on ${poeEsc(p.switch_name)}"><span class="pg-port-name"><b>${poeEsc(p.port_id)}</b><small class="muted">${poeEsc([p.switch_name, org ? p.site_name : '', p.neighbor].filter(Boolean).join(' · '))}</small></span><span class="pg-port-w ${p.watts >= 30 ? 'poe-draw-high' : p.watts >= 15 ? 'poe-draw-mid' : ''}">${poeEsc(fmtW(p.watts))}</span><span class="pg-bar pg-port-bar"><i data-pct="${((Number(p.watts) || 0) / max) * 100}"></i></span></button>`,
        )
        .join('') || '<div class="muted">No powered ports reported.</div>';
    swap('#pgTopPorts', 'pgTopPorts', html);
  }
  function renderOverview(d) {
    ov = d;
    const org = d.scope === 'org';
    const scope = $('#pgScope'),
      title = $('#pgTitle');
    if (scope) scope.textContent = `PoE power safety · ${org ? 'All sites' : d.site_name || 'This site'}`;
    if (title) title.textContent = org ? 'Where PoE needs attention' : 'Site PoE overview';
    swap(
      '#pgWarnings',
      'pgWarnings',
      (d.warnings || []).map((w) => `<div class="notice warning">${poeEsc(w)}</div>`).join(''),
    );
    renderTiles(d);
    renderSites(d);
    renderSwitches(d);
    renderIssues(d);
    renderTopPorts(d);
  }
  function rerenderOverview() {
    if (ov) renderOverview(ov);
  }
  function overviewMessage(html) {
    for (const k of ['pgTiles', 'pgSites', 'pgSwitches', 'pgIssues', 'pgTopPorts']) rendered[k] = '';
    ['#pgSites', '#pgSwitches', '#pgIssues', '#pgTopPorts'].forEach((sel) => {
      const el = $(sel);
      if (el) el.innerHTML = '';
    });
    swap('#pgTiles', 'pgTiles', html);
  }
  function setMode(dev) {
    $('#poeOverview')?.classList.toggle('hidden', Boolean(dev));
    $('#view-poe .poe-layout')?.classList.toggle('hidden', !dev);
  }
  async function fetchOverview(site, fresh) {
    const d = await j(overviewUrl(site, fresh));
    ovCache.set(site || '', d);
    return d;
  }

  // ---- refresh countdown (same pattern as Command Center: nextAutoAt + 1 s ticker) ----
  function updateCountdown() {
    const meta = $('#poeRefreshMeta'),
      el = $('#poeCountdown'),
      upd = $('#poeUpdated');
    if (!meta || !el) return;
    const active = Boolean(lastUpdated);
    meta.classList.toggle('is-idle', !active && !quietBusy);
    meta.classList.toggle('is-busy', quietBusy);
    meta.classList.toggle('is-paused', active && !tickTimer && !quietBusy);
    $('#poeRefreshError')?.classList.toggle('hidden', !lastError);
    if (upd)
      upd.textContent = lastUpdated
        ? `Updated ${lastUpdated.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}`
        : '';
    if (quietBusy) el.textContent = 'Refreshing…';
    else if (!lastUpdated) el.textContent = lastError ? 'Waiting for data' : 'Loading…';
    else if (!tickTimer) el.textContent = 'Auto-refresh paused';
    else el.textContent = `Refresh in ${Math.max(0, Math.ceil((nextAutoAt - Date.now()) / 1000))}s`;
  }
  function stopTimer() {
    if (tickTimer) clearInterval(tickTimer);
    tickTimer = null;
  }
  function tick() {
    if (!viewVisible()) {
      // Page left or window hidden: stop ticking; refresh() / visibilitychange resume it.
      stopTimer();
      updateCountdown();
      return;
    }
    if (!quietBusy && Date.now() >= nextAutoAt) quietRefresh();
    updateCountdown();
  }
  function startTimer() {
    if (!viewVisible()) return;
    if (!tickTimer) tickTimer = setInterval(tick, 1000);
    updateCountdown();
  }
  function schedule() {
    nextAutoAt = Date.now() + POE_AUTO_REFRESH_MS;
    startTimer();
  }
  // Background refresh: never clears the page, never shows "Loading…".
  async function quietRefresh(fresh = false) {
    const sel = selection();
    if (quietBusy) return;
    const seq = loadSeq;
    quietBusy = true;
    updateCountdown();
    try {
      if (sel.dev) {
        const d = await j(summaryUrl(sel, fresh));
        if (seq !== loadSeq) return;
        renderSummary(d);
      } else {
        const d = await fetchOverview(sel.site, fresh);
        if (seq !== loadSeq) return;
        renderOverview(d);
      }
      lastUpdated = new Date();
      lastError = false;
    } catch (err) {
      if (seq !== loadSeq) return;
      lastError = true;
      console.warn('Power Guard refresh failed', err);
    } finally {
      quietBusy = false;
      if (seq === loadSeq) schedule();
      updateCountdown();
    }
  }
  async function loadOverview(seq, site) {
    const key = site || '';
    if (ovKey !== key) {
      tileFilter = '';
      showAllSwitches = false;
      showAllSites = false;
    }
    ovKey = key;
    const cached = ovCache.get(key);
    // Coming back to an overview we already have: show it instantly, then refresh quietly.
    if (cached) {
      renderOverview(cached);
      lastUpdated = new Date(cached.generated_at * 1000 || Date.now());
      updateCountdown();
      return quietRefresh();
    }
    lastUpdated = null;
    overviewMessage(
      `<div class="notice info pg-loading">Loading ${site ? 'site' : 'organization'} PoE overview…</div>`,
    );
    updateCountdown();
    try {
      const d = await fetchOverview(site, false);
      if (seq !== loadSeq) return;
      renderOverview(d);
      lastUpdated = new Date();
    } catch (err) {
      if (seq !== loadSeq) return;
      lastError = true;
      overviewMessage(
        `<div class="notice warning">Unable to load the PoE overview: ${poeEsc(err.message)}</div>`,
      );
    }
    schedule();
  }
  // Full load (switch / site changed): the old data belongs to another scope.
  async function load() {
    const sel = selection();
    const seq = ++loadSeq;
    quietBusy = false;
    lastError = false;
    setMode(sel.dev);
    if (!sel.dev) return loadOverview(seq, sel.site);
    ports = [];
    lastUpdated = null;
    setHtml('#poeRisks', 'risks', '');
    setHtml('#poePorts', 'ports', '');
    setHtml('#poeSummary', 'summary', '<div class="notice info">Loading live PoE data…</div>');
    updateCountdown();
    try {
      const d = await j(summaryUrl(sel));
      if (seq !== loadSeq) return;
      renderSummary(d);
      lastUpdated = new Date();
      openPendingPort();
    } catch (err) {
      if (seq === loadSeq) {
        lastError = true;
        clearView(`Unable to load PoE data: ${err.message}`);
      }
    }
    if (seq === loadSeq) schedule();
  }
  // Called by the shell when the page is opened again: resume quietly (refresh now if stale).
  async function resume() {
    if (!lastUpdated) return load();
    if (Date.now() >= nextAutoAt) await quietRefresh();
    else startTimer();
  }
  function refreshNow() {
    return lastUpdated ? quietRefresh(true) : load();
  }

  // ---- row → full port details (Port Toolkit dialog) ----
  function showPort(portId) {
    const p = ports.find((x) => String(x.port_id) === String(portId));
    const ops = window.MistTools.operations;
    if (p && ops?.showPortDetails) ops.showPortDetails(p);
    return Boolean(p);
  }
  function openPendingPort() {
    const port = pendingPort;
    pendingPort = null;
    if (port) showPort(port);
  }
  function openPort(row) {
    showPort(row?.dataset.port);
  }
  function onRowClick(e) {
    const row = e.target.closest('tr[data-port]');
    if (!row) return;
    if (String(window.getSelection?.() || '').trim()) return; // user is selecting text to copy
    openPort(row);
  }
  function onRowKey(e) {
    if (e.key !== 'Enter' && e.key !== ' ') return;
    const row = e.target.closest('tr[data-port]');
    if (!row || e.target !== row) return;
    e.preventDefault();
    openPort(row);
  }

  // ---- site / switch selection and drill-down ----
  async function populateSwitches(site) {
    const sw = $('#poeSwitch');
    if (!site) {
      sw.innerHTML = '<option value="">All switches — org overview</option>';
      return;
    }
    let rows = switchLists.get(site);
    if (!rows) {
      sw.innerHTML = '<option value="">Loading switches…</option>';
      try {
        rows = await j(`/api/v1/operations/switches?site_id=${encodeURIComponent(site)}`);
        rows.sort((a, b) => String(a.name || '').localeCompare(String(b.name || '')));
        switchLists.set(site, rows);
      } catch (err) {
        console.warn('Power Guard could not list switches', err);
        rows = [];
      }
    }
    sw.innerHTML =
      '<option value="">All switches — site overview</option>' +
      rows.map((x) => `<option value="${poeEsc(x.id)}">${poeEsc(x.name)}</option>`).join('');
  }
  async function drill(site, dev, port) {
    const s = $('#poeSite'),
      sw = $('#poeSwitch');
    if (!s || !sw) return;
    ++loadSeq; // cancel anything in flight for the old scope
    if (site && ![...s.options].some((o) => o.value === site)) return;
    if (s.value !== site || sw.options.length <= 1) {
      s.value = site;
      await populateSwitches(site);
    }
    sw.value = dev && [...sw.options].some((o) => o.value === dev) ? dev : '';
    pendingPort = sw.value ? port || null : null;
    $('#view-poe .pg-toolbar')?.scrollIntoView({ block: 'nearest' });
    await load();
  }
  function onDrillClick(e) {
    const tile = e.target.closest('[data-tile]');
    if (tile) {
      tileFilter = tileFilter === tile.dataset.tile ? '' : tile.dataset.tile;
      showAllSwitches = false;
      rerenderOverview();
      return;
    }
    const target = e.target.closest('[data-site]');
    if (!target) return;
    if (target.tagName === 'TR' && String(window.getSelection?.() || '').trim()) return;
    drill(target.dataset.site, target.dataset.dev, target.dataset.port);
  }
  function onDrillKey(e) {
    if (e.key !== 'Enter' && e.key !== ' ') return;
    const row = e.target.closest('tr[data-site]');
    if (!row || e.target !== row) return;
    e.preventDefault();
    drill(row.dataset.site, row.dataset.dev, row.dataset.port);
  }

  async function siteChanged() {
    ++loadSeq;
    await populateSwitches($('#poeSite').value);
    $('#poeSwitch').value = '';
    await load();
  }
  async function init() {
    if (initd) return;
    initd = true;
    const s = $('#poeSite');
    s.addEventListener('change', siteChanged);
    $('#poeSwitch').addEventListener('change', () => load());
    $('#poeRefresh').addEventListener('click', refreshNow);
    $('#poeRefreshNow')?.addEventListener('click', refreshNow);
    $('#poeBackOverview')?.addEventListener('click', () => {
      $('#poeSwitch').value = '';
      load();
    });
    $('#poeSearch')?.addEventListener('input', renderPorts);
    $('#poeSort')?.addEventListener('change', renderPorts);
    $('#poeModeFilter')?.addEventListener('change', renderPorts);
    $('#poeHighDraw')?.addEventListener('change', renderPorts);
    $('#poePorts')?.addEventListener('click', onRowClick);
    $('#poePorts')?.addEventListener('keydown', onRowKey);
    const overview = $('#poeOverview');
    overview?.addEventListener('click', onDrillClick);
    overview?.addEventListener('keydown', onDrillKey);
    $('#pgClearFilter')?.addEventListener('click', () => {
      tileFilter = '';
      rerenderOverview();
    });
    $('#pgSwitchesMore')?.addEventListener('click', () => {
      showAllSwitches = !showAllSwitches;
      rerenderOverview();
    });
    $('#pgSitesMore')?.addEventListener('click', () => {
      showAllSites = !showAllSites;
      rerenderOverview();
    });
    document.addEventListener('visibilitychange', () => {
      if (viewVisible()) resume().catch(() => {});
    });
    // The org overview does not need the site list, so both load in parallel.
    const sitesP = j('/api/v1/operations/sites')
      .then((rows) => {
        rows.sort((a, b) => String(a.name || '').localeCompare(String(b.name || '')));
        const keep = s.value;
        s.innerHTML =
          '<option value="">All sites — org overview</option>' +
          rows.map((x) => `<option value="${poeEsc(x.id)}">${poeEsc(x.name)}</option>`).join('');
        s.value = keep;
      })
      .catch((err) => console.warn('Power Guard could not list sites', err));
    await populateSwitches('');
    await Promise.all([sitesP, load()]);
  }
  // The shell's generic 30 s auto-refresh would duplicate our own timer, so autoRefresh is a no-op.
  return { init, refresh: () => resume(), autoRefresh: async () => {} };
})();
