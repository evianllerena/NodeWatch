window.MistTools = window.MistTools || {};

window.MistTools.detective = (() => {
  let sites = [],
    visibleSites = [];
  let lastSearch = null,
    selected = null,
    detailData = null,
    trafficData = null;
  let busy = false,
    searchSeq = 0,
    detailSeq = 0,
    trafficSeq = 0;
  let refreshTimer = null,
    countdownTimer = null,
    nextRefreshAt = 0;
  let resultPage = 1,
    pageSize = 100;
  const REFRESH_SECONDS = 15;

  const esc = (v) =>
    String(v ?? '').replace(
      /[&<>'"]/g,
      (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' })[c],
    );
  const present = (v) => !(v === undefined || v === null || v === '');
  async function getJSON(url) {
    const r = await fetch(url);
    if (!r.ok) {
      let t = await r.text();
      try {
        t = JSON.parse(t).detail || t;
      } catch {}
      throw new Error(t || `HTTP ${r.status}`);
    }
    return r.json();
  }
  function cleanMac(value) {
    return String(value ?? '')
      .replace(/[^0-9a-f]/gi, '')
      .toLowerCase();
  }
  function formatMac(value) {
    const raw = cleanMac(value);
    return raw.length === 12 ? raw.match(/.{2}/g).join(':') : String(value ?? '');
  }
  function isExactIp(value) {
    const q = String(value || '').trim();
    return (
      /^(?:\d{1,3}\.){3}\d{1,3}$/.test(q) && q.split('.').every((x) => Number(x) >= 0 && Number(x) <= 255)
    );
  }
  function isExactMac(value) {
    return cleanMac(value).length === 12;
  }
  function parseTime(value) {
    if (value === undefined || value === null || value === '') return null;
    if (typeof value === 'number' || /^\d+(\.\d+)?$/.test(String(value))) {
      let n = Number(value);
      if (!Number.isFinite(n)) return null;
      if (n < 100000000000) n *= 1000;
      const d = new Date(n);
      return Number.isNaN(d.getTime()) ? null : d;
    }
    const d = new Date(String(value));
    return Number.isNaN(d.getTime()) ? null : d;
  }
  function formatTime(value, absolute = false) {
    const d = parseTime(value);
    if (!d) return String(value ?? 'Not reported');
    const diff = Date.now() - d.getTime(),
      ms = Math.abs(diff),
      future = diff < 0;
    let text = 'just now';
    if (ms >= 60_000 && ms < 3_600_000)
      text = `${Math.floor(ms / 60_000)} min ${future ? 'from now' : 'ago'}`;
    else if (ms >= 3_600_000 && ms < 86_400_000)
      text = `${Math.floor(ms / 3_600_000)} hr ${future ? 'from now' : 'ago'}`;
    else if (ms >= 86_400_000 && ms < 7 * 86_400_000) {
      const n = Math.floor(ms / 86_400_000);
      text = `${n} day${n === 1 ? '' : 's'} ${future ? 'from now' : 'ago'}`;
    } else if (ms >= 7 * 86_400_000) text = d.toLocaleString();
    return absolute && ms < 7 * 86_400_000 ? `${text} · ${d.toLocaleString()}` : text;
  }
  function setLoading(on, message = 'Working...') {
    busy = on;
    const btn = document.querySelector('#detectiveSearchBtn');
    if (btn) {
      btn.disabled = on;
      btn.textContent = on ? message : 'Investigate';
    }
  }
  function clientProfile(item) {
    const p = item?.client_profile || {};
    if (item.kind === 'endpoint')
      return { label: item.intelligence_category || item.device_type || 'Endpoint' };
    if (item.kind === 'infrastructure')
      return {
        label:
          item.device_type === 'switch'
            ? 'Switch'
            : item.device_type === 'ap'
              ? 'Access Point'
              : item.device_type === 'gateway'
                ? 'Gateway'
                : 'Device',
      };
    return {
      label:
        p.label ||
        item.device_type ||
        (item.kind === 'wired_client'
          ? 'Wired client'
          : item.kind === 'wireless_client'
            ? 'Wireless client'
            : item.kind_label || 'Client'),
    };
  }
  function connectionLabel(r) {
    if (r.kind === 'wireless_client') return 'Wireless';
    if (r.kind === 'wired_client') return 'Wired';
    if (r.kind === 'nac_client') return 'NAC';
    if (r.kind === 'infrastructure') return 'Infrastructure';
    return 'Endpoint';
  }
  function vendorLabel(r) {
    if (r.vendor) return String(r.vendor);
    const sub = String(r.subtitle || '').trim();
    if (!sub || sub === r.display_mac || /wired client|wireless client|endpoint/i.test(sub)) return 'Unknown';
    return (
      sub
        .split(/\s{2,}|\s[-|]\s/)[0]
        .trim()
        .slice(0, 50) || 'Unknown'
    );
  }
  function resultType(r) {
    return String(r.device_type || r.intelligence_category || clientProfile(r).label || 'Unknown');
  }

  function renderSiteOptions() {
    const select = document.querySelector('#detectiveSite');
    if (!select) return;
    const current = select.value;
    select.innerHTML =
      '<option value="">All Sites</option>' +
      visibleSites.map((s) => `<option value="${esc(s.id)}">${esc(s.name)}</option>`).join('');
    if ([...select.options].some((o) => o.value === current)) select.value = current;
  }
  function filterSites() {
    const q = (document.querySelector('#detectiveSiteSearch')?.value || '').trim().toLowerCase();
    visibleSites = q
      ? sites.filter((s) =>
          String(s.name || '')
            .toLowerCase()
            .includes(q),
        )
      : sites;
    renderSiteOptions();
  }
  async function loadSites() {
    try {
      sites = (await getJSON('/api/detective/sites')).sort((a, b) =>
        String(a.name || '').localeCompare(String(b.name || '')),
      );
      visibleSites = [...sites];
      filterSites();
    } catch (err) {
      console.warn('Unable to load Detective sites', err);
    }
  }
  function populateSelect(id, values, allLabel) {
    const el = document.querySelector(id);
    if (!el) return;
    const current = el.value;
    const clean = [...new Set(values.filter(Boolean).map((v) => String(v)))].sort((a, b) =>
      a.localeCompare(b),
    );
    el.innerHTML =
      `<option value="">${esc(allLabel)}</option>` +
      clean.map((v) => `<option value="${esc(v)}">${esc(v)}</option>`).join('');
    if (clean.includes(current)) el.value = current;
  }
  function updateResultFilters() {
    const rows = lastSearch?.results || [];
    populateSelect('#detectiveConnectionFilter', rows.map(connectionLabel), 'Connection: All');
    populateSelect('#detectiveTypeFilter', rows.map(resultType), 'Type: All');
    populateSelect(
      '#detectiveVendorFilter',
      rows.map(vendorLabel).filter((v) => v !== 'Unknown'),
      'Vendor: All',
    );
  }
  function ipSortValue(ip) {
    const p = String(ip || '')
      .split('.')
      .map(Number);
    if (p.length !== 4 || p.some((x) => !Number.isFinite(x))) return Number.MAX_SAFE_INTEGER;
    return ((p[0] * 256 + p[1]) * 256 + p[2]) * 256 + p[3];
  }
  function filteredResults() {
    let rows = [...(lastSearch?.results || [])];
    const q = (document.querySelector('#detectiveResultSearch')?.value || '').trim().toLowerCase();
    const conn = document.querySelector('#detectiveConnectionFilter')?.value || '';
    const type = document.querySelector('#detectiveTypeFilter')?.value || '';
    const vendor = document.querySelector('#detectiveVendorFilter')?.value || '';
    const sort = document.querySelector('#detectiveSort')?.value || 'relevance';
    if (q)
      rows = rows.filter((r) =>
        [
          r.title,
          r.subtitle,
          r.ip,
          r.display_mac,
          r.site,
          r.attachment,
          r.port_id,
          r.username,
          r.hostname,
          vendorLabel(r),
          resultType(r),
          connectionLabel(r),
        ].some((v) =>
          String(v || '')
            .toLowerCase()
            .includes(q),
        ),
      );
    if (conn) rows = rows.filter((r) => connectionLabel(r) === conn);
    if (type) rows = rows.filter((r) => resultType(r) === type);
    if (vendor) rows = rows.filter((r) => vendorLabel(r) === vendor);
    if (sort === 'last_seen')
      rows.sort(
        (a, b) => (parseTime(b.last_seen)?.getTime() || 0) - (parseTime(a.last_seen)?.getTime() || 0),
      );
    else if (sort === 'hostname')
      rows.sort((a, b) =>
        String(a.title || a.hostname || '').localeCompare(String(b.title || b.hostname || '')),
      );
    else if (sort === 'ip') rows.sort((a, b) => ipSortValue(a.ip) - ipSortValue(b.ip));
    else if (sort === 'vendor') rows.sort((a, b) => vendorLabel(a).localeCompare(vendorLabel(b)));
    else if (sort === 'type') rows.sort((a, b) => resultType(a).localeCompare(resultType(b)));
    else
      rows.sort(
        (a, b) =>
          (Number(b.score) || 0) - (Number(a.score) || 0) ||
          (parseTime(b.last_seen)?.getTime() || 0) - (parseTime(a.last_seen)?.getTime() || 0),
      );
    return rows;
  }
  function resultButton(r, idx) {
    const active =
      selected &&
      selected.kind === r.kind &&
      cleanMac(selected.mac) === cleanMac(r.mac) &&
      String(selected.site_id || '') === String(r.site_id || '');
    const seen = r.last_seen ? formatTime(r.last_seen) : '';
    const type = resultType(r),
      conn = connectionLabel(r),
      vendor = vendorLabel(r);
    return `<button class="detective-result ${active ? 'active' : ''}" data-result-index="${idx}"><span class="detective-result-icon">${esc(conn === 'Wireless' ? 'Wi' : conn === 'Wired' ? 'LAN' : conn === 'Infrastructure' ? 'NW' : 'ID')}</span><span class="detective-result-copy"><span class="detective-result-title"><strong>${esc(r.title || r.hostname || r.display_mac || 'Unknown device')}</strong><em>${esc(conn)}</em></span><span class="detective-result-sub">${esc([type, vendor !== 'Unknown' ? vendor : ''].filter(Boolean).join(' · '))}</span><span class="detective-result-path">${esc(r.site || 'Unknown site')}${r.attachment ? ` → ${esc(r.attachment)}` : ''}${r.port_id ? ` → ${esc(r.port_id)}` : ''}</span><span class="detective-result-meta">${r.ip ? `<span>${esc(r.ip)}</span>` : ''}${r.display_mac ? `<code>${esc(formatMac(r.display_mac))}</code>` : ''}${r.vlan ? `<span>VLAN ${esc(r.vlan)}</span>` : ''}${seen ? `<span>Seen ${esc(seen)}</span>` : ''}</span></span></button>`;
  }
  function selectResult(row, button = null) {
    selected = row;
    trafficData = null;
    document
      .querySelectorAll('#detectiveResults .detective-result')
      .forEach((x) => x.classList.remove('active'));
    if (button) button.classList.add('active');
    showDetailLoading(row);
    loadDetail(false);
    // Start the firewall-log query right away (it is the slowest part) instead of after the detail loads.
    if (row?.ip) loadTraffic(false);
  }
  function resetPage() {
    resultPage = 1;
  }
  // The results list has the same pager above and below it (ids with and without "Top").
  const PAGER_SUFFIXES = ['Top', ''];
  function updatePagers(start, end, total, pages) {
    PAGER_SUFFIXES.forEach((sfx) => {
      const pager = document.querySelector(`#detectivePagination${sfx}`);
      if (!pager) return;
      pager.classList.toggle('hidden', !total);
      const info = document.querySelector(`#detectivePageInfo${sfx}`);
      if (info)
        info.textContent = total
          ? `Showing ${start + 1}–${end} of ${total}${pages > 1 ? ` · Page ${resultPage} of ${pages}` : ''}`
          : '';
      const prev = document.querySelector(`#detectivePrevPage${sfx}`),
        next = document.querySelector(`#detectiveNextPage${sfx}`),
        size = document.querySelector(`#detectivePageSize${sfx}`);
      if (prev) prev.disabled = resultPage <= 1;
      if (next) next.disabled = resultPage >= pages;
      if (size) size.value = String(pageSize);
    });
  }
  function renderResults() {
    const host = document.querySelector('#detectiveResults'),
      count = document.querySelector('#detectiveResultCount');
    if (!host || !count) return;
    const rows = filteredResults();
    const totalRaw = lastSearch?.results?.length || 0;
    count.textContent = rows.length === totalRaw ? String(totalRaw) : `${rows.length}/${totalRaw}`;
    if (!rows.length) {
      host.innerHTML =
        '<div class="detective-empty"><strong>No matching results.</strong><span>Adjust the filters or investigate another site/search.</span></div>';
      updatePagers(0, 0, 0, 1);
      return;
    }
    const pages = Math.max(1, Math.ceil(rows.length / pageSize));
    resultPage = Math.min(Math.max(1, resultPage), pages);
    const start = (resultPage - 1) * pageSize,
      end = Math.min(start + pageSize, rows.length),
      pageRows = rows.slice(start, end);
    host.innerHTML = pageRows.map((r, i) => resultButton(r, start + i)).join('');
    host.querySelectorAll('[data-result-index]').forEach((btn) => {
      const row = rows[Number(btn.dataset.resultIndex)];
      btn.addEventListener('click', () => selectResult(row, btn));
      // Hover / keyboard focus: start the slow firewall-log query before the click.
      btn.addEventListener('mouseenter', () => prefetchTraffic(row));
      btn.addEventListener('focus', () => prefetchTraffic(row));
      btn.addEventListener('mouseleave', cancelTrafficPrefetch);
    });
    updatePagers(start, end, rows.length, pages);
  }
  function renderResultScope(data) {
    const el = document.querySelector('#detectiveResultScope');
    if (!el) return;
    const parts = [];
    if (data?.mode !== 'simulation')
      parts.push(
        `Clients seen in the last ${data?.client_lookback === '7d' || !data?.client_lookback ? '7 days' : esc(data.client_lookback)}; infrastructure from Mist inventory.`,
      );
    if (data?.query_type === 'ip_prefix') parts.push(`IP addresses starting with “${esc(data.query)}”.`);
    let html = parts.length ? `<span>${parts.join(' ')}</span>` : '';
    if (data?.truncated) {
      const which = (data.truncated_sources || []).map(esc).join(', ') || 'one source';
      html += `<strong class="detective-truncated">Results are incomplete: ${which} reached the ${Number(data.source_limit || 0).toLocaleString()}-row limit. Narrow the search to see everything.</strong>`;
    }
    const failed = [...new Set((data?.errors || []).map((e) => e.source).filter(Boolean))];
    if (failed.length)
      html += `<strong class="detective-truncated">Some sources could not be read (${failed.map(esc).join(', ')}); results may be incomplete.</strong>`;
    el.innerHTML = html;
    el.classList.toggle('hidden', !html);
  }
  function autoSelectExact(query) {
    const rows = lastSearch?.results || [];
    if (!rows.length) return false;
    let match = null;
    if (isExactIp(query)) match = rows.find((r) => String(r.ip || '').trim() === query.trim());
    else if (isExactMac(query)) {
      const m = cleanMac(query);
      match = rows.find((r) => cleanMac(r.mac || r.display_mac) === m);
    }
    if (!match) return false;
    selectResult(match);
    return true;
  }

  async function runSearch() {
    if (busy) return;
    const q = document.querySelector('#detectiveQuery').value.trim(),
      siteId = document.querySelector('#detectiveSite').value;
    if (q.length < 2 && !siteId) {
      document.querySelector('#detectiveSearchMeta').textContent =
        'Select a site to list its devices, or enter at least two search characters.';
      return;
    }
    const seq = ++searchSeq;
    setLoading(true, 'Searching...');
    const started = performance.now();
    try {
      const params = new URLSearchParams({ q });
      if (siteId) params.set('site_id', siteId);
      const data = await getJSON(`/api/detective/search?${params}`);
      if (seq !== searchSeq) return;
      if (siteId)
        data.results = (data.results || []).filter((r) => String(r.site_id || '') === String(siteId));
      data.total = (data.results || []).length;
      lastSearch = data;
      renderResultScope(data);
      selected = null;
      detailData = null;
      resetDetail();
      resetPage();
      updateResultFilters();
      renderResults();
      const elapsed = Math.round(performance.now() - started),
        mode = data.mode === 'simulation' ? 'Preview data' : 'Live data';
      document.querySelector('#detectiveSearchMeta').textContent =
        `${mode} · ${data.total || 0} matches · ${elapsed < 1000 ? `${elapsed} ms` : `${(elapsed / 1000).toFixed(1)} s`}`;
      if (q) autoSelectExact(q);
    } catch (err) {
      if (seq !== searchSeq) return;
      console.error(err);
      document.querySelector('#detectiveSearchMeta').textContent = `Search failed: ${err.message}`;
      document.querySelector('#detectiveResults').innerHTML =
        `<div class="detective-empty error"><strong>Search failed.</strong><span>${esc(err.message)}</span></div>`;
    } finally {
      if (seq === searchSeq) setLoading(false);
    }
  }
  function resetDetail() {
    document.querySelector('#detectiveDetail')?.classList.add('hidden');
    const empty = document.querySelector('#detectiveDetailEmpty');
    if (!empty) return;
    empty.classList.remove('hidden');
    empty.innerHTML =
      '<div class="detective-empty-icon">⌕</div><strong>Select a result</strong><span>Device, live connection, security, conditions, traffic, and deeper context will appear here.</span>';
    stopCountdown('Select a device');
  }
  function showDetailLoading(item) {
    document.querySelector('#detectiveDetail')?.classList.add('hidden');
    const empty = document.querySelector('#detectiveDetailEmpty');
    empty?.classList.remove('hidden');
    if (empty)
      empty.innerHTML = `<div class="detective-empty-icon detective-pulse">⌕</div><strong>Building investigation…</strong><span>${esc(item.title || item.display_mac || 'Selected device')}</span>`;
  }
  function fieldValue(id, value) {
    if (value === true || value === false) return value ? 'Yes' : 'No';
    if (id === 'device.mac') return formatMac(value);
    if (/first_seen|last_activity|last_seen|receive_time/.test(id)) return formatTime(value, true);
    if (id === 'security.confidence' && present(value)) return `${value}%`;
    if (id === 'network.rssi' && present(value)) return `${value} dBm`;
    if (id === 'network.band' && present(value))
      return String(value).match(/ghz/i) ? String(value) : `${value} GHz`;
    if (id === 'security.endpoint_protection') {
      const t = String(value).replaceAll('_', ' ').trim();
      if (/not protected/i.test(t)) return 'Not detected / not reported';
      return t;
    }
    return String(value ?? '');
  }
  function rowsHtml(defs, values) {
    return defs
      .filter(([id]) => present(values[id]))
      .map(
        ([id, label]) =>
          `<div class="detective-unified-row"><span>${esc(label)}</span><strong title="${esc(fieldValue(id, values[id]))}">${esc(fieldValue(id, values[id]))}</strong></div>`,
      )
      .join('');
  }
  function renderCore(data) {
    const v = data.fields || {};
    const deviceDefs = [
      ['device.hostname', 'Hostname'],
      ['device.ip', 'IP Address'],
      ['device.mac', 'MAC Address'],
      ['device.vendor', 'Vendor'],
      ['device.category', 'Device Type'],
      ['device.model', 'Model'],
      ['security.confidence', 'Classification Confidence'],
    ];
    const connDefs = [
      ['network.site', 'Site'],
      ['network.connection_type', 'Connection'],
      ['network.ssid', 'SSID'],
      ['network.vlan', 'VLAN'],
      ['network.switch', 'Switch'],
      ['network.port', 'Port'],
      ['network.ap', 'Access Point'],
      ['network.band', 'Band'],
      ['network.channel', 'Channel'],
      ['network.rssi', 'RSSI'],
      ['security.last_activity', 'Last Seen'],
    ];
    const securityDefs = [
      ['security.risk_level', 'Risk'],
      ['security.risk_score', 'Risk Score'],
      ['security.internet_access', 'Internet Access'],
      ['security.endpoint_protection', 'Endpoint Protection'],
      ['identity.auth_method', 'Authentication'],
      ['identity.username', 'Identity'],
      ['identity.nac_profile', 'NAC Profile'],
      ['identity.nac_state', 'NAC State'],
    ];
    document.querySelector('#detectiveDeviceRows').innerHTML =
      rowsHtml(deviceDefs, v) || '<div class="detective-none">No device identity returned.</div>';
    document.querySelector('#detectiveConnectionRows').innerHTML =
      rowsHtml(connDefs, v) || '<div class="detective-none">No live connection returned.</div>';
    const sec = rowsHtml(securityDefs, v),
      section = document.querySelector('#detectiveSecuritySection');
    section.classList.remove('hidden');
    document.querySelector('#detectiveSecurityRows').innerHTML =
      sec ||
      '<div class="detective-none">No additional security/access fields reported for this endpoint.</div>';
  }
  // ---- Conditions · Requires attention (v0.10.24) -------------------------------------------------
  // Each open condition is a keyboard-accessible row that expands to WHAT, WHERE (site, devices with
  // Device Finder / Topology links, ports), since when, which system reported it and the fix if known.
  // The backend sends neutral ``conditions``; sample/older payloads fall back to the raw alarm rows.
  let conditionFilter = 'all';
  function conditionRows(data) {
    if (Array.isArray(data.conditions)) return data.conditions;
    return (data.alarms || []).map((a, i) => ({
      key: String(a.id || i),
      title: String(a.title || a.type || 'Active condition').replaceAll('_', ' '),
      severity: /crit|major/i.test(a.severity || '') ? 'critical' : /warn|minor/i.test(a.severity || '') ? 'warning' : 'info',
      detail: a.text || a.detail || a.message || '',
      fix: '',
      site: '',
      devices: [],
      ports: [],
      since: a.timestamp || '',
      last_seen: a.last_seen || a.timestamp || '',
      count: a.count || 1,
      source: '',
    }));
  }
  function conditionWhere(c) {
    return [
      (c.devices || [])
        .map((d) => d.name)
        .filter(Boolean)
        .slice(0, 2)
        .join(', ') + ((c.devices || []).length > 2 ? ` +${c.devices.length - 2}` : ''),
      (c.ports || []).length ? `port ${c.ports.slice(0, 2).join(', ')}` : '',
      c.site,
    ]
      .filter(Boolean)
      .join(' · ');
  }
  function conditionBody(c) {
    const dl = (label, value) =>
      value ? `<div class="dt-cond-fact"><dt>${esc(label)}</dt><dd>${value}</dd></div>` : '';
    const devices = (c.devices || [])
      .map(
        (d) =>
          `<span class="dt-cond-device"><b>${esc(d.name)}</b>${d.type ? ` <small class="muted">${esc(d.type === 'ap' ? 'access point' : d.type)}</small>` : ''}${
            d.mac
              ? ` <button type="button" class="link-btn" data-find-device="${esc(d.mac)}">Open in Device Finder</button> <button type="button" class="link-btn" data-topo-device="${esc(d.mac)}" data-topo-name="${esc(d.name)}" data-topo-port="${esc((c.ports || [])[0] || '')}" title="Opens the device's site map with ${(c.ports || [])[0] ? `port ${esc(c.ports[0])}` : 'the device'} highlighted and the path its traffic takes">Show in Topology</button>`
              : ''
          }</span>`,
      )
      .join('');
    return `<dl class="dt-cond-facts">${dl('What', esc(c.detail || c.title))}${dl('Site', esc(c.site))}${dl(
      'Where',
      devices,
    )}${dl('Ports', esc((c.ports || []).join(', ')))}${dl('Since', esc(formatTime(c.since, true)))}${dl(
      'Last seen',
      c.last_seen && c.last_seen !== c.since ? esc(formatTime(c.last_seen, true)) : '',
    )}${dl('Reported by', esc(c.source))}${dl('How to fix', esc(c.fix))}</dl>`;
  }
  function renderAlarms(data) {
    const all = conditionRows(data || {}),
      section = document.querySelector('#detectiveConditionsSection'),
      host = document.querySelector('#detectiveAlarms');
    document.querySelector('#detectiveAlarmCount').textContent = String(all.length);
    if (!all.length) {
      section.classList.add('hidden');
      host.innerHTML = '';
      return;
    }
    section.classList.remove('hidden');
    const counts = { critical: 0, warning: 0 };
    all.forEach((c) => {
      if (c.severity in counts) counts[c.severity] += 1;
    });
    if (conditionFilter !== 'all' && !counts[conditionFilter]) conditionFilter = 'all';
    const open = new Set([...host.querySelectorAll('details[open]')].map((d) => d.dataset.condKey));
    const rows = conditionFilter === 'all' ? all : all.filter((c) => c.severity === conditionFilter);
    const chip = (id, label, n) =>
      `<button type="button" class="dt-cond-chip ${esc(id)}" data-cond-filter="${esc(id)}" aria-pressed="${conditionFilter === id}">${esc(label)} <span>${n}</span></button>`;
    const chips =
      counts.critical || counts.warning
        ? `<div class="dt-cond-chips" role="group" aria-label="Filter by severity">${chip('all', 'All', all.length)}${counts.critical ? chip('critical', 'Critical', counts.critical) : ''}${counts.warning ? chip('warning', 'Warning', counts.warning) : ''}</div>`
        : '';
    host.innerHTML =
      chips +
      rows
        .map(
          (c) =>
            `<details class="dt-cond ${esc(c.severity)}" data-cond-key="${esc(c.key)}"${open.has(String(c.key)) ? ' open' : ''}><summary><span class="severity-dot ${esc(c.severity)}" aria-hidden="true"></span><span class="dt-cond-main"><strong>${esc(c.title)}${c.count > 1 ? ` ×${esc(c.count)}` : ''}</strong><small>${esc(conditionWhere(c) || c.detail || '')}</small></span><time>${esc(formatTime(c.last_seen || c.since))}</time></summary>${conditionBody(c)}</details>`,
        )
        .join('');
    host.querySelectorAll('[data-cond-filter]').forEach((b) =>
      b.addEventListener('click', () => {
        conditionFilter = b.dataset.condFilter;
        renderAlarms(detailData);
      }),
    );
    host.querySelectorAll('[data-find-device]').forEach((b) =>
      b.addEventListener('click', () => findDevice(b.dataset.findDevice)),
    );
    host.querySelectorAll('[data-topo-device]').forEach((b) =>
      b.addEventListener('click', () => showInTopology(b.dataset.topoDevice, b.dataset.topoName, b.dataset.topoPort)),
    );
  }
  function findDevice(query) {
    const input = document.querySelector('#detectiveQuery');
    if (!input) return;
    input.value = query;
    const form = document.querySelector('#detectiveSearchForm');
    if (form?.requestSubmit) form.requestSubmit();
    else document.querySelector('#detectiveSearchBtn')?.click();
    input.scrollIntoView({ block: 'center', behavior: 'smooth' });
  }
  // Opens Topology at the device: the page's own focusDevice() when it offers one, else its search box.
  async function showInTopology(mac, name, port = '') {
    await window.MistApp?.openTool('topology');
    const topo = window.MistTools?.topology;
    if (typeof topo?.focusDevice === 'function') {
      topo.focusDevice({ mac, name, port });
      return;
    }
    const search = document.querySelector('#tpSearch, #topoSearch');
    if (!search) return;
    search.value = name || mac;
    search.dispatchEvent(new Event('input', { bubbles: true }));
    search.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true }));
  }
  function humanize(value) {
    const text = String(value ?? '')
      .replace(/[_-]+/g, ' ')
      .trim();
    return text ? text.charAt(0).toUpperCase() + text.slice(1).toLowerCase() : '';
  }
  function moreRow(label, value) {
    return `<div class="detective-more-row"><span>${esc(label)}</span><strong>${esc(value)}</strong></div>`;
  }
  // Facts already shown in the header and the Device / Connection / Security cards, keyed like the
  // backend's row keys (detective_service.curated_details), so "More information" never repeats them.
  const TOP_FACT_KEYS = {
    'device.hostname': 'hostname',
    'device.ip': 'ip',
    'device.mac': 'mac',
    'device.vendor': 'manufacturer',
    'device.model': 'model',
    'network.site': 'site',
    'network.ssid': 'ssid',
    'network.vlan': 'vlan',
    'network.switch': 'attached_name',
    'network.ap': 'attached_name',
    'network.port': 'port',
    'network.band': 'band',
    'network.channel': 'channel',
    'network.rssi': 'rssi',
    'security.last_activity': 'last_seen',
    'identity.username': 'username',
    'identity.auth_method': 'auth_method',
    'identity.nac_profile': 'nac_rule',
    'identity.nac_state': 'auth_state',
  };
  function normFact(value) {
    const text = String(value ?? '')
      .trim()
      .toLowerCase();
    const mac = text.replace(/[^0-9a-f]/g, '');
    if (mac.length === 12 && /^[0-9a-f:.\- ]+$/.test(text)) return mac;
    return text.replace(/\s+/g, ' ');
  }
  function topFacts(data) {
    const v = data.fields || {},
      identity = data.identity || {},
      facts = {};
    const put = (key, value) => {
      if (!present(value)) return;
      (facts[key] ||= new Set()).add(normFact(value));
    };
    Object.entries(TOP_FACT_KEYS).forEach(([field, key]) => put(key, v[field]));
    put('hostname', identity.hostname);
    put('ip', identity.ip);
    put('mac', identity.mac);
    put('username', identity.username);
    return facts;
  }
  // Curated, labelled sections built by the backend (detective_service.curated_details);
  // the browser never dumps raw provider records or internal ids.
  // ---- More details (v0.10.24) -------------------------------------------------------------------------
  // Fact sections are cards in an even grid (2–3 columns, same padding, aligned label/value columns,
  // equal heights per row; a long card spans the full row instead of leaving a tiny card beside it). Lists
  // (recent changes, NAC events) span the full width. Empty sections are not drawn, and the
  // subtitle names only the sections that have data.
  function factSections(sections, facts = {}) {
    return (Array.isArray(sections) ? sections : [])
      .map((section) => {
        const rows = (section?.rows || [])
          .filter((r) => r && present(r.label) && present(r.value))
          .filter((r) => !(r.key && facts[r.key]?.has(normFact(r.value))));
        return {
          title: section.title || 'Details',
          rows: rows.length,
          html: rows
            .map((r) => moreRow(r.label, r.format === 'time' ? formatTime(r.value, true) : String(r.value)))
            .join(''),
        };
      })
      .filter((b) => b.rows);
  }
  function moreCard(b) {
    // A long card (10+ facts) spans the whole row with its facts in columns, so it never towers over
    // a short neighbour; the others share rows of equal height.
    const cls = b.wide ? ' dt-more-wide' : b.rows > 9 ? ' dt-more-span' : b.fill ? ` dt-more-fill-${b.fill}` : '';
    return `<section class="detective-more-section dt-more-card${cls}"><h5 class="dt-more-title">${esc(b.title)}</h5><div class="dt-more-body">${b.html}</div></section>`;
  }
  function renderMore(data) {
    const host = document.querySelector('#detectiveMoreContent');
    if (!host) return;
    const nac = data.nac_events || [];
    // The current path (site → switch/AP → port/SSID → VLAN) is the Connection card; the backend's
    // "Path upstream" section adds what lies beyond it.
    const blocks = factSections(data.details, topFacts(data));
    const changes = data.recent_changes || [];
    if (changes.length)
      blocks.push({
        title: 'Recent changes to this device (7 days)',
        wide: true,
        rows: changes.length,
        html: changes
          .map((c) => {
            const a = c.actor || {};
            const who = [
              a.name,
              a.email && a.email !== a.name ? a.email : '',
              (a.roles || [])[0] || a.kind_label,
              c.source_label ? `in ${c.source_label}` : '',
            ]
              .filter(Boolean)
              .join(' · ');
            const counts =
              Number.isFinite(Number(a.changes_7d)) && Number(a.changes_7d) > 0
                ? `${Number(a.changes_24h) || 0} change(s) by them in 24 h, ${Number(a.changes_7d)} in 7 days`
                : '';
            const fields = (c.changes || [])
              .slice(0, 6)
              .map((x) => `${x.label}: ${x.before || '—'} → ${x.after || '—'}`)
              .join('; ');
            return `<div class="detective-more-event"><strong>${esc(c.action || 'Change')} ${esc(c.what || '')}</strong><span>${esc(who)}${counts ? ` <small class="muted">(${esc(counts)})</small>` : ''}${fields ? `<br><small>${esc(fields)}</small>` : ''}</span><time>${esc(formatTime(c.timestamp || c.time))}</time></div>`;
          })
          .join(''),
      });
    if (nac.length)
      blocks.push({
        title: 'Recent NAC events',
        wide: true,
        rows: nac.length,
        html: nac
          .slice(0, 20)
          .map(
            (e) =>
              `<div class="detective-more-event"><strong>${esc(humanize(String(e.type || e.status || 'NAC event').replace(/^NAC_/i, '')))}</strong><span>${esc(e.text || e.nacrule_name || e.username || '')}</span><time>${esc(formatTime(e.timestamp || e.last_seen))}</time></div>`,
          )
          .join(''),
      });
    // v0.10.32: Marvis is no longer part of More details (it was slow, licence-dependent and rarely
    // actionable here); the Operations Assistant keeps its "Open Mist (Marvis)" link.
    if (data.provider_partial)
      blocks.push({
        title: 'Data sources',
        rows: 1,
        html: moreRow('Device intelligence', 'Partially available — some fields may be missing'),
      });
    // Rows of similar size: cards are ordered by length (ties keep their natural order) so each grid row
    // pairs cards of about the same height; a last card alone in its row widens to fill it.
    const width = host.clientWidth || host.parentElement?.clientWidth || 900;
    const cols = width > 1100 ? 3 : width > 520 ? 2 : 1;
    const cards = blocks
      .filter((b) => !b.wide)
      .map((b, i) => ({ ...b, order: i }))
      .sort((x, y) => (x.rows > 9) - (y.rows > 9) || y.rows - x.rows || x.order - y.order);
    const normal = cards.filter((b) => b.rows <= 9);
    const left = normal.length % cols;
    if (cols > 1 && left) normal[normal.length - 1].fill = cols - left + 1;
    const lists = blocks.filter((b) => b.wide);
    host.innerHTML = blocks.length
      ? `${cards.length ? `<div class="dt-more-grid">${cards.map(moreCard).join('')}</div>` : ''}${lists.map(moreCard).join('')}`
      : '<div class="detective-none">No additional information returned.</div>';
    const sub = document.querySelector('#detectiveMoreSubtitle');
    if (sub) {
      const names = blocks.filter((b) => !b.pending).map((b) => b.title.replace(/\s*\(.*\)$/, ''));
      sub.textContent = names.length ? names.join(' · ') : '';
      sub.classList.toggle('hidden', !names.length);
    }
  }
  function formatBytes(value) {
    const n = Number(value);
    if (value === undefined || value === null || value === '' || !Number.isFinite(n) || n < 0) return '—';
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    let size = n,
      unit = 0;
    while (size >= 1024 && unit < units.length - 1) {
      size /= 1024;
      unit++;
    }
    return unit === 0 ? `${Math.round(size)} B` : `${size.toFixed(size < 10 ? 1 : 0)} ${units[unit]}`;
  }

  // Traffic & Sessions: the firewall-style log table lives in static/traffic-log.js.
  // v0.10.15: the 15-minute and full-window queries run at the same time (they used to run one after
  // the other); answers are kept per device for 60 s; hovering a result starts its query early;
  // the status line is a compact bar (count · window, response-time chip, live pill, progress bar).
  const TRAFFIC_LIVE_MS = 20000;
  const TRAFFIC_CACHE_MS = 60000;
  const TRAFFIC_LIMIT = 500;
  const TRAFFIC_QUICK_LIMIT = 200;
  let trafficLive = false;
  let trafficLiveTimer = null;
  let trafficLoadingIp = '';
  let trafficRendered = null; // the object last drawn, so detail auto-refreshes do not redraw the table
  const trafficCache = new Map(); // `${ip}|${window}` -> { data, at }
  const trafficInflight = new Map(); // `${ip}|${window}|${limit}` -> { promise, at }
  let prefetchTimer = null;
  // v0.10.32: Live is on unless it was turned off. NodeWatch's local port can change between starts
  // (each port is its own browser storage), so an "on" saved earlier was often forgotten and the table
  // stopped refreshing (seen in the Mac app).
  try {
    trafficLive = localStorage.getItem('nodewatch.trafficLive') !== '0';
  } catch {
    trafficLive = true;
  }

  function trafficIp() {
    return detailData?.fields?.['device.ip'] || detailData?.identity?.ip || selected?.ip || '';
  }
  function trafficWindow() {
    return document.querySelector('#detectiveTrafficWindow')?.value || '1h';
  }
  function trafficWindowLabel(value) {
    const opt = [...(document.querySelector('#detectiveTrafficWindow')?.options || [])].find(
      (o) => o.value === value,
    );
    return String(opt?.textContent || value || '').replace(/^Last /i, 'last ');
  }

  function trafficStateText(shown, total) {
    return `${shown}/${total} session${total === 1 ? '' : 's'}`;
  }
  function secondsText(ms) {
    const s = Number(ms) / 1000;
    return s < 10 ? `${s.toFixed(1)} s` : `${Math.round(s)} s`;
  }

  // Compact status bar under the toolbar. Everything dynamic is escaped.
  function renderTrafficStatus(data, { loadingWider = false } = {}) {
    const meta = document.querySelector('#detectiveTrafficMeta');
    if (!meta) return;
    const count = Array.isArray(data?.sessions) ? data.sessions.length : 0;
    const win = trafficWindowLabel(data?.partial ? '15m' : data?.window || trafficWindow());
    const timing = data?.timing || {};
    const paMs = Number(timing.palo_alto_ms) || Number(data?.query_duration_ms) || 0;
    const parts = [
      `<span class="tl-stat-count"><strong>${esc(count.toLocaleString())}</strong> ${data?.has_more ? 'newest ' : ''}log${count === 1 ? '' : 's'} · ${esc(win)}</span>`,
    ];
    if (paMs) {
      const tip = [
        'Palo Alto response time',
        timing.queries ? `${timing.queries} quer${timing.queries === 1 ? 'y' : 'ies'}` : '',
        data?.cached ? `kept from ${Math.round((Number(data.age_ms) || 0) / 1000)} s ago` : '',
      ]
        .filter(Boolean)
        .join(' · ');
      parts.push(
        `<span class="tl-chip" title="${esc(tip)}"><span class="tl-chip-icon" aria-hidden="true">⏱</span>${esc(secondsText(paMs))}</span>`,
      );
    }
    if (data?.cached)
      parts.push(
        '<span class="tl-chip tl-chip-quiet" title="Shown from the last minute’s answer. Refresh to ask Palo Alto again.">cached</span>',
      );
    if (trafficLive)
      parts.push(
        `<span class="tl-live-pill" title="Live: checks for new logs every ${TRAFFIC_LIVE_MS / 1000} s. Logs reach Strata 1–2 minutes after the firewall writes them, so the newest rows are about that far behind."><span class="tl-live-pill-dot" aria-hidden="true"></span>Live</span>`,
      );
    if (loadingWider)
      parts.push(
        `<span class="tl-progress" role="progressbar" aria-label="Loading ${esc(trafficWindowLabel(trafficWindow()))}" title="Loading ${esc(trafficWindowLabel(trafficWindow()))}…"></span>`,
      );
    meta.classList.toggle('tl-status-loading', !!loadingWider);
    meta.innerHTML = parts.join('');
  }

  function renderTraffic(data) {
    trafficRendered = data;
    const state = document.querySelector('#detectiveTrafficState');
    const body = document.querySelector('#detectiveTrafficRows');
    const meta = document.querySelector('#detectiveTrafficMeta');
    const table = document.querySelector('#detectiveTrafficTableWrap');
    const toolbar = document.querySelector('#detectiveTrafficToolbar');
    if (!body || !state) return;

    const compact = (message, label, { showToolbar = false, loading = false } = {}) => {
      state.textContent = label;
      if (meta) {
        meta.classList.toggle('tl-status-loading', loading);
        meta.textContent = message || 'Traffic session data is not currently available.';
        if (loading)
          meta.insertAdjacentHTML(
            'beforeend',
            '<span class="tl-progress" role="progressbar" aria-label="Loading"></span>',
          );
      }
      if (table) table.classList.add('hidden');
      if (toolbar) toolbar.classList.toggle('hidden', !showToolbar);
      body.innerHTML = '';
    };

    if (data?.loading) {
      compact(data.message || 'Asking Palo Alto…', 'Loading…', { showToolbar: true, loading: true });
      return;
    }
    if (data?.error) {
      compact(data.error, 'Traffic query failed', { showToolbar: true });
      return;
    }
    if (data?.configured === false || data?.available === false) {
      compact(
        data?.message || 'Traffic session data is not currently connected.',
        data?.status_label || 'Data source unavailable',
      );
      return;
    }
    const total = Array.isArray(data?.sessions) ? data.sessions.length : 0;
    if (toolbar) toolbar.classList.remove('hidden');
    if (!total) {
      compact(
        data?.message || 'No traffic sessions found for this device during the selected time range.',
        data?.status_label || 'No traffic found',
        { showToolbar: true },
      );
      return;
    }
    if (table) table.classList.remove('hidden');
    const log = window.NodeWatchTrafficLog;
    let shown = total;
    if (log) shown = log.setRows(data.sessions).shown;
    else
      body.innerHTML = data.sessions
        .map(
          (r) =>
            `<tr><td>${esc(r.rule || '')}</td><td>${esc(r.application || '')}</td><td>${esc(r.destination || '')}</td></tr>`,
        )
        .join('');
    state.textContent = trafficStateText(shown, total);
    renderTrafficStatus(data, { loadingWider: !!data.partial });
  }

  function trafficCacheGet(ip, windowValue) {
    const hit = trafficCache.get(`${ip}|${windowValue}`);
    if (!hit || Date.now() - hit.at > TRAFFIC_CACHE_MS) return null;
    return { ...hit.data, cached: true, age_ms: Date.now() - hit.at };
  }
  function trafficCachePut(ip, windowValue, data) {
    if (!data || data.available === false || data.error) return;
    trafficCache.set(`${ip}|${windowValue}`, { data, at: Date.now() });
    if (trafficCache.size > 40) trafficCache.delete(trafficCache.keys().next().value);
  }

  // Identical requests share one fetch (e.g. the hover prefetch and the click that follows it).
  function fetchTraffic(ip, windowValue, { fresh = false, limit = TRAFFIC_LIMIT, sinceMs = 0 } = {}) {
    const params = new URLSearchParams({ ip, window: windowValue, limit: String(limit) });
    if (fresh) params.set('refresh', 'true');
    if (sinceMs) params.set('since_ms', String(Math.floor(sinceMs)));
    if (sinceMs) return getJSON(`/api/detective/traffic?${params}`);
    const key = `${ip}|${windowValue}|${limit}`;
    const running = trafficInflight.get(key);
    if (running && !fresh) return running.promise;
    const promise = getJSON(`/api/detective/traffic?${params}`).finally(() => {
      if (trafficInflight.get(key)?.promise === promise) trafficInflight.delete(key);
    });
    trafficInflight.set(key, { promise, at: Date.now() });
    return promise;
  }

  function prefetchTraffic(row) {
    clearTimeout(prefetchTimer);
    const ip = row?.ip;
    if (!ip) return;
    prefetchTimer = setTimeout(() => {
      const windowValue = trafficWindow();
      if (trafficCacheGet(ip, windowValue) || trafficInflight.has(`${ip}|${windowValue}|${TRAFFIC_LIMIT}`))
        return;
      // At most one hover prefetch at a time, so sweeping the mouse over the list stays cheap.
      if ([...trafficInflight.keys()].some((k) => k.endsWith(`|${TRAFFIC_LIMIT}`))) return;
      fetchTraffic(ip, windowValue)
        .then((data) => trafficCachePut(ip, windowValue, data))
        .catch(() => {
          /* the click reports errors */
        });
    }, 180);
  }
  function cancelTrafficPrefetch() {
    clearTimeout(prefetchTimer);
  }

  // fresh: ask Palo Alto again (Refresh). restart: a new time range for the same device.
  async function loadTraffic(fresh = false, { restart = false } = {}) {
    const ip = trafficIp();
    if (!ip) {
      if (!detailData) return;
      trafficData = {
        available: false,
        configured: true,
        sessions: [],
        message: 'No client IP is available for traffic correlation.',
        status_label: 'No client IP',
      };
      renderTraffic(trafficData);
      return;
    }
    if (!fresh && !restart && trafficLoadingIp === ip) return; // already loading for this device
    const windowValue = trafficWindow();
    const seq = ++trafficSeq;
    if (!fresh) {
      const cached = trafficCacheGet(ip, windowValue);
      if (cached) {
        trafficData = cached;
        renderTraffic(trafficData);
        scheduleTrafficLive();
        if (trafficLive) pollTrafficLive();
        return;
      }
    }
    trafficLoadingIp = ip;
    const btn = document.querySelector('#detectiveTrafficRefresh');
    if (btn) {
      btn.disabled = true;
      btn.textContent = 'Loading…';
    }
    renderTraffic({ loading: true, message: `Asking Palo Alto for ${ip}…` });
    let fullDone = false;
    try {
      const prefetched = trafficInflight.get(`${ip}|${windowValue}|${TRAFFIC_LIMIT}`);
      const full = fetchTraffic(ip, windowValue, { fresh, limit: TRAFFIC_LIMIT });
      // Both queries start now. The small 15-minute one usually answers first and is shown with a
      // progress bar until the full window replaces it. Skipped if a hover prefetch is well ahead.
      if (windowValue !== '15m' && !(prefetched && Date.now() - prefetched.at > 3000)) {
        fetchTraffic(ip, '15m', { fresh, limit: TRAFFIC_QUICK_LIMIT })
          .then((quick) => {
            if (seq !== trafficSeq || fullDone) return;
            if (quick?.available !== false && (quick.sessions || []).length) {
              trafficData = { ...quick, partial: true };
              renderTraffic(trafficData);
            }
          })
          .catch(() => {
            /* the full query reports any error */
          });
      }
      const data = await full;
      fullDone = true;
      if (seq !== trafficSeq) return;
      trafficCachePut(ip, windowValue, data);
      trafficData = data;
      renderTraffic(trafficData);
      scheduleTrafficLive();
    } catch (err) {
      fullDone = true;
      if (seq !== trafficSeq) return;
      trafficData = { error: err.message, sessions: [] };
      renderTraffic(trafficData);
    } finally {
      if (seq === trafficSeq) {
        trafficLoadingIp = '';
        if (btn) {
          btn.disabled = false;
          btn.textContent = 'Refresh traffic';
        }
      }
    }
  }

  // Live mode: every 20 s ask only for logs newer than the newest row shown, and add them on top
  // (only the new rows are drawn; the table is not rebuilt).
  async function pollTrafficLive() {
    const log = window.NodeWatchTrafficLog;
    const ip = trafficIp();
    if (!trafficLive || !ip || !log || !trafficData?.sessions || trafficLoadingIp) return;
    if (
      document.visibilityState !== 'visible' ||
      (document.querySelector('#view-detective')?.classList.contains('hidden') && !log.isFullscreen?.())
    )
      return;
    const seq = trafficSeq;
    try {
      const since = log.newestEpoch() || Date.now() - 15 * 60 * 1000;
      const data = await fetchTraffic(ip, '15m', { sinceMs: since, limit: TRAFFIC_LIMIT });
      if (seq !== trafficSeq || !trafficLive) return;
      const r = log.setRows(data.sessions || [], { merge: true });
      trafficData = {
        ...trafficData,
        sessions: log.rows(),
        cached: false,
        query_duration_ms: data.query_duration_ms,
        timing: data.timing || trafficData.timing,
      };
      trafficRendered = trafficData;
      trafficCachePut(ip, trafficWindow(), trafficData);
      const state = document.querySelector('#detectiveTrafficState');
      if (state) state.textContent = trafficStateText(r.shown, r.total);
      renderTrafficStatus(trafficData);
    } catch (err) {
      console.warn('Live traffic update failed', err);
    }
  }
  function scheduleTrafficLive() {
    clearInterval(trafficLiveTimer);
    trafficLiveTimer = trafficLive ? setInterval(pollTrafficLive, TRAFFIC_LIVE_MS) : null;
    const btn = document.querySelector('#tlLive');
    if (btn) {
      btn.setAttribute('aria-pressed', String(trafficLive));
      btn.classList.toggle('active', trafficLive);
    }
  }
  function toggleTrafficLive() {
    trafficLive = !trafficLive;
    try {
      localStorage.setItem('nodewatch.trafficLive', trafficLive ? '1' : '0');
    } catch {
      /* ignore */
    }
    scheduleTrafficLive();
    if (trafficData?.sessions?.length)
      renderTrafficStatus(trafficData, { loadingWider: !!trafficData.partial });
    if (trafficLive) pollTrafficLive();
  }

  function renderDetail(data) {
    detailData = data;
    document.querySelector('#detectiveDetailEmpty').classList.add('hidden');
    document.querySelector('#detectiveDetail').classList.remove('hidden');
    const identity = data.identity || {},
      v = data.fields || {};
    const kind = (data.kind || 'investigation').replaceAll('_', ' ');
    document.querySelector('#detectiveDetailKind').textContent =
      kind.length <= 3 ? kind.toUpperCase() : kind.charAt(0).toUpperCase() + kind.slice(1);
    document.querySelector('#detectiveDetailTitle').textContent =
      identity.title || identity.mac || 'Investigation';
    const meta = [
      v['device.ip'] || identity.ip,
      v['device.mac'] ? formatMac(v['device.mac']) : identity.mac ? formatMac(identity.mac) : '',
      v['network.connection_type'],
      v['security.risk_level'] ? `${v['security.risk_level']} risk` : '',
    ].filter(Boolean);
    document.querySelector('#detectiveIdentityMeta').innerHTML = meta
      .map((x) => `<span>${esc(x)}</span>`)
      .join('');
    renderCore(data);
    renderAlarms(data);
    renderMore(data);
    // The detail refreshes every 15 s; redraw the traffic table only if its data changed.
    if (!trafficData) {
      if (!trafficRendered?.loading) renderTraffic({ loading: true });
    } else if (trafficData !== trafficRendered) renderTraffic(trafficData);
    startCountdown();
  }
  async function loadDetail(refresh = false) {
    if (!selected) return;
    const item = { ...selected },
      seq = ++detailSeq,
      btn = document.querySelector('#detectiveDetailRefresh');
    if (btn) {
      btn.disabled = true;
      btn.textContent = refresh ? 'Refreshing...' : 'Loading...';
    }
    const countdown = document.querySelector('#detectiveRefreshCountdown');
    if (countdown) countdown.textContent = 'Updating…';
    const started = performance.now();
    try {
      const params = new URLSearchParams({ kind: item.kind, mac: item.mac });
      if (item.site_id) params.set('site_id', item.site_id);
      if (refresh) params.set('refresh', 'true');
      const data = await getJSON(`/api/detective/detail?${params}`);
      if (seq !== detailSeq) return;
      if (item.site_id && data.identity?.site_id && String(data.identity.site_id) !== String(item.site_id))
        throw new Error('Detail response did not match the selected site scope.');
      renderDetail(data);
      const elapsed = Math.round(performance.now() - started);
      document.querySelector('#detectiveDetailLoadTime').textContent =
        `${elapsed < 1000 ? `${elapsed} ms` : `${(elapsed / 1000).toFixed(1)} s`}`;
      if (!trafficData) loadTraffic(false);
    } catch (err) {
      if (seq !== detailSeq) return;
      console.error(err);
      stopCountdown('Refresh paused');
      const empty = document.querySelector('#detectiveDetailEmpty');
      empty.classList.remove('hidden');
      empty.innerHTML = `<div class="detective-empty-icon">!</div><strong>Unable to build investigation.</strong><span>${esc(err.message)}</span>`;
      document.querySelector('#detectiveDetail').classList.add('hidden');
    } finally {
      if (seq === detailSeq && btn) {
        btn.disabled = false;
        btn.textContent = 'Refresh now';
      }
    }
  }
  function stopCountdown(text = 'Paused') {
    nextRefreshAt = 0;
    const label = document.querySelector('#detectiveRefreshCountdown');
    if (label) label.textContent = text;
    document.querySelector('#detectiveLiveState')?.classList.add('paused');
  }
  function startCountdown() {
    nextRefreshAt = Date.now() + REFRESH_SECONDS * 1000;
    document.querySelector('#detectiveLiveState')?.classList.remove('paused');
    updateCountdown();
  }
  function updateCountdown() {
    const label = document.querySelector('#detectiveRefreshCountdown');
    if (!label) return;
    if (document.visibilityState !== 'visible') {
      label.textContent = 'Paused while tab is inactive';
      document.querySelector('#detectiveLiveState')?.classList.add('paused');
      return;
    }
    if (!selected || !nextRefreshAt) {
      label.textContent = selected ? 'Refresh paused' : 'Select a device';
      return;
    }
    document.querySelector('#detectiveLiveState')?.classList.remove('paused');
    const left = Math.max(0, Math.ceil((nextRefreshAt - Date.now()) / 1000));
    label.textContent = left ? `Refresh in ${left}s` : 'Updating…';
  }
  async function autoRefresh() {
    if (!selected || !detailData || busy || document.visibilityState !== 'visible') return;
    // v0.10.23: only while Device Finder is the open page (it kept re-reading the selected device's
    // detail from Mist every 15 s after the user had moved to another page).
    if (document.querySelector('#view-detective')?.classList.contains('hidden')) return;
    if (!nextRefreshAt || Date.now() < nextRefreshAt) return;
    nextRefreshAt = Date.now() + REFRESH_SECONDS * 1000;
    await loadDetail(false);
  }
  async function init() {
    // v0.10.40: the site list loads in the background; the search works at once (all sites) and an
    // Enter before the list arrives no longer submits the form natively (which reloaded the window).
    loadSites();
    document.querySelector('#detectiveSearchForm')?.addEventListener('submit', (e) => {
      e.preventDefault();
      runSearch();
    });
    document.querySelector('#detectiveDetailRefresh')?.addEventListener('click', () => loadDetail(true));
    document.querySelector('#detectiveSiteSearch')?.addEventListener('input', filterSites);
    document.querySelector('#detectiveSite')?.addEventListener('change', () => {
      const siteSearch = document.querySelector('#detectiveSiteSearch');
      if (siteSearch) siteSearch.value = '';
      visibleSites = [...sites];
      renderSiteOptions();
    });
    [
      '#detectiveResultSearch',
      '#detectiveConnectionFilter',
      '#detectiveTypeFilter',
      '#detectiveVendorFilter',
      '#detectiveSort',
    ].forEach((id) =>
      document.querySelector(id)?.addEventListener(id.includes('Search') ? 'input' : 'change', () => {
        resetPage();
        renderResults();
      }),
    );
    PAGER_SUFFIXES.forEach((sfx) => {
      document.querySelector(`#detectivePrevPage${sfx}`)?.addEventListener('click', () => {
        resultPage = Math.max(1, resultPage - 1);
        renderResults();
        document.querySelector('#detectiveResults')?.scrollTo({ top: 0 });
      });
      document.querySelector(`#detectiveNextPage${sfx}`)?.addEventListener('click', () => {
        resultPage++;
        renderResults();
        document.querySelector('#detectiveResults')?.scrollTo({ top: 0 });
      });
      document.querySelector(`#detectivePageSize${sfx}`)?.addEventListener('change', (e) => {
        pageSize = Number(e.target.value) || 100;
        resetPage();
        renderResults();
      });
    });
    let trafficFilterTimer = null;
    document.querySelector('#detectiveTrafficSearch')?.addEventListener('input', () => {
      clearTimeout(trafficFilterTimer);
      trafficFilterTimer = setTimeout(() => {
        const log = window.NodeWatchTrafficLog;
        const r = log?.render();
        const state = document.querySelector('#detectiveTrafficState');
        if (r && state && trafficData?.sessions?.length)
          state.textContent = trafficStateText(r.shown, r.total);
      }, 250);
    });
    document.addEventListener('nodewatch:traffic-filtered', (e) => {
      const state = document.querySelector('#detectiveTrafficState');
      if (state && trafficData?.sessions?.length)
        state.textContent = trafficStateText(e.detail.shown, e.detail.total);
    });
    document
      .querySelector('#detectiveTrafficWindow')
      ?.addEventListener('change', () => (detailData || selected) && loadTraffic(false, { restart: true }));
    document
      .querySelector('#detectiveTrafficRefresh')
      ?.addEventListener('click', () => (detailData || selected) && loadTraffic(true));
    document.querySelector('#tlLive')?.addEventListener('click', toggleTrafficLive);
    scheduleTrafficLive();
    document.addEventListener('visibilitychange', () => {
      if (document.visibilityState === 'visible' && selected) startCountdown();
      else updateCountdown();
    });
    if (!countdownTimer) countdownTimer = setInterval(updateCountdown, 1000);
    if (!refreshTimer) refreshTimer = setInterval(autoRefresh, 1000);
  }
  async function refresh() {
    loadSites(); // background: a revisit never waits for the site list
  }
  return {
    init,
    refresh,
    autoRefresh,
    _test: {
      formatBytes,
      renderTraffic,
      renderMore,
      renderResults,
      renderResultScope,
      setSearch: (d) => (lastSearch = d),
    },
  };
})();
