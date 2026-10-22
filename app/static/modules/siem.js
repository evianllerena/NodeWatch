const siemEsc = (v) =>
  String(v ?? '').replace(
    /[&<>"']/g,
    (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c],
  );
window.MistTools.siem = (() => {
  let initd = false,
    events = [];
  async function j(url, options) {
    const r = await fetch(url, options);
    const d = await r.json().catch(() => ({ detail: r.statusText }));
    if (!r.ok) throw new Error(d.detail || r.statusText);
    return d;
  }
  function epoch(v) {
    let n = Number(v);
    if (v !== '' && v != null && Number.isFinite(n)) {
      if (n < 1e11) n *= 1000;
      return n;
    }
    const d = new Date(v);
    return Number.isNaN(d.getTime()) ? 0 : d.getTime();
  }
  const eventMs = (e) => Number(e?.epoch_ms) || epoch(e?.timestamp);
  function fmtTime(v) {
    const n = typeof v === 'object' && v ? eventMs(v) : epoch(v);
    return n ? new Date(n).toLocaleString() : '—';
  }
  function ago(ms) {
    if (!ms) return '';
    const s = Math.round((Date.now() - ms) / 1000);
    if (s < 0) return 'in the future';
    if (s < 60) return 'just now';
    const m = Math.round(s / 60);
    if (m < 60) return `${m} min ago`;
    const h = Math.round(m / 60);
    if (h < 48) return `${h} h ago`;
    return `${Math.round(h / 24)} days ago`;
  }
  // Mist severities collapse to three buckets everywhere (filter, sort, chips, CEF).
  function sevNorm(v) {
    const s = String(v || '').toLowerCase();
    if (s === 'critical' || s === 'major') return 'critical';
    if (s === 'minor' || s === 'warn' || s === 'warning') return 'warning';
    return 'info';
  }
  const SEV_RANK = { critical: 0, warning: 1, info: 2 };
  const SOURCE_LABEL = {
    alarm: 'Alarm',
    device_event: 'Device event',
    audit: 'Audit',
    nodewatch: 'NodeWatch',
  };
  const CHANGE_LABEL = { deleted: 'Deleted', committed: 'Committed', neutral: 'No change' };
  function changeClass(e) {
    const text = [e.event_type, e.code, e.message, e.action, e.operation].join(' ').toLowerCase();
    if (/delete|deleted|remove|removed|decommission/.test(text)) return 'deleted';
    if (
      /commit|committed|create|created|add|added|update|updated|change|changed|apply|applied|config/.test(
        text,
      )
    )
      return 'committed';
    return 'neutral';
  }
  function fmtMac(v) {
    const raw = String(v || '')
      .toLowerCase()
      .replace(/[^0-9a-f]/g, '');
    return raw.length === 12 ? raw.match(/../g).join(':') : String(v || '');
  }
  const typeLabel = (e) =>
    e.source === 'audit' ? e.event_type || 'Activity' : e.title || e.event_type || '';
  const siteLabel = (e) => e.site_name || (e.site_id ? `Site ${String(e.site_id).slice(0, 8)}…` : '—');
  const sevChip = (sev) =>
    `<span class="nw-chip nw-sev-${sev}">${siemEsc(sev[0].toUpperCase() + sev.slice(1))}</span>`;
  const changeChip = (cls) => `<span class="nw-chip nw-change-${cls}">${siemEsc(CHANGE_LABEL[cls])}</span>`;
  function searchText(e) {
    return [
      fmtTime(e),
      sevNorm(e.severity),
      SOURCE_LABEL[e.source] || e.source,
      typeLabel(e),
      e.event_type,
      e.code,
      e.site_name,
      e.site_id,
      e.device_name,
      e.device_mac,
      fmtMac(e.device_mac),
      e.client_mac,
      fmtMac(e.client_mac),
      e.admin,
      e.message,
      CHANGE_LABEL[changeClass(e)],
    ]
      .join(' ')
      .toLowerCase();
  }
  let shown = [];
  function rowHtml(e, i) {
    const sev = sevNorm(e.severity),
      cls = changeClass(e),
      ms = eventMs(e);
    return (
      `<tr class="clickable-row siem-change-${cls}" data-siem-index="${i}" tabindex="0">` +
      `<td data-sort="${ms}">${siemEsc(fmtTime(e))}</td>` +
      `<td data-sort="${SEV_RANK[sev]}">${sevChip(sev)}</td>` +
      `<td>${siemEsc(SOURCE_LABEL[e.source] || e.source)}</td>` +
      `<td>${changeChip(cls)} ${siemEsc(typeLabel(e))}</td>` +
      `<td>${siemEsc(siteLabel(e))}</td>` +
      `<td>${siemEsc(String(e.message ?? '').slice(0, 180))}</td></tr>`
    );
  }
  function render() {
    let rows = [...events];
    const q = (document.querySelector('#siemSearch')?.value || '').trim().toLowerCase();
    const sev = document.querySelector('#siemSeverity')?.value || '',
      ct = document.querySelector('#siemChangeType')?.value || '',
      sort = document.querySelector('#siemSort')?.value || 'newest';
    if (q) rows = rows.filter((e) => searchText(e).includes(q));
    if (sev) rows = rows.filter((e) => sevNorm(e.severity) === sev);
    if (ct) rows = rows.filter((e) => changeClass(e) === ct);
    if (sort === 'oldest') rows.sort((a, b) => eventMs(a) - eventMs(b));
    else if (sort === 'severity')
      rows.sort(
        (a, b) => SEV_RANK[sevNorm(a.severity)] - SEV_RANK[sevNorm(b.severity)] || eventMs(b) - eventMs(a),
      );
    else if (sort === 'source')
      rows.sort((a, b) => String(a.source || '').localeCompare(String(b.source || '')));
    else rows.sort((a, b) => eventMs(b) - eventMs(a));
    shown = rows;
    document.querySelector('#siemRows').innerHTML = rows.length
      ? rows.map(rowHtml).join('')
      : '<tr><td colspan="6" class="muted">No events match the current filters.</td></tr>';
    document.querySelector('#siemCount').textContent = `${rows.length} of ${events.length} normalized events`;
  }
  function changesTable(changes) {
    if (!changes?.length) return '';
    const opLabel = { added: 'Added', removed: 'Removed', changed: 'Changed' };
    return (
      '<h4>What changed</h4><div class="table-wrap"><table class="nw-change-table"><thead><tr><th>Field</th><th>Before</th><th>After</th></tr></thead><tbody>' +
      changes
        .map(
          (c) =>
            `<tr class="nw-op-${siemEsc(c.op)}"><td><span class="nw-chip nw-op-chip-${siemEsc(c.op)}">${siemEsc(opLabel[c.op] || c.op)}</span> ${siemEsc(c.label)}</td><td>${siemEsc(c.before || '—')}</td><td>${siemEsc(c.after || '—')}</td></tr>`,
        )
        .join('') +
      '</tbody></table></div>'
    );
  }
  function detailRow(label, value) {
    return value ? `<dt>${siemEsc(label)}</dt><dd>${siemEsc(value)}</dd>` : '';
  }
  function fieldValue(f) {
    return f.kind === 'time' ? `${fmtTime(f.value)} (${ago(Number(f.value))})` : String(f.value ?? '');
  }
  function eventDetailHtml(e) {
    const sev = sevNorm(e.severity),
      cls = changeClass(e),
      ms = eventMs(e);
    const device = [e.device_name, fmtMac(e.device_mac)].filter(Boolean).join(' · ');
    const main =
      detailRow('When', ms ? `${fmtTime(e)} (${ago(ms)})` : '') +
      detailRow(
        'Severity',
        sev[0].toUpperCase() +
          sev.slice(1) +
          (e.severity_raw && e.severity_raw.toLowerCase() !== sev ? ` (Mist: ${e.severity_raw})` : ''),
      ) +
      detailRow('Source', SOURCE_LABEL[e.source] || e.source) +
      detailRow('Type', e.source === 'audit' ? e.event_type : e.code || e.event_type) +
      detailRow('Site', e.site_name || (e.site_id ? 'Unknown site' : 'Organization')) +
      detailRow('Device', device) +
      detailRow('Client MAC', fmtMac(e.client_mac)) +
      detailRow('Admin', e.admin) +
      detailRow('Message', e.message);
    const extra = (e.details || []).map((f) => detailRow(f.label, fieldValue(f))).join('');
    const link = e.mist_url
      ? `<p><a class="btn secondary" href="${siemEsc(e.mist_url)}" target="_blank" rel="noopener">Open in Mist ↗</a></p>`
      : '';
    return (
      `<div class="nw-detail-chips">${sevChip(sev)} ${changeChip(cls)}</div>` +
      `<dl class="nw-detail-list">${main}</dl>` +
      (extra ? `<h4>Event fields</h4><dl class="nw-detail-list">${extra}</dl>` : '') +
      changesTable(e.changes) +
      link
    );
  }
  function openEvent(e) {
    const dlg = document.querySelector('#siemEventDialog');
    if (!e || !dlg) return;
    document.querySelector('#siemEventTitle').textContent = e.title || typeLabel(e) || 'Event';
    const body = document.querySelector('#siemEventBody');
    body.className = `nw-detail siem-change-${changeClass(e)}`;
    body.innerHTML = eventDetailHtml(e);
    if (dlg.showModal) dlg.showModal();
  }
  function rowFromEvent(ev) {
    const row = ev.target?.closest?.('[data-siem-index]');
    return row ? shown[Number(row.dataset.siemIndex)] : null;
  }
  async function load() {
    document.querySelector('#siemCount').textContent = 'Loading…';
    try {
      const d = await j('/api/v1/siem/preview?limit=1000');
      events = d.events || [];
      render();
    } catch (err) {
      document.querySelector('#siemCount').textContent = 'Load failed';
      document.querySelector('#siemRows').innerHTML = `<tr><td colspan="6">${siemEsc(err.message)}</td></tr>`;
    }
  }
  function showProvider() {
    const p = document.querySelector('#siemProvider').value;
    document.querySelector('#siemSplunkFields').classList.toggle('hidden', p !== 'splunk_hec');
    document.querySelector('#siemSyslogFields').classList.toggle('hidden', p !== 'syslog_cef');
  }
  function statusText(cfg) {
    const s = cfg.status || {};
    if (!cfg.enabled) return 'Disabled';
    if (s.last_error) return `Error · ${s.last_error}`;
    if (s.last_success) return `Active · last sent ${s.last_sent || 0}`;
    return 'Enabled · awaiting first cycle';
  }
  // Splunk Cloud web URL → HEC event endpoint (https://http-inputs-<stack>.splunkcloud.com/...).
  function suggestHecUrl(input) {
    const text = String(input || '').trim();
    if (!text) return '';
    let u;
    try {
      u = new URL(/^[a-z]+:\/\//i.test(text) ? text : `https://${text}`);
    } catch {
      return '';
    }
    const host = u.hostname.toLowerCase();
    const domain = ['splunkcloud.com', 'splunkcloudgc.com'].find((d) => host.endsWith(`.${d}`));
    if (!domain || /^http-inputs[-.]/.test(host) || (u.port && u.port !== '443')) return '';
    const stack = host.slice(0, -(domain.length + 1));
    return stack ? `https://http-inputs-${stack}.${domain}/services/collector/event` : '';
  }
  function updateEndpointHint() {
    const input = (document.querySelector('#siemSplunkUrl')?.value || '').trim(),
      hint = document.querySelector('#siemEndpointHint');
    if (!hint) return;
    let html = siemEsc(
        'Use the Splunk HTTP Event Collector endpoint, not the Splunk Web login URL — e.g. https://http-inputs-<stack>.splunkcloud.com/services/collector/event (port 443) for Splunk Cloud, or https://<host>:8088/services/collector/event on-prem. NodeWatch verifies HEC with a real test event.',
      ),
      cls = 'notice info siem-span-2';
    const suggestion = suggestHecUrl(input);
    if (suggestion) {
      html =
        `This is the Splunk Web address. For this stack the HEC endpoint is <strong>${siemEsc(suggestion)}</strong> (port 443). ` +
        `Splunk Cloud on Google Cloud uses https://http-inputs.&lt;stack&gt;.splunkcloud.com instead. ` +
        `<button type="button" id="siemUseHecUrl" class="btn tiny secondary" data-url="${siemEsc(suggestion)}">Use HEC URL</button>`;
      cls = 'notice warning siem-span-2';
    } else if (/\/services\/collector\/raw/i.test(input)) {
      html = siemEsc(
        'NodeWatch sends JSON event envelopes — use /services/collector/event instead of /services/collector/raw.',
      );
      cls = 'notice warning siem-span-2';
    }
    hint.innerHTML = html;
    hint.className = cls;
    const btn = hint.querySelector?.('#siemUseHecUrl');
    if (btn)
      btn.addEventListener('click', () => {
        document.querySelector('#siemSplunkUrl').value = btn.dataset.url;
        updateEndpointHint();
      });
  }
  async function loadForwarder() {
    const cfg = await j('/api/v1/siem/forwarder');
    document.querySelector('#siemProvider').value = cfg.provider || 'splunk_hec';
    document.querySelector('#siemInterval').value = String(cfg.interval_seconds || 60);
    document.querySelector('#siemEnabled').checked = !!cfg.enabled;
    document.querySelector('#siemSplunkUrl').value = cfg.splunk_url || '';
    document.querySelector('#siemSplunkToken').value = '';
    document.querySelector('#siemSplunkToken').placeholder = cfg.token_present
      ? 'Saved in Credential Manager — leave blank to keep'
      : 'Enter Splunk HEC token';
    document.querySelector('#siemSplunkIndex').value = cfg.splunk_index || '';
    document.querySelector('#siemSplunkSourceType').value =
      cfg.splunk_sourcetype || 'nodewatch:network:events';
    document.querySelector('#siemVerifyTls').checked = cfg.verify_tls !== false;
    document.querySelector('#siemProxy').value = cfg.proxy_url || '';
    document.querySelector('#siemSyslogHost').value = cfg.syslog_host || '';
    document.querySelector('#siemSyslogPort').value = cfg.syslog_port || 514;
    document.querySelector('#siemSyslogProtocol').value = cfg.syslog_protocol || 'udp';
    document.querySelector('#siemForwardStatus').textContent = statusText(cfg);
    showProvider();
    updateEndpointHint();
  }
  async function saveForwarder() {
    const provider = document.querySelector('#siemProvider').value,
      verifyTls = document.querySelector('#siemVerifyTls').checked;
    if (
      provider === 'splunk_hec' &&
      !verifyTls &&
      !confirm('TLS certificate verification is disabled for Splunk HEC. Save this insecure setting anyway?')
    )
      return;
    const msg = document.querySelector('#siemForwardMessage');
    msg.textContent = 'Saving…';
    const payload = {
      provider,
      interval_seconds: Number(document.querySelector('#siemInterval').value || 60),
      enabled: document.querySelector('#siemEnabled').checked,
      splunk_url: document.querySelector('#siemSplunkUrl').value.trim(),
      splunk_token: document.querySelector('#siemSplunkToken').value.trim(),
      splunk_index: document.querySelector('#siemSplunkIndex').value.trim(),
      splunk_sourcetype: document.querySelector('#siemSplunkSourceType').value.trim(),
      verify_tls: verifyTls,
      proxy_url: document.querySelector('#siemProxy').value.trim(),
      syslog_host: document.querySelector('#siemSyslogHost').value.trim(),
      syslog_port: Number(document.querySelector('#siemSyslogPort').value || 514),
      syslog_protocol: document.querySelector('#siemSyslogProtocol').value,
    };
    try {
      await j('/api/v1/siem/forwarder', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      msg.textContent = 'Destination saved.';
      await loadForwarder();
    } catch (err) {
      msg.textContent = err.message;
    }
  }
  async function action(path, label) {
    const msg = document.querySelector('#siemForwardMessage');
    msg.textContent = label + '…';
    try {
      const d = await j(path, { method: 'POST' });
      msg.textContent = `${label} complete · ${d.sent ?? 0} event(s)`;
      await loadForwarder();
    } catch (err) {
      msg.textContent = err.message;
      await loadForwarder().catch(() => {});
      // A failed Splunk send: show where it breaks without making the engineer click again.
      if (document.querySelector('#siemProvider').value === 'splunk_hec') diagnose();
    }
  }
  async function diagnose() {
    const box = document.querySelector('#siemDiagResult');
    box.classList.remove('hidden');
    box.innerHTML = '<div class="muted">Checking the connection step by step…</div>';
    try {
      const d = await j('/api/v1/siem/forwarder/diagnose', { method: 'POST' });
      const icon = (ok) => (ok === true ? '✓' : ok === false ? '✕' : '!');
      const cls = (ok) => (ok === true ? 'ok' : ok === false ? 'bad' : 'warn');
      const rows = (d.steps || [])
        .map(
          (s) =>
            `<li class="${cls(s.ok)}"><span class="siem-diag-icon" aria-hidden="true">${icon(s.ok)}</span><b>${siemEsc(s.label)}</b><span>${siemEsc(s.detail)}</span>${s.ms != null ? `<small class="muted">${siemEsc(s.ms)} ms</small>` : ''}</li>`,
        )
        .join('');
      const v = d.verdict;
      const advice = (d.advice || [])
        .filter((a) => !v || a !== v.detail)
        .map((a) => `<li>${siemEsc(a)}</li>`)
        .join('');
      // v0.10.24: "Which side is the issue?" - the verdict from the firewall logs, with the public egress
      // IP to give to the Splunk admin (copy button).
      const verdict = v
        ? `<div class="siem-verdict siem-verdict-${siemEsc(v.side)}" role="status"><div class="siem-verdict-top"><span class="siem-verdict-label">Where the problem is</span><strong>${siemEsc(v.headline)}</strong></div><p>${siemEsc(v.detail)}</p>${
            v.egress_ip || v.local_ip
              ? `<div class="siem-verdict-ips">${v.egress_ip ? `<span>Public egress IP <code>${siemEsc(v.egress_ip)}</code> <button type="button" class="btn ghost small" data-copy="${siemEsc(v.egress_ip)}">Copy</button></span>` : ''}${v.local_ip ? `<span class="muted">This PC <code>${siemEsc(v.local_ip)}</code></span>` : ''}</div>`
              : ''
          }</div>`
        : '';
      box.innerHTML = `<div class="siem-diag-head"><strong>${d.ok ? 'Splunk HEC is reachable and the token works' : 'Connection check stopped at the first problem'}</strong><small class="muted">${siemEsc(d.endpoint || '')}</small></div>${verdict}<ol class="siem-diag-steps">${rows}</ol>${advice ? `<div class="siem-diag-advice"><b>What else to check</b><ul>${advice}</ul></div>` : ''}`;
      box.querySelectorAll('[data-copy]').forEach((btn) =>
        btn.addEventListener('click', async () => {
          try {
            await navigator.clipboard.writeText(btn.dataset.copy);
            btn.textContent = 'Copied';
          } catch {
            btn.textContent = 'Select and copy';
          }
          setTimeout(() => (btn.textContent = 'Copy'), 1500);
        }),
      );
    } catch (err) {
      box.innerHTML = `<div class="notice error">${siemEsc(err.message)}</div>`;
    }
  }
  async function downloadExport(fmt) {
    const r = await fetch(`/api/v1/siem/export?fmt=${encodeURIComponent(fmt)}&limit=5000`, {
      method: 'POST',
    });
    if (!r.ok) {
      let msg = await r.text();
      try {
        msg = JSON.parse(msg).detail || msg;
      } catch {}
      throw new Error(msg || `HTTP ${r.status}`);
    }
    const blob = await r.blob(),
      disp = r.headers.get('content-disposition') || '',
      match = disp.match(/filename="?([^";]+)"?/i),
      name = match?.[1] || `NodeWatch-SIEM.${fmt === 'cef' ? 'cef' : 'jsonl'}`,
      url = URL.createObjectURL(blob),
      a = document.createElement('a');
    a.href = url;
    a.download = name;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
  function init() {
    if (initd) return;
    initd = true;
    document.querySelector('#siemRefresh').onclick = load;
    document.querySelector('#siemJson').onclick = () => downloadExport('jsonl');
    document.querySelector('#siemCef').onclick = () => downloadExport('cef');
    document.querySelector('#siemProvider').onchange = showProvider;
    document.querySelector('#siemSaveForwarder').onclick = saveForwarder;
    document.querySelector('#siemTestForwarder').onclick = () =>
      action('/api/v1/siem/forwarder/test', 'Test event');
    document.querySelector('#siemDiagnose').onclick = diagnose;
    document.querySelector('#siemRunForwarder').onclick = () =>
      action('/api/v1/siem/forwarder/run', 'Forward now');
    document.querySelector('#siemSplunkUrl')?.addEventListener('input', updateEndpointHint);
    const rowsEl = document.querySelector('#siemRows');
    rowsEl?.addEventListener('click', (ev) => openEvent(rowFromEvent(ev)));
    rowsEl?.addEventListener('keydown', (ev) => {
      if (ev.key === 'Enter') openEvent(rowFromEvent(ev));
    });
    ['siemSearch', 'siemSeverity', 'siemChangeType', 'siemSort'].forEach((id) =>
      document.querySelector('#' + id)?.addEventListener(id === 'siemSearch' ? 'input' : 'change', render),
    );
    autoAt = Date.now();
    return Promise.all([load(), loadForwarder()]);
  }
  // v0.10.40: the event preview (up to 1,000 rows, rebuilt from every alarm, event and audit entry on the
  // server) is re-read every 2 minutes while open, not on every 30 s page tick.
  let autoAt = 0;
  function autoRefresh() {
    if (Date.now() - autoAt < 120000) return Promise.resolve();
    autoAt = Date.now();
    return load();
  }
  return {
    init,
    refresh: load,
    autoRefresh,
    _test: {
      sevNorm,
      suggestHecUrl,
      eventDetailHtml,
      changeClass,
      fmtTime,
      render,
      setEvents: (list) => {
        events = list;
      },
    },
  };
})();
