// Settings › Connections (v0.10.18): "Connected" cards + an "Available" catalog, and the
// Add-connection wizard (pick → before you start → connect → test → done). Everything is drawn from
// the connector manifests (settings fields + setup guide); no per-vendor UI code.
// The backend (app/modules/connectors/router.py) owns validation and secrets; this page never sees a
// saved secret value (secret fields come back as true/false).
(function () {
  'use strict';

  const API = '/api/v1/connectors';
  const CATEGORY_ORDER = ['network_management', 'firewall', 'sdwan', 'logging', 'siem', 'other'];
  const STATE_CLASS = {
    connected: 'is-ok',
    ready: 'is-ready',
    disabled: 'is-off',
    not_configured: 'is-off',
    error: 'is-bad',
    load_failed: 'is-bad',
  };
  const STEPS = ['Choose', 'Before you start', 'Connect', 'Test', 'Done'];
  const CHECK_ICON = { pass: '✓', fail: '✕', warn: '!', skip: '–' };
  const STATUS_TEXT = {
    ok: 'Readable',
    partial: 'Readable, some details missing',
    denied: 'Refused',
    empty: 'Empty',
    unsupported: 'Not offered',
    error: 'Failed',
    timeout: 'Timed out',
    skipped: 'Not checked',
  };
  let catalog = null;
  let recheckCount = 0;
  let recheckTimer = null;
  let capabilities = {};
  let loading = null;
  let wiz = null; // { id, step, mode: 'new'|'edit'|'retest', values, report, testing, saved, query }

  const esc = nwEscapeHtml; // one shared escaper (core.js)

  const call = (url, options = {}) =>
    nwFetchJSON(url, { ...options, headers: { 'Content-Type': 'application/json', ...(options.headers || {}) } }); // core.js

  const rows = () => catalog?.connectors || [];
  const row = (id) => rows().find((c) => c.connector_id === id);
  const isConnected = (c) => c.state === 'load_failed' || !!c.configured;

  // ---- shared bits ---------------------------------------------------------------------------
  // v0.10.32: a Preview connector that works on this network (connected and answering, remembered across
  // restarts by the backend as verified_here) is shown as Stable: it has now been validated on a live system.
  function badges(c) {
    const shown = c.maturity_shown || c.maturity;
    if (shown === 'preview')
      return '<span class="conn-badge conn-preview" title="Built from the vendor\'s public API documentation; not yet validated on a live system">Preview</span>';
    if (shown === 'stable')
      return `<span class="conn-badge conn-stable" title="${c.maturity === 'preview' && c.verified_here ? 'Working on your network: validated here on a live system' : 'Validated on a live system'}">Stable</span>`;
    return '';
  }

  function stateBadge(c) {
    const cls = STATE_CLASS[c.state] || 'is-off';
    return `<span class="conn-badge conn-state ${cls}">${esc(c.label || c.state)}</span>`;
  }

  function chips(c) {
    return (c.capabilities || [])
      .map(
        (cap) =>
          `<span class="conn-chip" title="${esc(cap)}">${esc((c.capability_labels || {})[cap] || cap)}</span>`,
      )
      .join('');
  }

  // ---- main page: Connected + Available -----------------------------------------------------
  function connectedCard(c) {
    const stateCls = STATE_CLASS[c.state] || 'is-off';
    const err = (c.state === 'error' || c.state === 'load_failed') && c.health && c.health.last_error;
    let actions;
    if (c.state === 'load_failed') {
      actions = `<span class="muted">Fix or remove the <code>${esc(c.package || c.connector_id)}</code> connector folder and restart NodeWatch. Details are in the NodeWatch log.</span>`;
    } else if (c.managed_elsewhere) {
      // v0.10.23: an inventory switch for connections set up elsewhere (Strata Cloud Manager firewalls).
      const inv = c.inventory_switch
        ? `<label class="conn-switch" title="Show this account's firewalls in Topology and Inventory"><input type="checkbox" data-act="enable"${c.inventory_enabled ? ' checked' : ''}><span class="conn-switch-track" aria-hidden="true"></span><span>Firewall inventory ${c.inventory_enabled ? 'on' : 'off'}</span></label>`
        : '';
      actions = `${inv}<span class="muted conn-where">Set up on <strong>${esc(c.settings_location || 'its own settings section')}</strong></span>
        <span class="conn-actions-row"><button type="button" class="btn ghost small" data-act="retest">Re-test</button><button type="button" class="btn secondary small" data-act="goto" data-target="${esc(c.settings_location || '')}">Open settings</button></span>`;
    } else {
      actions = `<label class="conn-switch" title="Use this connection in NodeWatch"><input type="checkbox" data-act="enable"${c.enabled ? ' checked' : ''}><span class="conn-switch-track" aria-hidden="true"></span><span>${c.enabled ? 'On' : 'Off'}</span></label>
        <span class="conn-actions-row"><button type="button" class="btn ghost small" data-act="disconnect">Disconnect</button><button type="button" class="btn ghost small" data-act="retest">Re-test</button><button type="button" class="btn secondary small" data-act="edit">Edit</button></span>`;
    }
    const summary = c.setup?.summary || c.description || '';
    return `<article class="conn-item ${stateCls}" data-connector="${esc(c.connector_id)}" data-ui="Settings &amp; Support › Connections › Connected › ${esc(c.product)}">
      <header class="conn-head">
        <div class="conn-title"><div class="eyebrow">${esc(c.vendor || c.category_label)}</div><h4>${esc(c.product)}</h4></div>
        <div class="conn-badges">${badges(c)}${stateBadge(c)}</div>
      </header>
      <p class="conn-desc">${esc(summary)}</p>
      <div class="conn-chips" aria-label="What NodeWatch reads">${chips(c)}</div>
      ${err ? `<div class="notice conn-error" role="alert"><strong>Last error:</strong> ${esc(err)}</div>` : ''}
      <div class="conn-foot">${actions}</div>
    </article>`;
  }

  function availableTile(c) {
    const mins = c.setup?.estimated_minutes;
    return `<article class="conn-tile" data-connector="${esc(c.connector_id)}" data-ui="Settings &amp; Support › Connections › Ready to connect › ${esc(c.product)}">
      <div class="conn-tile-top"><div><div class="eyebrow">${esc(c.vendor)}</div><h5>${esc(c.product)}</h5></div>${badges(c)}</div>
      <p class="conn-tile-desc">${esc(c.setup?.summary || c.description || '')}</p>
      <div class="conn-tile-foot"><span class="muted">${esc(c.category_label || '')}${mins ? ` · about ${esc(mins)} min` : ''}</span><button type="button" class="btn secondary small" data-act="connect">Connect</button></div>
    </article>`;
  }

  function renderSummary() {
    const summary = document.querySelector('#connSummary');
    const connected = rows().filter((r) => r.state === 'connected' || r.state === 'ready').length;
    // v0.10.32: no "of N": products can be added at any time, so only what is connected is counted.
    if (summary) summary.textContent = connected ? `${connected} connected` : 'Nothing connected yet';
  }

  function render() {
    const root = document.querySelector('#connGroups');
    if (!root || !catalog) return;
    renderSummary();
    const sorted = [...rows()].sort(
      (a, b) =>
        CATEGORY_ORDER.indexOf(a.category) - CATEGORY_ORDER.indexOf(b.category) ||
        String(a.product).localeCompare(String(b.product)),
    );
    const connected = sorted.filter(isConnected);
    const available = sorted.filter((c) => !isConnected(c));
    root.innerHTML = `
      <section class="conn-section" data-ui="Settings &amp; Support › Connections › Connected">
        <h4 class="conn-group-title">Connected <span class="conn-count">${connected.length}</span></h4>
        ${
          connected.length
            ? `<div class="conn-grid">${connected.map(connectedCard).join('')}</div>`
            : '<div class="conn-empty">Nothing is connected yet. Use <strong>Add connection</strong> to connect your first product — it takes about 5 minutes.</div>'
        }
      </section>
      ${
        available.length
          ? `<section class="conn-section conn-ready" data-ui="Settings &amp; Support › Connections › Ready to connect"><div class="conn-avail-grid">${available.map(availableTile).join('')}</div></section>`
          : ''
      }`;
    renderCapabilities();
    // The three-step guide is for a first connection; once something is connected it steps aside.
    document.querySelector('#view-settings .settings-start')?.classList.toggle('hidden', connected.length > 0);
  }

  function renderCapabilities() {
    const strip = document.querySelector('#connCapabilities');
    if (!strip) return;
    const entries = Object.entries(capabilities || {});
    if (!entries.length) {
      strip.innerHTML = '';
      return;
    }
    const names = Object.fromEntries(rows().map((c) => [c.connector_id, c.product]));
    strip.innerHTML = `<span class="conn-capstrip-label">Data available now</span>${entries
      .map(([cap, info]) => {
        const from = (info.sources || []).map((s) => names[s] || s).join(', ');
        return `<span class="conn-cap ${info.available ? 'is-on' : 'is-off'}" title="${esc(info.available ? `From ${from}` : 'No connected source offers this yet')}">${info.available ? '✓ ' : ''}${esc(info.label || cap)}</span>`;
      })
      .join('')}`;
  }

  // ---- data ------------------------------------------------------------------------------------
  async function load() {
    if (loading) return loading;
    loading = (async () => {
      try {
        const [cat, caps] = await Promise.all([call(API), call(`${API}/capabilities`)]);
        catalog = cat;
        capabilities = caps.capabilities || {};
        window.NodeWatchCapabilities = capabilities;
        document.dispatchEvent(new CustomEvent('nodewatch:capabilities', { detail: capabilities }));
        render();
        // v0.10.35: connections still being checked in the background (start-up) refresh themselves.
        const checking = rows().some((c) => c.configured && c.enabled && c.state === 'ready');
        if (checking && recheckCount < 6) {
          recheckCount += 1;
          clearTimeout(recheckTimer);
          recheckTimer = setTimeout(() => load(), 5000);
        }
      } catch (err) {
        const root = document.querySelector('#connGroups');
        if (root)
          root.innerHTML = `<div class="notice warning">Connections could not be loaded: ${esc(err.message)}</div>`;
      } finally {
        loading = null;
      }
    })();
    return loading;
  }

  function replaceRow(r) {
    if (!catalog || !r || !r.connector_id) return;
    catalog.connectors = catalog.connectors.map((c) => (c.connector_id === r.connector_id ? r : c));
  }

  async function refreshCapabilities() {
    try {
      const caps = await call(`${API}/capabilities`);
      capabilities = caps.capabilities || {};
      window.NodeWatchCapabilities = capabilities;
      document.dispatchEvent(new CustomEvent('nodewatch:capabilities', { detail: capabilities }));
      renderCapabilities();
    } catch {}
  }

  function gotoSection(target) {
    const section = Array.from(document.querySelectorAll('#view-settings [data-ui]')).find(
      (el) => el.dataset.ui === target,
    );
    if (section) window.MistTools?.settings?.showCard?.(section); // its section of Settings first (v0.10.32)
    section?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  // ---- card actions --------------------------------------------------------------------------
  async function cardAction(id, action, el) {
    const c = row(id);
    if (!c) return;
    if (action === 'connect') return openWizard(id, 1, 'new');
    if (action === 'edit') return openWizard(id, 2, 'edit');
    if (action === 'retest') return openWizard(id, 3, 'retest');
    if (action === 'goto') return gotoSection(el.dataset.target || '');
    if (action === 'disconnect') {
      if (
        !confirm(
          `Disconnect ${c.product}? Its settings and saved credentials are removed from this computer.`,
        )
      )
        return;
      try {
        const res = await call(`${API}/${encodeURIComponent(id)}`, { method: 'DELETE' });
        replaceRow(res.connector);
        render();
        await refreshCapabilities();
      } catch (err) {
        alert(`Could not disconnect: ${err.message}`);
      }
      return;
    }
    if (action === 'enable') {
      el.disabled = true;
      try {
        const res = await call(`${API}/${encodeURIComponent(id)}/enabled`, {
          method: 'POST',
          body: JSON.stringify({ enabled: !!el.checked }),
        });
        replaceRow(res.connector);
        render();
        await refreshCapabilities();
      } catch (err) {
        el.checked = !el.checked;
        alert(err.message);
      } finally {
        el.disabled = false;
      }
    }
  }

  // ---- wizard ------------------------------------------------------------------------------------
  function wizEls() {
    let layer = document.querySelector('#connWizard');
    if (!layer) {
      // On <body>: the Settings cards use backdrop-filter, which would clip a fixed layer.
      layer = document.createElement('div');
      layer.id = 'connWizard';
      layer.className = 'connwiz-layer hidden';
      layer.innerHTML = `<div class="connwiz-backdrop" data-wiz="close"></div>
        <section class="connwiz" role="dialog" aria-modal="true" aria-labelledby="connwizTitle" data-ui="Settings &amp; Support › Connections › Add connection" tabindex="-1">
          <header class="connwiz-head"><div><div class="eyebrow" data-wiz-eyebrow>Add connection</div><h3 id="connwizTitle">Add connection</h3></div><button type="button" class="connwiz-x" data-wiz="close" aria-label="Close">✕</button></header>
          <ol class="connwiz-steps" data-ui="Settings &amp; Support › Connections › Add connection › Steps"></ol>
          <div class="connwiz-body"></div>
          <footer class="connwiz-foot"></footer>
        </section>`;
      document.body.appendChild(layer);
      wireWizard(layer);
    }
    return {
      layer,
      dialog: layer.querySelector('.connwiz'),
      title: layer.querySelector('#connwizTitle'),
      eyebrow: layer.querySelector('[data-wiz-eyebrow]'),
      steps: layer.querySelector('.connwiz-steps'),
      body: layer.querySelector('.connwiz-body'),
      foot: layer.querySelector('.connwiz-foot'),
    };
  }

  function openWizard(id = '', step = 0, mode = 'new') {
    const c = id ? row(id) : null;
    wiz = { id, step, mode, values: c ? initialValues(c) : {}, report: null, testing: false, query: '' };
    const { layer } = wizEls();
    layer.classList.remove('hidden');
    document.body.classList.add('connwiz-open');
    drawWizard();
    if (mode === 'retest') runTest();
  }

  function closeWizard() {
    const layer = document.querySelector('#connWizard');
    layer?.classList.add('hidden');
    document.body.classList.remove('connwiz-open');
    wiz = null;
    render();
  }

  function initialValues(c) {
    const values = {};
    (c.settings || []).forEach((f) => {
      const v = c.values ? c.values[f.key] : undefined;
      if (f.type === 'secret') values[f.key] = '';
      else
        values[f.key] =
          v === undefined || v === null ? (f.default ?? (f.type === 'boolean' ? false : '')) : v;
    });
    return values;
  }

  function stepsHtml() {
    const c = wiz.id ? row(wiz.id) : null;
    const managed = !!c?.managed_elsewhere;
    return STEPS.map((label, i) => {
      const state = i < wiz.step ? 'is-done' : i === wiz.step ? 'is-current' : '';
      const off = managed && (i === 2 || i === 4) ? ' is-skipped' : '';
      return `<li class="${state}${off}"${i === wiz.step ? ' aria-current="step"' : ''}><span class="connwiz-num">${i < wiz.step ? '✓' : i + 1}</span><span>${esc(label)}</span></li>`;
    }).join('');
  }

  function drawWizard() {
    if (!wiz) return;
    const els = wizEls();
    const c = wiz.id ? row(wiz.id) : null;
    els.eyebrow.textContent =
      wiz.mode === 'edit'
        ? 'Edit connection'
        : wiz.mode === 'retest'
          ? 'Re-test connection'
          : 'Add connection';
    els.title.textContent = c ? `${c.vendor ? `${c.vendor} · ` : ''}${c.product}` : 'Choose what to connect';
    els.steps.innerHTML = stepsHtml();
    const [body, foot] = [step0, step1, step2, step3, step4][wiz.step](c);
    els.body.innerHTML = body;
    els.foot.innerHTML = foot;
    els.body.scrollTop = 0;
    const focus =
      els.body.querySelector('[data-autofocus]') ||
      els.body.querySelector('input:not([type=checkbox]), select') ||
      els.dialog;
    setTimeout(() => focus?.focus?.(), 30);
    if (wiz.step === 2) validateForm(false);
  }

  // Step 1 — choose
  function step0() {
    const q = (wiz.query || '').toLowerCase().trim();
    const labels = catalog?.categories || {};
    const list = rows().filter(
      (c) =>
        c.state !== 'load_failed' &&
        (!q ||
          [c.vendor, c.product, c.category_label, c.setup?.summary, c.description]
            .join(' ')
            .toLowerCase()
            .includes(q)),
    );
    const groups = CATEGORY_ORDER.map((cat) => [cat, list.filter((c) => c.category === cat)]).filter(
      ([, l]) => l.length,
    );
    const cards = groups
      .map(
        ([cat, l]) =>
          `<section class="connwiz-cat"><h4 class="conn-group-title">${esc(labels[cat] || cat)}</h4><div class="connwiz-cards">${l
            .map(
              (
                c,
              ) => `<button type="button" class="connwiz-card${c.configured ? ' is-connected' : ''}" data-wiz="pick" data-id="${esc(c.connector_id)}">
              <span class="connwiz-card-top"><span><span class="eyebrow">${esc(c.vendor)}</span><strong>${esc(c.product)}</strong></span><span class="conn-badges">${badges(c)}${c.configured ? '<span class="conn-badge conn-state is-ok">Already connected</span>' : ''}</span></span>
              <span class="connwiz-card-desc">${esc(c.setup?.summary || c.description || '')}</span>
              <span class="connwiz-card-meta">${c.setup?.estimated_minutes ? `About ${esc(c.setup.estimated_minutes)} min` : ''}${c.managed_elsewhere ? ` · set up on ${esc(c.settings_location)}` : ''}</span>
            </button>`,
            )
            .join('')}</div></section>`,
      )
      .join('');
    const body = `<label class="connwiz-search"><span class="connwiz-sr">Search products</span><input type="search" data-wiz-input="query" placeholder="Search vendors and products — Silver Peak, Panorama, SNMP …" value="${esc(wiz.query || '')}" autocomplete="off" data-autofocus></label>
      <div data-wiz-results>${cards || '<p class="muted">No product matches. NodeWatch reads from the products listed here; developers can add one with tools/new_connector.py.</p>'}</div>`;
    return [
      body,
      `<span class="muted">Pick a product to see how to connect it.</span><button type="button" class="btn ghost" data-wiz="close">Cancel</button>`,
    ];
  }

  // Step 2 — before you start
  function step1(c) {
    const s = c.setup || {};
    const prereq = (s.prerequisites || []).map((p) => `<li>${esc(p)}</li>`).join('');
    const steps = (s.steps || [])
      .map(
        (st) =>
          `<li><strong>${esc(st.title)}</strong><p>${esc(st.detail)}</p>${
            st.copy
              ? `<div class="connwiz-copy"><code>${esc(st.copy)}</code><button type="button" class="btn ghost small" data-wiz="copy" data-copy="${esc(st.copy)}">Copy</button></div>`
              : ''
          }${st.link ? `<a class="conn-docs" href="${esc(st.link)}" target="_blank" rel="noopener noreferrer">Vendor instructions ↗</a>` : ''}</li>`,
      )
      .join('');
    const uncertain = (s.uncertain || []).map((u) => `<li>${esc(u)}</li>`).join('');
    const body = c.setup
      ? `<p class="connwiz-lead">${esc(s.summary)}</p>
      <div class="connwiz-split">
        <div>
          ${prereq ? `<h4 class="connwiz-h">You need</h4><ul class="connwiz-list">${prereq}</ul>` : ''}
          <h4 class="connwiz-h">Create a read-only ${c.managed_elsewhere ? 'access' : 'account or key'}</h4>
          <ol class="connwiz-howto">${steps}</ol>
        </div>
        <aside class="connwiz-aside">
          <div class="connwiz-box is-key"><h4 class="connwiz-h">Least privilege</h4><p>${esc(s.permissions)}</p></div>
          <div class="connwiz-box"><h4 class="connwiz-h">What Test checks</h4><p>${esc(s.verify)}</p></div>
          ${uncertain ? `<div class="connwiz-box is-unsure"><h4 class="connwiz-h">Not yet confirmed on a live system</h4><ul class="connwiz-list">${uncertain}</ul></div>` : ''}
          <p class="muted connwiz-meta">${s.estimated_minutes ? `About ${esc(s.estimated_minutes)} minutes. ` : ''}${c.docs_url ? `<a class="conn-docs" href="${esc(c.docs_url)}" target="_blank" rel="noopener noreferrer">API documentation ↗</a>` : ''}</p>
        </aside>
      </div>`
      : `<p class="muted">This connector has no setup guide yet. Fill in the connection form; the vendor documentation is linked below.</p>${c.docs_url ? `<a class="conn-docs" href="${esc(c.docs_url)}" target="_blank" rel="noopener noreferrer">API documentation ↗</a>` : ''}`;
    const back =
      wiz.mode === 'new' ? '<button type="button" class="btn ghost" data-wiz="back">Back</button>' : '';
    const next = c.managed_elsewhere
      ? `<button type="button" class="btn ghost" data-wiz="retest-managed">Test current setup</button><button type="button" class="btn primary" data-wiz="goto" data-target="${esc(c.settings_location)}">Open ${esc(
          String(c.settings_location || '')
            .split('›')
            .pop()
            .trim(),
        )}</button>`
      : '<button type="button" class="btn primary" data-wiz="next">I have the details — continue</button>';
    return [body, `${back}<span class="connwiz-spacer"></span>${next}`];
  }

  // Step 3 — connect (the manifest-generated form)
  function fieldHtml(c, f) {
    const id = `connwiz-${c.connector_id}-${f.key}`;
    const value = wiz.values[f.key];
    const saved = c.values ? c.values[f.key] === true : false;
    const help = f.help ? `<small class="conn-help">${esc(f.help)}</small>` : '';
    const req = f.required ? ' <span class="conn-req" aria-hidden="true">*</span>' : '';
    const err = `<small class="conn-invalid hidden" data-err-for="${esc(f.key)}" role="alert"></small>`;
    if (f.type === 'boolean') {
      return `<label class="check-row conn-field conn-wide" for="${id}"><input id="${id}" type="checkbox" data-key="${esc(f.key)}" data-type="boolean"${value ? ' checked' : ''}> ${esc(f.label)}</label>${help ? `<div class="conn-wide">${help}</div>` : ''}`;
    }
    if (f.type === 'select') {
      const opts = (f.options || [])
        .map(
          (o) =>
            `<option value="${esc(o)}"${o === (value ?? f.default) ? ' selected' : ''}>${esc(o)}</option>`,
        )
        .join('');
      return `<label class="conn-field" for="${id}"><span>${esc(f.label)}${req}</span><select id="${id}" data-key="${esc(f.key)}" data-type="select">${opts}</select>${help}${err}</label>`;
    }
    if (f.type === 'secret') {
      const ph = saved ? 'Saved — leave blank to keep' : f.placeholder || 'Paste it here';
      return `<label class="conn-field" for="${id}"><span>${esc(f.label)}${req}</span><span class="connwiz-secret"><input id="${id}" type="password" autocomplete="new-password" spellcheck="false" data-key="${esc(f.key)}" data-type="secret" data-required="${f.required && !saved ? '1' : ''}" placeholder="${esc(ph)}" value="${esc(value || '')}"><button type="button" class="btn ghost small" data-wiz="reveal" aria-label="Show or hide ${esc(f.label)}">Show</button></span>${saved ? '<span class="conn-saved">Saved in Windows Credential Manager</span>' : ''}${help}${err}</label>`;
    }
    const type = f.type === 'number' ? 'number' : f.type === 'url' ? 'url' : 'text';
    return `<label class="conn-field" for="${id}"><span>${esc(f.label)}${req}</span><input id="${id}" type="${type}" autocomplete="off" spellcheck="false" data-key="${esc(f.key)}" data-type="${esc(f.type)}" data-required="${f.required ? '1' : ''}"${f.origin_only ? ' data-origin-only="1"' : ''} value="${esc(value ?? '')}" placeholder="${esc(f.placeholder || '')}">${help}${err}</label>`;
  }

  function step2(c) {
    const fields = (c.settings || []).map((f) => fieldHtml(c, f)).join('');
    const tlsOff = wiz.values.verify_tls === false;
    const body = `<form class="conn-form connwiz-form" data-wiz-form novalidate>
        <p class="muted connwiz-lead">Paste the details from the previous step. Secrets go to Windows Credential Manager and are never shown again.${wiz.mode === 'edit' ? ' Leave a saved secret blank to keep it.' : ''}</p>
        <div class="conn-fields">${fields}</div>
        <div class="notice warning conn-tls${tlsOff ? '' : ' hidden'}" data-tls-warning>Certificate checks are off for this connection. Prefer a private CA certificate file.</div>
      </form>`;
    const back = '<button type="button" class="btn ghost" data-wiz="back">Back</button>';
    return [
      body,
      `${back}<span class="connwiz-spacer"></span><button type="button" class="btn primary" data-wiz="test">Test connection</button>`,
    ];
  }

  function readForm() {
    const form = document.querySelector('[data-wiz-form]');
    if (!form || !wiz) return;
    form.querySelectorAll('[data-key]').forEach((el) => {
      wiz.values[el.dataset.key] = el.dataset.type === 'boolean' ? !!el.checked : el.value;
    });
  }

  function fieldError(el) {
    const v = String(el.value || '').trim();
    const type = el.dataset.type;
    if (el.dataset.required === '1' && !v) return 'Required';
    if (!v) return '';
    if (type === 'url') {
      try {
        const u = new URL(v);
        if (u.protocol !== 'https:') return 'Must start with https://';
        if (u.username || u.password) return 'No user name or password in the address';
        // A pasted page address (…/webclient/…#/) is reduced to the server for APIs that live at the root.
        if (el.dataset.originOnly === '1' && (u.pathname !== '/' || u.search || u.hash)) el.value = u.origin;
        else if (u.search || u.hash) return 'No query or fragment in the address';
      } catch {
        return 'Not a valid address — for example https://host.example.com';
      }
    }
    if (type === 'number' && !Number.isFinite(Number(v))) return 'Must be a number';
    if (v.length > 4096) return 'Too long';
    return '';
  }

  /** Inline validation: messages under fields (only once touched unless `all`), Test disabled when invalid. */
  function validateForm(all) {
    const form = document.querySelector('[data-wiz-form]');
    if (!form) return true;
    let ok = true;
    form.querySelectorAll('[data-key]').forEach((el) => {
      if (el.dataset.type === 'boolean' || el.dataset.type === 'select') return;
      const msg = fieldError(el);
      if (msg) ok = false;
      const box = form.querySelector(`[data-err-for="${el.dataset.key}"]`);
      const show = msg && (all || el.dataset.touched === '1');
      if (box) {
        box.textContent = show ? msg : '';
        box.classList.toggle('hidden', !show);
      }
      el.setAttribute('aria-invalid', show ? 'true' : 'false');
    });
    const btn = document.querySelector('.connwiz-foot [data-wiz="test"]');
    if (btn) btn.setAttribute('aria-disabled', ok ? 'false' : 'true');
    return ok;
  }

  // Step 4 — test
  function checklistHtml(report) {
    return `<ul class="connwiz-checks" data-ui="Settings &amp; Support › Connections › Add connection › Test checklist">${(
      report.checks || []
    )
      .map(
        (ch) =>
          `<li class="is-${esc(ch.status)}"><span class="connwiz-icon" aria-hidden="true">${CHECK_ICON[ch.status] || '–'}</span><span class="connwiz-check-label">${esc(ch.label)}</span><span class="connwiz-check-detail">${esc(ch.detail)}</span></li>`,
      )
      .join('')}</ul>`;
  }

  function capsHtml(report) {
    const probes = report.probes || [];
    if (!(report.capabilities || []).length) return '';
    const rowsHtml = report.capabilities
      .map((cap) => {
        const mine = probes.filter((p) => p.capability === cap.capability);
        const needs = mine
          .filter((p) => ['denied', 'empty'].includes(p.status) && p.needs)
          .map((p) => p.needs);
        const sub = mine
          .map(
            (p) =>
              `<li class="is-${esc(p.status)}"><span>${esc(p.check)}${p.optional ? ' <em>(details)</em>' : ''}</span><span>${esc(STATUS_TEXT[p.status] || p.status)}${p.status !== 'ok' && p.detail ? ` — ${esc(p.detail)}` : ''}</span></li>`,
          )
          .join('');
        return `<tr class="is-${esc(cap.status)}"><td><strong>${esc(cap.label)}</strong></td><td><span class="connwiz-pill is-${esc(cap.status)}">${esc(STATUS_TEXT[cap.status] || cap.status)}</span></td><td>${esc(cap.detail)}${
          needs.length ? `<div class="connwiz-needs">Needs: ${esc([...new Set(needs)].join('; '))}</div>` : ''
        }${sub ? `<details class="connwiz-probes"><summary>${mine.length} check${mine.length === 1 ? '' : 's'}</summary><ul>${sub}</ul></details>` : ''}</td></tr>`;
      })
      .join('');
    return `<h4 class="connwiz-h">What this ${esc(report._credential || 'account')} can read</h4>
      <table class="connwiz-caps" data-nosort data-nofilter data-ui="Settings &amp; Support › Connections › Add connection › Capability checks"><thead><tr><th>Data</th><th>Result</th><th>Details</th></tr></thead><tbody>${rowsHtml}</tbody></table>`;
  }

  function step3(c) {
    const r = wiz.report;
    const budget = catalog?.probe_budget_s || 20;
    let body;
    if (wiz.testing) {
      body = `<div class="connwiz-testing" role="status"><span class="connwiz-spinner" aria-hidden="true"></span><div><strong>Testing ${esc(c.product)}…</strong><p class="muted">Read-only checks, at most ${esc(budget)} seconds. Nothing is saved yet.</p></div></div>`;
    } else if (!r) {
      body = '<p class="muted">Run the test to check the connection.</p>';
    } else if (r.httpError) {
      body = `<div class="notice conn-error" role="alert"><strong>The test could not run:</strong> ${esc(r.httpError)}</div>`;
    } else {
      const unlock = r.unlock
        ? `<div class="connwiz-box ${r.unlock.more_needed ? 'is-unsure' : 'is-key'} connwiz-unlock"><h4 class="connwiz-h">Would more permission help?</h4><p>${esc(r.unlock.text)}</p>${
            (r.unlock.items || []).length
              ? `<ul class="connwiz-list connwiz-unlock-items">${r.unlock.items.map((i) => `<li><strong>${esc(i.unlocks)}</strong> — ${esc(i.needs)}</li>`).join('')}</ul>`
              : ''
          }</div>`
        : '';
      const failed = !r.ok || (r.checks || []).some((ch) => ch.status === 'fail' || ch.status === 'warn');
      const tips = (c.setup?.troubleshooting || [])
        .map((t) => `<li><strong>${esc(t.symptom)}</strong> — ${esc(t.fix)}</li>`)
        .join('');
      body = `<div class="connwiz-verdict ${r.ok ? 'is-ok' : 'is-bad'}"><strong>${r.ok ? 'Connected' : 'Not connected yet'}</strong><span>${esc(r.ok ? r.sample || r.detail || '' : r.error || '')}</span></div>
        ${checklistHtml(r)}
        ${capsHtml(r)}
        ${unlock}
        ${tips ? `<details class="connwiz-trouble"${failed ? ' open' : ''}><summary>Troubleshooting</summary><ul>${tips}</ul></details>` : ''}
        <p class="muted connwiz-meta">Finished in ${esc((r.elapsed_ms / 1000).toFixed(1))} s · read-only${wiz.mode === 'retest' ? ' · saved settings' : ' · not saved yet'}</p>`;
    }
    const busy = wiz.testing ? ' disabled' : '';
    let foot;
    if (c.managed_elsewhere) {
      foot = `<button type="button" class="btn ghost" data-wiz="back"${busy}>Back</button><span class="connwiz-spacer"></span><button type="button" class="btn ghost" data-wiz="rerun"${busy}>Run again</button><button type="button" class="btn primary" data-wiz="close"${busy}>Done</button>`;
    } else if (wiz.mode === 'retest') {
      foot = `<button type="button" class="btn ghost" data-wiz="edit"${busy}>Edit connection</button><span class="connwiz-spacer"></span><button type="button" class="btn ghost" data-wiz="rerun"${busy}>Run again</button><button type="button" class="btn primary" data-wiz="close"${busy}>Done</button>`;
    } else {
      const ok = r && r.ok;
      foot = `<button type="button" class="btn ghost" data-wiz="back"${busy}>Back</button><span class="connwiz-spacer"></span><button type="button" class="btn ghost" data-wiz="rerun"${busy}>Run again</button>${
        ok
          ? `<button type="button" class="btn primary" data-wiz="save"${busy}>Save connection</button>`
          : `<button type="button" class="btn secondary" data-wiz="save"${busy || (r ? '' : ' disabled')}>Save anyway</button>`
      }`;
    }
    return [body, foot];
  }

  // Step 5 — done
  function step4(c) {
    const s = c.setup || {};
    const places = new Map();
    Object.values(c.features || {}).forEach((list) =>
      (list || []).forEach((p) => {
        const cur = places.get(p.tool) || { label: p.label, what: [] };
        if (!cur.what.includes(p.what)) cur.what.push(p.what);
        places.set(p.tool, cur);
      }),
    );
    const where = [...places.entries()]
      .map(
        ([tool, p]) =>
          `<li><button type="button" class="btn ghost small" data-wiz="open-tool" data-tool="${esc(tool)}">Open ${esc(p.label)}</button><span class="muted">${esc(p.what.slice(0, 3).join(' · ') + (p.what.length > 3 ? ' …' : ''))}</span></li>`,
      )
      .join('');
    const data = (s.data_you_get || []).map((d) => `<li>${esc(d)}</li>`).join('');
    const body = `<div class="connwiz-verdict is-ok"><strong>${esc(c.product)} is saved</strong><span>${c.enabled ? 'NodeWatch reads from it now.' : 'Switched off — turn it on to use it.'}</span></div>
      <label class="conn-switch connwiz-enable"><input type="checkbox" data-wiz="enable"${c.enabled ? ' checked' : ''}><span class="conn-switch-track" aria-hidden="true"></span><span>Use this connection in NodeWatch</span></label>
      <div class="connwiz-split">
        <div><h4 class="connwiz-h">What you get now</h4><ul class="connwiz-list">${data || chips(c)}</ul></div>
        <div><h4 class="connwiz-h">Where to see it</h4><ul class="connwiz-where">${where || '<li class="muted">Tools pick it up automatically.</li>'}</ul></div>
      </div>`;
    return [
      body,
      '<span class="connwiz-spacer"></span><button type="button" class="btn primary" data-wiz="close">Close</button>',
    ];
  }

  // ---- wizard actions ----------------------------------------------------------------------------
  async function runTest() {
    if (!wiz) return;
    const c = row(wiz.id);
    wiz.step = 3;
    wiz.testing = true;
    wiz.report = null;
    drawWizard();
    const body = { probe: true };
    if (wiz.mode !== 'retest' && !c.managed_elsewhere) body.values = { ...wiz.values, enabled: true };
    const mine = wiz;
    let report;
    try {
      report = await call(`${API}/${encodeURIComponent(c.connector_id)}/test`, {
        method: 'POST',
        body: JSON.stringify(body),
      });
    } catch (err) {
      report = { ok: false, httpError: err.message, checks: [] };
    }
    if (wiz !== mine) return; // closed or restarted meanwhile
    if (report.connector) replaceRow(report.connector);
    report._credential = /key|token/i.test(JSON.stringify((c.settings || []).map((f) => f.label)))
      ? 'key'
      : 'account';
    wiz.report = report;
    wiz.testing = false;
    drawWizard();
  }

  async function save() {
    const c = row(wiz.id);
    const res = await call(`${API}/${encodeURIComponent(c.connector_id)}`, {
      method: 'POST',
      // v0.10.23: editing a connection keeps its On/Off state (it used to switch it on silently).
      body: JSON.stringify({
        enabled: wiz.mode === 'edit' ? !!c.enabled : true,
        values: { ...wiz.values, enabled: wiz.mode === 'edit' ? !!c.enabled : true },
      }),
    });
    replaceRow(res.connector);
    wiz.step = 4;
    drawWizard();
    await refreshCapabilities();
  }

  async function wizAction(action, el) {
    if (!wiz) return;
    if (action === 'close') return closeWizard();
    if (action === 'pick') {
      wiz.id = el.dataset.id;
      wiz.values = initialValues(row(wiz.id));
      wiz.mode = row(wiz.id)?.configured && !row(wiz.id)?.managed_elsewhere ? 'edit' : 'new';
      wiz.step = 1;
      return drawWizard();
    }
    if (action === 'back') {
      if (wiz.step === 2) readForm();
      if (wiz.step === 1 && wiz.mode !== 'new') return closeWizard();
      wiz.step = row(wiz.id)?.managed_elsewhere && wiz.step === 3 ? 1 : Math.max(0, wiz.step - 1);
      if (wiz.step === 0) wiz.id = '';
      return drawWizard();
    }
    if (action === 'next') {
      wiz.step = 2;
      return drawWizard();
    }
    if (action === 'edit') {
      wiz.mode = 'edit';
      wiz.step = 2;
      return drawWizard();
    }
    if (action === 'test') {
      readForm();
      document.querySelectorAll('[data-wiz-form] [data-key]').forEach((i) => (i.dataset.touched = '1'));
      if (!validateForm(true)) {
        document.querySelector('[data-wiz-form] [aria-invalid="true"]')?.focus();
        return;
      }
      return runTest();
    }
    if (action === 'retest-managed' || action === 'rerun') return runTest();
    if (action === 'save') {
      el.disabled = true;
      try {
        await save();
      } catch (err) {
        wiz.report = { ...(wiz.report || {}), ok: false, httpError: `Not saved: ${err.message}` };
        drawWizard();
      }
      return;
    }
    if (action === 'goto') {
      const target = el.dataset.target || '';
      closeWizard();
      return gotoSection(target);
    }
    if (action === 'copy') {
      const text = el.dataset.copy || '';
      try {
        await navigator.clipboard.writeText(text);
        el.textContent = 'Copied';
      } catch {
        el.textContent = 'Select and copy';
      }
      setTimeout(() => (el.textContent = 'Copy'), 1600);
      return;
    }
    if (action === 'reveal') {
      const input = el.parentElement?.querySelector('input');
      if (input) {
        input.type = input.type === 'password' ? 'text' : 'password';
        el.textContent = input.type === 'password' ? 'Show' : 'Hide';
      }
      return;
    }
    if (action === 'open-tool') {
      const tool = el.dataset.tool;
      closeWizard();
      await window.MistApp?.openTool?.(tool);
      return;
    }
    if (action === 'enable') {
      el.disabled = true;
      try {
        const res = await call(`${API}/${encodeURIComponent(wiz.id)}/enabled`, {
          method: 'POST',
          body: JSON.stringify({ enabled: !!el.checked }),
        });
        replaceRow(res.connector);
        drawWizard();
        await refreshCapabilities();
      } catch (err) {
        el.checked = !el.checked;
        alert(err.message);
      } finally {
        el.disabled = false;
      }
    }
  }

  function wireWizard(layer) {
    layer.addEventListener('click', (ev) => {
      const el = ev.target.closest?.('[data-wiz]');
      if (!el || el.dataset.wiz === 'enable') return;
      if (el.getAttribute('aria-disabled') === 'true' && el.dataset.wiz === 'test') {
        wizAction('test', el); // shows every message instead of doing nothing
        return;
      }
      wizAction(el.dataset.wiz, el);
    });
    layer.addEventListener('change', (ev) => {
      const el = ev.target;
      if (el.dataset?.wiz === 'enable') wizAction('enable', el);
    });
    layer.addEventListener('input', (ev) => {
      const el = ev.target;
      if (el.dataset?.wizInput === 'query' && wiz) {
        wiz.query = el.value;
        const [body] = step0();
        const holder = document.createElement('div');
        holder.innerHTML = body;
        layer.querySelector('[data-wiz-results]').innerHTML =
          holder.querySelector('[data-wiz-results]').innerHTML;
        return;
      }
      if (el.closest?.('[data-wiz-form]')) {
        el.dataset.touched = '1';
        if (el.dataset.key === 'verify_tls') {
          layer.querySelector('[data-tls-warning]')?.classList.toggle('hidden', el.checked);
        }
        validateForm(false);
      }
    });
    layer.addEventListener('focusout', (ev) => {
      const el = ev.target;
      if (el.closest?.('[data-wiz-form]') && el.dataset?.key) {
        el.dataset.touched = '1';
        validateForm(false);
      }
    });
    layer.addEventListener('submit', (ev) => ev.preventDefault());
    layer.addEventListener('keydown', (ev) => {
      if (ev.key === 'Escape') closeWizard();
      if (ev.key === 'Enter' && ev.target.matches?.('[data-wiz-form] input:not([type=checkbox])')) {
        ev.preventDefault();
        wizAction('test', ev.target);
      }
    });
  }

  // ---- wiring ------------------------------------------------------------------------------------
  function wire() {
    const root = document.querySelector('#connGroups');
    if (!root || root.dataset.wired) return;
    root.dataset.wired = '1';
    root.addEventListener('click', (ev) => {
      const el = ev.target.closest?.('[data-act]');
      const card = el?.closest('[data-connector]');
      if (el && card && el.dataset.act !== 'enable') cardAction(card.dataset.connector, el.dataset.act, el);
    });
    root.addEventListener('change', (ev) => {
      const el = ev.target;
      const card = el.closest?.('[data-connector]');
      if (el.dataset?.act === 'enable' && card) cardAction(card.dataset.connector, 'enable', el);
    });
    document.querySelector('#connAdd')?.addEventListener('click', async () => {
      if (!catalog) await load();
      openWizard('', 0, 'new');
    });
  }

  function init() {
    wire();
    return load();
  }

  // Settings has its own module (settings.js); load whenever the Settings view is shown.
  function watchSettingsView() {
    const view = document.querySelector('#view-settings');
    if (!view || typeof MutationObserver === 'undefined' || !view.classList) return;
    let wasHidden = view.classList.contains('hidden');
    if (!wasHidden) init();
    new MutationObserver(() => {
      const hidden = view.classList.contains('hidden');
      if (wasHidden && !hidden) init();
      wasHidden = hidden;
    }).observe(view, { attributes: true, attributeFilter: ['class'] });
  }

  window.MistTools = window.MistTools || {};
  window.MistTools.connections = {
    init,
    refresh: load,
    capabilities: () => capabilities,
    /** True when at least one connected source offers ``capability`` (features can hide otherwise). */
    has: (capability) => !!capabilities?.[capability]?.available,
    /** Open the Add-connection wizard, optionally for one connector (e.g. from a "connect X" hint). */
    add: async (connectorId = '') => {
      wire();
      if (!catalog) await load();
      openWizard(connectorId, connectorId ? 1 : 0, 'new');
    },
  };
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', watchSettingsView);
  } else {
    watchSettingsView();
  }
})();
