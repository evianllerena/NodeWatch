window.MistTools = window.MistTools || {};

function settingsEls() {
  return {
    host: document.querySelector('#settingsHost'),
    org: document.querySelector('#settingsOrg'),
    token: document.querySelector('#settingsToken'),
    tls: document.querySelector('#settingsTls'),
    state: document.querySelector('#settingsState'),
    result: document.querySelector('#settingsResult'),
    dataPath: document.querySelector('#settingsDataPath'),
    store: document.querySelector('#settingsCredentialStore'),
  };
}

function slsEls() {
  return {
    state: document.querySelector('#slsState'),
    enabled: document.querySelector('#slsEnabled'),
    result: document.querySelector('#slsResult'),
    queryHost: document.querySelector('#slsQueryHost'),
    tenant: document.querySelector('#slsTenant'),
  };
}

function paEls() {
  return {
    state: document.querySelector('#paDsState'),
    enabled: document.querySelector('#paDsEnabled'),
    clientId: document.querySelector('#paDsClientId'),
    tsgId: document.querySelector('#paDsTsgId'),
    secret: document.querySelector('#paDsSecret'),
    result: document.querySelector('#paDsResult'),
  };
}

async function api(url, options = {}) {
  const r = await fetch(url, { headers: { 'Content-Type': 'application/json' }, ...options });
  let body = {};
  try {
    body = await r.json();
  } catch {}
  if (!r.ok) throw new Error(body.detail || body.message || `HTTP ${r.status}`);
  return body;
}

function payload() {
  const e = settingsEls();
  return {
    api_host: e.host.value.trim(),
    org_id: e.org.value.trim(),
    token: e.token.value.trim(),
    verify_tls: e.tls.checked,
  };
}

function slsPayload(enabled) {
  const e = slsEls();
  const payload = { enabled: !!enabled };
  if (e.queryHost) payload.query_host = e.queryHost.value.trim();
  if (e.tenant) payload.tenant_header = e.tenant.value.trim();
  return payload;
}

function showSlsResult(message, ok = true) {
  const e = slsEls();
  if (!e.result) return;
  e.result.classList.remove('hidden', 'warning', 'success', 'info');
  e.result.classList.add(ok ? 'success' : 'warning');
  e.result.textContent = message;
}

function paPayload() {
  const e = paEls();
  return {
    enabled: !!e.enabled?.checked,
    client_id: e.clientId?.value.trim() || '',
    tsg_id: e.tsgId?.value.trim() || '',
    client_secret: e.secret?.value.trim() || '',
  };
}

function showResult(message, ok = true) {
  const e = settingsEls();
  e.result.classList.remove('hidden', 'warning', 'success', 'info');
  e.result.classList.add(ok ? 'success' : 'warning');
  e.result.textContent = message;
}

function showPaResult(message, ok = true) {
  const e = paEls();
  if (!e.result) return;
  e.result.classList.remove('hidden', 'warning', 'success', 'info');
  e.result.classList.add(ok ? 'success' : 'warning');
  e.result.textContent = message;
}

async function loadIntegrations() {
  const data = await api('/api/integrations');
  const pa = data.palo_alto_device_security || {};
  const e = paEls();
  const sls = data.strata_logging_service || {};
  const se = slsEls();
  if (se.enabled) se.enabled.checked = sls.enabled === true;
  if (se.queryHost && document.activeElement !== se.queryHost) se.queryHost.value = sls.query_host || '';
  if (se.tenant && document.activeElement !== se.tenant) se.tenant.value = sls.tenant_header || '';
  if (se.state)
    se.state.textContent =
      sls.status_label ||
      {
        connected: 'Connected',
        verification_required: 'Verification required',
        configured_disabled: 'Verified · Disabled',
        configuration_invalid: 'Configuration invalid',
        not_configured: 'Not configured',
      }[sls.status] ||
      'Not configured';
  if (e.enabled) e.enabled.checked = pa.enabled === true;
  if (e.state)
    e.state.textContent =
      pa.enabled && pa.configured ? 'Enabled' : pa.configured ? 'Configured' : 'Not configured';
  if (e.clientId) {
    e.clientId.value = '';
    e.clientId.placeholder = pa.client_id_present
      ? 'Client ID stored securely — leave blank to keep it'
      : 'Enter Client ID';
  }
  if (e.tsgId) {
    e.tsgId.value = '';
    e.tsgId.placeholder = pa.tsg_id_present
      ? 'TSG ID stored securely — leave blank to keep it'
      : 'Enter TSG ID';
  }
  if (e.secret) {
    e.secret.value = '';
    e.secret.placeholder = pa.client_secret_present
      ? 'Client Secret stored securely — leave blank to keep it'
      : 'Enter Client Secret';
  }
  return data;
}

async function load() {
  const [data] = await Promise.all([
    api('/api/settings'),
    loadIntegrations().catch((err) => {
      console.warn('Integration status unavailable', err);
      return {};
    }),
  ]);
  const e = settingsEls();
  e.host.value = data.api_host || 'https://api.mist.com';
  e.org.value = data.org_id || '';
  e.token.value = '';
  e.tls.checked = data.verify_tls !== false;
  e.token.placeholder = data.token_present
    ? 'Token already stored securely — leave blank to keep it'
    : 'Enter Mist API token';
  e.state.textContent = data.configured ? 'Configured' : 'Setup required';
  e.dataPath.textContent = data.data_root || '%LOCALAPPDATA%\\NodeWatch';
  e.store.textContent = data.credential_store || 'Windows Credential Manager';
  return data;
}

function confirmTlsBypass() {
  const e = settingsEls();
  if (e.tls.checked) return true;
  return confirm(
    'TLS certificate verification is disabled. This weakens protection of API credentials and network data. Continue only if you intentionally use a trusted interception/testing environment.',
  );
}

async function test() {
  if (!confirmTlsBypass()) return;
  const btn = document.querySelector('#settingsTest');
  btn.disabled = true;
  btn.textContent = 'Testing…';
  try {
    const r = await api('/api/settings/test', { method: 'POST', body: JSON.stringify(payload()) });
    showResult(`Connected to ${r.organization}. ${r.site_count} site(s) visible.`, true);
  } catch (err) {
    showResult(`Connection failed: ${err.message}`, false);
  } finally {
    btn.disabled = false;
    btn.textContent = 'Test Connection';
  }
}

async function save() {
  if (!confirmTlsBypass()) return;
  const btn = document.querySelector('#settingsSave');
  btn.disabled = true;
  btn.textContent = 'Saving…';
  try {
    const r = await api('/api/settings/save', { method: 'POST', body: JSON.stringify(payload()) });
    showResult(`Saved securely. Connected to ${r.organization}.`, true);
    await load();
    await window.MistApp.refreshConnectionStatus(true);
    setTimeout(() => window.MistApp.openTool('dashboard'), 450);
  } catch (err) {
    showResult(`Nothing was saved: ${err.message}`, false);
  } finally {
    btn.disabled = false;
    btn.textContent = 'Save & Connect';
  }
}

async function reset() {
  if (
    !confirm(
      'Reset the Mist connection on this computer? Audit history, diagnostics, and other integrations will remain.',
    )
  )
    return;
  await api('/api/settings/reset', { method: 'POST', body: '{}' });
  await load();
  await window.MistApp.refreshConnectionStatus(false);
  showResult('Mist connection reset. Enter connection details to reconnect.', true);
}

async function testPa() {
  const btn = document.querySelector('#paDsTest');
  if (btn) {
    btn.disabled = true;
    btn.textContent = 'Testing…';
  }
  try {
    const result = await api('/api/integrations/palo-alto-device-security/test', {
      method: 'POST',
      body: JSON.stringify(paPayload()),
    });
    // Only a strict, fresh probe counts: a new OAuth token plus a real device-list read.
    const n = result?.devices_returned;
    if (
      !result?.ok ||
      result?.stage !== 'api' ||
      !Number.isInteger(n) ||
      !Number.isFinite(result?.status_code)
    )
      throw new Error('IoT Security did not confirm a real device-list read (stage: api).');
    const tsg = result.tsg_suffix ? `TSG …${result.tsg_suffix}` : 'the TSG';
    const total = Number.isFinite(result.total) && result.total !== n ? ` (${result.total} in total)` : '';
    showPaResult(
      `Verified: signed in to ${tsg} and read ${n} device(s)${total} from IoT Security (GET ${result.endpoint || '/iot/pub/v1/device/list'} → ${result.status_code}).`,
      true,
    );
  } catch (err) {
    showPaResult(`Not connected — ${err.message}`, false);
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.textContent = 'Test Connection';
    }
  }
}

async function savePa() {
  const btn = document.querySelector('#paDsSave');
  if (btn) {
    btn.disabled = true;
    btn.textContent = 'Saving…';
  }
  try {
    await api('/api/integrations/palo-alto-device-security/save', {
      method: 'POST',
      body: JSON.stringify(paPayload()),
    });
    showPaResult(
      'Integration saved securely. Access tokens will be created and refreshed automatically in memory.',
      true,
    );
    await loadIntegrations();
  } catch (err) {
    showPaResult(err.message, false);
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.textContent = 'Save Integration';
    }
  }
}

async function resetPa() {
  if (
    !confirm(
      'Reset the Device Intelligence integration on this computer?\n\nThe Palo Alto service account is removed from the credential store, unless Traffic & Sessions still uses it; then it is kept and only Device Intelligence is reset.',
    )
  )
    return;
  const btn = document.querySelector('#paDsReset');
  if (btn) btn.disabled = true;
  try {
    const res = await api('/api/integrations/palo-alto-device-security/reset', { method: 'POST', body: '{}' });
    showPaResult(
      res?.credentials_kept
        ? res.note || 'Device Intelligence was reset. The shared Palo Alto service account was kept.'
        : 'Device Intelligence integration reset and its credentials removed.',
      true,
    );
    await loadIntegrations();
  } catch (err) {
    showPaResult(`Reset failed: ${err.message}`, false);
  } finally {
    if (btn) btn.disabled = false;
  }
}

async function openData() {
  const r = await api('/api/settings/open-data-folder', { method: 'POST', body: '{}' });
  if (!r.ok && r.path) showResult(`Data folder: ${r.path}`, true);
}

// Stops the NodeWatch backend (NodeWatchBackend.exe / python.exe) and replaces the
// page with a notice, because nothing else in this tab works afterwards.
async function exitNodeWatch() {
  if (!confirm('Exit NodeWatch? The background process stops; start NodeWatch again from its launcher.'))
    return;
  const btn = document.querySelector('#settingsExitApp');
  if (btn) btn.disabled = true;
  try {
    await api('/api/system/exit', { method: 'POST', body: '{}' });
  } catch (err) {
    if (btn) btn.disabled = false;
    showResult('Exit failed: ' + err.message, false);
    return;
  }
  document.querySelectorAll('dialog[open]').forEach((d) => d.close());
  const box = document.createElement('main');
  box.setAttribute('role', 'status');
  Object.assign(box.style, {
    minHeight: '100vh',
    display: 'flex',
    flexDirection: 'column',
    alignItems: 'center',
    justifyContent: 'center',
    gap: '12px',
    padding: '24px',
    textAlign: 'center',
  });
  const title = document.createElement('h1');
  title.textContent = 'NodeWatch has stopped.';
  const hint = document.createElement('p');
  hint.textContent = /Mac/i.test(navigator.userAgent || '') ? 'Close this window with ⌘W.' : 'Close this window with Alt+F4 or its × button.';
  const close = document.createElement('button');
  close.type = 'button';
  close.className = 'btn primary';
  close.textContent = 'Close window';
  close.addEventListener('click', () => window.close());
  box.append(title, hint, close);
  document.body.replaceChildren(box);
  document.title = 'NodeWatch stopped';
  setTimeout(() => window.close(), 400);
}

async function loadPlatformLock() {
  const state = document.querySelector('#platformLockState');
  if (!state) return;
  try {
    await api('/api/platform-overview/lock');
    state.textContent = 'Owner key enrolled · Overview locked';
  } catch {
    state.textContent = 'Lock status unavailable';
  }
}

async function savePlatformPin() {
  const current = document.querySelector('#platformCurrentPin')?.value || '';
  const pin = document.querySelector('#platformNewPin')?.value || '';
  const confirmPin = document.querySelector('#platformConfirmPin')?.value || '';
  if (!current) {
    showResult('Current owner access key is required to rotate the key.', false);
    return;
  }
  if (!pin || pin.length < 16) {
    showResult('New owner access key must be at least 16 characters.', false);
    return;
  }
  if (pin !== confirmPin) {
    showResult('Owner key confirmation does not match.', false);
    return;
  }
  try {
    await api('/api/platform-overview/lock/configure', {
      method: 'POST',
      body: JSON.stringify({ current_key: current, owner_key: pin }),
    });
    showResult(
      'Owner access key rotated. Keep the new key private; distributed users cannot reset it without the current key.',
      true,
    );
    ['#platformCurrentPin', '#platformNewPin', '#platformConfirmPin'].forEach((q) => {
      const e = document.querySelector(q);
      if (e) e.value = '';
    });
    await loadPlatformLock();
  } catch (err) {
    showResult(`Unable to rotate owner key: ${err.message}`, false);
  }
}

let slsBusy = false;

async function recordSlsUiEvent(event, enabled) {
  try {
    await api('/api/integrations/strata-logging/ui-event', {
      method: 'POST',
      body: JSON.stringify({ event, enabled: !!enabled }),
    });
  } catch (err) {
    console.warn('Unable to record SLS UI diagnostic event', err);
  }
}

function setSlsBusy(busy, buttonLabel = '') {
  slsBusy = !!busy;
  const e = slsEls();
  const verify = document.querySelector('#slsTest');
  const reset = document.querySelector('#slsReset');
  if (e.enabled) e.enabled.disabled = !!busy;
  if (verify) {
    verify.disabled = !!busy;
    if (buttonLabel) verify.textContent = buttonLabel;
    else if (!busy) verify.textContent = 'Verify Again';
  }
  if (reset) reset.disabled = !!busy;
}

async function toggleSls() {
  if (slsBusy) return;
  const e = slsEls();
  if (!e.enabled) return;
  const desired = !!e.enabled.checked;
  void recordSlsUiEvent(desired ? 'SLS_UI_ENABLE_CLICKED' : 'SLS_UI_DISABLE_CLICKED', desired);
  setSlsBusy(true, desired ? 'Verifying…' : 'Updating…');
  try {
    if (desired) {
      if (e.state) e.state.textContent = 'Verifying…';
      showSlsResult(
        'Checking Common Services OAuth and running a real read-only firewall traffic query…',
        true,
      );
      const d = await api('/api/integrations/strata-logging/enable', {
        method: 'POST',
        body: JSON.stringify(slsPayload(true)),
      });
      if (e.state) e.state.textContent = 'Connected';
      e.enabled.checked = true;
      const count =
        d.sample_count !== undefined && d.sample_count !== null ? ` · ${d.sample_count} sample row(s)` : '';
      showSlsResult(`Connected and saved. Traffic & Sessions is enabled${count}.`, true);
    } else {
      if (e.state) e.state.textContent = 'Disabling…';
      await api('/api/integrations/strata-logging/enable', {
        method: 'POST',
        body: JSON.stringify(slsPayload(false)),
      });
      const data = await loadIntegrations();
      const state = data?.strata_logging_service || {};
      if (e.state) e.state.textContent = state.status_label || 'Configured · Disabled';
      showSlsResult(
        'Traffic & Sessions is disabled. Common Services credentials remain stored securely.',
        true,
      );
    }
  } catch (err) {
    if (desired) e.enabled.checked = false;
    const message = err?.message || String(err);
    if (e.state) e.state.textContent = desired ? 'Verification failed' : 'Update failed';
    showSlsResult(
      `${desired ? 'Could not enable Traffic & Sessions' : 'Could not disable Traffic & Sessions'}: ${message}`,
      false,
    );
    try {
      const data = await loadIntegrations();
      const state = data?.strata_logging_service || {};
      if (e.state)
        e.state.textContent = desired ? 'Verification failed' : state.status_label || 'Update failed';
      if (desired) e.enabled.checked = false;
    } catch {}
  } finally {
    setSlsBusy(false);
  }
}

async function testSls() {
  if (slsBusy) return;
  const e = slsEls();
  const enabled = !!e.enabled?.checked;
  void recordSlsUiEvent('SLS_UI_VERIFY_CLICKED', enabled);
  setSlsBusy(true, 'Verifying…');
  try {
    if (e.state) e.state.textContent = 'Verifying…';
    showSlsResult('Testing Common Services OAuth and a real read-only firewall traffic query…', true);
    const endpoint = enabled
      ? '/api/integrations/strata-logging/enable'
      : '/api/integrations/strata-logging/test';
    const d = await api(endpoint, { method: 'POST', body: JSON.stringify(slsPayload(enabled)) });
    const sample =
      d.sample_count !== undefined && d.sample_count !== null ? d.sample_count : d.integration?.sample_count;
    if (e.state) e.state.textContent = enabled ? 'Connected' : 'Verified · Disabled';
    showSlsResult(
      `Verification succeeded${sample !== undefined && sample !== null ? ` · ${sample} sample row(s)` : ''}.${enabled ? ' Traffic & Sessions is enabled and saved.' : ' Turn on the switch to enable Traffic & Sessions.'}`,
      true,
    );
    await loadIntegrations();
  } catch (err) {
    if (e.state) e.state.textContent = 'Verification failed';
    showSlsResult(`Verification failed: ${err.message}`, false);
  } finally {
    setSlsBusy(false);
  }
}

async function resetSls() {
  if (slsBusy) return;
  if (
    !confirm(
      'Reset the Strata Logging Service Traffic & Sessions state? Your shared Common Services credentials will be retained.',
    )
  )
    return;
  void recordSlsUiEvent('SLS_UI_RESET_CLICKED', false);
  setSlsBusy(true, 'Resetting…');
  const e = slsEls();
  try {
    await api('/api/integrations/strata-logging/reset', { method: 'POST', body: '{}' });
    if (e.enabled) e.enabled.checked = false;
    if (e.state) e.state.textContent = 'Ready to verify';
    showSlsResult('Traffic & Sessions state reset. Common Services credentials were retained.', true);
    await loadIntegrations();
  } catch (err) {
    showSlsResult(`Reset failed: ${err.message}`, false);
  } finally {
    setSlsBusy(false);
  }
}

// ------------------------------------------------------------ appearance

const UI_NAMES_KEY = 'nodewatch.showUiNames';

function setUiNames(on) {
  document.documentElement.classList.toggle('show-ui-names', !!on);
  try {
    localStorage.setItem(UI_NAMES_KEY, on ? '1' : '0');
  } catch {
    /* storage unavailable: setting lasts until the page reloads */
  }
}

async function renderThemeChoices() {
  const host = document.querySelector('#themeChoices');
  if (!host) return;
  let catalogue = {};
  try {
    catalogue = (await (await fetch('/static/themes.json')).json()).themes || {};
  } catch {
    catalogue = {};
  }
  const state = window.MistApp?.uiState?.() || {};
  const active = document.documentElement.dataset.theme || state.theme || 'original';
  const themes = state.themes?.length
    ? state.themes
    : Object.entries(catalogue).map(([id, t]) => ({ id, ...t }));
  host.innerHTML = themes
    .map((t) => {
      const p = catalogue[t.id]?.preview || {};
      const vars = Object.entries(p)
        .map(([k, v]) => `--sw-${k}:${/^#[0-9a-f]{6}$/i.test(v) ? v : '#888'}`)
        .join(';');
      // Swatches show colours only: where the menu sits is the separate Page layout choice.
      return (
        `<button type="button" class="theme-choice" role="radio" data-theme-id="${t.id}" aria-checked="${t.id === active}">` +
        `<span class="theme-swatch" data-swatch="${vars}"><span class="sw-side"></span><span class="sw-main">` +
        `<span class="sw-card"><span class="sw-dot"></span><span class="sw-bar"></span><span class="sw-btn"></span></span>` +
        `<span class="sw-card"><span class="sw-bar"></span></span></span></span>` +
        `<strong></strong><small></small></button>`
      );
    })
    .join('');
  // Text and colours are set through the DOM (no inline styles: the CSP forbids them).
  host.querySelectorAll('.theme-choice').forEach((btn) => {
    const t = themes.find((x) => x.id === btn.dataset.themeId);
    btn.querySelector('strong').textContent = t.label;
    btn.querySelector('small').textContent = t.description;
    const sw = btn.querySelector('.theme-swatch');
    sw.dataset.swatch.split(';').forEach((pair) => {
      const [k, v] = pair.split(':');
      if (k) sw.style.setProperty(k, v);
    });
    const dots = sw.querySelectorAll('.sw-dot');
    dots.forEach((d) => d.style.setProperty('background', catalogue[t.id]?.preview?.critical || '#d92d20'));
    btn.addEventListener('click', async () => {
      await window.MistApp.applyTheme(t.id);
      host
        .querySelectorAll('.theme-choice')
        .forEach((b) => b.setAttribute('aria-checked', String(b === btn)));
      const label = document.querySelector('#appearanceState');
      if (label) label.textContent = `${t.label} · saved`;
      syncAppearanceControls();
    });
  });
  const label = document.querySelector('#appearanceState');
  if (label) label.textContent = themes.find((t) => t.id === active)?.label || '';
}

// Night mode control in Settings › Appearance (state lives on <html>, saved by core.js).
function syncAppearanceControls() {
  const root = document.documentElement;
  const pref = root.dataset.nightPref || 'off';
  document
    .querySelectorAll('#nightChoices [data-night]')
    .forEach((b) => b.setAttribute('aria-checked', String(b.dataset.night === pref)));
  const note = document.querySelector('#nightNote');
  if (note) {
    const state = window.MistApp?.uiState?.() || {};
    const theme = (state.themes || []).find((t) => t.id === root.dataset.theme);
    note.textContent =
      root.dataset.mode === 'dark'
        ? `${theme?.label || 'This look'} is always dark, so night mode changes nothing here.`
        : pref === 'system'
          ? `Following Windows: currently ${root.dataset.night === 'on' ? 'night' : 'day'}.`
          : '';
  }
  syncLayoutControls();
}

// ------------------------------------------------------------ page layout (v0.10.15)

const LAYOUT_CARDS = [
  {
    id: 'aurora',
    label: 'Aurora glass',
    description: 'Default. Frosted sidebar on the left, comfortable spacing, centred pages.',
  },
  {
    id: 'dense',
    label: 'Compact NOC',
    description: 'Tighter spacing, smaller cards and more table rows; full width, no glass or shadows.',
  },
  {
    id: 'top',
    label: 'Top navigation',
    description: 'A horizontal menu bar across the top instead of a sidebar.',
  },
  {
    id: 'focus',
    label: 'Focus / wide',
    description: 'Menu folded to an icon rail and pages use the full window width.',
  },
  {
    id: 'custom',
    label: 'Custom',
    description: 'Your own mix: pick menu position, density, width, corners, glass and shadows below.',
  },
];

function renderLayoutChoices() {
  const host = document.querySelector('#layoutChoices');
  if (!host) return;
  host.innerHTML = LAYOUT_CARDS.map(
    (c) =>
      `<button type="button" class="layout-choice" role="radio" aria-checked="false" data-layout-id="${c.id}">` +
      `<span class="layout-thumb lt-${c.id}" aria-hidden="true"><span class="lt-side"><i></i><i></i><i></i><i></i></span>` +
      `<span class="lt-main"><span class="lt-card lt-wide"></span><span class="lt-card"></span><span class="lt-card"></span>` +
      `<span class="lt-card"></span><span class="lt-card"></span><span class="lt-knobs"><i></i><i></i><i></i></span></span></span>` +
      `<strong></strong><small></small></button>`,
  ).join('');
  host.querySelectorAll('.layout-choice').forEach((btn) => {
    const card = LAYOUT_CARDS.find((c) => c.id === btn.dataset.layoutId);
    btn.querySelector('strong').textContent = card.label;
    btn.querySelector('small').textContent = card.description;
    btn.addEventListener('click', async () => {
      if (card.id === 'custom') {
        await window.MistApp.applyLayout({ preset: 'custom' });
        document.querySelector('#layoutCustom .seg-control button')?.focus();
      } else {
        await window.MistApp.applyLayout({ preset: card.id });
      }
      syncLayoutControls();
    });
  });
  // Arrow keys move between the layout cards (radio-group behaviour).
  host.addEventListener('keydown', (e) => {
    if (!['ArrowRight', 'ArrowDown', 'ArrowLeft', 'ArrowUp'].includes(e.key)) return;
    const items = [...host.querySelectorAll('.layout-choice')];
    const i = items.indexOf(document.activeElement);
    if (i < 0) return;
    e.preventDefault();
    const step = e.key === 'ArrowRight' || e.key === 'ArrowDown' ? 1 : -1;
    items[(i + step + items.length) % items.length].focus();
  });
}

// "position" is a view of two saved values: the layout's nav (side / top) and the folded menu.
function layoutControlValue(key, layout) {
  if (key === 'position') {
    if (layout.nav === 'top') return 'top';
    return document.documentElement.classList.contains('menu-hidden') ? 'icons' : 'side';
  }
  return layout[key];
}

function syncLayoutControls() {
  const layout = window.MistApp?.currentLayout?.();
  if (!layout) return;
  document
    .querySelectorAll('#layoutChoices .layout-choice')
    .forEach((b) => b.setAttribute('aria-checked', String(b.dataset.layoutId === layout.preset)));
  document
    .querySelectorAll('[data-lset]')
    .forEach((b) =>
      b.setAttribute('aria-checked', String(layoutControlValue(b.dataset.lset, layout) === b.dataset.value)),
    );
  const state = document.querySelector('#layoutState');
  if (state) state.textContent = LAYOUT_CARDS.find((c) => c.id === layout.preset)?.label || '';
}

function wireLayoutControls() {
  renderLayoutChoices();
  document.querySelectorAll('[data-lset]').forEach((b) =>
    b.addEventListener('click', async () => {
      const key = b.dataset.lset;
      const value = b.dataset.value;
      let changes;
      if (key === 'text') changes = { text: value };
      else if (key === 'position')
        changes =
          value === 'top'
            ? { preset: 'custom', nav: 'top' }
            : { preset: 'custom', nav: 'side', collapsed: value === 'icons' };
      else changes = { preset: 'custom', [key]: value };
      await window.MistApp.applyLayout(changes);
      syncLayoutControls();
    }),
  );
  document.querySelector('#layoutReset')?.addEventListener('click', async () => {
    await window.MistApp.resetLayout();
    syncLayoutControls();
  });
  syncLayoutControls();
}

function wireAppearanceControls() {
  document.querySelectorAll('#nightChoices [data-night]').forEach((b) =>
    b.addEventListener('click', async () => {
      await window.MistApp.setNight(b.dataset.night);
      syncAppearanceControls();
    }),
  );
  wireLayoutControls();
  document.addEventListener('nodewatch:ui-changed', syncAppearanceControls);
  syncAppearanceControls();
}

// Settings › Support: "Keep NodeWatch running when its window is closed" (v0.10.24, default off).
async function wireKeepRunning() {
  const box = document.querySelector('#settingsKeepRunning');
  if (!box || box.dataset.wired) return;
  box.dataset.wired = '1';
  try {
    const state = await api('/api/system/keep-running');
    box.checked = !!state.keep_running;
  } catch {
    box.disabled = true;
    return;
  }
  box.addEventListener('change', async () => {
    const wanted = box.checked;
    box.disabled = true;
    try {
      const state = await api('/api/system/keep-running', {
        method: 'POST',
        body: JSON.stringify({ keep_running: wanted }),
      });
      box.checked = !!state.keep_running;
      showResult(
        wanted
          ? 'NodeWatch will keep running when its window is closed. Use “Exit NodeWatch now” to stop it.'
          : 'NodeWatch will close itself about a minute after its last window is closed.',
        true,
      );
    } catch (err) {
      box.checked = !wanted;
      showResult('Could not save the setting: ' + err.message, false);
    } finally {
      box.disabled = false;
    }
  });
}

// ---- Sections (v0.10.32) -------------------------------------------------------------------------
// Settings & Support was one long page of ten cards. It is now four sections (Connections, Appearance,
// Team, Support & data); Connections opens first with a three-step "get connected" guide. The chosen
// section is a history entry (Back returns to the previous one) and is remembered on this computer.
const SETTINGS_TABS = ['connections', 'appearance', 'team', 'support'];
let settingsTab = 'connections';
function showSettingsTab(tab, { push = true } = {}) {
  if (!SETTINGS_TABS.includes(tab)) tab = 'connections';
  const changed = tab !== settingsTab;
  settingsTab = tab;
  document.querySelectorAll('#view-settings [data-settings-tab]').forEach((el) => {
    if (el.getAttribute('role') === 'tab') {
      el.setAttribute('aria-selected', String(el.dataset.settingsTab === tab));
      el.tabIndex = el.dataset.settingsTab === tab ? 0 : -1;
    } else el.classList.toggle('is-tab-on', el.dataset.settingsTab === tab);
  });
  try {
    localStorage.setItem('nodewatch.settingsTab', tab);
  } catch {
    /* storage unavailable */
  }
  if (push && changed) window.MistApp?.pushView?.(tab === 'connections' ? null : { tab });
}
// A card asked for by name (another page's "Open settings" link): open its section first.
function showSettingsCard(el) {
  const tab = el?.closest?.('[data-settings-tab]')?.dataset.settingsTab;
  if (tab) showSettingsTab(tab);
}
function wireSettingsTabs() {
  const nav = document.querySelector('#view-settings .settings-tabs');
  if (!nav) return;
  nav.addEventListener('click', (e) => {
    const b = e.target.closest('[data-settings-tab]');
    if (b) showSettingsTab(b.dataset.settingsTab);
  });
  nav.addEventListener('keydown', (e) => {
    if (e.key !== 'ArrowRight' && e.key !== 'ArrowLeft') return;
    const i = SETTINGS_TABS.indexOf(settingsTab) + (e.key === 'ArrowRight' ? 1 : -1);
    const next = SETTINGS_TABS[(i + SETTINGS_TABS.length) % SETTINGS_TABS.length];
    showSettingsTab(next);
    nav.querySelector(`[data-settings-tab="${next}"]`)?.focus();
  });
  document.querySelector('#settingsStartAdd')?.addEventListener('click', () => document.querySelector('#connAdd')?.click());
  // On a Mac secrets live in the login keychain, not Windows Credential Manager.
  if (/Mac/i.test(navigator.platform || navigator.userAgent || '')) {
    document.querySelectorAll('#view-settings [data-credstore]').forEach((x) => (x.textContent = 'your macOS keychain'));
  }
  let saved = 'connections';
  try {
    saved = localStorage.getItem('nodewatch.settingsTab') || 'connections';
  } catch {
    /* storage unavailable */
  }
  // Nothing connected yet: always start on Connections.
  const st = window.MistApp?.lastStatus?.();
  if (st && !(st.any_source_configured ?? st.configured)) saved = 'connections';
  settingsTab = '';
  showSettingsTab(saved, { push: false });
  window.MistApp?.pushView?.(saved === 'connections' ? null : { tab: saved }, { replace: true });
}

async function init() {
  wireSettingsTabs();
  // v0.10.40: settings, themes and the platform lock are independent: request them together.
  const lockLoaded = loadPlatformLock();
  await Promise.all([load(), renderThemeChoices()]);
  wireAppearanceControls();
  const namesToggle = document.querySelector('#uiLabelsToggle');
  if (namesToggle) {
    namesToggle.checked = document.documentElement.classList.contains('show-ui-names');
    namesToggle.addEventListener('change', () => setUiNames(namesToggle.checked));
  }
  document.querySelector('#settingsTest')?.addEventListener('click', test);
  document.querySelector('#settingsSave')?.addEventListener('click', save);
  document.querySelector('#settingsReset')?.addEventListener('click', reset);
  document.querySelector('#settingsOpenData')?.addEventListener('click', openData);
  document.querySelector('#paDsTest')?.addEventListener('click', testPa);
  document.querySelector('#paDsSave')?.addEventListener('click', savePa);
  document.querySelector('#paDsReset')?.addEventListener('click', resetPa);
  document.querySelector('#slsEnabled')?.addEventListener('change', toggleSls);
  document.querySelector('#slsTest')?.addEventListener('click', testSls);
  document.querySelector('#slsReset')?.addEventListener('click', resetSls);
  document.querySelector('#settingsExportDiagnostics')?.addEventListener('click', async () => {
    const btn = document.querySelector('#settingsExportDiagnostics');
    if (btn) btn.disabled = true;
    try {
      const r = await fetch('/api/support/diagnostics', { method: 'POST' });
      if (!r.ok) throw new Error((await r.text()) || `HTTP ${r.status}`);
      const blob = await r.blob();
      const disp = r.headers.get('content-disposition') || '';
      const match = disp.match(/filename=\"?([^\";]+)\"?/i);
      const name = match?.[1] || 'NodeWatch-Diagnostics.zip';
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = name;
      document.body.appendChild(a);
      a.click();
      a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch (err) {
      showResult('Diagnostic export failed: ' + err.message, false);
    } finally {
      if (btn) btn.disabled = false;
    }
  });
  document.querySelector('#platformPinSave')?.addEventListener('click', savePlatformPin);
  document.querySelector('#settingsExitApp')?.addEventListener('click', exitNodeWatch);
  wireKeepRunning();
  await lockLoaded;
}

window.MistTools.settings = {
  init,
  refresh: load,
  autoRefresh: async () => {},
  restoreView: async (view) => showSettingsTab(view?.tab || 'connections', { push: false }),
  showTab: showSettingsTab,
  showCard: showSettingsCard,
};
