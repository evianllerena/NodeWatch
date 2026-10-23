window.MistTools = window.MistTools || {};

window.MistTools.alerting = (() => {
  let config = null;
  let feed = null;
  let browserActive = new Map(); // alert id → source id
  const primedSources = new Set();
  let pollTimer = null;
  let primed = false;
  const esc = nwEscapeHtml; // one shared escaper (core.js)

  const getJSON = (url) => nwFetchJSON(url); // shared helper (core.js)
  const postJSON = (url, body = {}) => nwFetchJSON(url, { method: 'POST', body: JSON.stringify(body) });
  function fmtMac(v = '') {
    const raw = String(v)
      .replace(/[^0-9a-f]/gi, '')
      .toLowerCase();
    return raw.length === 12 ? raw.match(/.{2}/g).join(':') : String(v || '');
  }
  function fmtTime(v) {
    if (!v) return '';
    let n = Number(v);
    if (Number.isFinite(n)) {
      if (n < 1e11) n *= 1000;
      const d = new Date(n);
      return Number.isNaN(d.getTime()) ? '' : d.toLocaleString();
    }
    const d = new Date(v);
    return Number.isNaN(d.getTime()) ? String(v) : d.toLocaleString();
  }

  function renderFeed() {
    const alerts = feed?.alerts || [];
    const count = document.querySelector('#alertingCount');
    if (count) count.textContent = `${alerts.length} visible`;
    const host = document.querySelector('#alertingFeed');
    if (!host) return;
    host.innerHTML = alerts.length
      ? alerts
          .map(
            (a) =>
              `<article class="alert-feed-row ${esc(a.severity || 'warning')}"><div class="alert-feed-icon">${a.severity === 'critical' ? '!' : '△'}</div><div><div class="alert-feed-title"><strong>${esc(a.title)}</strong><span class="severity-badge ${esc(a.severity || 'warning')}">${esc(a.severity || 'warning')}</span></div><p>${esc(a.message)}</p><small>${esc(a.site || '')} ${a.device ? `· ${esc(a.device)}` : ''} ${a.mac ? `· ${esc(fmtMac(a.mac))}` : ''} ${a.timestamp ? `· ${esc(fmtTime(a.timestamp))}` : ''} ${a.source_label ? `· ${esc(a.source_label)}` : ''}</small></div></article>`,
          )
          .join('')
      : '<div class="noc-empty">No disconnect alerts are currently visible.</div>';
    const sent = document.querySelector('#alertingSent');
    if (sent) {
      const n = config?.status?.notifications_sent || 0;
      sent.textContent = n ? `${n} webhook alert${n === 1 ? '' : 's'} sent` : 'No webhook alerts sent yet';
    }
    const suppressed = document.querySelector('#alertingSuppressed');
    if (suppressed) suppressed.textContent = String(feed?.suppressed_transient || 0);
  }

  function browserState() {
    const el = document.querySelector('#alertingBrowserState');
    const btn = document.querySelector('#alertingBrowser');
    if (!el || !btn) return;
    if (!('Notification' in window)) {
      el.textContent = 'Browser notifications unavailable';
      btn.disabled = true;
      return;
    }
    const enabled = localStorage.getItem('mntBrowserAlerts') === '1' && Notification.permission === 'granted';
    el.textContent = enabled
      ? 'Browser alerts enabled'
      : Notification.permission === 'denied'
        ? 'Browser notifications blocked by browser'
        : 'Browser alerts not enabled';
    btn.textContent = enabled ? 'Disable Browser Alerts' : 'Enable Browser Alerts';
  }

  // v0.10.24: alerts come from several sources. A source whose read failed this poll keeps its
  // previous alerts "active" (they did not resolve, they were just not read), and every source gets its
  // own baseline the first time it is seen, so neither a failed poll nor a newly added connector
  // re-fires notifications for alerts that were already open. Incomplete Mist data keeps everything.
  function maybeNotify(alerts = [], meta = feed || {}) {
    if ((meta.errors || []).length) return;
    const sourceOf = (a) => a?.source || 'mist';
    const current = new Map((alerts || []).filter((a) => a?.id).map((a) => [a.id, a]));
    const failed = new Set(meta.failed_sources || []);
    const next = new Map([...current].map(([id, a]) => [id, sourceOf(a)]));
    for (const [id, src] of browserActive) {
      if (!next.has(id) && (failed.has(src) || (failed.has('*') && src !== 'mist'))) next.set(id, src);
    }
    const enabled =
      localStorage.getItem('mntBrowserAlerts') === '1' &&
      'Notification' in window &&
      Notification.permission === 'granted';
    for (const [id, a] of current) {
      if (browserActive.has(id)) continue;
      if (!primed || !primedSources.has(sourceOf(a))) continue; // first sight of this source: baseline
      if (enabled) {
        try {
          new Notification(`${a.severity === 'critical' ? 'Critical: ' : ''}${a.title}`, {
            body: a.message,
            tag: `mnt-${id}`,
            renotify: false,
          });
        } catch (e) {
          console.warn('Notification failed', e);
        }
      }
    }
    (meta.polled_sources || []).forEach((src) => failed.has(src) || primedSources.add(src));
    current.forEach((a) => primedSources.add(sourceOf(a)));
    primed = true;
    // A recovered episode drops out of this set. If it genuinely disconnects later,
    // it becomes new again and may notify once more.
    browserActive = next;
  }

  async function refresh(force = false, silent = false) {
    const btn = document.querySelector('#alertingRefresh');
    if (btn && !silent) {
      btn.disabled = true;
      btn.textContent = 'Refreshing...';
    }
    try {
      feed = await getJSON(`/api/v1/alerting/feed${force ? '?refresh=true' : ''}`);
      maybeNotify(feed.notification_alerts || feed.alerts || []);
      renderFeed();
      const state = document.querySelector('#alertingState');
      if (state)
        state.textContent = (feed.clusters || []).length
          ? 'Possible outage detected'
          : (feed.active_down || []).length
            ? `${feed.active_down.length} down`
            : 'Monitoring';
    } finally {
      if (btn && !silent) {
        btn.disabled = false;
        btn.textContent = 'Refresh Now';
      }
    }
  }

  async function loadConfig() {
    config = await getJSON('/api/v1/alerting/config');
    const set = (id, v) => {
      const e = document.querySelector(id);
      if (e) e.value = String(v ?? '');
    };
    const check = (id, v) => {
      const e = document.querySelector(id);
      if (e) e.checked = Boolean(v);
    };
    check('#alertingEnabled', config.enabled);
    set('#alertingPoll', config.poll_seconds);
    set('#alertingMinDevices', config.outage_min_devices);
    set('#alertingPercent', config.outage_percent);
    set('#alertingCooldown', config.cooldown_seconds);
    check('#alertingAp', config.notify_ap);
    check('#alertingSwitch', config.notify_switch);
    check('#alertingGateway', config.notify_gateway);
    check('#alertingIsolatedAp', config.notify_isolated_ap);
    check('#alertingRequireActive', config.require_active_confirmation);
    set('#alertingGrace', config.disconnect_grace_seconds || 120);
    check('#alertingWebhookEnabled', config.webhook_enabled);
    set('#alertingWebhookFormat', config.webhook_format || 'generic');
    const url = document.querySelector('#alertingWebhookUrl');
    if (url)
      url.placeholder = config.webhook_present ? 'Saved securely — leave blank to keep' : 'https://...';
    const msg = document.querySelector('#alertingMessage');
    if (msg) {
      const st = config.status || {};
      msg.textContent = st.last_error
        ? `Last error: ${st.last_error}`
        : st.last_notification
          ? `Last external notification: ${new Date(st.last_notification).toLocaleString()}`
          : 'No external notifications sent yet.';
    }
    browserState();
    renderFeed();
  }

  async function save() {
    const btn = document.querySelector('#alertingSave');
    const msg = document.querySelector('#alertingMessage');
    if (btn) btn.disabled = true;
    try {
      config = await postJSON('/api/v1/alerting/config', {
        enabled: document.querySelector('#alertingEnabled')?.checked,
        poll_seconds: Number(document.querySelector('#alertingPoll')?.value || 60),
        outage_min_devices: Number(document.querySelector('#alertingMinDevices')?.value || 3),
        outage_percent: Number(document.querySelector('#alertingPercent')?.value || 25),
        cooldown_seconds: Number(document.querySelector('#alertingCooldown')?.value || 1800),
        notify_ap: document.querySelector('#alertingAp')?.checked,
        notify_switch: document.querySelector('#alertingSwitch')?.checked,
        notify_gateway: document.querySelector('#alertingGateway')?.checked,
        notify_isolated_ap: document.querySelector('#alertingIsolatedAp')?.checked,
        require_active_confirmation: document.querySelector('#alertingRequireActive')?.checked,
        disconnect_grace_seconds: Number(document.querySelector('#alertingGrace')?.value || 120),
        webhook_enabled: document.querySelector('#alertingWebhookEnabled')?.checked,
        webhook_format: document.querySelector('#alertingWebhookFormat')?.value || 'generic',
        webhook_url: document.querySelector('#alertingWebhookUrl')?.value || '',
      });
      if (document.querySelector('#alertingWebhookUrl'))
        document.querySelector('#alertingWebhookUrl').value = '';
      if (msg) msg.textContent = 'Alerting settings saved.';
      await loadConfig();
      await refresh(true, true);
    } catch (e) {
      if (msg) msg.textContent = `Save failed: ${e.message}`;
    } finally {
      if (btn) btn.disabled = false;
    }
  }

  async function testWebhook() {
    const btn = document.querySelector('#alertingTest'),
      msg = document.querySelector('#alertingMessage');
    if (btn) btn.disabled = true;
    try {
      await postJSON('/api/v1/alerting/test', {});
      if (msg) msg.textContent = 'Test alert sent.';
      await loadConfig();
    } catch (e) {
      if (msg) msg.textContent = `Test failed: ${e.message}`;
    } finally {
      if (btn) btn.disabled = false;
    }
  }

  async function toggleBrowser() {
    if (!('Notification' in window)) return;
    const active = localStorage.getItem('mntBrowserAlerts') === '1' && Notification.permission === 'granted';
    if (active) {
      localStorage.removeItem('mntBrowserAlerts');
      browserState();
      return;
    }
    const result = await Notification.requestPermission();
    if (result === 'granted') {
      localStorage.setItem('mntBrowserAlerts', '1');
      browserActive = new Map(
        (feed?.notification_alerts || feed?.alerts || []).filter((a) => a?.id).map((a) => [a.id, a.source || 'mist']),
      );
      (feed?.notification_alerts || feed?.alerts || []).forEach((a) => primedSources.add(a.source || 'mist'));
      (feed?.polled_sources || []).forEach((src) => primedSources.add(src));
      primed = true;
    }
    browserState();
  }

  // Part of Command Center since v0.10.11: dashboard.js calls init() once and refresh(true) on Refresh NOC.
  async function init() {
    await Promise.all([loadConfig(), refresh(false, true)]);
    document.querySelector('#alertingSave')?.addEventListener('click', save);
    document.querySelector('#alertingTest')?.addEventListener('click', testWebhook);
    document.querySelector('#alertingBrowser')?.addEventListener('click', toggleBrowser);
    if (!pollTimer)
      pollTimer = setInterval(() => {
        // v0.10.23: a hidden window polls only when browser notifications are switched on (they are
        // the reason to keep polling while NodeWatch is minimised); otherwise it used to poll every
        // 20 s forever. The backend monitor keeps checking (and sending webhooks) regardless.
        let notifying = false;
        try {
          notifying =
            localStorage.getItem('mntBrowserAlerts') === '1' &&
            typeof Notification !== 'undefined' &&
            Notification.permission === 'granted';
        } catch {
          notifying = false;
        }
        if (!notifying) {
          // v0.10.40: without browser notifications the feed is only worth reading while it is on screen
          // (the Command Center); it used to be re-read and redrawn every 20 s on every page.
          const view = document.querySelector('#view-dashboard');
          if (document.visibilityState !== 'visible' || !view || view.classList.contains('hidden')) return;
        }
        refresh(false, true).catch((e) => console.warn('Alerting poll failed', e));
      }, 20000);
  }
  return { init, refresh, autoRefresh: () => refresh(false, true) };
})();
