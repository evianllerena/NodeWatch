// Settings › Team triage (v0.10.18): where acknowledge / snooze / dismiss / mute / notes / assignments are
// kept. The choices and their form fields come from the triage store manifests
// (app/services/triage/backends/*), so a new store appears here without UI changes.
(function () {
  'use strict';

  const API = '/api/dashboard/triage';
  const MODE = {
    ok: ['Synced', 'is-ok'],
    local: ['This PC only', 'is-ready'],
    offline: ['Offline — saving on this PC', 'is-bad'],
    read_only: ['Read-only for you', 'is-warn'],
    error: ['Problem', 'is-bad'],
    unknown: ['Checking…', 'is-ready'],
  };
  let info = null;
  let selected = '';
  let loading = null;
  let statusTimer = null;
  const values = {};

  const esc = nwEscapeHtml; // one shared escaper (core.js)
  const ago = (ts) => {
    if (!ts) return 'never';
    const s = Math.max(0, Math.round(Date.now() / 1000 - ts));
    if (s < 60) return `${s}s ago`;
    if (s < 3600) return `${Math.floor(s / 60)} min ago`;
    if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
    return `${Math.floor(s / 86400)} d ago`;
  };
  const $ = (sel) => document.querySelector(sel);

  const call = (url, options = {}) =>
    nwFetchJSON(url, { ...options, headers: { 'Content-Type': 'application/json', ...(options.headers || {}) } }); // core.js

  const manifest = (id) => (info?.backends || []).find((b) => b.backend_id === id);

  // ---- rendering ---------------------------------------------------------------------------
  function fieldHtml(m, f) {
    const id = `tt-${m.backend_id}-${f.key}`;
    const saved = (info.settings?.[m.backend_id] || {})[f.key];
    const value = values[id] ?? saved ?? f.default ?? '';
    const help = f.help ? `<small class="muted">${esc(f.help)}</small>` : '';
    return `<label for="${id}">${esc(f.label)}<input id="${id}" type="text" data-key="${esc(f.key)}"${f.required ? ' required aria-required="true"' : ''} value="${esc(value)}" placeholder="${esc(f.placeholder || '')}" autocomplete="off" spellcheck="false" maxlength="240">${help}</label>`;
  }

  function choicesHtml() {
    return (info.backends || [])
      .map((m) => {
        const on = m.backend_id === selected;
        const tag = !m.available
          ? '<span class="tt-tag">Coming later</span>'
          : m.maturity === 'preview'
            ? '<span class="tt-tag preview">Preview</span>'
            : '';
        const active = m.backend_id === info.active ? '<span class="tt-tag active">In use</span>' : '';
        return `<button type="button" role="radio" class="tt-choice${on ? ' selected' : ''}" data-tt-backend="${esc(m.backend_id)}" aria-checked="${on}"${m.available ? '' : ' disabled aria-disabled="true"'}><strong>${esc(m.label.replace(/\s*\(coming later\)$/i, ''))}${tag}${active}</strong><small>${esc(m.description)}</small></button>`;
      })
      .join('');
  }

  function statusHtml(st) {
    if (!st) return '';
    const [label, cls] = MODE[st.mode] || MODE.unknown;
    const me = st.me || {};
    const others = (st.users || []).filter(
      (u) => String(u.user).toLowerCase() !== String(me.user).toLowerCase(),
    );
    const people = others.length
      ? others
          .map(
            (u) =>
              `<li><b>${esc(u.display || u.user)}${u.conflict ? ' <span class="tt-tag preview" title="Another user uses the same display name">Same name as another user</span>' : ''}</b><small>${esc(u.user)} · ${esc((u.machines || []).join(', '))} · last active ${esc(ago(u.last_ts))}</small></li>`,
          )
          .join('')
      : `<li class="muted">${st.shared ? 'Nobody else yet.' : 'Not shared — only you.'}</li>`;
    const rows = [
      ['Store', `${st.label || st.backend}${st.location ? ` — ${st.location}` : ''}`],
      ['Last sync', st.shared ? ago(st.last_sync) : 'Not needed (this PC only)'],
      ['Waiting to sync', `${st.pending || 0} action${st.pending === 1 ? '' : 's'}`],
      ['You appear as', `${me.display || me.user} (${me.user} on ${me.machine})`],
      [
        'History',
        `${st.events || 0} events${st.skipped_lines ? ` · ${st.skipped_lines} damaged lines skipped` : ''}${st.rejected ? ` · ${st.rejected} invalid events ignored` : ''}${st.future_events ? ` · ${st.future_events} from a clock ahead of yours (waiting)` : ''}`,
      ],
      [
        'Identity checks',
        !st.shared
          ? 'Not needed (this PC only)'
          : st.owner_check === 'enforced'
            ? `${st.foreign_files ? `${st.foreign_files} file(s) skipped: created by someone other than the user they name` : 'Every log file is owned by the user it names'}${st.unverified_files ? ` · ${st.unverified_files} file(s) whose owner could not be checked` : ''}${st.ignored_writers ? ` · ${st.ignored_writers} writer(s) over the limit ignored` : ''}`
            : `OFF — this share does not keep Windows file owners (for example a NAS "force user" setting), so who wrote each entry cannot be verified${st.ignored_writers ? ` · ${st.ignored_writers} writer(s) over the limit ignored` : ''}`,
      ],
    ]
      .map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(v)}</dd>`)
      .join('');
    const problem = st.last_error || st.config_error;
    return `<div class="tt-status" data-ui="Settings &amp; Support › Team triage › Sync status">
      <div class="tt-status-head"><h4>Sync status</h4><span class="tt-mode ${cls}">${esc(label)}</span></div>
      ${problem ? `<div class="notice ${st.mode === 'offline' ? 'info' : 'warning'}">${esc(problem)}</div>` : ''}
      ${st.mode === 'read_only' ? '<div class="notice warning">You can read the shared folder but not write to it: you see your team’s triage, but your own acknowledgements, snoozes, notes and assignments are refused. Ask for Modify permission on the folder, or choose Only this PC.</div>' : ''}
      <dl class="settings-info tt-info">${rows}</dl>
      <h5>Teammates seen <small class="muted">${others.length}</small></h5><ul class="tt-people">${people}</ul>
      <div class="editor-actions left"><button type="button" id="ttSync" class="btn secondary">Sync now</button><a id="ttExport" class="btn ghost" href="${API}/export" download>Export history (JSON)</a></div>
    </div>`;
  }

  function render() {
    const host = $('#ttBody');
    if (!host || !info) return;
    const m = manifest(selected) || manifest(info.active);
    if (!m) return;
    const switching = selected !== info.active;
    const activeLabel = manifest(info.active)?.label || info.active;
    const st = info.status || {};
    const state = $('#ttState');
    if (state)
      state.textContent =
        activeLabel + (st.shared && st.mode ? ` · ${(MODE[st.mode] || MODE.unknown)[0]}` : '');
    host.innerHTML = `
      <div class="tt-choices" role="radiogroup" aria-label="Where triage is kept">${choicesHtml()}</div>
      <div class="settings-form tt-form">
        ${(m.settings || []).map((f) => fieldHtml(m, f)).join('')}
        <label for="ttDisplay">Your name shown to teammates<input id="ttDisplay" type="text" maxlength="80" autocomplete="off" value="${esc(values.ttDisplay ?? info.display_name ?? '')}" placeholder="${esc(info.me?.user || '')}"><small class="muted">Optional. Otherwise your Windows user name (${esc(info.me?.user || '')}) is shown.</small></label>
      </div>
      ${switching ? `<label class="check-row tt-copy"><input id="ttCopy" type="checkbox" checked> Copy this PC’s current triage into “${esc(m.label)}” (acknowledgements, snoozes, dismissals, mutes, assignments and notes from the last 30 days)</label>` : ''}
      ${m.shared ? '<div class="notice info tt-privacy">The shared folder holds plain JSON files. Anyone who can open the share can read who acknowledged, snoozed, dismissed, muted, assigned or commented on which alert, and when. No passwords or API tokens are ever written there. Each PC writes only its own file, so no locking is needed and it keeps working while the share is offline.</div><div class="notice warning tt-privacy"><strong>Who did what is only as trustworthy as the share.</strong> NodeWatch reads a log file only when its Windows owner is the user its name claims, and flags look-alike display names. Shares that map every user to one account (for example a NAS “force user” setting) defeat this check, and administrators of the share can still forge entries. Recommended folder permissions: your NOC group <em>Modify</em> on this folder only (“This folder only”), <em>CREATOR OWNER</em> Full control on subfolders and files, no other write access, and no “force user” mapping.</div>' : ''}
      <div id="ttResult" class="notice info hidden" role="status"></div>
      <div class="editor-actions">${m.shared ? '<button type="button" id="ttTest" class="btn secondary">Test folder</button>' : ''}<button type="button" id="ttSave" class="btn primary">${switching ? `Use ${esc(m.label)}` : 'Save'}</button></div>
      ${statusHtml(st)}`;
  }

  function result(text, kind = 'info') {
    const el = $('#ttResult');
    if (!el) return;
    el.className = `notice ${kind}`;
    el.textContent = text;
  }

  function formSettings() {
    const out = {};
    document.querySelectorAll('#ttBody .tt-form input[data-key]').forEach((i) => {
      out[i.dataset.key] = i.value.trim();
    });
    return out;
  }

  // ---- actions -----------------------------------------------------------------------------
  async function test() {
    result('Testing — writing and reading back a small test file…');
    try {
      const r = await call(`${API}/store/test`, {
        method: 'POST',
        body: JSON.stringify({ backend: selected, settings: formSettings() }),
      });
      result(r.message || (r.ok ? 'OK' : 'Failed'), r.ok ? (r.read_only ? 'warning' : 'success') : 'error');
    } catch (err) {
      result(err.message, 'error');
    }
  }

  async function save() {
    const btn = $('#ttSave');
    if (btn) btn.disabled = true;
    result('Saving…');
    try {
      const r = await call(`${API}/store`, {
        method: 'POST',
        body: JSON.stringify({
          backend: selected,
          settings: formSettings(),
          display_name: $('#ttDisplay')?.value || '',
          copy_local: Boolean($('#ttCopy')?.checked),
        }),
      });
      info = r;
      selected = r.active;
      Object.keys(values).forEach((k) => delete values[k]);
      render();
      result(
        `Saved. Triage is now kept in “${manifest(r.active)?.label || r.active}”.${r.copied ? ` Copied ${r.copied} item${r.copied === 1 ? '' : 's'} from before.` : ''}`,
        'success',
      );
      window.MistTools?.dashboard?.refresh?.(false, true)?.catch?.(() => {});
    } catch (err) {
      result(err.message, 'error');
      if (btn) btn.disabled = false;
    }
  }

  async function syncNow() {
    try {
      info.status = await call(`${API}/sync`, { method: 'POST' });
      render();
    } catch (err) {
      result(err.message, 'error');
    }
  }

  async function refreshStatus() {
    const view = $('#view-settings');
    if (!info || !view || view.classList.contains('hidden') || document.visibilityState !== 'visible') return;
    if (document.activeElement?.closest?.('#ttBody .tt-form')) return; // do not re-render while typing
    try {
      info.status = await call(`${API}/status`);
      render();
    } catch {}
  }

  function wire() {
    const host = $('#ttBody');
    if (!host || host.dataset.wired) return;
    host.dataset.wired = '1';
    host.addEventListener('click', (ev) => {
      const choice = ev.target.closest('[data-tt-backend]');
      if (choice && !choice.disabled) {
        document.querySelectorAll('#ttBody input[id]').forEach((i) => {
          values[i.id] = i.value;
        });
        selected = choice.dataset.ttBackend;
        render();
        $(`#ttBody [data-tt-backend="${selected}"]`)?.focus();
        return;
      }
      if (ev.target.closest('#ttTest')) test();
      else if (ev.target.closest('#ttSave')) save();
      else if (ev.target.closest('#ttSync')) syncNow();
    });
    host.addEventListener('keydown', (ev) => {
      const choice = ev.target.closest?.('[data-tt-backend]');
      if (!choice || !['ArrowLeft', 'ArrowRight', 'ArrowUp', 'ArrowDown'].includes(ev.key)) return;
      ev.preventDefault();
      const all = [...host.querySelectorAll('[data-tt-backend]:not([disabled])')];
      const at = all.indexOf(choice);
      const next =
        all[(at + (ev.key === 'ArrowLeft' || ev.key === 'ArrowUp' ? -1 : 1) + all.length) % all.length];
      next?.click();
    });
  }

  function load() {
    if (loading) return loading;
    loading = call(`${API}/store`)
      .then((d) => {
        info = d;
        if (!selected || !manifest(selected)) selected = d.active;
        render();
      })
      .catch((err) => {
        const host = $('#ttBody');
        if (host)
          host.innerHTML = `<div class="notice error">Could not load team triage settings: ${esc(err.message)}</div>`;
      })
      .finally(() => {
        loading = null;
      });
    return loading;
  }

  function init() {
    wire();
    if (!statusTimer) statusTimer = setInterval(refreshStatus, 15000);
    return load();
  }

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
  window.MistTools.teamTriage = { init, refresh: load };
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', watchSettingsView);
  else watchSettingsView();
})();
