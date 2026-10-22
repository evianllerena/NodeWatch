let sites = [];
let vcs = [];
let inventory = [];
let selectedVC = null;
let originalMembers = [];
let workingMembers = [];
let dialogMode = null;
let dialogIndex = null;
let draggedIndex = null;
let previewValid = false;
let previewHasWarnings = false;
let vcLoadSeq = 0;
let vcDetailSeq = 0;
let overview = null;
let overviewSeq = 0;
let overviewFilter = '';
let healthSeq = 0;
let healthTarget = null; // { site_id, device_id }
let pendingDrill = null; // device_id to open once the drilled-to site's chassis list loads

const $ = (s) => document.querySelector(s);
const esc = (s) =>
  String(s ?? '').replace(
    /[&<>'"]/g,
    (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' })[c],
  );
const normalizeMac = (m) =>
  String(m || '')
    .toLowerCase()
    .replace(/[^0-9a-f]/g, '');
const roleLabel = (r) =>
  ({ master: 'Master', backup: 'Backup', linecard: 'Linecard', 'routing-engine': 'Routing Engine' })[r] || r;

async function vcJSON(url, opts) {
  const r = await fetch(url, opts || { cache: 'no-store' });
  if (!r.ok) {
    let t = await r.text();
    try {
      const j = JSON.parse(t);
      t = j.detail || t;
    } catch {}
    throw new Error(typeof t === 'string' ? t : JSON.stringify(t));
  }
  return r.json();
}

async function initVC() {
  // v0.10.40: the all-sites overview (the slow read) starts together with the site list.
  const overview = loadOverview(false);
  sites = await vcJSON('/api/v1/sites');
  inventory = [];
  $('#siteSelect').innerHTML =
    '<option value="">Select a site</option>' +
    sites.map((s) => `<option value="${esc(s.id)}">${esc(s.name)}</option>`).join('');
  $('#siteSelect').addEventListener('change', async () => {
    selectedVC = null;
    originalMembers = [];
    workingMembers = [];
    $('#editorSection').classList.add('hidden');
    hideHealth();
    const siteId = $('#siteSelect').value;
    overviewFilter = '';
    loadOverview(false);
    if (!siteId) {
      vcs = [];
      inventory = [];
      $('#vcCount').textContent = 'Select a site';
      $('#vcGrid').innerHTML =
        '<div class="noc-empty">Select a site to discover its Virtual Chassis devices.</div>';
      return;
    }
    // Site selection only discovers VC summaries. Standalone inventory is needed
    // only for Add/Replace and is loaded lazily after Manage VC opens.
    inventory = [];
    await loadVCs(false);
  });
  $('#refreshBtn').addEventListener('click', async () => {
    const siteId = $('#siteSelect').value;
    const jobs = [loadOverview(true)];
    if (healthTarget) jobs.push(loadHealth(healthTarget.site_id, healthTarget.device_id, true));
    if (siteId) {
      inventory = [];
      jobs.push(loadVCs(true));
    }
    await Promise.all(jobs);
  });
  $('#vcHealthRefresh')?.addEventListener('click', () => {
    if (healthTarget) loadHealth(healthTarget.site_id, healthTarget.device_id, true);
  });
  $('#vcOverviewTiles')?.addEventListener('click', (e) => {
    const tile = e.target.closest('[data-vc-filter]');
    if (!tile) return;
    overviewFilter = overviewFilter === tile.dataset.vcFilter ? '' : tile.dataset.vcFilter;
    renderOverview();
  });
  const rows = $('#vcOverviewRows');
  rows?.addEventListener('click', (e) => {
    const tr = e.target.closest('tr[data-vc-row]');
    if (tr) drillTo(Number(tr.dataset.vcRow));
  });
  rows?.addEventListener('keydown', (e) => {
    const tr = e.target.closest('tr[data-vc-row]');
    if (tr && (e.key === 'Enter' || e.key === ' ')) {
      e.preventDefault();
      drillTo(Number(tr.dataset.vcRow));
    }
  });
  $('#closeEditor').addEventListener('click', () => $('#editorSection').classList.add('hidden'));
  $('#resetBtn').addEventListener('click', resetWorking);
  $('#previewBtn').addEventListener('click', openPreview);
  $('#addMemberBtn').addEventListener('click', () => openMemberDialog('add'));
  $('#memberForm').addEventListener('submit', saveMemberDialog);
  // Cancel / × only close the dialog. (v0.10.12: they used to be submit buttons, so a browser that
  // did not report which button was pressed treated Cancel as Save and added the pre-selected switch.)
  ['#memberDialogClose', '#memberDialogCancel'].forEach((sel) =>
    $(sel)?.addEventListener('click', () => $('#memberDialog').close()),
  );
  $('#previewBack')?.addEventListener('click', () => $('#previewDialog').close());
  $('#applyBtn').addEventListener('click', applyChanges);
  $('#applyConfirm')?.addEventListener('change', updateApplyState);
  $('#vcCount').textContent = 'Select a site';
  $('#vcGrid').innerHTML =
    '<div class="noc-empty">Select a site to discover its Virtual Chassis devices.</div>';
  await overview;
}

async function loadVCs(force = false, silent = false) {
  const siteId = $('#siteSelect').value;
  if (!siteId) {
    return;
  }
  const requestSeq = ++vcLoadSeq;
  const qs = `site_id=${encodeURIComponent(siteId)}${force ? '&refresh=true' : ''}`;
  if (!silent) $('#vcCount').textContent = 'Discovering chassis...';
  try {
    const returned = await vcJSON(`/api/v1/virtual-chassis?${qs}`);
    if (requestSeq !== vcLoadSeq) return; // Ignore an older response after the user changed sites.
    const leaked = returned.filter((vc) => String(vc.site_id || '') !== String(siteId));
    if (leaked.length)
      console.warn('Backend returned chassis outside selected site; suppressed in UI', leaked);
    vcs = returned.filter((vc) => String(vc.site_id || '') === String(siteId));
    $('#vcCount').textContent =
      `${vcs.length} chassis found${vcs.some((v) => v && v.sample) ? ' · SAMPLE DATA (Mist not connected)' : ''}`;
    $('#vcGrid').innerHTML = vcs.length
      ? vcs
          .map(
            (vc, i) => `
      <article class="vc-card">
        <div class="eyebrow" title="${esc(vc.model)} · ${esc(siteName(vc.site_id))}">${esc(vc.model)} · ${esc(siteName(vc.site_id))}</div>
        <h3 title="${esc(vc.name)}">${esc(vc.name)}</h3>
        <div class="sub">${esc(vc.status)} · ${vc.preprovisioned ? 'Preprovisioned' : 'Not preprovisioned'}</div>
        <div class="stats">
          <div class="stat"><b>${vc.member_count ?? vc.members.length}</b><span>Members</span></div>
          <div class="stat"><b>${esc(vc.members.find((m) => m.vc_role === 'master') ? 'Master' : 'Open to view')}</b><span>Routing Engine</span></div>
        </div>
        <div class="identity ${vc.identity_mode.includes('Legacy') ? 'warn' : 'ok'}">${esc(vc.identity_mode)}</div>
        <div class="vc-card-health" data-vc-health="${esc(vc.device_id)}"></div>
        <button class="btn primary" data-manage-vc="${i}">Manage VC</button>
      </article>`,
          )
          .join('')
      : '<div class="noc-empty">No Virtual Chassis devices were found for this selection. Refresh after confirming the switches are assigned to this org/site.</div>';
    $('#vcGrid')
      .querySelectorAll('[data-manage-vc]')
      .forEach((btn) => {
        btn.addEventListener('click', () => manageVC(Number(btn.dataset.manageVc)));
      });
    decorateCards();
    if (pendingDrill) {
      const target = pendingDrill;
      pendingDrill = null;
      const idx = vcs.findIndex((v) => String(v.device_id) === String(target));
      if (idx >= 0) manageVC(idx);
      else loadHealth(siteId, target);
    }
  } catch (e) {
    if (requestSeq !== vcLoadSeq) return;
    $('#vcCount').textContent = 'Discovery failed';
    $('#vcGrid').innerHTML =
      `<div class="source-banner error"><strong>Virtual Chassis discovery failed</strong>${esc(e.message)}</div>`;
  }
}

function siteName(id) {
  return sites.find((x) => x.id === id)?.name || id || 'Unknown site';
}

async function manageVC(i) {
  const summary = vcs[i];
  if (!summary) return;
  const requestSeq = ++vcDetailSeq;
  selectedVC = summary;
  previewValid = false;
  $('#editorTitle').textContent = summary.name;
  $('#editorMeta').innerHTML = [
    siteName(summary.site_id),
    summary.model,
    `${summary.members.length} members`,
    summary.identity_mode,
    summary.status,
  ]
    .map((x) => `<span class="chip">${esc(x)}</span>`)
    .join('');
  $('#editorSection').classList.remove('hidden');
  $('#memberRows').innerHTML =
    '<tr><td colspan="5"><div class="noc-empty">Loading live VC member details from Mist…</div></td></tr>';
  loadHealth(summary.site_id, summary.device_id);
  $('#vcHealthSection').scrollIntoView({ behavior: 'smooth', block: 'start' });
  try {
    const detail = await vcJSON(
      `/api/v1/virtual-chassis/detail?site_id=${encodeURIComponent(summary.site_id)}&device_id=${encodeURIComponent(summary.device_id)}`,
    );
    if (requestSeq !== vcDetailSeq || $('#siteSelect').value !== summary.site_id) return;
    selectedVC = detail;
    vcs[i] = detail;
  } catch (e) {
    if (requestSeq !== vcDetailSeq) return;
    console.warn('Live VC detail enrichment failed; using discovery summary', e);
    selectedVC = summary;
  }
  originalMembers = structuredClone(selectedVC.members).sort((a, b) => a.member_id - b.member_id);
  workingMembers = structuredClone(originalMembers);
  const meta = [
    siteName(selectedVC.site_id),
    selectedVC.model,
    `${selectedVC.members.length} members`,
    selectedVC.identity_mode,
    selectedVC.status,
  ];
  if (selectedVC.version) meta.push(`VC firmware ${selectedVC.version}`);
  $('#editorMeta').innerHTML = meta.map((x) => `<span class="chip">${esc(x)}</span>`).join('');
  renderMembers();
  // Do not make opening the editor wait on the standalone-switch inventory.
  // Prime it in the background for Add/Replace actions.
  vcJSON(`/api/v1/inventory?site_id=${encodeURIComponent(selectedVC.site_id)}`)
    .then((rows) => {
      if (selectedVC && selectedVC.site_id === summary.site_id) inventory = rows;
    })
    .catch((e) => console.warn('Site inventory preload failed', e));
}

function renderMembers() {
  workingMembers.forEach((m, i) => (m.member_id = i));
  $('#memberRows').innerHTML = workingMembers
    .map(
      (m, i) => `
    <tr draggable="true" data-index="${i}">
      <td><span class="order-badge"><span class="grip">☰</span><strong>${i}</strong></span></td>
      <td><code>${esc(m.mac)}</code>${m.connected === false ? '<span class="mini-state bad-text">offline</span>' : ''}</td>
      <td><strong>${esc(m.serial || 'Not reported')}</strong><small class="cell-sub">${m.version ? `${esc(m.version)}${m.version_scope === 'vc' ? ' · VC firmware' : ''}` : 'Firmware not reported by Mist'}</small></td>
      <td><select class="role-select" data-role-index="${i}">${['master', 'backup', 'linecard', ...(m.vc_role === 'routing-engine' ? ['routing-engine'] : [])].map((r) => `<option value="${r}" ${m.vc_role === r ? 'selected' : ''}>${roleLabel(r)}</option>`).join('')}</select></td>
      <td><div class="row-actions"><button class="mini" data-replace-index="${i}">Replace</button><button class="mini remove" data-remove-index="${i}">Remove</button></div></td>
    </tr>`,
    )
    .join('');
  document.querySelectorAll('#memberRows tr').forEach((row) => {
    row.addEventListener('dragstart', () => {
      draggedIndex = +row.dataset.index;
      row.classList.add('dragging');
    });
    row.addEventListener('dragend', () => row.classList.remove('dragging'));
    row.addEventListener('dragover', (e) => e.preventDefault());
    row.addEventListener('drop', (e) => {
      e.preventDefault();
      const target = +row.dataset.index;
      if (draggedIndex === null || target === draggedIndex) return;
      const [m] = workingMembers.splice(draggedIndex, 1);
      workingMembers.splice(target, 0, m);
      draggedIndex = null;
      invalidatePreview();
      renderMembers();
    });
  });
  document.querySelectorAll('#memberRows [data-role-index]').forEach((select) => {
    select.addEventListener('change', () => changeRole(Number(select.dataset.roleIndex), select.value));
  });
  document.querySelectorAll('#memberRows [data-replace-index]').forEach((btn) => {
    btn.addEventListener('click', () => openMemberDialog('replace', Number(btn.dataset.replaceIndex)));
  });
  document.querySelectorAll('#memberRows [data-remove-index]').forEach((btn) => {
    btn.addEventListener('click', () => removeMember(Number(btn.dataset.removeIndex)));
  });
}

function invalidatePreview() {
  previewValid = false;
  previewHasWarnings = false;
  const c = $('#applyConfirm');
  if (c) c.checked = false;
  const b = $('#applyBtn');
  if (b) b.disabled = true;
}
function changeRole(i, v) {
  workingMembers[i].vc_role = v;
  invalidatePreview();
}
function removeMember(i) {
  if (
    confirm(
      `Remove member ${workingMembers[i].member_id} (${workingMembers[i].mac}) from the proposed VC configuration?`,
    )
  ) {
    workingMembers.splice(i, 1);
    invalidatePreview();
    renderMembers();
  }
}
function resetWorking() {
  workingMembers = structuredClone(originalMembers);
  invalidatePreview();
  renderMembers();
}

function eligibleInventory() {
  if (!selectedVC) return [];
  const current = new Set(workingMembers.map((x) => normalizeMac(x.mac)));
  return inventory.filter(
    (x) => x.site_id === selectedVC.site_id && !x.in_virtual_chassis && !current.has(normalizeMac(x.mac)),
  );
}

async function openMemberDialog(mode, index = null) {
  dialogMode = mode;
  dialogIndex = index;
  if (selectedVC && !inventory.length) {
    try {
      inventory = await vcJSON(`/api/v1/inventory?site_id=${encodeURIComponent(selectedVC.site_id)}`);
    } catch (e) {
      console.warn('Site inventory load failed', e);
    }
  }
  $('#dialogEyebrow').textContent = mode === 'replace' ? 'REPLACE MEMBER' : 'ADD MEMBER';
  $('#dialogTitle').textContent =
    mode === 'replace' ? `Replace member ${workingMembers[index].member_id}` : 'Add a VC member';
  const eligible = eligibleInventory();
  const radioList = eligible.length
    ? eligible
        .map(
          (x, j) =>
            `<label class="inventory-option"><input type="radio" name="inv" value="${j}"><span><strong>${esc(x.model)} · ${esc(x.mac)}</strong><small>${esc(x.serial)} · ${esc(x.status)} · ${esc(x.site)}</small></span></label>`,
        )
        .join('')
    : '<div class="noc-empty">No standalone switches at this site are currently eligible from inventory. You can still enter a MAC manually; the backend will verify it exists at this site before applying.</div>';
  const preserve =
    mode === 'replace'
      ? `<div class="notice info">Member ID <b>${workingMembers[index].member_id}</b> and role <b>${roleLabel(workingMembers[index].vc_role)}</b> will be preserved unless you edit them afterward.</div>`
      : '';
  $('#dialogBody').dataset.eligible = JSON.stringify(eligible);
  $('#dialogBody').innerHTML =
    `${preserve}<div class="field"><label>Select standalone switch from this Mist site</label><div class="inventory-list">${radioList}</div></div>
    <div class="notice warning">Manual MAC entry is allowed, but Apply will be rejected unless that MAC exists in Mist inventory at the same site.</div>
    <div class="form-grid"><div class="full field"><label>Manual MAC (optional)</label><input id="manualMac" placeholder="68:ed:57:xx:xx:xx"></div>
      ${mode === 'add' ? `<div class="field"><label>Member ID</label><input id="newMemberId" type="number" min="0" value="${workingMembers.length}"></div><div class="field"><label>Role</label><select id="newRole"><option value="linecard">Linecard</option><option value="backup">Backup</option><option value="master">Master</option></select></div>` : ''}</div>`;
  $('#memberDialog').showModal();
}

function saveMemberDialog(e) {
  // Only the Save button (type=submit) or Enter in a field reaches here; nothing is pre-selected.
  e?.preventDefault();
  const eligible = JSON.parse($('#dialogBody').dataset.eligible || '[]');
  const selected = document.querySelector('input[name="inv"]:checked');
  const chosen = selected ? eligible[+selected.value] : null;
  const manual = normalizeMac($('#manualMac')?.value || '');
  const mac = manual || chosen?.mac;
  if (!mac || normalizeMac(mac).length !== 12) {
    alert('Enter or select a valid 12-digit MAC address.');
    return;
  }
  if (workingMembers.some((m, i) => normalizeMac(m.mac) === normalizeMac(mac) && i !== dialogIndex)) {
    alert('That MAC already exists in the proposed VC.');
    return;
  }
  if (dialogMode === 'replace') {
    const current = workingMembers[dialogIndex];
    workingMembers[dialogIndex] = {
      ...current,
      mac: normalizeMac(mac),
      serial: manual ? 'Manual entry' : chosen?.serial || 'Unknown',
      model: chosen?.model || current.model,
    };
    invalidatePreview();
  } else {
    const id = Number($('#newMemberId').value);
    const role = $('#newRole').value;
    workingMembers.push({
      mac: normalizeMac(mac),
      serial: manual ? 'Manual entry' : chosen?.serial || 'Unknown',
      model: chosen?.model || 'Switch',
      vc_role: role,
      member_id: id,
      vc_ports: [],
    });
    workingMembers.sort((a, b) => a.member_id - b.member_id);
    invalidatePreview();
  }
  $('#memberDialog').close();
  renderMembers();
}

function originalByMac(mac) {
  return originalMembers.find((m) => normalizeMac(m.mac) === normalizeMac(mac));
}
function workingByMac(mac) {
  return workingMembers.find((m) => normalizeMac(m.mac) === normalizeMac(mac));
}
function makeDiff() {
  const groups = [];
  const usedOriginal = new Set();
  workingMembers.forEach((w, wi) => {
    const sameMac = originalByMac(w.mac);
    if (sameMac) {
      usedOriginal.add(normalizeMac(w.mac));
      const rows = [];
      ['mac', 'member_id', 'vc_role'].forEach((k) => {
        const before = sameMac[k],
          after = w[k];
        if (before === after) rows.push({ field: k, value: after, type: 'same', status: 'No change' });
        else {
          rows.push({ field: k, value: before, type: 'old', status: 'Previous' });
          rows.push({ field: k, value: after, type: 'new', status: 'New' });
        }
      });
      groups.push({ title: `Member ${wi}`, rows });
      return;
    }
    const oldAtPosition = originalMembers.find((o) => o.member_id === wi && !workingByMac(o.mac));
    const rows = [];
    if (oldAtPosition) {
      usedOriginal.add(normalizeMac(oldAtPosition.mac));
      rows.push({ field: 'mac', value: oldAtPosition.mac, type: 'old', status: 'Removed' });
      rows.push({ field: 'mac', value: w.mac, type: 'new', status: 'New' });
      for (const k of ['member_id', 'vc_role']) {
        const before = oldAtPosition[k],
          after = w[k];
        if (before === after) rows.push({ field: k, value: after, type: 'same', status: 'No change' });
        else {
          rows.push({ field: k, value: before, type: 'old', status: 'Previous' });
          rows.push({ field: k, value: after, type: 'new', status: 'New' });
        }
      }
      groups.push({ title: `Member ${wi} — Replace`, rows });
    } else
      groups.push({
        title: `Member ${wi} — New`,
        rows: [
          { field: 'mac', value: w.mac, type: 'new', status: 'New' },
          { field: 'member_id', value: w.member_id, type: 'new', status: 'New' },
          { field: 'vc_role', value: roleLabel(w.vc_role), type: 'new', status: 'New' },
        ],
      });
  });
  originalMembers.forEach((o) => {
    if (!usedOriginal.has(normalizeMac(o.mac)) && !workingByMac(o.mac))
      groups.push({
        title: `Member ${o.member_id} — Removed`,
        rows: [
          { field: 'mac', value: o.mac, type: 'old', status: 'Deleted' },
          { field: 'member_id', value: o.member_id, type: 'old', status: 'Deleted' },
          { field: 'vc_role', value: roleLabel(o.vc_role), type: 'old', status: 'Deleted' },
        ],
      });
  });
  return groups;
}

function updateApplyState() {
  const c = $('#applyConfirm');
  const btn = $('#applyBtn');
  if (!btn) return;
  btn.disabled = !(previewValid && c?.checked);
}

async function openPreview() {
  if (!selectedVC) return;
  try {
    const data = await vcJSON('/api/v1/virtual-chassis/preview', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        site_id: selectedVC.site_id,
        device_id: selectedVC.device_id,
        identity_mode: selectedVC.identity_mode,
        original_members: originalMembers,
        members: workingMembers,
      }),
    });
    previewValid = !!(data.valid && data.write_enabled);
    previewHasWarnings = !!data.has_warnings;
    $('#previewTitle').textContent = selectedVC.name;
    $('#diffList').innerHTML = makeDiff()
      .map(
        (g) =>
          `<div class="diff-member"><div class="diff-head">${esc(g.title)}</div>${g.rows.map((r) => `<div class="diff-row ${r.type}"><strong>${esc(r.field === 'vc_role' ? 'Role' : r.field === 'member_id' ? 'Member ID' : 'MAC')}</strong><span>${esc(r.field === 'vc_role' ? roleLabel(r.value) : r.value)}</span><span class="diff-status">${esc(r.status)}</span></div>`).join('')}</div>`,
      )
      .join('');
    $('#validationList').innerHTML = data.checks
      .map((c) => {
        const level = c.level || 'blocker';
        const cls = c.ok ? 'yes' : level === 'warning' ? 'warn' : 'no';
        const icon = c.ok ? '✓' : level === 'warning' ? '⚠' : '✕';
        const tag = level === 'warning' && !c.ok ? '<span class="validation-tag">Warning</span>' : '';
        return `<div class="validation-item ${level}"><span class="${cls}">${icon}</span><span>${esc(c.label)}${tag}</span></div>`;
      })
      .join('');
    const confirmBox = $('#applyConfirm');
    confirmBox.checked = false;
    confirmBox.disabled = !previewValid;
    const eligibility = $('#applyEligibility');
    if (eligibility) {
      eligibility.textContent = !previewValid
        ? 'Apply is blocked only by the red structural checks above.'
        : previewHasWarnings
          ? 'No structural blockers. Review the amber warnings, then check the box to enable Apply to Mist.'
          : 'No structural blockers. Check the box to enable Apply to Mist.';
      eligibility.className = `apply-eligibility ${previewValid ? 'ready' : 'blocked'}`;
    }
    $('#applyBtn').textContent = 'Apply to Mist';
    updateApplyState();
    $('#previewDialog').showModal();
  } catch (e) {
    alert('Preview failed: ' + e.message);
  }
}

async function applyChanges() {
  if (!selectedVC || !previewValid || !$('#applyConfirm').checked) return;
  const warningText = previewHasWarnings
    ? '\n\nThe preview contains amber warnings. They are advisory and will not block this write.'
    : '';
  if (
    !confirm(
      `Apply the proposed Virtual Chassis configuration to ${selectedVC.name} in Mist?${warningText}\n\nA local before/request/after audit snapshot will be written.`,
    )
  )
    return;
  const btn = $('#applyBtn');
  btn.disabled = true;
  btn.textContent = 'Applying...';
  try {
    const result = await vcJSON('/api/v1/virtual-chassis/apply', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        confirmed: true,
        site_id: selectedVC.site_id,
        device_id: selectedVC.device_id,
        preprovisioned: selectedVC.preprovisioned,
        identity_mode: selectedVC.identity_mode,
        original_members: originalMembers,
        members: workingMembers,
      }),
    });
    $('#previewDialog').close();
    $('#resultTitle').textContent = result.verified
      ? 'Change applied and verified'
      : 'Change accepted — verification pending';
    $('#resultBody').innerHTML =
      `<div class="success-box ${result.verified ? '' : 'warning-box'}"><strong>${result.verified ? 'Mist configuration matches the requested VC state.' : 'Mist accepted the update, but the immediate re-query did not yet match the requested state.'}</strong><br><small>Audit snapshot: ${esc(result.audit_file || 'written')}</small></div>`;
    $('#resultDialog').showModal();
    await loadVCs(true);
    inventory = await vcJSON(`/api/v1/inventory?site_id=${encodeURIComponent(selectedVC.site_id)}`);
    $('#editorSection').classList.add('hidden');
    // Keep the other pages current after a network write without making the user refresh them.
    window.MistTools?.dashboard?.refresh?.(false).catch?.(() => {});
    window.MistTools?.history?.refresh?.(false).catch?.(() => {});
  } catch (e) {
    $('#previewDialog').close();
    $('#resultTitle').textContent = 'Change failed';
    $('#resultBody').innerHTML =
      `<div class="source-banner error"><strong>Mist rejected or could not complete the change</strong>${esc(e.message)}</div>`;
    $('#resultDialog').showModal();
  } finally {
    btn.disabled = false;
    btn.textContent = 'Apply to Mist';
  }
}

// ---------------------------------------------------------------- v0.10.15 stack health
const SEV_LABEL = { critical: 'Critical', warning: 'Warning', info: 'Notice', ok: 'Healthy' };
const SEV_ORDER = { critical: 3, warning: 2, info: 1, ok: 0 };
const fmtPct = (v) => (v == null ? '—' : `${Math.round(v)}%`);
const fmtNum = (v, d = 0) => (v == null ? '—' : Number(v).toFixed(d));
function fmtUptime(sec) {
  if (sec == null) return '—';
  const s = Number(sec);
  if (s < 3600) return `${Math.max(1, Math.floor(s / 60))}m`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ${Math.floor((s % 3600) / 60)}m`;
  return `${Math.floor(s / 86400)}d ${Math.floor((s % 86400) / 3600)}h`;
}
function fmtAgo(epochSec) {
  if (!epochSec) return '—';
  const d = Date.now() / 1000 - Number(epochSec);
  if (d < 60) return 'just now';
  if (d < 3600) return `${Math.floor(d / 60)} min ago`;
  if (d < 86400) return `${Math.floor(d / 3600)} h ago`;
  return `${Math.floor(d / 86400)} d ago`;
}
function fmtTime(epochSec) {
  if (!epochSec) return '';
  return new Date(Number(epochSec) * 1000).toLocaleString([], {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}
const sevPill = (sev) => `<span class="vc-sev ${esc(sev)}">${esc(SEV_LABEL[sev] || sev)}</span>`;
const roleShort = (r) =>
  ({ master: 'Master', backup: 'Backup', linecard: 'Linecard', 'routing-engine': 'RE' })[r] || r || '—';

async function loadOverview(force = false, silent = false) {
  const seq = ++overviewSeq;
  const siteId = $('#siteSelect')?.value || '';
  if (!silent) {
    $('#vcOverviewScope').textContent = siteId ? siteName(siteId) : 'All sites';
    $('#vcOverviewMeta').textContent = 'Checking stack health…';
    if (!overview || overview.site_id !== siteId)
      $('#vcOverviewRows').innerHTML =
        '<tr><td colspan="8"><div class="noc-empty">Reading switch stats, alarms and VC events from Mist…</div></td></tr>';
  }
  const qs = new URLSearchParams();
  if (siteId) qs.set('site_id', siteId);
  if (force) qs.set('refresh', 'true');
  try {
    const data = await vcJSON(`/api/v1/virtual-chassis/overview?${qs}`);
    if (seq !== overviewSeq) return;
    overview = data;
    renderOverview();
    decorateCards();
  } catch (e) {
    if (seq !== overviewSeq) return;
    $('#vcOverviewMeta').textContent = 'Health check failed';
    $('#vcOverviewTiles').innerHTML = '';
    $('#vcOverviewRows').innerHTML =
      `<tr><td colspan="8"><div class="source-banner error"><strong>Stack health unavailable</strong>${esc(e.message)}</div></td></tr>`;
  }
}

const TILE_DEFS = [
  ['stacks', 'Stacks', ''],
  ['critical', 'Critical', 'critical'],
  ['warning', 'Warnings', 'warning'],
  ['healthy', 'Healthy', 'ok'],
  ['offline', 'Offline', 'critical'],
  ['members_missing', 'Members missing', 'critical'],
  ['vcp_down', 'VC ports down', 'warning'],
  ['no_backup', 'No backup RE', 'warning'],
  ['mixed_firmware', 'Mixed firmware', 'warning'],
  ['env_alarms', 'PSU / fan / temp', 'warning'],
  ['recent_reboots', 'Reboots 7d', 'info'],
  ['switchovers', 'Switchovers 7d', 'warning'],
];

function rowMatchesFilter(r, f) {
  if (!f || f === 'stacks') return true;
  if (f === 'critical' || f === 'warning') return r.severity === f;
  if (f === 'healthy') return r.severity === 'ok' || r.severity === 'info';
  return Number(r.counts?.[f] || 0) > 0;
}

function renderOverview() {
  const data = overview;
  if (!data) return;
  const t = data.totals || {};
  const siteId = $('#siteSelect')?.value || '';
  $('#vcOverviewScope').textContent =
    data.scope === 'site' ? `${siteName(data.site_id)} · site scope` : 'All sites';
  const updated = data.generated_at
    ? new Date(data.generated_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    : '';
  $('#vcOverviewMeta').textContent = [
    `${t.stacks || 0} stack${t.stacks === 1 ? '' : 's'}`,
    data.scope === 'org' ? `${t.sites || 0} site${t.sites === 1 ? '' : 's'}` : '',
    `${t.members || 0} members`,
    updated ? `updated ${updated}` : '',
    data.sample ? 'SAMPLE DATA (Mist not connected)' : '',
  ]
    .filter(Boolean)
    .join(' · ');
  $('#vcOverviewTiles').innerHTML = TILE_DEFS.map(([key, label, tone]) => {
    const value = Number(t[key] || 0);
    const cls = [
      'vc-tile',
      value && tone ? `tone-${tone}` : 'quiet',
      overviewFilter === key ? 'active' : '',
    ].join(' ');
    return `<button type="button" class="${cls}" data-vc-filter="${esc(key)}" title="${esc(label)}: ${value}" aria-pressed="${overviewFilter === key}"><b>${value}</b><span>${esc(label)}</span></button>`;
  }).join('');
  $('#vcOverviewWarn').innerHTML = (data.warnings || [])
    .map((w) => `<div class="notice warning vc-warn">${esc(w)}</div>`)
    .join('');
  const rows = (data.stacks || [])
    .map((r, i) => ({ r, i }))
    .filter(({ r }) => rowMatchesFilter(r, overviewFilter));
  if (!rows.length) {
    $('#vcOverviewRows').innerHTML = `<tr><td colspan="8"><div class="noc-empty">${
      (data.stacks || []).length
        ? 'No stacks match this filter. Click the tile again to clear it.'
        : siteId
          ? 'No Virtual Chassis stacks report statistics at this site.'
          : 'No Virtual Chassis stacks report statistics in this organization.'
    }</div></td></tr>`;
    return;
  }
  $('#vcOverviewRows').innerHTML = rows
    .map(({ r, i }) => {
      const brief = r.members_brief || [];
      const missing = brief.filter((m) => m.present === false).length;
      const roles = [
        r.master_fpc != null ? `Master FPC ${r.master_fpc}` : '<span class="bad-text">No master</span>',
        r.backup_fpc != null
          ? `<small class="cell-sub">Backup FPC ${r.backup_fpc}</small>`
          : r.member_count > 1
            ? '<small class="cell-sub warn-text">No backup</small>'
            : '',
      ].join('');
      const versions = r.versions || [];
      const fw = versions.length
        ? `${esc(versions.join(', '))}${versions.length > 1 ? ' <span class="vc-flag">mixed</span>' : ''}`
        : '<span class="muted">—</span>';
      const issues = (r.issues || []).slice(0, 2);
      const more = (r.issues || []).length - issues.length;
      const ev = r.last_event;
      return `<tr data-vc-row="${i}" tabindex="0" class="vc-rank-row sev-${esc(r.severity)}" title="Open ${esc(r.name)}">
        <td data-sort="${SEV_ORDER[r.severity] * 10000 + Number(r.score || 0)}">${sevPill(r.severity)}</td>
        <td><strong>${esc(r.name)}</strong><small class="cell-sub">${esc(r.model || '')}${r.status && r.status !== 'connected' ? ` · <span class="bad-text">${esc(r.status)}</span>` : ''}</small></td>
        <td>${esc(r.site_name || siteName(r.site_id))}</td>
        <td data-sort="${r.present_count}"><strong>${r.present_count}/${r.member_count}</strong>${missing ? `<small class="cell-sub bad-text">${missing} missing</small>` : ''}</td>
        <td>${roles}</td>
        <td>${fw}</td>
        <td class="vc-issue-cell">${
          issues.length
            ? issues.map((x) => `<div class="vc-issue ${esc(x.severity)}">${esc(x.text)}</div>`).join('') +
              (more > 0 ? `<small class="muted">+${more} more</small>` : '')
            : '<span class="muted">No issues</span>'
        }</td>
        <td data-sort="${ev?.timestamp || 0}">${ev ? `${esc(ev.label)}<small class="cell-sub">${esc(fmtAgo(ev.timestamp))}</small>` : '<span class="muted">None in 7 days</span>'}</td>
      </tr>`;
    })
    .join('');
}

function decorateCards() {
  if (!overview) return;
  const byId = new Map((overview.stacks || []).map((r) => [String(r.device_id), r]));
  document.querySelectorAll('#vcGrid [data-vc-health]').forEach((el) => {
    const r = byId.get(String(el.dataset.vcHealth));
    if (!r) {
      el.innerHTML = '';
      return;
    }
    el.innerHTML = `${sevPill(r.severity)}<span class="vc-card-issue">${esc(r.top_issue || 'No issues detected')}</span>`;
  });
}

function drillTo(index) {
  const r = overview?.stacks?.[index];
  if (!r) return;
  const select = $('#siteSelect');
  if (select.value !== r.site_id) {
    pendingDrill = r.device_id;
    select.value = r.site_id;
    select.dispatchEvent(new Event('change', { bubbles: true }));
    return;
  }
  const idx = vcs.findIndex((v) => String(v.device_id) === String(r.device_id));
  if (idx >= 0) manageVC(idx);
  else {
    loadHealth(r.site_id, r.device_id);
    $('#vcHealthSection').scrollIntoView({ behavior: 'smooth', block: 'start' });
  }
}

function hideHealth() {
  healthTarget = null;
  healthSeq++;
  $('#vcHealthSection')?.classList.add('hidden');
}

async function loadHealth(siteId, deviceId, force = false) {
  const seq = ++healthSeq;
  healthTarget = { site_id: siteId, device_id: deviceId };
  const section = $('#vcHealthSection');
  section.classList.remove('hidden');
  if (!force) {
    const known = overview?.stacks?.find((r) => String(r.device_id) === String(deviceId));
    $('#vcHealthTitle').textContent = known?.name || 'Loading stack…';
    $('#vcHealthMeta').innerHTML = '';
    $('#vcHealthBody').innerHTML =
      '<div class="noc-empty">Reading member stats, VC links, environment and events from Mist…</div>';
  }
  const qs = new URLSearchParams({ site_id: siteId, device_id: deviceId });
  if (force) qs.set('refresh', 'true');
  try {
    const d = await vcJSON(`/api/v1/virtual-chassis/health?${qs}`);
    if (seq !== healthSeq) return;
    renderHealth(d);
  } catch (e) {
    if (seq !== healthSeq) return;
    $('#vcHealthBody').innerHTML =
      `<div class="source-banner error"><strong>Stack detail unavailable</strong>${esc(e.message)}</div>`;
  }
}

const VERDICT_ICON = { ok: '✓', info: 'i', warning: '!', critical: '✕' };

function renderHealth(d) {
  $('#vcHealthTitle').textContent = d.name || 'Stack';
  const chips = [
    [d.site_name || siteName(d.site_id), ''],
    [d.model, ''],
    [d.status === 'connected' ? 'Connected' : d.status, d.status === 'connected' ? 'good' : 'bad'],
    [`${d.present_count}/${d.member_count} members present`, d.present_count < d.member_count ? 'bad' : ''],
    [d.topology?.label, d.topology?.redundant === false && d.member_count > 1 ? 'warn' : ''],
    [d.ip ? `IP ${d.ip}` : '', ''],
    [d.uptime != null ? `Up ${fmtUptime(d.uptime)}` : '', ''],
    [d.preprovisioned == null ? '' : d.preprovisioned ? 'Preprovisioned' : 'Not preprovisioned', ''],
    [d.sample ? 'SAMPLE DATA' : '', 'warn'],
  ].filter(([x]) => x);
  $('#vcHealthMeta').innerHTML = [sevPill(d.severity)]
    .concat(chips.map(([x, c]) => `<span class="chip ${c ? `vc-chip-${c}` : ''}">${esc(x)}</span>`))
    .join('');
  const warn = (d.warnings || []).map((w) => `<div class="notice warning vc-warn">${esc(w)}</div>`).join('');
  const verdicts = (d.verdicts || [])
    .map(
      (v) =>
        `<div class="vc-verdict ${esc(v.level)}"><span class="vc-verdict-icon" aria-hidden="true">${VERDICT_ICON[v.level] || 'i'}</span><div><strong>${esc(v.topic)}</strong><p>${esc(v.text)}</p></div></div>`,
    )
    .join('');
  const issues = (d.issues || []).length
    ? `<ul class="vc-issue-list">${d.issues
        .map((i) => `<li class="${esc(i.severity)}">${sevPill(i.severity)}<span>${esc(i.text)}</span></li>`)
        .join('')}</ul>`
    : '<div class="noc-empty">No open issues detected for this stack.</div>';
  const links = d.links || [];
  const upN = links.filter((l) => l.state === 'up').length;
  const downN = links.length - upN;
  $('#vcHealthBody').innerHTML = `${warn}
    <div class="vc-panel"><div class="vc-panel-head"><h4>Stack topology <span class="muted">· ${esc(d.topology?.label || '')}</span></h4><span class="muted">${upN} VC link${upN === 1 ? '' : 's'} up${downN ? ` · <span class="bad-text">${downN} down</span>` : ''}</span></div>${topologySvg(d)}
      <div class="vc-legend" aria-hidden="true"><span><i class="lg up"></i>VC link up</span><span><i class="lg down"></i>VC port down</span><span><i class="lg master"></i>Master</span><span><i class="lg backup"></i>Backup</span><span><i class="lg missing"></i>Not present</span></div></div>
    <div class="vc-health-grid">
      <div class="vc-panel"><h4>Verdicts</h4><div class="vc-verdicts">${verdicts}</div></div>
      <div class="vc-panel"><h4>Open issues <span class="muted">(${(d.issues || []).length})</span></h4>${issues}</div>
    </div>
    <div class="vc-panel"><h4>Members</h4>${memberTable(d)}</div>
    <div class="vc-panel"><h4>Environment</h4>${environment(d)}</div>
    <div class="vc-health-grid">
      <div class="vc-panel"><h4>VC ports</h4>${vcPortsTable(d)}</div>
      <div class="vc-panel"><h4>VC events · last 7 days <span class="muted">(${(d.events || []).length})</span></h4>${timeline(d)}</div>
    </div>`;
  applyBars($('#vcHealthBody'));
}

function topologySvg(d) {
  const members = d.members || [];
  if (!members.length) return '<div class="noc-empty">Mist did not report any members.</div>';
  const W = 156,
    H = 76,
    GAP = 64,
    PAD = 16,
    TOP = 14;
  const pos = new Map(members.map((m, i) => [m.fpc, i]));
  const cx = (i) => PAD + i * (W + GAP) + W / 2;
  const width = PAD * 2 + members.length * W + (members.length - 1) * GAP;
  const links = d.links || [];
  const pairCount = new Map();
  let maxDepth = 0;
  const paths = [];
  links.forEach((l) => {
    const a = pos.get(l.local_fpc);
    const b = pos.get(l.remote_fpc);
    const title = `FPC ${l.local_fpc ?? '?'} ${l.local_port || ''} ↔ ${l.remote_fpc != null ? `FPC ${l.remote_fpc} ${l.remote_port || ''}` : 'no neighbour'} · ${l.state}`;
    const y0 = TOP + H;
    if (a == null) return;
    if (b == null || a === b) {
      // Down port with no neighbour: a short stub with a break mark under the member.
      const k = `stub-${a}`;
      const n = pairCount.get(k) || 0;
      pairCount.set(k, n + 1);
      const x = cx(a) + 26 + n * 14;
      maxDepth = Math.max(maxDepth, 34);
      paths.push(
        `<g class="vc-link ${l.state === 'up' ? 'up' : 'down'}"><title>${esc(title)}</title><path d="M ${x} ${y0} L ${x} ${y0 + 26}"/><path class="x" d="M ${x - 5} ${y0 + 21} L ${x + 5} ${y0 + 31} M ${x + 5} ${y0 + 21} L ${x - 5} ${y0 + 31}"/></g>`,
      );
      return;
    }
    const lo = Math.min(a, b),
      hi = Math.max(a, b);
    const k = `${lo}-${hi}`;
    const n = pairCount.get(k) || 0;
    pairCount.set(k, n + 1);
    if (hi - lo === 1 && n === 0) {
      const y = TOP + H / 2;
      paths.push(
        `<g class="vc-link ${l.state === 'up' ? 'up' : 'down'}"><title>${esc(title)}</title><path d="M ${cx(lo) + W / 2} ${y} L ${cx(hi) - W / 2} ${y}"/></g>`,
      );
      return;
    }
    const depth = 22 + (hi - lo) * 14 + n * 12;
    maxDepth = Math.max(maxDepth, depth);
    const x1 = cx(lo) - 10 + n * 8,
      x2 = cx(hi) + 10 - n * 8;
    paths.push(
      `<g class="vc-link ${l.state === 'up' ? 'up' : 'down'}"><title>${esc(title)}</title><path d="M ${x1} ${y0} C ${x1} ${y0 + depth * 1.3}, ${x2} ${y0 + depth * 1.3}, ${x2} ${y0}"/></g>`,
    );
  });
  const height = TOP + H + maxDepth + 16;
  const boxes = members
    .map((m, i) => {
      const x = PAD + i * (W + GAP);
      const cls = ['vc-node', m.present === false ? 'missing' : '', m.role || ''].join(' ');
      return `<g class="${esc(cls)}"><title>${esc(`FPC ${m.fpc} · ${roleShort(m.role)} · ${m.model || ''} · ${m.serial || ''} · ${m.version || ''}`)}</title>
        <rect x="${x}" y="${TOP}" width="${W}" height="${H}" rx="10"/>
        <text class="t1" x="${x + 12}" y="${TOP + 22}">FPC ${esc(m.fpc)}</text>
        <text class="t2" x="${x + W - 12}" y="${TOP + 22}" text-anchor="end">${esc(roleShort(m.role))}</text>
        <text class="t3" x="${x + 12}" y="${TOP + 42}">${esc((m.model || '').slice(0, 18))}</text>
        <text class="t3" x="${x + 12}" y="${TOP + 60}">${esc(m.present === false ? m.vc_state || 'not present' : (m.version || '').slice(0, 18))}</text></g>`;
    })
    .join('');
  return `<div class="vc-topo-wrap"><svg class="vc-topo" viewBox="0 0 ${width} ${height}" width="${width}" height="${height}" role="img" aria-label="Virtual Chassis topology">${paths.join('')}${boxes}</svg></div>`;
}

function hwSummary(list) {
  if (!list?.length) return '<span class="muted">—</span>';
  const bad = list.filter((x) => x.status === 'bad').length;
  const ok = list.filter((x) => x.status === 'ok').length;
  if (bad)
    return `<span class="bad-text">${bad} fault${bad > 1 ? 's' : ''}</span><small class="cell-sub">${ok}/${list.length} OK</small>`;
  return `<span class="ok-text">${ok}/${list.length} OK</span>`;
}

function memberTable(d) {
  const ms = d.members || [];
  if (!ms.length) return '<div class="noc-empty">No member data.</div>';
  const majority = (() => {
    const c = {};
    ms.forEach((m) => m.version && (c[m.version] = (c[m.version] || 0) + 1));
    return Object.entries(c).sort((a, b) => b[1] - a[1])[0]?.[0];
  })();
  const body = ms
    .map((m) => {
      const poe = m.poe;
      const poeTxt =
        poe && poe.max_power
          ? `${fmtNum(poe.power_draw)} / ${fmtNum(poe.max_power)} W<small class="cell-sub">${Math.round(((poe.power_draw || 0) / poe.max_power) * 100)}% used</small>`
          : '—';
      const state =
        m.present === false
          ? `<span class="bad-text">${esc(m.vc_state || 'not present')}</span>`
          : `<span class="ok-text">${esc(m.vc_state || 'present')}</span>`;
      const fwOdd = m.version && majority && m.version !== majority;
      const hot = m.max_temp != null && m.max_temp >= 70;
      return `<tr class="${m.present === false ? 'vc-row-missing' : ''}">
        <td data-sort="${m.fpc}"><strong>${esc(m.fpc)}</strong></td>
        <td><span class="vc-role ${esc(m.role)}">${esc(roleShort(m.role))}</span></td>
        <td>${state}</td>
        <td>${esc(m.model || '—')}<small class="cell-sub">${esc([m.serial, m.mac].filter(Boolean).join(' · '))}</small></td>
        <td>${m.version ? `<span class="${fwOdd ? 'warn-text' : ''}">${esc(m.version)}</span>` : '—'}${m.pending_version && m.pending_version !== m.version ? `<small class="cell-sub">staged ${esc(m.pending_version)}</small>` : ''}${m.backup_version ? `<small class="cell-sub">backup ${esc(m.backup_version)}</small>` : ''}</td>
        <td data-sort="${m.uptime ?? -1}">${esc(fmtUptime(m.uptime))}</td>
        <td data-sort="${m.cpu ?? -1}"><span class="${m.cpu >= 85 ? 'warn-text' : ''}">${esc(fmtPct(m.cpu))}</span> / <span class="${m.memory >= 85 ? 'warn-text' : ''}">${esc(fmtPct(m.memory))}</span></td>
        <td data-sort="${m.max_temp ?? -1}" class="${hot ? 'warn-text' : ''}">${m.max_temp != null ? `${esc(fmtNum(m.max_temp))} °C` : '—'}</td>
        <td>${hwSummary(m.psus)}<small class="cell-sub">fans <span class="${m.fans?.some((x) => x.status === 'bad') ? 'bad-text' : ''}">${m.fans?.length ? `${m.fans.filter((x) => x.status === 'ok').length}/${m.fans.length} OK` : '—'}</span></small></td>
        <td data-sort="${poe?.power_draw ?? -1}">${poeTxt}</td>
        <td data-sort="${m.ports_up ?? -1}">${m.ports_up != null ? `${m.ports_up}/${m.ports_total}` : m.ports_total ? `—/${m.ports_total}` : '—'}</td>
      </tr>`;
    })
    .join('');
  return `<div class="table-wrap vc-member-table"><table><thead><tr><th>FPC</th><th>Role</th><th>State</th><th>Model / Serial · MAC</th><th>Firmware</th><th>Uptime</th><th>CPU / Mem</th><th>Temp</th><th>PSU / Fans</th><th>PoE</th><th>Ports up</th></tr></thead><tbody>${body}</tbody></table></div>`;
}

function environment(d) {
  const ms = d.members || [];
  if (!ms.length) return '<div class="noc-empty">No environment data.</div>';
  const chip = (x, extra = '') =>
    `<span class="vc-hw ${esc(x.status)}" title="${esc(x.raw || x.status)}">${esc(x.name)}${extra}</span>`;
  return `<div class="vc-env-grid">${ms
    .map((m) => {
      const poe = m.poe;
      const pct = poe && poe.max_power ? Math.min(100, ((poe.power_draw || 0) / poe.max_power) * 100) : null;
      return `<div class="vc-env ${m.present === false ? 'missing' : ''}">
        <div class="vc-env-head"><strong>FPC ${esc(m.fpc)}</strong><span class="muted">${esc(roleShort(m.role))} · ${esc(m.model || '')}</span></div>
        <div class="vc-env-row"><span class="lbl">Power</span>${m.psus.length ? m.psus.map((x) => chip(x)).join('') : '<span class="muted">not reported</span>'}</div>
        <div class="vc-env-row"><span class="lbl">Fans</span>${m.fans.length ? m.fans.map((x) => chip(x, x.airflow ? ` · ${esc(x.airflow)}` : '')).join('') : '<span class="muted">not reported</span>'}</div>
        <div class="vc-env-row"><span class="lbl">Temp</span>${m.temperatures.length ? m.temperatures.map((x) => chip(x, x.celsius != null ? ` ${esc(fmtNum(x.celsius))} °C` : '')).join('') : '<span class="muted">not reported</span>'}</div>
        <div class="vc-env-row"><span class="lbl">PoE</span>${pct == null ? '<span class="muted">not reported</span>' : `<span class="vc-bar" role="img" aria-label="PoE ${Math.round(pct)}% used"><i data-pct="${pct.toFixed(1)}"></i></span><span class="muted">${esc(fmtNum(poe.power_draw))} of ${esc(fmtNum(poe.max_power))} W</span>`}</div>
        ${m.errors?.length ? `<div class="vc-env-row"><span class="lbl">Errors</span><span class="bad-text">${esc(m.errors.join('; '))}</span></div>` : ''}
      </div>`;
    })
    .join('')}</div>`;
}

function vcPortsTable(d) {
  const links = d.links || [];
  if (!links.length)
    return '<div class="noc-empty">Mist did not report VC port details for this stack.</div>';
  const rows = links
    .slice()
    .sort((a, b) =>
      a.state === b.state ? (a.local_fpc ?? 99) - (b.local_fpc ?? 99) : a.state === 'down' ? -1 : 1,
    )
    .map(
      (l) => `<tr>
        <td data-sort="${l.local_fpc ?? -1}">FPC ${esc(l.local_fpc ?? '?')}</td><td><code>${esc(l.local_port || '—')}</code></td>
        <td data-sort="${l.remote_fpc ?? -1}">${l.remote_fpc != null ? `FPC ${esc(l.remote_fpc)}` : '<span class="muted">—</span>'}</td><td><code>${esc(l.remote_port || '—')}</code></td>
        <td title="${esc(l.source || '')}"><span class="vc-link-state ${esc(l.state)}">${esc(l.state === 'up' ? 'Up' : 'Down')}</span>${l.since ? `<small class="cell-sub">since ${esc(fmtAgo(l.since))}</small>` : l.state !== 'up' && l.source ? `<small class="cell-sub">${esc(l.source)}</small>` : ''}</td>
        <td>${esc(l.speed || '—')}</td></tr>`,
    )
    .join('');
  return `<div class="table-wrap"><table><thead><tr><th>Local</th><th>Port</th><th>Remote</th><th>Port</th><th>State</th><th>Speed</th></tr></thead><tbody>${rows}</tbody></table></div>`;
}

function timeline(d) {
  const evs = d.events || [];
  if (!evs.length)
    return '<div class="noc-empty">No VC, restart, environment or config events in the last 7 days.</div>';
  return `<ol class="vc-timeline">${evs
    .slice(0, 40)
    .map(
      (e) => `<li class="kind-${esc(e.kind)}"><span class="dot" aria-hidden="true"></span><div>
        <div class="vc-ev-head"><strong>${esc(e.label)}</strong>${e.fpc != null ? `<span class="chip">FPC ${esc(e.fpc)}</span>` : ''}${e.port ? `<code>${esc(e.port)}</code>` : ''}</div>
        <small class="muted">${esc(fmtTime(e.timestamp))} · ${esc(fmtAgo(e.timestamp))} · ${esc(e.type)}</small>
        ${e.text ? `<p>${esc(e.text)}</p>` : ''}</div></li>`,
    )
    .join('')}</ol>`;
}

function applyBars(root = document) {
  root
    .querySelectorAll('.vc-bar i[data-pct]')
    .forEach((i) => i.style.setProperty('--pct', `${i.dataset.pct}%`));
}

window.MistTools = window.MistTools || {};
async function refreshVCView(force = false, silent = false) {
  const siteId = $('#siteSelect')?.value;
  const jobs = [loadOverview(force, silent)];
  if (siteId) jobs.push(loadVCs(force, silent));
  await Promise.all(jobs);
}
window.MistTools.virtualChassis = {
  init: initVC,
  refresh: refreshVCView,
  autoRefresh: () => refreshVCView(false, true),
};
