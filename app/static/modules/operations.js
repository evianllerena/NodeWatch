const opsEsc = nwEscapeHtml; // one shared escaper (core.js)
window.MistTools.operations = (() => {
  let inited = false,
    site = '',
    device = '',
    selected = '',
    ports = [],
    members = [],
    profiles = [],
    selection = [], // port IDs being configured
    anchor = '', // last clicked port, for shift-click ranges
    member = null, // VC member filter on the faceplate (null = all members stacked)
    switchInfo = null, // last loaded switch header
    overview = null, // /api/v1/operations/overview payload (org or site scope)
    overviewSeq = 0,
    ovCat = '', // category tile filter
    ovLimit = 120, // issue rows shown before "Show all"
    ovInfoOpen = new Set(), // switch groups whose informational findings are unfolded
    snapshot = null; // form values when the selection was made (to send only what changed)
  // v0.10.32: site / switch / port choices are history entries (Back returns to the previous one).
  function navPush(replace = false) {
    const view = site ? { site, device: device || '', port: device ? selected || '' : '' } : null;
    window.MistApp?.pushView?.(view, { replace });
  }
  const j = (url, opt) => nwFetchJSON(url, opt); // shared helper (core.js)
  async function sites() {
    const rows = (await j('/api/v1/operations/sites')).sort((a, b) =>
      String(a.name || '').localeCompare(String(b.name || '')),
    );
    const e = document.querySelector('#opsSite');
    e.innerHTML =
      '<option value="">Select site</option>' +
      rows.map((x) => `<option value="${opsEsc(x.id)}">${opsEsc(x.name)}</option>`).join('');
  }
  async function switches() {
    site = document.querySelector('#opsSite').value;
    const e = document.querySelector('#opsSwitch');
    e.innerHTML = '<option>Loading…</option>';
    if (!site) {
      e.innerHTML = '<option value="">Select switch</option>';
      return;
    }
    const rows = await j(`/api/v1/operations/switches?site_id=${encodeURIComponent(site)}`);
    rows.sort((a, b) => String(a.name || '').localeCompare(String(b.name || '')));
    e.innerHTML =
      '<option value="">Select switch</option>' +
      rows
        .map((x) => `<option value="${opsEsc(x.id)}">${opsEsc(x.name)} · ${opsEsc(x.model)}</option>`)
        .join('');
  }
  const isPowered = (p) => Boolean(p.poe_on) || (Number(p.poe_watts) || 0) > 0;
  const speedOf = (p) => Number(p.speed_mbps) || 0;
  function deviceName(p) {
    return p.neighbor_system_name || p.client_hostname || p.client_manufacturer || p.manufacturer || '';
  }
  function searchable(p) {
    return [
      p.port_id,
      p.mac,
      p.client_mac,
      p.neighbor_mac,
      p.neighbor_system_name,
      p.neighbor_port_desc,
      p.manufacturer,
      p.client_manufacturer,
      p.client_hostname,
      p.client_ip,
      p.auth_state,
      p.speed,
      p.usage,
      p.description,
      p.lag_parent,
    ]
      .join(' ')
      .toLowerCase();
  }
  // ---------------------------------------------------------------- port table columns
  // Every column the chooser offers. get() returns display text ('' = empty); sort() a raw
  // sortable value for table-tools (data-sort); na names the backend not_applicable reason.
  const COLS_KEY = 'nodewatch.portToolkit.columns.v1';
  const DEFAULT_COLS = ['port', 'link', 'speed', 'poe', 'auth', 'mac', 'neighbor', 'issues'];
  const num = (v) => (v == null || v === '' || !Number.isFinite(Number(v)) ? null : Number(v));
  const nfmt = (v) => (num(v) == null ? '' : num(v).toLocaleString());
  const epochMs = (v) => (num(v) ? (num(v) > 1e12 ? num(v) : num(v) * 1000) : 0);
  function agoText(ms) {
    if (!ms) return '';
    const s = Math.max(0, Math.round((Date.now() - ms) / 1000));
    if (s < 90) return `${s}s`;
    if (s < 5400) return `${Math.round(s / 60)}m`;
    if (s < 172800) return `${Math.round(s / 3600)}h`;
    return `${Math.round(s / 86400)}d`;
  }
  const usageOf = (p) => p.config?.usage || p.usage || '';
  const SEV_RANK = { critical: 0, warning: 1, info: 2 };
  const worstIssue = (p) =>
    [...(p.issues || [])].sort((a, b) => (SEV_RANK[a.severity] ?? 3) - (SEV_RANK[b.severity] ?? 3))[0];
  const COLUMNS = [
    { key: 'port', label: 'Port', fixed: true, sort: (p) => p.port_id, html: portCell },
    {
      key: 'link',
      label: 'Link',
      get: (p) => (p.up ? 'Up' : p.admin_disabled ? 'Disabled' : 'Down'),
      cls: (p) => (p.up ? 'ops-up' : 'ops-down'),
    },
    { key: 'issues', label: 'Issues', html: issuesCell, sort: (p) => issueSort(p) },
    {
      key: 'speed',
      label: 'Speed',
      get: (p) => (p.not_applicable?.speed ? '' : p.speed),
      sort: speedOf,
      na: 'speed',
    },
    {
      key: 'duplex',
      label: 'Duplex',
      get: (p) => (p.full_duplex === true ? 'Full' : p.full_duplex === false ? 'Half' : ''),
    },
    {
      key: 'poe',
      label: 'PoE / Draw',
      get: (p) => (isPowered(p) ? `${(Number(p.poe_watts) || 0).toFixed(1)} W` : ''),
      sort: (p) => (isPowered(p) ? Number(p.poe_watts) || 0 : ''),
      na: 'poe',
    },
    { key: 'poe_mode', label: 'PoE mode', get: (p) => p.poe_mode, na: 'poe' },
    { key: 'poe_class', label: 'PoE class', get: (p) => p.poe_class },
    { key: 'poe_priority', label: 'PoE priority', get: (p) => p.poe_priority },
    { key: 'poe_status', label: 'PoE status', get: (p) => p.poe_status },
    { key: 'auth', label: 'Auth', get: (p) => p.auth_state, na: 'auth' },
    { key: 'mac', label: 'MAC', get: (p) => p.mac || p.client_mac, mono: true, na: 'mac' },
    {
      key: 'neighbor',
      label: 'Neighbor / Manufacturer',
      html: neighborCell,
      sort: deviceName,
      na: 'neighbor',
    },
    { key: 'description', label: 'Description', get: (p) => p.config?.description ?? p.description },
    { key: 'usage', label: 'Profile / usage', get: usageOf },
    { key: 'vlan', label: 'VLAN', get: (p) => p.vlan_id, sort: (p) => num(p.vlan_id) ?? p.vlan_id },
    { key: 'networks', label: 'Networks (units)', get: (p) => (p.networks || []).join(', ') },
    { key: 'ips', label: 'IP addresses', get: (p) => (p.ips || []).join(', '), mono: true },
    { key: 'mtu', label: 'MTU', get: (p) => nfmt(p.mtu), sort: (p) => num(p.mtu) ?? '' },
    { key: 'stp_state', label: 'STP state', get: (p) => p.stp_state },
    { key: 'stp_role', label: 'STP role', get: (p) => p.stp_role },
    {
      key: 'neighbor_system_name',
      label: 'LLDP system name',
      get: (p) => p.neighbor_system_name,
      na: 'neighbor',
    },
    { key: 'neighbor_port_desc', label: 'LLDP port', get: (p) => p.neighbor_port_desc, na: 'neighbor' },
    {
      key: 'neighbor_mac',
      label: 'LLDP chassis MAC',
      get: (p) => p.neighbor_mac,
      mono: true,
      na: 'neighbor',
    },
    { key: 'neighbor_mgmt_ip', label: 'LLDP mgmt IP', get: (p) => p.neighbor_mgmt_ip, mono: true },
    { key: 'neighbor_system_desc', label: 'LLDP system description', get: (p) => p.neighbor_system_desc },
    { key: 'client_hostname', label: 'Client hostname', get: (p) => p.client_hostname },
    { key: 'client_ip', label: 'Client IP', get: (p) => p.client_ip, mono: true },
    { key: 'client_manufacturer', label: 'Client manufacturer', get: (p) => p.client_manufacturer },
    {
      key: 'client_count',
      label: 'Wired clients',
      get: (p) => nfmt(p.client_count || null),
      sort: (p) => p.client_count || 0,
    },
    {
      key: 'mac_count',
      label: 'MACs learned',
      get: (p) => nfmt(p.mac_count),
      sort: (p) => num(p.mac_count) ?? '',
    },
    {
      key: 'mac_limit',
      label: 'MAC limit',
      get: (p) => nfmt(p.mac_limit),
      sort: (p) => num(p.mac_limit) ?? '',
    },
    {
      key: 'util',
      label: 'Utilisation',
      get: (p) => (num(p.utilisation_pct) == null ? '' : `${p.utilisation_pct}%`),
      sort: (p) => num(p.utilisation_pct) ?? '',
    },
    { key: 'rx_bps', label: 'Receive rate', get: (p) => fmtBps(p.rx_bps), sort: (p) => num(p.rx_bps) ?? '' },
    { key: 'tx_bps', label: 'Transmit rate', get: (p) => fmtBps(p.tx_bps), sort: (p) => num(p.tx_bps) ?? '' },
    {
      key: 'rx_bytes',
      label: 'Received bytes',
      get: (p) => fmtBytes(p.rx_bytes),
      sort: (p) => num(p.rx_bytes) ?? '',
    },
    {
      key: 'tx_bytes',
      label: 'Sent bytes',
      get: (p) => fmtBytes(p.tx_bytes),
      sort: (p) => num(p.tx_bytes) ?? '',
    },
    {
      key: 'rx_pkts',
      label: 'Received packets',
      get: (p) => nfmt(p.rx_pkts),
      sort: (p) => num(p.rx_pkts) ?? '',
    },
    { key: 'tx_pkts', label: 'Sent packets', get: (p) => nfmt(p.tx_pkts), sort: (p) => num(p.tx_pkts) ?? '' },
    {
      key: 'rx_errors',
      label: 'Input errors',
      get: (p) => nfmt(p.rx_errors),
      sort: (p) => num(p.rx_errors) ?? '',
    },
    {
      key: 'tx_errors',
      label: 'Output errors',
      get: (p) => nfmt(p.tx_errors),
      sort: (p) => num(p.tx_errors) ?? '',
    },
    {
      key: 'crc_errors',
      label: 'CRC / FCS errors',
      get: (p) => nfmt(p.crc_errors),
      sort: (p) => num(p.crc_errors) ?? '',
    },
    {
      key: 'rx_bcast_pkts',
      label: 'Broadcast in',
      get: (p) => nfmt(p.rx_bcast_pkts),
      sort: (p) => num(p.rx_bcast_pkts) ?? '',
    },
    {
      key: 'rx_mcast_pkts',
      label: 'Multicast in',
      get: (p) => nfmt(p.rx_mcast_pkts),
      sort: (p) => num(p.rx_mcast_pkts) ?? '',
    },
    {
      key: 'last_flapped',
      label: 'Last flapped',
      get: (p) => (epochMs(p.last_flapped) ? `${agoText(epochMs(p.last_flapped))} ago` : ''),
      title: (p) => (epochMs(p.last_flapped) ? new Date(epochMs(p.last_flapped)).toLocaleString() : ''),
      sort: (p) => (epochMs(p.last_flapped) ? Date.now() - epochMs(p.last_flapped) : ''),
    },
    {
      key: 'uptime',
      label: 'Link uptime',
      get: (p) => (p.up && epochMs(p.last_flapped) ? agoText(epochMs(p.last_flapped)) : ''),
      sort: (p) => (p.up && epochMs(p.last_flapped) ? Date.now() - epochMs(p.last_flapped) : ''),
    },
    { key: 'xcvr_model', label: 'Transceiver model', get: (p) => p.xcvr_model, na: 'xcvr' },
    { key: 'xcvr_part_number', label: 'Transceiver part', get: (p) => p.xcvr_part_number, na: 'xcvr' },
    { key: 'xcvr_serial', label: 'Transceiver serial', get: (p) => p.xcvr_serial, mono: true, na: 'xcvr' },
    {
      key: 'member',
      label: 'Member (FPC)',
      get: (p) => (p.fpc == null ? '' : `FPC ${p.fpc}`),
      sort: (p) => p.fpc ?? '',
    },
    {
      key: 'lag',
      label: 'LAG',
      get: (p) => p.lag_parent || ((p.lag_members || []).length ? `${p.lag_members.length} members` : ''),
    },
    { key: 'critical', label: 'Up/down alerts', get: (p) => (p.config?.critical ? 'On' : '') },
    { key: 'config_source', label: 'Config source', get: (p) => p.config_source },
    { key: 'kind', label: 'Interface type', get: (p) => p.kind },
    {
      key: 'active',
      label: 'Active traffic',
      get: (p) => (p.active === true ? 'Yes' : p.active === false ? 'No' : ''),
    },
  ];
  // Mist fields already represented by a column above (other raw keys are offered as "Mist: <key>").
  const RAW_COVERED = new Set(
    'port_id up speed full_duplex poe_on poe_disabled poe_mode poe_priority power_draw auth_state stp_state stp_role mac port_mac neighbor_mac neighbor_system_name neighbor_port_desc neighbor_mgmt_addr neighbor_system_desc vlan_id vlan usage port_usage description port_desc rx_bytes tx_bytes rx_pkts tx_pkts rx_bps tx_bps rx_errors tx_errors rx_fcserrors rx_bcast_pkts tx_bcast_pkts rx_mcast_pkts tx_mcast_pkts mac_count mac_limit mtu poe_class poe_status xcvr_model xcvr_serial xcvr_part_number last_flapped active disabled org_id site_id timestamp for_site'.split(
      ' ',
    ),
  );
  function rawValue(v) {
    if (v == null) return '';
    if (typeof v === 'object') return JSON.stringify(v).slice(0, 120);
    return String(v);
  }
  function catalog() {
    const extra = new Set();
    ports.forEach((p) => Object.keys(p.raw || {}).forEach((k) => RAW_COVERED.has(k) || extra.add(k)));
    return [
      ...COLUMNS,
      ...[...extra].sort().map((k) => ({
        key: `raw:${k}`,
        label: `Mist: ${k}`,
        get: (p) => rawValue(p.raw?.[k]),
        sort: (p) => (typeof p.raw?.[k] === 'number' ? p.raw[k] : rawValue(p.raw?.[k])),
      })),
    ];
  }
  function loadCols() {
    try {
      const saved = JSON.parse(localStorage.getItem(COLS_KEY) || 'null');
      if (Array.isArray(saved?.visible) && saved.visible.length) return saved.visible.map(String);
    } catch {
      /* storage unavailable: defaults */
    }
    return [...DEFAULT_COLS];
  }
  let visibleCols = loadCols();
  function saveCols() {
    try {
      localStorage.setItem(COLS_KEY, JSON.stringify({ visible: visibleCols }));
    } catch {
      /* private mode / blocked storage: keep the choice for this session only */
    }
  }
  function activeCols() {
    const all = new Map(catalog().map((c) => [c.key, c]));
    const out = visibleCols.map((k) => all.get(k)).filter(Boolean);
    if (!out.some((c) => c.key === 'port')) out.unshift(all.get('port'));
    return out;
  }
  // Empty cell: muted mark with the reason (n/a = does not apply to this kind of port).
  function naCell(p, col) {
    const reason = col.na ? p.not_applicable?.[col.na] : '';
    if (!reason) return `<td class="ops-empty" data-sort="">—</td>`;
    const text = /disabled in the port/i.test(reason)
      ? 'off'
      : p.kind !== 'physical' || /no PoE$|not PoE-capable|Fibre/i.test(reason)
        ? 'n/a'
        : '—';
    return `<td data-sort=""><span class="ops-na" title="${opsEsc(reason)}" aria-label="${opsEsc(`${text}: ${reason}`)}">${text}</span></td>`;
  }
  function cellHtml(p, col) {
    if (col.html) {
      const inner = col.html(p);
      if (!inner && col.na) return naCell(p, col);
      const s = col.sort ? col.sort(p) : '';
      return `<td data-sort="${opsEsc(s ?? '')}">${inner || '—'}</td>`;
    }
    const text = col.get(p);
    if (text === '' || text == null) return naCell(p, col);
    const sortVal = col.sort ? col.sort(p) : null;
    const attrs = [
      sortVal != null ? `data-sort="${opsEsc(sortVal)}"` : '',
      col.mono || col.cls ? `class="${col.mono ? 'mono' : ''} ${col.cls ? col.cls(p) : ''}"` : '',
      col.title ? `title="${opsEsc(col.title(p))}"` : '',
    ]
      .filter(Boolean)
      .join(' ');
    return `<td ${attrs}>${opsEsc(text)}</td>`;
  }
  function portCell(p) {
    const lagChip = p.lag_parent ? ` <span class="chip ops-chip">LAG ${opsEsc(p.lag_parent)}</span>` : '';
    const members = p.lag_members || [];
    const up = (p.lag_neighbors || []).filter((m) => m.up).length;
    const lagLine = members.length
      ? `<small class="muted ops-sub">${members.length} member${members.length === 1 ? '' : 's'}${(p.lag_neighbors || []).length ? ` (${up} up)` : ''}: ${opsEsc(members.join(', '))}</small>`
      : '';
    return `<strong>${opsEsc(p.port_id)}</strong>${lagChip}${lagLine}`;
  }
  function neighborCell(p) {
    const name = deviceName(p);
    if (!name) return '';
    const extra = (p.client_count || 0) > 1 ? ` +${p.client_count - 1} more` : '';
    const secondary = p.neighbor_system_name ? p.neighbor_port_desc : '';
    return `${opsEsc(name)}${opsEsc(extra)}${secondary ? `<small class="muted ops-sub">${opsEsc(secondary)}</small>` : ''}`;
  }
  function issueSort(p) {
    const w = worstIssue(p);
    return w ? `${SEV_RANK[w.severity] ?? 3}${w.label}` : '';
  }
  function issuesCell(p) {
    const list = p.issues || [];
    if (!list.length) return '<span class="ops-ok" title="No problems detected on this port">OK</span>';
    return list
      .map(
        (i) =>
          `<span class="ops-issue sev-${opsEsc(i.severity)}" title="${opsEsc(i.detail)}">${opsEsc(i.label)}</span>`,
      )
      .join(' ');
  }
  function renderPort(p, cols) {
    return `<tr data-port="${opsEsc(p.port_id)}" class="ops-row${selection.includes(p.port_id) ? ' selected-row' : ''}">${cols.map((c) => cellHtml(p, c)).join('')}</tr>`;
  }
  // The whole table is rebuilt when the columns change so table-tools wires the new headers.
  let builtCols = '';
  function buildTable(cols) {
    const sig = cols.map((c) => c.key).join('|');
    if (sig === builtCols && document.querySelector('#opsPortRows')) return;
    builtCols = sig;
    const wrap = document.querySelector('#opsTableWrap');
    if (!wrap) return;
    wrap.innerHTML = `<table id="opsPortTable"><thead><tr>${cols
      .map((c) => `<th scope="col" data-col="${opsEsc(c.key)}">${opsEsc(c.label)}</th>`)
      .join('')}</tr></thead><tbody id="opsPortRows"></tbody></table>`;
  }
  function render() {
    const cols = activeCols();
    buildTable(cols);
    let rows = [...ports];
    const q = (document.querySelector('#opsSearch')?.value || '').trim().toLowerCase();
    const speed = document.querySelector('#opsSpeedFilter')?.value || '';
    const poe = document.querySelector('#opsPoeFilter')?.value || '';
    const sort = document.querySelector('#opsSort')?.value || 'port';
    const showInternal = Boolean(document.querySelector('#opsShowInternal')?.checked);
    const hidden = showInternal ? 0 : rows.filter((p) => p.internal).length;
    if (!showInternal) rows = rows.filter((p) => !p.internal);
    if (q)
      rows = rows.filter((p) =>
        `${searchable(p)} ${cols
          .filter((c) => c.get)
          .map((c) => c.get(p))
          .join(' ')} ${(p.issues || []).map((i) => i.label).join(' ')}`
          .toLowerCase()
          .includes(q),
      );
    if (speed) rows = rows.filter((p) => Math.round(speedOf(p)) === Number(speed));
    if (poe === 'powered') rows = rows.filter(isPowered);
    if (poe === 'unpowered') rows = rows.filter((p) => !isPowered(p));
    if (sort === 'speed_desc') rows.sort((a, b) => speedOf(b) - speedOf(a));
    else if (sort === 'speed_asc') rows.sort((a, b) => speedOf(a) - speedOf(b));
    else if (sort === 'poe_desc')
      rows.sort((a, b) => (Number(b.poe_watts) || 0) - (Number(a.poe_watts) || 0));
    else if (sort === 'neighbor')
      rows.sort((a, b) => String(deviceName(a)).localeCompare(String(deviceName(b))));
    else
      rows.sort((a, b) =>
        String(a.port_id || '').localeCompare(String(b.port_id || ''), undefined, { numeric: true }),
      );
    document.querySelector('#opsPortRows').innerHTML =
      rows.map((p) => renderPort(p, cols)).join('') ||
      `<tr><td colspan="${cols.length}">${ports.length ? 'No ports match the current filter.' : 'Select a switch to see its ports.'}</td></tr>`;
    const total = ports.length - hidden;
    document.querySelector('#opsState').textContent =
      `${rows.length} of ${total} ports` + (hidden ? ` · ${hidden} internal hidden` : '');
  }
  function renderWarnings(list) {
    const box = document.querySelector('#opsWarnings');
    if (!box) return;
    box.innerHTML = (list || []).map((w) => `<div class="notice warning">${opsEsc(w)}</div>`).join('');
  }
  let loadedKey = ''; // site|switch whose ports (and profiles) are on screen
  async function load(fresh = false) {
    device = document.querySelector('#opsSwitch').value;
    syncMode();
    if (!site || !device) return;
    const state = document.querySelector('#opsState');
    state.textContent = 'Loading ports…';
    try {
      const d = await j(
        `/api/v1/operations/ports?site_id=${encodeURIComponent(site)}&device_id=${encodeURIComponent(device)}&fresh=${fresh}`,
      );
      if (d.switch?.id && d.switch.id !== document.querySelector('#opsSwitch').value) return; // switched meanwhile
      document.querySelector('#opsSwitchMeta').textContent = [d.switch.name, d.switch.model, d.switch.version]
        .filter(Boolean)
        .join(' · ');
      switchInfo = d.switch;
      ports = d.ports || [];
      members = d.members || [];
      renderWarnings(d.warnings);
      render();
      if (selected && !ports.some((p) => p.port_id === selected)) selected = '';
      selection = selection.filter((pid) => ports.some((p) => p.port_id === pid));
      renderFaceplate(d.switch);
      // v0.10.40: profiles and the edit form only when another switch was loaded; the 30 s refresh of the
      // same switch used to re-request the profiles and refill the form (losing unsaved edits).
      const key = `${site}|${device}`;
      if (key !== loadedKey) {
        loadedKey = key;
        loadProfiles();
        if (selection.length) fillForm();
      }
    } catch (err) {
      ports = [];
      renderWarnings([`Unable to load ports: ${err.message}`]);
      render();
    }
  }
  // ---- Port details dialog: human labels only, rows without a value are omitted.
  const fmtNum = (v) => (v == null || v === '' ? '' : Number(v).toLocaleString());
  function fmtBps(v) {
    const n = Number(v);
    if (v == null || v === '' || !Number.isFinite(n)) return '';
    if (n >= 1e9) return `${(n / 1e9).toFixed(2)} Gbps`;
    if (n >= 1e6) return `${(n / 1e6).toFixed(1)} Mbps`;
    if (n >= 1e3) return `${(n / 1e3).toFixed(1)} kbps`;
    return `${n} bps`;
  }
  function fmtBytes(v) {
    const n = Number(v);
    if (!n) return '';
    const units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
    let i = 0,
      x = n;
    while (x >= 1024 && i < units.length - 1) {
      x /= 1024;
      i += 1;
    }
    return `${x.toFixed(i ? 1 : 0)} ${units[i]}`;
  }
  function fmtTime(epoch) {
    const n = Number(epoch);
    if (!n) return '';
    const d = new Date(n > 1e12 ? n : n * 1000);
    const mins = Math.round((Date.now() - d.getTime()) / 60000);
    let ago = '';
    if (mins >= 0 && mins < 60) ago = `${mins} min ago`;
    else if (mins >= 60 && mins < 2880) ago = `${Math.round(mins / 60)} h ago`;
    else if (mins >= 2880) ago = `${Math.round(mins / 1440)} days ago`;
    return `${d.toLocaleString()}${ago ? ` (${ago})` : ''}`;
  }
  function pair(a, b, sep = ' / ') {
    return [a, b].filter((x) => x !== '' && x != null).join(sep);
  }
  function detailSection(title, rows) {
    const items = rows.filter(([, v]) => v !== '' && v != null && v !== false);
    if (!items.length) return '';
    return `<section class="ops-detail-section"><h4>${opsEsc(title)}</h4><dl class="ops-detail-list">${items
      .map(([k, v]) => `<dt>${opsEsc(k)}</dt><dd>${opsEsc(v)}</dd>`)
      .join('')}</dl></section>`;
  }
  function showDetails(pid) {
    showPortDetails(ports.find((x) => x.port_id === pid));
  }
  // Also used by Power Guard (same normalized port objects from /api/v1/operations/ports).
  function showPortDetails(p) {
    const dlg = document.querySelector('#opsPortDialog');
    if (!p || !dlg) return;
    const duplex = p.full_duplex === true ? 'Full duplex' : p.full_duplex === false ? 'Half duplex' : '';
    const errors =
      p.rx_errors != null || p.tx_errors != null
        ? `${fmtNum(p.rx_errors || 0)} / ${fmtNum(p.tx_errors || 0)}`
        : '';
    const packets =
      p.rx_pkts != null || p.tx_pkts != null ? `${fmtNum(p.rx_pkts || 0)} / ${fmtNum(p.tx_pkts || 0)}` : '';
    const util =
      p.utilisation_pct != null
        ? `${p.utilisation_pct}% (receive ${fmtBps(p.rx_bps) || '0 bps'}, transmit ${fmtBps(p.tx_bps) || '0 bps'})`
        : pair(fmtBps(p.rx_bps), fmtBps(p.tx_bps));
    const poeState = p.poe_disabled ? 'Disabled' : isPowered(p) ? 'Delivering power' : '';
    const draw = isPowered(p) ? `${(Number(p.poe_watts) || 0).toFixed(1)} W` : '';
    const lag = p.lag_parent
      ? `Member of ${p.lag_parent}`
      : (p.lag_members || []).length
        ? `${p.lag_members.length} members (${p.lag_members.join(', ')})`
        : '';
    const issues = (p.issues || []).map((i) => [i.label, `${i.severity}: ${i.detail}`]);
    const lagRows = (p.lag_neighbors || []).map((m) => [
      m.member,
      [m.up == null ? '' : m.up ? 'Up' : 'Down', m.speed, pair(m.system_name, m.port_desc, ' · ')]
        .filter(Boolean)
        .join(' · ') || 'No LLDP neighbor reported',
    ]);
    const naLabels = {
      poe: 'PoE',
      auth: 'Authentication',
      mac: 'MAC',
      neighbor: 'Neighbor',
      xcvr: 'Transceiver',
      speed: 'Speed',
    };
    const naRows = Object.entries(p.not_applicable || {}).map(([k, v]) => [naLabels[k] || k, v]);
    const html = [
      detailSection('Issues detected', issues),
      detailSection('Link', [
        ['Status', p.up ? 'Up' : 'Down'],
        ['Speed / duplex', pair(p.speed, duplex, ' · ')],
        ['Profile / usage', p.usage],
        ['Description', p.description],
        ['VLAN', p.vlan_id],
        ['Aggregated link', lag],
        ['Last flap', fmtTime(p.last_flapped)],
        ['MTU', fmtNum(p.mtu)],
        ['Networks', (p.networks || []).join(', ')],
        ['IP addresses', (p.ips || []).join(', ')],
        ['Interface type', p.internal ? 'Internal / management interface' : p.kind || ''],
      ]),
      detailSection('LAG member links', lagRows),
      detailSection('Security & spanning tree', [
        ['Authentication', p.auth_state],
        ['STP state', p.stp_state],
        ['STP role', p.stp_role],
        [
          'MAC addresses learned',
          pair(fmtNum(p.mac_count), p.mac_limit ? `limit ${fmtNum(p.mac_limit)}` : '', ' · '),
        ],
      ]),
      detailSection('Power over Ethernet', [
        ['PoE', poeState],
        ['Mode', p.poe_mode],
        ['Priority', p.poe_priority],
        ['Current draw', draw],
      ]),
      detailSection('Traffic', [
        ['Utilisation', util],
        ['Packets (receive / transmit)', packets],
        ['Data (receive / transmit)', pair(fmtBytes(p.rx_bytes), fmtBytes(p.tx_bytes))],
        ['Errors (receive / transmit)', errors],
        ['CRC / FCS errors', fmtNum(p.crc_errors)],
      ]),
      detailSection('Transceiver', [
        ['Model', p.xcvr_model],
        ['Serial number', p.xcvr_serial],
        ['Part number', p.xcvr_part_number],
      ]),
      detailSection('LLDP neighbor', [
        ['System name', p.neighbor_system_name],
        ['Port', p.neighbor_port_desc],
        ['MAC address', p.neighbor_mac],
        ['Management IP', p.neighbor_mgmt_ip],
        ['Manufacturer', p.manufacturer],
      ]),
      detailSection('Why some fields are empty', naRows),
    ].join('');
    const clients = p.clients || [];
    const clientTable = clients.length
      ? `<section class="ops-detail-section ops-detail-wide"><h4>Wired clients on this port (${clients.length})</h4><div class="table-wrap"><table><thead><tr><th>MAC</th><th>Hostname</th><th>Manufacturer</th><th>IP address</th><th>VLAN</th></tr></thead><tbody>${clients
          .map(
            (c) =>
              `<tr><td class="mono">${opsEsc(c.mac)}</td><td>${opsEsc(c.hostname || '—')}</td><td>${opsEsc(c.manufacturer || '—')}</td><td class="mono">${opsEsc(c.ip || '—')}</td><td>${opsEsc(c.vlan || '—')}</td></tr>`,
          )
          .join('')}</tbody></table></div></section>`
      : '';
    document.querySelector('#opsPortDialogTitle').textContent = p.port_id;
    document.querySelector('#opsPortDialogBody').innerHTML =
      html + clientTable || '<p class="muted">Mist returned no details for this port.</p>';
    if (!dlg.open) dlg.showModal();
  }
  // ---------------------------------------------------------------- faceplate
  const PHYS = /^(ge|mge|xe|et|mxe|ce|xle|fte)-(\d+)\/(\d+)\/(\d+)(?::(\d+))?$/i;
  const parsePort = (pid) => {
    const m = PHYS.exec(pid || '');
    return m ? { type: m[1].toLowerCase(), fpc: +m[2], pic: +m[3], num: +m[4], chan: m[5] } : null;
  };
  const roleLabel = (r) =>
    ({ master: 'Primary', backup: 'Backup', linecard: 'Member' })[String(r || '').toLowerCase()] || 'Member';
  const isUplinkPort = (p) =>
    /uplink|trunk|vc/i.test(p.usage || p.config?.usage || '') ||
    Boolean(p.lag_parent) ||
    parsePort(p.port_id)?.pic > 0;
  function groupLabel(pic, type) {
    if (pic === 0) return type === 'mge' ? 'RJ-45 multigig' : type === 'ge' ? 'RJ-45' : type.toUpperCase();
    return { xe: 'SFP+', et: 'QSFP28', ge: 'SFP', mge: 'RJ-45', xle: 'QSFP+' }[type] || type.toUpperCase();
  }
  // Every Virtual Chassis member is drawn at once, stacked like the physical stack.
  const portLabel = (k) => k.num + (k.chan ? `:${k.chan}` : '');
  function isUnused(p) {
    const u = usageOf(p);
    return (
      !p.up &&
      (!u || u === 'default') &&
      !(p.config?.description ?? p.description) &&
      !p.neighbor_system_name &&
      !p.neighbor_mac &&
      !(p.client_count > 0) &&
      !isPowered(p) &&
      !p.lag_parent
    );
  }
  function portTile(x) {
    if (!x) return '<span class="ops-port ops-port-empty" aria-hidden="true"></span>';
    const p = x.p;
    const issue = (p.issues || []).some((i) => i.severity !== 'info') ? worstIssue(p) : null;
    const disabled = usageOf(p) === 'disabled' || p.admin_disabled;
    const unused = !disabled && isUnused(p);
    const cls = [
      'ops-port',
      p.up ? 'up' : 'down',
      unused ? 'unused' : '',
      isPowered(p) ? 'poe' : '',
      isUplinkPort(p) ? 'uplink' : '',
      selection.includes(p.port_id) ? 'selected' : '',
      disabled ? 'disabled' : '',
      issue ? `issue sev-${issue.severity}` : '',
    ]
      .filter(Boolean)
      .join(' ');
    const tip = [
      p.port_id,
      p.up ? 'Up' : disabled ? 'Disabled' : unused ? 'Down · unused' : 'Down',
      p.speed,
      usageOf(p) ? `profile ${usageOf(p)}` : '',
      isPowered(p) ? `PoE ${(Number(p.poe_watts) || 0).toFixed(1)} W` : '',
      deviceName(p),
      p.config?.description ?? p.description,
      ...(p.issues || []).map((i) => `⚠ ${i.label}: ${i.detail}`),
    ]
      .filter(Boolean)
      .join(' · ');
    const icon = isUplinkPort(p) && p.up ? '↑' : isPowered(p) ? 'ϟ' : '';
    return `<button type="button" class="${cls}" data-port="${opsEsc(p.port_id)}" title="${opsEsc(tip)}" aria-pressed="${selection.includes(p.port_id)}" aria-label="${opsEsc(tip)}"><span class="ops-port-icon" aria-hidden="true">${icon}</span></button>`;
  }
  function portGroup(pic, type, list) {
    list.sort((a, b) => a.k.num - b.k.num || String(a.k.chan || '').localeCompare(String(b.k.chan || '')));
    // Pairs: even port on top, odd below, like the front panel; a gap every 12 ports.
    // Channelized ports (et-0/1/0:0-3) get two columns per parent port.
    const channelized = list.some((x) => x.k.chan);
    const cols = [];
    list.forEach((x) => {
      const ch = Number(x.k.chan || 0);
      const col = channelized ? x.k.num * 2 + Math.floor(ch / 2) : Math.floor(x.k.num / 2);
      let c = cols.find((y) => y.col === col);
      if (!c) cols.push((c = { col, top: null, bottom: null }));
      if ((channelized ? ch : x.k.num) % 2 === 0 && !c.top) c.top = x;
      else c.bottom = c.bottom || x;
    });
    cols.sort((a, b) => a.col - b.col);
    const blocks = [];
    cols.forEach((c, i) => {
      if (i && c.col % 6 === 0 && pic === 0) blocks.push('<span class="ops-gap" aria-hidden="true"></span>');
      blocks.push(
        `<span class="ops-col"><small>${c.top ? portLabel(c.top.k) : ''}</small>${portTile(c.top)}${portTile(c.bottom)}<small>${c.bottom ? portLabel(c.bottom.k) : ''}</small></span>`,
      );
    });
    return `<div class="ops-port-group"><span class="ops-group-label">${opsEsc(groupLabel(pic, type))}</span><div class="ops-port-cols">${blocks.join('')}</div></div>`;
  }
  function memberSummary(list, info) {
    const total = list.length;
    const up = list.filter((x) => x.p.up).length;
    const poe = list.filter((x) => isPowered(x.p));
    const watts = poe.reduce((s, x) => s + (Number(x.p.poe_watts) || 0), 0);
    const unused = list.filter((x) => isUnused(x.p) && !x.p.admin_disabled).length;
    const issues = list.filter((x) => (x.p.issues || []).some((i) => i.severity !== 'info')).length;
    const budget = Number(info?.poe_max_watts) || 0;
    const bits = [
      `<span><b>${up}</b>/${total} up</span>`,
      poe.length || budget
        ? `<span>PoE <b>${watts.toFixed(1)}</b>${budget ? ` / ${budget.toFixed(0)}` : ''} W · ${poe.length} powered</span>`
        : '',
      `<span>${unused} unused</span>`,
      issues ? `<span class="ops-member-issues">${issues} with issues</span>` : '',
    ];
    return bits.filter(Boolean).join('<i aria-hidden="true">·</i>');
  }
  function renderFaceplate(sw) {
    const card = document.querySelector('#opsFaceplateCard');
    const host = document.querySelector('#opsFaceplate');
    if (!card || !host) return;
    const phys = ports.map((p) => ({ p, k: parsePort(p.port_id) })).filter((x) => x.k);
    card.classList.toggle('hidden', !phys.length || !device);
    if (!phys.length) return;
    document.querySelector('#opsFaceplateTitle').textContent = sw?.name || switchInfo?.name || 'Switch';
    const fpcs = [...new Set(phys.map((x) => x.k.fpc))].sort((a, b) => a - b);
    if (member !== null && !fpcs.includes(member)) member = null;
    // Quick filter: all members stacked (default) or one member.
    const tabs = document.querySelector('#opsMemberTabs');
    tabs.innerHTML =
      fpcs.length > 1
        ? `<button type="button" role="tab" class="ops-member-tab" data-fpc="" aria-selected="${member === null}">All ${fpcs.length} members</button>` +
          fpcs
            .map((f) => {
              const m = members.find((x) => x.fpc === f);
              return `<button type="button" role="tab" class="ops-member-tab" data-fpc="${f}" aria-selected="${f === member}"><b>${f}</b>${opsEsc(roleLabel(m?.role))}</button>`;
            })
            .join('')
        : '';
    tabs.classList.toggle('hidden', fpcs.length < 2);
    tabs.querySelectorAll('[data-fpc]').forEach((b) =>
      b.addEventListener('click', () => {
        member = b.dataset.fpc === '' ? null : Number(b.dataset.fpc);
        renderFaceplate(sw);
      }),
    );
    const shown = member === null ? fpcs : [member];
    host.innerHTML = shown
      .map((fpc) => {
        const mine = phys.filter((x) => x.k.fpc === fpc);
        const info = members.find((x) => x.fpc === fpc);
        const groups = new Map();
        mine.forEach((x) => {
          const key = `${x.k.pic}|${x.k.type}`;
          if (!groups.has(key)) groups.set(key, []);
          groups.get(key).push(x);
        });
        const keys = [...groups.keys()].sort((a, b) => Number(a.split('|')[0]) - Number(b.split('|')[0]));
        const role = info ? roleLabel(info.role) : fpcs.length > 1 ? 'Member' : '';
        const roleCls =
          String(info?.role || '').toLowerCase() === 'master'
            ? 'primary'
            : String(info?.role || '').toLowerCase();
        const head = `<div class="ops-member-head"><span class="ops-member-badge">FPC ${fpc}</span>${role ? `<span class="ops-member-role role-${opsEsc(roleCls)}">${opsEsc(role)}</span>` : ''}<span class="ops-member-model">${opsEsc(info?.model || (fpcs.length === 1 ? sw?.model || '' : ''))}</span><span class="ops-member-sum">${memberSummary(mine, info)}</span></div>`;
        const body = keys
          .map((key) => {
            const [pic, type] = key.split('|');
            return portGroup(Number(pic), type, groups.get(key));
          })
          .join('');
        return `<section class="ops-member" data-fpc="${fpc}" aria-label="FPC ${fpc}${role ? ` ${opsEsc(role)}` : ''}">${head}<div class="ops-member-ports">${body}</div></section>`;
      })
      .join('');
    host
      .querySelectorAll('.ops-port[data-port]')
      .forEach((b) => b.addEventListener('click', (e) => clickPort(b.dataset.port, e)));
  }
  // Port order for Shift-click ranges: member, module, port (works across stacked members).
  function orderedIds() {
    return ports
      .map((p) => ({ id: p.port_id, k: parsePort(p.port_id) }))
      .filter((x) => x.k)
      .sort(
        (a, b) =>
          a.k.fpc - b.k.fpc ||
          a.k.pic - b.k.pic ||
          a.k.num - b.k.num ||
          String(a.k.chan || '').localeCompare(String(b.k.chan || '')) ||
          a.k.type.localeCompare(b.k.type),
      )
      .map((x) => x.id);
  }
  function clickPort(pid, e) {
    if (e.shiftKey && anchor) {
      const ids = orderedIds();
      const [i, j] = [ids.indexOf(anchor), ids.indexOf(pid)].sort((x, y) => x - y);
      const range = ids.slice(i, j + 1);
      selectPorts([...new Set([...(e.ctrlKey || e.metaKey ? selection : []), ...range])], false);
      return;
    }
    anchor = pid;
    if (e.ctrlKey || e.metaKey)
      selectPorts(selection.includes(pid) ? selection.filter((x) => x !== pid) : [...selection, pid]);
    else selectPorts([pid]);
  }

  // "ge-0/0/1-3, ge-0/0/7" <-> ['ge-0/0/1','ge-0/0/2','ge-0/0/3','ge-0/0/7']
  function collapse(ids) {
    const groups = new Map();
    const out = [];
    ids.forEach((pid) => {
      const m = /^(.*\/)(\d+)$/.exec(pid);
      if (!m) return out.push(pid);
      if (!groups.has(m[1])) groups.set(m[1], []);
      groups.get(m[1]).push(+m[2]);
    });
    groups.forEach((nums, prefix) => {
      nums.sort((a, b) => a - b);
      let start = nums[0],
        prev = nums[0];
      nums
        .slice(1)
        .concat([null])
        .forEach((n) => {
          if (n !== null && n === prev + 1) return (prev = n);
          out.push(start === prev ? `${prefix}${start}` : `${prefix}${start}-${prev}`);
          start = prev = n;
        });
    });
    return out.join(', ');
  }
  function expand(text) {
    const known = new Set(ports.map((p) => p.port_id.toLowerCase()));
    const out = [];
    for (const raw of String(text || '')
      .split(/[,\s]+/)
      .filter(Boolean)) {
      const m = /^(.*\/)(\d+)-(\d+)$/.exec(raw.toLowerCase());
      const list =
        m && +m[3] >= +m[2] && +m[3] - +m[2] <= 128
          ? Array.from({ length: +m[3] - +m[2] + 1 }, (_, i) => `${m[1]}${+m[2] + i}`)
          : [raw.toLowerCase()];
      for (const pid of list) {
        if (!known.has(pid)) return { error: `Invalid port ID range: ${raw}` };
        const real = ports.find((p) => p.port_id.toLowerCase() === pid).port_id;
        if (!out.includes(real)) out.push(real);
      }
    }
    return { ids: out };
  }

  function selectPorts(ids, setAnchor = true) {
    selection = ids;
    selected = ids[0] || '';
    if (setAnchor && ids.length === 1) anchor = ids[0];
    document.querySelectorAll('#opsFaceplate .ops-port[data-port]').forEach((b) => {
      const on = selection.includes(b.dataset.port);
      b.classList.toggle('selected', on);
      b.setAttribute('aria-pressed', String(on));
    });
    document
      .querySelectorAll('#opsPortRows tr')
      .forEach((r) => r.classList.toggle('selected-row', selection.includes(r.dataset.port)));
    const panel = document.querySelector('#opsActionPanel');
    panel.classList.toggle('hidden', !selection.length);
    if (selection.length) fillForm();
    if (device && !window.MistApp?.isRestoringView?.()) navPush(true);
  }
  function select(pid) {
    selectPorts(pid ? [pid] : []);
  }

  const radio = (name) => document.querySelector(`input[name="${name}"]:checked`)?.value || '';
  function setRadio(name, value) {
    document.querySelectorAll(`input[name="${name}"]`).forEach((r) => (r.checked = r.value === value));
  }
  // Shared value across the selected ports, or undefined when they differ.
  function common(get) {
    const vals = selection.map((pid) => get(ports.find((p) => p.port_id === pid) || {}));
    return vals.every((v) => v === vals[0]) ? vals[0] : undefined;
  }
  function fillForm() {
    document.querySelector('#opsSelected').textContent =
      selection.length === 1 ? selection[0] : `${selection.length} ports`;
    document.querySelector('#opsPortIds').value = collapse(selection);
    const src = common((p) => p.config_source);
    document.querySelector('#opsConfigSource').textContent =
      src === 'inherited'
        ? 'Settings inherited from the site or template; saving creates a switch-level override.'
        : src === 'switch'
          ? 'Configured on this switch.'
          : 'Mixed: some ports have switch-level settings.';
    const usage = common((p) => p.config?.usage || p.usage || '');
    const sel = document.querySelector('#opsUsage');
    renderProfileOptions(usage === undefined ? '__mixed__' : usage);
    document.querySelector('#opsDynamic').checked =
      common((p) => p.config?.dynamic_usage === 'dynamic') === true;
    const desc = common((p) => p.config?.description ?? p.description ?? '');
    const descEl = document.querySelector('#opsDescription');
    descEl.value = desc === undefined ? '' : desc;
    descEl.placeholder =
      desc === undefined ? '(different on the selected ports — leave empty to keep)' : 'Add Description';
    const crit = common((p) => Boolean(p.config?.critical));
    setRadio('opsCritical', crit === undefined ? '' : crit ? 'on' : 'off');
    const aggr = common((p) => Boolean(p.config?.aggregated));
    setRadio('opsAggr', aggr === undefined ? '' : aggr ? 'on' : 'off');
    const ae = common((p) => p.config?.ae_idx ?? '');
    document.querySelector('#opsAeIdx').value = ae === undefined ? '' : ae;
    const op = common((p) => !p.config?.no_local_overwrite);
    setRadio('opsOperator', op === undefined ? '' : op ? 'yes' : 'no');
    document.querySelector('#opsAeIdx').classList.toggle('hidden', radio('opsAggr') !== 'on');
    snapshot = formValues();
    void sel;
    hideError();
    document.querySelector('#opsChangePreview').classList.add('hidden');
    updateDirty();
  }
  function formValues() {
    return {
      usage: document.querySelector('#opsUsage').value,
      dynamic: document.querySelector('#opsDynamic').checked,
      description: document.querySelector('#opsDescription').value,
      critical: radio('opsCritical'),
      aggr: radio('opsAggr'),
      ae: document.querySelector('#opsAeIdx').value,
      operator: radio('opsOperator'),
    };
  }
  // Only fields the user actually changed are sent to Mist.
  function changes() {
    const now = formValues();
    const out = {};
    if (!snapshot) return out;
    if (now.usage !== snapshot.usage && now.usage && now.usage !== '__mixed__') out.usage = now.usage;
    if (now.dynamic !== snapshot.dynamic) out.dynamic_usage = now.dynamic;
    if (now.description !== snapshot.description && (now.description || snapshot.description))
      out.description = now.description;
    if (now.critical !== snapshot.critical && now.critical) out.critical = now.critical === 'on';
    if ((now.aggr !== snapshot.aggr && now.aggr) || (now.aggr === 'on' && now.ae !== snapshot.ae)) {
      out.aggregated = now.aggr === 'on';
      if (out.aggregated) out.ae_idx = Number(now.ae);
    }
    if (now.operator !== snapshot.operator && now.operator) out.no_local_overwrite = now.operator === 'no';
    return out;
  }
  function updateDirty() {
    const n = Object.keys(changes()).length;
    const btn = document.querySelector('#opsApplyProfile');
    btn.disabled = !n || !selection.length;
    btn.textContent = n ? `Review ${n} change${n === 1 ? '' : 's'}` : 'No changes yet';
  }
  function showError(msg) {
    const e = document.querySelector('#opsConfigError');
    e.textContent = msg;
    e.classList.remove('hidden');
  }
  function hideError() {
    document.querySelector('#opsConfigError').classList.add('hidden');
  }

  async function loadProfiles() {
    profiles = [];
    renderProfileOptions(document.querySelector('#opsUsage')?.value || '');
    try {
      profiles = await j(
        `/api/v1/operations/port-profiles?site_id=${encodeURIComponent(site)}&device_id=${encodeURIComponent(device)}`,
      );
    } catch (err) {
      profiles = [];
      console.warn('Port profiles unavailable', err);
    }
    if (selection.length) fillForm();
    else renderProfileOptions('');
  }
  function renderProfileOptions(current) {
    const sel = document.querySelector('#opsUsage');
    if (!sel) return;
    const names = profiles.map((p) => p.name);
    const extra =
      current && current !== '__mixed__' && !names.includes(current) ? [{ name: current, summary: '' }] : [];
    sel.innerHTML =
      (current === '__mixed__'
        ? '<option value="__mixed__">— different on the selected ports —</option>'
        : '') +
      (!current ? '<option value="">— inherited / not set —</option>' : '') +
      [...profiles, ...extra]
        .map(
          (p) =>
            `<option value="${opsEsc(p.name)}">${opsEsc(p.name)}${p.summary ? ` — ${opsEsc(p.summary)}` : ''}</option>`,
        )
        .join('');
    sel.value = current || '';
    const info = profiles.find((p) => p.name === sel.value);
    document.querySelector('#opsUsageSummary').textContent = info?.summary || '';
  }

  async function review() {
    hideError();
    const parsed = expand(document.querySelector('#opsPortIds').value);
    if (parsed.error) return showError(parsed.error);
    if (!parsed.ids.length) return showError('Enter at least one port ID.');
    const ch = changes();
    if (ch.aggregated && !(Number.isInteger(ch.ae_idx) && ch.ae_idx >= 0 && ch.ae_idx <= 127))
      return showError('Enter an AE index between 0 and 127 for the aggregated link.');
    if (!Object.keys(ch).length) return showError('Nothing has changed yet.');
    const box = document.querySelector('#opsChangePreview');
    box.classList.remove('hidden');
    box.innerHTML = '<div class="muted">Checking the ports with Mist…</div>';
    let preview;
    try {
      preview = await j('/api/v1/operations/preview', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          site_id: site,
          device_id: device,
          port_id: parsed.ids[0],
          action: 'profile_update',
          payload: { ...ch, port_ids: parsed.ids },
        }),
      });
    } catch (err) {
      box.innerHTML = '';
      box.classList.add('hidden');
      return showError(`Could not check the change: ${err.message}`);
    }
    const label = {
      usage: 'Profile',
      dynamic_usage: 'Dynamic port configuration',
      description: 'Description',
      critical: 'Up / down port alerts',
      aggregated: 'Port aggregation',
      ae_idx: 'AE index',
      no_local_overwrite: 'Port operator may modify',
    };
    const show = (k, v) =>
      k === 'no_local_overwrite'
        ? v
          ? 'No'
          : 'Yes'
        : typeof v === 'boolean'
          ? v
            ? 'Enabled'
            : 'Disabled'
          : v === ''
            ? '(empty)'
            : String(v);
    const before = (pid, k) => {
      const p = ports.find((x) => x.port_id === pid) || {};
      const c = p.config || {};
      const v =
        k === 'usage'
          ? c.usage || p.usage || 'inherited'
          : k === 'dynamic_usage'
            ? c.dynamic_usage === 'dynamic'
            : k === 'description'
              ? (c.description ?? p.description ?? '')
              : k === 'no_local_overwrite'
                ? Boolean(c.no_local_overwrite)
                : (c[k] ?? (k === 'ae_idx' ? '' : false));
      return show(k, v);
    };
    // One row per setting and current value; ports sharing both are collapsed ("ge-0/0/4-9").
    const groups = new Map();
    Object.entries(ch).forEach(([k, v]) =>
      parsed.ids.forEach((pid) => {
        const was = before(pid, k);
        const key = `${k}\u0000${was}`;
        if (!groups.has(key)) groups.set(key, { k, v, was, ids: [] });
        groups.get(key).ids.push(pid);
      }),
    );
    const rows = [...groups.values()]
      .map(
        (g) =>
          `<tr><td class="mono">${opsEsc(collapse(g.ids))}</td><td>${opsEsc(label[g.k] || g.k)}</td><td class="ops-old">${opsEsc(g.was)}</td><td class="ops-new">${opsEsc(show(g.k, g.v))}</td></tr>`,
      )
      .join('');
    const warn = (preview.warnings || []).map((w) => `<li>${opsEsc(w)}</li>`).join('');
    box.innerHTML = `<strong>Review: ${parsed.ids.length} port${parsed.ids.length === 1 ? '' : 's'} on ${opsEsc(document.querySelector('#opsSwitchMeta')?.textContent || 'this switch')}</strong>
      <div class="table-wrap"><table data-nofilter data-nosort><thead><tr><th>Port</th><th>Setting</th><th>Now</th><th>After</th></tr></thead><tbody>${rows}</tbody></table></div>
      ${warn ? `<ul class="ops-warn-list">${warn}</ul>` : ''}
      ${preview.protected ? '<label class="check-row ops-protected"><input id="opsProtectedOk" type="checkbox"> I understand this changes a protected port and may disconnect devices</label>' : ''}
      <div class="ops-config-actions"><button id="opsConfirmApply" type="button" class="btn primary">Apply to Mist</button><button id="opsCancelApply" type="button" class="btn ghost">Cancel</button></div>
      <small class="muted">The change is written with this NodeWatch's Mist API token, recorded in the Activity Log, and checked afterwards.</small>`;
    box.querySelector('#opsCancelApply').addEventListener('click', () => box.classList.add('hidden'));
    box.querySelector('#opsConfirmApply').addEventListener('click', async () => {
      if (preview.protected && !box.querySelector('#opsProtectedOk')?.checked)
        return showError('Tick the protected-port confirmation first.');
      await apply(parsed.ids, { ...ch, ...(preview.protected ? { allow_protected_port: true } : {}) });
    });
  }
  async function apply(ids, payload) {
    const out = document.querySelector('#opsResult');
    const btn = document.querySelector('#opsConfirmApply');
    if (btn) {
      btn.disabled = true;
      btn.textContent = 'Applying…';
    }
    try {
      const result = await j('/api/v1/operations/execute', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          site_id: site,
          device_id: device,
          port_id: ids[0],
          action: 'profile_update',
          confirmed: true,
          payload: { ...payload, port_ids: ids },
        }),
      });
      out.textContent = result.message || 'Applied.';
      document.querySelector('#opsChangePreview').classList.add('hidden');
      loadedKey = ''; // applied: refill the form and its change baseline from the new state
      await load(true);
    } catch (err) {
      showError(`Not applied: ${err.message}`);
      if (btn) {
        btn.disabled = false;
        btn.textContent = 'Apply to Mist';
      }
    }
  }

  // Bounce / cable test act on one port (the first selected).
  async function execute(action, payload = {}) {
    if (!selected) return alert('Select a port first.');
    const out = document.querySelector('#opsResult');
    try {
      const request = { site_id: site, device_id: device, port_id: selected, action, payload };
      const preview = await j('/api/v1/operations/preview', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(request),
      });
      const warnings = (preview.warnings || []).join('\n• ');
      if (
        !confirm(
          `${action.replace('_', ' ')} on ${selected}?${warnings ? '\n\n• ' + warnings : ''}\n\nThis action will be audited.`,
        )
      )
        return;
      if (preview.protected) {
        if (
          !confirm(
            `${selected} is a protected uplink/VC/management port. Are you absolutely sure you want to change it?`,
          )
        )
          return;
        request.payload = { ...payload, allow_protected_port: true };
      }
      out.textContent = 'Submitting to Mist…';
      const result = await j('/api/v1/operations/execute', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ...request, confirmed: true }),
      });
      out.textContent = result.message || 'Completed';
      loadedKey = ''; // applied: refill the form and its change baseline from the new state
      await load(true);
    } catch (err) {
      out.textContent = `Not applied: ${err.message}`;
    }
  }
  // ---------------------------------------------------------------- port health overview
  // No switch selected: the org-wide (or site-wide) list of the most important port problems.
  function syncMode() {
    const portMode = Boolean(device);
    document.querySelector('#opsOverviewCard')?.classList.toggle('hidden', portMode);
    document.querySelector('#opsPortLayout')?.classList.toggle('hidden', !portMode);
    document.querySelector('#opsFilterBar')?.classList.toggle('hidden', !portMode);
    if (!portMode) {
      document.querySelector('#opsFaceplateCard')?.classList.add('hidden');
      document.querySelector('#opsActionPanel')?.classList.add('hidden');
      renderWarnings([]);
    }
  }
  const sevLabel = { critical: 'Critical', warning: 'Warning', info: 'Info' };
  async function loadOverview(fresh = false) {
    const seq = ++overviewSeq;
    const card = document.querySelector('#opsOverviewCard');
    if (!card) return;
    const siteName = site
      ? document.querySelector('#opsSite')?.selectedOptions?.[0]?.textContent || 'Site'
      : '';
    document.querySelector('#opsOverviewTitle').textContent = site
      ? `Port health · ${siteName}`
      : 'Port health · All sites';
    document.querySelector('#opsOverviewMeta').textContent = 'Checking switch ports…';
    card.setAttribute('aria-busy', 'true');
    try {
      const d = await j(`/api/v1/operations/overview?site_id=${encodeURIComponent(site)}&fresh=${fresh}`);
      if (seq !== overviewSeq) return;
      overview = d;
      renderOverview();
    } catch (err) {
      if (seq !== overviewSeq) return;
      overview = null;
      document.querySelector('#opsOverviewMeta').textContent = '';
      document.querySelector('#opsOverviewTiles').innerHTML = '';
      document.querySelector('#opsOverviewList').innerHTML =
        `<div class="notice warning">Port health is unavailable: ${opsEsc(err.message)}</div>`;
    } finally {
      if (seq === overviewSeq) card.removeAttribute('aria-busy');
    }
  }
  function renderOverview() {
    const d = overview;
    if (!d) return;
    const t = d.totals || {};
    const when = d.generated_at ? new Date(d.generated_at * 1000).toLocaleTimeString() : '';
    document.querySelector('#opsOverviewMeta').textContent = [
      `${nfmt(t.ports || 0)} switch ports on ${nfmt(t.switches || 0)} switch${t.switches === 1 ? '' : 'es'}${d.scope === 'org' ? ` in ${nfmt(t.sites || 0)} site${t.sites === 1 ? '' : 's'}` : ''}`,
      `${nfmt(t.up || 0)} up`,
      t.poe_watts ? `${t.poe_watts} W PoE` : '',
      when ? `checked ${when}${d.cached ? ' (cached)' : ''}` : '',
    ]
      .filter(Boolean)
      .join(' · ');
    const summary = `<button type="button" class="ops-ov-tile ops-ov-total${ovCat ? '' : ' active'}" data-cat="" aria-pressed="${!ovCat}"><b>${nfmt(t.issues || 0)}</b><span>All issues</span><small>${t.critical ? `<em class="sev-critical">${t.critical} critical</em> · ` : ''}${nfmt(t.affected_switches || 0)} switch${t.affected_switches === 1 ? '' : 'es'}</small></button>`;
    document.querySelector('#opsOverviewTiles').innerHTML =
      summary +
      (d.categories || [])
        .map(
          (c) =>
            `<button type="button" class="ops-ov-tile sev-${opsEsc(c.severity)}${ovCat === c.key ? ' active' : ''}" data-cat="${opsEsc(c.key)}" aria-pressed="${ovCat === c.key}" title="${opsEsc(c.description)}"${c.count ? '' : ' disabled'}><b>${c.count ? nfmt(c.count) : '✓'}</b><span>${opsEsc(c.label)}</span>${c.critical ? `<small><em class="sev-critical">${c.critical} critical</em></small>` : ''}</button>`,
        )
        .join('');
    const list = (d.issues || []).filter((i) => !ovCat || i.category === ovCat);
    const box = document.querySelector('#opsOverviewList');
    const warn = (d.warnings || []).map((w) => `<div class="notice warning">${opsEsc(w)}</div>`).join('');
    if (!list.length) {
      box.innerHTML =
        warn +
        `<div class="ops-ov-empty"><b>No port problems found</b><span class="muted">${
          d.scope === 'org' ? 'across the organization' : 'at this site'
        }${ovCat ? ' in this category' : ''}. Select a ${site ? 'switch' : 'site and switch'} to inspect its ports.</span></div>`;
      return;
    }
    // Group by site then switch, keeping the severity order of the first issue in each group.
    // Informational findings stay folded per switch unless a category is chosen or unfolded.
    const groups = new Map();
    const siteOrder = [];
    list.slice(0, ovLimit).forEach((i) => {
      const k = `${i.site_id}|${i.device_id || i.switch_name}`;
      if (!siteOrder.includes(i.site_id)) siteOrder.push(i.site_id);
      if (!groups.has(k))
        groups.set(k, {
          key: k,
          site_id: i.site_id,
          site_name: i.site_name,
          device_id: i.device_id,
          name: i.switch_name,
          rows: [],
          info: [],
        });
      const g = groups.get(k);
      (i.severity === 'info' && !ovCat && !ovInfoOpen.has(k) ? g.info : g.rows).push(i);
    });
    const ordered = [...groups.values()].sort(
      (a, b) => siteOrder.indexOf(a.site_id) - siteOrder.indexOf(b.site_id),
    );
    let lastSite = null;
    const html = [];
    ordered.forEach((g) => {
      if (d.scope === 'org' && g.site_name !== lastSite) {
        lastSite = g.site_name;
        html.push(`<div class="ops-ov-site">${opsEsc(g.site_name)}</div>`);
      }
      const crit = g.rows.filter((r) => r.severity === 'critical').length;
      const total = g.rows.length + g.info.length;
      const infoLabels = [...new Set(g.info.map((r) => r.label))].join(', ');
      const fold = g.info.length
        ? `<button type="button" class="ops-ov-fold" data-info="${opsEsc(g.key)}" aria-expanded="false">+ ${g.info.length} informational finding${g.info.length === 1 ? '' : 's'} <span class="muted">(${opsEsc(infoLabels)})</span></button>`
        : '';
      html.push(
        `<div class="ops-ov-group"><button type="button" class="ops-ov-switch" data-site="${opsEsc(g.site_id)}" data-device="${opsEsc(g.device_id)}" data-name="${opsEsc(g.name)}" title="Open ${opsEsc(g.name)} in the Port Toolkit"><span class="ops-ov-swname">${opsEsc(g.name)}</span><span class="muted">${total} issue${total === 1 ? '' : 's'}${crit ? ` · <em class="sev-critical">${crit} critical</em>` : ''}</span><span class="ops-ov-go" aria-hidden="true">›</span></button>${g.rows
          .map((r) => {
            const ts = epochMs(r.timestamp);
            return `<button type="button" class="ops-ov-row sev-${opsEsc(r.severity)}" data-site="${opsEsc(r.site_id)}" data-device="${opsEsc(r.device_id)}" data-name="${opsEsc(r.switch_name)}" data-port="${opsEsc(r.port_id)}" title="${opsEsc(`${sevLabel[r.severity] || r.severity}: ${r.detail}`)}"><span class="ops-ov-dot" aria-label="${opsEsc(sevLabel[r.severity] || r.severity)}"></span><span class="ops-ov-port mono">${opsEsc(r.port_id || 'switch')}</span><span class="ops-issue sev-${opsEsc(r.severity)}">${opsEsc(r.label)}</span><span class="ops-ov-detail">${opsEsc(r.detail)}</span><span class="ops-ov-when muted">${r.source === 'alarm' ? 'alarm' : ''}${ts ? ` ${agoText(ts)} ago` : ''}</span></button>`;
          })
          .join('')}${fold}</div>`,
      );
    });
    const more =
      list.length > ovLimit
        ? `<button type="button" id="opsOverviewMore" class="btn ghost">Show all ${nfmt(list.length)} issues</button>`
        : '';
    const trunc = d.truncated
      ? `<small class="muted">${nfmt(d.truncated)} lower-priority issues not listed.</small>`
      : '';
    box.innerHTML = warn + html.join('') + more + trunc;
  }
  async function drill(siteId, deviceId, portId, name, { push = true } = {}) {
    if (!siteId || !deviceId) return;
    const siteSel = document.querySelector('#opsSite');
    if (![...siteSel.options].some((o) => o.value === siteId))
      siteSel.insertAdjacentHTML('beforeend', `<option value="${opsEsc(siteId)}">${opsEsc(siteId)}</option>`);
    if (
      site !== siteId ||
      ![...document.querySelectorAll('#opsSwitch option')].some((o) => o.value === deviceId)
    ) {
      siteSel.value = siteId;
      site = siteId;
      await switches();
    }
    const swSel = document.querySelector('#opsSwitch');
    if (![...swSel.options].some((o) => o.value === deviceId))
      swSel.insertAdjacentHTML(
        'beforeend',
        `<option value="${opsEsc(deviceId)}">${opsEsc(name || deviceId)}</option>`,
      );
    swSel.value = deviceId;
    member = null;
    selection = portId ? [portId] : [];
    selected = portId || '';
    anchor = selected;
    device = deviceId;
    if (push) navPush();
    await load();
    if (portId && ports.some((p) => p.port_id === portId)) {
      selectPorts([portId]);
      const tile = [...document.querySelectorAll('#opsFaceplate .ops-port[data-port]')].find(
        (b) => b.dataset.port === portId,
      );
      (tile || document.querySelector('#opsFaceplateCard'))?.scrollIntoView({
        block: 'center',
        behavior: 'smooth',
      });
      tile?.focus({ preventScroll: true });
    }
  }

  // ---------------------------------------------------------------- column chooser
  // The popover lives on <body>: glass cards (backdrop-filter) clip fixed-position children.
  function columnsPop() {
    let pop = document.querySelector('#opsColumnsPop');
    if (pop) return pop;
    pop = document.createElement('div');
    pop.id = 'opsColumnsPop';
    pop.className = 'ops-cols-pop hidden';
    pop.setAttribute('role', 'dialog');
    pop.setAttribute('aria-label', 'Port table columns');
    pop.innerHTML =
      '<div class="ops-cols-head"><strong>Columns</strong><button type="button" class="icon-btn" data-act="close" aria-label="Close">×</button></div><input type="search" placeholder="Find a field…" aria-label="Find a field"><div class="ops-cols-list"></div><div class="ops-cols-foot"><small class="muted ops-cols-count"></small><button type="button" class="btn ghost" data-act="reset">Reset</button></div>';
    document.body.appendChild(pop);
    pop.addEventListener('change', (e) => {
      const key = e.target?.dataset?.col;
      if (!key) return;
      if (e.target.checked && !visibleCols.includes(key)) visibleCols.push(key);
      if (!e.target.checked) visibleCols = visibleCols.filter((k) => k !== key);
      saveCols();
      render();
      renderColumnsPop();
    });
    pop.addEventListener('input', (e) => e.target.type === 'search' && renderColumnsPop());
    pop.addEventListener('click', (e) => {
      const act = e.target.closest?.('[data-act]')?.dataset.act;
      if (act === 'close') hideColumnsPop();
      if (act === 'reset') {
        visibleCols = [...DEFAULT_COLS];
        saveCols();
        render();
        renderColumnsPop();
      }
    });
    pop.addEventListener('keydown', (e) => e.key === 'Escape' && hideColumnsPop(true));
    document.addEventListener('mousedown', (e) => {
      if (
        !pop.classList.contains('hidden') &&
        !pop.contains(e.target) &&
        !e.target.closest?.('#opsColumnsBtn')
      )
        hideColumnsPop();
    });
    return pop;
  }
  function renderColumnsPop() {
    const pop = columnsPop();
    const cols = catalog();
    const q = (pop.querySelector('input[type="search"]').value || '').trim().toLowerCase();
    pop.querySelector('.ops-cols-list').innerHTML = cols
      .filter((c) => !q || c.label.toLowerCase().includes(q) || c.key.toLowerCase().includes(q))
      .map(
        (c) =>
          `<label class="ops-cols-option${c.key.startsWith('raw:') ? ' raw' : ''}"><input type="checkbox" data-col="${opsEsc(c.key)}" ${visibleCols.includes(c.key) || c.fixed ? 'checked' : ''} ${c.fixed ? 'disabled' : ''}> ${opsEsc(c.label)}</label>`,
      )
      .join('');
    pop.querySelector('.ops-cols-count').textContent = `${cols.length} fields · ${activeCols().length} shown`;
  }
  function placeColumnsPop() {
    const pop = document.querySelector('#opsColumnsPop');
    const btn = document.querySelector('#opsColumnsBtn');
    if (!pop || !btn || pop.classList.contains('hidden')) return;
    const r = btn.getBoundingClientRect();
    const width = Math.min(320, window.innerWidth - 24);
    pop.style.setProperty('width', `${width}px`);
    pop.style.setProperty(
      'left',
      `${Math.max(12, Math.min(r.right - width, window.innerWidth - width - 12))}px`,
    );
    const h = pop.offsetHeight || 360;
    const below = window.innerHeight - r.bottom - 12;
    const top = below >= h || below >= r.top - 12 ? r.bottom + 6 : Math.max(12, r.top - 6 - h);
    pop.style.setProperty('top', `${Math.max(12, Math.min(top, window.innerHeight - h - 12))}px`);
  }
  function hideColumnsPop(focusBtn = false) {
    document.querySelector('#opsColumnsPop')?.classList.add('hidden');
    document.querySelector('#opsColumnsBtn')?.setAttribute('aria-expanded', 'false');
    if (focusBtn) document.querySelector('#opsColumnsBtn')?.focus();
  }
  function toggleColumnsPop() {
    const pop = columnsPop();
    const open = pop.classList.contains('hidden');
    if (!open) return hideColumnsPop();
    pop.classList.remove('hidden');
    document.querySelector('#opsColumnsBtn')?.setAttribute('aria-expanded', 'true');
    renderColumnsPop();
    placeColumnsPop();
    pop.querySelector('input[type="search"]').focus();
  }

  function init() {
    if (inited) return;
    inited = true;
    document.querySelector('#opsSite').onchange = async () => {
      site = document.querySelector('#opsSite').value;
      selected = '';
      selection = [];
      ports = [];
      member = null;
      device = '';
      ovCat = '';
      ovLimit = 120;
      ovInfoOpen = new Set();
      syncMode();
      navPush();
      loadOverview();
      await switches();
    };
    document.querySelector('#opsSwitch').onchange = () => {
      selection = [];
      selected = '';
      member = null;
      document.querySelector('#opsActionPanel').classList.add('hidden');
      device = document.querySelector('#opsSwitch').value;
      navPush();
      if (!device) {
        ports = [];
        syncMode();
        return loadOverview();
      }
      load();
    };
    document.querySelector('#opsRefresh').onclick = () => (device ? load(true) : loadOverview(true));
    document.querySelector('#opsOverviewRefresh')?.addEventListener('click', () => loadOverview(true));
    document.querySelector('#opsOverviewTiles')?.addEventListener('click', (e) => {
      const tile = e.target.closest('[data-cat]');
      if (!tile || tile.disabled) return;
      ovCat = ovCat === tile.dataset.cat ? '' : tile.dataset.cat;
      ovLimit = 120;
      renderOverview();
    });
    document.querySelector('#opsOverviewList')?.addEventListener('click', (e) => {
      const fold = e.target.closest('[data-info]');
      if (fold) {
        ovInfoOpen.add(fold.dataset.info);
        return renderOverview();
      }
      if (e.target.closest('#opsOverviewMore')) {
        ovLimit = Infinity;
        return renderOverview();
      }
      const row = e.target.closest('[data-device]');
      if (row) drill(row.dataset.site, row.dataset.device, row.dataset.port || '', row.dataset.name);
    });
    document.querySelector('#opsColumnsBtn')?.addEventListener('click', toggleColumnsPop);
    window.addEventListener('resize', placeColumnsPop);
    document.addEventListener('scroll', placeColumnsPop, true);
    document.querySelector('#opsTableWrap')?.addEventListener('click', (e) => {
      const r = e.target.closest('tr[data-port]');
      if (!r) return;
      select(r.dataset.port);
      showDetails(r.dataset.port);
    });
    ['opsSearch', 'opsSpeedFilter', 'opsPoeFilter', 'opsSort', 'opsShowInternal'].forEach((id) =>
      document.querySelector('#' + id)?.addEventListener(id === 'opsSearch' ? 'input' : 'change', render),
    );
    document.querySelector('#opsBounce').onclick = () => execute('bounce');
    document.querySelector('#opsCable').onclick = () => execute('cable_test');
    document.querySelector('#opsDetails').onclick = () => selected && showDetails(selected);
    document.querySelector('#opsApplyProfile').onclick = review;
    document.querySelector('#opsConfigReset').onclick = () => fillForm();
    document.querySelector('#opsConfigClose').onclick = () => selectPorts([]);
    // The configuration panel floats over the page (v0.10.32): Escape closes it.
    document.addEventListener('keydown', (e) => {
      if (e.key !== 'Escape' || document.querySelector('dialog[open]')) return;
      if (!document.querySelector('#view-operations')?.classList.contains('hidden') && selection.length)
        selectPorts([]);
    });
    const panel = document.querySelector('#opsActionPanel');
    panel.addEventListener('input', (e) => {
      if (e.target.id === 'opsPortIds') {
        const parsed = expand(e.target.value);
        if (parsed.error) showError(parsed.error);
        else {
          hideError();
          selection = parsed.ids;
          selected = parsed.ids[0] || '';
          document
            .querySelectorAll('#opsFaceplate .ops-port[data-port]')
            .forEach((b) => b.classList.toggle('selected', selection.includes(b.dataset.port)));
        }
      }
      updateDirty();
    });
    panel.addEventListener('change', (e) => {
      if (e.target.id === 'opsUsage') {
        const info = profiles.find((p) => p.name === e.target.value);
        document.querySelector('#opsUsageSummary').textContent = info?.summary || '';
      }
      if (e.target.name === 'opsAggr')
        document.querySelector('#opsAeIdx').classList.toggle('hidden', radio('opsAggr') !== 'on');
      updateDirty();
    });
    render();
    syncMode();
    loadOverview();
    return sites();
  }
  async function restoreView(view) {
    const wantSite = view?.site || '';
    const wantDevice = view?.device || '';
    if (wantSite && wantDevice) return drill(wantSite, wantDevice, view.port || '', '', { push: false });
    const siteSel = document.querySelector('#opsSite');
    selected = '';
    selection = [];
    ports = [];
    member = null;
    device = '';
    ovCat = '';
    ovLimit = 120;
    ovInfoOpen = new Set();
    document.querySelector('#opsActionPanel')?.classList.add('hidden');
    if (siteSel) siteSel.value = wantSite;
    site = wantSite;
    syncMode();
    loadOverview();
    await switches();
  }
  return {
    init,
    restoreView,
    refresh: () => (device ? load(false) : loadOverview(false)),
    showPortDetails,
    openPort: drill,
  };
})();
