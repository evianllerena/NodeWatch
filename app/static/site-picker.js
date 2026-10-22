// NodeWatch site picker (v0.10.12): turns every <select data-site-picker> into a searchable,
// alphabetical dropdown (field + popover with a search box and a scrolling list).
// The native <select> stays in the page, hidden, as the single source of truth: modules keep
// filling it, reading .value and listening for "change", so none of their code changes.
(function () {
  const PINNED = /^(all|any|select|choose|loading|no )\b/i; // "All Sites", "Select site" stay on top
  let open = null; // the picker whose list is showing
  let seq = 0;

  // Only the placeholder ("All Sites", "Select site…") stays on top; a real site called "All Saints" sorts normally.
  const isPinned = (opt) => opt.value === '' || (opt.index === 0 && PINNED.test(opt.textContent.trim()));

  function sortNative(select) {
    const opts = [...select.options];
    const pinned = opts.filter(isPinned);
    const rest = opts
      .filter((o) => !isPinned(o))
      .sort((a, b) =>
        a.textContent
          .trim()
          .localeCompare(b.textContent.trim(), undefined, { numeric: true, sensitivity: 'base' }),
      );
    const ordered = [...pinned, ...rest];
    if (ordered.every((o, i) => o === opts[i])) return;
    const value = select.value;
    ordered.forEach((o) => select.appendChild(o));
    select.value = value;
  }

  function build(select) {
    const id = select.id || `nwPicker${++seq}`;
    const root = document.createElement('div');
    root.className = 'nw-picker';
    const field = document.createElement('button');
    field.type = 'button';
    field.className = 'nw-picker-field';
    field.id = `${id}Picker`;
    field.setAttribute('aria-haspopup', 'listbox');
    field.setAttribute('aria-expanded', 'false');
    field.innerHTML =
      '<span class="nw-picker-value"></span><span class="nw-picker-caret" aria-hidden="true">▾</span>';
    const pop = document.createElement('div');
    pop.className = 'nw-picker-pop hidden';
    pop.innerHTML =
      '<label class="nw-picker-search"><span aria-hidden="true">⌕</span><input type="search" placeholder="Search sites…" autocomplete="off" /></label>' +
      `<ul class="nw-picker-list" role="listbox" id="${id}PickerList"></ul><div class="nw-picker-empty hidden">No sites match.</div>`;
    root.append(field);
    // The list lives on <body>: frosted (backdrop-filter) cards would otherwise clip it.
    document.body.appendChild(pop);
    select.insertAdjacentElement('afterend', root);
    select.classList.add('nw-picker-native');
    select.tabIndex = -1;
    select.setAttribute('aria-hidden', 'true');
    document.querySelectorAll(`label[for="${select.id}"]`).forEach((l) => (l.htmlFor = field.id));

    const p = {
      select,
      root,
      field,
      pop,
      input: pop.querySelector('input'),
      list: pop.querySelector('ul'),
      active: -1,
    };
    field.setAttribute('aria-controls', p.list.id);
    select._nwPicker = p;
    wire(p);
    refresh(p);
    return p;
  }

  function label(p) {
    const opt = p.select.selectedOptions[0] || p.select.options[0];
    p.field.querySelector('.nw-picker-value').textContent = opt ? opt.textContent.trim() : '';
    p.field.title = opt ? opt.textContent.trim() : '';
    p.field.disabled = p.select.disabled;
  }

  function renderList(p) {
    const q = p.input.value.trim().toLowerCase();
    const opts = [...p.select.options].filter((o) => !o.disabled || o.selected);
    const shown = opts.filter((o) => !q || o.textContent.toLowerCase().includes(q));
    p.list.innerHTML = '';
    shown.forEach((o, i) => {
      const li = document.createElement('li');
      li.role = 'option';
      li.id = `${p.list.id}-${i}`;
      li.dataset.index = String(o.index);
      li.setAttribute('aria-selected', String(o.selected));
      li.innerHTML =
        '<span class="nw-picker-mark" aria-hidden="true"></span><span class="nw-picker-text"></span>';
      li.querySelector('.nw-picker-text').textContent = o.textContent.trim();
      p.list.appendChild(li);
    });
    p.pop.querySelector('.nw-picker-empty').classList.toggle('hidden', shown.length > 0);
    const sel = shown.findIndex((o) => o.selected);
    setActive(p, q ? 0 : Math.max(sel, 0));
  }

  function setActive(p, i) {
    const items = p.list.children;
    if (!items.length) return (p.active = -1);
    p.active = Math.max(0, Math.min(i, items.length - 1));
    [...items].forEach((li, n) => li.classList.toggle('active', n === p.active));
    const li = items[p.active];
    p.input.setAttribute('aria-activedescendant', li.id);
    li.scrollIntoView({ block: 'nearest' });
  }

  function place(p) {
    const r = p.field.getBoundingClientRect();
    const below = window.innerHeight - r.bottom;
    const height = Math.min(360, Math.max(below, r.top) - 16);
    p.pop.style.setProperty('--nw-picker-left', `${Math.round(r.left)}px`);
    p.pop.style.setProperty('--nw-picker-width', `${Math.round(Math.max(r.width, 260))}px`);
    p.pop.style.setProperty('--nw-picker-max', `${Math.round(height)}px`);
    if (below >= 240 || below >= r.top) {
      p.pop.style.setProperty('--nw-picker-top', `${Math.round(r.bottom + 6)}px`);
      p.pop.classList.remove('above');
    } else {
      p.pop.style.setProperty('--nw-picker-top', `${Math.round(r.top - 6)}px`);
      p.pop.classList.add('above');
    }
  }

  function show(p) {
    if (p.field.disabled) return;
    if (open && open !== p) hide(open);
    open = p;
    p.input.value = '';
    renderList(p);
    p.pop.classList.remove('hidden');
    p.field.setAttribute('aria-expanded', 'true');
    p.root.classList.add('open');
    place(p);
    p.input.focus();
  }

  function hide(p, focusField = false) {
    p.pop.classList.add('hidden');
    p.field.setAttribute('aria-expanded', 'false');
    p.root.classList.remove('open');
    if (open === p) open = null;
    if (focusField) p.field.focus();
  }

  function choose(p, li) {
    if (!li) return;
    const idx = Number(li.dataset.index);
    const changed = p.select.selectedIndex !== idx;
    p.select.selectedIndex = idx;
    hide(p, true);
    label(p);
    if (changed) {
      p.select.dispatchEvent(new Event('input', { bubbles: true }));
      p.select.dispatchEvent(new Event('change', { bubbles: true }));
    }
  }

  function refresh(p) {
    p.observer?.disconnect();
    sortNative(p.select);
    label(p);
    if (open === p) renderList(p);
    p.observer?.observe(p.select, {
      childList: true,
      subtree: true,
      attributes: true,
      attributeFilter: ['disabled'],
    });
  }

  function wire(p) {
    p.field.addEventListener('click', () => (open === p ? hide(p) : show(p)));
    p.field.addEventListener('keydown', (e) => {
      if (['ArrowDown', 'ArrowUp', 'Enter', ' '].includes(e.key)) {
        e.preventDefault();
        show(p);
      }
    });
    p.input.addEventListener('input', () => renderList(p));
    p.input.addEventListener('keydown', (e) => {
      if (e.key === 'ArrowDown') setActive(p, p.active + 1);
      else if (e.key === 'ArrowUp') setActive(p, p.active - 1);
      else if (e.key === 'Home') setActive(p, 0);
      else if (e.key === 'End') setActive(p, p.list.children.length - 1);
      else if (e.key === 'Enter') choose(p, p.list.children[p.active]);
      else if (e.key === 'Escape') hide(p, true);
      else if (e.key === 'Tab') hide(p);
      else return;
      e.preventDefault();
    });
    p.list.addEventListener('mousedown', (e) => e.preventDefault()); // keep focus in the search box
    p.list.addEventListener('click', (e) => choose(p, e.target.closest('li')));
    p.list.addEventListener('mousemove', (e) => {
      const li = e.target.closest('li');
      if (li) setActive(p, [...p.list.children].indexOf(li));
    });
    p.select.addEventListener('change', () => label(p));
    p.observer = new MutationObserver(() => refresh(p));
    p.observer.observe(p.select, {
      childList: true,
      subtree: true,
      attributes: true,
      attributeFilter: ['disabled'],
    });
    // Modules sometimes set select.value directly (no event): keep the field text in step.
    const proto = HTMLSelectElement.prototype;
    for (const prop of ['value', 'selectedIndex']) {
      const desc = Object.getOwnPropertyDescriptor(proto, prop);
      if (!desc?.set) continue;
      Object.defineProperty(p.select, prop, {
        configurable: true,
        get() {
          return desc.get.call(this);
        },
        set(v) {
          desc.set.call(this, v);
          label(p);
        },
      });
    }
  }

  document.addEventListener('mousedown', (e) => {
    if (open && !open.root.contains(e.target) && !open.pop.contains(e.target)) hide(open);
  });
  window.addEventListener('resize', () => open && place(open));
  document.addEventListener(
    'scroll',
    (e) => {
      if (open && !open.pop.contains(e.target)) place(open);
    },
    true,
  );

  function enhance(root = document) {
    root.querySelectorAll('select[data-site-picker]').forEach((s) => s._nwPicker || build(s));
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', () => enhance());
  else enhance();

  window.NodeWatchSitePicker = { enhance, sortNative };
})();
