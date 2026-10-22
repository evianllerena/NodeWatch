// Runs in <head> before the page draws: resolves night mode "Match Windows" so there is no flash,
// and (v0.10.15) restores a page layout that was only saved in this browser.
(function () {
  const root = document.documentElement;
  const query = window.matchMedia ? window.matchMedia('(prefers-color-scheme: dark)') : null;
  function sync() {
    if (root.getAttribute('data-night-pref') === 'system')
      root.setAttribute('data-night', query && query.matches ? 'on' : 'off');
  }
  sync();
  if (query && query.addEventListener) query.addEventListener('change', sync);
  window.NodeWatchNight = { sync };

  // The server copy (rendered into <html>) wins; the browser copy only fills in when none is saved.
  if (root.getAttribute('data-layout-saved') === '1') return;
  const allowed = {
    layout: ['aurora', 'dense', 'top', 'focus', 'custom'],
    lnav: ['side', 'top'],
    ldensity: ['comfortable', 'compact'],
    lwidth: ['fixed', 'full'],
    lradius: ['theme', 'square', 'subtle', 'rounded', 'round'],
    lglass: ['on', 'off'],
    lshadow: ['on', 'off'],
    text: ['s', 'm', 'l', 'xl'],
  };
  const keys = {
    layout: 'preset',
    lnav: 'nav',
    ldensity: 'density',
    lwidth: 'width',
    lradius: 'radius',
    lglass: 'glass',
    lshadow: 'shadows',
    text: 'text',
  };
  let saved = null;
  try {
    saved = JSON.parse(localStorage.getItem('nodewatch.layout') || 'null');
  } catch {
    saved = null;
  }
  if (!saved || typeof saved !== 'object') return;
  Object.keys(allowed).forEach(function (attr) {
    const value = saved[keys[attr]];
    if (allowed[attr].indexOf(value) !== -1) root.setAttribute('data-' + attr, value);
  });
  if (root.getAttribute('data-lnav') === 'top') root.setAttribute('data-nav', 'top');
})();
