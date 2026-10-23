'use strict';
// Every frontend module must at least parse and evaluate in a browser-like context.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { createContext, loadModule } = require('./dom_stub.cjs');

const root = path.join(__dirname, '..', '..', 'app', 'static');
const modules = fs.readdirSync(path.join(root, 'modules')).filter((f) => f.endsWith('.js'));

test('loads core.js', () => {
  const { context } = createContext();
  assert.doesNotThrow(() => loadModule(context, 'app/static/core.js'));
});

// index.html loads core.js before every module, so do the same here.
for (const file of modules) {
  test(`loads modules/${file} after core.js`, () => {
    const { context } = createContext();
    loadModule(context, 'app/static/core.js');
    assert.doesNotThrow(() => loadModule(context, `app/static/modules/${file}`));
  });
}

test('core.js keeps setNavBadge on window.MistApp after boot wiring', () => {
  const { context } = createContext();
  loadModule(context, 'app/static/core.js');
  assert.equal(typeof context.window.MistApp.setNavBadge, 'function');
  assert.equal(typeof context.window.MistApp.openTool, 'function');
});
