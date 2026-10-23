// Minimal DOM stand-in so NodeWatch frontend modules can be loaded and exercised in Node
// without a browser. Elements are created on demand per selector.
'use strict';
const vm = require('node:vm');
const fs = require('node:fs');
const path = require('node:path');

function makeElement(selector) {
  const classes = new Set(['hidden']);
  const listeners = {};
  return {
    listeners,
    selector,
    innerHTML: '',
    textContent: '',
    value: '',
    disabled: false,
    checked: false,
    dataset: {},
    selectedOptions: [],
    options: [],
    classList: {
      add: (...c) => c.forEach((x) => classes.add(x)),
      remove: (...c) => c.forEach((x) => classes.delete(x)),
      toggle: (c, on) => { const want = on === undefined ? !classes.has(c) : !!on; want ? classes.add(c) : classes.delete(c); return want; },
      contains: (c) => classes.has(c),
    },
    addEventListener(type, fn) { (listeners[type] = listeners[type] || []).push(fn); },
    querySelectorAll: () => [],
    scrollTo() {},
    focus() {},
    select() {},
  };
}

function createContext() {
  const elements = new Map();
  const document = {
    querySelector(sel) { if (!elements.has(sel)) elements.set(sel, makeElement(sel)); return elements.get(sel); },
    querySelectorAll: () => [],
    addEventListener() {},
    visibilityState: 'visible',
    activeElement: null,
    documentElement: makeElement('html'),
    body: { appendChild() {} },
    createElement: (tag) => makeElement(tag),
  };
  const calls = [];
  const routes = {};
  const fetchStub = async (url, init = {}) => {
    calls.push({ url: String(url), init });
    const path = String(url).replace(/\?.*$/, '');
    const handler = routes[path];
    if (!handler) return { ok: false, status: 404, json: async () => ({ detail: `no route ${path}` }), text: async () => '' };
    const body = await handler(init);
    return { ok: true, status: 200, json: async () => body, text: async () => JSON.stringify(body) };
  };
  const window = { location: { href: 'http://127.0.0.1:8765/', origin: 'http://127.0.0.1:8765' }, fetch: fetchStub };
  const context = {
    window, document, console, fetch: fetchStub, confirm: () => true, alert() {},
    setInterval: () => 0, setTimeout: () => 0, clearInterval() {}, performance: { now: () => 0 },
    URL, URLSearchParams, Headers: globalThis.Headers, Request: globalThis.Request,
  };
  window.document = document;
  vm.createContext(context);
  return { context, elements, calls, routes };
}

function loadModule(context, relPath) {
  const file = path.join(__dirname, '..', '..', relPath);
  vm.runInContext(fs.readFileSync(file, 'utf8'), context, { filename: file });
}

module.exports = { createContext, loadModule };
