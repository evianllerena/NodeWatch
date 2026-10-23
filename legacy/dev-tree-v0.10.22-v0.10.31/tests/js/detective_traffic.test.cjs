'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createContext, loadModule } = require('./dom_stub.cjs');

function detective() {
  const { context, elements } = createContext();
  loadModule(context, 'app/static/traffic-log.js');
  loadModule(context, 'app/static/modules/detective.js');
  return { mod: context.window.MistTools.detective, elements };
}

test('formatBytes formats sizes', () => {
  const { mod } = detective();
  const f = mod._test.formatBytes;
  assert.equal(f(0), '0 B');
  assert.equal(f(1536), '1.5 KB');
  assert.equal(f(64303), '63 KB');
  assert.equal(f(5 * 1024 * 1024 * 1024), '5.0 GB');
  assert.equal(f(undefined), '—');
  assert.equal(f('abc'), '—');
});

test('traffic table renders real sessions without throwing', () => {
  const { mod, elements } = detective();
  mod._test.renderTraffic({
    available: true,
    configured: true,
    window: '1h',
    sessions: [
      { rule: 'LMC_out', application: 'ibm-bigfix', destination: '10.100.30.226', destination_port: 52311, action: 'allow', bytes_total: 64303, receive_time: '2026-10-08T12:45:14+00:00' },
      { rule: '<b>x</b>', application: 'ping', destination: '23.219.0.139', action: 'allow', bytes_total: 152 },
    ],
  });
  const html = elements.get('#detectiveTrafficRows').innerHTML;
  assert.match(html, /ibm-bigfix/);
  assert.match(html, /LMC_out/);
  assert.match(html, /&lt;b&gt;x&lt;\/b&gt;/, 'rule names must be HTML-escaped');
  assert.doesNotMatch(html, /<b>x<\/b>/);
  assert.equal(elements.get('#detectiveTrafficState').textContent, '2/2 sessions');
  assert.equal(elements.get('#detectiveTrafficTableWrap').classList.contains('hidden'), false);
});

test('traffic error is shown as a message', () => {
  const { mod, elements } = detective();
  mod._test.renderTraffic({ error: 'Log query HTTP 403', sessions: [] });
  assert.equal(elements.get('#detectiveTrafficState').textContent, 'Traffic query failed');
  assert.equal(elements.get('#detectiveTrafficMeta').textContent, 'Log query HTTP 403');
});
