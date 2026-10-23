'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createContext, loadModule } = require('./dom_stub.cjs');

function detective() {
  const { context, elements } = createContext();
  loadModule(context, 'app/static/modules/detective.js');
  return { mod: context.window.MistTools.detective, elements };
}

test('More information renders curated sections only, never raw keys or ids', () => {
  const { mod, elements } = detective();
  mod._test.renderMore({
    identity: { site_id: '11111111-2222-4333-8444-555555555555' },
    device: { id: 'dev-uuid', org_id: 'org-uuid', model: 'AP45' },
    authentication: { nac_error: 'x' },
    details: [
      {
        title: 'Client',
        rows: [
          { label: 'Manufacturer', value: '<Apple>', format: 'text' },
          { label: 'Last seen', value: 'not-a-date', format: 'time' },
        ],
      },
      { title: 'Empty', rows: [] },
    ],
    nac_events: [{ type: 'NAC_CLIENT_PERMITTED', text: 'ok', timestamp: '' }],
    troubleshoot: {},
  });
  const html = elements.get('#detectiveMoreContent').innerHTML;
  assert.match(html, /Manufacturer/);
  assert.match(html, /&lt;Apple&gt;/);
  assert.match(html, /Client permitted/);
  assert.doesNotMatch(html, /Empty/);
  assert.doesNotMatch(html, /org-uuid|dev-uuid|11111111-2222|org_id|Site ID|nac_error/);
});

test('pager is always shown with "Showing x–y of N", above and below', () => {
  const { mod, elements } = detective();
  mod._test.setSearch({ results: [{ title: 'a', mac: '1' }, { title: 'b', mac: '2' }] });
  mod._test.renderResults();
  for (const sfx of ['Top', '']) {
    assert.equal(elements.get(`#detectivePagination${sfx}`).classList.contains('hidden'), false);
    assert.equal(elements.get(`#detectivePageInfo${sfx}`).textContent, 'Showing 1–2 of 2');
  }
});

test('result scope states the 7-day client window and truncation', () => {
  const { mod, elements } = detective();
  mod._test.renderResultScope({
    mode: 'live',
    client_lookback: '7d',
    truncated: true,
    truncated_sources: ['wireless clients'],
    source_limit: 50000,
    errors: [],
  });
  const html = elements.get('#detectiveResultScope').innerHTML;
  assert.match(html, /Clients seen in the last 7 days/);
  assert.match(html, /incomplete: wireless clients reached the 50,000-row limit/);
});
