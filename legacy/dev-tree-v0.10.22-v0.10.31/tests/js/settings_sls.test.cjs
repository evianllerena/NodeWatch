'use strict';
// Behavioural check of the Traffic & Sessions controls in settings.js: the switch and
// buttons are wired, and enabling sends the host/tenant settings to the backend.
const test = require('node:test');
const assert = require('node:assert/strict');
const { createContext, loadModule } = require('./dom_stub.cjs');

async function settingsPage() {
  const env = createContext();
  const integration = { enabled: false, status: 'verification_required', status_label: 'Ready to verify', query_host: 'https://pa-us01.api.prismaaccess.com', tenant_header: '' };
  env.routes['/api/settings'] = () => ({ api_host: 'https://api.mist.com', org_id: '', configured: false });
  env.routes['/api/integrations'] = () => ({ palo_alto_device_security: {}, strata_logging_service: integration });
  env.routes['/api/platform-overview/lock'] = () => ({ locked: true });
  env.routes['/api/integrations/strata-logging/ui-event'] = () => ({ ok: true });
  env.routes['/api/integrations/strata-logging/enable'] = (init) => {
    const body = JSON.parse(init.body);
    integration.enabled = body.enabled;
    return { ok: true, sample_count: 1, integration };
  };
  loadModule(env.context, 'app/static/modules/settings.js');
  await env.context.window.MistTools.settings.init();
  return env;
}

test('Traffic & Sessions controls are wired to handlers', async () => {
  const { elements } = await settingsPage();
  for (const [id, type] of [['#slsEnabled', 'change'], ['#slsTest', 'click'], ['#slsReset', 'click']]) {
    assert.equal(typeof elements.get(id)?.listeners[type]?.[0], 'function', `${id} ${type} handler`);
  }
  assert.equal(elements.get('#slsQueryHost').value, 'https://pa-us01.api.prismaaccess.com');
});

test('turning the switch on posts enable with host and tenant', async () => {
  const { elements, calls } = await settingsPage();
  elements.get('#slsQueryHost').value = 'pa-eu01.api.prismaaccess.com';
  elements.get('#slsTenant').value = '1844525482:572447260';
  elements.get('#slsEnabled').checked = true;
  await elements.get('#slsEnabled').listeners.change[0]();
  const enable = calls.find((c) => c.url === '/api/integrations/strata-logging/enable');
  assert.ok(enable, 'enable endpoint called');
  assert.deepEqual(JSON.parse(enable.init.body), {
    enabled: true,
    query_host: 'pa-eu01.api.prismaaccess.com',
    tenant_header: '1844525482:572447260',
  });
  assert.match(elements.get('#slsResult').textContent, /Connected and saved/);
  assert.ok(calls.some((c) => c.url === '/api/integrations/strata-logging/ui-event'), 'UI diagnostic event recorded');
});
