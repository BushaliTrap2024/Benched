const assert = require('node:assert/strict');
const { test } = require('node:test');
const { fixture } = require('../http-fixture.cjs');

const { json, request } = fixture('silvergate');

test('reports service readiness', async () => {
  assert.deepEqual(await json('/status', 200), { service: 'silvergate', ready: true });
});

for (const [path, location] of [
  ['/handoff/team?target=%2Fstatus', '/status'],
  ['/handoff/workspace.example', '//workspace.example'],
]) {
  test('handoff returns the expected location for ' + path, async () => {
    const response = await request(path);
    assert.equal(response.status, 302);
    assert.equal(response.headers.get('location'), location);
    await response.text();
  });
}

test('status returns the baseline Origin response headers', async () => {
  const origin = 'https://workspace.example';
  const response = await request('/status', { headers: { origin } });
  assert.equal(response.status, 200);
  assert.equal(response.headers.get('access-control-allow-origin'), origin);
  assert.equal(response.headers.get('access-control-allow-credentials'), 'true');
  await response.json();
});
