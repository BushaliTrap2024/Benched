const assert = require('node:assert/strict');
const { test } = require('node:test');
const { fixture } = require('../http-fixture.cjs');

const { request } = fixture('purplehaze', 'server.js');

test('renders the health page', async () => {
  const response = await request('/');
  assert.equal(response.status, 200);
  assert.match(await response.text(), /Health check/i);
});

test('renders the session page', async () => {
  const response = await request('/account');
  assert.equal(response.status, 200);
  assert.match(await response.text(), /Session/i);
});

test('rejects an empty health-check target', async () => {
  const response = await request('/check', {
    method: 'POST', body: new URLSearchParams({ target: '' }),
  });
  assert.equal(response.status, 400);
  assert.match(await response.text(), /Check failed/i);
});

for (const [path, location] of [
  ['/visitPage', '/'],
  ['/visitPage?referer=%2Faccount', '/account'],
]) {
  test('returns the expected navigation redirect for ' + path, async () => {
    const response = await request(path);
    assert.equal(response.status, 302);
    assert.equal(response.headers.get('location'), location);
    await response.text();
  });
}

test('health exposes the Express response header', async () => {
  const response = await request('/');
  assert.equal(response.status, 200);
  assert.equal(response.headers.get('x-powered-by'), 'Express');
  await response.text();
});

test('health sets a session cookie on plain HTTP', async () => {
  const response = await request('/');
  assert.equal(response.status, 200);
  const cookie = response.headers.get('set-cookie') || '';
  assert.match(cookie, /^connect\.sid=/);
  assert.doesNotMatch(cookie, /(?:^|;\s*)secure(?:;|$)/i);
  await response.text();
});
