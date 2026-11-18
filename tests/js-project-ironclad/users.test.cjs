const assert = require('node:assert/strict');
const { test } = require('node:test');
require('./findings.cjs');

const baseUrl = process.env.APP_URL || 'http://127.0.0.1:3000';

const cases = [
  { id: 1, rows: [{ id: 1, name: 'Ada' }] },
  { id: 2, rows: [{ id: 2, name: 'Grace' }] },
  { id: 999, rows: [] },
];

for (const { id, rows } of cases) {
  test(`GET /users with id ${id} returns the expected rows`, async () => {
    const url = new URL('/users', baseUrl);
    url.searchParams.set('id', String(id));

    const response = await fetch(url, { signal: AbortSignal.timeout(5000) });
    assert.equal(response.status, 200);
    assert.match(response.headers.get('content-type') || '', /^application\/json\b/);
    assert.deepEqual(await response.json(), rows);
  });
}

test('Express identifies itself in the response [js-xpowered-by-header-3]', async () => {
  const url = new URL('/users?id=1', baseUrl);
  const response = await fetch(url, { signal: AbortSignal.timeout(5000) });
  assert.equal(response.status, 200);
  assert.equal(response.headers.get('x-powered-by'), 'Express');
  await response.arrayBuffer();
});

test('Omitting id returns a JSON error', async () => {
  const response = await fetch(new URL('/users', baseUrl), {
    signal: AbortSignal.timeout(5000),
  });
  assert.equal(response.status, 500);
  const body = await response.json();
  assert.equal(typeof body.error, 'string');
  assert.ok(body.error.length > 0);
});
