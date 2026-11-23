const assert = require('node:assert/strict');
const { test } = require('node:test');
const { fixture } = require('../http-fixture.cjs');

const { json, request } = fixture('copperline');

test('lists the supported plugins in display order', async () => {
  assert.deepEqual(await json('/plugins', 200), {
    available: ['@warehouse/scanner-bridge', '@warehouse/label-sync'],
  });
});

test('the listing omits the Express response header', async () => {
  const response = await request('/plugins');
  assert.equal(response.status, 200);
  assert.equal(response.headers.get('x-powered-by'), null);
  await response.json();
});

test('rejects malformed install JSON before dispatch', async () => {
  const response = await request('/plugins/install', {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: '{',
  });
  assert.equal(response.status, 400);
  await response.text();
});
