const assert = require('node:assert/strict');
const { test } = require('node:test');
const { fixture } = require('../http-fixture.cjs');

const { json, request } = fixture('skylark');

for (const [name, query, valid] of [
  ['a shelf code', '?code=123%23', true],
  ['a shelf code in a label', '?code=aisle-7%23-east', true],
  ['a short code missing the delimiter', '?code=123', false],
  ['an omitted code', '', false],
]) {
  test('validates ' + name, async () => {
    assert.deepEqual(await json('/shelves/validate' + query, 200), { valid });
  });
}

test('serves the dashboard JavaScript asset', async () => {
  const response = await request('/dashboard.js');
  assert.equal(response.status, 200);
  assert.match(response.headers.get('content-type') || '', /javascript/);
  assert.ok((await response.text()).length > 0);
});
