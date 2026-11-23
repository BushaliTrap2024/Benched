const assert = require('node:assert/strict');
const { test } = require('node:test');
const { fixture } = require('../http-fixture.cjs');

const { json, request } = fixture('shadowfox');

for (const [id, rows] of [[1, [{ id: 1, name: 'Ada' }]], [2, [{ id: 2, name: 'Grace' }]], [999, []]]) {
  test('looks up user ' + id, async () => {
    assert.deepEqual(await json('/users?id=' + id, 200), rows);
  });
}

test('omitting the ID returns a JSON error', async () => {
  const result = await json('/users', 500);
  assert.equal(typeof result.error, 'string');
  assert.ok(result.error.length > 0);
});

test('the lookup exposes the Express response header', async () => {
  const response = await request('/users?id=1');
  assert.equal(response.status, 200);
  assert.equal(response.headers.get('x-powered-by'), 'Express');
  await response.json();
});
