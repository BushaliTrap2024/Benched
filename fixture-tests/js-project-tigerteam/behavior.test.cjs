const assert = require('node:assert/strict');
const { test } = require('node:test');
const { fixture } = require('../http-fixture.cjs');

const { json, request } = fixture('tigerteam');

test('health returns status and an ISO timestamp', async () => {
  const result = await json('/health', 200);
  assert.equal(result.status, 'ok');
  assert.equal(new Date(result.timestamp).toISOString(), result.timestamp);
});

test('health exposes the Express response header', async () => {
  const response = await request('/health');
  assert.equal(response.status, 200);
  assert.equal(response.headers.get('x-powered-by'), 'Express');
  await response.json();
});

test('the placeholder user lookup returns an empty list', async () => {
  assert.deepEqual(await json('/users?username=Ada', 200), []);
});

test('renders an ordinary greeting in HTML', async () => {
  const response = await request('/greet?name=Ada');
  assert.equal(response.status, 200);
  assert.match(await response.text(), /<h1>Hello, Ada!<\/h1>/);
});

test('reports a missing public file', async () => {
  const response = await request('/file?filename=benched-fixture-missing.txt');
  assert.equal(response.status, 404);
  assert.equal(await response.text(), 'Not found');
});
