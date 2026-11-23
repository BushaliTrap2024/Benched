const assert = require('node:assert/strict');
const { test } = require('node:test');
const { fixture, jsonBody } = require('../http-fixture.cjs');

const { json } = fixture('riverbend');
const profile = '/imports/profile';

test('reads the published import defaults', async () => {
  assert.deepEqual(await json(profile, 200), {
    columns: ['sku', 'name', 'quantity'], defaults: { warehouse: 'central' },
  });
});

test('creates the default SKU mapping from an empty request', async () => {
  assert.deepEqual(await json(profile, 200, jsonBody('POST', {})), {
    profile: { columns: { sku: 'Supplier SKU' }, defaults: {} },
  });
});

test('stores a supplied value under the selected section', async () => {
  assert.deepEqual(await json(profile, 200, jsonBody('POST', {
    section: 'defaults', key: 'warehouse', value: 'north',
  })), { profile: { columns: {}, defaults: { warehouse: 'north' } } });
});
