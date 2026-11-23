const assert = require('node:assert/strict');
const { test } = require('node:test');
const { fixture, jsonBody } = require('../http-fixture.cjs');

const { json } = fixture('goldleaf');

test('lists the report templates', async () => {
  assert.deepEqual(await json('/reports/templates', 200), {
    templates: ['turnover', 'shortage', 'supplier-delay'],
  });
});

for (const [name, body, key] of [
  ['default metric', {}, 'monthlyTurnover'],
  ['custom metric', { metricKey: 'weekly shortage' }, 'weekly shortage'],
  ['empty metric', { metricKey: '' }, 'monthlyTurnover'],
]) {
  test('previews the ' + name, async () => {
    assert.deepEqual(await json('/reports/preview', 200, jsonBody('POST', body)), {
      source: 'saved-report', preview: { [key]: 42 },
    });
  });
}
