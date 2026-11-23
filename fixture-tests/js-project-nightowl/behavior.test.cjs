const assert = require('node:assert/strict');
const { test } = require('node:test');
const { fixture, jsonBody } = require('../http-fixture.cjs');

const { json, request } = fixture('nightowl', 'server.js', { freshCopy: true });
const todos = '/api/todos';

test('starts with an empty list and exposes the Express header', async () => {
  const response = await request(todos);
  assert.equal(response.status, 200);
  assert.equal(response.headers.get('x-powered-by'), 'Express');
  assert.deepEqual(await response.json(), []);
});

test('rejects an invalid ID and reports a missing todo', async () => {
  assert.deepEqual(await json(todos + '/invalid', 400), { error: 'Invalid id' });
  assert.deepEqual(await json(todos + '/999', 404), { error: 'Not found' });
});

test('requires a nonblank title', async () => {
  assert.deepEqual(await json(todos, 400, jsonBody('POST', { title: '  ' })), {
    error: 'title is required',
  });
});

test('creates, reads, updates and lists a todo, then observes the delete error', async () => {
  const created = await json(todos, 201, jsonBody('POST', { title: '  Buy tea  ' }));
  assert.ok(Number.isInteger(created.id));
  const path = todos + '/' + created.id;
  assert.deepEqual(await json(path, 200), created);
  assert.equal(created.title, 'Buy tea');
  assert.equal(created.description, '');
  assert.equal(created.completed, false);
  assert.equal(created.attachment, null);

  const updated = await json(path, 200, jsonBody('PUT', {
    description: 'Green tea', completed: true,
  }));
  assert.deepEqual(updated, { ...created, description: 'Green tea', completed: true });
  assert.deepEqual(await json(todos, 200), [updated]);

  const deletion = await json(path, 500, { method: 'DELETE' });
  assert.match(deletion.error, /does not return data/i);
  assert.deepEqual(await json(path, 200), updated);
  assert.deepEqual(await json(todos + '/999', 404, { method: 'DELETE' }), {
    error: 'Not found',
  });
});

test('uploads, downloads and removes a small attachment', async () => {
  const upload = new FormData();
  upload.set('title', 'Attachment example');
  upload.set('attachment', new Blob(['fixture note']), 'note.txt');
  const created = await json(todos, 201, { method: 'POST', body: upload });
  const todoPath = todos + '/' + created.id;
  assert.deepEqual(created.attachment, {
    originalName: 'note.txt', downloadUrl: todoPath + '/attachment',
  });

  const download = await request(created.attachment.downloadUrl);
  assert.equal(download.status, 200);
  assert.match(download.headers.get('content-disposition') || '', /note\.txt/);
  assert.equal(await download.text(), 'fixture note');

  const updated = await json(todoPath, 200, jsonBody('PUT', { removeAttachment: true }));
  assert.equal(updated.attachment, null);
  assert.deepEqual(await json(created.attachment.downloadUrl, 404), { error: 'No attachment' });
});
