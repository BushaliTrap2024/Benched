const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const { once } = require('node:events');
const { cp, mkdtemp, rm } = require('node:fs/promises');
const { createServer } = require('node:net');
const { tmpdir } = require('node:os');
const { basename, delimiter, join, resolve } = require('node:path');
const { setTimeout } = require('node:timers/promises');
const { before, after } = require('node:test');

function fixture(name, entry = 'app.js', { freshCopy = false } = {}) {
  const project = resolve(process.env.FIXTURE_APP_DIR ||
    join(__dirname, '..', 'fixtures', 'js-project-' + name, 'project'));
  let child;
  let scratch;
  let baseUrl;
  let output = '';

  before(async () => {
    let cwd = project;
    if (freshCopy) {
      scratch = await mkdtemp(join(tmpdir(), 'benched-' + name + '-'));
      cwd = join(scratch, 'project');
      await cp(project, cwd, {
        recursive: true,
        filter: file => !/^(node_modules|uploads|todos\.sqlite(?:-.*)?)$/.test(basename(file)),
      });
    }

    const socket = createServer().listen(0, '127.0.0.1');
    await once(socket, 'listening');
    const { port } = socket.address();
    await new Promise((done, reject) => socket.close(error => error ? reject(error) : done()));
    baseUrl = 'http://127.0.0.1:' + port;
    const modulePaths = [join(project, 'node_modules'), process.env.NODE_PATH].filter(Boolean);
    child = spawn(process.execPath, [entry], {
      cwd,
      env: { ...process.env, PORT: String(port), NODE_PATH: modulePaths.join(delimiter) },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    child.on('error', error => { output += error.message; });
    for (const stream of [child.stdout, child.stderr]) {
      stream.setEncoding('utf8').on('data', chunk => { output = (output + chunk).slice(-4000); });
    }
    for (let attempt = 0; attempt < 60; attempt++) {
      if (child.exitCode !== null || child.signalCode !== null) break;
      try {
        const response = await request('/__fixture_readiness__');
        await response.body?.cancel();
        if (child.exitCode === null) return;
      } catch (error) {
        if (!(error instanceof TypeError)) throw error;
      }
      await setTimeout(100);
    }
    assert.fail('Fixture did not start. App output:\n' + output);
  });

  after(async () => {
    try {
      if (child?.pid && child.exitCode === null && child.signalCode === null) {
        const closed = once(child, 'close');
        child.kill();
        const timer = globalThis.setTimeout(() => child.kill('SIGKILL'), 2000);
        try { await closed; } finally { clearTimeout(timer); }
      }
    } finally {
      if (scratch) await rm(scratch, { recursive: true, force: true });
    }
  });

  function request(path, options = {}) {
    return fetch(new URL(path, baseUrl), {
      redirect: 'manual',
      signal: AbortSignal.timeout(5000),
      ...options,
    });
  }

  async function json(path, expectedStatus, options) {
    const response = await request(path, options);
    assert.equal(response.status, expectedStatus, path);
    assert.match(response.headers.get('content-type') || '', /^application\/json\b/);
    return response.json();
  }

  return { request, json };
}

function jsonBody(method, body) {
  return {
    method,
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  };
}

module.exports = { fixture, jsonBody };
