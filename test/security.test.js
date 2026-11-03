'use strict';
// Tests for the security-audit fixes: the browser-mode access key, the admin-autostart install check
// and owner-only data files.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const http = require('http');
const { Store } = require('../src/main/store');
const { isAdminOnlyInstallDir } = require('../src/main/util');

const RENDERER = path.join(__dirname, '..', 'src', 'renderer');

function request(port, { method = 'GET', path: p = '/', headers = {}, body } = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, method, path: p, headers }, (res) => {
      let data = '';
      res.on('data', (d) => { data += d; });
      res.on('end', () => resolve({ status: res.statusCode, body: data }));
    });
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

async function startServer() {
  const calls = [];
  const { server, token } = require('../src/main/devserver').start(0, async (type) => { calls.push(type); return { ok: type }; }, RENDERER);
  await new Promise((r) => server.once('listening', r));
  return { server, token, port: server.address().port, calls };
}

test('browser mode never serves its access key to whoever connects', async () => {
  const { server, token, port } = await startServer();
  try {
    const page = await request(port);
    assert.equal(page.status, 200);
    assert.ok(!page.body.includes(token), 'the page must not contain the key');
    assert.ok(!/nw-dev-token/.test(page.body));
  } finally { server.close(); }
});

test('browser mode API calls need the exact access key', async () => {
  const { server, token, port, calls } = await startServer();
  const call = (headers) => request(port, { method: 'POST', path: '/api/call', headers: { 'Content-Type': 'application/json', ...headers }, body: '{"type":"getState"}' });
  try {
    assert.equal((await call({})).status, 403, 'no key');
    assert.equal((await call({ 'X-NetWatch-Token': token.slice(0, -1) })).status, 403, 'shortened key');
    assert.equal((await call({ 'X-NetWatch-Token': `${token.slice(0, -1)}0` === token ? `${token.slice(0, -1)}1` : `${token.slice(0, -1)}0` })).status, 403, 'wrong key');
    assert.equal(calls.length, 0, 'the handler never ran for refused calls');
    const ok = await call({ 'X-NetWatch-Token': token });
    assert.equal(ok.status, 200);
    assert.deepEqual(JSON.parse(ok.body), { ok: true, result: { ok: 'getState' } });
  } finally { server.close(); }
});

test('browser mode refuses other host names and other origins (DNS rebinding, cross-site pages)', async () => {
  const { server, token, port } = await startServer();
  try {
    assert.equal((await request(port, { headers: { Host: `evil.example:${port}` } })).status, 403, 'rebinding page fetching /');
    const post = (headers) => request(port, { method: 'POST', path: '/api/call', headers: { 'Content-Type': 'application/json', 'X-NetWatch-Token': token, ...headers }, body: '{"type":"getState"}' });
    assert.equal((await post({ Host: `evil.example:${port}` })).status, 403);
    assert.equal((await post({ Origin: 'https://evil.example' })).status, 403);
    assert.equal((await post({ Origin: `http://localhost:${port}` })).status, 200, 'the page itself is allowed');
  } finally { server.close(); }
});

test('admin autostart only accepts installs inside Program Files', () => {
  const env = { ProgramFiles: 'C:\\Program Files', 'ProgramFiles(x86)': 'C:\\Program Files (x86)', ProgramW6432: 'C:\\Program Files' };
  assert.equal(isAdminOnlyInstallDir('C:\\Program Files\\NetWatch', env), true);
  assert.equal(isAdminOnlyInstallDir('c:/program files (x86)/NetWatch/', env), true);
  assert.equal(isAdminOnlyInstallDir('C:\\Users\\me\\AppData\\Local\\Programs\\NetWatch', env), false, 'per-user install');
  assert.equal(isAdminOnlyInstallDir('C:\\Program Files Evil\\NetWatch', env), false, 'look-alike folder');
  assert.equal(isAdminOnlyInstallDir('C:\\Program Files\\..\\Users\\me\\NetWatch', env), false, 'path climbing out');
  assert.equal(isAdminOnlyInstallDir('', env), false);
  assert.equal(isAdminOnlyInstallDir('C:\\Program Files\\NetWatch', {}), false, 'unknown environment fails closed');
});

test('data folder and files are private to the owner', { skip: process.platform === 'win32' && 'Windows uses ACLs on the profile folder instead of modes' }, () => {
  const parent = fs.mkdtempSync(path.join(os.tmpdir(), 'nw-sec-'));
  const dir = path.join(parent, 'data');
  fs.mkdirSync(dir, { mode: 0o755 });
  fs.chmodSync(dir, 0o755); // as an older version would have left it
  const store = new Store(dir);
  store.writeJson('settings.json', { a: 1 });
  store.appendAlert({ t: 1, severity: 'LOW', message: 'x' });
  store.writePrivateText('web-access.txt', 'http://127.0.0.1:1/#token=abc\n');
  const mode = (p) => fs.statSync(p).mode & 0o777;
  assert.equal(mode(dir), 0o700, 'existing folder tightened');
  for (const f of ['settings.json', 'alerts.jsonl', 'web-access.txt']) assert.equal(mode(path.join(dir, f)), 0o600, f);
  fs.rmSync(parent, { recursive: true, force: true });
});

test('the access-key file is replaced, not appended, each start', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'nw-sec-'));
  const store = new Store(dir);
  store.writePrivateText('web-access.txt', 'first\n');
  store.writePrivateText('web-access.txt', 'second\n');
  assert.equal(fs.readFileSync(path.join(dir, 'web-access.txt'), 'utf8'), 'second\n');
  fs.rmSync(dir, { recursive: true, force: true });
});
