'use strict';
// Engine tests with a fake collector: no network, no OS calls.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const http = require('http');
const { Store, sanitizeSettings } = require('../src/main/store');
const { Monitor } = require('../src/main/monitor');
const { Geo } = require('../src/main/geo');

const tmpDir = () => fs.mkdtempSync(path.join(os.tmpdir(), 'nw-test-'));

function fakePlatform(over = {}) {
  const calls = { sample: 0, dns: 0, signatures: 0 };
  const platform = {
    name: 'test', isAdmin: () => false, riskyFolders: [], systemPrefixes: [], signatureSupported: true,
    dnsSupported: true, dnsNeedsAdmin: true, firewall: { supported: false },
    async sample() {
      calls.sample++;
      return {
        tcp: [
          { pid: 100, state: 'ESTABLISHED', localIp: '192.168.1.5', localPort: 50000, remoteIp: '93.184.216.34', remotePort: 443 },
          { pid: 0, state: 'ESTABLISHED', localIp: '192.168.1.5', localPort: 50001, remoteIp: '8.8.8.8', remotePort: 443 },
          { pid: 0, state: 'ESTABLISHED', localIp: '192.168.1.5', localPort: 50002, remoteIp: '1.1.1.1', remotePort: 443 },
        ],
        udp: [], procs: new Map([[100, { name: 'app', path: '/opt/app/app', ppid: 1 }]]),
        connBytes: null, procBytes: null, totals: { rx: 0, tx: 0 }, measuring: false,
      };
    },
    async signatures() { calls.signatures++; return new Map(); }, // every check fails
    async dnsCache() { calls.dns++; return new Map(); },
    async arp() { return []; },
    async commandLine() { return ''; },
    ...over,
  };
  return { platform, calls };
}

function makeMonitor(platform) {
  const settings = sanitizeSettings({});
  const stub = { lookup: () => null, update: async () => false, status: () => [], cache: new Map() };
  const geo = { lookup: () => '', update: async () => false, status: () => ({}), cache: new Map() };
  const m = new Monitor({ platform, store: new Store(tmpDir()), intel: stub, geo, settings, version: 'test' });
  m.knownApps.add('seeded'); // skip first-run learning so new-program alerts fire
  m.learning = false;
  return m;
}

test('connections with no visible owner become one untrustable "Unknown process"', async () => {
  const { platform } = fakePlatform();
  const m = makeMonitor(platform);
  const alerts = [];
  m.on('alert', (a) => alerts.push(a));
  await m.scan();
  const unknown = m.snapshot.programs.find((p) => p.unknown);
  assert.equal(unknown.name, 'Unknown process');
  assert.equal(unknown.conns, 2);
  assert.ok(!m.snapshot.programs.some((p) => p.name === 'System'));
  assert.ok(!alerts.some((a) => a.program === 'Unknown process'), 'no per-program alerts for the unknown group');
  assert.ok(alerts.some((a) => a.program === 'app' && a.severity === 'LOW'), 'real programs still get new-program alerts');
  await assert.rejects(m.action('trust', { key: 'unknown process', trusted: true }), /can't be trusted/);
  assert.equal(m.isTrusted('Unknown process', null), false);
});

test('a failed signature check is retried later instead of cached as Unknown', async () => {
  const { platform, calls } = fakePlatform();
  const m = makeMonitor(platform);
  assert.equal(m.signature('/opt/app/app').status, 'Checking');
  await m.refreshSignatures();
  assert.equal(calls.signatures, 1);
  assert.equal(m.sigCache.has('/opt/app/app'), false, 'nothing cached for a failed check');
  assert.equal(m.signature('/opt/app/app').status, 'Unknown', 'reported Unknown while waiting to retry');
  m.sigFailed.set('/opt/app/app', Date.now() - 11 * 60e3);
  assert.equal(m.signature('/opt/app/app').status, 'Checking', 'queued again after the retry delay');
});

test('the DNS cache is not polled when it needs admin rights and NetWatch has none', async () => {
  const { platform, calls } = fakePlatform();
  const m = makeMonitor(platform);
  m.admin = false;
  await m.refreshDns();
  assert.equal(calls.dns, 0);
  m.admin = true;
  await m.refreshDns();
  assert.equal(calls.dns, 1);
});

test('a scan requested during another scan runs again afterwards', async () => {
  let release;
  const { platform, calls } = fakePlatform();
  const sample = platform.sample;
  platform.sample = async () => { if (calls.sample === 0) await new Promise((r) => { release = r; }); return sample(); };
  const m = makeMonitor(platform);
  const first = m.scan();
  const second = m.scan();
  const third = m.scan();
  assert.equal(second, third, 'callers waiting on the same rescan share it');
  release();
  await first;
  await second;
  assert.equal(calls.sample, 2, 'the second caller got a fresh scan, not the in-flight one');
});

test('damaged settings fall back to defaults instead of crashing', () => {
  const s = sanitizeSettings({ push: null, quiet: 'x', intel: { feeds: 5 }, intervalSec: 'abc', alertCountries: 'RU' });
  assert.equal(s.push.minSeverity, 'HIGH');
  assert.equal(s.quiet.from, '00:00');
  assert.equal(typeof s.intel.feeds, 'object');
  assert.equal(s.intervalSec, 5);
  assert.deepEqual(s.alertCountries, []);
  const a = sanitizeSettings({});
  a.push.ntfyUrl = 'changed';
  assert.equal(sanitizeSettings({}).push.ntfyUrl, '', 'defaults are copied, never shared');
});

test('a fresh country database on disk is not downloaded again', async () => {
  const dir = tmpDir();
  fs.mkdirSync(path.join(dir, 'geo'));
  fs.writeFileSync(path.join(dir, 'geo', 'dbip-country-ipv4-num.csv'), '134744064,134744319,US\n');
  fs.writeFileSync(path.join(dir, 'geo', 'meta.json'), JSON.stringify({ updatedAt: Date.now() }));
  const realFetch = global.fetch;
  let fetches = 0;
  global.fetch = async () => { fetches++; throw new Error('no network in tests'); };
  try {
    const geo = new Geo(dir, () => sanitizeSettings({}));
    assert.equal(await geo.update(false), false);
    assert.equal(fetches, 0);
    assert.equal(geo.lookup('8.8.8.8'), 'US');
  } finally { global.fetch = realFetch; }
});

test('a malformed URL gets 400 and the local server keeps running', async () => {
  const { server } = require('../src/main/devserver').start(0, async () => ({}), path.join(__dirname, '..', 'src', 'renderer'));
  await new Promise((r) => server.once('listening', r));
  const { port } = server.address();
  const get = (p) => new Promise((resolve, reject) => {
    http.get({ host: '127.0.0.1', port, path: p }, (res) => { res.resume(); resolve(res.statusCode); }).on('error', reject);
  });
  try {
    assert.equal(await get('/%E0%A4%A'), 400);
    assert.equal(await get('/'), 200);
  } finally { server.close(); }
});
