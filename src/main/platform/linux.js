'use strict';
// Linux collector: sockets and totals from /proc, socket owners and per-connection byte counters from `ss`.
// Without root, sockets of other users' processes have no visible owner (the monitor shows them as "Unknown process").
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFile } = require('child_process');
const P = require('./parsers');

const read = (f) => { try { return fs.readFileSync(f, 'utf8'); } catch { return ''; } };
const run = (cmd, args) => new Promise((resolve) => {
  execFile(cmd, args, { timeout: 15000, maxBuffer: 32 * 1024 * 1024 }, (err, stdout) => resolve(err ? '' : String(stdout)));
});

let procCache = new Map();
function processInfo(pid) {
  const name = read(`/proc/${pid}/comm`).trim();
  if (!name) return null;
  const cached = procCache.get(pid);
  if (cached && cached.name === name) return cached;
  let exe = null;
  try { exe = fs.readlinkSync(`/proc/${pid}/exe`); } catch { /* other user's process */ }
  return { name, path: exe, ppid: P.parseProcStatPpid(read(`/proc/${pid}/stat`)) };
}

module.exports = {
  name: 'linux',
  isAdmin: () => typeof process.getuid === 'function' && process.getuid() === 0,
  riskyFolders: ['/tmp/', '/var/tmp/', '/dev/shm/', path.join(os.homedir(), 'Downloads') + '/'],
  systemPrefixes: ['/usr/lib/systemd/', '/lib/systemd/'],
  signatureSupported: false,
  dnsSupported: false,
  firewall: { supported: false },
  async sample() {
    // `ss` finds socket owners in native code without blocking the app (a JS walk of every /proc/<pid>/fd
    // costs tens of thousands of synchronous syscalls per scan on a busy desktop).
    const [ssProcText, ssInfoText] = await Promise.all([run('ss', ['-tuanpH']), run('ss', ['-tinH', 'state', 'established'])]);
    const owners = P.parseSsProcesses(ssProcText);
    const ownerOf = (proto, r) => (r.remoteIp ? owners.get(`${proto}|${r.localIp}|${r.localPort}|${r.remoteIp}|${r.remotePort}`) : 0)
      || owners.get(`${proto}|L|${r.localPort}`) || 0;
    const tcp = [
      ...P.parseProcNetTcp(read('/proc/net/tcp')),
      ...P.parseProcNetTcp(read('/proc/net/tcp6')),
    ].filter((r) => r.state === 'ESTABLISHED' || r.state === 'LISTEN')
      .map((r) => ({ ...r, pid: ownerOf('tcp', r.state === 'ESTABLISHED' ? r : { localIp: r.localIp, localPort: r.localPort }) }));
    const udp = [
      ...P.parseProcNetUdp(read('/proc/net/udp')),
      ...P.parseProcNetUdp(read('/proc/net/udp6')),
    ].map((r) => ({ ...r, pid: ownerOf('udp', r) }));

    const procs = new Map();
    for (const pid of new Set([...tcp, ...udp].map((r) => r.pid).filter(Boolean))) {
      const info = processInfo(pid);
      if (info) procs.set(pid, info);
    }
    procCache = procs;

    // ss reports bytes per socket for every user; key them the same way the monitor does.
    const ss = P.parseSsTcpInfo(ssInfoText);
    const connBytes = new Map();
    for (const r of tcp) {
      if (r.state !== 'ESTABLISHED') continue;
      const b = ss.get(`${r.localIp}|${r.localPort}|${r.remoteIp}|${r.remotePort}`);
      if (b) connBytes.set(`${r.pid}|${r.remoteIp}|${r.remotePort}|${r.localPort}`, b);
    }
    return {
      tcp: tcp.map(({ inode, ...r }) => r),
      udp: udp.map(({ inode, ...r }) => r),
      procs,
      connBytes: ss.size ? connBytes : null,
      procBytes: null,
      totals: P.parseProcNetDev(read('/proc/net/dev')),
      measuring: ss.size > 0,
    };
  },
  async signatures(paths) { return new Map(paths.map((p) => [p, { status: 'Unknown', signer: '' }])); },
  async dnsCache() { return null; },
  async arp() { return P.parseArp(read('/proc/net/arp')); },
  async commandLine(pid) { return read(`/proc/${parseInt(pid, 10)}/cmdline`).split('\0').filter(Boolean).join(' '); },
};
