'use strict';
// macOS collector: lsof for sockets, ps for processes, nettop for per-process bytes, codesign for signatures.
// Without root, lsof only lists this user's sockets; browser mode run with sudo sees system services too.
const os = require('os');
const path = require('path');
const { execFile } = require('child_process');
const P = require('./parsers');

const run = (cmd, args, timeout = 15000) => new Promise((resolve) => {
  execFile(cmd, args, { timeout, maxBuffer: 32 * 1024 * 1024 }, (err, stdout, stderr) => resolve({ ok: !err, out: String(stdout), err: String(stderr) }));
});

module.exports = {
  name: 'macos',
  isAdmin: () => typeof process.getuid === 'function' && process.getuid() === 0,
  riskyFolders: ['/tmp/', '/private/tmp/', '/private/var/tmp/', path.join(os.homedir(), 'Downloads') + '/'],
  systemPrefixes: ['/System/', '/usr/libexec/', '/usr/sbin/'],
  signatureSupported: true,
  dnsSupported: false,
  firewall: { supported: false },
  async sample() {
    const [lsof, ps, nettop, netstat] = await Promise.all([
      run('lsof', ['+c', '0', '-nP', '-iTCP', '-iUDP', '-FpcPnT']), // +c 0: full command names, not 15 characters
      run('ps', ['-axo', 'pid=,ppid=,comm=']),
      run('nettop', ['-P', '-L', '1', '-x', '-J', 'bytes_in,bytes_out']),
      run('netstat', ['-ibn']),
    ]);
    const socks = P.parseLsof(lsof.out);
    const psMap = P.parsePs(ps.out);
    const procs = new Map();
    for (const s of socks) {
      if (procs.has(s.pid)) continue;
      const info = psMap.get(s.pid);
      const p = info && info.path.startsWith('/') ? info.path : null;
      procs.set(s.pid, { name: s.command || (p ? path.basename(p) : `PID ${s.pid}`), path: p, ppid: info ? info.ppid : 0 });
    }
    const procBytes = P.parseNettop(nettop.out);
    return {
      tcp: socks.filter((s) => s.proto === 'TCP' && (s.state === 'ESTABLISHED' || s.state === 'LISTEN'))
        .map((s) => ({ pid: s.pid, state: s.state, localIp: s.localIp === '*' ? '0.0.0.0' : s.localIp, localPort: s.localPort, remoteIp: s.remoteIp, remotePort: s.remotePort })),
      udp: socks.filter((s) => s.proto === 'UDP').map((s) => ({ pid: s.pid, localIp: s.localIp, localPort: s.localPort })),
      procs,
      connBytes: null,
      procBytes: procBytes.size ? procBytes : null,
      totals: P.parseNetstatIbn(netstat.out),
      measuring: procBytes.size > 0,
    };
  },
  async signatures(paths) {
    const out = new Map();
    for (const p of paths) {
      const verify = await run('codesign', ['--verify', '--strict', p], 20000);
      const info = await run('codesign', ['-dv', '--verbose=2', p], 20000);
      const authority = /Authority=(.+)/.exec(info.err);
      const signed = /Signature size=|Authority=/.test(info.err);
      out.set(p, {
        status: verify.ok ? 'Valid' : signed ? 'HashMismatch' : 'NotSigned',
        signer: authority ? authority[1].replace(/^Developer ID Application:\s*/, '').trim() : '',
      });
    }
    return out;
  },
  async dnsCache() { return null; },
  async arp() { return P.parseArp((await run('arp', ['-an'])).out); },
  async commandLine(pid) { return (await run('ps', ['-o', 'command=', '-p', String(parseInt(pid, 10))])).out.trim(); },
};
