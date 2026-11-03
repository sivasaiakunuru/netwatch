'use strict';
// Pure parsers for the text that OS tools print. Kept free of I/O so they can be unit-tested on any OS.
const { formatIpv6, normalizeIp } = require('../util');

// ---------- Linux /proc/net/{tcp,tcp6,udp,udp6} ----------

const LINUX_TCP_STATES = { '01': 'ESTABLISHED', '0A': 'LISTEN' };

function procHexToIp(hex) {
  if (hex.length === 8) {
    const b = [];
    for (let i = 3; i >= 0; i--) b.push(parseInt(hex.substr(i * 2, 2), 16));
    return b.join('.');
  }
  const bytes = [];
  for (let w = 0; w < 4; w++) for (let i = 3; i >= 0; i--) bytes.push(parseInt(hex.substr(w * 8 + i * 2, 2), 16));
  return formatIpv6(bytes);
}

function procAddr(field) {
  const [hex, port] = field.split(':');
  return { ip: procHexToIp(hex), port: parseInt(port, 16) };
}

/** Rows of /proc/net/tcp*: [{ localIp, localPort, remoteIp, remotePort, state, inode }] */
function parseProcNetTcp(text) {
  const rows = [];
  for (const line of text.split('\n').slice(1)) {
    const f = line.trim().split(/\s+/);
    if (f.length < 10) continue;
    const l = procAddr(f[1]), r = procAddr(f[2]);
    rows.push({ localIp: l.ip, localPort: l.port, remoteIp: r.ip, remotePort: r.port, state: LINUX_TCP_STATES[f[3]] || f[3], inode: f[9] });
  }
  return rows;
}

/** Rows of /proc/net/udp*: [{ localIp, localPort, inode }] */
function parseProcNetUdp(text) {
  const rows = [];
  for (const line of text.split('\n').slice(1)) {
    const f = line.trim().split(/\s+/);
    if (f.length < 10) continue;
    const l = procAddr(f[1]);
    rows.push({ localIp: l.ip, localPort: l.port, inode: f[9] });
  }
  return rows;
}

/** /proc/net/dev: total received/sent bytes over real interfaces. */
function parseProcNetDev(text) {
  let rx = 0, tx = 0;
  for (const line of text.split('\n').slice(2)) {
    const i = line.indexOf(':');
    if (i < 0) continue;
    const name = line.slice(0, i).trim();
    if (/^(lo|docker|veth|br-|virbr|lxc|cni|flannel)/.test(name)) continue;
    const f = line.slice(i + 1).trim().split(/\s+/).map(Number);
    rx += f[0] || 0; tx += f[8] || 0;
  }
  return { rx, tx };
}

/** Parent pid from /proc/<pid>/stat (the name may contain spaces and parentheses). */
function parseProcStatPpid(text) {
  const close = text.lastIndexOf(')');
  const f = text.slice(close + 2).split(' ');
  return parseInt(f[1], 10) || 0;
}

function splitHostPort(s) {
  const i = s.lastIndexOf(':');
  let host = s.slice(0, i);
  if (host.startsWith('[')) host = host.slice(1, -1);
  return { ip: normalizeIp(host.split('%')[0]), port: parseInt(s.slice(i + 1), 10) };
}

/**
 * `ss -tinH` output: socket lines followed by indented detail lines with byte counters.
 * Returns Map "localIp|localPort|remoteIp|remotePort" -> { rx, tx }.
 */
function parseSsTcpInfo(text) {
  const out = new Map();
  let key = null;
  for (const line of text.split('\n')) {
    if (!line.trim()) continue;
    if (!/^\s/.test(line)) {
      const addrs = line.trim().split(/\s+/).filter((t) => /:\d+$/.test(t));
      if (addrs.length >= 2) {
        const l = splitHostPort(addrs[addrs.length - 2]), r = splitHostPort(addrs[addrs.length - 1]);
        key = `${l.ip}|${l.port}|${r.ip}|${r.port}`;
      } else key = null;
      continue;
    }
    if (!key) continue;
    const rx = /bytes_received:(\d+)/.exec(line);
    const tx = /bytes_sent:(\d+)/.exec(line) || /bytes_acked:(\d+)/.exec(line);
    if (rx || tx) out.set(key, { rx: rx ? +rx[1] : 0, tx: tx ? +tx[1] : 0 });
  }
  return out;
}

// ---------- macOS ----------

/**
 * `lsof -nP -iTCP -iUDP -FpcPnT` output. Returns
 * [{ pid, command, proto, localIp, localPort, remoteIp, remotePort, state }]
 */
function parseLsof(text) {
  const rows = [];
  let pid = 0, command = '', cur = null;
  const flush = () => { if (cur && cur.name) rows.push(finish(cur)); cur = null; };
  const finish = (c) => {
    const [local, remote] = c.name.split('->');
    const l = local.startsWith('*:') ? { ip: '*', port: parseInt(local.slice(2), 10) } : splitHostPort(local);
    const r = remote ? splitHostPort(remote) : { ip: '', port: 0 };
    return { pid, command, proto: c.proto, localIp: l.ip, localPort: l.port, remoteIp: r.ip, remotePort: r.port, state: c.state || (remote ? 'ESTABLISHED' : '') };
  };
  for (const line of text.split('\n')) {
    if (!line) continue;
    const tag = line[0], val = line.slice(1);
    if (tag === 'p') { flush(); pid = parseInt(val, 10); command = ''; }
    else if (tag === 'c') command = val;
    else if (tag === 'f') { flush(); cur = { proto: '', name: '', state: '' }; }
    else if (cur && tag === 'P') cur.proto = val;
    else if (cur && tag === 'n') cur.name = val;
    else if (cur && tag === 'T' && val.startsWith('ST=')) cur.state = val.slice(3);
  }
  flush();
  return rows;
}

/** `nettop -P -L 1 -x -J bytes_in,bytes_out`: Map pid -> { rx, tx } (bytes since the process started). */
function parseNettop(text) {
  const out = new Map();
  for (const line of text.split('\n').slice(1)) {
    const f = line.split(',');
    if (f.length < 3) continue;
    const dot = f[0].lastIndexOf('.');
    const pid = parseInt(f[0].slice(dot + 1), 10);
    if (!pid) continue;
    const prev = out.get(pid) || { rx: 0, tx: 0 };
    out.set(pid, { rx: prev.rx + (+f[1] || 0), tx: prev.tx + (+f[2] || 0) });
  }
  return out;
}

/** `netstat -ibn` on macOS: total bytes across en* interfaces (link-level rows only). */
function parseNetstatIbn(text) {
  let rx = 0, tx = 0;
  for (const line of text.split('\n').slice(1)) {
    const t = line.trim().split(/\s+/);
    if (t.length < 10 || !/^en\d+/.test(t[0]) || !t[2].startsWith('<Link#')) continue;
    rx += +t[t.length - 5] || 0;
    tx += +t[t.length - 2] || 0;
  }
  return { rx, tx };
}

/** `ps -axo pid=,ppid=,comm=`: Map pid -> { ppid, path } */
function parsePs(text) {
  const out = new Map();
  for (const line of text.split('\n')) {
    const m = /^\s*(\d+)\s+(\d+)\s+(.+)$/.exec(line);
    if (m) out.set(+m[1], { ppid: +m[2], path: m[3].trim() });
  }
  return out;
}

// ---------- ARP tables (devices on the local network) ----------

function normalizeMac(mac) {
  const parts = mac.toLowerCase().split(/[:-]/);
  if (parts.length !== 6) return null;
  return parts.map((p) => p.padStart(2, '0')).join(':');
}

function usableMac(mac) {
  if (!mac || mac === '00:00:00:00:00:00' || mac === 'ff:ff:ff:ff:ff:ff') return false;
  return (parseInt(mac.slice(0, 2), 16) & 1) === 0; // multicast MACs have the lowest bit of the first byte set
}

/** Windows `arp -a`, macOS `arp -an` and Linux /proc/net/arp: [{ ip, mac }] */
function parseArp(text) {
  const out = [];
  const seen = new Set();
  const add = (ip, rawMac) => {
    const mac = normalizeMac(rawMac);
    if (!usableMac(mac) || seen.has(mac + ip)) return;
    const last = +ip.split('.')[3];
    if (last === 255 || /^(22[4-9]|23\d)\./.test(ip)) return; // broadcast / multicast
    seen.add(mac + ip);
    out.push({ ip, mac });
  };
  for (const line of text.split('\n')) {
    let m = /^\s*(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f]{2}(?:-[0-9a-f]{2}){5})\s/i.exec(line); // Windows
    if (m) { add(m[1], m[2]); continue; }
    m = /\((\d+\.\d+\.\d+\.\d+)\) at ([0-9a-f]{1,2}(?::[0-9a-f]{1,2}){5})/i.exec(line); // macOS / BSD
    if (m) { add(m[1], m[2]); continue; }
    m = /^(\d+\.\d+\.\d+\.\d+)\s+0x\w+\s+0x(\w+)\s+([0-9a-f]{2}(?::[0-9a-f]{2}){5})/i.exec(line); // Linux /proc/net/arp
    if (m && (parseInt(m[2], 16) & 2)) add(m[1], m[3]);
  }
  return out;
}

/** Locally administered MAC (second-lowest bit of the first byte): phones use these as "private" random addresses. */
function isRandomMac(mac) {
  return (parseInt(mac.slice(0, 2), 16) & 2) === 2;
}

module.exports = {
  parseProcNetTcp, parseProcNetUdp, parseProcNetDev, parseProcStatPpid, parseSsTcpInfo,
  parseLsof, parseNettop, parseNetstatIbn, parsePs, parseArp, normalizeMac, isRandomMac, splitHostPort,
};
