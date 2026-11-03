'use strict';
// Small helpers shared by the monitor, collectors and tests. No Electron imports here.
const net = require('net');

/** Strips an IPv4-mapped IPv6 prefix and zone id so addresses compare cleanly. */
function normalizeIp(ip) {
  if (!ip) return ip;
  ip = String(ip).split('%')[0];
  if (/^::ffff:\d+\.\d+\.\d+\.\d+$/i.test(ip)) return ip.slice(7);
  return ip.toLowerCase();
}

/** True for addresses on the public internet (not LAN, loopback, link-local, multicast, CGNAT). */
function isPublicIp(ip) {
  ip = normalizeIp(ip);
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split('.').map(Number);
    if (a === 0 || a === 10 || a === 127 || a >= 224) return false;
    if (a === 169 && b === 254) return false;
    if (a === 172 && b >= 16 && b <= 31) return false;
    if (a === 192 && b === 168) return false;
    if (a === 100 && b >= 64 && b <= 127) return false; // carrier-grade NAT
    return true;
  }
  if (net.isIPv6(ip)) {
    if (ip === '::' || ip === '::1') return false;
    if (/^(fe[89ab]|fc|fd|ff)/.test(ip)) return false;
    return true;
  }
  return false;
}

function ipv4ToInt(ip) {
  const p = ip.split('.');
  return (((+p[0]) << 24) >>> 0) + ((+p[1]) << 16) + ((+p[2]) << 8) + (+p[3]);
}

/** Parses "1.2.3.0/24" or "1.2.3.4" into [start, end] integers; null for anything else (IPv6 included). */
function parseIpv4Cidr(s) {
  const m = /^(\d{1,3}(?:\.\d{1,3}){3})(?:\/(\d{1,2}))?$/.exec(String(s).trim());
  if (!m || !net.isIPv4(m[1])) return null;
  const bits = m[2] === undefined ? 32 : +m[2];
  if (bits > 32) return null;
  const base = ipv4ToInt(m[1]);
  const size = 2 ** (32 - bits);
  const start = base - (base % size);
  return [start, start + size - 1];
}

/** Eight 16-bit groups of an IPv6 address (handles "::" and an embedded IPv4 tail). */
function ipv6Groups(ip) {
  ip = String(ip).split('%')[0];
  let v4 = null;
  if (ip.includes('.')) {
    const i = ip.lastIndexOf(':');
    v4 = ip.slice(i + 1);
    ip = ip.slice(0, i) + ':0:0';
  }
  const halves = ip.split('::');
  const left = halves[0] ? halves[0].split(':') : [];
  const right = halves.length > 1 && halves[1] ? halves[1].split(':') : [];
  const fill = halves.length > 1 ? 8 - left.length - right.length : 0;
  const groups = [...left, ...Array(Math.max(0, fill)).fill('0'), ...right].map((h) => parseInt(h, 16) || 0);
  if (v4) { const n = ipv4ToInt(v4); groups[6] = n >>> 16; groups[7] = n & 0xffff; }
  return groups;
}

/** Top 64 bits of an IPv6 address as a BigInt: enough precision for country ranges. */
function ipv6High64(ip) {
  const g = ipv6Groups(ip);
  return (BigInt(g[0]) << 48n) | (BigInt(g[1]) << 32n) | (BigInt(g[2]) << 16n) | BigInt(g[3]);
}

/** Formats 16 raw bytes as a compressed IPv6 string; IPv4-mapped addresses come back as plain IPv4. */
function formatIpv6(bytes) {
  const g = [];
  for (let i = 0; i < 16; i += 2) g.push((bytes[i] << 8) | bytes[i + 1]);
  if (g.slice(0, 5).every((x) => x === 0) && g[5] === 0xffff) {
    return `${bytes[12]}.${bytes[13]}.${bytes[14]}.${bytes[15]}`;
  }
  // Longest run of zero groups becomes "::"
  let bestStart = -1, bestLen = 0;
  for (let i = 0; i < 8;) {
    if (g[i] !== 0) { i++; continue; }
    let j = i;
    while (j < 8 && g[j] === 0) j++;
    if (j - i > bestLen && j - i > 1) { bestStart = i; bestLen = j - i; }
    i = j;
  }
  const hex = g.map((x) => x.toString(16));
  if (bestStart < 0) return hex.join(':');
  return `${hex.slice(0, bestStart).join(':')}::${hex.slice(bestStart + bestLen).join(':')}`;
}

/** Shannon entropy in bits per character. */
function entropy(s) {
  const counts = {};
  for (const c of s) counts[c] = (counts[c] || 0) + 1;
  let e = 0;
  for (const k in counts) { const p = counts[k] / s.length; e -= p * Math.log2(p); }
  return e;
}

// Infrastructure domains that legitimately use random-looking names (CDN shards, cloud hosts).
const RANDOM_OK_SUFFIXES = [
  'cloudfront.net', 'akamaiedge.net', 'akamai.net', 'akamaized.net', 'amazonaws.com', 'googleusercontent.com',
  'googlevideo.com', 'gvt1.com', 'gvt2.com', '1e100.net', 'azureedge.net', 'azurefd.net', 'msedge.net', 'trafficmanager.net',
  'cloudapp.azure.com', 'windows.net', 'azure.com', 'office.net', 'office.com', 'microsoft.com', 'live.com', 'fastly.net',
  'cloudflare.net', 'cloudflare.com', 'edgekey.net', 'edgesuite.net', 'llnwd.net', 'fbcdn.net', 'cdninstagram.com',
  'whatsapp.net', 'apple.com', 'icloud.com', 'aaplimg.com', 'steamcontent.com', 'nflxvideo.net', 'doubleclick.net',
];

/**
 * Heuristic for machine-generated domain names (used by some malware to find its servers):
 * a long, high-entropy, vowel-poor label right below the public suffix.
 */
function looksRandomDomain(domain) {
  if (!domain) return false;
  const d = domain.toLowerCase().replace(/\.$/, '');
  if (RANDOM_OK_SUFFIXES.some((s) => d === s || d.endsWith(`.${s}`))) return false;
  const labels = d.split('.');
  if (labels.length < 2) return false;
  const label = labels[labels.length - 2].length <= 3 && labels.length >= 3 ? labels[labels.length - 3] : labels[labels.length - 2];
  if (label.length < 12) return false;
  const letters = label.replace(/[^a-z]/g, '');
  const vowels = (letters.match(/[aeiou]/g) || []).length;
  const digits = (label.match(/\d/g) || []).length;
  const vowelRatio = letters.length ? vowels / letters.length : 0;
  return entropy(label) >= 3.6 && (vowelRatio < 0.25 || digits / label.length > 0.3);
}

const SEVERITY_RANK = { LOW: 1, MEDIUM: 2, HIGH: 3 };

function dayKey(d = new Date()) {
  const p = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`;
}

/** Minutes since midnight for "HH:MM". */
function parseClock(s) {
  const m = /^(\d{1,2}):(\d{2})$/.exec(String(s || '').trim());
  return m ? Math.min(23, +m[1]) * 60 + Math.min(59, +m[2]) : null;
}

/** Whether `date` falls in a daily window that may wrap past midnight (e.g. 23:00-06:00). */
function inDailyWindow(date, from, to) {
  const f = parseClock(from), t = parseClock(to);
  if (f === null || t === null || f === t) return false;
  const now = date.getHours() * 60 + date.getMinutes();
  return f < t ? now >= f && now < t : now >= f || now < t;
}

/**
 * Whether a Windows folder is inside Program Files, which only administrators can change. Code that runs
 * with admin rights without a prompt (the login task) must live there: an "only for me" install under
 * AppData can be rewritten by any program running as the user.
 */
function isAdminOnlyInstallDir(dir, env = process.env) {
  const norm = (p) => String(p || '').replace(/\//g, '\\').replace(/\\+$/, '').toLowerCase();
  const target = norm(dir);
  if (!target || target.includes('\\..')) return false;
  return [env.ProgramW6432, env.ProgramFiles, env['ProgramFiles(x86)']]
    .filter(Boolean).map(norm)
    .some((root) => target === root || target.startsWith(`${root}\\`));
}

module.exports = {
  normalizeIp, isPublicIp, ipv4ToInt, parseIpv4Cidr, ipv6Groups, ipv6High64, formatIpv6,
  entropy, looksRandomDomain, SEVERITY_RANK, dayKey, parseClock, inDailyWindow, isAdminOnlyInstallDir,
};
